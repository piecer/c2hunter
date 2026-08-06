package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"c2hunter/sensor/internal/batch"
	"c2hunter/sensor/internal/capture"
	"c2hunter/sensor/internal/flow"
	"c2hunter/sensor/internal/flowbatch"
	"c2hunter/sensor/internal/metadata"
	"c2hunter/sensor/internal/packet"
	"c2hunter/sensor/internal/spool"
)

type FlowUploader interface {
	UploadFlowBatch(context.Context, flowbatch.Batch) (flowbatch.ACK, error)
}

type PCAPSink interface {
	Enqueue(packet.Packet) bool
}

type PipelineConfig struct {
	SensorID, JobID              string
	ActiveJobIDs                 []string
	Interface, Direction         string
	IdleTimeout                  time.Duration
	PayloadPreviewBytes          int
	BatchMaxItems, BatchMaxBytes int
	PacketQueueSize              int
	Source                       func() (capture.Reader, error)
	Filter                       *packet.Filter
	Limits                       capture.Limits
	CaptureBudget                *CaptureBudget
	Spool                        *spool.Spool
	Uploader                     FlowUploader
	BatchManager                 *BatchManager
	PCAPSink                     PCAPSink
	PCAPSinks                    []PCAPSink
	Now                          func() time.Time
	IdleTicks                    <-chan time.Time
}

type CaptureCompletion struct {
	JobID      string
	StopReason capture.StopReason
}

type CaptureSnapshot struct {
	ReceivedPackets    uint64
	DroppedPackets     uint64
	DecodeErrors       uint64
	PendingBytes       uint64
	LostBatches        uint64
	LostBytes          uint64
	PCAPDroppedPackets uint64
	ActiveJobs         []string
	CompletedJobs      []CaptureCompletion
	LastError          string
	StopReason         capture.StopReason
	Interfaces         []InterfaceSnapshot
}

type InterfaceSnapshot struct {
	Interface       string `json:"interface"`
	Direction       string `json:"direction,omitempty"`
	Status          string `json:"status"`
	ReceivedPackets uint64 `json:"received_packets"`
	DroppedPackets  uint64 `json:"dropped_packets"`
	DecodeErrors    uint64 `json:"decode_errors"`
	LastError       string `json:"last_error,omitempty"`
}

type Pipeline struct {
	cfg         PipelineConfig
	manager     *BatchManager
	ownsManager bool
	mu          sync.RWMutex
	snapshot    CaptureSnapshot
	// cachedDrop holds the latest dropped-packet count from periodic refresh.
	cachedDrop atomic.Uint64
}

type CaptureBudget struct {
	mu                   sync.Mutex
	maxPackets, maxBytes uint64
	packets, bytes       uint64
	done                 chan struct{}
	stopReason           capture.StopReason
	stopOnce             sync.Once
}

func NewCaptureBudget(maxPackets, maxBytes uint64) *CaptureBudget {
	return &CaptureBudget{
		maxPackets: maxPackets,
		maxBytes:   maxBytes,
		done:       make(chan struct{}),
	}
}

func (b *CaptureBudget) Done() <-chan struct{} {
	if b == nil {
		return nil
	}
	return b.done
}

func (b *CaptureBudget) StopReason() capture.StopReason {
	if b == nil {
		return ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stopReason
}

func (b *CaptureBudget) stopLocked(reason capture.StopReason) {
	b.stopReason = reason
	b.stopOnce.Do(func() { close(b.done) })
}

// Reserve accounts one accepted packet. stopAfter is set when this packet
// exactly consumes the budget; rejected packets are never processed further.
func (b *CaptureBudget) Reserve(wireBytes uint64) (accepted bool, stopAfter capture.StopReason) {
	if b == nil {
		return true, ""
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.maxPackets > 0 && b.packets >= b.maxPackets {
		b.stopLocked(capture.StopMaxPackets)
		return false, capture.StopMaxPackets
	}
	if b.maxBytes > 0 && (wireBytes > b.maxBytes-b.bytes) {
		b.stopLocked(capture.StopMaxBytes)
		return false, capture.StopMaxBytes
	}
	b.packets++
	b.bytes += wireBytes
	if b.maxPackets > 0 && b.packets >= b.maxPackets {
		b.stopLocked(capture.StopMaxPackets)
		return true, capture.StopMaxPackets
	}
	if b.maxBytes > 0 && b.bytes >= b.maxBytes {
		b.stopLocked(capture.StopMaxBytes)
		return true, capture.StopMaxBytes
	}
	return true, ""
}

type packetEvent struct {
	packet packet.Packet
	err    error
}

func NewPipeline(cfg PipelineConfig) (*Pipeline, error) {
	if cfg.SensorID == "" || cfg.JobID == "" {
		return nil, fmt.Errorf("sensor and capture job IDs are required")
	}
	if cfg.Source == nil {
		return nil, fmt.Errorf("packet source is required")
	}
	if cfg.BatchMaxItems <= 0 || cfg.BatchMaxBytes <= 0 || cfg.PacketQueueSize <= 0 {
		return nil, fmt.Errorf("pipeline queue and batch limits must be positive")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	manager := cfg.BatchManager
	ownsManager := false
	if manager == nil {
		if cfg.Spool == nil || cfg.Uploader == nil {
			return nil, fmt.Errorf("batch manager or spool and uploader are required")
		}
		var err error
		manager, err = NewBatchManager(BatchManagerConfig{
			Store: cfg.Spool, Uploader: cfg.Uploader,
			QueueSize: cfg.PacketQueueSize, UploadInterval: time.Second, Now: cfg.Now,
		})
		if err != nil {
			return nil, err
		}
		ownsManager = true
	}
	return &Pipeline{cfg: cfg, manager: manager, ownsManager: ownsManager}, nil
}

func (p *Pipeline) Run(ctx context.Context) error {
	if p.ownsManager {
		managerCtx, stopManager := context.WithCancel(context.WithoutCancel(ctx))
		p.manager.Start(managerCtx)
		defer func() {
			stopManager()
			<-p.manager.Done()
		}()
	}
	activeJobs := append([]string(nil), p.cfg.ActiveJobIDs...)
	if len(activeJobs) == 0 {
		activeJobs = []string{p.cfg.JobID}
	}
	p.update(func(s *CaptureSnapshot) {
		s.ActiveJobs = activeJobs
		s.CompletedJobs = nil
		s.LastError = ""
		s.StopReason = ""
		s.Interfaces = []InterfaceSnapshot{{Interface: p.cfg.Interface, Direction: p.cfg.Direction, Status: "CAPTURING"}}
	})
	defer p.update(func(s *CaptureSnapshot) {
		s.ActiveJobs = nil
		if len(s.Interfaces) > 0 && s.Interfaces[0].Status == "CAPTURING" {
			s.Interfaces[0].Status = "ONLINE"
		}
	})

	reader, err := p.cfg.Source()
	if err != nil {
		p.fail("capture open failed: " + err.Error())
		return err
	}
	if retainer, ok := reader.(capture.RawFrameRetainer); ok {
		retainer.SetRetainRawFrame(p.cfg.PCAPSink != nil || len(p.cfg.PCAPSinks) > 0)
	}
	defer reader.Close()

	readerCtx, cancelReader := context.WithCancel(ctx)
	defer cancelReader()
	events := make(chan packetEvent, p.cfg.PacketQueueSize)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		p.readPackets(readerCtx, reader, events)
	}()

	// Periodic socket-stats snapshot (1 s interval). This removes per-packet
	// syscall overhead from the hot path; DroppedPackets is updated here and
	// read atomically by both main loop and decode-error handler.
	statsDone := make(chan struct{})
	go func() {
		tick := time.NewTicker(1 * time.Second)
		defer tick.Stop()
		defer close(statsDone)
		for {
			select {
			case <-readerCtx.Done():
				p.cachedDrop.Store(snapshotDroppedPackets(reader))
				return
			case <-tick.C:
				p.cachedDrop.Store(snapshotDroppedPackets(reader))
			}
		}
	}()

	aggregator := flow.NewAggregatorWithPayloadPreview(p.cfg.SensorID, p.cfg.JobID, p.cfg.IdleTimeout, p.cfg.PayloadPreviewBytes)
	queue := batch.NewQueue[flow.Record](p.cfg.BatchMaxItems, p.cfg.BatchMaxBytes, recordSize)
	started := p.cfg.Limits.StartedAt
	var capturedPackets, capturedBytes uint64

	var ticker *time.Ticker
	idleTicks := p.cfg.IdleTicks
	if idleTicks == nil {
		interval := p.cfg.IdleTimeout / 2
		if interval <= 0 {
			interval = 30 * time.Second
		}
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
		idleTicks = ticker.C
	}

	var captureBudgetDone <-chan struct{}
	if p.cfg.CaptureBudget != nil {
		captureBudgetDone = p.cfg.CaptureBudget.Done()
	}

	finish := func(reason capture.StopReason) error {
		cancelReader()
		// AF_PACKET Close unmaps its ring. Wait until Next has returned so the
		// capture goroutine cannot access that mapping after Run returns.
		<-readerDone
		<-statsDone
		p.setStopReason(reason)
		if reason == capture.StopMaxPackets || reason == capture.StopMaxBytes {
			completed := make([]CaptureCompletion, 0, len(activeJobs))
			for _, jobID := range activeJobs {
				if jobID == "" {
					continue
				}
				completed = append(completed, CaptureCompletion{JobID: jobID, StopReason: reason})
			}
			p.update(func(s *CaptureSnapshot) {
				s.CompletedJobs = completed
			})
		}
		if err := p.addRecords(queue, aggregator.Flush()); err != nil {
			return err
		}
		if err := p.persist(queue.Flush()); err != nil {
			return err
		}
		p.refreshSpoolMetrics()
		return nil
	}

	for {
		if reason := p.asynchronousStop(ctx, started); reason != "" {
			return finish(reason)
		}
		select {
		case <-ctx.Done():
			return finish(capture.StopContext)
		case <-captureBudgetDone:
			reason := p.cfg.CaptureBudget.StopReason()
			if reason == "" {
				reason = capture.StopMaxPackets
			}
			return finish(reason)
		case tick := <-idleTicks:
			if err := p.addRecords(queue, aggregator.Expire(tick)); err != nil {
				return err
			}
			if err := p.persist(queue.Flush()); err != nil {
				return err
			}
		case event := <-events:
			if event.err != nil {
				if errors.Is(event.err, io.EOF) {
					return finish(capture.StopEndOfInput)
				}
				p.fail("capture read failed: " + event.err.Error())
				_ = finish("")
				return event.err
			}
			pkt := event.packet
			if !p.cfg.Limits.StartTime.IsZero() && pkt.Timestamp.Before(p.cfg.Limits.StartTime) {
				continue
			}
			if !p.cfg.Limits.EndTime.IsZero() && !pkt.Timestamp.Before(p.cfg.Limits.EndTime) {
				return finish(capture.StopEndTime)
			}
			if started.IsZero() {
				started = pkt.Timestamp
			}
			if p.cfg.Limits.Duration > 0 && !pkt.Timestamp.Before(started.Add(p.cfg.Limits.Duration)) {
				return finish(capture.StopDuration)
			}
			if p.cfg.Filter != nil && !p.cfg.Filter.Match(pkt) {
				continue
			}
			budgetStop := capture.StopReason("")
			if p.cfg.CaptureBudget != nil {
				accepted, reason := p.cfg.CaptureBudget.Reserve(uint64(pkt.WireLength))
				if !accepted {
					return finish(reason)
				}
				budgetStop = reason
			}
			if p.cfg.PCAPSink != nil {
				p.cfg.PCAPSink.Enqueue(pkt)
			}
			for _, sink := range p.cfg.PCAPSinks {
				sink.Enqueue(pkt)
			}
			protocolMetadata, _ := metadata.Parse(servicePort(pkt), pkt.Payload)
			if err := p.addRecords(queue, aggregator.AddWithMetadata(pkt, protocolMetadata)); err != nil {
				return err
			}
			capturedPackets++
			capturedBytes += uint64(pkt.WireLength)
			p.update(func(s *CaptureSnapshot) {
				s.ReceivedPackets++
				if len(s.Interfaces) > 0 {
					s.Interfaces[0].ReceivedPackets++
				}
			})
			if budgetStop != "" {
				return finish(budgetStop)
			}
			if p.cfg.Limits.MaxPackets > 0 && capturedPackets >= p.cfg.Limits.MaxPackets {
				return finish(capture.StopMaxPackets)
			}
			if p.cfg.Limits.MaxBytes > 0 && capturedBytes >= p.cfg.Limits.MaxBytes {
				return finish(capture.StopMaxBytes)
			}
		}
	}
}

func (p *Pipeline) readPackets(ctx context.Context, reader capture.Reader, events chan<- packetEvent) {
	for {
		pkt, err := reader.Next(ctx)
		if errors.Is(err, capture.ErrPollTimeout) || errors.Is(err, capture.ErrUnsupportedPacket) {
			continue
		}
		if errors.Is(err, capture.ErrMalformedPacket) {
			p.update(func(s *CaptureSnapshot) {
				s.DecodeErrors++
				if len(s.Interfaces) > 0 {
					s.Interfaces[0].DecodeErrors++
				}
			})
			continue
		}
		if err != nil {
			select {
			case events <- packetEvent{err: err}:
			case <-ctx.Done():
			}
			return
		}
		select {
		case events <- packetEvent{packet: pkt}:
		case <-ctx.Done():
			return
		}
	}
}

// snapshotDroppedPackets queries the reader once for the current cumulative
// dropped-packet count. It is called from a dedicated 1 s goroutine, not from
// the per-packet hot path.
func snapshotDroppedPackets(reader capture.Reader) uint64 {
	if counter, ok := reader.(capture.DropCounter); ok {
		return counter.DroppedPackets()
	}
	return 0
}

func (p *Pipeline) asynchronousStop(ctx context.Context, started time.Time) capture.StopReason {
	if ctx.Err() != nil {
		return capture.StopContext
	}
	if p.cfg.Limits.UserStopped != nil && p.cfg.Limits.UserStopped() {
		return capture.StopUser
	}
	if p.cfg.Limits.DiskAvailable != nil && !p.cfg.Limits.DiskAvailable() {
		return capture.StopDisk
	}
	if p.cfg.Limits.Timeout > 0 && !started.IsZero() && !p.cfg.Now().Before(started.Add(p.cfg.Limits.Timeout)) {
		return capture.StopTimeout
	}
	return ""
}

func (p *Pipeline) addRecords(queue *batch.Queue[flow.Record], records []flow.Record) error {
	for _, record := range records {
		full, err := queue.Add(record)
		if err != nil {
			p.fail("batch queue failed: " + err.Error())
			return err
		}
		if err := p.persist(full); err != nil {
			return err
		}
	}
	return nil
}

func (p *Pipeline) persist(records []flow.Record) error {
	if len(records) == 0 {
		return nil
	}
	completed, err := flowbatch.New(records)
	if err != nil {
		return err
	}
	data, err := flowbatch.Encode(completed)
	if err != nil {
		return err
	}
	if !p.manager.Enqueue(spool.Batch{ID: completed.BatchID, Data: data, CreatedAt: p.cfg.Now()}) {
		return nil
	}
	p.refreshSpoolMetrics()
	return nil
}

func (p *Pipeline) refreshSpoolMetrics() {
	manager := p.manager.Snapshot()
	p.update(func(s *CaptureSnapshot) {
		s.PendingBytes = manager.PendingBytes
		s.LostBatches = manager.LostBatches
		s.LostBytes = manager.LostBytes
	})
	// Update DroppedPackets from latest periodic snapshot + decode errors.
	srcDrops := p.cachedDrop.Load()
	p.update(func(s *CaptureSnapshot) {
		s.DroppedPackets = srcDrops + s.DecodeErrors
		if len(s.Interfaces) > 0 {
			s.Interfaces[0].DroppedPackets = s.DroppedPackets
		}
	})
}

func (p *Pipeline) Snapshot() CaptureSnapshot {
	p.mu.RLock()
	out := p.snapshot
	out.ActiveJobs = append([]string(nil), out.ActiveJobs...)
	out.Interfaces = append([]InterfaceSnapshot(nil), out.Interfaces...)
	p.mu.RUnlock()
	manager := p.manager.Snapshot()
	out.PendingBytes = manager.PendingBytes
	out.LostBatches = manager.LostBatches
	out.LostBytes = manager.LostBytes
	if manager.LastError != "" {
		out.LastError = manager.LastError
	}

	return out
}

func (p *Pipeline) update(change func(*CaptureSnapshot)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	change(&p.snapshot)
}
func (p *Pipeline) fail(message string) {
	p.update(func(s *CaptureSnapshot) {
		s.LastError = message
		if len(s.Interfaces) > 0 {
			s.Interfaces[0].Status, s.Interfaces[0].LastError = "ERROR", message
		}
	})
}
func (p *Pipeline) setStopReason(reason capture.StopReason) {
	p.update(func(s *CaptureSnapshot) { s.StopReason = reason })
}

func servicePort(pkt packet.Packet) uint16 {
	for _, port := range []uint16{pkt.DestinationPort, pkt.SourcePort} {
		switch port {
		case 53, 80, 443, 8000, 8080, 8443:
			return port
		}
	}
	return pkt.DestinationPort
}

func recordSize(record flow.Record) int {
	completed, err := flowbatch.New([]flow.Record{record})
	if err != nil {
		return -1
	}
	data, err := flowbatch.Encode(completed)
	if err != nil {
		return -1
	}
	return len(data)
}

func isDuplicate(err error) bool {
	return err != nil && strings.Contains(err.Error(), "already exists")
}
