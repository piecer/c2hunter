package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
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

type PipelineConfig struct {
	SensorID, JobID              string
	Interface, Direction         string
	IdleTimeout                  time.Duration
	PayloadPreviewBytes          int
	BatchMaxItems, BatchMaxBytes int
	PacketQueueSize              int
	Source                       func() (capture.Reader, error)
	Filter                       *packet.Filter
	Limits                       capture.Limits
	Spool                        *spool.Spool
	Uploader                     FlowUploader
	Now                          func() time.Time
	IdleTicks                    <-chan time.Time
}

type CaptureSnapshot struct {
	ReceivedPackets uint64
	DroppedPackets  uint64
	DecodeErrors    uint64
	PendingBytes    uint64
	LostBatches     uint64
	LostBytes       uint64
	ActiveJobs      []string
	LastError       string
	StopReason      capture.StopReason
	Interfaces      []InterfaceSnapshot
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
	cfg      PipelineConfig
	mu       sync.RWMutex
	snapshot CaptureSnapshot
}

type packetEvent struct {
	packet packet.Packet
	err    error
}

func NewPipeline(cfg PipelineConfig) (*Pipeline, error) {
	if cfg.SensorID == "" || cfg.JobID == "" {
		return nil, fmt.Errorf("sensor and capture job IDs are required")
	}
	if cfg.Source == nil || cfg.Spool == nil || cfg.Uploader == nil {
		return nil, fmt.Errorf("packet source, spool and uploader are required")
	}
	if cfg.BatchMaxItems <= 0 || cfg.BatchMaxBytes <= 0 || cfg.PacketQueueSize <= 0 {
		return nil, fmt.Errorf("pipeline queue and batch limits must be positive")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Pipeline{cfg: cfg}, nil
}

func (p *Pipeline) Run(ctx context.Context) error {
	p.update(func(s *CaptureSnapshot) {
		s.ActiveJobs = []string{p.cfg.JobID}
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

	// Replay durable work before opening AF_PACKET. This preserves restart
	// delivery even while a capture interface is temporarily unavailable.
	p.drain(ctx)

	reader, err := p.cfg.Source()
	if err != nil {
		p.fail("capture open failed: " + err.Error())
		return err
	}
	defer reader.Close()

	readerCtx, cancelReader := context.WithCancel(ctx)
	defer cancelReader()
	events := make(chan packetEvent, p.cfg.PacketQueueSize)
	go p.readPackets(readerCtx, reader, events)

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

	finish := func(reason capture.StopReason) error {
		cancelReader()
		p.setStopReason(reason)
		if err := p.addRecords(queue, aggregator.Flush()); err != nil {
			return err
		}
		if err := p.persist(queue.Flush()); err != nil {
			return err
		}
		p.drain(ctx)
		return nil
	}

	for {
		if reason := p.asynchronousStop(ctx, started); reason != "" {
			return finish(reason)
		}
		select {
		case <-ctx.Done():
			return finish(capture.StopContext)
		case tick := <-idleTicks:
			if err := p.addRecords(queue, aggregator.Expire(tick)); err != nil {
				return err
			}
			if err := p.persist(queue.Flush()); err != nil {
				return err
			}
			p.drain(ctx)
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
			protocolMetadata, _ := metadata.Parse(servicePort(pkt), pkt.Payload)
			if err := p.addRecords(queue, aggregator.AddWithMetadata(pkt, protocolMetadata)); err != nil {
				return err
			}
			capturedPackets++
			capturedBytes += uint64(pkt.WireLength)
			sourceDrops := droppedPackets(reader)
			p.update(func(s *CaptureSnapshot) {
				s.ReceivedPackets++
				s.DroppedPackets = sourceDrops + s.DecodeErrors
				if len(s.Interfaces) > 0 {
					s.Interfaces[0].ReceivedPackets++
					s.Interfaces[0].DroppedPackets = s.DroppedPackets
				}
			})
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
			sourceDrops := droppedPackets(reader)
			p.update(func(s *CaptureSnapshot) {
				s.DecodeErrors++
				s.DroppedPackets = sourceDrops + s.DecodeErrors
				if len(s.Interfaces) > 0 {
					s.Interfaces[0].DecodeErrors++
					s.Interfaces[0].DroppedPackets = s.DroppedPackets
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

func droppedPackets(reader capture.Reader) uint64 {
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
	err = p.cfg.Spool.Put(spool.Batch{ID: completed.BatchID, Data: data, CreatedAt: p.cfg.Now()})
	if err != nil && !isDuplicate(err) {
		p.fail("spool write failed: " + err.Error())
		return err
	}
	p.refreshSpoolMetrics()
	p.drain(context.Background())
	return nil
}

func (p *Pipeline) drain(ctx context.Context) {
	pending, err := p.cfg.Spool.Pending()
	if err != nil {
		p.fail("spool read failed: " + err.Error())
		return
	}
	now := p.cfg.Now()
	for _, stored := range pending {
		if !stored.NextAttempt.IsZero() && stored.NextAttempt.After(now) {
			continue
		}
		completed, err := flowbatch.Decode(stored.Data)
		if err != nil {
			p.fail("spooled batch decode failed: " + err.Error())
			continue
		}
		ack, err := p.cfg.Uploader.UploadFlowBatch(ctx, completed)
		if err != nil || ack.BatchID != completed.BatchID || (!ack.Accepted && !ack.Duplicate) {
			if err == nil {
				err = fmt.Errorf("batch %s was not acknowledged", completed.BatchID)
			}
			_ = p.cfg.Spool.Retry(stored.ID)
			p.fail("flow batch upload failed: " + err.Error())
			break
		}
		if err := p.cfg.Spool.ACK(stored.ID); err != nil {
			p.fail("spool ACK failed: " + err.Error())
			break
		}
		p.update(func(s *CaptureSnapshot) {
			if len(s.ActiveJobs) > 0 {
				s.LastError = ""
			}
		})
	}
	p.refreshSpoolMetrics()
}

func (p *Pipeline) refreshSpoolMetrics() {
	pending, err := p.cfg.Spool.Pending()
	if err != nil {
		return
	}
	var bytes uint64
	for _, stored := range pending {
		bytes += uint64(len(stored.Data))
	}
	loss := p.cfg.Spool.Loss()
	p.update(func(s *CaptureSnapshot) {
		s.PendingBytes = bytes
		s.LostBatches = loss.Batches
		s.LostBytes = loss.Bytes
	})
}

func (p *Pipeline) Snapshot() CaptureSnapshot {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := p.snapshot
	out.ActiveJobs = append([]string(nil), out.ActiveJobs...)
	out.Interfaces = append([]InterfaceSnapshot(nil), out.Interfaces...)
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
