package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"c2hunter/sensor/internal/packet"
	pcapstore "c2hunter/sensor/internal/pcap"
)

type PCAPWriterConfig struct {
	JobID        string
	Rotator      *pcapstore.Rotator
	QueueSize    int
	Directory    string
	MaxDiskBytes int64
	Startup      *PCAPStartup
	Budget       *PCAPBudget
}

type PCAPBudget struct {
	mu                   sync.Mutex
	maxPackets, maxBytes uint64
	packets, bytes       uint64
}

func NewPCAPBudget(maxPackets, maxBytes uint64) *PCAPBudget {
	return &PCAPBudget{maxPackets: maxPackets, maxBytes: maxBytes}
}

func (b *PCAPBudget) Exhausted() bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return (b.maxPackets > 0 && b.packets >= b.maxPackets) ||
		(b.maxBytes > 0 && b.bytes >= b.maxBytes)
}

func (b *PCAPBudget) Reserve(bytes uint64) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.maxPackets > 0 && b.packets >= b.maxPackets {
		return false
	}
	if b.maxBytes > 0 && (bytes > b.maxBytes-b.bytes) {
		return false
	}
	b.packets++
	b.bytes += bytes
	return true
}

func (b *PCAPBudget) Release(bytes uint64) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.packets > 0 {
		b.packets--
	}
	if bytes <= b.bytes {
		b.bytes -= bytes
	}
}

type PCAPStartup struct {
	directory string
	once      sync.Once
	err       error
}

func NewPCAPStartup(directory string) *PCAPStartup {
	return &PCAPStartup{directory: directory}
}

func (s *PCAPStartup) Prepare() error {
	s.once.Do(func() { s.err = pcapstore.RecoverPartialSegments(s.directory) })
	return s.err
}

type PCAPWriter struct {
	cfg      PCAPWriterConfig
	queue    chan packet.Packet
	slots    chan struct{}
	mu       sync.RWMutex
	snapshot CaptureSnapshot
}

var pcapDiskMu sync.Mutex

func NewPCAPWriter(cfg PCAPWriterConfig) (*PCAPWriter, error) {
	if cfg.Rotator == nil {
		return nil, fmt.Errorf("PCAP rotator is required")
	}
	if cfg.QueueSize <= 0 {
		return nil, fmt.Errorf("PCAP queue size must be positive")
	}
	if cfg.MaxDiskBytes < 0 {
		return nil, fmt.Errorf("PCAP disk limit cannot be negative")
	}
	if cfg.MaxDiskBytes > 0 && cfg.Directory == "" {
		return nil, fmt.Errorf("PCAP directory is required with a disk limit")
	}
	return &PCAPWriter{cfg: cfg, queue: make(chan packet.Packet, cfg.QueueSize), slots: make(chan struct{}, cfg.QueueSize)}, nil
}

func (w *PCAPWriter) Enqueue(pkt packet.Packet) bool {
	if len(pkt.RawFrame) == 0 {
		w.drop("raw frame is unavailable for PCAP storage")
		return false
	}
	if w.cfg.Budget != nil && w.cfg.Budget.Exhausted() {
		w.drop("analysis PCAP limit reached")
		return false
	}
	select {
	case w.slots <- struct{}{}:
	default:
		w.drop("PCAP writer queue is full")
		return false
	}
	pkt.RawFrame = append([]byte(nil), pkt.RawFrame...)
	pkt.CapturedLength = len(pkt.RawFrame)
	if pkt.WireLength < pkt.CapturedLength {
		pkt.WireLength = pkt.CapturedLength
	}
	w.queue <- pkt
	return true
}

func (w *PCAPWriter) Run(ctx context.Context) error {
	w.setActiveJob(true)
	defer w.setActiveJob(false)
	if w.cfg.Startup != nil {
		if err := w.cfg.Startup.Prepare(); err != nil {
			w.fail("recover PCAP segments: " + err.Error())
			return err
		}
	}
	for {
		select {
		case pkt := <-w.queue:
			<-w.slots
			w.write(pkt)
		case <-ctx.Done():
			for {
				select {
				case pkt := <-w.queue:
					<-w.slots
					w.write(pkt)
				default:
					if err := w.cfg.Rotator.Close(); err != nil {
						w.fail("close PCAP rotator: " + err.Error())
						return err
					}
					return nil
				}
			}
		}
	}
}

func (w *PCAPWriter) write(pkt packet.Packet) {
	info := pcapstore.PacketInfo{Timestamp: pkt.Timestamp, CaptureLength: len(pkt.RawFrame), WireLength: pkt.WireLength}
	needed := w.cfg.Rotator.EstimatedWriteBytes(info, len(pkt.RawFrame))
	reserved := false
	if w.cfg.Budget != nil {
		if !w.cfg.Budget.Reserve(uint64(needed)) {
			w.drop("analysis PCAP limit reached")
			return
		}
		reserved = true
	}
	if w.cfg.MaxDiskBytes > 0 {
		pcapDiskMu.Lock()
		defer pcapDiskMu.Unlock()
		ok, err := makePCAPRoom(w.cfg.Directory, w.cfg.MaxDiskBytes, needed)
		if err != nil {
			if reserved {
				w.cfg.Budget.Release(uint64(needed))
			}
			w.drop("enforce PCAP disk limit: " + err.Error())
			return
		}
		if !ok {
			if reserved {
				w.cfg.Budget.Release(uint64(needed))
			}
			w.drop("PCAP disk limit reached")
			return
		}
	}
	if err := w.cfg.Rotator.WritePacket(info, pkt.RawFrame); err != nil {
		if reserved {
			w.cfg.Budget.Release(uint64(needed))
		}
		w.drop("write PCAP packet: " + err.Error())
		return
	}
	w.clearError()
}

func (w *PCAPWriter) Snapshot() CaptureSnapshot {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.snapshot
}

func (w *PCAPWriter) setActiveJob(active bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.snapshot.ActiveJobs = nil
	if active && w.cfg.JobID != "" {
		w.snapshot.ActiveJobs = []string{w.cfg.JobID}
	}
}

func (*PCAPWriter) backgroundRuntime() {}

func (w *PCAPWriter) drop(message string) {
	w.mu.Lock()
	w.snapshot.PCAPDroppedPackets++
	w.snapshot.LastError = message
	w.mu.Unlock()
}

func (w *PCAPWriter) fail(message string) {
	w.mu.Lock()
	w.snapshot.LastError = message
	w.mu.Unlock()
}

func (w *PCAPWriter) clearError() {
	w.mu.Lock()
	w.snapshot.LastError = ""
	w.mu.Unlock()
}

type pcapDiskFile struct {
	path    string
	size    int64
	modTime int64
	final   bool
}

func makePCAPRoom(directory string, maxBytes, needed int64) (bool, error) {
	entries, err := os.ReadDir(directory)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(directory, 0700); err != nil {
			return false, err
		}
		entries = nil
	} else if err != nil {
		return false, err
	}
	var total int64
	var finalized []pcapDiskFile
	for _, entry := range entries {
		isEvictable := strings.HasSuffix(entry.Name(), ".pcap.uploaded") || strings.Contains(entry.Name(), ".pcap.corrupt-")
		isPending := strings.HasSuffix(entry.Name(), ".pcap")
		isActive := strings.HasSuffix(entry.Name(), ".pcap.partial") || strings.HasSuffix(entry.Name(), ".pcap.uploading")
		if entry.IsDir() || (!isEvictable && !isPending && !isActive) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return false, err
		}
		item := pcapDiskFile{path: filepath.Join(directory, entry.Name()), size: info.Size(), modTime: info.ModTime().UnixNano(), final: isEvictable}
		total += item.size
		if item.final {
			finalized = append(finalized, item)
		}
	}
	sort.Slice(finalized, func(i, j int) bool { return finalized[i].modTime < finalized[j].modTime })
	for _, item := range finalized {
		if total+needed <= maxBytes {
			break
		}
		if err := os.Remove(item.path); err != nil && !os.IsNotExist(err) {
			return false, err
		}
		total -= item.size
	}
	return total+needed <= maxBytes, nil
}
