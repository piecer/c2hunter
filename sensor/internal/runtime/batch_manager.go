package runtime

import (
	"context"
	"fmt"
	"sync"
	"time"

	"c2hunter/sensor/internal/flowbatch"
	"c2hunter/sensor/internal/spool"
)

// BatchStore is the durable storage contract used by BatchManager.
type BatchStore interface {
	Put(spool.Batch) error
	Pending() ([]spool.Batch, error)
	ACK(string) error
	Retry(string) error
	Loss() spool.LossReport
}

type BatchManagerConfig struct {
	Store          BatchStore
	Uploader       FlowUploader
	QueueSize      int
	UploadInterval time.Duration
	Now            func() time.Time
}

// BatchManager decouples capture from disk and network waits. Enqueue is always
// non-blocking; a full bounded queue is accounted as local loss.
type BatchManager struct {
	cfg              BatchManagerConfig
	queue            chan spool.Batch
	uploadNow        chan struct{}
	startOnce        sync.Once
	done             chan struct{}
	mu               sync.RWMutex
	snapshot         CaptureSnapshot
	queueLostBatches uint64
	queueLostBytes   uint64
}

func NewBatchManager(cfg BatchManagerConfig) (*BatchManager, error) {
	if cfg.Store == nil || cfg.Uploader == nil {
		return nil, fmt.Errorf("batch store and uploader are required")
	}
	if cfg.QueueSize <= 0 {
		return nil, fmt.Errorf("batch manager queue size must be positive")
	}
	if cfg.UploadInterval <= 0 {
		cfg.UploadInterval = time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &BatchManager{
		cfg:       cfg,
		queue:     make(chan spool.Batch, cfg.QueueSize),
		uploadNow: make(chan struct{}, 1),
		done:      make(chan struct{}),
	}, nil
}

func (m *BatchManager) Start(ctx context.Context) {
	m.startOnce.Do(func() {
		go func() {
			var workers sync.WaitGroup
			writerDone := make(chan struct{})
			workers.Add(2)
			go func() {
				defer workers.Done()
				defer close(writerDone)
				m.writeLoop(ctx)
			}()
			go func() { defer workers.Done(); m.uploadLoop(ctx, writerDone) }()
			workers.Wait()
			close(m.done)
		}()
	})
}

func (m *BatchManager) Done() <-chan struct{} { return m.done }

func (m *BatchManager) Run(ctx context.Context) error {
	m.Start(ctx)
	<-m.Done()
	return nil
}

func (m *BatchManager) Snapshot() CaptureSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.snapshot
}

func (*BatchManager) backgroundRuntime() {}

func (m *BatchManager) Enqueue(batch spool.Batch) bool {
	select {
	case m.queue <- batch:
		return true
	default:
		m.recordLocalLoss(batch, "flow batch queue is full")
		return false
	}
}

func (m *BatchManager) writeLoop(ctx context.Context) {
	for {
		select {
		case batch := <-m.queue:
			m.write(batch)
		case <-ctx.Done():
			for {
				select {
				case batch := <-m.queue:
					m.write(batch)
				default:
					return
				}
			}
		}
	}
}

func (m *BatchManager) write(batch spool.Batch) {
	if err := m.cfg.Store.Put(batch); err != nil && !isDuplicate(err) {
		m.recordLocalLoss(batch, "spool write failed: "+err.Error())
		return
	}
	m.refreshMetrics()
	select {
	case m.uploadNow <- struct{}{}:
	default:
	}
}

func (m *BatchManager) uploadLoop(ctx context.Context, writerDone <-chan struct{}) {
	ticker := time.NewTicker(m.cfg.UploadInterval)
	defer ticker.Stop()
	m.drain(ctx, false)
	for {
		select {
		case <-ctx.Done():
			<-writerDone
			finalCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			m.drain(finalCtx, true)
			cancel()
			return
		case <-m.uploadNow:
			m.drain(ctx, false)
		case <-ticker.C:
			m.drain(ctx, false)
		}
	}
}

func (m *BatchManager) drain(ctx context.Context, force bool) {
	pending, err := m.cfg.Store.Pending()
	if err != nil {
		m.fail("spool read failed: " + err.Error())
		return
	}
	now := m.cfg.Now()
	hadError := false
	for _, stored := range pending {
		if ctx.Err() != nil {
			break
		}
		if !force && !stored.NextAttempt.IsZero() && stored.NextAttempt.After(now) {
			continue
		}
		completed, err := flowbatch.Decode(stored.Data)
		if err != nil {
			hadError = true
			m.fail("spooled batch decode failed: " + err.Error())
			continue
		}
		ack, err := m.cfg.Uploader.UploadFlowBatch(ctx, completed)
		if err != nil || ack.BatchID != completed.BatchID || (!ack.Accepted && !ack.Duplicate) {
			hadError = true
			if err == nil {
				err = fmt.Errorf("batch %s was not acknowledged", completed.BatchID)
			}
			_ = m.cfg.Store.Retry(stored.ID)
			m.fail("flow batch upload failed: " + err.Error())
			if force {
				continue
			}
			break
		}
		if err := m.cfg.Store.ACK(stored.ID); err != nil {
			hadError = true
			m.fail("spool ACK failed: " + err.Error())
			if force {
				continue
			}
			break
		}
		m.mu.Lock()
		if !hadError {
			m.snapshot.LastError = ""
		}
		m.mu.Unlock()
	}
	m.refreshMetrics()
}

func (m *BatchManager) refreshMetrics() {
	pending, err := m.cfg.Store.Pending()
	if err != nil {
		m.fail("spool read failed: " + err.Error())
		return
	}
	var bytes uint64
	for _, stored := range pending {
		bytes += uint64(len(stored.Data))
	}
	loss := m.cfg.Store.Loss()
	m.mu.Lock()
	m.snapshot.PendingBytes = bytes
	m.snapshot.LostBatches = loss.Batches + m.queueLostBatches
	m.snapshot.LostBytes = loss.Bytes + m.queueLostBytes
	m.mu.Unlock()
}

func (m *BatchManager) fail(message string) {
	m.mu.Lock()
	m.snapshot.LastError = message
	m.mu.Unlock()
}

func (m *BatchManager) recordLocalLoss(batch spool.Batch, message string) {
	m.mu.Lock()
	m.queueLostBatches++
	m.queueLostBytes += uint64(len(batch.Data))
	m.snapshot.LostBatches = m.queueLostBatches
	m.snapshot.LostBytes = m.queueLostBytes
	m.snapshot.LastError = message
	m.mu.Unlock()
}
