package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type PCAPSegmentUploader interface {
	UploadPCAPSegment(context.Context, string, string, string, string, io.Reader, int64) error
}

type PCAPArchiveManagerConfig struct {
	Directory    string
	SensorID     string
	Uploader     PCAPSegmentUploader
	ScanInterval time.Duration
	FinalTimeout time.Duration
	Startup      *PCAPStartup
}

type PCAPArchiveManager struct {
	cfg         PCAPArchiveManagerConfig
	mu          sync.RWMutex
	snapshot    CaptureSnapshot
	blockedJobs map[string]struct{}
}

type pcapUploadClaim struct {
	path     string
	original string
	filename string
	size     int64
	modTime  time.Time
}

func NewPCAPArchiveManager(cfg PCAPArchiveManagerConfig) (*PCAPArchiveManager, error) {
	if cfg.Directory == "" {
		return nil, fmt.Errorf("PCAP archive directory is required")
	}
	if cfg.SensorID == "" {
		return nil, fmt.Errorf("sensor ID is required for PCAP archive upload")
	}
	if cfg.Uploader == nil {
		return nil, fmt.Errorf("PCAP segment uploader is required")
	}
	if cfg.ScanInterval <= 0 {
		cfg.ScanInterval = time.Second
	}
	if cfg.FinalTimeout <= 0 {
		cfg.FinalTimeout = 30 * time.Second
	}
	return &PCAPArchiveManager{cfg: cfg, blockedJobs: make(map[string]struct{})}, nil
}

type permanentPCAPUploadError interface {
	Permanent() bool
}

func (m *PCAPArchiveManager) Run(ctx context.Context) error {
	if m.cfg.Startup != nil {
		if err := m.cfg.Startup.Prepare(); err != nil {
			m.fail("recover PCAP segments: " + err.Error())
			return err
		}
	}
	ticker := time.NewTicker(m.cfg.ScanInterval)
	defer ticker.Stop()
	m.uploadAvailable(ctx)
	for {
		select {
		case <-ctx.Done():
			finalCtx, cancel := context.WithTimeout(context.Background(), m.cfg.FinalTimeout)
			defer cancel()
			if err := waitForPCAPFinalization(finalCtx, m.cfg.Directory); err != nil {
				m.fail("wait for PCAP finalization: " + err.Error())
				return nil
			}
			m.uploadAvailable(finalCtx)
			return nil
		case <-ticker.C:
			m.uploadAvailable(ctx)
		}
	}
}

func waitForPCAPFinalization(ctx context.Context, directory string) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		entries, err := os.ReadDir(directory)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		partial := false
		for _, entry := range entries {
			if !entry.IsDir() && entry.Type()&os.ModeSymlink == 0 && strings.HasSuffix(entry.Name(), ".pcap.partial") {
				partial = true
				break
			}
		}
		if !partial {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (m *PCAPArchiveManager) uploadAvailable(ctx context.Context) {
	for ctx.Err() == nil {
		claim, err := claimOldestPCAP(m.cfg.Directory)
		if err != nil {
			m.fail("scan PCAP archive: " + err.Error())
			return
		}
		if claim == nil {
			m.clearError()
			return
		}
		jobID := analysisJobIDFromPCAPFilename(claim.filename)
		m.mu.RLock()
		_, blocked := m.blockedJobs[jobID]
		m.mu.RUnlock()
		if jobID != "" && blocked {
			_ = rejectPCAPClaim(*claim)
			continue
		}
		if err := m.uploadClaim(ctx, *claim); err != nil {
			if permanent, ok := err.(permanentPCAPUploadError); ok && permanent.Permanent() {
				if jobID != "" {
					m.mu.Lock()
					m.blockedJobs[jobID] = struct{}{}
					m.mu.Unlock()
				}
				_ = rejectPCAPClaim(*claim)
				m.fail("PCAP upload permanently rejected: " + err.Error())
				continue
			}
			restorePCAPClaim(*claim)
			if ctx.Err() == nil {
				m.fail("upload PCAP segment: " + err.Error())
			}
			return
		}
		if err := completePCAPClaim(*claim); err != nil {
			m.fail("finalize PCAP upload: " + err.Error())
			return
		}
		m.clearError()
	}
}

func (m *PCAPArchiveManager) uploadClaim(ctx context.Context, claim pcapUploadClaim) error {
	file, err := os.Open(claim.path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != claim.size {
		return fmt.Errorf("claimed PCAP changed before upload")
	}
	digest := sha256.Sum256([]byte(m.cfg.SensorID + "\x00" + claim.filename))
	return m.cfg.Uploader.UploadPCAPSegment(
		ctx,
		m.cfg.SensorID,
		hex.EncodeToString(digest[:]),
		analysisJobIDFromPCAPFilename(claim.filename),
		claim.filename,
		file,
		claim.size,
	)
}

func analysisJobIDFromPCAPFilename(filename string) string {
	jobID, _, found := strings.Cut(filepath.Base(filename), "--")
	if !found {
		return ""
	}
	return jobID
}

func claimOldestPCAP(directory string) (*pcapUploadClaim, error) {
	pcapDiskMu.Lock()
	defer pcapDiskMu.Unlock()
	entries, err := os.ReadDir(directory)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	claims := make([]pcapUploadClaim, 0)
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || (!strings.HasSuffix(entry.Name(), ".pcap") && !strings.HasSuffix(entry.Name(), ".pcap.uploading")) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		original := strings.TrimSuffix(path, ".uploading")
		claims = append(claims, pcapUploadClaim{
			path: path, original: original, filename: filepath.Base(original), size: info.Size(), modTime: info.ModTime(),
		})
	}
	if len(claims) == 0 {
		return nil, nil
	}
	sort.Slice(claims, func(i, j int) bool { return claims[i].modTime.Before(claims[j].modTime) })
	claim := claims[0]
	if claim.path == claim.original {
		claim.path += ".uploading"
		if err := os.Rename(claim.original, claim.path); err != nil {
			return nil, err
		}
	}
	return &claim, nil
}

func restorePCAPClaim(claim pcapUploadClaim) {
	pcapDiskMu.Lock()
	defer pcapDiskMu.Unlock()
	if _, err := os.Stat(claim.original); err == nil {
		return
	}
	_ = os.Rename(claim.path, claim.original)
}

func completePCAPClaim(claim pcapUploadClaim) error {
	pcapDiskMu.Lock()
	defer pcapDiskMu.Unlock()
	return os.Rename(claim.path, claim.original+".uploaded")
}

func rejectPCAPClaim(claim pcapUploadClaim) error {
	pcapDiskMu.Lock()
	defer pcapDiskMu.Unlock()
	return os.Rename(claim.path, claim.original+".rejected")
}

func (m *PCAPArchiveManager) Snapshot() CaptureSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.snapshot
}

func (*PCAPArchiveManager) backgroundRuntime()         {}
func (*PCAPArchiveManager) trailingBackgroundRuntime() {}

func (m *PCAPArchiveManager) fail(message string) {
	m.mu.Lock()
	m.snapshot.LastError = message
	m.mu.Unlock()
}

func (m *PCAPArchiveManager) clearError() {
	m.mu.Lock()
	m.snapshot.LastError = ""
	m.mu.Unlock()
}
