package spool

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
)

type Limits struct {
	MaxBytes int64
	MaxAge   time.Duration
}
type Batch struct {
	ID          string    `json:"id"`
	Data        []byte    `json:"data"`
	CreatedAt   time.Time `json:"created_at"`
	Attempts    int       `json:"attempts"`
	NextAttempt time.Time `json:"next_attempt"`
}
type LossReport struct {
	Batches uint64 `json:"batches"`
	Bytes   uint64 `json:"bytes"`
}
type Spool struct {
	mu     sync.Mutex
	dir    string
	limits Limits
	now    func() time.Time
	loss   LossReport
}

var safeID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func Open(dir string, limits Limits, now func() time.Time) (*Spool, error) {
	if limits.MaxBytes <= 0 {
		return nil, fmt.Errorf("max bytes must be positive")
	}
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	s := &Spool{dir: dir, limits: limits, now: now}
	data, err := os.ReadFile(filepath.Join(dir, ".loss.json"))
	if err == nil {
		if err := json.Unmarshal(data, &s.loss); err != nil {
			return nil, fmt.Errorf("load loss report: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}
func (s *Spool) Put(batch Batch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !safeID.MatchString(batch.ID) {
		return fmt.Errorf("invalid batch ID")
	}
	path := s.path(batch.ID)
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("batch %s already exists", batch.ID)
	} else if !os.IsNotExist(err) {
		return err
	}
	if batch.CreatedAt.IsZero() {
		batch.CreatedAt = s.now()
	}
	if int64(len(batch.Data)) > s.limits.MaxBytes {
		return fmt.Errorf("batch exceeds spool size")
	}
	if err := s.write(batch); err != nil {
		return err
	}
	return s.enforce()
}
func (s *Spool) ACK(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !safeID.MatchString(id) {
		return fmt.Errorf("invalid batch ID")
	}
	err := os.Remove(s.path(id))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
func (s *Spool) Retry(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.read(id)
	if err != nil {
		return err
	}
	b.Attempts++
	delay := time.Second * time.Duration(1<<min(b.Attempts-1, 6))
	b.NextAttempt = s.now().Add(delay)
	return s.write(b)
}
func (s *Spool) Pending() ([]Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enforce(); err != nil {
		return nil, err
	}
	return s.load()
}
func (s *Spool) Loss() LossReport      { s.mu.Lock(); defer s.mu.Unlock(); return s.loss }
func (s *Spool) path(id string) string { return filepath.Join(s.dir, id+".json") }
func (s *Spool) read(id string) (Batch, error) {
	if !safeID.MatchString(id) {
		return Batch{}, fmt.Errorf("invalid batch ID")
	}
	data, err := os.ReadFile(s.path(id))
	if err != nil {
		return Batch{}, err
	}
	var b Batch
	if err := json.Unmarshal(data, &b); err != nil {
		return Batch{}, err
	}
	return b, nil
}
func (s *Spool) load() ([]Batch, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var out []Batch
	for _, entry := range entries {
		if entry.IsDir() || entry.Name()[0] == '.' || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		id := entry.Name()[:len(entry.Name())-5]
		b, err := s.read(id)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}
func (s *Spool) enforce() error {
	batches, err := s.load()
	if err != nil {
		return err
	}
	now := s.now()
	var total int64
	for _, b := range batches {
		total += int64(len(b.Data))
	}
	for _, b := range batches {
		expired := s.limits.MaxAge > 0 && !now.Before(b.CreatedAt.Add(s.limits.MaxAge))
		oversize := total > s.limits.MaxBytes
		if !expired && !oversize {
			continue
		}
		if err := os.Remove(s.path(b.ID)); err != nil {
			return err
		}
		total -= int64(len(b.Data))
		s.loss.Batches++
		s.loss.Bytes += uint64(len(b.Data))
	}
	return s.persistLoss()
}
func (s *Spool) write(b Batch) error {
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, ".batch-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, s.path(b.ID))
}
func (s *Spool) persistLoss() error {
	data, err := json.Marshal(s.loss)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, ".loss.json"), data, 0600)
}
