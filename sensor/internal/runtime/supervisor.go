package runtime

import (
	"context"
	"fmt"
	"sync"
)

// Supervisor owns the currently applied capture group. Apply performs a
// cancel-and-wait handoff so an interface is never captured by two versions.
type Supervisor struct {
	mu      sync.RWMutex
	ctx     context.Context
	group   *CaptureGroup
	cancel  context.CancelFunc
	done    chan error
	version int64
}

func NewSupervisor() *Supervisor { return &Supervisor{} }

func (s *Supervisor) Run(ctx context.Context) error {
	s.mu.Lock()
	s.ctx = ctx
	if s.group != nil && s.cancel == nil {
		s.startLocked(s.group)
	}
	done := s.done
	s.mu.Unlock()
	<-ctx.Done()
	s.stopCurrent()
	if done != nil {
		select {
		case <-done:
		default:
		}
	}
	return nil
}

func (s *Supervisor) Apply(version int64, members []CaptureRuntime) error {
	group, err := NewCaptureGroup(members)
	if err != nil {
		return fmt.Errorf("build capture group: %w", err)
	}
	s.stopCurrent()
	s.mu.Lock()
	s.group = group
	s.version = version
	if s.ctx != nil && s.ctx.Err() == nil {
		s.startLocked(group)
	}
	s.mu.Unlock()
	return nil
}

func (s *Supervisor) startLocked(group *CaptureGroup) {
	ctx, cancel := context.WithCancel(s.ctx)
	s.cancel = cancel
	s.done = make(chan error, 1)
	done := s.done
	go func() { done <- group.Run(ctx) }()
}

func (s *Supervisor) stopCurrent() {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.cancel, s.done = nil, nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
		if done != nil {
			<-done
		}
	}
}

func (s *Supervisor) Version() int64 { s.mu.RLock(); defer s.mu.RUnlock(); return s.version }
func (s *Supervisor) Snapshot() CaptureSnapshot {
	s.mu.RLock()
	group := s.group
	s.mu.RUnlock()
	if group == nil {
		return CaptureSnapshot{}
	}
	return group.Snapshot()
}
