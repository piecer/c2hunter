package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
)

// Supervisor owns the currently applied capture group. lifecycle serializes
// complete cancel-and-join handoffs, including Run startup and teardown. mu
// protects publication state only; it is never held across child calls or joins.
type Supervisor struct {
	lifecycle  sync.Mutex
	mu         sync.RWMutex
	ctx        context.Context
	group      *CaptureGroup
	owner      *captureOwner
	pending    bool
	version    int64
	generation uint64
	instanceID string
	initErr    error
}
type captureOwner struct {
	lifetime captureLifetime
	cancel   context.CancelFunc
	done     chan struct{}
}

func NewSupervisor() *Supervisor {
	var id [16]byte
	_, err := io.ReadFull(rand.Reader, id[:])
	return &Supervisor{instanceID: hex.EncodeToString(id[:]), initErr: err}
}

func (s *Supervisor) Run(ctx context.Context) error {
	s.lifecycle.Lock()
	s.mu.Lock()
	if s.initErr != nil {
		err := s.initErr
		s.mu.Unlock()
		s.lifecycle.Unlock()
		return err
	}
	if s.ctx != nil {
		s.mu.Unlock()
		s.lifecycle.Unlock()
		return fmt.Errorf("capture supervisor already running")
	}
	if s.group != nil && !s.pending {
		if s.generation >= maxReadinessInteger {
			s.mu.Unlock()
			s.lifecycle.Unlock()
			return fmt.Errorf("capture generation exhausted")
		}
		s.generation++
	}
	s.ctx = ctx
	if s.group != nil && ctx.Err() == nil {
		s.startLocked(s.group)
	}
	s.mu.Unlock()
	s.lifecycle.Unlock()
	<-ctx.Done()
	s.lifecycle.Lock()
	s.stopOwned()
	s.mu.Lock()
	s.ctx = nil
	s.mu.Unlock()
	s.lifecycle.Unlock()
	return nil
}

func (s *Supervisor) Apply(version int64, members []CaptureRuntime) error {
	group, err := NewCaptureGroup(members)
	if err != nil {
		return fmt.Errorf("build capture group: %w", err)
	}
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	s.mu.RLock()
	initErr := s.initErr
	full := s.generation >= maxReadinessInteger
	s.mu.RUnlock()
	if initErr != nil {
		return initErr
	}
	if full {
		return fmt.Errorf("capture generation exhausted")
	}
	s.stopOwned()
	s.mu.Lock()
	s.group = group
	s.version = version
	s.generation++
	s.pending = true
	if s.ctx != nil && s.ctx.Err() == nil {
		s.startLocked(group)
	}
	s.mu.Unlock()
	return nil
}

// Caller holds lifecycle and mu. Starting a goroutine does not wait on any
// child code. Each goroutine closes only its own completion channel.
func (s *Supervisor) startLocked(group *CaptureGroup) {
	ctx, cancel := context.WithCancel(s.ctx)
	owner := &captureOwner{lifetime: captureLifetime{ctx: ctx}, cancel: cancel, done: make(chan struct{})}
	s.owner = owner
	s.pending = false
	go func() {
		defer close(owner.done)
		defer owner.lifetime.terminal.Store(true)
		_ = group.Run(ctx)
	}()
}

func (s *Supervisor) stopCurrent() {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	s.stopOwned()
}

// Caller holds lifecycle, not mu. Revocation precedes cancellation and drain.
func (s *Supervisor) stopOwned() {
	s.mu.Lock()
	owner := s.owner
	s.owner = nil
	if owner != nil {
		owner.lifetime.terminal.Store(true)
	}
	s.mu.Unlock()
	if owner != nil {
		owner.cancel()
		<-owner.done
	}
}

const maxReadinessInteger = 9007199254740991

func (s *Supervisor) envelopeLocked() *CaptureReadiness {
	if s.initErr != nil || len(s.instanceID) != 32 || !readinessInstanceID.MatchString(s.instanceID) || s.generation == 0 || s.generation > maxReadinessInteger || s.version < 0 || s.version > maxReadinessInteger {
		return nil
	}
	return &CaptureReadiness{Version: 1, InstanceID: s.instanceID, Generation: s.generation, ConfigVersion: s.version, Interfaces: []CaptureReadyInterface{}}
}
func (s *Supervisor) Version() int64 { s.mu.RLock(); defer s.mu.RUnlock(); return s.version }
func (s *Supervisor) Snapshot() CaptureSnapshot {
	s.mu.RLock()
	group, owner, generation := s.group, s.owner, s.generation
	s.mu.RUnlock()
	var out CaptureSnapshot
	if group != nil {
		out = group.Snapshot()
	}
	var complete bool
	rows := []CaptureReadyInterface{}
	if out.observation != nil {
		complete, rows = out.observation.normalized()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	envelope := s.envelopeLocked()
	if group != s.group || owner != s.owner || generation != s.generation {
		return CaptureSnapshot{CaptureReadiness: envelope}
	}
	out.CaptureReadiness = envelope
	if envelope != nil && owner != nil && owner.lifetime.live() {
		envelope.Complete = complete
		envelope.Interfaces = rows
	}
	return out
}
