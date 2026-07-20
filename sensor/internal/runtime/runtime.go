package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"c2hunter/sensor/internal/telemetry"
)

type Status string

const (
	StatusOnline   Status = "ONLINE"
	StatusDegraded Status = "DEGRADED"
	StatusError    Status = "ERROR"
)

type Transport interface {
	Register(context.Context, telemetry.Registration) error
	Heartbeat(context.Context, telemetry.Heartbeat) error
	Close() error
}

type CaptureRuntime interface {
	Run(context.Context) error
	Snapshot() CaptureSnapshot
}

type Config struct {
	Registration      telemetry.Registration
	HeartbeatInterval time.Duration
	RetryInterval     time.Duration
	Capture           CaptureRuntime
}

type Health struct {
	Status     Status          `json:"status"`
	Registered bool            `json:"registered"`
	LastError  string          `json:"last_error,omitempty"`
	UpdatedAt  time.Time       `json:"updated_at"`
	Capture    CaptureSnapshot `json:"capture"`
}

type Runner struct {
	cfg       Config
	transport Transport
	mu        sync.RWMutex
	health    Health
}

func New(cfg Config, transport Transport) (*Runner, error) {
	if transport == nil {
		return nil, fmt.Errorf("transport is required")
	}
	if err := cfg.Registration.Validate(); err != nil {
		return nil, err
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = telemetry.DefaultHeartbeatInterval
	}
	if cfg.RetryInterval <= 0 {
		cfg.RetryInterval = 5 * time.Second
	}
	return &Runner{
		cfg:       cfg,
		transport: transport,
		health: Health{
			Status:    StatusDegraded,
			LastError: "registration pending",
			UpdatedAt: time.Now().UTC(),
		},
	}, nil
}

func (r *Runner) Run(ctx context.Context) error {
	defer r.transport.Close()
	if r.cfg.Capture != nil {
		go func() {
			if err := r.cfg.Capture.Run(ctx); err != nil {
				snapshot := r.cfg.Capture.Snapshot()
				message := snapshot.LastError
				if message == "" {
					message = "capture failed: " + err.Error()
				}
				r.setHealth(StatusDegraded, r.Health().Registered, message)
			}
		}()
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		registration := r.cfg.Registration
		registration.CurrentTime = time.Now().UTC()
		if r.cfg.Capture != nil {
			snapshot := r.cfg.Capture.Snapshot()
			registration.ReceivedPackets = snapshot.ReceivedPackets
			registration.DroppedPackets = snapshot.DroppedPackets
		}
		if err := r.transport.Register(ctx, registration); err != nil {
			r.setHealth(StatusDegraded, false, "registration failed: "+err.Error())
			log.Printf("sensor DEGRADED; controller registration failed, retrying in %s: %v", r.cfg.RetryInterval, err)
			if !wait(ctx, r.cfg.RetryInterval) {
				return nil
			}
			continue
		}
		status, lastError := r.captureHealth()
		r.setHealth(status, true, lastError)
		if r.runHeartbeats(ctx) {
			return nil
		}
	}
}

// runHeartbeats returns true when shutdown was requested and false when the
// controller connection failed and registration must be retried.
func (r *Runner) runHeartbeats(ctx context.Context) bool {
	ticker := time.NewTicker(r.cfg.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return true
		case <-ticker.C:
			health := r.Health()
			status, lastError := r.captureHealth()
			snapshot := CaptureSnapshot{}
			if r.cfg.Capture != nil {
				snapshot = r.cfg.Capture.Snapshot()
			}
			if lastError == "" {
				lastError = health.LastError
			}
			heartbeat := telemetry.Heartbeat{
				SensorID:        r.cfg.Registration.SensorID,
				Status:          telemetryStatus(status),
				CurrentTime:     time.Now().UTC(),
				LastError:       lastError,
				ActiveJobs:      snapshot.ActiveJobs,
				ReceivedPackets: snapshot.ReceivedPackets,
				DroppedPackets:  snapshot.DroppedPackets,
				PendingBytes:    snapshot.PendingBytes,
			}
			for _, item := range snapshot.Interfaces {
				heartbeat.Interfaces = append(heartbeat.Interfaces, telemetry.InterfaceStatus{Interface: item.Interface, Direction: item.Direction, Status: item.Status, ReceivedPackets: item.ReceivedPackets, DroppedPackets: item.DroppedPackets, LastError: item.LastError})
			}
			if err := r.transport.Heartbeat(ctx, heartbeat); err != nil {
				r.setHealth(StatusDegraded, false, "heartbeat failed: "+err.Error())
				log.Printf("sensor DEGRADED; heartbeat failed, registration will be retried: %v", err)
				return false
			}
		}
	}
}

func (r *Runner) Health() Health {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.health
}

func (r *Runner) setHealth(status Status, registered bool, lastError string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	snapshot := CaptureSnapshot{}
	if r.cfg.Capture != nil {
		snapshot = r.cfg.Capture.Snapshot()
	}
	r.health = Health{Status: status, Registered: registered, LastError: lastError, UpdatedAt: time.Now().UTC(), Capture: snapshot}
}

func (r *Runner) captureHealth() (Status, string) {
	if r.cfg.Capture == nil {
		return StatusOnline, ""
	}
	snapshot := r.cfg.Capture.Snapshot()
	if snapshot.LastError != "" {
		return StatusDegraded, snapshot.LastError
	}
	return StatusOnline, ""
}

func telemetryStatus(status Status) telemetry.Status {
	if status == StatusDegraded {
		return telemetry.StatusDegraded
	}
	if status == StatusError {
		return telemetry.StatusError
	}
	return telemetry.StatusOnline
}

func (r *Runner) HealthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		health := r.Health()
		w.Header().Set("Content-Type", "application/json")
		if health.Status == StatusError {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(health)
	})
}

func wait(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
