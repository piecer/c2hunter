package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"c2hunter/sensor/internal/telemetry"
)

type transportStub struct {
	mu             sync.Mutex
	registerErrors []error
	registrations  int
	heartbeats     []telemetry.Heartbeat
	closed         bool
}

func (s *transportStub) Register(context.Context, telemetry.Registration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.registrations++
	if len(s.registerErrors) == 0 {
		return nil
	}
	err := s.registerErrors[0]
	s.registerErrors = s.registerErrors[1:]
	return err
}
func (s *transportStub) Heartbeat(_ context.Context, h telemetry.Heartbeat) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.heartbeats = append(s.heartbeats, h)
	return nil
}
func (s *transportStub) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

type captureRuntimeStub struct {
	snapshot CaptureSnapshot
	err      error
}

func (s *captureRuntimeStub) Run(context.Context) error { return s.err }
func (s *captureRuntimeStub) Snapshot() CaptureSnapshot { return s.snapshot }

type shutdownCaptureRuntime struct {
	release chan struct{}
	done    chan struct{}
}

func (s *shutdownCaptureRuntime) Run(ctx context.Context) error {
	<-ctx.Done()
	<-s.release
	close(s.done)
	return nil
}

func (*shutdownCaptureRuntime) Snapshot() CaptureSnapshot { return CaptureSnapshot{} }

func registration() telemetry.Registration {
	return telemetry.Registration{SensorID: "sensor-a", Name: "Sensor A", Hostname: "host", AgentVersion: "test", OS: "linux", KernelVersion: "kernel", CurrentTime: time.Now(), Interfaces: []telemetry.Interface{{Name: "eth0", MAC: "00:00:00:00:00:00", Direction: "INBOUND"}}}
}

func TestRunnerClosesTransportAfterCaptureShutdownCompletes(t *testing.T) {
	transport := &transportStub{}
	capture := &shutdownCaptureRuntime{release: make(chan struct{}), done: make(chan struct{})}
	runner, err := New(Config{Registration: registration(), Capture: capture, HeartbeatInterval: time.Millisecond}, transport)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- runner.Run(ctx) }()
	cancel()
	time.Sleep(10 * time.Millisecond)
	transport.mu.Lock()
	closedEarly := transport.closed
	transport.mu.Unlock()
	if closedEarly {
		t.Fatal("transport closed before capture shutdown completed")
	}
	close(capture.release)
	if err := <-runDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-capture.done:
	default:
		t.Fatal("capture shutdown was not joined")
	}
}

func TestRunnerRetriesRegistrationAndNeverReportsOnlineBeforeSuccess(t *testing.T) {
	transport := &transportStub{registerErrors: []error{errors.New("gateway unavailable"), nil}}
	runner, err := New(Config{Registration: registration(), HeartbeatInterval: time.Millisecond, RetryInterval: time.Millisecond}, transport)
	if err != nil {
		t.Fatal(err)
	}
	if got := runner.Health().Status; got != StatusDegraded {
		t.Fatalf("initial status = %s", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for {
		transport.mu.Lock()
		registered, heartbeats := transport.registrations, append([]telemetry.Heartbeat(nil), transport.heartbeats...)
		transport.mu.Unlock()
		if registered >= 2 && len(heartbeats) > 0 {
			for _, heartbeat := range heartbeats {
				if heartbeat.Status != telemetry.StatusOnline {
					t.Fatalf("heartbeat after registration has status %s", heartbeat.Status)
				}
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("runner did not register and heartbeat")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !transport.closed {
		t.Fatal("transport was not closed on shutdown")
	}
}

func TestHealthHandlerExposesActualDegradedState(t *testing.T) {
	transport := &transportStub{}
	runner, err := New(Config{Registration: registration()}, transport)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	runner.HealthHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status code = %d", recorder.Code)
	}
	var health Health
	if err := json.NewDecoder(recorder.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	if health.Status != StatusDegraded || health.Registered {
		t.Fatalf("health = %+v", health)
	}
}

func TestRunnerReportsCaptureMetricsAndNeverOverstatesCaptureFailure(t *testing.T) {
	transport := &transportStub{}
	captureRuntime := &captureRuntimeStub{
		snapshot: CaptureSnapshot{ReceivedPackets: 12, DroppedPackets: 3, PendingBytes: 456, ActiveJobs: []string{"job-a"}, LastError: "AF_PACKET permission denied"},
		err:      errors.New("AF_PACKET permission denied"),
	}
	runner, err := New(Config{
		Registration: registration(), Capture: captureRuntime,
		HeartbeatInterval: time.Millisecond, RetryInterval: time.Millisecond,
		DiscoverInterfaces: func() ([]telemetry.Interface, error) {
			return []telemetry.Interface{{Name: "eth0"}, {Name: "eth1"}}, nil
		},
	}, transport)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for {
		transport.mu.Lock()
		heartbeats := append([]telemetry.Heartbeat(nil), transport.heartbeats...)
		transport.mu.Unlock()
		if len(heartbeats) > 0 {
			got := heartbeats[len(heartbeats)-1]
			if got.Status != telemetry.StatusDegraded || got.ReceivedPackets != 12 || got.DroppedPackets != 3 || got.PendingBytes != 456 || len(got.ActiveJobs) != 1 || len(got.DiscoveredInterfaces) != 2 {
				t.Fatalf("heartbeat = %+v", got)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("heartbeat was not sent")
		}
		time.Sleep(time.Millisecond)
	}
	if runner.Health().Status != StatusDegraded {
		t.Fatalf("health = %+v", runner.Health())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
