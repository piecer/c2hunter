package runtime

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"regexp"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"c2hunter/sensor/internal/batch"
	"c2hunter/sensor/internal/capture"
	"c2hunter/sensor/internal/flow"
	"c2hunter/sensor/internal/flowbatch"
	"c2hunter/sensor/internal/packet"
	"c2hunter/sensor/internal/telemetry"
)

type readinessReader struct{ entered chan struct{} }

func (r *readinessReader) Next(ctx context.Context) (packet.Packet, error) {
	close(r.entered)
	<-ctx.Done()
	return packet.Packet{}, ctx.Err()
}
func (r *readinessReader) Close() error { return nil }

func readinessPipeline(t *testing.T, source func() (capture.Reader, error)) *Pipeline {
	t.Helper()
	p, err := NewPipeline(PipelineConfig{SensorID: "sensor-a", JobID: "synthetic", ActiveJobIDs: []string{"actual-job"}, Interface: "eth0", Direction: "INBOUND", BatchMaxItems: 10, BatchMaxBytes: 64 << 10, PacketQueueSize: 1, Source: source, Spool: openTestSpool(t, t.TempDir(), time.Now), Uploader: &uploadStub{}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func awaitReadiness(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("barrier timed out")
	}
}
func localReadiness(t *testing.T, r *Runner) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	r.HealthHandler().ServeHTTP(w, httptest.NewRequest("GET", "/health", nil))
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	c := body["capture"].(map[string]any)
	value, ok := c["capture_readiness"].(map[string]any)
	if !ok {
		t.Fatalf("missing authoritative local readiness: %s", w.Body.String())
	}
	return value
}
func TestReadinessLocalHealthBlockedSourceThenReady(t *testing.T) {
	opened, release := make(chan struct{}), make(chan struct{})
	reader := &readinessReader{entered: make(chan struct{})}
	p := readinessPipeline(t, func() (capture.Reader, error) { close(opened); <-release; return reader, nil })
	s := NewSupervisor()
	if err := s.Apply(7, []CaptureRuntime{p}); err != nil {
		t.Fatal(err)
	}
	runner, err := New(Config{Registration: registration(), Capture: s}, &transportStub{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = runner.Run(ctx) }()
	released := false
	defer func() {
		cancel()
		if !released {
			close(release)
		}
		awaitReadiness(t, done)
	}()
	awaitReadiness(t, opened)
	legacy := p.Snapshot()
	if len(legacy.ActiveJobs) != 1 || len(legacy.Interfaces) != 1 || legacy.Interfaces[0].Status != "CAPTURING" {
		t.Fatal("legacy capture facts missing before acquisition")
	}
	blocked := localReadiness(t, runner)
	rows := blocked["interfaces"].([]any)
	if blocked["complete"] != true || len(rows) != 1 || rows[0].(map[string]any)["capture_ready"] != false {
		t.Fatalf("blocked source observation = %v", blocked)
	}
	close(release)
	released = true
	awaitReadiness(t, reader.entered)
	ready := localReadiness(t, runner)
	rows = ready["interfaces"].([]any)
	if ready["complete"] != true || len(rows) != 1 || rows[0].(map[string]any)["capture_ready"] != true {
		t.Fatalf("acquired source not ready: %v", ready)
	}
	row := rows[0].(map[string]any)
	if row["interface"] != "eth0" || row["direction"] != "INBOUND" || row["job_ids"].([]any)[0] != "actual-job" || ready["generation"] != float64(1) || ready["config_version"] != float64(7) {
		t.Fatalf("wrong ownership association: %v", ready)
	}
	if p.Snapshot().ReceivedPackets != 0 {
		t.Fatal("readiness required packets")
	}
}

type countedReadinessReader struct{ next, closed int }

func (r *countedReadinessReader) Next(context.Context) (packet.Packet, error) {
	r.next++
	return packet.Packet{}, context.Canceled
}
func (r *countedReadinessReader) Close() error { r.closed++; return nil }
func TestReadinessCancellationDuringSourceDoesNotLaunchLateReader(t *testing.T) {
	opened, release := make(chan struct{}), make(chan struct{})
	reader := &countedReadinessReader{}
	p := readinessPipeline(t, func() (capture.Reader, error) { close(opened); <-release; return reader, nil })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = p.Run(ctx) }()
	awaitReadiness(t, opened)
	cancel()
	if p.Snapshot().observation.interfaces[0].CaptureReady {
		t.Error("blocked canceled Source ready")
	}
	select {
	case <-done:
		t.Error("blocked Source claimed finished")
	default:
	}
	close(release)
	awaitReadiness(t, done)
	if reader.next != 0 || reader.closed != 1 {
		t.Fatalf("late reader Next=%d Close=%d", reader.next, reader.closed)
	}
}
func TestReadinessCanceledBeforeSource(t *testing.T) {
	calls := 0
	p := readinessPipeline(t, func() (capture.Reader, error) { calls++; return &countedReadinessReader{}, nil })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = p.Run(ctx)
	if calls != 0 {
		t.Fatalf("Source called after cancellation: %d", calls)
	}
}

func TestReadinessNilSourceFailsWithoutPanic(t *testing.T) {
	p := readinessPipeline(t, func() (capture.Reader, error) { return nil, nil })
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil Source panicked: %v", r)
		}
	}()
	if err := p.Run(context.Background()); err == nil {
		t.Fatal("nil reader accepted")
	}
	if p.Snapshot().observation.interfaces[0].CaptureReady {
		t.Fatal("nil reader ready")
	}
}

func TestReadinessCancellationMasksUncooperativeReader(t *testing.T) {
	reader := &blockingLifecycleSource{entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	p := readinessPipeline(t, func() (capture.Reader, error) { return reader, nil })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = p.Run(ctx) }()
	awaitReadiness(t, reader.entered)
	cancel()
	if p.Snapshot().observation.interfaces[0].CaptureReady {
		t.Error("canceled uncooperative reader still ready")
	}
	select {
	case <-done:
		t.Error("uncooperative Next claimed complete")
	default:
	}
	select {
	case <-reader.closed:
		t.Error("closed before Next joined")
	default:
	}
	close(reader.release)
	awaitReadiness(t, done)
}

type terminalReadinessReader struct {
	err                        error
	statsEntered, statsRelease chan struct{}
	statsOnce                  sync.Once
	closed                     int
}

func (r *terminalReadinessReader) Next(context.Context) (packet.Packet, error) {
	return packet.Packet{}, r.err
}
func (r *terminalReadinessReader) DroppedPackets() uint64 {
	r.statsOnce.Do(func() { close(r.statsEntered) })
	<-r.statsRelease
	return 0
}
func (r *terminalReadinessReader) Close() error { r.closed++; return nil }
func TestReadinessTerminalRevokesBeforeStatsDrain(t *testing.T) {
	for _, terminal := range []error{io.EOF, errors.New("fatal reader")} {
		t.Run(terminal.Error(), func(t *testing.T) {
			reader := &terminalReadinessReader{err: terminal, statsEntered: make(chan struct{}), statsRelease: make(chan struct{})}
			p := readinessPipeline(t, func() (capture.Reader, error) { return reader, nil })
			done := make(chan error, 1)
			go func() { done <- p.Run(context.Background()) }()
			awaitReadiness(t, reader.statsEntered)
			if p.Snapshot().observation.interfaces[0].CaptureReady {
				t.Error("terminal reader resurrected readiness during stats drain")
			}
			if reader.closed != 0 {
				t.Error("reader closed before stats join")
			}
			close(reader.statsRelease)
			err := <-done
			if terminal == io.EOF && err != nil || terminal != io.EOF && !errors.Is(err, terminal) {
				t.Errorf("lost original error: %v", err)
			}
			if reader.closed != 1 {
				t.Errorf("Close count %d", reader.closed)
			}
		})
	}
}

type drainReadinessReader struct {
	pkt                                                          packet.Packet
	nextEntered, nextRelease, statsEntered, statsRelease, closed chan struct{}
	calls                                                        int
	closes                                                       atomic.Int32
	statsOnce                                                    sync.Once
}

func (r *drainReadinessReader) Next(context.Context) (packet.Packet, error) {
	r.calls++
	if r.calls == 1 {
		return r.pkt, nil
	}
	close(r.nextEntered)
	<-r.nextRelease
	return packet.Packet{}, io.EOF
}
func (r *drainReadinessReader) DroppedPackets() uint64 {
	r.statsOnce.Do(func() { close(r.statsEntered) })
	<-r.statsRelease
	return 0
}
func (r *drainReadinessReader) Close() error { r.closes.Add(1); close(r.closed); return nil }

type barrierReadinessSink struct{ entered, release chan struct{} }

func (s *barrierReadinessSink) Enqueue(packet.Packet) bool {
	close(s.entered)
	<-s.release
	return true
}
func TestReadinessAddRecordsFailureJoinsBothReaders(t *testing.T) {
	now := time.Now()
	reader := &drainReadinessReader{pkt: testPacket(now, "x"), nextEntered: make(chan struct{}), nextRelease: make(chan struct{}), statsEntered: make(chan struct{}), statsRelease: make(chan struct{}), closed: make(chan struct{})}
	p := readinessPipeline(t, func() (capture.Reader, error) { return reader, nil })
	p.cfg.BatchMaxBytes = 1
	p.cfg.IdleTimeout = time.Second
	ticks := make(chan time.Time, 1)
	p.cfg.IdleTicks = ticks
	sink := &barrierReadinessSink{entered: make(chan struct{}), release: make(chan struct{})}
	p.cfg.PCAPSink = sink
	done := make(chan error, 1)
	go func() { done <- p.Run(context.Background()) }()
	awaitReadiness(t, sink.entered)
	awaitReadiness(t, reader.nextEntered)
	ticks <- now.Add(2 * time.Second)
	close(sink.release)
	awaitReadiness(t, reader.statsEntered)
	if p.Snapshot().observation.interfaces[0].CaptureReady {
		t.Error("queue error ready during drain")
	}
	if reader.closes.Load() != 0 {
		t.Error("Close before Next/stats joins")
	}
	close(reader.nextRelease)
	if reader.closes.Load() != 0 {
		t.Error("Close before stats join")
	}
	close(reader.statsRelease)
	err := <-done
	if err == nil {
		t.Error("queue error swallowed")
	}
	if reader.closes.Load() != 1 {
		t.Errorf("Close count %d", reader.closes.Load())
	}
}

func TestReadinessPacketLimitsRevokeBeforeSink(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(map[bool]string{false: "local", true: "shared"}[shared], func(t *testing.T) {
			reader := &packetSourceStub{packets: []packet.Packet{testPacket(time.Now(), "x")}}
			// Keep Next nonterminal until the sink is released so EOF cannot mask the limit defect.
			next := &drainReadinessReader{pkt: reader.packets[0], nextEntered: make(chan struct{}), nextRelease: make(chan struct{}), statsEntered: make(chan struct{}), statsRelease: make(chan struct{}), closed: make(chan struct{})}
			p := readinessPipeline(t, func() (capture.Reader, error) { return next, nil })
			if shared {
				p.cfg.CaptureBudget = NewCaptureBudget(1, 0)
			} else {
				p.cfg.Limits.MaxPackets = 1
			}
			sink := &barrierReadinessSink{entered: make(chan struct{}), release: make(chan struct{})}
			p.cfg.PCAPSink = sink
			done := make(chan struct{})
			go func() { defer close(done); _ = p.Run(context.Background()) }()
			awaitReadiness(t, sink.entered)
			if p.Snapshot().observation.interfaces[0].CaptureReady {
				t.Error("limit reached but ready through sink work")
			}
			close(sink.release)
			close(next.nextRelease)
			close(next.statsRelease)
			awaitReadiness(t, done)
		})
	}
}

func TestReadinessPipelineObservationEligibility(t *testing.T) {
	cases := []struct {
		name       string
		iface, dir string
		ids        []string
		complete   bool
	}{
		{"valid", "eth0", "INBOUND", []string{"actual-job"}, true},
		{"bad-interface", "bad iface", "INBOUND", []string{"actual-job"}, false},
		{"long-interface", strings.Repeat("a", 16), "INBOUND", []string{"actual-job"}, false},
		{"bad-direction", "eth0", "SIDEWAYS", []string{"actual-job"}, false},
		{"bad-id", "eth0", "INBOUND", []string{"a b"}, false},
		{"long-id", "eth0", "INBOUND", []string{strings.Repeat("a", 201)}, false},
		{"max-names", strings.Repeat("a", 15), "UNKNOWN", []string{strings.Repeat("x", 200)}, true},
	}
	for _, n := range []int{128, 129} {
		ids := make([]string, n)
		for i := range ids {
			ids[i] = "duplicate"
		}
		cases = append(cases, struct {
			name       string
			iface, dir string
			ids        []string
			complete   bool
		}{fmt.Sprint(n), "eth0", "BIDIRECTIONAL", ids, n == 128})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reader := &readinessReader{entered: make(chan struct{})}
			p := readinessPipeline(t, func() (capture.Reader, error) { return reader, nil })
			cfg := p.cfg
			cfg.Interface, cfg.Direction, cfg.ActiveJobIDs = tc.iface, tc.dir, tc.ids
			var err error
			p, err = NewPipeline(cfg)
			if err != nil {
				t.Fatalf("observation policy rejected legacy constructor: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { defer close(done); _ = p.Run(ctx) }()
			awaitReadiness(t, reader.entered)
			snap := p.Snapshot()
			cancel()
			awaitReadiness(t, done)
			if len(snap.ActiveJobs) != len(tc.ids) {
				t.Error("observation changed legacy capture jobs")
			}
			if snap.observation == nil || snap.observation.complete != tc.complete || !tc.complete && len(snap.observation.interfaces) != 0 {
				t.Fatalf("eligibility = %+v", snap.observation)
			}
		})
	}
}

func observedRuntime(rows []CaptureReadyInterface) *controllableCapture {
	return &controllableCapture{started: make(chan struct{}), stopped: make(chan struct{}), snap: CaptureSnapshot{observation: &captureObservation{complete: true, interfaces: rows}}}
}
func readyRow(iface string, ready bool) CaptureReadyInterface {
	return CaptureReadyInterface{Interface: iface, Direction: "INBOUND", JobIDs: []string{"actual-job"}, CaptureReady: ready}
}

type forgedBackground struct{ *controllableCapture }

func (*forgedBackground) backgroundRuntime() {}
func TestReadinessGroupForegroundEligibilityAndRawBounds(t *testing.T) {
	for _, name := range []string{"background-only", "background-forgery", "unsupported", "empty", "conflict", "same-duplicates", "two-required", "raw-128", "raw-129", "jobs-128", "jobs-129", "members-129", "invalid"} {
		t.Run(name, func(t *testing.T) {
			rows := []CaptureReadyInterface{readyRow("eth0", true)}
			wantComplete := true
			wantRows := 1
			var members []CaptureRuntime
			var starts []<-chan struct{}
			add := func(c *controllableCapture) { members = append(members, c); starts = append(starts, c.started) }
			switch name {
			case "background-only":
				wantComplete = false
				wantRows = 0
			case "unsupported", "empty", "conflict", "raw-129", "jobs-129", "members-129", "invalid":
				wantComplete = false
				wantRows = 0
			case "two-required":
				rows = append(rows, readyRow("eth1", false))
				wantRows = 2
			case "same-duplicates":
				rows = append(rows, readyRow("eth0", true))
			}
			switch name {
			case "raw-128", "raw-129":
				n := 128
				if name == "raw-129" {
					n++
				}
				rows = nil
				for i := 0; i < n; i++ {
					rows = append(rows, readyRow("eth0", true))
				}
			case "jobs-128", "jobs-129":
				n := 128
				if name == "jobs-129" {
					n++
				}
				rows[0].JobIDs = make([]string, n)
				for i := range rows[0].JobIDs {
					rows[0].JobIDs[i] = "same"
				}
			case "conflict":
				rows = append(rows, readyRow("eth0", false))
			case "empty":
				rows = nil
			case "invalid":
				rows[0].Interface = "bad iface"
			}
			if name != "background-only" {
				c := observedRuntime(rows)
				if name == "unsupported" {
					c.snap.observation = nil
				}
				add(c)
			}
			if name == "members-129" {
				for i := 0; i < 128; i++ {
					add(observedRuntime([]CaptureReadyInterface{readyRow("eth0", true)}))
				}
			}
			if name == "background-only" || name == "background-forgery" {
				c := observedRuntime([]CaptureReadyInterface{readyRow("forged", true)})
				members = append(members, &forgedBackground{c})
				if name != "background-only" {
					starts = append(starts, c.started)
				}
			}
			s := NewSupervisor()
			if err := s.Apply(1, members); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { defer close(done); _ = s.Run(ctx) }()
			for _, ch := range starts {
				awaitReadiness(t, ch)
			}
			got := s.Snapshot().CaptureReadiness
			cancel()
			awaitReadiness(t, done)
			if got == nil || got.Complete != wantComplete || len(got.Interfaces) != wantRows {
				t.Fatalf("observation = %+v", got)
			}
			if wantComplete && name == "same-duplicates" && len(got.Interfaces[0].JobIDs) != 1 {
				t.Fatal("duplicate association not collapsed")
			}
			if name == "two-required" && got.Interfaces[1].CaptureReady {
				t.Fatal("blocked required interface marked ready")
			}
		})
	}
}

type completingReadyRuntime struct {
	started, release chan struct{}
	err              error
}

func (c *completingReadyRuntime) Run(context.Context) error {
	close(c.started)
	<-c.release
	return c.err
}
func (*completingReadyRuntime) Snapshot() CaptureSnapshot {
	return CaptureSnapshot{observation: &captureObservation{complete: true, interfaces: []CaptureReadyInterface{readyRow("eth0", true)}}}
}

type drainingReadyBackground struct{ entered, release chan struct{} }

func (*drainingReadyBackground) backgroundRuntime() {}
func (b *drainingReadyBackground) Run(ctx context.Context) error {
	<-ctx.Done()
	close(b.entered)
	<-b.release
	return nil
}
func (*drainingReadyBackground) Snapshot() CaptureSnapshot { return CaptureSnapshot{} }
func TestReadinessForegroundCompletionRevokesBeforeBackgroundDrain(t *testing.T) {
	for _, err := range []error{nil, context.Canceled, errors.New("foreground fault")} {
		t.Run(fmt.Sprint(err), func(t *testing.T) {
			fg := &completingReadyRuntime{started: make(chan struct{}), release: make(chan struct{}), err: err}
			bg := &drainingReadyBackground{entered: make(chan struct{}), release: make(chan struct{})}
			s := NewSupervisor()
			_ = s.Apply(1, []CaptureRuntime{fg, bg})
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { defer close(done); _ = s.Run(ctx) }()
			awaitReadiness(t, fg.started)
			if !s.Snapshot().CaptureReadiness.Complete {
				t.Error("live foreground not complete")
			}
			close(fg.release)
			awaitReadiness(t, bg.entered)
			got := s.Snapshot().CaptureReadiness
			if got == nil || got.Complete || len(got.Interfaces) != 0 {
				t.Errorf("finished foreground ready during background drain: %+v", got)
			}
			cancel()
			close(bg.release)
			awaitReadiness(t, done)
		})
	}
}

func TestReadinessSupervisorMetadataDomains(t *testing.T) {
	if got := NewSupervisor().Snapshot().CaptureReadiness; got != nil {
		t.Fatalf("before Apply: %+v", got)
	}
	for _, version := range []int64{-1, 0, 9007199254740991, 9007199254740992} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			c := observedRuntime([]CaptureReadyInterface{readyRow("eth0", true)})
			s := NewSupervisor()
			_ = s.Apply(version, []CaptureRuntime{c})
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { defer close(done); _ = s.Run(ctx) }()
			awaitReadiness(t, c.started)
			got := s.Snapshot().CaptureReadiness
			cancel()
			awaitReadiness(t, done)
			if version < 0 || version > 9007199254740991 {
				if got != nil {
					t.Fatalf("invalid version became authority: %+v", got)
				}
			} else if got == nil || got.ConfigVersion != version || got.Generation != 1 || len(got.InstanceID) != 32 {
				t.Fatalf("valid boundary changed: %+v", got)
			}
		})
	}
}
func TestReadinessSupervisorDeniesEntropyFailureAndExhaustion(t *testing.T) {
	for _, name := range []string{"entropy", "generation"} {
		t.Run(name, func(t *testing.T) {
			s := NewSupervisor()
			if name == "entropy" {
				s.initErr = errors.New("entropy unavailable")
			} else {
				s.generation = 9007199254740991
			}
			c := observedRuntime([]CaptureReadyInterface{readyRow("eth0", true)})
			if err := s.Apply(1, []CaptureRuntime{c}); err == nil {
				t.Error("new ownership admitted without identity capacity")
			}
			if name == "entropy" && s.Snapshot().CaptureReadiness != nil {
				t.Error("entropy failure published identity")
			}
		})
	}
}

type reusableReadyRuntime struct {
	starts chan struct{}
	runs   atomic.Int32
}

func (c *reusableReadyRuntime) Run(ctx context.Context) error {
	c.runs.Add(1)
	c.starts <- struct{}{}
	<-ctx.Done()
	return nil
}
func (*reusableReadyRuntime) Snapshot() CaptureSnapshot {
	return CaptureSnapshot{observation: &captureObservation{complete: true, interfaces: []CaptureReadyInterface{readyRow("eth0", true)}}}
}
func TestReadinessSupervisorIndependentRestartAllocatesGeneration(t *testing.T) {
	c := &reusableReadyRuntime{starts: make(chan struct{}, 2)}
	s := NewSupervisor()
	_ = s.Apply(5, []CaptureRuntime{c})
	identity := s.Snapshot().CaptureReadiness.InstanceID
	for _, generation := range []uint64{1, 2} {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); _ = s.Run(ctx) }()
		awaitReadiness(t, c.starts)
		got := s.Snapshot().CaptureReadiness
		cancel()
		awaitReadiness(t, done)
		if got == nil || got.Generation != generation || got.InstanceID != identity {
			t.Fatalf("restart identity: %+v want generation %d", got, generation)
		}
	}
}

type snapshotCallbackRuntime struct{ snapshot func() CaptureSnapshot }

func (*snapshotCallbackRuntime) Run(context.Context) error   { return nil }
func (c *snapshotCallbackRuntime) Snapshot() CaptureSnapshot { return c.snapshot() }
func TestReadinessHealthSamplesOutsideLifecycleLock(t *testing.T) {
	calls := 0
	var runner *Runner
	child := &snapshotCallbackRuntime{snapshot: func() CaptureSnapshot {
		calls++
		if !runner.mu.TryLock() {
			t.Error("child Snapshot under health lifecycle lock")
		} else {
			runner.mu.Unlock()
		}
		return CaptureSnapshot{ActiveJobs: []string{"fresh"}}
	}}
	runner, _ = New(Config{Registration: registration(), Capture: child}, &transportStub{})
	runner.setHealth(StatusOnline, true, "")
	if calls != 0 {
		t.Error("setHealth called child Snapshot")
	}
	w := httptest.NewRecorder()
	runner.HealthHandler().ServeHTTP(w, httptest.NewRequest("GET", "/health", nil))
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Error("health missing no-store")
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if _, ok := body["capture_sampled_at"].(string); !ok {
		t.Error("missing separate capture sample timestamp")
	}
	if len(runner.health.Capture.ActiveJobs) != 0 {
		t.Error("fresh child sample written into lifecycle cache")
	}
	if calls < 1 || body["capture"].(map[string]any)["ActiveJobs"].([]any)[0] != "fresh" {
		t.Error("health not freshly sampled")
	}
}
func TestReadinessPipelineSnapshotOwnsCompletedJobs(t *testing.T) {
	p := readinessPipeline(t, func() (capture.Reader, error) { return &packetSourceStub{}, nil })
	p.update(func(s *CaptureSnapshot) { s.CompletedJobs = []CaptureCompletion{{JobID: "actual-job"}} })
	got := p.Snapshot()
	got.CompletedJobs[0].JobID = "mutated"
	got.observation.interfaces[0].JobIDs[0] = "mutated"
	next := p.Snapshot()
	if next.CompletedJobs[0].JobID != "actual-job" || next.observation.interfaces[0].JobIDs[0] != "actual-job" {
		t.Fatal("caller mutated pipeline state")
	}
}

func TestReadinessDirectRunnerCannotIssueAuthority(t *testing.T) {
	c := &captureRuntimeStub{snapshot: CaptureSnapshot{CaptureReadiness: &CaptureReadiness{Version: 1, InstanceID: strings.Repeat("a", 32), Generation: 1, Complete: true, Interfaces: []CaptureReadyInterface{readyRow("eth0", true)}}, ActiveJobs: []string{"actual-job"}, CompletedJobs: []CaptureCompletion{{JobID: "done"}}, Interfaces: []InterfaceSnapshot{{Interface: "eth0"}}}}
	r, _ := New(Config{Registration: registration(), Capture: c}, &transportStub{})
	h := r.Health()
	if h.Capture.CaptureReadiness != nil {
		t.Error("direct runtime forged Supervisor authority")
	}
	h.Capture.ActiveJobs[0] = "mutated"
	h.Capture.CompletedJobs[0].JobID = "mutated"
	h.Capture.Interfaces[0].Interface = "mutated"
	next := r.Health()
	if next.Capture.ActiveJobs[0] != "actual-job" || next.Capture.CompletedJobs[0].JobID != "done" || next.Capture.Interfaces[0].Interface != "eth0" {
		t.Error("Health leaked child slices")
	}
}

func TestReadinessSharedBudgetRevokesPeerBlockedInSink(t *testing.T) {
	budget := NewCaptureBudget(2, 0)
	var pipelines []*Pipeline
	var sinks []*barrierReadinessSink
	var readers []*drainReadinessReader
	var dones []chan struct{}
	for i := 0; i < 2; i++ {
		reader := &drainReadinessReader{pkt: testPacket(time.Now(), "x"), nextEntered: make(chan struct{}), nextRelease: make(chan struct{}), statsEntered: make(chan struct{}), statsRelease: make(chan struct{}), closed: make(chan struct{})}
		p := readinessPipeline(t, func() (capture.Reader, error) { return reader, nil })
		p.cfg.CaptureBudget = budget
		sink := &barrierReadinessSink{entered: make(chan struct{}), release: make(chan struct{})}
		p.cfg.PCAPSink = sink
		done := make(chan struct{})
		go func() { defer close(done); _ = p.Run(context.Background()) }()
		awaitReadiness(t, sink.entered)
		pipelines = append(pipelines, p)
		sinks = append(sinks, sink)
		readers = append(readers, reader)
		dones = append(dones, done)
	}
	if pipelines[0].Snapshot().observation.interfaces[0].CaptureReady {
		t.Error("peer still ready after shared budget exhausted")
	}
	for i := range pipelines {
		close(sinks[i].release)
		close(readers[i].nextRelease)
		close(readers[i].statsRelease)
		awaitReadiness(t, dones[i])
	}
}

type retainingReadinessReader struct {
	countedReadinessReader
	entered, release chan struct{}
}

func (r *retainingReadinessReader) SetRetainRawFrame(bool) { close(r.entered); <-r.release }
func TestReadinessCancellationDuringRetentionDoesNotStartNext(t *testing.T) {
	reader := &retainingReadinessReader{entered: make(chan struct{}), release: make(chan struct{})}
	p := readinessPipeline(t, func() (capture.Reader, error) { return reader, nil })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = p.Run(ctx) }()
	awaitReadiness(t, reader.entered)
	cancel()
	close(reader.release)
	awaitReadiness(t, done)
	if reader.next != 0 || reader.closed != 1 {
		t.Errorf("canceled retention Next=%d Close=%d", reader.next, reader.closed)
	}
}

func TestReadinessInvalidIdentityIsNull(t *testing.T) {
	for _, id := range []string{strings.Repeat("Z", 32), strings.Repeat("g", 32), strings.Repeat("a", 31), ""} {
		s := NewSupervisor()
		s.instanceID = id
		_ = s.Apply(1, []CaptureRuntime{observedRuntime([]CaptureReadyInterface{readyRow("eth0", true)})})
		if s.Snapshot().CaptureReadiness != nil {
			t.Errorf("malformed instance issued authority: %q", id)
		}
	}
}

type delayedObservationRuntime struct {
	*controllableCapture
	sampleEntered, sampleRelease chan struct{}
	samples                      atomic.Int32
}

func (c *delayedObservationRuntime) Snapshot() CaptureSnapshot {
	snap := c.controllableCapture.Snapshot()
	if c.samples.Add(1) == 1 {
		close(c.sampleEntered)
		<-c.sampleRelease
	}
	return snap
}
func TestReadinessStaleSnapshotAcrossReplacementOrStop(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(fmt.Sprint(replace), func(t *testing.T) {
			old := &delayedObservationRuntime{controllableCapture: observedRuntime([]CaptureReadyInterface{readyRow("eth0", true)}), sampleEntered: make(chan struct{}), sampleRelease: make(chan struct{})}
			old.snap.ActiveJobs = []string{"old-job"}
			old.snap.observation.interfaces[0].JobIDs = []string{"old-job"}
			s := NewSupervisor()
			_ = s.Apply(9, []CaptureRuntime{old})
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { defer close(done); _ = s.Run(ctx) }()
			awaitReadiness(t, old.started)
			sample := make(chan CaptureSnapshot, 1)
			go func() { sample <- s.Snapshot() }()
			awaitReadiness(t, old.sampleEntered)
			handoff := make(chan struct{})
			next := observedRuntime([]CaptureReadyInterface{readyRow("eth1", true)})
			next.snap.observation.interfaces[0].JobIDs = []string{"new-job"}
			go func() {
				defer close(handoff)
				if replace {
					_ = s.Apply(9, []CaptureRuntime{next})
				} else {
					s.stopCurrent()
				}
			}()
			awaitReadiness(t, handoff) // would deadlock if a state lock crossed child Snapshot
			if replace {
				awaitReadiness(t, next.started)
			}
			close(old.sampleRelease)
			got := <-sample
			expected := uint64(1)
			if replace {
				expected = 2
			}
			if got.CaptureReadiness == nil || got.CaptureReadiness.Generation != expected || got.CaptureReadiness.Complete || len(got.CaptureReadiness.Interfaces) != 0 {
				t.Errorf("stale publication: %+v", got.CaptureReadiness)
			}
			if len(got.ActiveJobs) != 0 {
				t.Error("old metrics attached to replacement authority")
			}
			if replace {
				fresh := s.Snapshot().CaptureReadiness
				if !fresh.Complete || fresh.Interfaces[0].Interface != "eth1" || fresh.Interfaces[0].JobIDs[0] != "new-job" {
					t.Error("replacement never ready")
				}
			}
			cancel()
			awaitReadiness(t, done)
		})
	}
}

type handoffReadinessRuntime struct {
	started, stopping, release chan struct{}
	active                     *atomic.Int32
	overlap                    *atomic.Bool
}

func (c *handoffReadinessRuntime) Run(ctx context.Context) error {
	if c.active.Add(1) != 1 {
		c.overlap.Store(true)
	}
	close(c.started)
	<-ctx.Done()
	close(c.stopping)
	if c.release != nil {
		<-c.release
	}
	c.active.Add(-1)
	return nil
}
func (*handoffReadinessRuntime) Snapshot() CaptureSnapshot {
	return CaptureSnapshot{observation: &captureObservation{complete: true, interfaces: []CaptureReadyInterface{readyRow("eth0", true)}}}
}
func TestReadinessConcurrentApplySerializesEntireDrain(t *testing.T) {
	active := &atomic.Int32{}
	overlap := &atomic.Bool{}
	makeRuntime := func(block bool) *handoffReadinessRuntime {
		c := &handoffReadinessRuntime{started: make(chan struct{}), stopping: make(chan struct{}), active: active, overlap: overlap}
		if block {
			c.release = make(chan struct{})
		}
		return c
	}
	old, first, second := makeRuntime(true), makeRuntime(false), makeRuntime(false)
	s := NewSupervisor()
	_ = s.Apply(1, []CaptureRuntime{old})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Run(ctx) }()
	awaitReadiness(t, old.started)
	appliedFirst := make(chan struct{})
	go func() { defer close(appliedFirst); _ = s.Apply(1, []CaptureRuntime{first}) }()
	awaitReadiness(t, old.stopping)
	if s.lifecycle.TryLock() {
		t.Error("handoff released lifecycle lock before drain")
		s.lifecycle.Unlock()
	}
	// State remains available while lifecycle is draining.
	if got := s.Snapshot().CaptureReadiness; got == nil || got.Complete {
		t.Errorf("authority not revoked before drain: %+v", got)
	}
	applyingSecond, appliedSecond := make(chan struct{}), make(chan struct{})
	go func() { close(applyingSecond); defer close(appliedSecond); _ = s.Apply(1, []CaptureRuntime{second}) }()
	awaitReadiness(t, applyingSecond)
	close(old.release)
	awaitReadiness(t, appliedFirst)
	awaitReadiness(t, appliedSecond)
	awaitReadiness(t, second.started)
	if got := s.Snapshot().CaptureReadiness; got.Generation != 3 {
		t.Errorf("same-version Apply generation: %+v", got)
	}
	cancel()
	awaitReadiness(t, done)
	if overlap.Load() || active.Load() != 0 {
		t.Fatalf("overlapping or leaked owners: active=%d overlap=%v", active.Load(), overlap.Load())
	}
}
func TestReadinessRunApplyStartupAndConcurrentRun(t *testing.T) {
	c := &reusableReadyRuntime{starts: make(chan struct{}, 3)}
	s := NewSupervisor()
	_ = s.Apply(1, []CaptureRuntime{c})
	s.lifecycle.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	runEntered := make(chan struct{})
	go func() { close(runEntered); defer close(done); _ = s.Run(ctx) }()
	awaitReadiness(t, runEntered)
	applied := make(chan struct{})
	go func() { defer close(applied); _ = s.Apply(1, []CaptureRuntime{c}) }()
	s.lifecycle.Unlock()
	awaitReadiness(t, applied)
	awaitReadiness(t, c.starts)
	secondDone := make(chan error, 1)
	go func() { secondDone <- s.Run(ctx) }()
	select {
	case err := <-secondDone:
		if err == nil {
			t.Error("concurrent Run admitted")
		}
	case <-time.After(3 * time.Second):
		t.Error("concurrent Run did not reject")
	}
	got := s.Snapshot().CaptureReadiness
	if got.Generation != 2 {
		t.Errorf("startup double increment: %+v", got)
	}
	cancel()
	awaitReadiness(t, done)
}

func TestReadinessRecordErrorsRevokeBeforeErrorPublication(t *testing.T) {
	for _, kind := range []string{"addRecords", "persist"} {
		t.Run(kind, func(t *testing.T) {
			reader := &readinessReader{entered: make(chan struct{})}
			p := readinessPipeline(t, func() (capture.Reader, error) { return reader, nil })
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { defer close(done); _ = p.Run(ctx) }()
			awaitReadiness(t, reader.entered)
			var err error
			if kind == "addRecords" {
				q := batch.NewQueue[flow.Record](1, 1, func(flow.Record) int { return 2 })
				err = p.addRecords(q, []flow.Record{{}})
			} else {
				err = p.persist([]flow.Record{{StartTime: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}})
			}
			if err == nil {
				t.Error("fault did not fire")
			}
			if p.Snapshot().observation.interfaces[0].CaptureReady {
				t.Error("record failure published while reader ready")
			}
			cancel()
			awaitReadiness(t, done)
		})
	}
}

func TestReadinessPersistFailureJoinsBothReadersOnEveryReturn(t *testing.T) {
	for _, maxItems := range []int{1, 10} {
		t.Run(fmt.Sprint(maxItems), func(t *testing.T) {
			now := time.Now()
			reader := &drainReadinessReader{pkt: testPacket(now, "x"), nextEntered: make(chan struct{}), nextRelease: make(chan struct{}), statsEntered: make(chan struct{}), statsRelease: make(chan struct{}), closed: make(chan struct{})}
			p := readinessPipeline(t, func() (capture.Reader, error) { return reader, nil })
			p.cfg.BatchMaxItems = maxItems
			p.cfg.IdleTimeout = time.Second
			ticks := make(chan time.Time, 1)
			p.cfg.IdleTicks = ticks
			sink := &barrierReadinessSink{entered: make(chan struct{}), release: make(chan struct{})}
			p.cfg.PCAPSink = sink
			injected := errors.New("injected batch encoding fault")
			faulted := make(chan struct{})
			p.encodeBatch = func(flowbatch.Batch) ([]byte, error) { close(faulted); return nil, injected }
			done := make(chan error, 1)
			go func() { done <- p.Run(context.Background()) }()
			awaitReadiness(t, sink.entered)
			awaitReadiness(t, reader.nextEntered)
			ticks <- now.Add(2 * time.Second)
			close(sink.release)
			awaitReadiness(t, faulted)
			awaitReadiness(t, reader.statsEntered)
			if p.Snapshot().observation.interfaces[0].CaptureReady {
				t.Error("persist failure ready during drain")
			}
			if reader.closes.Load() != 0 {
				t.Error("Close before both joins")
			}
			close(reader.statsRelease)
			if reader.closes.Load() != 0 {
				t.Error("Close before Next join")
			}
			close(reader.nextRelease)
			if err := <-done; !errors.Is(err, injected) {
				t.Errorf("lost persist error identity: %v", err)
			}
			if reader.closes.Load() != 1 {
				t.Errorf("Close count %d", reader.closes.Load())
			}
		})
	}
}

func TestReadinessAllStopsRevokeBeforeDrain(t *testing.T) {
	now := time.Now()
	cases := []struct {
		limits capture.Limits
		reason capture.StopReason
	}{
		{capture.Limits{UserStopped: func() bool { return true }}, capture.StopUser},
		{capture.Limits{DiskAvailable: func() bool { return false }}, capture.StopDisk},
		{capture.Limits{Timeout: time.Second, StartedAt: now.Add(-2 * time.Second)}, capture.StopTimeout},
		{capture.Limits{EndTime: now}, capture.StopEndTime},
		{capture.Limits{Duration: time.Second, StartedAt: now.Add(-2 * time.Second)}, capture.StopDuration},
		{capture.Limits{MaxBytes: 100}, capture.StopMaxBytes},
	}
	for _, tc := range cases {
		t.Run(string(tc.reason), func(t *testing.T) {
			reader := &drainReadinessReader{pkt: testPacket(now, "x"), nextEntered: make(chan struct{}), nextRelease: make(chan struct{}), statsEntered: make(chan struct{}), statsRelease: make(chan struct{}), closed: make(chan struct{})}
			p := readinessPipeline(t, func() (capture.Reader, error) { return reader, nil })
			p.cfg.Limits = tc.limits
			p.cfg.Now = func() time.Time { return now }
			done := make(chan error, 1)
			go func() { done <- p.Run(context.Background()) }()
			awaitReadiness(t, reader.statsEntered)
			if p.Snapshot().observation.interfaces[0].CaptureReady {
				t.Error("stop ready during drainage")
			}
			if reader.closes.Load() != 0 {
				t.Error("Close before drain")
			}
			close(reader.nextRelease)
			close(reader.statsRelease)
			if err := <-done; err != nil {
				t.Error(err)
			}
			if p.Snapshot().StopReason != tc.reason || reader.closes.Load() != 1 {
				t.Errorf("stop/Close: %+v %d", p.Snapshot(), reader.closes.Load())
			}
		})
	}
}
func TestReadinessEOFStaysRevokedDuringSuccessfulFinalFlush(t *testing.T) {
	p := readinessPipeline(t, func() (capture.Reader, error) {
		return &packetSourceStub{packets: []packet.Packet{testPacket(time.Now(), "x")}}, nil
	})
	entered, release := make(chan struct{}), make(chan struct{})
	p.encodeBatch = func(b flowbatch.Batch) ([]byte, error) { close(entered); <-release; return flowbatch.Encode(b) }
	done := make(chan error, 1)
	go func() { done <- p.Run(context.Background()) }()
	awaitReadiness(t, entered)
	if p.Snapshot().observation.interfaces[0].CaptureReady {
		t.Error("EOF ready during final flush")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if p.Snapshot().StopReason != capture.StopEndOfInput {
		t.Fatal("successful EOF lost")
	}
}

type recoverableReadinessReader struct {
	calls   int
	entered chan struct{}
}

func (r *recoverableReadinessReader) Next(ctx context.Context) (packet.Packet, error) {
	r.calls++
	switch r.calls {
	case 1:
		return packet.Packet{}, capture.ErrPollTimeout
	case 2:
		return packet.Packet{}, capture.ErrUnsupportedPacket
	case 3:
		return packet.Packet{}, capture.ErrMalformedPacket
	}
	close(r.entered)
	<-ctx.Done()
	return packet.Packet{}, ctx.Err()
}
func (*recoverableReadinessReader) Close() error { return nil }
func TestReadinessRecoverableErrorsRetainAcquisition(t *testing.T) {
	reader := &recoverableReadinessReader{entered: make(chan struct{})}
	p := readinessPipeline(t, func() (capture.Reader, error) { return reader, nil })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = p.Run(ctx) }()
	awaitReadiness(t, reader.entered)
	snap := p.Snapshot()
	if !snap.observation.interfaces[0].CaptureReady || snap.DecodeErrors != 1 || snap.ReceivedPackets != 0 {
		t.Errorf("recoverable readiness: %+v", snap)
	}
	cancel()
	awaitReadiness(t, done)
}
func TestReadinessImmediateTerminalCannotBeRevivedByDelayedParent(t *testing.T) {
	for _, terminal := range []error{io.EOF, errors.New("terminal")} {
		t.Run(terminal.Error(), func(t *testing.T) {
			reader := &terminalReadinessReader{err: terminal, statsEntered: make(chan struct{}), statsRelease: make(chan struct{})}
			p := readinessPipeline(t, func() (capture.Reader, error) { return reader, nil })
			parentEntered, parentRelease := make(chan struct{}), make(chan struct{})
			p.cfg.Limits.UserStopped = func() bool { close(parentEntered); <-parentRelease; return false }
			done := make(chan error, 1)
			go func() { done <- p.Run(context.Background()) }()
			awaitReadiness(t, parentEntered)
			// Taking p.mu provides a terminal-state barrier without assuming goroutine
			// scheduling or using a first packet as readiness evidence.
			deadline := time.After(3 * time.Second)
			for {
				p.mu.RLock()
				terminalLatched := p.readerTerminal
				p.mu.RUnlock()
				if terminalLatched {
					break
				}
				select {
				case <-deadline:
					t.Fatal("terminal latch not set")
				default:
				}
				goruntime.Gosched()
			}
			if p.Snapshot().observation.interfaces[0].CaptureReady {
				t.Error("terminal reader ready with parent delayed")
			}
			p.markReaderStarted() // a delayed start publication must also lose to terminal
			if p.Snapshot().observation.interfaces[0].CaptureReady {
				t.Error("start acknowledgement resurrected terminal reader")
			}
			close(parentRelease)
			awaitReadiness(t, reader.statsEntered)
			close(reader.statsRelease)
			err := <-done
			if terminal != io.EOF && !errors.Is(err, terminal) {
				t.Error("terminal error lost")
			}
		})
	}
}

type failedReadinessEntropy struct{ err error }

func (f failedReadinessEntropy) Read([]byte) (int, error) { return 0, f.err }
func TestReadinessConstructorEntropyFailureDeniesRun(t *testing.T) {
	original := rand.Reader
	sentinel := errors.New("entropy fixture failure")
	rand.Reader = failedReadinessEntropy{sentinel}
	s := NewSupervisor()
	rand.Reader = original
	if !errors.Is(s.initErr, sentinel) {
		t.Fatalf("entropy error not retained: %v", s.initErr)
	}
	c := observedRuntime([]CaptureReadyInterface{readyRow("eth0", true)})
	if err := s.Apply(1, []CaptureRuntime{c}); !errors.Is(err, sentinel) {
		t.Errorf("Apply: %v", err)
	}
	if err := s.Run(context.Background()); !errors.Is(err, sentinel) {
		t.Errorf("Run: %v", err)
	}
	select {
	case <-c.started:
		t.Error("entropy failure launched capture")
	default:
	}
	if s.Snapshot().CaptureReadiness != nil {
		t.Error("entropy failure minted identity")
	}
	a, b := NewSupervisor(), NewSupervisor()
	if a.instanceID == b.instanceID || !readinessInstanceID.MatchString(a.instanceID) {
		t.Error("instance identities not fresh crypto hex")
	}
}
func TestReadinessPendingApplyGenerationAndExhaustedRestart(t *testing.T) {
	s := NewSupervisor()
	old := observedRuntime([]CaptureReadyInterface{readyRow("eth0", true)})
	next := observedRuntime([]CaptureReadyInterface{readyRow("eth1", true)})
	_ = s.Apply(0, []CaptureRuntime{old})
	_ = s.Apply(0, []CaptureRuntime{next})
	if got := s.Snapshot().CaptureReadiness; got.Generation != 2 || got.Complete {
		t.Errorf("pending observation: %+v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Run(ctx) }()
	awaitReadiness(t, next.started)
	got := s.Snapshot().CaptureReadiness
	cancel()
	awaitReadiness(t, done)
	if got.Generation != 2 {
		t.Error("Run reallocated pending generation")
	}
	select {
	case <-old.started:
		t.Error("superseded pending runtime started")
	default:
	}
	s.generation = maxReadinessInteger
	if err := s.Run(context.Background()); err == nil {
		t.Error("exhausted independent restart admitted")
	}
	if err := s.Apply(1, []CaptureRuntime{old}); err == nil {
		t.Error("exhausted Apply admitted")
	}
}
func TestReadinessHealthDelayedSampleCannotWriteBackLifecycle(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	c := &snapshotCallbackRuntime{snapshot: func() CaptureSnapshot { close(entered); <-release; return CaptureSnapshot{ActiveJobs: []string{"old"}} }}
	r, _ := New(Config{Registration: registration(), Capture: c}, &transportStub{})
	r.setHealth(StatusOnline, true, "")
	sampled := make(chan Health, 1)
	go func() { sampled <- r.Health() }()
	awaitReadiness(t, entered)
	updated := make(chan struct{})
	go func() { defer close(updated); r.setHealth(StatusError, false, "new lifecycle") }()
	awaitReadiness(t, updated)
	close(release)
	old := <-sampled
	r.mu.RLock()
	current := r.health
	r.mu.RUnlock()
	if current.Status != StatusError || current.Registered || current.LastError != "new lifecycle" || len(current.Capture.ActiveJobs) != 0 {
		t.Errorf("stale sample wrote cache: %+v", current)
	}
	if old.CaptureSampledAt.IsZero() || old.CaptureSampledAt.Before(old.UpdatedAt) {
		t.Error("capture sample timestamp not distinct lifecycle fact")
	}
}
func TestReadinessSupervisorNestedSlicesAndSortAreOwned(t *testing.T) {
	rows := []CaptureReadyInterface{readyRow("eth9", true), readyRow("eth0", true)}
	rows[1].JobIDs = []string{"z-job", "a-job", "a-job"}
	c := observedRuntime(rows)
	s := NewSupervisor()
	_ = s.Apply(1, []CaptureRuntime{c})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Run(ctx) }()
	awaitReadiness(t, c.started)
	r, _ := New(Config{Registration: registration(), Capture: s}, &transportStub{})
	first := r.Health().Capture.CaptureReadiness
	if first.Interfaces[0].Interface != "eth0" || strings.Join(first.Interfaces[0].JobIDs, ",") != "a-job,z-job" {
		t.Errorf("unsorted/doubled rows: %+v", first)
	}
	first.Interfaces[0].Interface = "changed"
	first.Interfaces[0].JobIDs[0] = "changed"
	first.Generation = 999
	next := r.Health().Capture.CaptureReadiness
	if next.Generation != 1 || next.Interfaces[0].Interface != "eth0" || next.Interfaces[0].JobIDs[0] != "a-job" {
		t.Error("Health caller mutated Supervisor or Group state")
	}
	cancel()
	awaitReadiness(t, done)
}

func TestReadinessDistinctRawBoundaries(t *testing.T) {
	for _, kind := range []string{"rows", "jobs"} {
		for _, n := range []int{128, 129} {
			t.Run(fmt.Sprintf("%s-%d", kind, n), func(t *testing.T) {
				rows := []CaptureReadyInterface{readyRow("eth0", true)}
				if kind == "rows" {
					rows = nil
					for i := 0; i < n; i++ {
						rows = append(rows, readyRow(fmt.Sprintf("eth%03d", i), true))
					}
				} else {
					rows[0].JobIDs = nil
					for i := 0; i < n; i++ {
						rows[0].JobIDs = append(rows[0].JobIDs, fmt.Sprintf("job%03d", i))
					}
				}
				c := observedRuntime(rows)
				s := NewSupervisor()
				_ = s.Apply(1, []CaptureRuntime{c})
				ctx, cancel := context.WithCancel(context.Background())
				done := make(chan struct{})
				go func() { defer close(done); _ = s.Run(ctx) }()
				awaitReadiness(t, c.started)
				got := s.Snapshot().CaptureReadiness
				cancel()
				awaitReadiness(t, done)
				if n == 129 {
					if got.Complete || len(got.Interfaces) != 0 {
						t.Error("over budget prefix published")
					}
				} else if !got.Complete || kind == "rows" && len(got.Interfaces) != 128 || kind == "jobs" && len(got.Interfaces[0].JobIDs) != 128 {
					t.Fatalf("exact boundary denied: %+v", got)
				}
			})
		}
	}
}
func TestReadinessActualTwoSourcesAreAllRequired(t *testing.T) {
	reader := &readinessReader{entered: make(chan struct{})}
	ready := readinessPipeline(t, func() (capture.Reader, error) { return reader, nil })
	ready.cfg.Interface = "eth1"
	opened, release := make(chan struct{}), make(chan struct{})
	late := &countedReadinessReader{}
	blocked := readinessPipeline(t, func() (capture.Reader, error) { close(opened); <-release; return late, nil })
	s := NewSupervisor()
	_ = s.Apply(1, []CaptureRuntime{ready, blocked})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Run(ctx) }()
	awaitReadiness(t, reader.entered)
	awaitReadiness(t, opened)
	r, _ := New(Config{Registration: registration(), Capture: s}, &transportStub{})
	got := r.Health().Capture.CaptureReadiness
	if !got.Complete || len(got.Interfaces) != 2 || got.Interfaces[0].CaptureReady || !got.Interfaces[1].CaptureReady {
		t.Errorf("partial source admission: %+v", got)
	}
	cancel()
	close(release)
	awaitReadiness(t, done)
	if late.next != 0 || late.closed != 1 {
		t.Error("blocked sibling not closed on cancellation")
	}
}
func TestReadinessBackgroundFailureRetiresUncooperativeForeground(t *testing.T) {
	c := &handoffReadinessRuntime{started: make(chan struct{}), stopping: make(chan struct{}), release: make(chan struct{}), active: &atomic.Int32{}, overlap: &atomic.Bool{}}
	bg := &backgroundErrorRuntime{captureRuntimeStub: &captureRuntimeStub{err: errors.New("background failed")}}
	s := NewSupervisor()
	_ = s.Apply(1, []CaptureRuntime{c, bg})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Run(ctx) }()
	awaitReadiness(t, c.stopping)
	got := s.Snapshot().CaptureReadiness
	if got.Complete || len(got.Interfaces) != 0 {
		t.Error("background failure left foreground ready")
	}
	cancel()
	close(c.release)
	awaitReadiness(t, done)
}
func TestReadinessUnsupportedSiblingDeniesReadyPrefix(t *testing.T) {
	good := observedRuntime([]CaptureReadyInterface{readyRow("eth0", true)})
	bad := observedRuntime(nil)
	bad.snap.observation = nil
	s := NewSupervisor()
	_ = s.Apply(1, []CaptureRuntime{good, bad})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Run(ctx) }()
	awaitReadiness(t, good.started)
	awaitReadiness(t, bad.started)
	got := s.Snapshot().CaptureReadiness
	cancel()
	awaitReadiness(t, done)
	if got.Complete || len(got.Interfaces) != 0 {
		t.Error("unsupported required source left a ready prefix")
	}
	encoded, err := json.Marshal(got)
	if err != nil || !strings.Contains(string(encoded), `"interfaces":[]`) {
		t.Errorf("empty arrays not serialized: %s %v", encoded, err)
	}
}

func TestReadinessAddedAllocationsStopAtRawBudget(t *testing.T) {
	p := readinessPipeline(t, func() (capture.Reader, error) { return &packetSourceStub{}, nil })
	makeGroup := func(n int) *CaptureGroup {
		members := make([]CaptureRuntime, n)
		for i := range members {
			members[i] = p
		}
		g, _ := NewCaptureGroup(members)
		g.lifetime = &captureLifetime{ctx: context.Background()}
		return g
	}
	small, large := makeGroup(129), makeGroup(2048)
	// These idle fixture snapshots have no legacy metric slices to allocate.
	// Increasing rejected raw input may not keep copying added sidecars.
	smallAllocs := testing.AllocsPerRun(5, func() { _ = small.Snapshot() })
	largeAllocs := testing.AllocsPerRun(5, func() { _ = large.Snapshot() })
	t.Logf("readiness allocations: raw129=%v raw2048=%v", smallAllocs, largeAllocs)
	if largeAllocs > smallAllocs+4 {
		t.Fatalf("sidecar allocations grow beyond raw budget: 129=%v 2048=%v", smallAllocs, largeAllocs)
	}
}

type nilReadinessReader struct{}

func (*nilReadinessReader) Next(context.Context) (packet.Packet, error) {
	return packet.Packet{}, io.EOF
}
func (*nilReadinessReader) Close() error { return nil }
func TestReadinessTypedNilReaderIsNotAcquired(t *testing.T) {
	p := readinessPipeline(t, func() (capture.Reader, error) { var reader *nilReadinessReader; return reader, nil })
	if err := p.Run(context.Background()); err == nil {
		t.Error("typed nil reader accepted as a capture resource")
	}
	if p.Snapshot().observation.interfaces[0].CaptureReady {
		t.Error("typed nil reader ready")
	}
}

type multipleDrainReadinessReader struct {
	drainReadinessReader
	packets []packet.Packet
	index   int
}

func (r *multipleDrainReadinessReader) Next(context.Context) (packet.Packet, error) {
	if r.index < len(r.packets) {
		p := r.packets[r.index]
		r.index++
		return p, nil
	}
	close(r.nextEntered)
	<-r.nextRelease
	return packet.Packet{}, io.EOF
}
func TestReadinessPacketEventRecordFailuresJoinBeforeClose(t *testing.T) {
	for _, kind := range []string{"queue", "persist"} {
		t.Run(kind, func(t *testing.T) {
			now := time.Now()
			reader := &multipleDrainReadinessReader{drainReadinessReader: drainReadinessReader{nextEntered: make(chan struct{}), nextRelease: make(chan struct{}), statsEntered: make(chan struct{}), statsRelease: make(chan struct{}), closed: make(chan struct{})}, packets: []packet.Packet{testPacket(now, "x"), testPacket(now.Add(2*time.Second), "y")}}
			p := readinessPipeline(t, func() (capture.Reader, error) { return reader, nil })
			p.cfg.IdleTimeout = time.Second
			p.cfg.IdleTicks = make(chan time.Time)
			p.cfg.BatchMaxItems = 1
			sink := &secondPacketBarrierSink{entered: make(chan struct{}), release: make(chan struct{})}
			p.cfg.PCAPSink = sink
			sentinel := errors.New("event persist fault")
			if kind == "queue" {
				p.cfg.BatchMaxBytes = 1
			} else {
				p.encodeBatch = func(flowbatch.Batch) ([]byte, error) { return nil, sentinel }
			}
			done := make(chan error, 1)
			go func() { done <- p.Run(context.Background()) }()
			awaitReadiness(t, sink.entered)
			awaitReadiness(t, reader.nextEntered)
			close(sink.release)
			awaitReadiness(t, reader.statsEntered)
			if p.Snapshot().observation.interfaces[0].CaptureReady || reader.closes.Load() != 0 {
				t.Error("event error not revoked/joined")
			}
			close(reader.nextRelease)
			close(reader.statsRelease)
			err := <-done
			if err == nil || kind == "persist" && !errors.Is(err, sentinel) {
				t.Errorf("event error lost: %v", err)
			}
			if reader.closes.Load() != 1 {
				t.Error("event Close not exactly once")
			}
		})
	}
}

type errorAfterPacketReader struct {
	terminalReadinessReader
	pkt   packet.Packet
	calls int
}

func (r *errorAfterPacketReader) Next(context.Context) (packet.Packet, error) {
	r.calls++
	if r.calls == 1 {
		return r.pkt, nil
	}
	return packet.Packet{}, r.err
}
func TestReadinessTerminalErrorIdentitySurvivesFinalFlushFailure(t *testing.T) {
	for _, terminal := range []error{io.EOF, errors.New("original fatal")} {
		t.Run(terminal.Error(), func(t *testing.T) {
			reader := &errorAfterPacketReader{terminalReadinessReader: terminalReadinessReader{err: terminal, statsEntered: make(chan struct{}), statsRelease: make(chan struct{})}, pkt: testPacket(time.Now(), "x")}
			p := readinessPipeline(t, func() (capture.Reader, error) { return reader, nil })
			p.cfg.IdleTimeout = time.Hour
			flushError := errors.New("flush fault")
			faults := 0
			p.encodeBatch = func(flowbatch.Batch) ([]byte, error) { faults++; return nil, flushError }
			done := make(chan error, 1)
			go func() { done <- p.Run(context.Background()) }()
			awaitReadiness(t, reader.statsEntered)
			if p.Snapshot().observation.interfaces[0].CaptureReady || reader.closed != 0 {
				t.Error("terminal not revoked during stats drain")
			}
			close(reader.statsRelease)
			err := <-done
			want := terminal
			if terminal == io.EOF {
				want = flushError
			}
			if !errors.Is(err, want) || faults != 1 || reader.closed != 1 {
				t.Errorf("original error/flush/Close: %v faults=%d close=%d", err, faults, reader.closed)
			}
		})
	}
}

type secondPacketBarrierSink struct {
	calls            int
	entered, release chan struct{}
}

func (s *secondPacketBarrierSink) Enqueue(packet.Packet) bool {
	s.calls++
	if s.calls == 2 {
		close(s.entered)
		<-s.release
	}
	return true
}

type readinessHeartbeatTransport struct {
	transportStub
	sent chan telemetry.Heartbeat
}

func (t *readinessHeartbeatTransport) Heartbeat(ctx context.Context, h telemetry.Heartbeat) error {
	select {
	case t.sent <- h:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func TestReadinessIsAbsentFromProducedLegacyHeartbeat(t *testing.T) {
	reader := &readinessReader{entered: make(chan struct{})}
	p := readinessPipeline(t, func() (capture.Reader, error) { return reader, nil })
	s := NewSupervisor()
	_ = s.Apply(1, []CaptureRuntime{p})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Run(ctx) }()
	awaitReadiness(t, reader.entered)
	transport := &readinessHeartbeatTransport{sent: make(chan telemetry.Heartbeat, 10)}
	r, _ := New(Config{Registration: registration(), Capture: s, HeartbeatInterval: time.Millisecond}, transport)
	r.setHealth(StatusOnline, true, "")
	heartbeatCtx, stopHeartbeat := context.WithCancel(ctx)
	heartbeatDone := make(chan struct{})
	go func() { defer close(heartbeatDone); r.runHeartbeats(heartbeatCtx) }()
	var heartbeat telemetry.Heartbeat
	select {
	case heartbeat = <-transport.sent:
	case <-time.After(3 * time.Second):
		t.Fatal("production heartbeat not emitted")
	}
	stopHeartbeat()
	awaitReadiness(t, heartbeatDone)
	encoded, err := json.Marshal(heartbeat)
	if err != nil || strings.Contains(string(encoded), "capture_readiness") || strings.Contains(string(encoded), "instance_id") || strings.Contains(string(encoded), "generation") {
		t.Errorf("readiness leaked into legacy producer DTO: %s %v", encoded, err)
	}
	if len(heartbeat.ActiveJobs) != 1 || heartbeat.ActiveJobs[0] != "actual-job" || len(heartbeat.Interfaces) != 1 || heartbeat.Interfaces[0].Status != "CAPTURING" {
		t.Errorf("legacy capture facts changed: %+v", heartbeat)
	}
	cancel()
	awaitReadiness(t, done)
}

func TestReadinessHTTPFreshlyRevokesDuringBlockedDrain(t *testing.T) {
	reader := &blockingLifecycleSource{entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	p := readinessPipeline(t, func() (capture.Reader, error) { return reader, nil })
	s := NewSupervisor()
	_ = s.Apply(1, []CaptureRuntime{p})
	r, _ := New(Config{Registration: registration(), Capture: s, HeartbeatInterval: time.Hour}, &transportStub{})
	r.setHealth(StatusOnline, true, "")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Run(ctx) }()
	awaitReadiness(t, reader.entered)
	before := r.Health()
	if !before.Capture.CaptureReadiness.Interfaces[0].CaptureReady {
		t.Fatal("fixture not ready")
	}
	cancel()
	w := httptest.NewRecorder()
	r.HealthHandler().ServeHTTP(w, httptest.NewRequest("GET", "/health", nil))
	var after Health
	if err := json.Unmarshal(w.Body.Bytes(), &after); err != nil {
		t.Fatal(err)
	}
	if after.Capture.CaptureReadiness == nil || after.Capture.CaptureReadiness.Complete || len(after.Capture.CaptureReadiness.Interfaces) != 0 {
		t.Error("HTTP retained readiness after cancellation")
	}
	if !after.Registered || !after.UpdatedAt.Equal(before.UpdatedAt) || after.CaptureSampledAt.Before(before.CaptureSampledAt) || w.Header().Get("Cache-Control") != "no-store" {
		t.Error("fresh sample overwrote lifecycle facts or was cacheable")
	}
	select {
	case <-done:
		t.Error("blocked drain claimed completion")
	default:
	}
	close(reader.release)
	awaitReadiness(t, done)
}

func TestReadinessSourceFailureAndSyntheticFallback(t *testing.T) {
	sentinel := errors.New("fixture Source failure")
	calls := 0
	p := readinessPipeline(t, func() (capture.Reader, error) { calls++; return nil, sentinel })
	p.cfg.ActiveJobIDs = nil
	before := p.Snapshot()
	if before.CaptureReadiness != nil || !before.observation.complete || before.observation.interfaces[0].CaptureReady || before.observation.interfaces[0].JobIDs[0] != "synthetic" || calls != 0 {
		t.Error("pre-acquisition observation or fallback invalid")
	}
	if err := p.Run(context.Background()); !errors.Is(err, sentinel) {
		t.Errorf("Source error lost: %v", err)
	}
	after := p.Snapshot()
	if after.observation.interfaces[0].CaptureReady || after.LastError == "" || calls != 1 {
		t.Error("Source failure published acquisition or lost legacy error")
	}
}

func TestReadinessNameValidationMatchesFrozenASCIIGrammar(t *testing.T) {
	ifacePattern := regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
	jobPattern := regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,200}$`)
	samples := []string{"", strings.Repeat("a", 15), strings.Repeat("a", 16), strings.Repeat("a", 200), strings.Repeat("a", 201), "é", "인터페이스", "a\nb", "a:b"}
	for i := 0; i < 256; i++ {
		samples = append(samples, string([]byte{byte(i)}))
	}
	for _, sample := range samples {
		row := readyRow(sample, true)
		if got := eligibleReadyRow(row); got != ifacePattern.MatchString(sample) {
			t.Errorf("interface grammar mismatch %q: %v", sample, got)
		}
		row = readyRow("eth0", true)
		row.JobIDs = []string{sample}
		if got := eligibleReadyRow(row); got != jobPattern.MatchString(sample) {
			t.Errorf("job grammar mismatch %q: %v", sample, got)
		}
	}
}
