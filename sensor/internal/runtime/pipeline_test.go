package runtime

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"sync"
	"testing"
	"time"

	"c2hunter/sensor/internal/capture"
	"c2hunter/sensor/internal/direction"
	"c2hunter/sensor/internal/flowbatch"
	"c2hunter/sensor/internal/packet"
	"c2hunter/sensor/internal/spool"
)

type packetSourceStub struct {
	packets        []packet.Packet
	index          int
	retainRawFrame bool
}

func (s *packetSourceStub) Next(context.Context) (packet.Packet, error) {
	if s.index == len(s.packets) {
		return packet.Packet{}, io.EOF
	}
	p := s.packets[s.index]
	s.index++
	return p, nil
}
func (*packetSourceStub) Close() error { return nil }
func (s *packetSourceStub) SetRetainRawFrame(enabled bool) {
	s.retainRawFrame = enabled
}

type blockingLifecycleSource struct {
	entered chan struct{}
	release chan struct{}
	closed  chan struct{}
}

func (s *blockingLifecycleSource) Next(ctx context.Context) (packet.Packet, error) {
	close(s.entered)
	<-s.release
	return packet.Packet{}, ctx.Err()
}

func (s *blockingLifecycleSource) Close() error {
	close(s.closed)
	return nil
}

type uploadStub struct {
	mu      sync.Mutex
	batches []flowbatch.Batch
	err     error
}

func (s *uploadStub) UploadFlowBatch(_ context.Context, batch flowbatch.Batch) (flowbatch.ACK, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batches = append(s.batches, batch)
	if s.err != nil {
		return flowbatch.ACK{}, s.err
	}
	return flowbatch.ACK{BatchID: batch.BatchID, Accepted: true}, nil
}

func (s *uploadStub) snapshot() []flowbatch.Batch {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]flowbatch.Batch(nil), s.batches...)
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for !condition() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !condition() {
		t.Fatal("condition was not met before timeout")
	}
}

func testPacket(at time.Time, payload string) packet.Packet {
	return packet.Packet{
		Timestamp:       at,
		WireLength:      100,
		IPVersion:       4,
		SourceIP:        netip.MustParseAddr("10.0.0.2"),
		DestinationIP:   netip.MustParseAddr("203.0.113.8"),
		SourcePort:      43210,
		DestinationPort: 80,
		Protocol:        packet.TCP,
		Direction:       direction.Outbound,
		Payload:         []byte(payload),
	}
}

func openTestSpool(t *testing.T, dir string, now func() time.Time) *spool.Spool {
	t.Helper()
	s, err := spool.Open(dir, spool.Limits{MaxBytes: 1 << 20, MaxAge: time.Hour}, now)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPipelineRunsPacketsThroughMetadataAggregationSpoolAndACK(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	source := &packetSourceStub{packets: []packet.Packet{
		testPacket(now, "GET /beacon HTTP/1.1\r\nHost: c2.example\r\n\r\n"),
		testPacket(now.Add(time.Second), "GET /beacon HTTP/1.1\r\nHost: c2.example\r\n\r\n"),
	}}
	uploader := &uploadStub{}
	pipeline, err := NewPipeline(PipelineConfig{
		SensorID: "sensor-a", JobID: "job-a", IdleTimeout: time.Minute,
		BatchMaxItems: 10, BatchMaxBytes: 64 << 10, PacketQueueSize: 4,
		Source: func() (capture.Reader, error) { return source, nil },
		Spool:  openTestSpool(t, t.TempDir(), func() time.Time { return now }), Uploader: uploader,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pipeline.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(uploader.snapshot()) == 1 })
	uploaded := uploader.snapshot()
	if len(uploaded[0].Flows) != 1 {
		t.Fatalf("uploaded batches = %+v", uploaded)
	}
	flow := uploaded[0].Flows[0]
	if flow.PacketCount != 2 || flow.TotalBytes != 200 || flow.Domain != "c2.example" || flow.Direction != "OUTBOUND" {
		t.Fatalf("flow = %+v", flow)
	}
	snapshot := pipeline.Snapshot()
	if snapshot.ReceivedPackets != 2 || snapshot.PendingBytes != 0 || len(snapshot.ActiveJobs) != 0 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

func TestPipelineRestartResendsStableSpooledBatchID(t *testing.T) {
	now := time.Unix(200, 0).UTC()
	dir := t.TempDir()
	failed := &uploadStub{err: errors.New("offline")}
	first, err := NewPipeline(PipelineConfig{
		SensorID: "sensor-a", JobID: "job-a", BatchMaxItems: 1, BatchMaxBytes: 64 << 10, PacketQueueSize: 1,
		Source: func() (capture.Reader, error) {
			return &packetSourceStub{packets: []packet.Packet{testPacket(now, "x")}}, nil
		},
		Spool: openTestSpool(t, dir, func() time.Time { return now }), Uploader: failed, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return first.Snapshot().LastError != "" })
	if first.Snapshot().LastError == "" {
		t.Fatal("upload failure was not reflected in pipeline status")
	}
	var pending []spool.Batch
	waitFor(t, func() bool {
		var err error
		pending, err = openTestSpool(t, dir, func() time.Time { return now.Add(2 * time.Second) }).Pending()
		return err == nil && len(pending) == 1
	})
	pending, err = openTestSpool(t, dir, func() time.Time { return now.Add(2 * time.Second) }).Pending()
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending = %+v, %v", pending, err)
	}
	stableID := pending[0].ID

	recovered := &uploadStub{}
	second, err := NewPipeline(PipelineConfig{
		SensorID: "sensor-a", JobID: "job-a", BatchMaxItems: 1, BatchMaxBytes: 64 << 10, PacketQueueSize: 1,
		Source: func() (capture.Reader, error) { return &packetSourceStub{}, nil },
		Spool:  openTestSpool(t, dir, func() time.Time { return now.Add(2 * time.Second) }), Uploader: recovered, Now: func() time.Time { return now.Add(2 * time.Second) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(recovered.snapshot()) == 1 })
	recoveredBatches := recovered.snapshot()
	if recoveredBatches[0].BatchID != stableID {
		t.Fatalf("recovered batches = %+v, stable ID = %s", recoveredBatches, stableID)
	}
}

func TestPipelineAppliesStartFilterAndPacketLimit(t *testing.T) {
	start := time.Unix(300, 0).UTC()
	filter, err := packet.NewFilter(packet.FilterSpec{Protocols: []packet.Protocol{packet.TCP}, DestinationPorts: []uint16{443}})
	if err != nil {
		t.Fatal(err)
	}
	source := &packetSourceStub{packets: []packet.Packet{
		testPacket(start.Add(-time.Second), "too early"),
		testPacket(start, "wrong port"),
		testPacket(start.Add(time.Second), "accepted"),
		testPacket(start.Add(2*time.Second), "past max packet"),
	}}
	source.packets[1].DestinationPort = 80
	source.packets[2].DestinationPort = 443
	source.packets[3].DestinationPort = 443
	uploader := &uploadStub{}
	pipeline, err := NewPipeline(PipelineConfig{
		SensorID: "sensor-a", JobID: "job-a", BatchMaxItems: 10, BatchMaxBytes: 64 << 10, PacketQueueSize: 4,
		Source: func() (capture.Reader, error) { return source, nil }, Filter: filter,
		Limits: capture.Limits{StartTime: start, MaxPackets: 1},
		Spool:  openTestSpool(t, t.TempDir(), func() time.Time { return start }), Uploader: uploader, Now: func() time.Time { return start },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pipeline.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(uploader.snapshot()) == 1 })
	uploaded := uploader.snapshot()
	snapshot := pipeline.Snapshot()
	if uploaded[0].Flows[0].DestinationPort != 443 || snapshot.ReceivedPackets != 1 {
		t.Fatalf("batches=%+v snapshot=%+v", uploaded, snapshot)
	}
	if len(snapshot.CompletedJobs) != 1 || snapshot.CompletedJobs[0].JobID != "job-a" || snapshot.CompletedJobs[0].StopReason != capture.StopMaxPackets {
		t.Fatalf("capture completions = %+v", snapshot.CompletedJobs)
	}
}

func TestPipelineKeepsCapturingAcrossRecoverablePacketErrors(t *testing.T) {
	now := time.Unix(400, 0).UTC()
	source := &pollTimeoutSource{}
	pipeline, err := NewPipeline(PipelineConfig{
		SensorID: "sensor-a", JobID: "job-a", BatchMaxItems: 10, BatchMaxBytes: 64 << 10, PacketQueueSize: 1,
		Source: func() (capture.Reader, error) { return source, nil },
		Spool:  openTestSpool(t, t.TempDir(), func() time.Time { return now }), Uploader: &uploadStub{}, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pipeline.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	snapshot := pipeline.Snapshot()
	if source.calls != 4 || snapshot.LastError != "" || snapshot.DecodeErrors != 1 || snapshot.DroppedPackets != 3 || len(snapshot.Interfaces) != 1 || snapshot.Interfaces[0].Status != "ONLINE" || snapshot.Interfaces[0].DecodeErrors != 1 || snapshot.Interfaces[0].DroppedPackets != 3 {
		t.Fatalf("calls = %d, snapshot = %+v", source.calls, pipeline.Snapshot())
	}
}

func TestPipelineWaitsForPacketReaderBeforeClose(t *testing.T) {
	now := time.Unix(450, 0).UTC()
	source := &blockingLifecycleSource{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		closed:  make(chan struct{}),
	}
	pipeline, err := NewPipeline(PipelineConfig{
		SensorID: "sensor-a", JobID: "job-a", BatchMaxItems: 10, BatchMaxBytes: 64 << 10, PacketQueueSize: 1,
		Source: func() (capture.Reader, error) { return source, nil },
		Spool:  openTestSpool(t, t.TempDir(), func() time.Time { return now }), Uploader: &uploadStub{}, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- pipeline.Run(ctx) }()
	<-source.entered
	cancel()

	prematureClose := false
	select {
	case <-source.closed:
		prematureClose = true
	case <-time.After(100 * time.Millisecond):
	}
	close(source.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if prematureClose {
		t.Fatal("capture reader was closed while Next was still using it")
	}
	select {
	case <-source.closed:
	case <-time.After(time.Second):
		t.Fatal("capture reader was not closed after Next returned")
	}
}

type pollTimeoutSource struct{ calls int }

func (s *pollTimeoutSource) Next(context.Context) (packet.Packet, error) {
	s.calls++
	if s.calls == 1 {
		return packet.Packet{}, capture.ErrPollTimeout
	}
	if s.calls == 2 {
		return packet.Packet{}, capture.ErrUnsupportedPacket
	}
	if s.calls == 3 {
		return packet.Packet{}, capture.ErrMalformedPacket
	}
	return packet.Packet{}, io.EOF
}
func (*pollTimeoutSource) Close() error           { return nil }
func (*pollTimeoutSource) DroppedPackets() uint64 { return 2 }

type pcapSinkStub struct{ packets []packet.Packet }

func (s *pcapSinkStub) Enqueue(pkt packet.Packet) bool {
	s.packets = append(s.packets, pkt)
	return true
}

func TestPipelineFansAcceptedRawFramesToEachAnalysisPCAPSink(t *testing.T) {
	now := time.Unix(500, 0).UTC()
	first, second := &pcapSinkStub{}, &pcapSinkStub{}
	source := &packetSourceStub{packets: []packet.Packet{{Timestamp: now, Protocol: packet.TCP, RawFrame: []byte{1, 2, 3}, WireLength: 3}}}
	pipeline, err := NewPipeline(PipelineConfig{
		SensorID: "sensor-a", JobID: "continuous", BatchMaxItems: 10, BatchMaxBytes: 64 << 10, PacketQueueSize: 4,
		Source:    func() (capture.Reader, error) { return source, nil },
		PCAPSinks: []PCAPSink{first, second},
		Spool:     openTestSpool(t, t.TempDir(), func() time.Time { return now }), Uploader: &uploadStub{}, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pipeline.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(first.packets) != 1 || len(second.packets) != 1 {
		t.Fatalf("fanout counts = %d, %d", len(first.packets), len(second.packets))
	}
}

func TestPipelineOnlySendsAcceptedRawFramesToConfiguredPCAPSink(t *testing.T) {
	now := time.Unix(500, 0).UTC()
	accepted := testPacket(now, "accepted")
	accepted.DestinationPort = 443
	accepted.RawFrame = []byte{1, 2, 3}
	rejected := testPacket(now, "rejected")
	rejected.DestinationPort = 80
	rejected.RawFrame = []byte{4, 5, 6}
	filter, err := packet.NewFilter(packet.FilterSpec{DestinationPorts: []uint16{443}})
	if err != nil {
		t.Fatal(err)
	}
	sink := &pcapSinkStub{}
	source := &packetSourceStub{packets: []packet.Packet{rejected, accepted}}
	pipeline, err := NewPipeline(PipelineConfig{
		SensorID: "sensor-a", JobID: "job-a", BatchMaxItems: 10, BatchMaxBytes: 64 << 10, PacketQueueSize: 4,
		Source: func() (capture.Reader, error) {
			return source, nil
		},
		Filter: filter, PCAPSink: sink,
		Spool: openTestSpool(t, t.TempDir(), func() time.Time { return now }), Uploader: &uploadStub{}, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pipeline.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sink.packets) != 1 || string(sink.packets[0].RawFrame) != string(accepted.RawFrame) {
		t.Fatalf("stored packets = %+v", sink.packets)
	}
	if !source.retainRawFrame {
		t.Fatal("pipeline did not enable raw frame retention for PCAP sink")
	}
}

func TestCaptureBudgetRespectsPackets(t *testing.T) {
	pktBudget := NewCaptureBudget(1, 0)
	if accepted, _ := pktBudget.Reserve(51); !accepted {
		t.Fatal("first packet should be accepted")
	}
	// With maxPackets=1 the first (and only) packet reaches the limit, so
	// Done() is closed immediately by the same Reserve call.
	if accepted, stop := pktBudget.Reserve(51); accepted || stop != capture.StopMaxPackets {
		t.Fatalf("packet reservation = %v, %q", accepted, stop)
	}
	select {
	case <-pktBudget.Done():
	default:
		t.Fatal("done channel should close after reaching the packet limit")
	}
	if reason := pktBudget.StopReason(); reason != capture.StopMaxPackets {
		t.Fatalf("stop reason = %q", reason)
	}
}

func TestCaptureBudgetRespectsBytes(t *testing.T) {
	byteBudget := NewCaptureBudget(0, 150)
	if accepted, _ := byteBudget.Reserve(100); !accepted {
		t.Fatal("first byte reservation rejected")
	}
	select {
	case <-byteBudget.Done():
		t.Fatal("done channel should not be closed before reaching the limit")
	default:
	}
	if accepted, stop := byteBudget.Reserve(51); accepted || stop != capture.StopMaxBytes {
		t.Fatalf("overflow reservation = %v, %q", accepted, stop)
	}
	select {
	case <-byteBudget.Done():
	default:
		t.Fatal("done channel should close after reaching the byte limit")
	}
	if reason := byteBudget.StopReason(); reason != capture.StopMaxBytes {
		t.Fatalf("stop reason = %q", reason)
	}
}
