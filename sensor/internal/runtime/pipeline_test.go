package runtime

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"testing"
	"time"

	"c2hunter/sensor/internal/capture"
	"c2hunter/sensor/internal/direction"
	"c2hunter/sensor/internal/flowbatch"
	"c2hunter/sensor/internal/packet"
	"c2hunter/sensor/internal/spool"
)

type packetSourceStub struct {
	packets []packet.Packet
	index   int
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

type uploadStub struct {
	batches []flowbatch.Batch
	err     error
}

func (s *uploadStub) UploadFlowBatch(_ context.Context, batch flowbatch.Batch) (flowbatch.ACK, error) {
	s.batches = append(s.batches, batch)
	if s.err != nil {
		return flowbatch.ACK{}, s.err
	}
	return flowbatch.ACK{BatchID: batch.BatchID, Accepted: true}, nil
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
	if len(uploader.batches) != 1 || len(uploader.batches[0].Flows) != 1 {
		t.Fatalf("uploaded batches = %+v", uploader.batches)
	}
	flow := uploader.batches[0].Flows[0]
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
	if first.Snapshot().LastError == "" {
		t.Fatal("upload failure was not reflected in pipeline status")
	}
	pending, err := openTestSpool(t, dir, func() time.Time { return now.Add(2 * time.Second) }).Pending()
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
	if len(recovered.batches) != 1 || recovered.batches[0].BatchID != stableID {
		t.Fatalf("recovered batches = %+v, stable ID = %s", recovered.batches, stableID)
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
	if len(uploader.batches) != 1 || uploader.batches[0].Flows[0].DestinationPort != 443 || pipeline.Snapshot().ReceivedPackets != 1 {
		t.Fatalf("batches=%+v snapshot=%+v", uploader.batches, pipeline.Snapshot())
	}
}

func TestPipelineTreatsPacketPollTimeoutAsIdleCapture(t *testing.T) {
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
	if source.calls != 3 || snapshot.LastError != "" || len(snapshot.Interfaces) != 1 || snapshot.Interfaces[0].Status != "ONLINE" {
		t.Fatalf("calls = %d, snapshot = %+v", source.calls, pipeline.Snapshot())
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
	return packet.Packet{}, io.EOF
}
func (*pollTimeoutSource) Close() error { return nil }
