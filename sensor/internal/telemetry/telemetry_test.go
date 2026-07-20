package telemetry

import (
	"context"
	"testing"
	"time"
)

func TestStatusAndClockSkew(t *testing.T) {
	if DeriveStatus(StatusOnline, 3*time.Second, 2*time.Second) != StatusDegraded {
		t.Fatal("clock skew not degraded")
	}
	if DeriveStatus(StatusCapturing, time.Second, 2*time.Second) != StatusCapturing {
		t.Fatal("valid status changed")
	}
	for _, s := range []Status{StatusOnline, StatusOffline, StatusDegraded, StatusCapturing, StatusError} {
		if s.String() == "" {
			t.Fatal("empty status")
		}
	}
}
func TestRegistrationAndHeartbeatContainOperationalFields(t *testing.T) {
	r := Registration{SensorID: "s", Name: "edge", Hostname: "host", AgentVersion: "1", OS: "linux", KernelVersion: "k", Interfaces: []Interface{{Name: "eth0", MAC: "00:11", Direction: "INBOUND"}}, Capabilities: []string{"AF_PACKET", "TPACKET_V3"}, CurrentTime: time.Unix(1, 0), AvailableDiskBytes: 1000, DroppedPackets: 2}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	h := Heartbeat{SensorID: "s", Status: StatusCapturing, CurrentTime: time.Unix(2, 0), CPUPercent: 10, MemoryBytes: 20, DiskUsedBytes: 30, ActiveJobs: []string{"j"}, ReceivedPackets: 40, DroppedPackets: 2, PendingBytes: 50, LastError: ""}
	if err := h.Validate(); err != nil {
		t.Fatal(err)
	}
}
func TestHeartbeatLoopDefaultsToTenSecondsAndStops(t *testing.T) {
	if DefaultHeartbeatInterval != 10*time.Second {
		t.Fatal("heartbeat default changed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := RunHeartbeats(ctx, time.Millisecond, func() Heartbeat { return Heartbeat{SensorID: "s", Status: StatusOnline, CurrentTime: time.Now()} }, func(Heartbeat) error { calls++; cancel(); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
}
