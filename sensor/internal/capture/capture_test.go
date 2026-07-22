package capture

import (
	"context"
	"errors"
	"testing"
	"time"

	"c2hunter/sensor/internal/packet"
)

type sliceReader struct {
	packets []packet.Packet
	i       int
}

func (r *sliceReader) Next(context.Context) (packet.Packet, error) {
	if r.i == len(r.packets) {
		return packet.Packet{}, EndOfInput
	}
	p := r.packets[r.i]
	r.i++
	return p, nil
}
func (r *sliceReader) Close() error { return nil }

func TestRunStopsAtEarliestPacketOrByteLimit(t *testing.T) {
	start := time.Unix(100, 0)
	reader := &sliceReader{packets: []packet.Packet{{Timestamp: start, WireLength: 60}, {Timestamp: start.Add(time.Second), WireLength: 60}, {Timestamp: start.Add(2 * time.Second), WireLength: 60}}}
	result, err := Run(context.Background(), reader, Limits{MaxPackets: 3, MaxBytes: 100}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Reason != StopMaxBytes || result.Packets != 2 || result.Bytes != 120 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestRunSupportsTimeDurationTimeoutDiskAndUserStop(t *testing.T) {
	start := time.Unix(100, 0)
	tests := []struct {
		name    string
		limits  Limits
		packets []packet.Packet
		want    StopReason
	}{
		{"end time", Limits{EndTime: start.Add(time.Second)}, []packet.Packet{{Timestamp: start}, {Timestamp: start.Add(2 * time.Second)}}, StopEndTime},
		{"duration", Limits{Duration: time.Second}, []packet.Packet{{Timestamp: start}, {Timestamp: start.Add(time.Second)}}, StopDuration},
		{"timeout", Limits{StartedAt: start, Timeout: time.Second, Now: func() time.Time { return start.Add(2 * time.Second) }}, []packet.Packet{{Timestamp: start}}, StopTimeout},
		{"disk", Limits{DiskAvailable: func() bool { return false }}, []packet.Packet{{Timestamp: start}}, StopDisk},
		{"user", Limits{UserStopped: func() bool { return true }}, []packet.Packet{{Timestamp: start}}, StopUser},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Run(context.Background(), &sliceReader{packets: tt.packets}, tt.limits, nil)
			if err != nil {
				t.Fatal(err)
			}
			if result.Reason != tt.want {
				t.Fatalf("got %v want %v", result.Reason, tt.want)
			}
		})
	}
}

func TestRunPropagatesReaderError(t *testing.T) {
	r := errorReader{err: errors.New("capture failed")}
	_, err := Run(context.Background(), r, Limits{}, nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRunTreatsPacketPollTimeoutAsIdleCapture(t *testing.T) {
	reader := &timeoutThenEndReader{}
	result, err := Run(context.Background(), reader, Limits{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Reason != StopEndOfInput || reader.calls != 2 {
		t.Fatalf("result = %+v, calls = %d", result, reader.calls)
	}
}

type timeoutThenEndReader struct{ calls int }

func (r *timeoutThenEndReader) Next(context.Context) (packet.Packet, error) {
	r.calls++
	if r.calls == 1 {
		return packet.Packet{}, ErrPollTimeout
	}
	return packet.Packet{}, EndOfInput
}
func (*timeoutThenEndReader) Close() error { return nil }

type errorReader struct{ err error }

func (r errorReader) Next(context.Context) (packet.Packet, error) { return packet.Packet{}, r.err }
func (errorReader) Close() error                                  { return nil }
