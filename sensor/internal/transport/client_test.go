package transport

import (
	"context"
	"errors"
	"testing"
	"time"

	"c2hunter/sensor/internal/telemetry"
)

type streamStub struct {
	messages []Message
	failData bool
	closed   bool
}

func (s *streamStub) Send(m Message) error {
	s.messages = append(s.messages, m)
	if s.failData && m.Kind == MessageBatch {
		return errors.New("network")
	}
	return nil
}
func (s *streamStub) Receive(context.Context) (Command, error) { return Command{}, context.Canceled }
func (s *streamStub) Close() error                             { s.closed = true; return nil }

type dialerStub struct {
	streams []*streamStub
	calls   int
}

func (d *dialerStub) Dial(context.Context) (Stream, error) {
	s := d.streams[d.calls]
	d.calls++
	return s, nil
}
func TestClientReconnectsAndRegistersBeforeRetry(t *testing.T) {
	first := &streamStub{failData: true}
	second := &streamStub{}
	d := &dialerStub{streams: []*streamStub{first, second}}
	r := telemetry.Registration{SensorID: "s", Name: "n", Hostname: "h", AgentVersion: "1", OS: "linux", KernelVersion: "k", CurrentTime: time.Now()}
	c, err := NewClient(d, r, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Send(context.Background(), Message{Kind: MessageBatch, Batch: &Batch{ID: "b", Payload: []byte("x")}}); err != nil {
		t.Fatal(err)
	}
	if d.calls != 2 || !first.closed {
		t.Fatalf("did not reconnect: calls=%d closed=%v", d.calls, first.closed)
	}
	if len(first.messages) < 2 || first.messages[0].Kind != MessageRegistration || second.messages[0].Kind != MessageRegistration || second.messages[1].Kind != MessageBatch {
		t.Fatalf("registration ordering wrong: %v %v", first.messages, second.messages)
	}
}
func TestClientRejectsInvalidRegistration(t *testing.T) {
	if _, err := NewClient(&dialerStub{}, telemetry.Registration{}, time.Second); err == nil {
		t.Fatal("invalid registration accepted")
	}
}
