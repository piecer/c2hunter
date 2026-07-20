package transport

import (
	"context"
	"fmt"
	"sync"
	"time"

	"c2hunter/sensor/internal/telemetry"
)

type MessageKind uint8

const (
	MessageRegistration MessageKind = iota + 1
	MessageHeartbeat
	MessageBatch
	MessageLossReport
	MessageCommandResult
)

type Batch struct {
	ID            string
	SchemaVersion uint32
	Checksum      string
	Payload       []byte
}
type LossReport struct {
	Batches, Bytes uint64
	Reason         string
}
type Command struct {
	ID, Type string
	Payload  []byte
}
type Message struct {
	Kind         MessageKind
	Registration *telemetry.Registration
	Heartbeat    *telemetry.Heartbeat
	Batch        *Batch
	Loss         *LossReport
	CommandID    string
	CommandError string
}
type Stream interface {
	Send(Message) error
	Receive(context.Context) (Command, error)
	Close() error
}
type Dialer interface {
	Dial(context.Context) (Stream, error)
}
type Client struct {
	mu           sync.Mutex
	dialer       Dialer
	registration telemetry.Registration
	retryDelay   time.Duration
	stream       Stream
}

func NewClient(dialer Dialer, registration telemetry.Registration, retryDelay time.Duration) (*Client, error) {
	if dialer == nil {
		return nil, fmt.Errorf("dialer is required")
	}
	if err := registration.Validate(); err != nil {
		return nil, err
	}
	if retryDelay <= 0 {
		retryDelay = time.Second
	}
	return &Client{dialer: dialer, registration: registration, retryDelay: retryDelay}, nil
}
func (c *Client) Send(ctx context.Context, message Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if c.stream == nil {
			stream, err := c.dialer.Dial(ctx)
			if err != nil {
				if err := wait(ctx, c.retryDelay); err != nil {
					return err
				}
				continue
			}
			registration := c.registration
			if err := stream.Send(Message{Kind: MessageRegistration, Registration: &registration}); err != nil {
				stream.Close()
				if err := wait(ctx, c.retryDelay); err != nil {
					return err
				}
				continue
			}
			c.stream = stream
		}
		if err := c.stream.Send(message); err == nil {
			return nil
		}
		c.stream.Close()
		c.stream = nil
		if err := wait(ctx, c.retryDelay); err != nil {
			return err
		}
	}
}
func (c *Client) Receive(ctx context.Context) (Command, error) {
	c.mu.Lock()
	stream := c.stream
	c.mu.Unlock()
	if stream == nil {
		return Command{}, fmt.Errorf("not connected")
	}
	return stream.Receive(ctx)
}
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stream == nil {
		return nil
	}
	err := c.stream.Close()
	c.stream = nil
	return err
}
func wait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
