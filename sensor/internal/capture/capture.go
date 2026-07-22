package capture

import (
	"context"
	"errors"
	"io"
	"time"

	"c2hunter/sensor/internal/packet"
)

var EndOfInput = io.EOF
var ErrPollTimeout = errors.New("packet poll timeout expired")
var ErrUnsupportedPacket = errors.New("unsupported packet")

type Reader interface {
	Next(context.Context) (packet.Packet, error)
	Close() error
}
type StopReason string

const (
	StopEndOfInput StopReason = "END_OF_INPUT"
	StopEndTime    StopReason = "END_TIME"
	StopDuration   StopReason = "DURATION"
	StopMaxPackets StopReason = "MAX_PACKETS"
	StopMaxBytes   StopReason = "MAX_BYTES"
	StopUser       StopReason = "USER_STOP"
	StopDisk       StopReason = "DISK_LOW"
	StopTimeout    StopReason = "TIMEOUT"
	StopContext    StopReason = "CONTEXT"
)

type Limits struct {
	StartTime                  time.Time
	EndTime                    time.Time
	Duration                   time.Duration
	MaxPackets, MaxBytes       uint64
	StartedAt                  time.Time
	Timeout                    time.Duration
	UserStopped, DiskAvailable func() bool
	Now                        func() time.Time
}
type Result struct {
	Reason         StopReason
	Packets, Bytes uint64
}

func Run(ctx context.Context, r Reader, limits Limits, consume func(packet.Packet) error) (Result, error) {
	var result Result
	started := limits.StartedAt
	now := limits.Now
	if now == nil {
		now = time.Now
	}
	for {
		if err := ctx.Err(); err != nil {
			result.Reason = StopContext
			return result, nil
		}
		if limits.UserStopped != nil && limits.UserStopped() {
			result.Reason = StopUser
			return result, nil
		}
		if limits.DiskAvailable != nil && !limits.DiskAvailable() {
			result.Reason = StopDisk
			return result, nil
		}
		if limits.Timeout > 0 && !started.IsZero() && !now().Before(started.Add(limits.Timeout)) {
			result.Reason = StopTimeout
			return result, nil
		}
		p, err := r.Next(ctx)
		if errors.Is(err, io.EOF) {
			result.Reason = StopEndOfInput
			return result, nil
		}
		if errors.Is(err, ErrPollTimeout) || errors.Is(err, ErrUnsupportedPacket) {
			continue
		}
		if err != nil {
			return result, err
		}
		if started.IsZero() {
			started = p.Timestamp
		}
		if !limits.StartTime.IsZero() && p.Timestamp.Before(limits.StartTime) {
			continue
		}
		if !limits.EndTime.IsZero() && !p.Timestamp.Before(limits.EndTime) {
			result.Reason = StopEndTime
			return result, nil
		}
		if limits.Duration > 0 && !p.Timestamp.Before(started.Add(limits.Duration)) {
			result.Reason = StopDuration
			return result, nil
		}
		if consume != nil {
			if err := consume(p); err != nil {
				return result, err
			}
		}
		result.Packets++
		result.Bytes += uint64(p.WireLength)
		if limits.MaxPackets > 0 && result.Packets >= limits.MaxPackets {
			result.Reason = StopMaxPackets
			return result, nil
		}
		if limits.MaxBytes > 0 && result.Bytes >= limits.MaxBytes {
			result.Reason = StopMaxBytes
			return result, nil
		}
	}
}
