package telemetry

import (
	"context"
	"fmt"
	"time"
)

const DefaultHeartbeatInterval = 10 * time.Second

type Status uint8

const (
	StatusOnline Status = iota + 1
	StatusOffline
	StatusDegraded
	StatusCapturing
	StatusError
)

func (s Status) String() string {
	switch s {
	case StatusOnline:
		return "ONLINE"
	case StatusOffline:
		return "OFFLINE"
	case StatusDegraded:
		return "DEGRADED"
	case StatusCapturing:
		return "CAPTURING"
	case StatusError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}
func DeriveStatus(reported Status, clockOffset, tolerance time.Duration) Status {
	if clockOffset < 0 {
		clockOffset = -clockOffset
	}
	if tolerance > 0 && clockOffset > tolerance {
		return StatusDegraded
	}
	return reported
}

type Interface struct {
	Name, MAC, Direction string
	VLANs                map[uint16]string
}
type Registration struct {
	SensorID, Name, Hostname, AgentVersion, OS, KernelVersion string
	Interfaces                                                []Interface
	Capabilities                                              []string
	CurrentTime                                               time.Time
	AvailableDiskBytes, ReceivedPackets, DroppedPackets       uint64
}

func (r Registration) Validate() error {
	if r.SensorID == "" || r.Name == "" || r.Hostname == "" || r.AgentVersion == "" || r.OS == "" || r.KernelVersion == "" || r.CurrentTime.IsZero() {
		return fmt.Errorf("registration identity, platform and time fields are required")
	}
	return nil
}

type Heartbeat struct {
	SensorID                                      string
	Status                                        Status
	CurrentTime                                   time.Time
	CPUPercent                                    float64
	MemoryBytes, DiskUsedBytes                    uint64
	ActiveJobs                                    []string
	ReceivedPackets, DroppedPackets, PendingBytes uint64
	LastError                                     string
	Interfaces                                    []InterfaceStatus
}

type InterfaceStatus struct {
	Interface       string `json:"interface"`
	Direction       string `json:"direction,omitempty"`
	Status          string `json:"status"`
	ReceivedPackets uint64 `json:"received_packets"`
	DroppedPackets  uint64 `json:"dropped_packets"`
	LastError       string `json:"last_error,omitempty"`
}

func (h Heartbeat) Validate() error {
	if h.SensorID == "" || h.Status.String() == "UNKNOWN" || h.CurrentTime.IsZero() {
		return fmt.Errorf("heartbeat sensor, status and time are required")
	}
	if h.CPUPercent < 0 || h.CPUPercent > 100 {
		return fmt.Errorf("CPU percent out of range")
	}
	return nil
}
func RunHeartbeats(ctx context.Context, interval time.Duration, snapshot func() Heartbeat, send func(Heartbeat) error) error {
	if interval <= 0 {
		interval = DefaultHeartbeatInterval
	}
	if snapshot == nil || send == nil {
		return fmt.Errorf("heartbeat snapshot and sender are required")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			h := snapshot()
			if err := h.Validate(); err != nil {
				return err
			}
			if err := send(h); err != nil {
				return err
			}
		}
	}
}
