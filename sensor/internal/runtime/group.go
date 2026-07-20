package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

type CaptureGroup struct {
	members []CaptureRuntime
	mu      sync.RWMutex
	errors  []string
}

func NewCaptureGroup(members []CaptureRuntime) (*CaptureGroup, error) {
	if len(members) == 0 {
		return nil, fmt.Errorf("at least one capture runtime is required")
	}
	for _, member := range members {
		if member == nil {
			return nil, fmt.Errorf("capture runtime is required")
		}
	}
	return &CaptureGroup{members: append([]CaptureRuntime(nil), members...)}, nil
}

func (g *CaptureGroup) Run(ctx context.Context) error {
	results := make(chan error, len(g.members))
	for _, member := range g.members {
		go func(runtime CaptureRuntime) { results <- runtime.Run(ctx) }(member)
	}
	var failures []error
	for range g.members {
		if err := <-results; err != nil && !errors.Is(err, context.Canceled) {
			failures = append(failures, err)
		}
	}
	g.mu.Lock()
	g.errors = g.errors[:0]
	for _, failure := range failures {
		g.errors = append(g.errors, failure.Error())
	}
	g.mu.Unlock()
	return errors.Join(failures...)
}

func (g *CaptureGroup) Snapshot() CaptureSnapshot {
	var out CaptureSnapshot
	jobs := make(map[string]struct{})
	var messages []string
	for _, member := range g.members {
		snapshot := member.Snapshot()
		out.ReceivedPackets += snapshot.ReceivedPackets
		out.DroppedPackets += snapshot.DroppedPackets
		if snapshot.PendingBytes > out.PendingBytes {
			out.PendingBytes = snapshot.PendingBytes
		}
		if snapshot.LostBatches > out.LostBatches {
			out.LostBatches = snapshot.LostBatches
		}
		if snapshot.LostBytes > out.LostBytes {
			out.LostBytes = snapshot.LostBytes
		}
		if snapshot.StopReason != "" {
			out.StopReason = snapshot.StopReason
		}
		for _, job := range snapshot.ActiveJobs {
			jobs[job] = struct{}{}
		}
		if snapshot.LastError != "" {
			messages = append(messages, snapshot.LastError)
		}
		out.Interfaces = append(out.Interfaces, snapshot.Interfaces...)
	}
	g.mu.RLock()
	messages = append(messages, g.errors...)
	g.mu.RUnlock()
	for job := range jobs {
		out.ActiveJobs = append(out.ActiveJobs, job)
	}
	out.LastError = strings.Join(uniqueStrings(messages), "; ")
	return out
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}
