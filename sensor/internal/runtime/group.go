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

type backgroundCaptureRuntime interface{ backgroundRuntime() }
type trailingBackgroundCaptureRuntime interface{ trailingBackgroundRuntime() }

type captureRuntimeKind uint8

const (
	foregroundRuntime captureRuntimeKind = iota
	backgroundRuntime
	trailingBackgroundRuntime
)

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
	foregroundCtx, cancelForeground := context.WithCancel(ctx)
	backgroundCtx, cancelBackground := context.WithCancel(context.Background())
	trailingCtx, cancelTrailing := context.WithCancel(context.Background())
	defer cancelForeground()
	defer cancelBackground()
	defer cancelTrailing()
	type result struct {
		err  error
		kind captureRuntimeKind
	}
	results := make(chan result, len(g.members))
	remaining := map[captureRuntimeKind]int{}
	for _, member := range g.members {
		kind := foregroundRuntime
		memberCtx := foregroundCtx
		if _, trailing := member.(trailingBackgroundCaptureRuntime); trailing {
			kind = trailingBackgroundRuntime
			memberCtx = trailingCtx
		} else if _, background := member.(backgroundCaptureRuntime); background {
			kind = backgroundRuntime
			memberCtx = backgroundCtx
		}
		remaining[kind]++
		go func(runtime CaptureRuntime, runtimeCtx context.Context, runtimeKind captureRuntimeKind) {
			results <- result{err: runtime.Run(runtimeCtx), kind: runtimeKind}
		}(member, memberCtx, kind)
	}
	var failures []error
	record := func(result result) {
		remaining[result.kind]--
		if result.err != nil && !errors.Is(result.err, context.Canceled) {
			failures = append(failures, result.err)
			cancelForeground()
			cancelBackground()
		}
	}
	for remaining[foregroundRuntime] > 0 {
		record(<-results)
	}
	cancelBackground()
	for remaining[backgroundRuntime] > 0 {
		record(<-results)
	}
	cancelTrailing()
	for remaining[trailingBackgroundRuntime] > 0 {
		record(<-results)
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
	completed := make(map[string]struct{})
	var messages []string
	for _, member := range g.members {
		snap := member.Snapshot()
		out.ReceivedPackets += snap.ReceivedPackets
		out.DroppedPackets += snap.DroppedPackets
		out.DecodeErrors += snap.DecodeErrors
		out.PCAPDroppedPackets += snap.PCAPDroppedPackets
		if snap.PendingBytes > out.PendingBytes {
			out.PendingBytes = snap.PendingBytes
		}
		if snap.LostBatches > out.LostBatches {
			out.LostBatches = snap.LostBatches
		}
		if snap.LostBytes > out.LostBytes {
			out.LostBytes = snap.LostBytes
		}
		if snap.StopReason != "" {
			out.StopReason = snap.StopReason
		}
		for _, job := range snap.ActiveJobs {
			jobs[job] = struct{}{}
		}
		if snap.LastError != "" {
			messages = append(messages, snap.LastError)
		}
		out.Interfaces = append(out.Interfaces, snap.Interfaces...)
		for _, completion := range snap.CompletedJobs {
			key := completion.JobID + "\x00" + string(completion.StopReason)
			if _, exists := completed[key]; exists {
				continue
			}
			completed[key] = struct{}{}
			out.CompletedJobs = append(out.CompletedJobs, completion)
		}
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
