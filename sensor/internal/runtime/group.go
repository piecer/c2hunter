package runtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
)

type CaptureGroup struct {
	members  []CaptureRuntime
	mu       sync.RWMutex
	errors   []string
	lifetime *captureLifetime
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
	life := &captureLifetime{ctx: foregroundCtx}
	g.mu.Lock()
	g.lifetime = life
	g.mu.Unlock()
	defer life.terminal.Store(true)
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
		kind := runtimeKind(member)
		memberCtx := foregroundCtx
		switch kind {
		case trailingBackgroundRuntime:
			memberCtx = trailingCtx
		case backgroundRuntime:
			memberCtx = backgroundCtx
		}
		remaining[kind]++
		go func(runtime CaptureRuntime, runtimeCtx context.Context, runtimeKind captureRuntimeKind) {
			err := runtime.Run(runtimeCtx)
			if runtimeKind == foregroundRuntime || err != nil {
				life.terminal.Store(true)
			}
			results <- result{err: err, kind: runtimeKind}
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

func (g *CaptureGroup) Snapshot() CaptureSnapshot { return g.snapshotWithReadiness(&readinessBudget{}) }
func (g *CaptureGroup) snapshotWithReadiness(budget *readinessBudget) CaptureSnapshot {
	g.mu.RLock()
	life := g.lifetime
	g.mu.RUnlock()
	var out CaptureSnapshot
	if budget != nil && !budget.failed {
		out.observation = &captureObservation{complete: true, interfaces: []CaptureReadyInterface{}}
	}
	jobs := make(map[string]struct{})
	completed := make(map[string]struct{})
	var messages []string
	for _, member := range g.members {
		childBudget := budget
		if runtimeKind(member) != foregroundRuntime {
			childBudget = nil
		}
		snap := snapshotCapture(member, childBudget)
		if out.observation != nil && childBudget != nil {
			if budget.failed {
				out.observation.invalidate()
			} else {
				out.observation.add(snap.observation)
			}
		}
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
	if out.observation != nil && (g.lifetime != life || !life.live()) {
		out.observation.invalidate()
	}
	g.mu.RUnlock()
	for job := range jobs {
		out.ActiveJobs = append(out.ActiveJobs, job)
	}

	out.LastError = strings.Join(uniqueStrings(messages), "; ")
	return out
}

func runtimeKind(member CaptureRuntime) captureRuntimeKind {
	if _, ok := member.(trailingBackgroundCaptureRuntime); ok {
		return trailingBackgroundRuntime
	}
	if _, ok := member.(backgroundCaptureRuntime); ok {
		return backgroundRuntime
	}
	return foregroundRuntime
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
