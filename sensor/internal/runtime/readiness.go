package runtime

import (
	"context"
	"regexp"
	"sort"
	"sync/atomic"
)

// One budget follows built-in foreground snapshots through the whole tree.
// Rejected siblings still contribute legacy metrics, but allocate no sidecars.
type readinessBudget struct {
	rows, jobs int
	failed     bool
}

func (b *readinessBudget) admit(rows, jobs int) bool {
	if b == nil || b.failed {
		return false
	}
	if rows < 1 || jobs < 1 || rows > readinessLimit-b.rows || jobs > readinessLimit-b.jobs {
		b.failed = true
		return false
	}
	b.rows += rows
	b.jobs += jobs
	return true
}
func snapshotCapture(member CaptureRuntime, budget *readinessBudget) CaptureSnapshot {
	switch child := member.(type) {
	case *Pipeline:
		return child.snapshotWithReadiness(budget)
	case *CaptureGroup:
		return child.snapshotWithReadiness(budget)
	default:
		snap := member.Snapshot()
		if budget != nil && !budget.failed {
			observation := snap.observation
			if observation == nil || !observation.complete || len(observation.interfaces) == 0 || len(observation.interfaces) > readinessLimit-budget.rows {
				budget.failed = true
				return snap
			}
			jobs := 0
			for _, row := range observation.interfaces {
				if len(row.JobIDs) > readinessLimit-budget.jobs-jobs || !eligibleReadyRow(row) {
					budget.failed = true
					return snap
				}
				jobs += len(row.JobIDs)
			}
			budget.admit(len(observation.interfaces), jobs)
		}
		return snap
	}
}

type captureLifetime struct {
	ctx      context.Context
	terminal atomic.Bool
}

func (l *captureLifetime) live() bool { return l != nil && l.ctx.Err() == nil && !l.terminal.Load() }

// CaptureReadiness is a local observation, never a telemetry heartbeat field.
// Only Supervisor supplies its instance and ownership generation.
type CaptureReadiness struct {
	Version       int                     `json:"version"`
	InstanceID    string                  `json:"instance_id"`
	Generation    uint64                  `json:"generation"`
	ConfigVersion int64                   `json:"config_version"`
	Complete      bool                    `json:"complete"`
	Interfaces    []CaptureReadyInterface `json:"interfaces"`
}
type CaptureReadyInterface struct {
	Interface    string   `json:"interface"`
	Direction    string   `json:"direction"`
	JobIDs       []string `json:"job_ids"`
	CaptureReady bool     `json:"capture_ready"`
}

const readinessLimit = 128

var readinessInstanceID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Validate the bounded ASCII grammar without regexp match-machine allocation.
// This also makes the raw-budget allocation bound independent of sync.Pool
// eviction (including the race detector's randomized pool drops).
func eligibleObservationName(value string, maxBytes int, allowColon bool) bool {
	if len(value) == 0 || len(value) > maxBytes {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-' || allowColon && c == ':' {
			continue
		}
		return false
	}
	return true
}

func eligibleReadyRow(row CaptureReadyInterface) bool {
	if !eligibleObservationName(row.Interface, 15, false) {
		return false
	}
	switch row.Direction {
	case "INBOUND", "OUTBOUND", "BIDIRECTIONAL", "UNKNOWN":
	default:
		return false
	}
	if len(row.JobIDs) == 0 || len(row.JobIDs) > readinessLimit {
		return false
	}
	for _, id := range row.JobIDs {
		if !eligibleObservationName(id, 200, true) {
			return false
		}
	}
	return true
}
func pipelineObservation(iface, direction string, ids []string, ready bool) *captureObservation {
	row := CaptureReadyInterface{Interface: iface, Direction: direction, JobIDs: ids, CaptureReady: ready}
	if !eligibleReadyRow(row) {
		return &captureObservation{interfaces: []CaptureReadyInterface{}}
	}
	row.JobIDs = append([]string(nil), ids...)
	return &captureObservation{complete: true, interfaces: []CaptureReadyInterface{row}}
}

// Raw observations remain uncollapsed through nested groups: duplicate entries
// still spend the shared budget. No child can hide raw cost behind deduplication.
func (o *captureObservation) add(child *captureObservation) {
	if !o.complete {
		return
	}
	if child == nil || !child.complete || len(child.interfaces) == 0 || len(child.interfaces) > readinessLimit-len(o.interfaces) {
		o.invalidate()
		return
	}
	jobs := 0
	for _, row := range o.interfaces {
		jobs += len(row.JobIDs)
	}
	for _, row := range child.interfaces {
		if len(row.JobIDs) > readinessLimit-jobs || !eligibleReadyRow(row) {
			o.invalidate()
			return
		}
		jobs += len(row.JobIDs)
	}
	for _, row := range child.interfaces {
		row.JobIDs = append([]string(nil), row.JobIDs...)
		o.interfaces = append(o.interfaces, row)
	}
}
func (o *captureObservation) invalidate() {
	o.complete = false
	o.interfaces = []CaptureReadyInterface{}
}
func (o *captureObservation) normalized() (bool, []CaptureReadyInterface) {
	empty := []CaptureReadyInterface{}
	checked := &captureObservation{complete: true}
	checked.add(o)
	if !checked.complete {
		return false, empty
	}
	rows := make(map[string]CaptureReadyInterface)
	for _, row := range checked.interfaces {
		key := row.Interface + "\x00" + row.Direction
		prior, ok := rows[key]
		if ok && prior.CaptureReady != row.CaptureReady {
			return false, empty
		}
		if !ok {
			prior = row
			prior.JobIDs = nil
		}
		prior.JobIDs = append(prior.JobIDs, row.JobIDs...)
		rows[key] = prior
	}
	result := make([]CaptureReadyInterface, 0, len(rows))
	for _, row := range rows {
		sort.Strings(row.JobIDs)
		ids := row.JobIDs[:0]
		for _, id := range row.JobIDs {
			if len(ids) == 0 || ids[len(ids)-1] != id {
				ids = append(ids, id)
			}
		}
		row.JobIDs = ids
		result = append(result, row)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Interface == result[j].Interface {
			return result[i].Direction < result[j].Direction
		}
		return result[i].Interface < result[j].Interface
	})
	return true, result
}

type captureObservation struct {
	complete   bool
	interfaces []CaptureReadyInterface
}
