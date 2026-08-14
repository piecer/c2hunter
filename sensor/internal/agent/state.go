package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type State struct {
	SensorID      string `json:"sensor_id"`
	AgentToken    string `json:"agent_token"`
	ConfigVersion int64  `json:"config_version"`
}

func Load(path string) (State, error) {
	// #nosec G304 -- path is a local administrator-configured state file.
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("read agent state: %w", err)
	}
	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, fmt.Errorf("decode agent state: %w", err)
	}
	return state, nil
}

func Save(path string, state State) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".state-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	fail := func(cause error) error { _ = tmp.Close(); return cause }
	if err := tmp.Chmod(0600); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	// #nosec G304 -- dir is derived from the administrator-configured state path.
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
