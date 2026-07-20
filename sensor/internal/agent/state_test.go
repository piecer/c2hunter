package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveStateAtomicallyWithOwnerOnlyPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "state.json")
	want := State{SensorID: "sensor-a", AgentToken: "secret", ConfigVersion: 7}
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("state = %+v, want %+v", got, want)
	}
}

func TestLoadMissingStateReturnsEmpty(t *testing.T) {
	got, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil || got != (State{}) {
		t.Fatalf("state=%+v err=%v", got, err)
	}
}
