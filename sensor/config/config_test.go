package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadAcceptsEnvironmentOnlyHTTPRuntimeConfiguration(t *testing.T) {
	t.Setenv("C2HUNTER_SENSOR_ID", "sensor-a")
	t.Setenv("C2HUNTER_SENSOR_NAME", "Sensor A")
	t.Setenv("C2HUNTER_CONTROLLER_URL", "http://controller:8000")
	t.Setenv("C2HUNTER_CAPTURE_INTERFACE", "eth0")
	t.Setenv("C2HUNTER_DIRECTION", "INBOUND")

	cfg, err := Load(strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Controller.URL != "http://controller:8000" {
		t.Fatalf("controller URL = %q", cfg.Controller.URL)
	}
	if len(cfg.CaptureSources) != 1 || cfg.CaptureSources[0].Interface != "eth0" {
		t.Fatalf("capture sources = %+v", cfg.CaptureSources)
	}
}

func TestLoadRejectsControllerURLWithUnsupportedScheme(t *testing.T) {
	t.Setenv("C2HUNTER_SENSOR_ID", "sensor-a")
	t.Setenv("C2HUNTER_SENSOR_NAME", "Sensor A")
	t.Setenv("C2HUNTER_CONTROLLER_URL", "ftp://controller:21")

	_, err := Load(strings.NewReader(""))
	if err == nil || !strings.Contains(err.Error(), "http or https") {
		t.Fatalf("expected URL scheme error, got %v", err)
	}
}

func TestLoadYAMLDefaultsAndEnvironmentOverride(t *testing.T) {
	t.Setenv("C2HUNTER_SENSOR_ID", "env-id")
	t.Setenv("C2HUNTER_CONTROLLER_ADDRESS", "controller:9443")
	cfg, err := Load(strings.NewReader(`
sensor:
  id: yaml-id
  name: edge
capture_sources:
  - interface: eth0
    direction: INBOUND
internal_networks: [10.0.0.0/8]
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sensor.ID != "env-id" || cfg.Controller.Address != "controller:9443" {
		t.Fatalf("env override failed: %+v", cfg)
	}
	if cfg.HeartbeatInterval != 10*time.Second || cfg.FlowIdleTimeout != 60*time.Second {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
	if cfg.Batch.MaxItems <= 0 || cfg.Batch.MaxBytes <= 0 {
		t.Fatalf("batch must be bounded: %+v", cfg.Batch)
	}
}

func TestLoadRejectsInvalidConfiguration(t *testing.T) {
	t.Setenv("C2HUNTER_SENSOR_ID", "")
	_, err := Load(strings.NewReader("sensor: {name: missing-id}\n"))
	if err == nil {
		t.Fatal("expected missing sensor id error")
	}
}

func TestLoadCaptureRuntimeBoundaries(t *testing.T) {
	cfg, err := Load(strings.NewReader(`
sensor: {id: sensor-a, name: edge}
capture_sources:
  - {interface: eth0, direction: UNKNOWN, bpf_filter: tcp}
capture:
  job_id: job-a
  start_time: 2026-07-20T10:00:00Z
  end_time: 2026-07-20T10:05:00Z
  duration_seconds: 120
  payload_preview_bytes: 128
  max_packets: 50
  max_bytes: 4096
  source_cidrs: [10.0.0.0/8]
  destination_ports: [443]
  protocols: [TCP]
  ip_versions: [4]
  directions: [OUTBOUND]
spool:
  directory: /tmp/c2hunter-spool
  max_bytes: 1048576
  max_age_seconds: 3600
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Capture.JobID != "job-a" || cfg.Capture.Duration != 2*time.Minute || cfg.Capture.MaxPackets != 50 || cfg.Capture.MaxBytes != 4096 || cfg.Capture.PayloadPreviewBytes != 128 {
		t.Fatalf("capture = %+v", cfg.Capture)
	}
	if cfg.Capture.StartTime.IsZero() || cfg.Capture.EndTime.IsZero() || cfg.Spool.Directory != "/tmp/c2hunter-spool" || cfg.Spool.MaxAge != time.Hour {
		t.Fatalf("capture/spool boundaries = %+v %+v", cfg.Capture, cfg.Spool)
	}
}

func TestLoadRejectsOversizedPayloadPreview(t *testing.T) {
	_, err := Load(strings.NewReader(`
sensor: {id: sensor-a, name: edge}
capture_sources: [{interface: eth0, direction: OUTBOUND}]
capture: {job_id: continuous, packet_queue_size: 4096, payload_preview_bytes: 257}
`))
	if err == nil || !strings.Contains(err.Error(), "payload_preview_bytes") {
		t.Fatalf("expected payload preview validation error, got %v", err)
	}
}

func TestLoadSupportsEnrollmentBootstrapWithoutLocalSensorID(t *testing.T) {
	t.Setenv("C2HUNTER_ENROLLMENT_TOKEN", "bootstrap-secret")
	cfg, err := Load(strings.NewReader(`controller: {url: https://controller.example}
sensor: {name: edge}
agent: {state_file: /tmp/sensor-state.json, config_poll_interval_seconds: 17}
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Agent.EnrollmentToken != "bootstrap-secret" || cfg.Agent.StateFile != "/tmp/sensor-state.json" || cfg.Agent.ConfigPollInterval != 17*time.Second {
		t.Fatalf("agent config = %+v", cfg.Agent)
	}
}
