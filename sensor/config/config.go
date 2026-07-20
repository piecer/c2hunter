package config

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Sensor struct {
		ID   string `yaml:"id"`
		Name string `yaml:"name"`
	} `yaml:"sensor"`
	Controller struct {
		Address string `yaml:"address"`
		URL     string `yaml:"url"`
	} `yaml:"controller"`
	CaptureSources    []CaptureSource `yaml:"capture_sources"`
	InternalNetworks  []string        `yaml:"internal_networks"`
	HeartbeatInterval time.Duration   `yaml:"-"`
	FlowIdleTimeout   time.Duration   `yaml:"-"`
	Batch             BatchConfig     `yaml:"batch"`
	Capture           CaptureConfig   `yaml:"capture"`
	Spool             SpoolConfig     `yaml:"spool"`
	Agent             AgentConfig     `yaml:"agent"`
}

type CaptureSource struct {
	Interface string `yaml:"interface"`
	Direction string `yaml:"direction"`
	BPFFilter string `yaml:"bpf_filter"`
	Enabled   *bool  `yaml:"enabled,omitempty"`
}

func (s CaptureSource) IsEnabled() bool { return s.Enabled == nil || *s.Enabled }

type AgentConfig struct {
	EnrollmentToken           string        `yaml:"enrollment_token"`
	StateFile                 string        `yaml:"state_file"`
	ConfigPollIntervalSeconds uint64        `yaml:"config_poll_interval_seconds"`
	ConfigPollInterval        time.Duration `yaml:"-"`
}

type BatchConfig struct {
	MaxItems int `yaml:"max_items"`
	MaxBytes int `yaml:"max_bytes"`
}

type CaptureConfig struct {
	JobID            string        `yaml:"job_id"`
	StartTimeText    string        `yaml:"start_time"`
	EndTimeText      string        `yaml:"end_time"`
	StartTime        time.Time     `yaml:"-"`
	EndTime          time.Time     `yaml:"-"`
	DurationSeconds  uint64        `yaml:"duration_seconds"`
	Duration         time.Duration `yaml:"-"`
	MaxPackets       uint64        `yaml:"max_packets"`
	MaxBytes         uint64        `yaml:"max_bytes"`
	PacketQueueSize  int           `yaml:"packet_queue_size"`
	BPF              string        `yaml:"bpf_filter"`
	SourceCIDRs      []string      `yaml:"source_cidrs"`
	DestinationCIDRs []string      `yaml:"destination_cidrs"`
	SourcePorts      []uint16      `yaml:"source_ports"`
	DestinationPorts []uint16      `yaml:"destination_ports"`
	Protocols        []string      `yaml:"protocols"`
	IPVersions       []uint8       `yaml:"ip_versions"`
	Directions       []string      `yaml:"directions"`
}

type SpoolConfig struct {
	Directory     string        `yaml:"directory"`
	MaxBytes      int64         `yaml:"max_bytes"`
	MaxAgeSeconds uint64        `yaml:"max_age_seconds"`
	MaxAge        time.Duration `yaml:"-"`
}

func Load(r io.Reader) (Config, error) {
	cfg := Config{
		HeartbeatInterval: 10 * time.Second,
		FlowIdleTimeout:   60 * time.Second,
		Batch:             BatchConfig{MaxItems: 1000, MaxBytes: 1 << 20},
		Capture:           CaptureConfig{JobID: "continuous", PacketQueueSize: 4096},
		Spool:             SpoolConfig{Directory: "/var/lib/c2hunter/spool", MaxBytes: 1 << 30, MaxAgeSeconds: 86400},
		Agent:             AgentConfig{StateFile: "/var/lib/c2hunter/state/agent.json", ConfigPollIntervalSeconds: 30},
	}
	if err := yaml.NewDecoder(r).Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	applyEnvironment(&cfg)
	if err := finalize(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyEnvironment(cfg *Config) {
	if v := os.Getenv("C2HUNTER_SENSOR_ID"); v != "" {
		cfg.Sensor.ID = v
	}
	if v := os.Getenv("C2HUNTER_CONTROLLER_ADDRESS"); v != "" {
		cfg.Controller.Address = v
	}
	if v := os.Getenv("C2HUNTER_SENSOR_NAME"); v != "" {
		cfg.Sensor.Name = v
	}
	if v := os.Getenv("C2HUNTER_CONTROLLER_URL"); v != "" {
		cfg.Controller.URL = strings.TrimRight(v, "/")
	}
	if v := os.Getenv("C2HUNTER_CAPTURE_INTERFACE"); v != "" {
		direction := os.Getenv("C2HUNTER_DIRECTION")
		if direction == "" {
			direction = "UNKNOWN"
		}
		cfg.CaptureSources = []CaptureSource{{Interface: v, Direction: direction}}
	}
	if v := os.Getenv("C2HUNTER_SPOOL_DIRECTORY"); v != "" {
		cfg.Spool.Directory = v
	}
	if v := os.Getenv("C2HUNTER_ENROLLMENT_TOKEN"); v != "" {
		cfg.Agent.EnrollmentToken = v
	}
	if v := os.Getenv("C2HUNTER_STATE_FILE"); v != "" {
		cfg.Agent.StateFile = v
	}
}

func finalize(cfg *Config) error {
	if cfg.Sensor.ID == "" && cfg.Agent.EnrollmentToken == "" {
		if _, err := os.Stat(cfg.Agent.StateFile); err != nil {
			return errors.New("sensor.id is required")
		}
	}
	if cfg.Batch.MaxItems <= 0 || cfg.Batch.MaxBytes <= 0 {
		return errors.New("batch limits must be positive")
	}
	if cfg.Controller.URL != "" {
		parsed, err := url.Parse(cfg.Controller.URL)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return errors.New("controller.url must use http or https scheme")
		}
	}
	validDirections := map[string]bool{"INBOUND": true, "OUTBOUND": true, "BIDIRECTIONAL": true, "UNKNOWN": true}
	for _, source := range cfg.CaptureSources {
		if source.Interface == "" {
			return errors.New("capture interface is required")
		}
		if !validDirections[source.Direction] {
			return fmt.Errorf("invalid direction %q", source.Direction)
		}
	}
	for _, value := range cfg.Capture.Directions {
		if !validDirections[value] {
			return fmt.Errorf("invalid capture direction %q", value)
		}
	}
	validProtocols := map[string]bool{"TCP": true, "UDP": true, "ICMP": true}
	for _, value := range cfg.Capture.Protocols {
		if !validProtocols[strings.ToUpper(value)] {
			return fmt.Errorf("invalid capture protocol %q", value)
		}
	}
	var err error
	if cfg.Capture.StartTime, err = parseOptionalTime(cfg.Capture.StartTimeText); err != nil {
		return fmt.Errorf("capture start_time: %w", err)
	}
	if cfg.Capture.EndTime, err = parseOptionalTime(cfg.Capture.EndTimeText); err != nil {
		return fmt.Errorf("capture end_time: %w", err)
	}
	if !cfg.Capture.StartTime.IsZero() && !cfg.Capture.EndTime.IsZero() && !cfg.Capture.EndTime.After(cfg.Capture.StartTime) {
		return errors.New("capture end_time must be after start_time")
	}
	cfg.Capture.Duration = time.Duration(cfg.Capture.DurationSeconds) * time.Second
	cfg.Spool.MaxAge = time.Duration(cfg.Spool.MaxAgeSeconds) * time.Second
	cfg.Agent.ConfigPollInterval = time.Duration(cfg.Agent.ConfigPollIntervalSeconds) * time.Second
	if cfg.Agent.StateFile == "" || cfg.Agent.ConfigPollInterval <= 0 {
		return errors.New("agent state file and config poll interval are required")
	}
	if cfg.Capture.JobID == "" || cfg.Capture.PacketQueueSize <= 0 {
		return errors.New("capture job ID and packet queue size are required")
	}
	if cfg.Spool.Directory == "" || cfg.Spool.MaxBytes <= 0 {
		return errors.New("spool directory and max bytes are required")
	}
	return nil
}

func parseOptionalTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, value)
}
