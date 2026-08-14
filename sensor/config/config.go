package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type CaptureMode string

const (
	CaptureModeOnDemand   CaptureMode = "on_demand"
	CaptureModeContinuous CaptureMode = "continuous"
)

type Config struct {
	Sensor struct {
		ID   string `yaml:"id"`
		Name string `yaml:"name"`
	} `yaml:"sensor"`
	Controller struct {
		Address       string `yaml:"address"`
		URL           string `yaml:"url"`
		AllowInsecure bool   `yaml:"allow_insecure"`
	} `yaml:"controller"`
	CaptureSources    []CaptureSource `yaml:"capture_sources"`
	CaptureJobs       []CaptureJob    `yaml:"-"`
	InternalNetworks  []string        `yaml:"internal_networks"`
	HeartbeatInterval time.Duration   `yaml:"-"`
	FlowIdleTimeout   time.Duration   `yaml:"-"`
	Batch             BatchConfig     `yaml:"batch"`
	Capture           CaptureConfig   `yaml:"capture"`
	Spool             SpoolConfig     `yaml:"spool"`
	PCAP              PCAPConfig      `yaml:"pcap"`
	Agent             AgentConfig     `yaml:"agent"`
}

type CaptureSource struct {
	Interface string `yaml:"interface"`
	Direction string `yaml:"direction"`
	BPFFilter string `yaml:"bpf_filter"`
	Enabled   *bool  `yaml:"enabled,omitempty"`
	StorePCAP bool   `yaml:"store_pcap"`
}

func (s CaptureSource) IsEnabled() bool { return s.Enabled == nil || *s.Enabled }

type CaptureJob struct {
	JobID       string
	StartTime   time.Time
	EndTime     time.Time
	StorePCAP   bool
	PacketQueue int
	MaxPackets  int64
	MaxBytes    int64
	BPFFilter   string
}

type AgentConfig struct {
	EnrollmentToken           string        `yaml:"enrollment_token"`
	StateFile                 string        `yaml:"state_file"`
	ConfigPollIntervalSeconds uint64        `yaml:"config_poll_interval_seconds"`
	ConfigPollInterval        time.Duration `yaml:"-"`
	CaptureMode               CaptureMode   `yaml:"capture_mode"`
}

type BatchConfig struct {
	MaxItems int `yaml:"max_items"`
	MaxBytes int `yaml:"max_bytes"`
}

func parseOptionalInt64(raw *int64, fallback int64) int64 {
	if raw == nil {
		return fallback
	}
	return *raw
}

type CaptureConfig struct {
	JobID               string        `yaml:"job_id"`
	StartTimeText       string        `yaml:"start_time"`
	EndTimeText         string        `yaml:"end_time"`
	StartTime           time.Time     `yaml:"-"`
	EndTime             time.Time     `yaml:"-"`
	DurationSeconds     uint64        `yaml:"duration_seconds"`
	Duration            time.Duration `yaml:"-"`
	MaxPackets          uint64        `yaml:"max_packets"`
	MaxBytes            uint64        `yaml:"max_bytes"`
	PacketQueueSize     int           `yaml:"packet_queue_size"`
	PayloadPreviewBytes int           `yaml:"payload_preview_bytes"`
	BPF                 string        `yaml:"bpf_filter"`
	SourceCIDRs         []string      `yaml:"source_cidrs"`
	DestinationCIDRs    []string      `yaml:"destination_cidrs"`
	SourcePorts         []uint16      `yaml:"source_ports"`
	DestinationPorts    []uint16      `yaml:"destination_ports"`
	Protocols           []string      `yaml:"protocols"`
	IPVersions          []uint8       `yaml:"ip_versions"`
	Directions          []string      `yaml:"directions"`
	StorePCAP           bool          `yaml:"store_pcap"`
}

func parseCaptureJobs(rawJSON []byte) ([]CaptureJob, error) {
	type jobWrapper struct {
		JobID       string  `json:"job_id"`
		StartTime   string  `json:"start_time"`
		EndTime     string  `json:"end_time"`
		StorePCAP   bool    `json:"store_pcap"`
		PacketQueue *uint32 `json:"packet_queue"`
		MaxPackets  *int64  `json:"max_packets"`
		MaxBytes    *int64  `json:"max_bytes"`
	}

	var jobs []jobWrapper
	if len(rawJSON) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(rawJSON, &jobs); err != nil {
		return nil, fmt.Errorf("unmarshal capture jobs: %w", err)
	}
	result := make([]CaptureJob, len(jobs))
	for i, j := range jobs {
		startTime := time.Time{}
		if j.StartTime != "" {
			t, err := time.Parse(time.RFC3339Nano, j.StartTime)
			if err != nil {
				return nil, fmt.Errorf("parse start_time for job %q: %w", j.JobID, err)
			}
			startTime = t
		}
		endTime := time.Time{}
		if j.EndTime != "" {
			t, err := time.Parse(time.RFC3339Nano, j.EndTime)
			if err != nil {
				return nil, fmt.Errorf("parse end_time for job %q: %w", j.JobID, err)
			}
			endTime = t
		}
		pq := 4096
		if j.PacketQueue != nil {
			pq = int(*j.PacketQueue)
		}
		result[i] = CaptureJob{
			JobID:       j.JobID,
			StartTime:   startTime,
			EndTime:     endTime,
			StorePCAP:   j.StorePCAP,
			PacketQueue: pq,
			MaxPackets:  parseOptionalInt64(j.MaxPackets, 0),
			MaxBytes:    parseOptionalInt64(j.MaxBytes, 0),
		}
	}
	return result, nil
}

type SpoolConfig struct {
	Directory     string        `yaml:"directory"`
	MaxBytes      int64         `yaml:"max_bytes"`
	MaxAgeSeconds uint64        `yaml:"max_age_seconds"`
	MaxAge        time.Duration `yaml:"-"`
}

type PCAPConfig struct {
	Directory                 string        `yaml:"directory"`
	MaxSegmentBytes           int64         `yaml:"max_segment_bytes"`
	MaxSegmentDurationSeconds uint64        `yaml:"max_segment_duration_seconds"`
	MaxSegmentDuration        time.Duration `yaml:"-"`
	MaxDiskBytes              int64         `yaml:"max_disk_bytes"`
	QueueSize                 int           `yaml:"queue_size"`
}

func Load(r io.Reader) (Config, error) {
	cfg := Config{
		HeartbeatInterval: 10 * time.Second,
		FlowIdleTimeout:   60 * time.Second,
		Batch:             BatchConfig{MaxItems: 1000, MaxBytes: 1 << 20},
		Capture:           CaptureConfig{JobID: "continuous", PacketQueueSize: 4096},
		Spool:             SpoolConfig{Directory: "/var/lib/c2hunter/spool", MaxBytes: 1 << 30, MaxAgeSeconds: 86400},
		PCAP:              PCAPConfig{Directory: "/var/lib/c2hunter/pcap", MaxSegmentBytes: 128 << 20, MaxSegmentDurationSeconds: 300, MaxDiskBytes: 1 << 30, QueueSize: 4096},
		Agent:             AgentConfig{StateFile: "/var/lib/c2hunter/state/agent.json", ConfigPollIntervalSeconds: 1, CaptureMode: CaptureModeOnDemand},
	}
	if err := yaml.NewDecoder(r).Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := applyEnvironment(&cfg); err != nil {
		return Config{}, err
	}
	if err := finalize(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyEnvironment(cfg *Config) error {
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
	if v := strings.TrimSpace(os.Getenv("C2HUNTER_ALLOW_INSECURE_CONTROLLER")); v != "" {
		allowInsecure, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("C2HUNTER_ALLOW_INSECURE_CONTROLLER must be a boolean: %w", err)
		}
		cfg.Controller.AllowInsecure = allowInsecure
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
	if v := strings.TrimSpace(os.Getenv("C2HUNTER_CAPTURE_MODE")); v != "" {
		cfg.Agent.CaptureMode = CaptureMode(strings.ToLower(v))
	}
	return nil
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
		hostIP := net.ParseIP(parsed.Hostname())
		isLoopback := strings.EqualFold(parsed.Hostname(), "localhost") ||
			(hostIP != nil && hostIP.IsLoopback())
		if parsed.Scheme == "http" && !isLoopback && !cfg.Controller.AllowInsecure {
			return errors.New("remote HTTP controller requires C2HUNTER_ALLOW_INSECURE_CONTROLLER=true")
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
	const maxDurationSeconds = uint64((1<<63 - 1) / int64(time.Second))
	for name, seconds := range map[string]uint64{
		"capture duration":      cfg.Capture.DurationSeconds,
		"spool max age":         cfg.Spool.MaxAgeSeconds,
		"PCAP segment duration": cfg.PCAP.MaxSegmentDurationSeconds,
		"agent poll interval":   cfg.Agent.ConfigPollIntervalSeconds,
	} {
		if seconds > maxDurationSeconds {
			return fmt.Errorf("%s exceeds the maximum supported duration", name)
		}
	}
	// #nosec G115 -- each uint64 value is bounded by maxDurationSeconds above.
	cfg.Capture.Duration = time.Duration(cfg.Capture.DurationSeconds) * time.Second
	// #nosec G115 -- each uint64 value is bounded by maxDurationSeconds above.
	cfg.Spool.MaxAge = time.Duration(cfg.Spool.MaxAgeSeconds) * time.Second
	// #nosec G115 -- each uint64 value is bounded by maxDurationSeconds above.
	cfg.PCAP.MaxSegmentDuration = time.Duration(cfg.PCAP.MaxSegmentDurationSeconds) * time.Second
	// #nosec G115 -- each uint64 value is bounded by maxDurationSeconds above.
	cfg.Agent.ConfigPollInterval = time.Duration(cfg.Agent.ConfigPollIntervalSeconds) * time.Second
	if cfg.Agent.StateFile == "" || cfg.Agent.ConfigPollInterval <= 0 {
		return errors.New("agent state file and config poll interval are required")
	}
	if cfg.Agent.CaptureMode == "" {
		cfg.Agent.CaptureMode = CaptureModeOnDemand
	}
	if cfg.Agent.CaptureMode != CaptureModeOnDemand &&
		cfg.Agent.CaptureMode != CaptureModeContinuous {
		return errors.New("agent capture_mode must be on_demand or continuous")
	}
	if cfg.Capture.PayloadPreviewBytes < 0 || cfg.Capture.PayloadPreviewBytes > 256 {
		return errors.New("capture payload_preview_bytes must be between 0 and 256")
	}
	if cfg.Capture.JobID == "" || cfg.Capture.PacketQueueSize <= 0 {
		return errors.New("capture job ID and packet queue size are required")
	}
	if cfg.Spool.Directory == "" || cfg.Spool.MaxBytes <= 0 {
		return errors.New("spool directory and max bytes are required")
	}
	if cfg.PCAP.Directory == "" || cfg.PCAP.MaxSegmentBytes <= 0 || cfg.PCAP.MaxSegmentDuration <= 0 || cfg.PCAP.MaxDiskBytes <= 0 || cfg.PCAP.QueueSize <= 0 {
		return errors.New("PCAP directory, rotation limits, disk limit and queue size are required")
	}
	return nil
}

func parseOptionalTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, value)
}

// MarshalJSON redacts the enrollment token before serialization.
func (a AgentConfig) MarshalJSON() ([]byte, error) {
	type mask struct {
		StateFile                 string      `json:"state_file"`
		ConfigPollIntervalSeconds uint64      `json:"config_poll_interval_seconds"`
		CaptureMode               CaptureMode `json:"capture_mode"`
		EnrollmentTokenProvided   *bool       `json:"enrollment_token_provided,omitempty"`
	}
	v := mask{StateFile: a.StateFile, ConfigPollIntervalSeconds: a.ConfigPollIntervalSeconds, CaptureMode: a.CaptureMode}
	if a.EnrollmentToken != "" {
		x := true
		v.EnrollmentTokenProvided = &x
	}
	return json.Marshal(v)
}

// UnmarshalJSON restores the enrollment token when deserializing persisted state.
func (a *AgentConfig) UnmarshalJSON(data []byte) error {
	type raw struct {
		EnrollmentToken           string      `json:"enrollment_token"`
		StateFile                 string      `json:"state_file"`
		ConfigPollIntervalSeconds uint64      `json:"config_poll_interval_seconds"`
		CaptureMode               CaptureMode `json:"capture_mode"`
		EnrollmentTokenProvided   *bool       `json:"enrollment_token_provided,omitempty"`
	}
	var r raw
	if err := json.Unmarshal(data, &r); err != nil {
		return fmt.Errorf("unmarshal agent config: %w", err)
	}
	a.StateFile = r.StateFile
	a.ConfigPollIntervalSeconds = r.ConfigPollIntervalSeconds
	a.CaptureMode = r.CaptureMode
	a.EnrollmentToken = r.EnrollmentToken
	return nil
}

func ParseValueOrDie[T string | int | uint32](val *T, envKey string) *T {
	if val != nil {
		return val
	}
	envVal := os.Getenv(envKey)
	if envVal == "" {
		return nil
	}
	var result T
	switch any(&result).(type) {
	case *string:
		s := envVal
		result = any(s).(T)
	case *int:
		parsed, _ := strconv.Atoi(envVal)
		result = any(parsed).(T)
	case *uint32:
		parsed, _ := strconv.ParseUint(envVal, 10, 32)
		result = any(uint32(parsed)).(T)
	default:
		panic("unsupported ParseValueOrDie type parameter")
	}
	return &result
}
