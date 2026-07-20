package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"c2hunter/sensor/internal/flowbatch"
	"c2hunter/sensor/internal/telemetry"
)

type HTTP struct {
	baseURL  string
	client   *http.Client
	mu       sync.RWMutex
	sensorID string
	token    string
}

type DiscoveredInterface struct {
	Name       string `json:"name"`
	MACAddress string `json:"mac_address,omitempty"`
}
type EnrollmentRequest struct {
	Hostname             string                `json:"hostname"`
	AgentVersion         string                `json:"agent_version"`
	OSVersion            string                `json:"os_version"`
	KernelVersion        string                `json:"kernel_version"`
	Capabilities         []string              `json:"capabilities"`
	DiscoveredInterfaces []DiscoveredInterface `json:"discovered_interfaces"`
}
type DesiredCaptureSource struct {
	Interface string `json:"interface"`
	Direction string `json:"direction"`
	BPFFilter string `json:"bpf_filter"`
	Enabled   bool   `json:"enabled"`
}
type DesiredConfig struct {
	SensorID                  string                 `json:"sensor_id,omitempty"`
	AgentToken                string                 `json:"agent_token,omitempty"`
	ConfigVersion             int64                  `json:"config_version"`
	CaptureSources            []DesiredCaptureSource `json:"capture_sources"`
	InternalNetworks          []string               `json:"internal_networks"`
	HeartbeatIntervalSeconds  int                    `json:"heartbeat_interval_seconds"`
	ConfigPollIntervalSeconds int                    `json:"config_poll_interval_seconds"`
}

func NewHTTP(baseURL string, client *http.Client) (*HTTP, error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("controller URL must use http or https scheme")
	}
	if client == nil {
		client = http.DefaultClient
	}
	return &HTTP{baseURL: parsed.String(), client: client}, nil
}

func (h *HTTP) SetIdentity(sensorID, token string) {
	h.mu.Lock()
	h.sensorID, h.token = sensorID, token
	h.mu.Unlock()
}
func (h *HTTP) authToken() string { h.mu.RLock(); defer h.mu.RUnlock(); return h.token }

func (h *HTTP) Claim(ctx context.Context, token string, request EnrollmentRequest) (DesiredConfig, error) {
	var response DesiredConfig
	err := h.doJSON(ctx, http.MethodPost, "/api/v1/sensor-enrollments/"+url.PathEscape(token)+"/claim", request, &response, "")
	if err == nil && (response.SensorID == "" || response.AgentToken == "") {
		err = fmt.Errorf("enrollment response omitted sensor_id or agent_token")
	}
	return response, err
}

func (h *HTTP) AgentConfig(ctx context.Context, sensorID string) (DesiredConfig, error) {
	var response DesiredConfig
	err := h.doJSON(ctx, http.MethodGet, "/api/v1/sensors/"+url.PathEscape(sensorID)+"/agent-config", nil, &response, h.authToken())
	return response, err
}

func (h *HTTP) Register(ctx context.Context, registration telemetry.Registration) error {
	interfaces := make([]map[string]any, 0, len(registration.Interfaces))
	for _, iface := range registration.Interfaces {
		var macAddress any
		if iface.MAC != "" {
			macAddress = iface.MAC
		}
		interfaces = append(interfaces, map[string]any{"name": iface.Name, "mac_address": macAddress, "direction": iface.Direction})
	}
	payload := map[string]any{
		"sensor_id": registration.SensorID, "name": registration.Name, "hostname": registration.Hostname,
		"agent_version": registration.AgentVersion, "os_version": registration.OS, "kernel_version": registration.KernelVersion,
		"interfaces": interfaces, "capabilities": registration.Capabilities, "current_time": registration.CurrentTime,
		"available_disk_bytes": registration.AvailableDiskBytes, "received_packets": registration.ReceivedPackets, "dropped_packets": registration.DroppedPackets,
	}
	return h.post(ctx, "/api/v1/sensors/register", payload)
}

func (h *HTTP) Heartbeat(ctx context.Context, heartbeat telemetry.Heartbeat) error {
	activeJobs := heartbeat.ActiveJobs
	if activeJobs == nil {
		activeJobs = []string{}
	}
	payload := map[string]any{
		"reported_at": heartbeat.CurrentTime, "status": heartbeat.Status.String(), "cpu_percent": heartbeat.CPUPercent,
		"memory_percent": float64(0), "disk_percent": float64(0), "active_job_ids": activeJobs,
		"received_packets": heartbeat.ReceivedPackets, "dropped_packets": heartbeat.DroppedPackets,
		"pending_bytes": heartbeat.PendingBytes, "last_error": nil, "interfaces": heartbeat.Interfaces,
	}
	if heartbeat.LastError != "" {
		payload["last_error"] = heartbeat.LastError
	}
	return h.post(ctx, "/api/v1/sensors/"+url.PathEscape(heartbeat.SensorID)+"/heartbeat", payload)
}

func (h *HTTP) UploadFlowBatch(ctx context.Context, batch flowbatch.Batch) (flowbatch.ACK, error) {
	body, err := json.Marshal(batch)
	if err != nil {
		return flowbatch.ACK{}, fmt.Errorf("encode flow batch: %w", err)
	}
	if len(batch.Flows) == 0 || batch.Flows[0].SensorID == "" {
		return flowbatch.ACK{}, fmt.Errorf("flow batch sensor ID is required")
	}
	path := "/api/v1/sensors/" + url.PathEscape(batch.Flows[0].SensorID) + "/flow-batches"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, h.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return flowbatch.ACK{}, fmt.Errorf("create flow batch request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if token := h.authToken(); token != "" {
		request.Header.Set("X-Sensor-Token", token)
	}
	response, err := h.client.Do(request)
	if err != nil {
		return flowbatch.ACK{}, fmt.Errorf("controller request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return flowbatch.ACK{}, fmt.Errorf("controller returned %s: %s", response.Status, strings.TrimSpace(string(message)))
	}
	var ack flowbatch.ACK
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&ack); err != nil {
		return flowbatch.ACK{}, fmt.Errorf("decode flow batch ACK: %w", err)
	}
	if ack.BatchID != batch.BatchID {
		return flowbatch.ACK{}, fmt.Errorf("flow batch ACK ID %q does not match %q", ack.BatchID, batch.BatchID)
	}
	return ack, nil
}

func (h *HTTP) post(ctx context.Context, path string, payload any) error {
	return h.doJSON(ctx, http.MethodPost, path, payload, nil, h.authToken())
}

func (h *HTTP) doJSON(ctx context.Context, method, path string, input, output any, token string) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, h.baseURL+path, body)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("X-Sensor-Token", token)
	}
	response, err := h.client.Do(request)
	if err != nil {
		return fmt.Errorf("controller request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return fmt.Errorf("controller returned %s: %s", response.Status, strings.TrimSpace(string(message)))
	}
	if output == nil {
		_, _ = io.Copy(io.Discard, response.Body)
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(output); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func (h *HTTP) Close() error { h.client.CloseIdleConnections(); return nil }
