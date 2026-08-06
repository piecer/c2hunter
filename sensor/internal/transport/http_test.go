package transport

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"c2hunter/sensor/internal/flowbatch"
	"c2hunter/sensor/internal/telemetry"
)

func TestHTTPTransportUsesControllerSensorRESTContract(t *testing.T) {
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.URL.Path)
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if request.URL.Path == "/api/v1/sensors/register" {
			interfaces, ok := body["interfaces"].([]any)
			if body["os_version"] != "linux" || body["current_time"] == nil || !ok || len(interfaces) != 2 {
				t.Fatalf("registration body = %#v", body)
			}
			loopback := interfaces[1].(map[string]any)
			if loopback["name"] != "lo" || loopback["mac_address"] != nil {
				t.Fatalf("loopback interface = %#v", loopback)
			}
		} else {
			activeJobs, ok := body["active_job_ids"].([]any)
			completed, completedOK := body["completed_capture_jobs"].([]any)
			discovered, discoveredOK := body["discovered_interfaces"].([]any)
			if body["reported_at"] == nil || body["status"] != "DEGRADED" || body["pcap_dropped_packets"] != float64(7) || !ok || len(activeJobs) != 0 || !completedOK || len(completed) != 1 || !discoveredOK || len(discovered) != 2 {
				t.Fatalf("heartbeat body = %#v", body)
			}
			loopback := discovered[1].(map[string]any)
			if loopback["name"] != "lo" || loopback["mac_address"] != nil {
				t.Fatalf("heartbeat loopback interface = %#v", loopback)
			}
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client, err := NewHTTP(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	registration := telemetry.Registration{SensorID: "sensor-a", Name: "Sensor A", Hostname: "host", AgentVersion: "test", OS: "linux", KernelVersion: "kernel", CurrentTime: time.Now(), Interfaces: []telemetry.Interface{
		{Name: "eth0", MAC: "00:00:00:00:00:00", Direction: "INBOUND"},
		{Name: "lo", Direction: "OUTBOUND"},
	}}
	if err := client.Register(context.Background(), registration); err != nil {
		t.Fatal(err)
	}
	heartbeat := telemetry.Heartbeat{
		SensorID: "sensor-a", Status: telemetry.StatusDegraded, CurrentTime: time.Now(), LastError: "capture unavailable",
		PCAPDroppedPackets:   7,
		CompletedCaptureJobs: []telemetry.CaptureCompletion{{JobID: "job-a", StopReason: "MAX_PACKETS"}},
		DiscoveredInterfaces: []telemetry.Interface{{Name: "eth0", MAC: "00:00:00:00:00:00"}, {Name: "lo"}},
	}
	if err := client.Heartbeat(context.Background(), heartbeat); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0] != "/api/v1/sensors/register" || paths[1] != "/api/v1/sensors/sensor-a/heartbeat" {
		t.Fatalf("paths = %v", paths)
	}
}

func TestHTTPTransportCapsHeartbeatDiscoveredInterfacesToControllerLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var body struct {
			DiscoveredInterfaces []telemetry.Interface `json:"discovered_interfaces"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body.DiscoveredInterfaces) != 128 {
			t.Fatalf("discovered interfaces = %d, want 128", len(body.DiscoveredInterfaces))
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client, err := NewHTTP(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	interfaces := make([]telemetry.Interface, 129)
	for index := range interfaces {
		interfaces[index] = telemetry.Interface{Name: fmt.Sprintf("veth%d", index)}
	}
	heartbeat := telemetry.Heartbeat{
		SensorID: "sensor-a", Status: telemetry.StatusOnline, CurrentTime: time.Now(),
		DiscoveredInterfaces: interfaces,
	}
	if err := client.Heartbeat(context.Background(), heartbeat); err != nil {
		t.Fatal(err)
	}
}

func TestAgentConfigDecodesRFC3339CaptureJobTimes(t *testing.T) {
	start := time.Date(2026, 8, 7, 1, 2, 3, 0, time.UTC)
	end := start.Add(5 * time.Minute)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/sensors/sensor-a/agent-config" {
			t.Fatalf("path = %s", request.URL.Path)
		}
		if request.Header.Get("X-Sensor-Token") != "sensor-token" {
			t.Fatalf("token = %q", request.Header.Get("X-Sensor-Token"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{
			"sensor_id":"sensor-a",
			"config_version":2,
			"capture_sources":[],
			"capture_jobs":[{
				"job_id":"job-a",
				"start_time":%q,
				"end_time":%q,
				"store_pcap":true,
				"max_packets":100,
				"max_bytes":4096,
				"bpf_filter":"udp and dst port 53"
			}],
			"internal_networks":[],
			"heartbeat_interval_seconds":15,
			"config_poll_interval_seconds":1
		}`, start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano))
	}))
	defer server.Close()

	client, err := NewHTTP(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	client.SetIdentity("sensor-a", "sensor-token")
	desired, err := client.AgentConfig(context.Background(), "sensor-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(desired.CaptureJobs) != 1 || !desired.CaptureJobs[0].StartTime.Equal(start) || !desired.CaptureJobs[0].EndTime.Equal(end) {
		t.Fatalf("capture jobs = %+v", desired.CaptureJobs)
	}
}

func TestHTTPTransportRejectsNonHTTPControllerURL(t *testing.T) {
	if _, err := NewHTTP("grpc://controller:8443", http.DefaultClient); err == nil {
		t.Fatal("expected unsupported transport scheme error")
	}
}

func TestHTTPTransportUsesLongerTimeoutForPCAPUploads(t *testing.T) {
	client, err := NewHTTP("https://controller.example", &http.Client{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if client.pcapClient.Timeout != minimumPCAPUploadTimeout {
		t.Fatalf("PCAP timeout = %s", client.pcapClient.Timeout)
	}
}

func TestHTTPTransportUploadsFlowBatchAndRequiresMatchingACK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/sensors/sensor-a/flow-batches" {
			t.Fatalf("path = %s", request.URL.Path)
		}
		var body struct {
			BatchID string                 `json:"batch_id"`
			Records []flowbatch.FlowRecord `json:"records"`
			Flows   json.RawMessage        `json:"flows"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.BatchID != "batch-a" || len(body.Records) != 1 || body.Flows != nil {
			t.Fatalf("body = %+v", body)
		}
		_ = json.NewEncoder(w).Encode(flowbatch.ACK{BatchID: body.BatchID, Duplicate: true})
	}))
	defer server.Close()
	client, err := NewHTTP(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	ack, err := client.UploadFlowBatch(context.Background(), flowbatch.Batch{BatchID: "batch-a", Flows: []flowbatch.FlowRecord{{SensorID: "sensor-a"}}})
	if err != nil {
		t.Fatal(err)
	}
	if ack.BatchID != "batch-a" || !ack.Duplicate {
		t.Fatalf("ACK = %+v", ack)
	}
}

func TestHTTPTransportUploadsPCAPSegmentWithSensorAuthentication(t *testing.T) {
	digest := sha256.Sum256([]byte("pcap"))
	checksum := hex.EncodeToString(digest[:])
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut || request.URL.Path != "/api/v1/sensors/sensor-a/pcap-segments/segment-a" {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		if request.URL.Query().Get("filename") != "eth0-000001.pcap" {
			t.Fatalf("query = %s", request.URL.RawQuery)
		}
		if request.URL.Query().Get("analysis_job_id") != "job-a" {
			t.Fatalf("analysis job query = %s", request.URL.RawQuery)
		}
		if request.Header.Get("X-Sensor-Token") != "sensor-token" {
			t.Fatalf("token = %q", request.Header.Get("X-Sensor-Token"))
		}
		if request.Header.Get("Content-Type") != "application/vnd.tcpdump.pcap" || request.ContentLength != 4 {
			t.Fatalf("headers = %#v, length = %d", request.Header, request.ContentLength)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil || string(body) != "pcap" {
			t.Fatalf("body = %q, err = %v", body, err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprintf(w, `{"segment_id":"segment-a","size_bytes":4,"sha256":"%s"}`, checksum)
	}))
	defer server.Close()
	client, err := NewHTTP(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	client.SetIdentity("sensor-a", "sensor-token")
	if err := client.UploadPCAPSegment(context.Background(), "sensor-a", "segment-a", "job-a", "eth0-000001.pcap", strings.NewReader("pcap"), 4); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPTransportRejectsMismatchedPCAPAcknowledgement(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"segment_id":"other","size_bytes":4,"sha256":"bad"}`)
	}))
	defer server.Close()
	client, err := NewHTTP(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.UploadPCAPSegment(context.Background(), "sensor-a", "segment-a", "job-a", "eth0-000001.pcap", strings.NewReader("pcap"), 4); err == nil {
		t.Fatal("mismatched ACK was accepted")
	}
}
