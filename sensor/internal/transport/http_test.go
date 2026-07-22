package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
			if body["reported_at"] == nil || body["status"] != "DEGRADED" || !ok || len(activeJobs) != 0 {
				t.Fatalf("heartbeat body = %#v", body)
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
	heartbeat := telemetry.Heartbeat{SensorID: "sensor-a", Status: telemetry.StatusDegraded, CurrentTime: time.Now(), LastError: "capture unavailable"}
	if err := client.Heartbeat(context.Background(), heartbeat); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0] != "/api/v1/sensors/register" || paths[1] != "/api/v1/sensors/sensor-a/heartbeat" {
		t.Fatalf("paths = %v", paths)
	}
}

func TestHTTPTransportRejectsNonHTTPControllerURL(t *testing.T) {
	if _, err := NewHTTP("grpc://controller:8443", http.DefaultClient); err == nil {
		t.Fatal("expected unsupported transport scheme error")
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
