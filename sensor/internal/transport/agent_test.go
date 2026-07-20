package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAgentHTTPEnrollmentConfigAndTokenContract(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch calls {
		case 1:
			if r.Method != http.MethodPost || r.URL.Path != "/api/v1/sensor-enrollments/bootstrap-token/claim" || r.Header.Get("X-Sensor-Token") != "" {
				t.Fatalf("enrollment request = %s %s token=%q", r.Method, r.URL.Path, r.Header.Get("X-Sensor-Token"))
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			interfaces, ok := body["discovered_interfaces"].([]any)
			if !ok || len(interfaces) != 1 {
				t.Fatalf("enrollment interfaces = %#v", body["discovered_interfaces"])
			}
			iface, ok := interfaces[0].(map[string]any)
			if body["hostname"] != "edge" || body["os_version"] != "linux" ||
				body["kernel_version"] != "kernel" || !ok || iface["mac_address"] != "00:11" {
				t.Fatalf("enrollment body = %+v", body)
			}
			_ = json.NewEncoder(w).Encode(DesiredConfig{SensorID: "sensor-a", AgentToken: "agent-secret", ConfigVersion: 3, CaptureSources: []DesiredCaptureSource{{Interface: "eth0", Direction: "INBOUND", Enabled: true}}})
		case 2:
			if r.Method != http.MethodGet || r.URL.Path != "/api/v1/sensors/sensor-a/agent-config" || r.Header.Get("X-Sensor-Token") != "agent-secret" {
				t.Fatalf("config request = %s %s token=%q", r.Method, r.URL.Path, r.Header.Get("X-Sensor-Token"))
			}
			_ = json.NewEncoder(w).Encode(DesiredConfig{SensorID: "sensor-a", ConfigVersion: 4})
		default:
			t.Fatalf("unexpected call %d", calls)
		}
	}))
	defer server.Close()

	client, err := NewHTTP(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := client.Claim(context.Background(), "bootstrap-token", EnrollmentRequest{
		Hostname: "edge", AgentVersion: "test", OSVersion: "linux", KernelVersion: "kernel",
		DiscoveredInterfaces: []DiscoveredInterface{{Name: "eth0", MACAddress: "00:11"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	client.SetIdentity(claimed.SensorID, claimed.AgentToken)
	got, err := client.AgentConfig(context.Background(), claimed.SensorID)
	if err != nil || got.ConfigVersion != 4 {
		t.Fatalf("config=%+v err=%v", got, err)
	}
}
