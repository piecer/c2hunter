package transport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"c2hunter/sensor/internal/telemetry"
)

type heartbeatRoundTripper func(*http.Request) (*http.Response, error)

func (f heartbeatRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func heartbeatInterfaceCases() map[string][]telemetry.InterfaceStatus {
	return map[string][]telemetry.InterfaceStatus{
		"nil":       nil,
		"empty":     {},
		"populated": {{Interface: "eth0", Direction: "OUTBOUND", Status: "DEGRADED", ReceivedPackets: 37, DroppedPackets: 2, LastError: "capture interrupted"}},
	}
}

func captureHeartbeat(t *testing.T, interfaces []telemetry.InterfaceStatus) []byte {
	t.Helper()
	var body []byte
	calls := 0
	client, err := NewHTTP("http://controller.invalid", &http.Client{Transport: heartbeatRoundTripper(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/sensors/contract-sensor/heartbeat" || r.Header.Get("X-Sensor-Token") != "contract-token" || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("unexpected heartbeat request: %s %s %v", r.Method, r.URL, r.Header)
		}
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("{}")), Header: make(http.Header)}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	client.SetIdentity("contract-sensor", "contract-token")
	heartbeat := telemetry.Heartbeat{SensorID: "contract-sensor", Status: telemetry.StatusOnline, CurrentTime: time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC), Interfaces: interfaces}
	var before []telemetry.InterfaceStatus
	if interfaces != nil {
		before = append([]telemetry.InterfaceStatus{}, interfaces...)
	}
	if err := client.Heartbeat(context.Background(), heartbeat); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !reflect.DeepEqual(heartbeat.Interfaces, before) {
		t.Fatalf("calls=%d; caller interfaces changed: %#v -> %#v", calls, before, heartbeat.Interfaces)
	}
	return body
}

func TestHeartbeatInterfacesAreArrays(t *testing.T) {
	for name, interfaces := range heartbeatInterfaceCases() {
		t.Run(name, func(t *testing.T) {
			body := captureHeartbeat(t, interfaces)
			var payload map[string]json.RawMessage
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"interfaces", "active_job_ids", "completed_capture_jobs"} {
				if len(payload[key]) == 0 || payload[key][0] != '[' {
					t.Errorf("%s must be an array, got %s", key, payload[key])
				}
			}
			var got []telemetry.InterfaceStatus
			if err := json.Unmarshal(payload["interfaces"], &got); err != nil {
				t.Fatal(err)
			}
			want := interfaces
			if want == nil {
				want = []telemetry.InterfaceStatus{}
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("interface fields changed: got %#v, want %#v", got, want)
			}
		})
	}
}

// The Python consumer test runs this producer and posts these exact request bytes.
// No sockets are opened and no checked-in JSON fixture can become stale.
func TestWriteHeartbeatWireFixtures(t *testing.T) {
	directory := os.Getenv("C2HUNTER_HEARTBEAT_FIXTURE_DIR")
	if directory == "" {
		t.Skip("invoked by controller/tests/test_go_heartbeat_contract.py")
	}
	for name, interfaces := range heartbeatInterfaceCases() {
		if err := os.WriteFile(filepath.Join(directory, name+".json"), captureHeartbeat(t, interfaces), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
