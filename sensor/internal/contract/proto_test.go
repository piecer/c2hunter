package contract

import (
	"os"
	"strings"
	"testing"
)

func TestSensorProtoDefinesOutboundStreamAndOperationalMessages(t *testing.T) {
	data, err := os.ReadFile("../../../proto/sensor.proto")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{"service SensorGateway", "rpc Connect(stream SensorEnvelope) returns (stream ControllerEnvelope)", "message SensorRegistration", "message Heartbeat", "message FlowBatch", "message BatchAck", "message LossReport", "message CaptureCommand", "enum Direction", "enum SensorStatus", "google.protobuf.Timestamp current_time", "google.protobuf.Timestamp reported_at", "double memory_percent", "uint64 pending_bytes"} {
		if !strings.Contains(text, required) {
			t.Errorf("missing %q", required)
		}
	}
}
