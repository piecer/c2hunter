package flowbatch_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"c2hunter/sensor/internal/capture"
	"c2hunter/sensor/internal/flow"
	"c2hunter/sensor/internal/flowbatch"
)

// TestNetworkAggregateCapabilityFixture characterizes the shared native producer,
// not a LIVE socket, capture readiness, or controller LIVE lifecycle. The PCAP
// contains only synthetic Ethernet/IPv4/TCP bytes, generated with the checksum-
// valid frame/capture helpers in analysis/tests/test_network_anomaly.py:
// SYN, repeated SYN, reverse SYN+ACK, "abc", repeated "abc", reverse ACK;
// epoch 1700000000, spaced 100ms apart. The Python contract reconstructs all bytes.
func TestNetworkAggregateCapabilityFixture(t *testing.T) {
	content, err := os.ReadFile("testdata/network_capability_six.pcap")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != "aa5cd301f6bcccaf6bd2f5d454780c83c21cc2df5bcd2b8a9d207db51e7d76bf" {
		t.Fatal("synthetic PCAP bytes changed")
	}
	reader, err := capture.NewOfflineReader(bytes.NewReader(content), "offline-owned", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(err)
		}
	})
	aggregator := flow.NewAggregator("s1", "network-capability-offline", time.Minute)
	var rows []flow.Record
	packetCount := 0
	var byteCount uint64
	for {
		packet, err := reader.Next(context.Background())
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		packetCount++
		if packetCount > 6 {
			t.Fatal("unexpected extra frame")
		}
		if !packet.EvidenceComplete || packet.WireLength <= 0 {
			t.Fatal("fixture must decode complete positive-length frames")
		}
		byteCount += uint64(packet.WireLength)
		rows = append(rows, aggregator.Add(packet)...)
	}
	rows = append(rows, aggregator.Flush()...)
	if packetCount != 6 || len(rows) != 2 {
		t.Fatalf("packets=%d rows=%d; want 6 and 2", packetCount, len(rows))
	}
	batch, err := flowbatch.New(rows)
	if err != nil {
		t.Fatal(err)
	}
	var packets, totalBytes uint64
	counts := map[string]uint64{}
	for _, row := range batch.Flows {
		packets += row.PacketCount
		totalBytes += row.TotalBytes
		counts[row.SourceIP] = row.PacketCount
	}
	if packets != 6 || totalBytes != byteCount || counts["10.0.0.1"] != 4 || counts["203.0.113.1"] != 2 {
		t.Fatalf("native aggregate conservation: packets=%d bytes=%d counts=%v", packets, totalBytes, counts)
	}
	encoded, err := flowbatch.Encode(batch)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Flows []map[string]json.RawMessage `json:"flows"`
	}
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	for _, row := range wire.Flows {
		// Other aggregate features (including SYN/DDoS sidecars) do not establish
		// the network analyzer's packet-local sequence/ACK/window evidence.
		for _, field := range []string{"packet_evidence_complete", "tcp_sequence", "tcp_acknowledgment", "tcp_window", "ip_ttl", "capture_interface_id"} {
			if _, exists := row[field]; exists {
				t.Fatalf("native network packet-evidence contract changed: %s", field)
			}
		}
	}
	output := os.Getenv("C2HUNTER_NETWORK_CAPABILITY_OUTPUT")
	if output == "" {
		output = filepath.Join(t.TempDir(), "native-batch.json")
	}
	// Explicit caller-owned output only. Never overwrite files or follow a final
	// symlink; ordinary go test writes solely inside its auto-cleaned TempDir.
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(encoded); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(actual, encoded) {
		t.Fatalf("export readback mismatch: %v", err)
	}
	t.Logf("synthetic pcap_sha256=%x decoded_packets=%d aggregate_rows=%d", digest, packetCount, len(rows))
}
