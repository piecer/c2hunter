package flowbatch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"c2hunter/sensor/internal/flow"
	"c2hunter/sensor/internal/metadata"
	"c2hunter/sensor/internal/packet"
)

type FlowRecord struct {
	SensorID               string    `json:"sensor_id"`
	Timestamp              time.Time `json:"timestamp"`
	SourceIP               string    `json:"source_ip"`
	DestinationIP          string    `json:"destination_ip"`
	SourcePort             uint16    `json:"source_port"`
	DestinationPort        uint16    `json:"destination_port"`
	Protocol               string    `json:"protocol"`
	Direction              string    `json:"direction"`
	PacketCount            uint64    `json:"packet_count"`
	TotalBytes             uint64    `json:"total_bytes"`
	TcpFlags               *TcpFlags `json:"tcp_flags,omitempty"`
	TCPFlagsObserved       bool      `json:"tcp_flags_observed,omitempty"`
	TCPSYNCount            uint64    `json:"tcp_syn_count,omitempty"`
	TCPACKCount            uint64    `json:"tcp_ack_count,omitempty"`
	TCPRSTCount            uint64    `json:"tcp_rst_count,omitempty"`
	TCPSYNOnlyCount        uint64    `json:"tcp_syn_only_count,omitempty"`
	TCPSYNACKCount         uint64    `json:"tcp_syn_ack_count,omitempty"`
	TCPACKOnlyCount        uint64    `json:"tcp_ack_only_count,omitempty"`
	Bidirectional          bool      `json:"bidirectional,omitempty"`
	PayloadHash            string    `json:"payload_hash,omitempty"`
	LastPayloadHash        string    `json:"last_payload_hash,omitempty"`
	PayloadPrefixHash      string    `json:"payload_prefix_hash,omitempty"`
	PayloadSampleHex       string    `json:"payload_sample_hex,omitempty"`
	PayloadLength          *uint32   `json:"payload_length,omitempty"`
	PayloadEntropy         *float64  `json:"payload_entropy,omitempty"`
	PayloadPrintableRatio  *float64  `json:"payload_printable_ratio,omitempty"`
	PayloadSimHash         string    `json:"payload_simhash,omitempty"`
	PayloadFeatureVersion  string    `json:"payload_feature_version,omitempty"`
	TLSFingerprint         string    `json:"tls_fingerprint,omitempty"`
	CertificateFingerprint string    `json:"certificate_fingerprint,omitempty"`
	Domain                 string    `json:"domain,omitempty"`
	PacketSizes            []uint32  `json:"packet_sizes"`
}

type TcpFlags struct {
	FIN             *uint64  `json:"fin,omitempty"`
	SYN             *uint64  `json:"syn,omitempty"`
	RST             *uint64  `json:"rst,omitempty"`
	PSH             *uint64  `json:"psh,omitempty"`
	ACK             *uint64  `json:"ack,omitempty"`
	URG             *uint64  `json:"urg,omitempty"`
	ECE             *uint64  `json:"ece,omitempty"`
	CWR             *uint64  `json:"cwr,omitempty"`
	SYNACKRatio     *float64 `json:"syn_ack_ratio,omitempty"`
	RSTRatio        *float64 `json:"rst_ratio,omitempty"`
	ConnectionCount *uint64  `json:"connection_count,omitempty"`
}

type Batch struct {
	BatchID string       `json:"batch_id"`
	Flows   []FlowRecord `json:"flows"`
}

type ACK struct {
	BatchID   string `json:"batch_id"`
	Accepted  bool   `json:"accepted"`
	Duplicate bool   `json:"duplicate"`
}

func New(records []flow.Record) (Batch, error) {
	flows := make([]FlowRecord, 0, len(records))
	for _, record := range records {
		flows = append(flows, fromRecord(record))
	}
	encoded, err := json.Marshal(flows)
	if err != nil {
		return Batch{}, fmt.Errorf("encode flow batch: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return Batch{BatchID: hex.EncodeToString(digest[:]), Flows: flows}, nil
}

func Encode(batch Batch) ([]byte, error) {
	data, err := json.Marshal(batch)
	if err != nil {
		return nil, fmt.Errorf("encode flow batch: %w", err)
	}
	return data, nil
}

func Decode(data []byte) (Batch, error) {
	var batch Batch
	if err := json.Unmarshal(data, &batch); err != nil {
		return Batch{}, fmt.Errorf("decode flow batch: %w", err)
	}
	if batch.BatchID == "" {
		return Batch{}, fmt.Errorf("flow batch ID is required")
	}
	return batch, nil
}

func fromRecord(record flow.Record) FlowRecord {
	out := FlowRecord{
		SensorID: record.Key.SensorID, Timestamp: record.StartTime,
		SourceIP: record.Key.SourceIP.String(), DestinationIP: record.Key.DestinationIP.String(),
		SourcePort: record.Key.SourcePort, DestinationPort: record.Key.DestinationPort,
		Protocol: protocolName(record.Key.Protocol), Direction: record.Key.Direction.String(),
		PacketCount: record.PacketCount, TotalBytes: record.TotalBytes,
		TCPFlagsObserved: record.TCPFlagsObserved,
		TCPSYNCount:      record.TCPFlags.SYN,
		TCPACKCount:      record.TCPFlags.ACK,
		TCPRSTCount:      record.TCPFlags.RST,
		TCPSYNOnlyCount:  record.TCPSYNOnlyCount,
		TCPSYNACKCount:   record.TCPSYNACKCount,
		TCPACKOnlyCount:  record.TCPACKOnlyCount,
		Bidirectional:    record.Bidirectional,
		PayloadHash:      record.FirstPayloadHash, LastPayloadHash: record.LastPayloadHash,
		PayloadPrefixHash: record.PayloadPrefixHash, PayloadSampleHex: record.PayloadSampleHex,
		PayloadSimHash:        record.PayloadSimHash,
		PayloadFeatureVersion: record.PayloadFeatureVersion,
	}
	if record.FirstPayloadHash != "" {
		out.PayloadLength = &record.FirstPayloadLength
		out.PayloadEntropy = &record.PayloadEntropy
		out.PayloadPrintableRatio = &record.PayloadPrintable
	}
	if record.MinPacketSize == record.MaxPacketSize {
		out.PacketSizes = []uint32{record.MinPacketSize}
	} else {
		out.PacketSizes = []uint32{record.MinPacketSize, record.MaxPacketSize}
	}
	out.TcpFlags = &TcpFlags{
		FIN: &record.TCPFlags.FIN,
		SYN: &record.TCPFlags.SYN,
		RST: &record.TCPFlags.RST,
		PSH: &record.TCPFlags.PSH,
		ACK: &record.TCPFlags.ACK,
		URG: &record.TCPFlags.URG,
		ECE: &record.TCPFlags.ECE,
		CWR: &record.TCPFlags.CWR,
	}
	if record.TCPFlags.SYN > 0 && record.TCPFlags.ACK > 0 {
		out.TcpFlags.SYNACKRatio = record.SYNACKRatio
	}
	if record.RSTRatio != nil {
		out.TcpFlags.RSTRatio = record.RSTRatio
	}
	if record.ConnectionCount != nil {
		out.TcpFlags.ConnectionCount = record.ConnectionCount
	}
	applyMetadata(&out, record.ProtocolMetadata)
	return out
}

func applyMetadata(record *FlowRecord, value metadata.Metadata) {
	if value.DNS != nil {
		record.Domain = value.DNS.QueryName
	}
	if value.HTTP != nil {
		record.Domain = value.HTTP.Host
	}
	if value.TLS != nil {
		record.Domain = value.TLS.SNI
		record.TLSFingerprint = value.TLS.ClientHelloFingerprint
		if record.TLSFingerprint == "" {
			record.TLSFingerprint = value.TLS.ServerHelloFingerprint
		}
		record.CertificateFingerprint = value.TLS.CertificateSHA256
	}
}

func protocolName(value packet.Protocol) string {
	switch value {
	case packet.TCP:
		return "TCP"
	case packet.UDP:
		return "UDP"
	case packet.ICMP:
		return "ICMP"
	default:
		return "UNKNOWN"
	}
}
