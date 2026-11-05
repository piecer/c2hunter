package packet_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"c2hunter/sensor/internal/packet"
)

// All inputs are synthetic payloads; these tests use no capture device or socket.
func passivePacket(payload []byte, src, dst uint16) packet.Packet {
	return packet.Packet{
		Protocol: packet.UDP, EvidenceComplete: true,
		Timestamp: time.UnixMicro(1234567), IPLength: 100,
		SourcePort: src, DestinationPort: dst, Payload: payload,
	}
}

func passiveDigest(data []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func checkPassiveSample(t *testing.T, p packet.Packet, semantic, transaction string) *packet.DDoSSample {
	t.Helper()
	original := bytes.Clone(p.Payload)
	got := p.DDoSSample()
	if got == nil {
		t.Fatal("complete passive transport evidence was dropped")
	}
	if got.Semantic != semantic {
		t.Errorf("semantic = %q, want %q", got.Semantic, semantic)
	}
	if transaction == "" {
		if got.Transaction != nil {
			t.Errorf("abstaining/unmatchable sample retained transaction %q", *got.Transaction)
		}
	} else if got.Transaction == nil || *got.Transaction != transaction {
		t.Errorf("transaction = %v, want %s", got.Transaction, transaction)
	}
	if !bytes.Equal(p.Payload, original) {
		t.Error("sample construction mutated the packet payload")
	}
	if got.TimestampUS != p.Timestamp.UnixMicro() {
		t.Errorf("timestamp = %d, want %d", got.TimestampUS, p.Timestamp.UnixMicro())
	}
	return got
}

func TestPassiveDNSQuestionTransaction(t *testing.T) {
	// Token input is the wire ID followed by the complete uncompressed question,
	// not flags, answer records, or the endpoint tuple. It is not authentication.
	question := []byte("\x03www\x07example\x03com\x00\x00\x01\x00\x01")
	query := append([]byte{0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0}, question...)
	response := bytes.Clone(query)
	response[2], response[3], response[7] = 0x81, 0x80, 1
	response = append(response, []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1}...)
	changedID := bytes.Clone(query)
	changedID[1] = 0x35
	changedType := bytes.Clone(query)
	changedType[len(changedType)-3] = 28
	changedClass := bytes.Clone(query)
	changedClass[len(changedClass)-1] = 3
	changedName := bytes.Clone(query)
	changedName[13] = 'W'
	root := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1}
	for _, tc := range []struct {
		name             string
		body             []byte
		src, dst         uint16
		semantic, rawKey string
	}{
		{"request", query, 53000, 53, "DNS_REQUEST", "\x12\x34\x03www\x07example\x03com\x00\x00\x01\x00\x01"},
		{"response_matches_despite_flags_and_answer", response, 53, 53000, "DNS_RESPONSE", "\x12\x34\x03www\x07example\x03com\x00\x00\x01\x00\x01"},
		{"other_client_port_same_question", query, 54000, 53, "DNS_REQUEST", "\x12\x34\x03www\x07example\x03com\x00\x00\x01\x00\x01"},
		{"different_id", changedID, 53000, 53, "DNS_REQUEST", "\x12\x35\x03www\x07example\x03com\x00\x00\x01\x00\x01"},
		{"different_type", changedType, 53000, 53, "DNS_REQUEST", "\x12\x34\x03www\x07example\x03com\x00\x00\x1c\x00\x01"},
		{"different_class", changedClass, 53000, 53, "DNS_REQUEST", "\x12\x34\x03www\x07example\x03com\x00\x00\x01\x00\x03"},
		{"exact_question_bytes_not_case_folded", changedName, 53000, 53, "DNS_REQUEST", "\x12\x34\x03Www\x07example\x03com\x00\x00\x01\x00\x01"},
		{"root_question_minimum_length", root, 53000, 53, "DNS_REQUEST", "\x12\x34\x00\x00\x01\x00\x01"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkPassiveSample(t, passivePacket(tc.body, tc.src, tc.dst), tc.semantic, passiveDigest([]byte(tc.rawKey)))
		})
	}
	// Maximum single-label length is admitted, rather than rejecting every
	// unusually long name in the malformed-label tests below.
	longQuestion := append([]byte{63}, bytes.Repeat([]byte{'a'}, 63)...)
	longQuestion = append(longQuestion, 0, 0, 1, 0, 1)
	longQuery := append(bytes.Clone(query[:12]), longQuestion...)
	key := append([]byte{0x12, 0x34}, longQuestion...)
	checkPassiveSample(t, passivePacket(longQuery, 53000, 53), "DNS_REQUEST", passiveDigest(key))
}

func TestPassiveDNSAbstainsOnUnsupportedOrIncompleteQuestions(t *testing.T) {
	valid := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1}
	withQuestion := func(question []byte) []byte {
		return append(bytes.Clone(valid[:12]), question...)
	}
	setByte := func(index int, value byte) []byte {
		b := bytes.Clone(valid)
		b[index] = value
		return b
	}
	response := setByte(2, 0x81)
	largeLabels := bytes.Repeat(append([]byte{63}, bytes.Repeat([]byte{'a'}, 63)...), 4)
	largeLabels = append(largeLabels, 0, 0, 1, 0, 1)
	tooManyLabels := append(bytes.Repeat([]byte{1, 'a'}, 128), 0, 0, 1, 0, 1)
	for _, tc := range []struct {
		name     string
		body     []byte
		src, dst uint16
	}{
		{"empty", nil, 53000, 53},
		{"short_header_and_question", valid[:16], 53000, 53},
		{"no_questions", setByte(5, 0), 53000, 53},
		{"multiple_questions", setByte(5, 2), 53000, 53},
		{"question_count_high_byte", setByte(4, 1), 53000, 53},
		{"opcode_bit_1", setByte(2, 0x09), 53000, 53},
		{"opcode_bit_2", setByte(2, 0x11), 53000, 53},
		{"opcode_bit_3", setByte(2, 0x21), 53000, 53},
		{"opcode_bit_4", setByte(2, 0x41), 53000, 53},
		{"truncated_header_flag", setByte(2, 0x03), 53000, 53},
		{"compressed_question", withQuestion([]byte{0xc0, 0x0c, 0, 1, 0, 1}), 53000, 53},
		{"reserved_label_tag", withQuestion([]byte{0x80, 'a', 0, 0, 1, 0, 1}), 53000, 53},
		{"label_exceeds_63", withQuestion(append([]byte{64}, bytes.Repeat([]byte{'a'}, 64)...)), 53000, 53},
		{"label_body_truncated", withQuestion([]byte{6, 'a', 'a', 'a', 'a', 'a'}), 53000, 53},
		{"missing_name_terminator", withQuestion([]byte{5, 'a', 'a', 'a', 'a', 'a'}), 53000, 53},
		{"truncated_type_and_class", valid[:len(valid)-1], 53000, 53},
		{"name_exceeds_bounded_scan", withQuestion(largeLabels), 53000, 53},
		{"label_count_exceeds_bounded_scan", withQuestion(tooManyLabels), 53000, 53},
		{"request_on_response_port_direction", valid, 53, 53000},
		{"response_on_request_port_direction", response, 53000, 53},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkPassiveSample(t, passivePacket(tc.body, tc.src, tc.dst), "UNKNOWN", "")
		})
	}
}

func TestPassiveNTPTransactionUsesExactClientTimestamp(t *testing.T) {
	// A response correlates on originate (24:32), not its own transmit (40:48).
	client := []byte{0, 0, 0, 0, 0, 0, 0, 1}
	server := []byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4}
	message := func(first, stratum byte, origin, transmit []byte) []byte {
		b := make([]byte, 48)
		b[0], b[1] = first, stratum
		copy(b[24:32], origin)
		copy(b[40:48], transmit)
		return b
	}
	for _, tc := range []struct {
		name     string
		body     []byte
		src, dst uint16
		semantic string
		key      []byte
	}{
		{"v4_client", message(0x23, 0, server, client), 53000, 123, "NTP_REQUEST", client},
		{"v3_client", message(0x1b, 0, server, client), 53000, 123, "NTP_REQUEST", client},
		{"v4_response_origin_matches_client", message(0x24, 1, client, server), 123, 53000, "NTP_RESPONSE", client},
		{"v3_response_stratum_upper_bound", message(0x1c, 15, client, server), 123, 53000, "NTP_RESPONSE", client},
		{"response_uses_origin_not_transmit", message(0x24, 2, server, client), 123, 53000, "NTP_RESPONSE", server},
		{"request_zero_transmit_ignores_nonzero_origin", message(0x23, 0, server, nil), 53000, 123, "NTP_REQUEST", nil},
		{"response_zero_origin_ignores_nonzero_transmit", message(0x24, 2, nil, server), 123, 53000, "NTP_RESPONSE", nil},
		{"zero_client_timestamp_preserves_semantic", message(0x23, 0, nil, nil), 53000, 123, "NTP_REQUEST", nil},
		{"zero_server_origin_preserves_semantic", message(0x24, 2, nil, nil), 123, 53000, "NTP_RESPONSE", nil},
		{"timestamp_first_byte_nonzero", message(0x23, 0, nil, []byte{1, 0, 0, 0, 0, 0, 0, 0}), 53000, 123, "NTP_REQUEST", []byte{1, 0, 0, 0, 0, 0, 0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := ""
			if tc.key != nil {
				want = passiveDigest(tc.key)
			}
			checkPassiveSample(t, passivePacket(tc.body, tc.src, tc.dst), tc.semantic, want)
		})
	}
}

func TestPassiveNTPAbstainsOnUnsupportedHeadersAndDirection(t *testing.T) {
	for _, tc := range []struct {
		name           string
		first, stratum byte
		length         int
		src, dst       uint16
	}{
		{"empty", 0, 0, 0, 123, 53000},
		{"truncated_request", 0x23, 0, 47, 53000, 123},
		{"truncated_response", 0x24, 1, 47, 123, 53000},
		{"version_zero", 0x04, 1, 48, 123, 53000},
		{"version_two", 0x14, 1, 48, 123, 53000},
		{"version_five", 0x2c, 1, 48, 123, 53000},
		{"reserved_mode_zero", 0x20, 1, 48, 123, 53000},
		{"symmetric_active", 0x21, 1, 48, 123, 53000},
		{"symmetric_passive", 0x22, 1, 48, 123, 53000},
		{"broadcast", 0x25, 1, 48, 123, 53000},
		{"control", 0x26, 1, 48, 123, 53000},
		{"private", 0x27, 1, 48, 123, 53000},
		{"response_stratum_zero", 0x24, 0, 48, 123, 53000},
		{"response_stratum_sixteen", 0x24, 16, 48, 123, 53000},
		{"request_wrong_direction", 0x23, 0, 48, 123, 53000},
		{"response_wrong_direction", 0x24, 1, 48, 53000, 123},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := bytes.Repeat([]byte{1}, tc.length)
			if len(body) >= 2 {
				body[0], body[1] = tc.first, tc.stratum
			}
			checkPassiveSample(t, passivePacket(body, tc.src, tc.dst), "UNKNOWN", "")
		})
	}
}

func TestPassiveProfileBoundedPrefixAndTransportFlags(t *testing.T) {
	prefix := bytes.Repeat([]byte{'x'}, 64)
	for _, tc := range []struct {
		name     string
		protocol packet.Protocol
		flags    packet.TCPFlags
		length   uint32
		payload  []byte
		preimage []byte
	}{
		{"empty_udp", packet.UDP, packet.TCPFlags{}, 100, nil, []byte("UDP|100|0|")},
		{"short_udp", packet.UDP, packet.TCPFlags{}, 100, []byte("abc"), []byte("UDP|100|0|abc")},
		{"prefix_exactly_64", packet.UDP, packet.TCPFlags{}, 100, prefix, append([]byte("UDP|100|0|"), prefix...)},
		{"byte_65_ignored", packet.UDP, packet.TCPFlags{}, 100, append(bytes.Clone(prefix), 'a'), append([]byte("UDP|100|0|"), prefix...)},
		{"different_suffix_same_profile", packet.UDP, packet.TCPFlags{}, 100, append(bytes.Clone(prefix), bytes.Repeat([]byte{'z'}, 4096)...), append([]byte("UDP|100|0|"), prefix...)},
		{"udp_ignores_tcp_flags", packet.UDP, packet.TCPFlags{SYN: true, ACK: true}, 100, []byte("abc"), []byte("UDP|100|0|abc")},
		{"ip_length_changes_profile", packet.UDP, packet.TCPFlags{}, 101, []byte("abc"), []byte("UDP|101|0|abc")},
		{"tcp_no_flags", packet.TCP, packet.TCPFlags{}, 100, []byte("abc"), []byte("TCP|100|0|abc")},
		{"fin", packet.TCP, packet.TCPFlags{FIN: true}, 100, nil, []byte("TCP|100|1|")},
		{"syn", packet.TCP, packet.TCPFlags{SYN: true}, 100, nil, []byte("TCP|100|2|")},
		{"rst", packet.TCP, packet.TCPFlags{RST: true}, 100, nil, []byte("TCP|100|4|")},
		{"psh", packet.TCP, packet.TCPFlags{PSH: true}, 100, nil, []byte("TCP|100|8|")},
		{"ack", packet.TCP, packet.TCPFlags{ACK: true}, 100, nil, []byte("TCP|100|16|")},
		{"urg", packet.TCP, packet.TCPFlags{URG: true}, 100, nil, []byte("TCP|100|32|")},
		{"ece", packet.TCP, packet.TCPFlags{ECE: true}, 100, nil, []byte("TCP|100|64|")},
		{"cwr", packet.TCP, packet.TCPFlags{CWR: true}, 100, nil, []byte("TCP|100|128|")},
		{"all_flags", packet.TCP, packet.TCPFlags{FIN: true, SYN: true, RST: true, PSH: true, ACK: true, URG: true, ECE: true, CWR: true}, 100, nil, []byte("TCP|100|255|")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := passivePacket(tc.payload, 40000, 53000)
			p.Protocol, p.TCPFlags, p.IPLength = tc.protocol, tc.flags, tc.length
			got := checkPassiveSample(t, p, "OTHER", "")
			if want := passiveDigest(tc.preimage); got.Profile != want {
				t.Errorf("profile = %s, want %s", got.Profile, want)
			}
		})
	}
	// UDP-specific semantics must not parse DNS bytes from a TCP packet.
	p := passivePacket([]byte{1, 2, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1}, 53000, 53)
	p.Protocol = packet.TCP
	checkPassiveSample(t, p, "OTHER", "")
}

func TestPassiveSampleAdmissionAndSubmicrosecondBounds(t *testing.T) {
	for _, tc := range []struct {
		name     string
		protocol packet.Protocol
		complete bool
	}{
		{"incomplete_udp", packet.UDP, false},
		{"incomplete_tcp", packet.TCP, false},
		{"icmp_not_transport_evidence", packet.ICMP, true},
		{"unknown_protocol", packet.UnknownProtocol, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := passivePacket([]byte("abc"), 40000, 53000)
			p.Protocol, p.EvidenceComplete = tc.protocol, tc.complete
			if got := p.DDoSSample(); got != nil {
				t.Fatalf("inadmissible sample retained: %+v", got)
			}
		})
	}
	// Integer-microsecond limits are already covered by ddos_corrections_test.go.
	// Exercise the nanosecond edge and dates whose UnixMicro value can overflow.
	const maxSafeUS int64 = 9007199254740991
	for _, tc := range []struct {
		name  string
		stamp time.Time
		want  int64
		keep  bool
	}{
		{"lower_minus_one_nanosecond", time.UnixMicro(-maxSafeUS).Add(-time.Nanosecond), 0, false},
		{"lower_plus_one_nanosecond", time.UnixMicro(-maxSafeUS).Add(time.Nanosecond), -maxSafeUS, true},
		{"upper_last_nanosecond", time.UnixMicro(maxSafeUS).Add(999 * time.Nanosecond), maxSafeUS, true},
		{"upper_exclusive", time.UnixMicro(maxSafeUS).Add(time.Microsecond), 0, false},
		{"far_future", time.Date(1000000, 1, 1, 0, 0, 0, 0, time.UTC), 0, false},
		{"far_past", time.Date(-1000000, 1, 1, 0, 0, 0, 0, time.UTC), 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := passivePacket(nil, 40000, 53000)
			p.Timestamp = tc.stamp
			got := p.DDoSSample()
			if !tc.keep {
				if got != nil {
					t.Fatalf("out-of-range timestamp retained: %+v", got)
				}
				return
			}
			if got == nil || got.TimestampUS != tc.want {
				t.Fatalf("boundary sample = %+v, want timestamp %d", got, tc.want)
			}
		})
	}
}
