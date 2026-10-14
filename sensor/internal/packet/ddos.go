package packet

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// DDoSSample is passive, bounded evidence, not transport/source authentication.
type DDoSSample struct {
	TimestampUS int64   `json:"timestamp_us"`
	Profile     string  `json:"profile"`
	Semantic    string  `json:"semantic"`
	Transaction *string `json:"transaction"`
}

type DDoSEvidence struct {
	Version        int          `json:"version"`
	Samples        []DDoSSample `json:"samples"`
	OmittedSamples uint64       `json:"omitted_samples"`
}

func digest(data []byte) string { value := sha256.Sum256(data); return hex.EncodeToString(value[:]) }

// DNS standard-query header and uncompressed question only. Other forms abstain.
func responseSemantics(payload []byte, src, dst uint16) (string, *string) {
	if src == 53 || dst == 53 {
		if len(payload) < 17 || payload[2]&0x7a != 0 || payload[4] != 0 || payload[5] != 1 {
			return "UNKNOWN", nil
		}
		offset := 12
		ended := false
		for i := 0; i < 128; i++ {
			if offset >= len(payload) || offset >= 268 {
				return "UNKNOWN", nil
			}
			size := int(payload[offset])
			offset++
			if size == 0 {
				ended = true
				break
			}
			if size > 63 {
				return "UNKNOWN", nil
			}
			offset += size
		}
		if !ended || offset+4 > len(payload) {
			return "UNKNOWN", nil
		}
		response := payload[2]&0x80 != 0
		if (response && src != 53) || (!response && dst != 53) {
			return "UNKNOWN", nil
		}
		data := append([]byte{}, payload[:2]...)
		data = append(data, payload[12:offset+4]...)
		token := digest(data)
		if response {
			return "DNS_RESPONSE", &token
		}
		return "DNS_REQUEST", &token
	}
	if src == 123 || dst == 123 {
		if len(payload) < 48 || ((payload[0]>>3)&7 != 3 && (payload[0]>>3)&7 != 4) {
			return "UNKNOWN", nil
		}
		var semantic string
		var raw []byte
		if payload[0]&7 == 4 && src == 123 && payload[1] >= 1 && payload[1] <= 15 {
			semantic = "NTP_RESPONSE"
			raw = payload[24:32]
		} else if payload[0]&7 == 3 && dst == 123 {
			semantic = "NTP_REQUEST"
			raw = payload[40:48]
		} else {
			return "UNKNOWN", nil
		}
		for _, b := range raw {
			if b != 0 {
				token := digest(raw)
				return semantic, &token
			}
		}
		return semantic, nil
	}
	// Unsupported reflection-service replies are neither parsed responses nor
	// affirmative direct-client evidence. Keep samples, but abstain.
	switch src {
	case 17, 19, 389, 1900, 11211:
		return "UNKNOWN", nil
	}
	return "OTHER", nil
}

func (p Packet) DDoSSample() *DDoSSample {
	if !p.EvidenceComplete || (p.Protocol != TCP && p.Protocol != UDP) {
		return nil
	}
	// Compare times before UnixMicro: extremely distant dates must not wrap
	// into a falsely plausible safe integer. Negative epochs are supported.
	const maxSafeUS int64 = 9007199254740991
	if p.Timestamp.Before(time.UnixMicro(-maxSafeUS)) || !p.Timestamp.Before(time.UnixMicro(maxSafeUS+1)) {
		return nil
	}
	protocol := "UDP"
	flags := 0
	if p.Protocol == TCP {
		protocol = "TCP"
		for i, set := range []bool{p.TCPFlags.FIN, p.TCPFlags.SYN, p.TCPFlags.RST, p.TCPFlags.PSH, p.TCPFlags.ACK, p.TCPFlags.URG, p.TCPFlags.ECE, p.TCPFlags.CWR} {
			if set {
				flags |= 1 << i
			}
		}
	}
	prefix := p.Payload
	if len(prefix) > 64 {
		prefix = prefix[:64]
	}
	data := append([]byte(fmt.Sprintf("%s|%d|%d|", protocol, p.IPLength, flags)), prefix...)
	semantic := "OTHER"
	var token *string
	if p.Protocol == UDP {
		semantic, token = responseSemantics(p.Payload, p.SourcePort, p.DestinationPort)
	}
	return &DDoSSample{TimestampUS: p.Timestamp.UnixMicro(), Profile: digest(data), Semantic: semantic, Transaction: token}
}
