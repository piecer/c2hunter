package metadata

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Kind string

const (
	KindDNS     Kind = "DNS"
	KindHTTP    Kind = "HTTP"
	KindTLS     Kind = "TLS"
	KindUnknown Kind = "UNKNOWN"
)

type DNS struct {
	QueryName    string
	QueryType    uint16
	ResponseCode uint8
	AnswerIP     string
	TTL          uint32
	TXTLength    int
	TXTHash      string
}
type HTTP struct {
	Method, Host, Path, UserAgent string
	StatusCode                    int
	ContentLength                 int64
}
type TLS struct {
	SNI                                                      string
	ALPN                                                     []string
	Version                                                  string
	CipherSuites                                             []uint16
	ClientHelloFingerprint                                   string
	ServerHelloFingerprint                                   string
	CertificateSubject, CertificateIssuer, CertificateSHA256 string
}
type Unknown struct {
	FirstBytesHash       string
	PayloadLength        int
	Entropy              float64
	PacketSizeSequence   []int
	RequestResponseRatio float64
}
type Metadata struct {
	Kind       Kind
	DNS        *DNS
	HTTP       *HTTP
	TLS        *TLS
	Unknown    *Unknown
	RawPayload []byte
}

func Parse(port uint16, payload []byte) (Metadata, error) {
	switch port {
	case 53:
		return parseDNS(payload)
	case 80, 8080, 8000:
		return parseHTTP(payload)
	case 443, 8443:
		return parseTLS(payload)
	default:
		return parseUnknown(payload), nil
	}
}
func parseDNS(payload []byte) (Metadata, error) {
	var decoded layers.DNS
	if err := decoded.DecodeFromBytes(payload, gopacket.NilDecodeFeedback); err != nil {
		return Metadata{}, fmt.Errorf("DNS: %w", err)
	}
	d := &DNS{ResponseCode: uint8(decoded.ResponseCode)}
	if len(decoded.Questions) > 0 {
		d.QueryName = string(decoded.Questions[0].Name)
		d.QueryType = uint16(decoded.Questions[0].Type)
	}
	for _, a := range decoded.Answers {
		if a.IP != nil && d.AnswerIP == "" {
			d.AnswerIP = a.IP.String()
			d.TTL = a.TTL
		}
		if a.Type == layers.DNSTypeTXT {
			d.TXTLength += len(a.TXT)
			h := sha256.Sum256(a.TXT)
			d.TXTHash = hex.EncodeToString(h[:])
		}
	}
	return Metadata{Kind: KindDNS, DNS: d}, nil
}
func parseHTTP(payload []byte) (Metadata, error) {
	reader := bufio.NewReader(ioLimit(payload))
	h := &HTTP{}
	if bytes.HasPrefix(payload, []byte("HTTP/")) {
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			return Metadata{}, fmt.Errorf("HTTP response: %w", err)
		}
		h.StatusCode = resp.StatusCode
		h.ContentLength = resp.ContentLength
		_ = resp.Body.Close()
	} else {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return Metadata{}, fmt.Errorf("HTTP request: %w", err)
		}
		h.Method = req.Method
		h.Host = req.Host
		h.Path = req.URL.Path
		h.UserAgent = req.UserAgent()
		h.ContentLength = req.ContentLength
		_ = req.Body.Close()
	}
	return Metadata{Kind: KindHTTP, HTTP: h}, nil
}
func ioLimit(payload []byte) *bytes.Reader {
	if len(payload) > 64<<10 {
		payload = payload[:64<<10]
	}
	return bytes.NewReader(payload)
}
func parseTLS(p []byte) (Metadata, error) {
	if len(p) < 9 || p[0] != 22 {
		return Metadata{}, fmt.Errorf("TLS: invalid record")
	}
	recordLen := int(binary.BigEndian.Uint16(p[3:5]))
	if recordLen > len(p)-5 {
		return Metadata{}, fmt.Errorf("TLS: truncated handshake")
	}
	if p[5] == 11 {
		return parseTLSCertificate(p[9 : 5+recordLen])
	}
	if p[5] == 2 {
		return parseTLSServerHello(p, recordLen)
	}
	if p[5] != 1 {
		return Metadata{}, fmt.Errorf("TLS: unsupported handshake")
	}
	helloLen := int(p[6])<<16 | int(p[7])<<8 | int(p[8])
	if helloLen > recordLen-4 || len(p) < 9+helloLen {
		return Metadata{}, fmt.Errorf("TLS: truncated client hello")
	}
	b := p[9 : 9+helloLen]
	if len(b) < 35 {
		return Metadata{}, fmt.Errorf("TLS: short client hello")
	}
	t := &TLS{Version: tlsVersion(binary.BigEndian.Uint16(b[:2]))}
	pos := 34
	sessionLen := int(b[pos])
	pos++
	if !advance(&pos, sessionLen, len(b)) {
		return Metadata{}, fmt.Errorf("TLS: bad session")
	}
	if pos+2 > len(b) {
		return Metadata{}, fmt.Errorf("TLS: missing ciphers")
	}
	cipherLen := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	pos += 2
	if cipherLen%2 != 0 || !advance(&pos, cipherLen, len(b)) {
		return Metadata{}, fmt.Errorf("TLS: bad ciphers")
	}
	for i := pos - cipherLen; i < pos; i += 2 {
		t.CipherSuites = append(t.CipherSuites, binary.BigEndian.Uint16(b[i:i+2]))
	}
	if pos >= len(b) {
		return Metadata{}, fmt.Errorf("TLS: missing compression")
	}
	compressionLen := int(b[pos])
	pos++
	if !advance(&pos, compressionLen, len(b)) {
		return Metadata{}, fmt.Errorf("TLS: bad compression")
	}
	if pos+2 > len(b) {
		return Metadata{}, fmt.Errorf("TLS: missing extensions")
	}
	extLen := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	pos += 2
	if !advance(&pos, extLen, len(b)) {
		return Metadata{}, fmt.Errorf("TLS: bad extensions")
	}
	end := pos
	pos -= extLen
	for pos+4 <= end {
		typ := binary.BigEndian.Uint16(b[pos : pos+2])
		n := int(binary.BigEndian.Uint16(b[pos+2 : pos+4]))
		pos += 4
		if pos+n > end {
			return Metadata{}, fmt.Errorf("TLS: bad extension")
		}
		data := b[pos : pos+n]
		if typ == 0 {
			t.SNI = parseSNI(data)
		} else if typ == 16 {
			t.ALPN = parseALPN(data)
		}
		pos += n
	}
	hash := sha256.Sum256(p[:5+recordLen])
	t.ClientHelloFingerprint = hex.EncodeToString(hash[:])
	return Metadata{Kind: KindTLS, TLS: t}, nil
}

func parseTLSServerHello(p []byte, recordLen int) (Metadata, error) {
	helloLen := int(p[6])<<16 | int(p[7])<<8 | int(p[8])
	if helloLen > recordLen-4 || len(p) < 9+helloLen {
		return Metadata{}, fmt.Errorf("TLS: truncated server hello")
	}
	body := p[9 : 9+helloLen]
	if len(body) < 38 {
		return Metadata{}, fmt.Errorf("TLS: short server hello")
	}

	metadata := &TLS{Version: tlsVersion(binary.BigEndian.Uint16(body[:2]))}
	position := 34
	sessionLength := int(body[position])
	position++
	if !advance(&position, sessionLength, len(body)) || position+3 > len(body) {
		return Metadata{}, fmt.Errorf("TLS: malformed server hello")
	}
	metadata.CipherSuites = []uint16{binary.BigEndian.Uint16(body[position : position+2])}
	position += 3 // selected cipher suite and compression method

	if position < len(body) {
		if position+2 > len(body) {
			return Metadata{}, fmt.Errorf("TLS: malformed server extensions")
		}
		extensionLength := int(binary.BigEndian.Uint16(body[position : position+2]))
		position += 2
		if position+extensionLength != len(body) {
			return Metadata{}, fmt.Errorf("TLS: malformed server extensions")
		}
	}

	fingerprint := sha256.Sum256(p[:5+recordLen])
	metadata.ServerHelloFingerprint = hex.EncodeToString(fingerprint[:])
	return Metadata{Kind: KindTLS, TLS: metadata}, nil
}

func parseTLSCertificate(body []byte) (Metadata, error) {
	if len(body) < 6 {
		return Metadata{}, fmt.Errorf("TLS: short certificate message")
	}
	listLength := int(body[0])<<16 | int(body[1])<<8 | int(body[2])
	certificateLength := int(body[3])<<16 | int(body[4])<<8 | int(body[5])
	if listLength > len(body)-3 || certificateLength > len(body)-6 {
		return Metadata{}, fmt.Errorf("TLS: truncated certificate")
	}
	der := body[6 : 6+certificateLength]
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return Metadata{}, fmt.Errorf("TLS certificate: %w", err)
	}
	hash := sha256.Sum256(der)
	return Metadata{Kind: KindTLS, TLS: &TLS{CertificateSubject: certificate.Subject.String(), CertificateIssuer: certificate.Issuer.String(), CertificateSHA256: hex.EncodeToString(hash[:])}}, nil
}
func advance(pos *int, n, limit int) bool {
	if n < 0 || *pos > limit-n {
		return false
	}
	*pos += n
	return true
}
func parseSNI(b []byte) string {
	if len(b) < 5 {
		return ""
	}
	n := int(binary.BigEndian.Uint16(b[3:5]))
	if 5+n > len(b) {
		return ""
	}
	return string(b[5 : 5+n])
}
func parseALPN(b []byte) []string {
	if len(b) < 2 {
		return nil
	}
	end := 2 + int(binary.BigEndian.Uint16(b[:2]))
	if end > len(b) {
		return nil
	}
	var out []string
	for pos := 2; pos < end; {
		n := int(b[pos])
		pos++
		if pos+n > end {
			return nil
		}
		out = append(out, string(b[pos:pos+n]))
		pos += n
	}
	return out
}
func tlsVersion(v uint16) string {
	switch v {
	case 0x0301:
		return "TLS1.0"
	case 0x0302:
		return "TLS1.1"
	case 0x0303:
		return "TLS1.2"
	case 0x0304:
		return "TLS1.3"
	default:
		return "0x" + strconv.FormatUint(uint64(v), 16)
	}
}
func parseUnknown(payload []byte) Metadata {
	n := len(payload)
	first := payload
	if len(first) > 64 {
		first = first[:64]
	}
	h := sha256.Sum256(first)
	counts := [256]int{}
	for _, b := range payload {
		counts[b]++
	}
	entropy := 0.0
	if n > 0 {
		for _, c := range counts {
			if c > 0 {
				p := float64(c) / float64(n)
				entropy -= p * math.Log2(p)
			}
		}
	}
	return Metadata{Kind: KindUnknown, Unknown: &Unknown{FirstBytesHash: hex.EncodeToString(h[:]), PayloadLength: n, Entropy: entropy, PacketSizeSequence: []int{n}}}
}
