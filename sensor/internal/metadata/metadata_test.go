package metadata

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestParseDNSMetadata(t *testing.T) {
	dns := &layers.DNS{ID: 1, QR: true, ResponseCode: layers.DNSResponseCodeNoErr, Questions: []layers.DNSQuestion{{Name: []byte("example.test"), Type: layers.DNSTypeA, Class: layers.DNSClassIN}}, Answers: []layers.DNSResourceRecord{{Name: []byte("example.test"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 60, IP: []byte{192, 0, 2, 1}}}}
	buf := gopacket.NewSerializeBuffer()
	if err := dns.SerializeTo(buf, gopacket.SerializeOptions{FixLengths: true}); err != nil {
		t.Fatal(err)
	}
	m, err := Parse(53, buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if m.Kind != KindDNS || m.DNS.QueryName != "example.test" || m.DNS.AnswerIP != "192.0.2.1" || m.DNS.TTL != 60 {
		t.Fatalf("bad DNS: %+v", m)
	}
}

func TestParseHTTPSafelyWithoutBody(t *testing.T) {
	payload := []byte("POST /submit?q=1 HTTP/1.1\r\nHost: example.test\r\nUser-Agent: agent\r\nContent-Length: 6\r\n\r\nsecret")
	m, err := Parse(80, payload)
	if err != nil {
		t.Fatal(err)
	}
	if m.HTTP.Method != "POST" || m.HTTP.Host != "example.test" || m.HTTP.Path != "/submit" || m.HTTP.ContentLength != 6 {
		t.Fatalf("bad HTTP: %+v", m.HTTP)
	}
	if m.RawPayload != nil {
		t.Fatal("HTTP body retained")
	}
	if _, err := Parse(80, []byte("not http")); err == nil {
		t.Fatal("malformed HTTP accepted")
	}
}

func TestParseTLSClientHelloSNIAndALPN(t *testing.T) {
	hello := clientHello("c2.example", "h2")
	m, err := Parse(443, hello)
	if err != nil {
		t.Fatal(err)
	}
	if m.Kind != KindTLS || m.TLS.SNI != "c2.example" || len(m.TLS.ALPN) != 1 || m.TLS.ALPN[0] != "h2" || m.TLS.Version != "TLS1.2" || len(m.TLS.CipherSuites) != 1 {
		t.Fatalf("bad TLS: %+v", m.TLS)
	}
	if _, err := Parse(443, hello[:8]); err == nil {
		t.Fatal("truncated TLS accepted")
	}
}

func TestParseTLSServerHelloFingerprint(t *testing.T) {
	body := []byte{3, 3}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0, 0x13, 0x01, 0, 0, 0)
	hs := append([]byte{2, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	record := append([]byte{22, 3, 3, byte(len(hs) >> 8), byte(len(hs))}, hs...)
	m, err := Parse(443, record)
	if err != nil {
		t.Fatal(err)
	}
	if m.TLS.Version != "TLS1.2" || len(m.TLS.CipherSuites) != 1 || m.TLS.CipherSuites[0] != 0x1301 || len(m.TLS.ServerHelloFingerprint) != 64 {
		t.Fatalf("bad server hello: %+v", m.TLS)
	}
}

func TestParseTLSCertificateMetadata(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sensor.test"}, Issuer: pkix.Name{CommonName: "test-ca"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(1000, 0)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listLen := len(der) + 3
	body := []byte{byte(listLen >> 16), byte(listLen >> 8), byte(listLen), byte(len(der) >> 16), byte(len(der) >> 8), byte(len(der))}
	body = append(body, der...)
	hs := append([]byte{11, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	record := []byte{22, 3, 3, byte(len(hs) >> 8), byte(len(hs))}
	record = append(record, hs...)
	m, err := Parse(443, record)
	if err != nil {
		t.Fatal(err)
	}
	if m.TLS.CertificateSubject != "CN=sensor.test" || m.TLS.CertificateIssuer != "CN=sensor.test" || len(m.TLS.CertificateSHA256) != 64 {
		t.Fatalf("bad certificate metadata: %+v", m.TLS)
	}
}

func TestUnknownMetadataUsesFeaturesNotPayload(t *testing.T) {
	m, err := Parse(9999, []byte{0, 1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if m.Kind != KindUnknown || m.Unknown.PayloadLength != 4 || len(m.Unknown.FirstBytesHash) != 64 || m.RawPayload != nil || m.Unknown.Entropy <= 0 {
		t.Fatalf("bad unknown: %+v", m)
	}
}

func clientHello(host, alpn string) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, 0, 2, 0x13, 0x01)
	body = append(body, 1, 0)
	sniData := append([]byte{0, byte(len(host) + 3), 0, 0, byte(len(host))}, []byte(host)...)
	alpnData := append([]byte{0, byte(len(alpn) + 1), byte(len(alpn))}, []byte(alpn)...)
	ext := append([]byte{0, 0, byte(len(sniData) >> 8), byte(len(sniData))}, sniData...)
	ext = append(ext, 0, 16, byte(len(alpnData)>>8), byte(len(alpnData)))
	ext = append(ext, alpnData...)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	record := []byte{22, 3, 1, 0, 0}
	binary.BigEndian.PutUint16(record[3:], uint16(len(hs)))
	return append(record, hs...)
}
