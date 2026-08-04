package main

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"c2hunter/sensor/config"
	interfacespkg "c2hunter/sensor/internal/interfaces"
	"c2hunter/sensor/internal/packet"
	"c2hunter/sensor/internal/transport"
)

func TestVersionAndDiagnosticCLI(t *testing.T) {
	oldVersion, oldCommit := version, commit
	version, commit = "1.2.3", "abc123"
	defer func() { version, commit = oldVersion, oldCommit }()
	var output strings.Builder
	if err := execute(context.Background(), []string{"--version"}, &output); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); !strings.Contains(got, "1.2.3") || !strings.Contains(got, "abc123") {
		t.Fatalf("version output = %q", got)
	}
	output.Reset()
	if err := execute(context.Background(), []string{"interfaces"}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "\"name\"") {
		t.Fatalf("interfaces output = %q", output.String())
	}
}

func TestBuildRegistrationIncludesConfiguredInterfaceMetadata(t *testing.T) {
	cfg := config.Config{}
	cfg.Sensor.ID = "sensor-a"
	cfg.Sensor.Name = "Sensor A"
	cfg.CaptureSources = []config.CaptureSource{{Interface: "eth-test", Direction: "INBOUND"}}
	lookup := func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name, HardwareAddr: net.HardwareAddr{0, 1, 2, 3, 4, 5}}, nil
	}

	registration, err := buildRegistration(cfg, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if len(registration.Interfaces) != 1 || registration.Interfaces[0].MAC != "00:01:02:03:04:05" {
		t.Fatalf("interfaces = %+v", registration.Interfaces)
	}
	if err := registration.Validate(); err != nil {
		t.Fatalf("registration is invalid: %v", err)
	}
}

func TestBuildRegistrationAllowsInterfaceWithoutMACAddress(t *testing.T) {
	cfg := config.Config{}
	cfg.Sensor.ID = "sensor-loopback"
	cfg.Sensor.Name = "Loopback Sensor"
	cfg.CaptureSources = []config.CaptureSource{{Interface: "lo", Direction: "OUTBOUND"}}

	registration, err := buildRegistration(cfg, func(name string) (*net.Interface, error) {
		return &net.Interface{Name: name}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(registration.Interfaces) != 1 || registration.Interfaces[0].MAC != "" {
		t.Fatalf("interfaces = %+v", registration.Interfaces)
	}
}

func TestDiscoverHeartbeatInterfacesIncludesUnconfiguredSystemInterfaces(t *testing.T) {
	got, err := discoverHeartbeatInterfaces(func() ([]interfacespkg.Info, error) {
		return []interfacespkg.Info{
			{Name: "eth0", MAC: "00:01:02:03:04:05"},
			{Name: "eth1", MAC: "00:01:02:03:04:06"},
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[1].Name != "eth1" || got[1].MAC != "00:01:02:03:04:06" {
		t.Fatalf("discovered interfaces = %+v", got)
	}
}

func TestBuildFilterAppliesCompiledBooleanBPF(t *testing.T) {
	expression := "((tcp or udp)) and (not dst port 22)"
	matcher, err := packet.CompileBPFMatcher(expression)
	if err != nil {
		t.Fatal(err)
	}
	filter, err := buildFilter(config.Config{}, expression, matcher)
	if err != nil {
		t.Fatal(err)
	}
	if !filter.Match(packet.Packet{Protocol: packet.TCP, DestinationPort: 443}) {
		t.Fatal("matching TCP packet rejected")
	}
	if !filter.Match(packet.Packet{Protocol: packet.UDP, DestinationPort: 53}) {
		t.Fatal("matching UDP packet rejected")
	}
	if filter.Match(packet.Packet{Protocol: packet.TCP, DestinationPort: 22}) {
		t.Fatal("source BPF exclusion was not applied")
	}
	if filter.Match(packet.Packet{Protocol: packet.ICMP}) {
		t.Fatal("global BPF exclusion was not applied")
	}
}

func TestCombineBPFExpressionsPreservesEachFilterScope(t *testing.T) {
	expression := combineBPFExpressions("tcp or udp", "dst port 53")
	matcher, err := packet.CompileBPFMatcher(expression)
	if err != nil {
		t.Fatal(err)
	}
	if matcher("eth0", packet.Packet{Protocol: packet.TCP, DestinationPort: 80}) {
		t.Fatal("source OR expression escaped the global destination-port filter")
	}
	if !matcher("eth0", packet.Packet{Protocol: packet.UDP, DestinationPort: 53}) {
		t.Fatal("packet matching both grouped expressions was rejected")
	}
}

func TestApplyDesiredUsesAnalysisCaptureJobsInsteadOfPerInterfacePCAPSelection(t *testing.T) {
	cfg := config.Config{}
	applyDesired(&cfg, transport.DesiredConfig{
		CaptureSources: []transport.DesiredCaptureSource{{Interface: "eth0", Direction: "OUTBOUND", Enabled: true, StorePCAP: true}},
		CaptureJobs:    []transport.DesiredCaptureJob{{JobID: "job-a", StorePCAP: true}},
	})
	if len(cfg.CaptureSources) != 1 || cfg.CaptureSources[0].StorePCAP {
		t.Fatalf("per-interface PCAP remained enabled: %+v", cfg.CaptureSources)
	}
	if len(cfg.CaptureJobs) != 1 || cfg.CaptureJobs[0].JobID != "job-a" || !cfg.CaptureJobs[0].StorePCAP {
		t.Fatalf("capture jobs = %+v", cfg.CaptureJobs)
	}
}

func TestPCAPFilePrefixRemovesPathSeparators(t *testing.T) {
	if got := pcapFilePrefix("../../eth0", "INGRESS"); got != ".._.._eth0-ingress" {
		t.Fatalf("prefix = %q", got)
	}
}

type captureWindowSinkStub struct{ count int }

func (s *captureWindowSinkStub) Enqueue(packet.Packet) bool { s.count++; return true }

func TestAnalysisPCAPSinkOnlyCapturesWithinJobWindow(t *testing.T) {
	start := time.Unix(100, 0).UTC()
	sink := &captureWindowSinkStub{}
	window := captureWindowPCAPSink{sink: sink, start: start, end: start.Add(time.Minute)}
	for _, timestamp := range []time.Time{start.Add(-time.Second), start, start.Add(time.Minute), start.Add(time.Minute + time.Second)} {
		window.Enqueue(packet.Packet{Timestamp: timestamp})
	}
	if sink.count != 2 {
		t.Fatalf("captured packets = %d", sink.count)
	}
}

func TestAnalysisJobPollingIsBoundedToOneSecond(t *testing.T) {
	if got := jobAwarePollInterval(30 * time.Second); got != time.Second {
		t.Fatalf("poll interval = %s", got)
	}
	if got := jobAwarePollInterval(500 * time.Millisecond); got != 500*time.Millisecond {
		t.Fatalf("short poll interval = %s", got)
	}
}

func TestActiveCaptureJobsDropsExpiredAndInvalidJobs(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	jobs := []config.CaptureJob{
		{JobID: ""},
		{JobID: "expired", EndTime: now},
		{JobID: "active", StartTime: now, EndTime: now.Add(time.Minute)},
		{JobID: "unbounded", StartTime: now},
	}

	active := activeCaptureJobs(jobs, now)
	if len(active) != 2 || active[0].JobID != "active" || active[1].JobID != "unbounded" {
		t.Fatalf("active jobs = %+v", active)
	}
}

func TestCaptureJobWindowAndIDsCoverOverlappingAnalyses(t *testing.T) {
	start := time.Unix(200, 0).UTC()
	jobs := []config.CaptureJob{
		{JobID: "job-b", StartTime: start.Add(30 * time.Second), EndTime: start.Add(2 * time.Minute)},
		{JobID: "job-a", StartTime: start, EndTime: start.Add(time.Minute)},
		{JobID: "job-a", StartTime: start, EndTime: start.Add(time.Minute)},
	}

	gotStart, gotEnd := captureJobWindow(jobs)
	if !gotStart.Equal(start) || !gotEnd.Equal(start.Add(2*time.Minute)) {
		t.Fatalf("capture window = %s .. %s", gotStart, gotEnd)
	}
	ids := captureJobIDs(jobs)
	if len(ids) != 2 || ids[0] != "job-b" || ids[1] != "job-a" {
		t.Fatalf("capture job IDs = %+v", ids)
	}
}

func TestIdleCaptureRuntimeWaitsForCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (idleCaptureRuntime{}).Run(ctx) }()

	select {
	case <-done:
		t.Fatal("idle runtime stopped before cancellation")
	case <-time.After(10 * time.Millisecond):
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestServiceSandboxAllowsNetlinkInterfaceDiscovery(t *testing.T) {
	data, err := os.ReadFile("../../../deploy/sensor/c2hunter-sensor.service")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "RestrictAddressFamilies=") {
			continue
		}
		for _, family := range strings.Fields(strings.TrimPrefix(line, "RestrictAddressFamilies=")) {
			if family == "AF_NETLINK" {
				return
			}
		}
		t.Fatalf("AF_NETLINK missing from %q", line)
	}
	t.Fatal("RestrictAddressFamilies is not configured")
}

func TestInstallersCreateWritablePCAPDirectory(t *testing.T) {
	installer, err := os.ReadFile("../../../scripts/install-sensor.sh")
	if err != nil {
		t.Fatal(err)
	}
	contents := string(installer)
	if !strings.Contains(contents, "-o c2hunter-sensor -g c2hunter-sensor") || !strings.Contains(contents, "/var/lib/c2hunter-sensor/pcap") {
		t.Fatal("canonical installer does not create a sensor-owned PCAP directory")
	}
	buildScript, err := os.ReadFile("../../../scripts/build-sensor-tarball.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(buildScript), `cp "$ROOT/scripts/install-sensor.sh"`) {
		t.Fatal("sensor artifact does not package the canonical installer")
	}
}
