package main

import (
	"context"
	"net"
	"strings"
	"testing"

	"c2hunter/sensor/config"
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
