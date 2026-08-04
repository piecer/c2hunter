package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"strings"
	"syscall"
	"time"

	"c2hunter/sensor/config"
	"c2hunter/sensor/internal/agent"
	"c2hunter/sensor/internal/capture"
	"c2hunter/sensor/internal/direction"
	interfacespkg "c2hunter/sensor/internal/interfaces"
	"c2hunter/sensor/internal/packet"
	pcapstore "c2hunter/sensor/internal/pcap"
	sensorruntime "c2hunter/sensor/internal/runtime"
	"c2hunter/sensor/internal/spool"
	"c2hunter/sensor/internal/telemetry"
	"c2hunter/sensor/internal/transport"
)

var version = "dev"
var commit = "unknown"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := execute(ctx, os.Args[1:], os.Stdout); err != nil {
		log.Printf("sensor stopped with error: %v", err)
		os.Exit(1)
	}
}

func execute(ctx context.Context, args []string, out io.Writer) error {
	if len(args) > 0 {
		switch args[0] {
		case "--version", "version":
			_, err := fmt.Fprintf(out, "c2hunter-sensor %s (commit %s)\n", version, commit)
			return err
		case "interfaces":
			items, err := interfacespkg.Discover()
			if err != nil {
				return err
			}
			encoder := json.NewEncoder(out)
			encoder.SetIndent("", "  ")
			return encoder.Encode(items)
		case "validate-config":
			path := ""
			if len(args) > 1 {
				path = args[1]
			}
			cfg, err := loadConfig(path)
			if err != nil {
				return err
			}
			if _, err := validateCaptureSources(cfg.CaptureSources); err != nil && cfg.Agent.EnrollmentToken == "" {
				return err
			}
			_, err = fmt.Fprintln(out, "configuration valid")
			return err
		default:
			return fmt.Errorf("unknown command %q", args[0])
		}
	}
	return run(ctx)
}

func run(ctx context.Context) error {
	cfg, err := loadConfig("")
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	if cfg.Controller.URL == "" {
		return errors.New("controller.url is required (C2HUNTER_CONTROLLER_URL)")
	}

	httpTransport, err := transport.NewHTTP(cfg.Controller.URL, &http.Client{Timeout: 10 * time.Second})
	if err != nil {
		return err
	}
	state, err := agent.Load(cfg.Agent.StateFile)
	if err != nil {
		return err
	}
	desired := transport.DesiredConfig{}
	if state.AgentToken == "" && cfg.Agent.EnrollmentToken != "" {
		desired, err = claim(ctx, httpTransport, cfg.Agent.EnrollmentToken)
		if err != nil {
			return fmt.Errorf("claim enrollment: %w", err)
		}
		state = agent.State{SensorID: desired.SensorID, AgentToken: desired.AgentToken, ConfigVersion: desired.ConfigVersion}
		if err := agent.Save(cfg.Agent.StateFile, state); err != nil {
			return fmt.Errorf("persist agent credentials: %w", err)
		}
	} else if state.AgentToken != "" {
		httpTransport.SetIdentity(state.SensorID, state.AgentToken)
		desired, err = httpTransport.AgentConfig(ctx, state.SensorID)
		if err != nil {
			return fmt.Errorf("fetch desired config: %w", err)
		}
	}
	if state.AgentToken != "" {
		httpTransport.SetIdentity(state.SensorID, state.AgentToken)
		cfg.Sensor.ID = state.SensorID
		applyDesired(&cfg, desired)
		if desired.ConfigVersion > state.ConfigVersion {
			state.ConfigVersion = desired.ConfigVersion
			if err := agent.Save(cfg.Agent.StateFile, state); err != nil {
				return err
			}
		}
	}
	if cfg.Sensor.ID == "" {
		return errors.New("sensor ID unavailable: configure sensor.id or enrollment token")
	}
	if cfg.Sensor.Name == "" {
		cfg.Sensor.Name, _ = os.Hostname()
	}

	registration, err := buildRegistration(cfg, net.InterfaceByName)
	if err != nil {
		return err
	}
	supervisor := sensorruntime.NewSupervisor()
	if err := applyPipelines(supervisor, cfg, httpTransport, state.ConfigVersion); err != nil {
		return err
	}

	runner, err := sensorruntime.New(sensorruntime.Config{
		Registration: registration, HeartbeatInterval: cfg.HeartbeatInterval,
		RetryInterval: retryInterval(), Capture: supervisor,
		DiscoverInterfaces: func() ([]telemetry.Interface, error) {
			return discoverHeartbeatInterfaces(interfacespkg.Discover)
		},
	}, httpTransport)
	if err != nil {
		return err
	}

	runtimeCtx, cancelRuntime := context.WithCancel(ctx)
	defer cancelRuntime()
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	if state.AgentToken != "" {
		go controlLoop(runtimeCtx, hup, supervisor, httpTransport, cfg, state)
	} else {
		go localReloadLoop(runtimeCtx, hup, supervisor, httpTransport, cfg)
	}

	healthAddress := os.Getenv("C2HUNTER_HEALTH_ADDRESS")
	if healthAddress == "" {
		healthAddress = ":8081"
	}
	server := &http.Server{Addr: healthAddress, Handler: runner.HealthHandler(), ReadHeaderTimeout: 2 * time.Second}
	serverErrors := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()
	runErrors := make(chan error, 1)
	go func() { runErrors <- runner.Run(runtimeCtx) }()
	var result error
	select {
	case <-ctx.Done():
	case err := <-serverErrors:
		result = fmt.Errorf("health server: %w", err)
	case err := <-runErrors:
		result = err
	}
	cancelRuntime()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil && result == nil {
		result = fmt.Errorf("shutdown health server: %w", err)
	}
	return result
}

func claim(ctx context.Context, client *transport.HTTP, token string) (transport.DesiredConfig, error) {
	items, err := interfacespkg.Discover()
	if err != nil {
		return transport.DesiredConfig{}, err
	}
	hostname, err := os.Hostname()
	if err != nil {
		return transport.DesiredConfig{}, err
	}
	request := transport.EnrollmentRequest{
		Hostname: hostname, AgentVersion: version,
		OSVersion: goruntime.GOOS, KernelVersion: kernelVersion(),
		Capabilities: []string{"flow-capture", "multi-interface", "pcap-storage", "pcap-upload"},
	}
	for _, item := range items {
		request.DiscoveredInterfaces = append(request.DiscoveredInterfaces, transport.DiscoveredInterface{Name: item.Name, MACAddress: item.MAC})
	}
	return client.Claim(ctx, token, request)
}

func discoverHeartbeatInterfaces(
	discover func() ([]interfacespkg.Info, error),
) ([]telemetry.Interface, error) {
	items, err := discover()
	if err != nil {
		return nil, err
	}
	result := make([]telemetry.Interface, 0, len(items))
	for _, item := range items {
		result = append(result, telemetry.Interface{Name: item.Name, MAC: item.MAC})
	}
	return result, nil
}

func controlLoop(ctx context.Context, hup <-chan os.Signal, supervisor *sensorruntime.Supervisor, client *transport.HTTP, cfg config.Config, state agent.State) {
	interval := jobAwarePollInterval(cfg.Agent.ConfigPollInterval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		force := false
		select {
		case <-ctx.Done():
			return
		case <-hup:
			force = true
		case <-ticker.C:
		}
		desired, err := client.AgentConfig(ctx, state.SensorID)
		if err != nil {
			log.Printf("desired config poll failed: %v", err)
			continue
		}
		if !force && desired.ConfigVersion <= state.ConfigVersion && captureJobsEqual(cfg.CaptureJobs, desired.CaptureJobs) {
			continue
		}
		next := cfg
		applyDesired(&next, desired)
		if err := applyPipelines(supervisor, next, client, desired.ConfigVersion); err != nil {
			log.Printf("desired config version %d rejected; keeping version %d: %v", desired.ConfigVersion, state.ConfigVersion, err)
			continue
		}
		nextInterval := jobAwarePollInterval(next.Agent.ConfigPollInterval)
		if nextInterval != interval {
			interval = nextInterval
			ticker.Reset(interval)
		}
		cfg = next
		state.ConfigVersion = desired.ConfigVersion
		if err := agent.Save(cfg.Agent.StateFile, state); err != nil {
			log.Printf("persist config version: %v", err)
		}
	}
}

func jobAwarePollInterval(configured time.Duration) time.Duration {
	if configured > time.Second {
		return time.Second
	}
	return configured
}

func localReloadLoop(ctx context.Context, hup <-chan os.Signal, supervisor *sensorruntime.Supervisor, client *transport.HTTP, cfg config.Config) {
	var versionNumber int64
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			next, err := loadConfig("")
			if err != nil {
				log.Printf("SIGHUP config reload rejected: %v", err)
				continue
			}
			versionNumber++
			if err := applyPipelines(supervisor, next, client, versionNumber); err != nil {
				log.Printf("SIGHUP pipeline rebuild rejected: %v", err)
				continue
			}
			cfg = next
			_ = cfg
		}
	}
}

func applyDesired(cfg *config.Config, desired transport.DesiredConfig) {
	if desired.SensorID != "" {
		cfg.Sensor.ID = desired.SensorID
	}
	cfg.InternalNetworks = append([]string(nil), desired.InternalNetworks...)
	cfg.CaptureSources = nil
	for _, source := range desired.CaptureSources {
		enabled := source.Enabled
		cfg.CaptureSources = append(cfg.CaptureSources, config.CaptureSource{Interface: source.Interface, Direction: source.Direction, BPFFilter: source.BPFFilter, Enabled: &enabled})
	}
	cfg.CaptureJobs = nil
	for _, job := range desired.CaptureJobs {
		cfg.CaptureJobs = append(cfg.CaptureJobs, config.CaptureJob{JobID: job.JobID, StartTime: job.StartTime, EndTime: job.EndTime, StorePCAP: job.StorePCAP})
	}
	if desired.HeartbeatIntervalSeconds > 0 {
		cfg.HeartbeatInterval = time.Duration(desired.HeartbeatIntervalSeconds) * time.Second
	}
	if desired.ConfigPollIntervalSeconds > 0 {
		cfg.Agent.ConfigPollInterval = time.Duration(desired.ConfigPollIntervalSeconds) * time.Second
	}
}

func applyPipelines(supervisor *sensorruntime.Supervisor, cfg config.Config, uploader sensorruntime.FlowUploader, versionNumber int64) error {
	cfg.CaptureJobs = activeCaptureJobs(cfg.CaptureJobs, time.Now().UTC())
	pipelines, err := buildPipelines(cfg, uploader)
	if err != nil {
		return err
	}
	return supervisor.Apply(versionNumber, pipelines)
}

func captureJobsEqual(current []config.CaptureJob, desired []transport.DesiredCaptureJob) bool {
	next := make([]config.CaptureJob, 0, len(desired))
	for _, job := range desired {
		next = append(next, config.CaptureJob{JobID: job.JobID, StartTime: job.StartTime, EndTime: job.EndTime, StorePCAP: job.StorePCAP})
	}
	return reflect.DeepEqual(current, next)
}

func activeCaptureJobs(jobs []config.CaptureJob, now time.Time) []config.CaptureJob {
	active := make([]config.CaptureJob, 0, len(jobs))
	for _, job := range jobs {
		if job.JobID == "" {
			continue
		}
		if !job.EndTime.IsZero() && !job.EndTime.After(now) {
			continue
		}
		active = append(active, job)
	}
	return active
}

func captureJobWindow(jobs []config.CaptureJob) (time.Time, time.Time) {
	var start time.Time
	var end time.Time
	for _, job := range jobs {
		if !job.StartTime.IsZero() && (start.IsZero() || job.StartTime.Before(start)) {
			start = job.StartTime
		}
		if !job.EndTime.IsZero() && (end.IsZero() || job.EndTime.After(end)) {
			end = job.EndTime
		}
	}
	return start, end
}

func captureJobIDs(jobs []config.CaptureJob) []string {
	seen := make(map[string]struct{}, len(jobs))
	ids := make([]string, 0, len(jobs))
	for _, job := range jobs {
		if job.JobID == "" {
			continue
		}
		if _, exists := seen[job.JobID]; exists {
			continue
		}
		seen[job.JobID] = struct{}{}
		ids = append(ids, job.JobID)
	}
	return ids
}

// idleCaptureRuntime keeps the durable spool and PCAP archive uploaders alive
// while no AF_PACKET reader is running.
type idleCaptureRuntime struct{}

func (idleCaptureRuntime) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func (idleCaptureRuntime) Snapshot() sensorruntime.CaptureSnapshot {
	return sensorruntime.CaptureSnapshot{}
}

type captureWindowPCAPSink struct {
	sink       sensorruntime.PCAPSink
	start, end time.Time
}

func (s captureWindowPCAPSink) Enqueue(pkt packet.Packet) bool {
	if (!s.start.IsZero() && pkt.Timestamp.Before(s.start)) || (!s.end.IsZero() && pkt.Timestamp.After(s.end)) {
		return true
	}
	return s.sink.Enqueue(pkt)
}

func buildPipelines(cfg config.Config, uploader sensorruntime.FlowUploader) ([]sensorruntime.CaptureRuntime, error) {
	store, err := spool.Open(cfg.Spool.Directory, spool.Limits{MaxBytes: cfg.Spool.MaxBytes, MaxAge: cfg.Spool.MaxAge}, time.Now)
	if err != nil {
		return nil, fmt.Errorf("open spool: %w", err)
	}
	manager, err := sensorruntime.NewBatchManager(sensorruntime.BatchManagerConfig{
		Store: store, Uploader: uploader, QueueSize: cfg.Capture.PacketQueueSize,
		UploadInterval: time.Second, Now: time.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("build batch manager: %w", err)
	}
	storeAnyPCAP := false
	for _, job := range cfg.CaptureJobs {
		storeAnyPCAP = storeAnyPCAP || job.StorePCAP
	}
	pcapUploader, canUploadPCAP := uploader.(sensorruntime.PCAPSegmentUploader)
	if storeAnyPCAP && !canUploadPCAP {
		return nil, fmt.Errorf("PCAP segment uploader is required when PCAP storage is enabled")
	}
	var pcapStartup *sensorruntime.PCAPStartup
	if storeAnyPCAP || canUploadPCAP {
		pcapStartup = sensorruntime.NewPCAPStartup(cfg.PCAP.Directory)
	}
	pipelines := []sensorruntime.CaptureRuntime{manager}
	if canUploadPCAP {
		archive, err := sensorruntime.NewPCAPArchiveManager(sensorruntime.PCAPArchiveManagerConfig{
			Directory: cfg.PCAP.Directory, SensorID: cfg.Sensor.ID, Uploader: pcapUploader,
			ScanInterval: time.Second, Startup: pcapStartup,
		})
		if err != nil {
			return nil, fmt.Errorf("build PCAP archive manager: %w", err)
		}
		pipelines = append(pipelines, archive)
	}
	if cfg.Agent.CaptureMode == config.CaptureModeOnDemand && len(cfg.CaptureJobs) == 0 {
		pipelines = append(pipelines, idleCaptureRuntime{})
		return pipelines, nil
	}

	sources, err := validateCaptureSources(cfg.CaptureSources)
	if err != nil {
		return nil, err
	}
	if len(sources) == 0 {
		return nil, errors.New("at least one enabled capture source is required")
	}
	directions := make(map[string]direction.Direction)
	for _, source := range sources {
		parsed, err := direction.Parse(source.Direction)
		if err != nil {
			return nil, err
		}
		directions[source.Interface] = parsed
	}
	classifier, err := direction.NewClassifier(directions, nil, cfg.InternalNetworks)
	if err != nil {
		return nil, err
	}

	captureStart := cfg.Capture.StartTime
	captureEnd := cfg.Capture.EndTime
	activeJobIDs := []string{cfg.Capture.JobID}
	if len(cfg.CaptureJobs) > 0 {
		captureStart, captureEnd = captureJobWindow(cfg.CaptureJobs)
		activeJobIDs = captureJobIDs(cfg.CaptureJobs)
	}
	for _, source := range sources {
		source := source
		bpfExpression := combineBPFExpressions(source.BPFFilter, cfg.Capture.BPF)
		matcher, err := packet.CompileBPFMatcher(bpfExpression)
		if err != nil {
			return nil, fmt.Errorf("capture source %s BPF: %w", source.Interface, err)
		}
		filter, err := buildFilter(cfg, bpfExpression, matcher)
		if err != nil {
			return nil, err
		}
		var pcapSinks []sensorruntime.PCAPSink
		for _, job := range cfg.CaptureJobs {
			if !job.StorePCAP {
				continue
			}
			rotator, err := pcapstore.NewRotator(
				pcapstore.FileFactory{Directory: cfg.PCAP.Directory, Prefix: pcapFilePrefix(job.JobID+"--"+source.Interface, source.Direction)},
				pcapstore.Limits{MaxBytes: cfg.PCAP.MaxSegmentBytes, MaxDuration: cfg.PCAP.MaxSegmentDuration},
			)
			if err != nil {
				return nil, fmt.Errorf("build PCAP rotator for %s: %w", source.Interface, err)
			}
			writer, err := sensorruntime.NewPCAPWriter(sensorruntime.PCAPWriterConfig{
				JobID:   job.JobID,
				Rotator: rotator, QueueSize: cfg.PCAP.QueueSize,
				Directory: cfg.PCAP.Directory, MaxDiskBytes: cfg.PCAP.MaxDiskBytes, Startup: pcapStartup,
			})
			if err != nil {
				return nil, fmt.Errorf("build PCAP writer for %s: %w", source.Interface, err)
			}
			pcapSinks = append(pcapSinks, captureWindowPCAPSink{sink: writer, start: job.StartTime, end: job.EndTime})
			pipelines = append(pipelines, writer)
		}
		pipeline, err := sensorruntime.NewPipeline(sensorruntime.PipelineConfig{
			SensorID: cfg.Sensor.ID, JobID: cfg.Capture.JobID + ":" + source.Interface + ":" + source.Direction,
			ActiveJobIDs: activeJobIDs,
			Interface:    source.Interface, Direction: source.Direction, IdleTimeout: cfg.FlowIdleTimeout,
			PayloadPreviewBytes: cfg.Capture.PayloadPreviewBytes,
			BatchMaxItems:       cfg.Batch.MaxItems, BatchMaxBytes: cfg.Batch.MaxBytes, PacketQueueSize: cfg.Capture.PacketQueueSize,
			Source: func() (capture.Reader, error) {
				return capture.NewLiveReader(source.Interface, capture.AFPacketOpener{}, classifier)
			},
			Filter: filter, Limits: capture.Limits{StartTime: captureStart, EndTime: captureEnd, Duration: cfg.Capture.Duration, MaxPackets: cfg.Capture.MaxPackets, MaxBytes: cfg.Capture.MaxBytes},
			BatchManager: manager, PCAPSinks: pcapSinks,
		})
		if err != nil {
			return nil, err
		}
		pipelines = append(pipelines, pipeline)
	}
	return pipelines, nil
}

func buildFilter(cfg config.Config, bpf string, matcher packet.BPFMatcher) (*packet.Filter, error) {
	var protocols []packet.Protocol
	for _, value := range cfg.Capture.Protocols {
		switch strings.ToUpper(value) {
		case "TCP":
			protocols = append(protocols, packet.TCP)
		case "UDP":
			protocols = append(protocols, packet.UDP)
		case "ICMP":
			protocols = append(protocols, packet.ICMP)
		}
	}
	var directions []direction.Direction
	for _, value := range cfg.Capture.Directions {
		parsed, err := direction.Parse(value)
		if err != nil {
			return nil, err
		}
		directions = append(directions, parsed)
	}
	return packet.NewFilter(packet.FilterSpec{BPFExpression: bpf, BPFMatcher: matcher, SourceCIDRs: cfg.Capture.SourceCIDRs, DestinationCIDRs: cfg.Capture.DestinationCIDRs, SourcePorts: cfg.Capture.SourcePorts, DestinationPorts: cfg.Capture.DestinationPorts, Protocols: protocols, IPVersions: cfg.Capture.IPVersions, Directions: directions})
}

func validateCaptureSources(configured []config.CaptureSource) ([]config.CaptureSource, error) {
	items, err := interfacespkg.Discover()
	if err != nil {
		return nil, err
	}
	byName := make(map[string]interfacespkg.Info, len(items))
	for _, item := range items {
		byName[item.Name] = item
	}
	seen := make(map[string]bool)
	var enabled []config.CaptureSource
	for _, source := range configured {
		if !source.IsEnabled() {
			continue
		}
		item, ok := byName[source.Interface]
		if !ok {
			return nil, fmt.Errorf("capture interface %q does not exist", source.Interface)
		}
		if !item.Up {
			return nil, fmt.Errorf("capture interface %q is down", source.Interface)
		}
		key := source.Interface + "\x00" + source.Direction
		if seen[key] {
			return nil, fmt.Errorf("duplicate capture source %s/%s", source.Interface, source.Direction)
		}
		seen[key] = true
		enabled = append(enabled, source)
	}
	return enabled, nil
}

func loadConfig(explicitPath string) (config.Config, error) {
	path := explicitPath
	if path == "" {
		path = os.Getenv("C2HUNTER_CONFIG")
	}
	if path == "" {
		return config.Load(strings.NewReader(""))
	}
	file, err := os.Open(path)
	if err != nil {
		return config.Config{}, fmt.Errorf("open configuration: %w", err)
	}
	defer file.Close()
	return config.Load(file)
}

func retryInterval() time.Duration {
	value := os.Getenv("C2HUNTER_RETRY_INTERVAL")
	if value == "" {
		return 5 * time.Second
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 5 * time.Second
	}
	return parsed
}

func buildRegistration(cfg config.Config, lookup func(string) (*net.Interface, error)) (telemetry.Registration, error) {
	interfaces := make([]telemetry.Interface, 0, len(cfg.CaptureSources))
	for _, source := range cfg.CaptureSources {
		if !source.IsEnabled() {
			continue
		}
		iface, err := lookup(source.Interface)
		if err != nil {
			return telemetry.Registration{}, fmt.Errorf("lookup capture interface %q: %w", source.Interface, err)
		}
		interfaces = append(interfaces, telemetry.Interface{Name: iface.Name, MAC: iface.HardwareAddr.String(), Direction: source.Direction})
	}
	hostname, err := os.Hostname()
	if err != nil {
		return telemetry.Registration{}, fmt.Errorf("hostname: %w", err)
	}
	var filesystem syscall.Statfs_t
	availableDisk := uint64(0)
	if err := syscall.Statfs(filepath.Dir(cfg.Spool.Directory), &filesystem); err == nil {
		availableDisk = filesystem.Bavail * uint64(filesystem.Bsize)
	}
	return telemetry.Registration{SensorID: cfg.Sensor.ID, Name: cfg.Sensor.Name, Hostname: hostname, AgentVersion: version, OS: goruntime.GOOS, KernelVersion: kernelVersion(), Interfaces: interfaces, Capabilities: []string{"AF_PACKET", "TPACKET_V3", "multi-interface", "durable-spool", "desired-config", "pcap-storage", "pcap-upload"}, CurrentTime: time.Now().UTC(), AvailableDiskBytes: availableDisk}, nil
}

func kernelVersion() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil || strings.TrimSpace(string(data)) == "" {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}
func nonempty(values ...string) []string {
	var out []string
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, strings.TrimSpace(value))
		}
	}
	return out
}

func pcapFilePrefix(interfaceName, direction string) string {
	value := interfaceName + "-" + strings.ToLower(direction)
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, value)
}

func combineBPFExpressions(expressions ...string) string {
	grouped := make([]string, 0, len(expressions))
	for _, expression := range expressions {
		if expression = strings.TrimSpace(expression); expression != "" {
			grouped = append(grouped, "("+expression+")")
		}
	}
	return strings.Join(grouped, " and ")
}
