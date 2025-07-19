package nmap

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/google/uuid"
)

type nmapScanner struct {
	cfg    config.NmapConfig
	logger *logger.Logger
}

func NewScanner(cfg config.NmapConfig, log interface {
	Info(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
}) core.Scanner {
	start := time.Now()

	// Initialize enhanced logger for Nmap scanner
	enhancedLogger, err := logger.New(config.LoggerConfig{Level: "debug", Format: "json"})
	if err != nil {
		// Fallback to basic logger if initialization fails
		enhancedLogger, _ = logger.New(config.LoggerConfig{Level: "info", Format: "json"})
	}
	enhancedLogger = enhancedLogger.WithComponent("nmap-scanner")

	ctx := context.Background()
	ctx, span := enhancedLogger.StartOperation(ctx, "nmap.NewScanner")
	defer func() {
		enhancedLogger.FinishOperation(ctx, span, "nmap.NewScanner", start, nil)
	}()

	enhancedLogger.WithContext(ctx).Infow("Initializing Nmap scanner",
		"scanner_type", "nmap",
		"component", "network_scanner",
		"binary_path", cfg.BinaryPath,
		"available_profiles", len(cfg.Profiles),
	)

	// Log available profiles
	profileNames := make([]string, 0, len(cfg.Profiles))
	for profileName := range cfg.Profiles {
		profileNames = append(profileNames, profileName)
	}
	enhancedLogger.WithContext(ctx).Debugw("Nmap scanner configuration",
		"binary_path", cfg.BinaryPath,
		"profiles", profileNames,
		"total_profiles", len(cfg.Profiles),
	)

	scanner := &nmapScanner{
		cfg:    cfg,
		logger: enhancedLogger,
	}

	enhancedLogger.WithContext(ctx).Infow("Nmap scanner initialized successfully",
		"scanner_type", "nmap",
		"total_init_duration_ms", time.Since(start).Milliseconds(),
		"capabilities", []string{"port_scanning", "service_detection", "os_detection", "vulnerability_assessment"},
	)

	return scanner
}

func (s *nmapScanner) Name() string {
	return "nmap"
}

func (s *nmapScanner) Type() types.ScanType {
	return types.ScanTypePort
}

func (s *nmapScanner) Validate(target string) error {
	start := time.Now()
	ctx := context.Background()
	ctx, span := s.logger.StartOperation(ctx, "nmap.Validate",
		"target", target,
	)
	var err error
	defer func() {
		s.logger.FinishOperation(ctx, span, "nmap.Validate", start, err)
	}()

	s.logger.WithContext(ctx).Debugw("Validating Nmap target",
		"target", target,
		"target_length", len(target),
	)

	if target == "" {
		err = fmt.Errorf("target cannot be empty")
		s.logger.LogError(ctx, err, "nmap.Validate.empty",
			"validation_type", "empty_target",
		)
		return err
	}

	// Check if target is an IP address
	validateStart := time.Now()
	if ip := net.ParseIP(target); ip != nil {
		s.logger.WithContext(ctx).Debugw("Target is valid IP address",
			"target", target,
			"ip_version", getIPVersion(ip),
			"validation_duration_ms", time.Since(validateStart).Milliseconds(),
		)
	} else {
		// Target is hostname - resolve it
		resolveStart := time.Now()
		addrs, err := net.LookupHost(target)
		resolveD := time.Since(resolveStart)

		if err != nil {
			s.logger.LogError(ctx, err, "nmap.Validate.resolve",
				"target", target,
				"validation_type", "hostname_resolution",
				"resolve_duration_ms", resolveD.Milliseconds(),
			)
			err = fmt.Errorf("invalid target: %w", err)
			return err
		}

		s.logger.WithContext(ctx).Debugw("Hostname resolution successful",
			"target", target,
			"resolved_addresses", addrs,
			"address_count", len(addrs),
			"resolve_duration_ms", resolveD.Milliseconds(),
		)
	}

	s.logger.WithContext(ctx).Infow("Nmap target validation successful",
		"target", target,
		"validation_duration_ms", time.Since(start).Milliseconds(),
	)

	return nil
}

func (s *nmapScanner) Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error) {
	start := time.Now()
	scanID := uuid.New().String()

	ctx, span := s.logger.StartOperation(ctx, "nmap.Scan",
		"target", target,
		"scan_id", scanID,
	)
	var err error
	defer func() {
		s.logger.FinishOperation(ctx, span, "nmap.Scan", start, err)
	}()

	s.logger.WithContext(ctx).Infow("Starting Nmap scan",
		"target", target,
		"scan_id", scanID,
		"available_options", len(options),
	)

	// Profile selection with detailed logging
	profile := options["profile"]
	if profile == "" {
		profile = "default"
		s.logger.WithContext(ctx).Debugw("Using default profile",
			"scan_id", scanID,
			"reason", "no profile specified in options",
		)
	} else {
		s.logger.WithContext(ctx).Debugw("Profile specified in options",
			"scan_id", scanID,
			"requested_profile", profile,
		)
	}

	profileArgs, ok := s.cfg.Profiles[profile]
	if !ok {
		s.logger.WithContext(ctx).Warnw("Requested profile not found, falling back to default",
			"scan_id", scanID,
			"requested_profile", profile,
			"available_profiles", getProfileNames(s.cfg.Profiles),
		)
		profile = "default"
		profileArgs = s.cfg.Profiles["default"]
	}

	s.logger.WithContext(ctx).Infow("Profile selected",
		"scan_id", scanID,
		"selected_profile", profile,
		"profile_args", profileArgs,
	)

	// Build command arguments with logging
	args := []string{"-oX", "-", target}
	baseArgsCount := len(args)

	if ports := options["ports"]; ports != "" {
		args = append(args, "-p", ports)
		s.logger.WithContext(ctx).Debugw("Port specification added",
			"scan_id", scanID,
			"ports", ports,
		)
	}

	profileArgsSlice := strings.Fields(profileArgs)
	args = append(args, profileArgsSlice...)

	s.logger.WithContext(ctx).Infow("Nmap command prepared",
		"scan_id", scanID,
		"binary_path", s.cfg.BinaryPath,
		"total_args", len(args),
		"base_args_count", baseArgsCount,
		"profile_args_count", len(profileArgsSlice),
		"full_args", args,
	)

	// Execute command with timing
	cmdStart := time.Now()
	cmd := exec.CommandContext(ctx, s.cfg.BinaryPath, args...)

	s.logger.WithContext(ctx).Infow("Executing Nmap scan",
		"scan_id", scanID,
		"command", s.cfg.BinaryPath,
		"target", target,
	)

	output, err := cmd.Output()
	cmdDuration := time.Since(cmdStart)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			s.logger.LogError(ctx, err, "nmap.Scan.command_failed",
				"scan_id", scanID,
				"exit_code", exitErr.ExitCode(),
				"stderr", string(exitErr.Stderr),
				"command_duration_ms", cmdDuration.Milliseconds(),
			)
			err = fmt.Errorf("nmap failed: %s", string(exitErr.Stderr))
			return nil, err
		}
		s.logger.LogError(ctx, err, "nmap.Scan.execution_error",
			"scan_id", scanID,
			"command_duration_ms", cmdDuration.Milliseconds(),
		)
		err = fmt.Errorf("failed to run nmap: %w", err)
		return nil, err
	}

	s.logger.WithContext(ctx).Infow("Nmap execution completed successfully",
		"scan_id", scanID,
		"command_duration_ms", cmdDuration.Milliseconds(),
		"output_size_bytes", len(output),
	)

	// Parse output with context
	parseStart := time.Now()
	findings, err := s.parseNmapOutput(ctx, output, target, scanID)
	parseDuration := time.Since(parseStart)

	if err != nil {
		s.logger.LogError(ctx, err, "nmap.Scan.parse_error",
			"scan_id", scanID,
			"output_size_bytes", len(output),
			"parse_duration_ms", parseDuration.Milliseconds(),
		)
		return nil, err
	}

	// Log scan completion with comprehensive metrics
	s.logger.WithContext(ctx).Infow("Nmap scan completed successfully",
		"scan_id", scanID,
		"target", target,
		"total_duration_ms", time.Since(start).Milliseconds(),
		"command_duration_ms", cmdDuration.Milliseconds(),
		"parse_duration_ms", parseDuration.Milliseconds(),
		"findings_count", len(findings),
		"output_size_bytes", len(output),
		"profile_used", profile,
	)

	// Log high-severity findings immediately
	for _, finding := range findings {
		if finding.Severity == types.SeverityCritical || finding.Severity == types.SeverityHigh {
			s.logger.WithContext(ctx).Warnw("High-severity finding discovered",
				"scan_id", scanID,
				"finding_type", finding.Type,
				"severity", finding.Severity,
				"title", finding.Title,
				"host", finding.Metadata["host"],
				"port", finding.Metadata["port"],
			)
		}
	}

	// Add scan metadata to all findings
	for i := range findings {
		if findings[i].Metadata == nil {
			findings[i].Metadata = make(map[string]interface{})
		}
		findings[i].Metadata["scan_id"] = scanID
		findings[i].Metadata["scan_duration_ms"] = time.Since(start).Milliseconds()
		findings[i].Metadata["nmap_profile"] = profile
	}

	return findings, nil
}

func (s *nmapScanner) parseNmapOutput(ctx context.Context, xmlData []byte, target string, scanID string) ([]types.Finding, error) {
	start := time.Now()
	ctx, span := s.logger.StartOperation(ctx, "nmap.parseNmapOutput",
		"target", target,
		"scan_id", scanID,
		"xml_size_bytes", len(xmlData),
	)
	var err error
	defer func() {
		s.logger.FinishOperation(ctx, span, "nmap.parseNmapOutput", start, err)
	}()

	s.logger.WithContext(ctx).Debugw("Starting Nmap output parsing",
		"scan_id", scanID,
		"xml_size_bytes", len(xmlData),
		"target", target,
	)

	var nmapRun nmapRun
	parseStart := time.Now()
	if err = xml.Unmarshal(xmlData, &nmapRun); err != nil {
		s.logger.LogError(ctx, err, "nmap.parseNmapOutput.xml_unmarshal",
			"scan_id", scanID,
			"xml_size_bytes", len(xmlData),
			"parse_duration_ms", time.Since(parseStart).Milliseconds(),
		)
		err = fmt.Errorf("failed to parse nmap XML: %w", err)
		return nil, err
	}

	s.logger.WithContext(ctx).Debugw("XML unmarshaling completed",
		"scan_id", scanID,
		"parse_duration_ms", time.Since(parseStart).Milliseconds(),
		"hosts_found", len(nmapRun.Hosts),
	)

	findings := []types.Finding{}
	hostCount := 0
	portCount := 0
	serviceMap := make(map[string]int)
	severityMap := make(map[types.Severity]int)

	for _, host := range nmapRun.Hosts {
		if host.Status.State != "up" {
			s.logger.WithContext(ctx).Debugw("Skipping host - not up",
				"scan_id", scanID,
				"host_status", host.Status.State,
			)
			continue
		}

		hostCount++
		address := s.getHostAddress(host)
		hostPortCount := 0

		s.logger.WithContext(ctx).Debugw("Processing active host",
			"scan_id", scanID,
			"host_address", address,
			"total_ports", len(host.Ports.Ports),
		)

		for _, port := range host.Ports.Ports {
			if port.State.State != "open" {
				continue
			}

			hostPortCount++
			portCount++
			serviceMap[port.Service.Name]++
			severity := s.calculateSeverity(port)
			severityMap[severity]++

			s.logger.WithContext(ctx).Debugw("Processing open port",
				"scan_id", scanID,
				"host", address,
				"port", port.PortID,
				"protocol", port.Protocol,
				"service", port.Service.Name,
				"version", port.Service.Version,
				"severity", severity,
			)

			finding := types.Finding{
				Tool:     "nmap",
				Type:     "open_port",
				Severity: severity,
				Title:    fmt.Sprintf("Open port %s/%s on %s", port.PortID, port.Protocol, address),
				Description: fmt.Sprintf(
					"Port %s/%s is open on %s. Service: %s %s",
					port.PortID, port.Protocol, address,
					port.Service.Name, port.Service.Version,
				),
				Evidence: s.generateEvidence(port),
				Metadata: map[string]interface{}{
					"host":         address,
					"port":         port.PortID,
					"protocol":     port.Protocol,
					"service":      port.Service.Name,
					"version":      port.Service.Version,
					"product":      port.Service.Product,
					"os_type":      port.Service.OSType,
					"extra_info":   port.Service.ExtraInfo,
					"service_conf": port.Service.Conf,
				},
			}

			if s.isHighRiskService(port.Service.Name) {
				finding.Solution = s.getServiceRecommendation(port.Service.Name)
				s.logger.WithContext(ctx).Warnw("High-risk service detected",
					"scan_id", scanID,
					"host", address,
					"port", port.PortID,
					"service", port.Service.Name,
					"risk_level", "high",
				)
			}

			findings = append(findings, finding)
		}

		s.logger.WithContext(ctx).Infow("Host processing completed",
			"scan_id", scanID,
			"host_address", address,
			"open_ports", hostPortCount,
		)

		if len(host.OS.OSMatches) > 0 {
			osMatch := host.OS.OSMatches[0]

			s.logger.WithContext(ctx).Debugw("OS detection result",
				"scan_id", scanID,
				"host", address,
				"os_name", osMatch.Name,
				"accuracy", osMatch.Accuracy,
				"total_matches", len(host.OS.OSMatches),
			)

			finding := types.Finding{
				Tool:     "nmap",
				Type:     "os_detection",
				Severity: types.SeverityInfo,
				Title:    fmt.Sprintf("Operating System detected on %s", address),
				Description: fmt.Sprintf(
					"OS Detection: %s (accuracy: %s%%)",
					osMatch.Name, osMatch.Accuracy,
				),
				Metadata: map[string]interface{}{
					"host":     address,
					"os_name":  osMatch.Name,
					"accuracy": osMatch.Accuracy,
				},
			}
			findings = append(findings, finding)
		}
	}

	// Log comprehensive parsing summary
	s.logger.WithContext(ctx).Infow("Nmap output parsing completed",
		"scan_id", scanID,
		"total_duration_ms", time.Since(start).Milliseconds(),
		"hosts_processed", hostCount,
		"total_open_ports", portCount,
		"total_findings", len(findings),
		"service_breakdown", serviceMap,
		"severity_breakdown", severityMap,
	)

	return findings, nil
}

func (s *nmapScanner) getHostAddress(host nmapHost) string {
	for _, addr := range host.Addresses {
		if addr.AddrType == "ipv4" {
			return addr.Addr
		}
	}
	for _, addr := range host.Addresses {
		if addr.AddrType == "ipv6" {
			return addr.Addr
		}
	}
	return "unknown"
}

func (s *nmapScanner) calculateSeverity(port nmapPort) types.Severity {
	service := port.Service.Name
	portNum := port.PortID

	highRiskServices := []string{"telnet", "ftp", "vnc", "rdp", "smb", "netbios-ssn"}
	for _, risk := range highRiskServices {
		if strings.Contains(service, risk) {
			return types.SeverityHigh
		}
	}

	highRiskPorts := []string{"23", "21", "445", "139", "3389", "5900"}
	for _, risk := range highRiskPorts {
		if portNum == risk {
			return types.SeverityHigh
		}
	}

	mediumRiskServices := []string{"mysql", "postgresql", "mongodb", "redis", "elasticsearch"}
	for _, risk := range mediumRiskServices {
		if strings.Contains(service, risk) {
			return types.SeverityMedium
		}
	}

	return types.SeverityLow
}

func (s *nmapScanner) isHighRiskService(service string) bool {
	highRisk := []string{"telnet", "ftp", "vnc", "rdp", "smb", "netbios", "rpc", "nfs"}
	service = strings.ToLower(service)

	for _, risk := range highRisk {
		if strings.Contains(service, risk) {
			return true
		}
	}
	return false
}

func (s *nmapScanner) generateEvidence(port nmapPort) string {
	var evidence strings.Builder

	evidence.WriteString(fmt.Sprintf("Port: %s/%s\n", port.PortID, port.Protocol))
	evidence.WriteString(fmt.Sprintf("State: %s\n", port.State.State))

	if port.Service.Name != "" {
		evidence.WriteString(fmt.Sprintf("Service: %s\n", port.Service.Name))
	}
	if port.Service.Version != "" {
		evidence.WriteString(fmt.Sprintf("Version: %s\n", port.Service.Version))
	}
	if port.Service.Product != "" {
		evidence.WriteString(fmt.Sprintf("Product: %s\n", port.Service.Product))
	}
	if port.Service.ExtraInfo != "" {
		evidence.WriteString(fmt.Sprintf("Extra Info: %s\n", port.Service.ExtraInfo))
	}

	return evidence.String()
}

func (s *nmapScanner) getServiceRecommendation(service string) string {
	recommendations := map[string]string{
		"telnet": "Telnet transmits data in plain text. Replace with SSH for secure remote access.",
		"ftp":    "FTP transmits credentials in plain text. Use SFTP or FTPS instead.",
		"vnc":    "Ensure VNC is properly secured with strong authentication and encryption.",
		"rdp":    "Enable Network Level Authentication and use strong passwords for RDP.",
		"smb":    "Disable SMBv1, ensure proper authentication, and restrict access.",
		"mysql":  "Bind to localhost only, use SSL/TLS, and implement strong authentication.",
		"redis":  "Enable authentication, bind to specific interfaces, and use SSL/TLS.",
	}

	service = strings.ToLower(service)
	for key, rec := range recommendations {
		if strings.Contains(service, key) {
			return rec
		}
	}

	return "Review service configuration and ensure proper security controls are in place."
}

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status    nmapStatus    `xml:"status"`
	Addresses []nmapAddress `xml:"address"`
	Ports     nmapPorts     `xml:"ports"`
	OS        nmapOS        `xml:"os"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   string      `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	Version   string `xml:"version,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	OSType    string `xml:"ostype,attr"`
	Conf      string `xml:"conf,attr"`
}

type nmapOS struct {
	OSMatches []nmapOSMatch `xml:"osmatch"`
}

type nmapOSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

// Helper functions for enhanced logging

func getIPVersion(ip net.IP) string {
	if ip.To4() != nil {
		return "IPv4"
	}
	return "IPv6"
}

func getProfileNames(profiles map[string]string) []string {
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	return names
}
