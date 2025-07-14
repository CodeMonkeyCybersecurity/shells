package nmap

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/yourusername/shells/internal/config"
	"github.com/yourusername/shells/internal/core"
	"github.com/yourusername/shells/pkg/types"
)

type nmapScanner struct {
	cfg    config.NmapConfig
	logger interface {
		Info(msg string, keysAndValues ...interface{})
		Error(msg string, keysAndValues ...interface{})
		Debug(msg string, keysAndValues ...interface{})
	}
}

func NewScanner(cfg config.NmapConfig, logger interface {
	Info(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
}) core.Scanner {
	return &nmapScanner{
		cfg:    cfg,
		logger: logger,
	}
}

func (s *nmapScanner) Name() string {
	return "nmap"
}

func (s *nmapScanner) Type() types.ScanType {
	return types.ScanTypePort
}

func (s *nmapScanner) Validate(target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}

	if net.ParseIP(target) == nil {
		if _, err := net.LookupHost(target); err != nil {
			return fmt.Errorf("invalid target: %w", err)
		}
	}

	return nil
}

func (s *nmapScanner) Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error) {
	profile := options["profile"]
	if profile == "" {
		profile = "default"
	}

	profileArgs, ok := s.cfg.Profiles[profile]
	if !ok {
		profileArgs = s.cfg.Profiles["default"]
	}

	args := []string{"-oX", "-", target}

	if ports := options["ports"]; ports != "" {
		args = append(args, "-p", ports)
	}

	args = append(args, strings.Fields(profileArgs)...)

	s.logger.Info("Running nmap scan", "target", target, "args", args)

	cmd := exec.CommandContext(ctx, s.cfg.BinaryPath, args...)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("nmap failed: %s", string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("failed to run nmap: %w", err)
	}

	return s.parseNmapOutput(output, target)
}

func (s *nmapScanner) parseNmapOutput(xmlData []byte, target string) ([]types.Finding, error) {
	var nmapRun nmapRun
	if err := xml.Unmarshal(xmlData, &nmapRun); err != nil {
		return nil, fmt.Errorf("failed to parse nmap XML: %w", err)
	}

	findings := []types.Finding{}

	for _, host := range nmapRun.Hosts {
		if host.Status.State != "up" {
			continue
		}

		address := s.getHostAddress(host)

		for _, port := range host.Ports.Ports {
			if port.State.State != "open" {
				continue
			}

			severity := s.calculateSeverity(port)

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
			}

			findings = append(findings, finding)
		}

		if len(host.OS.OSMatches) > 0 {
			osMatch := host.OS.OSMatches[0]
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
