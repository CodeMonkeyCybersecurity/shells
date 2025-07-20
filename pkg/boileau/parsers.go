package boileau

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
)

// Base parser implementations for each tool

// XSSStrikeParser parses XSSStrike output
type XSSStrikeParser struct{}

// NewXSSStrikeParser creates a new XSSStrike parser
func NewXSSStrikeParser() OutputParser {
	return &XSSStrikeParser{}
}

func (p *XSSStrikeParser) Parse(output string) ([]ToolFinding, error) {
	var findings []ToolFinding
	
	// Look for XSS findings
	xssRegex := regexp.MustCompile(`\[!\] XSS Vulnerability Found.*`)
	matches := xssRegex.FindAllString(output, -1)
	
	for _, match := range matches {
		findings = append(findings, ToolFinding{
			Type:        "XSS",
			Severity:    SeverityHigh,
			Title:       "Cross-Site Scripting (XSS) Vulnerability",
			Description: match,
			Evidence:    match,
			Solution:    "Implement proper input validation and output encoding",
		})
	}
	
	return findings, nil
}

// SQLMapParser parses SQLMap output
type SQLMapParser struct{}

// NewSQLMapParser creates a new SQLMap parser
func NewSQLMapParser() OutputParser {
	return &SQLMapParser{}
}

func (p *SQLMapParser) Parse(output string) ([]ToolFinding, error) {
	var findings []ToolFinding
	
	// Look for SQL injection findings
	if strings.Contains(output, "parameter") && strings.Contains(output, "is vulnerable") {
		findings = append(findings, ToolFinding{
			Type:        "SQL Injection",
			Severity:    SeverityCritical,
			Title:       "SQL Injection Vulnerability",
			Description: "SQL injection vulnerability detected in application",
			Evidence:    output,
			Solution:    "Use parameterized queries or prepared statements",
		})
	}
	
	return findings, nil
}

// MasscanParser parses Masscan output
type MasscanParser struct{}

// NewMasscanParser creates a new Masscan parser
func NewMasscanParser() OutputParser {
	return &MasscanParser{}
}

func (p *MasscanParser) Parse(output string) ([]ToolFinding, error) {
	var findings []ToolFinding
	
	scanner := bufio.NewScanner(strings.NewReader(output))
	portRegex := regexp.MustCompile(`Discovered open port (\d+)/(\w+) on (.+)`)
	
	openPorts := make(map[string][]string)
	
	for scanner.Scan() {
		line := scanner.Text()
		if matches := portRegex.FindStringSubmatch(line); len(matches) > 0 {
			port := matches[1]
			protocol := matches[2]
			host := matches[3]
			key := fmt.Sprintf("%s:%s", host, protocol)
			openPorts[key] = append(openPorts[key], port)
		}
	}
	
	// Create findings for open ports
	for hostProto, ports := range openPorts {
		severity := SeverityInfo
		if len(ports) > 10 {
			severity = SeverityMedium
		}
		
		findings = append(findings, ToolFinding{
			Type:        "Open Ports",
			Severity:    severity,
			Title:       fmt.Sprintf("Open Ports on %s", hostProto),
			Description: fmt.Sprintf("Found %d open ports: %s", len(ports), strings.Join(ports, ", ")),
			Metadata: map[string]interface{}{
				"ports": ports,
				"host":  hostProto,
			},
		})
	}
	
	return findings, nil
}

// AquatoneParser parses Aquatone output
type AquatoneParser struct{}

// NewAquatoneParser creates a new Aquatone parser
func NewAquatoneParser() OutputParser {
	return &AquatoneParser{}
}

func (p *AquatoneParser) Parse(output string) ([]ToolFinding, error) {
	var findings []ToolFinding
	
	// Aquatone creates screenshots and HTML reports
	if strings.Contains(output, "screenshots") {
		findings = append(findings, ToolFinding{
			Type:        "Visual Analysis",
			Severity:    SeverityInfo,
			Title:       "Web Application Screenshots Captured",
			Description: "Visual analysis of web application completed",
			Evidence:    output,
		})
	}
	
	return findings, nil
}

// TplmapParser parses Tplmap output
type TplmapParser struct{}

// NewTplmapParser creates a new Tplmap parser
func NewTplmapParser() OutputParser {
	return &TplmapParser{}
}

func (p *TplmapParser) Parse(output string) ([]ToolFinding, error) {
	var findings []ToolFinding
	
	if strings.Contains(output, "injection found") || strings.Contains(output, "vulnerable") {
		findings = append(findings, ToolFinding{
			Type:        "Template Injection",
			Severity:    SeverityHigh,
			Title:       "Server-Side Template Injection",
			Description: "Template injection vulnerability detected",
			Evidence:    output,
			Solution:    "Avoid user input in templates or use sandboxed template engines",
		})
	}
	
	return findings, nil
}

// SSRFMapParser parses SSRFMap output
type SSRFMapParser struct{}

// NewSSRFMapParser creates a new SSRFMap parser
func NewSSRFMapParser() OutputParser {
	return &SSRFMapParser{}
}

func (p *SSRFMapParser) Parse(output string) ([]ToolFinding, error) {
	var findings []ToolFinding
	
	if strings.Contains(output, "SSRF vulnerability") || strings.Contains(output, "successful") {
		findings = append(findings, ToolFinding{
			Type:        "SSRF",
			Severity:    SeverityHigh,
			Title:       "Server-Side Request Forgery",
			Description: "SSRF vulnerability detected allowing internal resource access",
			Evidence:    output,
			Solution:    "Implement URL validation and whitelist allowed destinations",
		})
	}
	
	return findings, nil
}

// NoSQLMapParser parses NoSQLMap output
type NoSQLMapParser struct{}

// NewNoSQLMapParser creates a new NoSQLMap parser
func NewNoSQLMapParser() OutputParser {
	return &NoSQLMapParser{}
}

func (p *NoSQLMapParser) Parse(output string) ([]ToolFinding, error) {
	var findings []ToolFinding
	
	if strings.Contains(output, "injection successful") || strings.Contains(output, "vulnerable") {
		findings = append(findings, ToolFinding{
			Type:        "NoSQL Injection",
			Severity:    SeverityCritical,
			Title:       "NoSQL Injection Vulnerability",
			Description: "NoSQL injection vulnerability detected",
			Evidence:    output,
			Solution:    "Sanitize user input and use proper query builders",
		})
	}
	
	return findings, nil
}

// CORSScannerParser parses CORS Scanner output
type CORSScannerParser struct{}

// NewCORSScannerParser creates a new CORS Scanner parser
func NewCORSScannerParser() OutputParser {
	return &CORSScannerParser{}
}

func (p *CORSScannerParser) Parse(output string) ([]ToolFinding, error) {
	var findings []ToolFinding
	
	if strings.Contains(output, "misconfigured") || strings.Contains(output, "wildcard") {
		findings = append(findings, ToolFinding{
			Type:        "CORS Misconfiguration",
			Severity:    SeverityMedium,
			Title:       "CORS Misconfiguration Detected",
			Description: "Cross-Origin Resource Sharing misconfiguration found",
			Evidence:    output,
			Solution:    "Configure CORS policies to only allow trusted origins",
		})
	}
	
	return findings, nil
}

// CommixParser parses Commix output
type CommixParser struct{}

// NewCommixParser creates a new Commix parser
func NewCommixParser() OutputParser {
	return &CommixParser{}
}

func (p *CommixParser) Parse(output string) ([]ToolFinding, error) {
	var findings []ToolFinding
	
	if strings.Contains(output, "command injection") || strings.Contains(output, "vulnerable") {
		findings = append(findings, ToolFinding{
			Type:        "Command Injection",
			Severity:    SeverityCritical,
			Title:       "OS Command Injection",
			Description: "Command injection vulnerability detected",
			Evidence:    output,
			Solution:    "Avoid executing system commands with user input",
		})
	}
	
	return findings, nil
}

// ArjunParser parses Arjun output
type ArjunParser struct{}

// NewArjunParser creates a new Arjun parser
func NewArjunParser() OutputParser {
	return &ArjunParser{}
}

func (p *ArjunParser) Parse(output string) ([]ToolFinding, error) {
	var findings []ToolFinding
	
	// Look for discovered parameters
	paramRegex := regexp.MustCompile(`\[\+\] Valid parameter found: (.+)`)
	matches := paramRegex.FindAllStringSubmatch(output, -1)
	
	if len(matches) > 0 {
		var params []string
		for _, match := range matches {
			if len(match) > 1 {
				params = append(params, match[1])
			}
		}
		
		findings = append(findings, ToolFinding{
			Type:        "Parameter Discovery",
			Severity:    SeverityInfo,
			Title:       "Hidden Parameters Discovered",
			Description: fmt.Sprintf("Found %d hidden parameters: %s", len(params), strings.Join(params, ", ")),
			Metadata: map[string]interface{}{
				"parameters": params,
			},
		})
	}
	
	return findings, nil
}

// GopherusParser parses Gopherus output
type GopherusParser struct{}

// NewGopherusParser creates a new Gopherus parser
func NewGopherusParser() OutputParser {
	return &GopherusParser{}
}

func (p *GopherusParser) Parse(output string) ([]ToolFinding, error) {
	var findings []ToolFinding
	
	if strings.Contains(output, "gopher://") || strings.Contains(output, "payload") {
		findings = append(findings, ToolFinding{
			Type:        "SSRF Exploitation",
			Severity:    SeverityInfo,
			Title:       "SSRF Exploitation Payloads Generated",
			Description: "Generated Gopher protocol payloads for SSRF exploitation",
			Evidence:    output,
		})
	}
	
	return findings, nil
}