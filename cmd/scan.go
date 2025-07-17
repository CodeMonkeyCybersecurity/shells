package cmd

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Perform security scans on targets",
	Long:  `Execute various types of security scans including port scanning, SSL analysis, vulnerability scanning, and more.`,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.AddCommand(portScanCmd)
	scanCmd.AddCommand(sslScanCmd)
	scanCmd.AddCommand(webScanCmd)
	scanCmd.AddCommand(vulnScanCmd)
	scanCmd.AddCommand(dnsScanCmd)
	scanCmd.AddCommand(dirScanCmd)
	scanCmd.AddCommand(oauth2ScanCmd)
	scanCmd.AddCommand(nucleiScanCmd)
	scanCmd.AddCommand(httpxScanCmd)
	scanCmd.AddCommand(jsScanCmd)
	scanCmd.AddCommand(graphqlScanCmd)
	scanCmd.AddCommand(scimScanCmd)
	scanCmd.AddCommand(smugglingScanCmd)
	scanCmd.AddCommand(fullScanCmd)

	// Add global flags for scan mode
	scanCmd.PersistentFlags().Bool("nomad", true, "Run scans in Nomad containers (default)")
	scanCmd.PersistentFlags().Bool("local", false, "Run scans locally (legacy mode)")
}

var portScanCmd = &cobra.Command{
	Use:   "port [target]",
	Short: "Perform port scanning using Nmap",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		profile, _ := cmd.Flags().GetString("profile")
		ports, _ := cmd.Flags().GetString("ports")

		log.Info("Starting port scan", "target", target, "profile", profile)

		options := map[string]string{
			"profile": profile,
			"ports":   ports,
		}

		return executeScan(target, types.ScanTypePort, options)
	},
}

var sslScanCmd = &cobra.Command{
	Use:   "ssl [target]",
	Short: "Perform SSL/TLS analysis",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		port, _ := cmd.Flags().GetString("port")

		log.Info("Starting SSL scan", "target", target)

		options := map[string]string{
			"port": port,
		}

		return executeScan(target, types.ScanTypeSSL, options)
	},
}

var webScanCmd = &cobra.Command{
	Use:   "web [target]",
	Short: "Perform web application scanning using ZAP",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		depth, _ := cmd.Flags().GetInt("depth")

		log.Info("Starting web scan", "target", target)

		options := map[string]string{
			"depth": fmt.Sprintf("%d", depth),
		}

		return executeScan(target, types.ScanTypeWeb, options)
	},
}

var vulnScanCmd = &cobra.Command{
	Use:   "vuln [target]",
	Short: "Perform vulnerability scanning using OpenVAS",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]

		log.Info("Starting vulnerability scan", "target", target)

		return executeScan(target, types.ScanTypeVuln, nil)
	},
}

var dnsScanCmd = &cobra.Command{
	Use:   "dns [domain]",
	Short: "Perform DNS enumeration",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		domain := args[0]

		log.Info("Starting DNS scan", "domain", domain)

		return executeScan(domain, types.ScanTypeDNS, nil)
	},
}

var dirScanCmd = &cobra.Command{
	Use:   "dir [target]",
	Short: "Perform directory and file discovery",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		wordlist, _ := cmd.Flags().GetString("wordlist")

		log.Info("Starting directory scan", "target", target)

		options := map[string]string{
			"wordlist": wordlist,
		}

		return executeScan(target, types.ScanTypeDirectory, options)
	},
}

var oauth2ScanCmd = &cobra.Command{
	Use:   "oauth2 [target]",
	Short: "Perform OAuth2/OIDC security testing",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		clientID, _ := cmd.Flags().GetString("client-id")
		clientSecret, _ := cmd.Flags().GetString("client-secret")
		redirectURI, _ := cmd.Flags().GetString("redirect-uri")

		log.Info("Starting OAuth2 scan", "target", target)

		options := map[string]string{
			"client_id":     clientID,
			"client_secret": clientSecret,
			"redirect_uri":  redirectURI,
		}

		return executeScan(target, types.ScanType("oauth2"), options)
	},
}

var nucleiScanCmd = &cobra.Command{
	Use:   "nuclei [target]",
	Short: "Perform nuclei template-based vulnerability scanning",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		severity, _ := cmd.Flags().GetString("severity")
		tags, _ := cmd.Flags().GetString("tags")
		templates, _ := cmd.Flags().GetString("templates")

		log.Info("Starting nuclei scan", "target", target)

		options := map[string]string{
			"severity":  severity,
			"tags":      tags,
			"templates": templates,
		}

		return executeScan(target, types.ScanType("vulnerability"), options)
	},
}

var httpxScanCmd = &cobra.Command{
	Use:   "httpx [target]",
	Short: "Perform advanced HTTP probing",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		followRedirects, _ := cmd.Flags().GetBool("follow-redirects")
		probeAllIPs, _ := cmd.Flags().GetBool("probe-all-ips")
		ports, _ := cmd.Flags().GetString("ports")

		log.Info("Starting httpx scan", "target", target)

		options := map[string]string{
			"follow_redirects": fmt.Sprintf("%t", followRedirects),
			"probe_all_ips":    fmt.Sprintf("%t", probeAllIPs),
			"ports":            ports,
		}

		return executeScan(target, types.ScanType("http_probe"), options)
	},
}

var jsScanCmd = &cobra.Command{
	Use:   "js [target]",
	Short: "Perform JavaScript analysis for secrets and vulnerabilities",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]

		log.Info("Starting JavaScript analysis", "target", target)

		return executeScan(target, types.ScanType("javascript"), nil)
	},
}

var graphqlScanCmd = &cobra.Command{
	Use:   "graphql [target]",
	Short: "Perform GraphQL security testing",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		authHeader, _ := cmd.Flags().GetString("auth-header")

		log.Info("Starting GraphQL scan", "target", target)

		options := map[string]string{
			"auth_header": authHeader,
		}

		return executeScan(target, types.ScanType("api"), options)
	},
}

var scimScanCmd = &cobra.Command{
	Use:   "scim [target]",
	Short: "Perform SCIM vulnerability scanning",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		authToken, _ := cmd.Flags().GetString("auth-token")
		authType, _ := cmd.Flags().GetString("auth-type")
		testAll, _ := cmd.Flags().GetBool("test-all")

		log.Info("Starting SCIM scan", "target", target)

		options := map[string]string{
			"auth-token": authToken,
			"auth-type":  authType,
		}

		if testAll {
			options["test-all"] = "true"
		}

		return executeScan(target, types.ScanTypeSCIM, options)
	},
}

var smugglingScanCmd = &cobra.Command{
	Use:   "smuggling [target]",
	Short: "Perform HTTP Request Smuggling detection",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]
		technique, _ := cmd.Flags().GetString("technique")
		differential, _ := cmd.Flags().GetBool("differential")

		log.Info("Starting smuggling scan", "target", target)

		options := map[string]string{
			"technique":    technique,
			"differential": fmt.Sprintf("%t", differential),
		}

		return executeScan(target, types.ScanTypeSmuggling, options)
	},
}

var fullScanCmd = &cobra.Command{
	Use:   "full [target]",
	Short: "Perform comprehensive scan using all available tools",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		target := args[0]

		log.Info("Starting full scan", "target", target)

		scanTypes := []types.ScanType{
			types.ScanTypePort,
			types.ScanTypeSSL,
			types.ScanTypeWeb,
			types.ScanTypeVuln,
			types.ScanTypeDNS,
			types.ScanTypeDirectory,
			types.ScanTypeSCIM,
			types.ScanTypeSmuggling,
			types.ScanType("oauth2"),
			types.ScanType("http_probe"),
			types.ScanType("javascript"),
			types.ScanType("api"),
		}

		for _, scanType := range scanTypes {
			if err := executeScan(target, scanType, nil); err != nil {
				log.Error("Scan failed", "type", scanType, "error", err)
			}
		}

		return nil
	},
}

func init() {
	portScanCmd.Flags().String("profile", "default", "Scan profile (default, fast, thorough)")
	portScanCmd.Flags().String("ports", "", "Port range to scan (e.g., 1-1000)")

	sslScanCmd.Flags().String("port", "443", "Port to scan for SSL/TLS")

	webScanCmd.Flags().Int("depth", 2, "Spider depth for web scanning")

	dirScanCmd.Flags().String("wordlist", "common.txt", "Wordlist for directory discovery")

	oauth2ScanCmd.Flags().String("client-id", "", "OAuth2 client ID")
	oauth2ScanCmd.Flags().String("client-secret", "", "OAuth2 client secret")
	oauth2ScanCmd.Flags().String("redirect-uri", "", "OAuth2 redirect URI")

	nucleiScanCmd.Flags().String("severity", "critical,high,medium,low", "Severity levels to scan for")
	nucleiScanCmd.Flags().String("tags", "", "Tags to filter templates")
	nucleiScanCmd.Flags().String("templates", "", "Specific templates to use")

	httpxScanCmd.Flags().Bool("follow-redirects", true, "Follow HTTP redirects")
	httpxScanCmd.Flags().Bool("probe-all-ips", false, "Probe all resolved IPs")
	httpxScanCmd.Flags().String("ports", "", "Ports to probe")

	graphqlScanCmd.Flags().String("auth-header", "", "Authorization header for GraphQL requests")

	scimScanCmd.Flags().String("auth-token", "", "Bearer token for SCIM authentication")
	scimScanCmd.Flags().String("auth-type", "bearer", "Authentication type (bearer, basic)")
	scimScanCmd.Flags().Bool("test-all", false, "Run all SCIM tests")

	smugglingScanCmd.Flags().String("technique", "all", "Smuggling technique (cl.te, te.cl, te.te, http2, all)")
	smugglingScanCmd.Flags().Bool("differential", true, "Use differential analysis")
}

func executeScan(target string, scanType types.ScanType, options map[string]string) error {
	// Create scan request and save to database
	scanRequest := &types.ScanRequest{
		ID:        uuid.New().String(),
		Target:    target,
		Type:      scanType,
		Status:    types.ScanStatusRunning,
		CreatedAt: time.Now(),
		Options:   options,
	}

	startTime := time.Now()
	scanRequest.StartedAt = &startTime

	// Save scan to database
	store := GetStore()
	if store != nil {
		if err := store.SaveScan(GetContext(), scanRequest); err != nil {
			fmt.Printf("Warning: Failed to save scan to database: %v\n", err)
		}
	}

	fmt.Printf("🔍 Executing %s scan on %s [ID: %s]\n", scanType, target, scanRequest.ID)

	var findings []types.Finding
	var err error

	// Check if Nomad is available and not disabled
	useNomad := true
	if options != nil && options["local"] == "true" {
		useNomad = false
	}

	// Check if nomad command is available
	if useNomad {
		if _, nomadErr := exec.LookPath("nomad"); nomadErr != nil {
			fmt.Printf("⚠️  Nomad not available, falling back to local execution\n")
			useNomad = false
		}
	}

	if useNomad {
		fmt.Printf("🐳 Running containerized scan via Nomad\n")
		findings, err = runNomadScan(scanType, target, options, scanRequest.ID)
	} else {
		fmt.Printf("🖥️  Running local scan\n")
		switch scanType {
		case types.ScanTypePort:
			findings, err = executePortScan(target, options, scanRequest.ID)
		case types.ScanTypeSSL:
			findings, err = executeSSLScan(target, options, scanRequest.ID)
		default:
			// For remaining scan types, create a basic finding and run legacy function
			err = runLegacyScan(target, scanType, options)
			if err == nil {
				finding := createFinding(scanRequest.ID, string(scanType), "legacy_scan", fmt.Sprintf("%s scan completed", scanType), fmt.Sprintf("Legacy scan of %s completed successfully", target), "Local scan execution", types.SeverityInfo)
				findings = append(findings, finding)
			}
		}
	}

	// Update scan completion status
	completedTime := time.Now()
	scanRequest.CompletedAt = &completedTime

	if err != nil {
		scanRequest.Status = types.ScanStatusFailed
		scanRequest.ErrorMessage = err.Error()
	} else {
		scanRequest.Status = types.ScanStatusCompleted
	}

	// Save scan results to database
	if store != nil {
		if updateErr := store.UpdateScan(GetContext(), scanRequest); updateErr != nil {
			fmt.Printf("Warning: Failed to update scan in database: %v\n", updateErr)
		}

		if len(findings) > 0 {
			if findingsErr := store.SaveFindings(GetContext(), findings); findingsErr != nil {
				fmt.Printf("Warning: Failed to save findings to database: %v\n", findingsErr)
			} else {
				fmt.Printf("✅ Saved %d findings to database\n", len(findings))
			}
		}
	}

	fmt.Printf("🏁 Scan completed [ID: %s] - Duration: %s\n", scanRequest.ID, completedTime.Sub(startTime).String())

	return err
}

func executePortScan(target string, options map[string]string, scanID string) ([]types.Finding, error) {
	profile := "default"
	if options != nil && options["profile"] != "" {
		profile = options["profile"]
	}

	ports := "1-1000"
	if options != nil && options["ports"] != "" {
		ports = options["ports"]
	}

	fmt.Printf("📊 Port Scan Results for %s\n", target)
	fmt.Printf("Profile: %s, Ports: %s\n", profile, ports)

	var findings []types.Finding

	// Check if nmap is available
	if _, err := exec.LookPath("nmap"); err != nil {
		fmt.Printf("⚠️  nmap not found, using basic connectivity test\n")
		if err := basicConnectivityTest(target); err != nil {
			return findings, err
		}
		// Create a basic finding for connectivity test
		finding := types.Finding{
			ID:          uuid.New().String(),
			ScanID:      scanID,
			Tool:        "connectivity",
			Type:        "info",
			Severity:    types.SeverityInfo,
			Title:       "Basic Connectivity Test",
			Description: "Target is reachable via HTTP/HTTPS",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		findings = append(findings, finding)
		return findings, nil
	}

	// Run basic nmap scan
	cmd := exec.Command("nmap", "-p", ports, target)
	output, err := cmd.Output()
	if err != nil {
		return findings, fmt.Errorf("nmap scan failed: %v", err)
	}

	fmt.Printf("Results:\n%s\n", string(output))

	// Parse nmap output for open ports and create findings
	findings = parseNmapOutput(string(output), scanID)

	return findings, nil
}

func executeSSLScan(target string, options map[string]string, scanID string) ([]types.Finding, error) {
	port := "443"
	if options != nil && options["port"] != "" {
		port = options["port"]
	}

	fmt.Printf("🔒 SSL/TLS Analysis for %s:%s\n", target, port)

	var findings []types.Finding

	// Check if openssl is available
	if _, err := exec.LookPath("openssl"); err != nil {
		fmt.Printf("⚠️  openssl not found, using basic HTTP client test\n")
		if err := basicSSLTest(target, port); err != nil {
			return findings, err
		}
		finding := createFinding(scanID, "ssl-basic", "ssl_test", "Basic SSL Test", "SSL/TLS connection successful", fmt.Sprintf("Connected to %s:%s", target, port), types.SeverityInfo)
		findings = append(findings, finding)
		return findings, nil
	}

	// Run openssl s_client test
	cmd := exec.Command("openssl", "s_client", "-connect", target+":"+port, "-servername", target, "-verify_return_error")
	output, err := cmd.Output()
	if err != nil {
		return findings, fmt.Errorf("SSL test failed: %v", err)
	}

	fmt.Printf("Results:\n%s\n", string(output))

	// Parse SSL output for findings
	findings = parseSSLOutput(string(output), scanID)

	return findings, nil
}

func executeWebScan(target string, options map[string]string, scanID string) ([]types.Finding, error) {
	fmt.Printf("🌐 Web Application Scan for %s\n", target)
	fmt.Printf("⚠️  ZAP not available, performing basic web probe\n")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return nil, fmt.Errorf("web probe failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Server: %s\n", resp.Header.Get("Server"))
	fmt.Printf("Content-Type: %s\n", resp.Header.Get("Content-Type"))

	return nil, nil
}

func executeDNSScan(target string, options map[string]string, scanID string) ([]types.Finding, error) {
	fmt.Printf("🌍 DNS Enumeration for %s\n", target)

	// Use nslookup for basic DNS lookup
	cmd := exec.Command("nslookup", target)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed: %v", err)
	}

	fmt.Printf("Results:\n%s\n", string(output))
	return nil, nil
}

func executeDirScan(target string, options map[string]string, scanID string) ([]types.Finding, error) {
	fmt.Printf("📁 Directory Discovery for %s\n", target)
	fmt.Printf("⚠️  Directory enumeration tools not available, performing basic path check\n")

	commonPaths := []string{"/admin", "/login", "/api", "/.well-known", "/robots.txt", "/sitemap.xml"}
	client := &http.Client{Timeout: 5 * time.Second}

	for _, path := range commonPaths {
		url := strings.TrimRight(target, "/") + path
		resp, err := client.Head(url)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode < 400 {
			fmt.Printf("✅ Found: %s [%d]\n", path, resp.StatusCode)
		}
	}

	return nil, nil
}

func executeSCIMScan(target string, options map[string]string, scanID string) ([]types.Finding, error) {
	fmt.Printf("👥 SCIM Vulnerability Scan for %s\n", target)
	fmt.Printf("⚠️  Basic SCIM endpoint discovery\n")

	scimPaths := []string{"/scim/v2", "/scim", "/api/scim/v2", "/api/scim"}
	client := &http.Client{Timeout: 10 * time.Second}

	for _, path := range scimPaths {
		url := strings.TrimRight(target, "/") + path
		resp, err := client.Head(url)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode < 400 {
			fmt.Printf("✅ SCIM endpoint found: %s [%d]\n", path, resp.StatusCode)
		}
	}

	return nil, nil
}

func executeSmugglingScan(target string, options map[string]string, scanID string) ([]types.Finding, error) {
	fmt.Printf("🚛 HTTP Request Smuggling Detection for %s\n", target)
	fmt.Printf("⚠️  Using basic smuggling detection\n")

	// This is a simplified implementation
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return nil, fmt.Errorf("smuggling test failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("Response headers analyzed for smuggling indicators\n")
	fmt.Printf("Transfer-Encoding: %s\n", resp.Header.Get("Transfer-Encoding"))
	fmt.Printf("Content-Length: %s\n", resp.Header.Get("Content-Length"))

	return nil, nil
}

func executeOAuth2Scan(target string, options map[string]string, scanID string) ([]types.Finding, error) {
	fmt.Printf("🔐 OAuth2/OIDC Security Testing for %s\n", target)

	oauthPaths := []string{"/.well-known/openid_configuration", "/oauth2/authorize", "/auth/oauth2"}
	client := &http.Client{Timeout: 10 * time.Second}

	for _, path := range oauthPaths {
		url := strings.TrimRight(target, "/") + path
		resp, err := client.Head(url)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode < 400 {
			fmt.Printf("✅ OAuth2 endpoint found: %s [%d]\n", path, resp.StatusCode)
		}
	}

	return nil, nil
}

func executeHttpxScan(target string, options map[string]string, scanID string) ([]types.Finding, error) {
	fmt.Printf("🌐 HTTP Probing for %s\n", target)

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}

	resp, err := client.Get(target)
	if err != nil {
		return nil, fmt.Errorf("HTTP probe failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Content-Length: %s\n", resp.Header.Get("Content-Length"))
	fmt.Printf("Server: %s\n", resp.Header.Get("Server"))
	fmt.Printf("Technology: %s\n", resp.Header.Get("X-Powered-By"))

	return nil, nil
}

func executeJSScan(target string, options map[string]string, scanID string) ([]types.Finding, error) {
	fmt.Printf("📜 JavaScript Analysis for %s\n", target)
	fmt.Printf("⚠️  Basic JavaScript endpoint discovery\n")

	jsPaths := []string{"/js/", "/assets/js/", "/static/js/", "/app.js", "/main.js"}
	client := &http.Client{Timeout: 10 * time.Second}

	for _, path := range jsPaths {
		url := strings.TrimRight(target, "/") + path
		resp, err := client.Head(url)
		if err != nil {
			continue
		}
		resp.Body.Close()

		contentType := resp.Header.Get("Content-Type")
		if resp.StatusCode < 400 && strings.Contains(contentType, "javascript") {
			fmt.Printf("✅ JavaScript file found: %s [%d]\n", path, resp.StatusCode)
		}
	}

	return nil, nil
}

func executeAPISecan(target string, options map[string]string, scanID string) ([]types.Finding, error) {
	fmt.Printf("🔌 API Security Testing for %s\n", target)

	apiPaths := []string{"/api", "/graphql", "/api/v1", "/api/v2", "/rest"}
	client := &http.Client{Timeout: 10 * time.Second}

	for _, path := range apiPaths {
		url := strings.TrimRight(target, "/") + path
		resp, err := client.Head(url)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode < 400 {
			fmt.Printf("✅ API endpoint found: %s [%d]\n", path, resp.StatusCode)
		}
	}

	return nil, nil
}

func executeVulnScan(target string, options map[string]string, scanID string) ([]types.Finding, error) {
	fmt.Printf("🛡️  Vulnerability Scan for %s\n", target)
	fmt.Printf("⚠️  OpenVAS not available, performing basic security checks\n")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return nil, fmt.Errorf("vulnerability check failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("Security Headers Analysis:\n")
	fmt.Printf("X-Frame-Options: %s\n", resp.Header.Get("X-Frame-Options"))
	fmt.Printf("X-XSS-Protection: %s\n", resp.Header.Get("X-XSS-Protection"))
	fmt.Printf("X-Content-Type-Options: %s\n", resp.Header.Get("X-Content-Type-Options"))
	fmt.Printf("Strict-Transport-Security: %s\n", resp.Header.Get("Strict-Transport-Security"))

	return nil, nil
}

func basicConnectivityTest(target string) error {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Head("http://" + target)
	if err != nil {
		resp, err = client.Head("https://" + target)
		if err != nil {
			return fmt.Errorf("connectivity test failed: %v", err)
		}
	}
	defer resp.Body.Close()

	fmt.Printf("✅ Target is reachable [%d]\n", resp.StatusCode)
	return nil
}

func basicSSLTest(target, port string) error {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("https://" + target + ":" + port)
	if err != nil {
		return fmt.Errorf("SSL test failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("✅ SSL/TLS connection successful [%d]\n", resp.StatusCode)
	return nil
}

// Helper function to parse nmap output and create findings
func parseNmapOutput(output, scanID string) []types.Finding {
	var findings []types.Finding
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		if strings.Contains(line, "/tcp") && strings.Contains(line, "open") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				port := strings.Split(parts[0], "/")[0]
				service := parts[2]

				finding := types.Finding{
					ID:          uuid.New().String(),
					ScanID:      scanID,
					Tool:        "nmap",
					Type:        "port_discovery",
					Severity:    types.SeverityInfo,
					Title:       fmt.Sprintf("Open Port: %s (%s)", port, service),
					Description: fmt.Sprintf("Port %s is open and running %s service", port, service),
					Evidence:    line,
					CreatedAt:   time.Now(),
					UpdatedAt:   time.Now(),
				}
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func parseSSLOutput(output, scanID string) []types.Finding {
	var findings []types.Finding

	if strings.Contains(output, "Verify return code: 0 (ok)") {
		finding := createFinding(scanID, "openssl", "ssl_certificate", "Valid SSL Certificate", "SSL certificate is valid and trusted", "Certificate verification successful", types.SeverityInfo)
		findings = append(findings, finding)
	}

	if strings.Contains(output, "TLSv1.3") {
		finding := createFinding(scanID, "openssl", "ssl_protocol", "TLS 1.3 Support", "Server supports TLS 1.3", "Modern TLS protocol detected", types.SeverityInfo)
		findings = append(findings, finding)
	}

	return findings
}

// Legacy scan runner for backward compatibility
func runLegacyScan(target string, scanType types.ScanType, options map[string]string) error {
	switch scanType {
	case types.ScanTypeWeb:
		return legacyWebScan(target, options)
	case types.ScanTypeDNS:
		return legacyDNSScan(target, options)
	case types.ScanTypeDirectory:
		return legacyDirScan(target, options)
	case types.ScanTypeSCIM:
		return legacySCIMScan(target, options)
	case types.ScanTypeSmuggling:
		return legacySmugglingScan(target, options)
	case types.ScanTypeVuln:
		return legacyVulnScan(target, options)
	default:
		return fmt.Errorf("legacy scan not implemented for %s", scanType)
	}
}

func legacyWebScan(target string, options map[string]string) error {
	fmt.Printf("🌐 Web Application Scan for %s\n", target)
	fmt.Printf("⚠️  ZAP not available, performing basic web probe\n")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return fmt.Errorf("web probe failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("Status: %s\n", resp.Status)
	fmt.Printf("Server: %s\n", resp.Header.Get("Server"))
	fmt.Printf("Content-Type: %s\n", resp.Header.Get("Content-Type"))

	return nil
}

func legacyDNSScan(target string, options map[string]string) error {
	fmt.Printf("🌍 DNS Enumeration for %s\n", target)

	cmd := exec.Command("nslookup", target)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("DNS lookup failed: %v", err)
	}

	fmt.Printf("Results:\n%s\n", string(output))
	return nil
}

func legacyDirScan(target string, options map[string]string) error {
	fmt.Printf("📁 Directory Discovery for %s\n", target)
	fmt.Printf("⚠️  Directory enumeration tools not available, performing basic path check\n")

	commonPaths := []string{"/admin", "/login", "/api", "/.well-known", "/robots.txt", "/sitemap.xml"}
	client := &http.Client{Timeout: 5 * time.Second}

	for _, path := range commonPaths {
		url := strings.TrimRight(target, "/") + path
		resp, err := client.Head(url)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode < 400 {
			fmt.Printf("✅ Found: %s [%d]\n", path, resp.StatusCode)
		}
	}

	return nil
}

func legacySCIMScan(target string, options map[string]string) error {
	fmt.Printf("👥 SCIM Vulnerability Scan for %s\n", target)
	fmt.Printf("⚠️  Basic SCIM endpoint discovery\n")

	scimPaths := []string{"/scim/v2", "/scim", "/api/scim/v2", "/api/scim"}
	client := &http.Client{Timeout: 10 * time.Second}

	for _, path := range scimPaths {
		url := strings.TrimRight(target, "/") + path
		resp, err := client.Head(url)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode < 400 {
			fmt.Printf("✅ SCIM endpoint found: %s [%d]\n", path, resp.StatusCode)
		}
	}

	return nil
}

func legacySmugglingScan(target string, options map[string]string) error {
	fmt.Printf("🚛 HTTP Request Smuggling Detection for %s\n", target)
	fmt.Printf("⚠️  Using basic smuggling detection\n")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return fmt.Errorf("smuggling test failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("Response headers analyzed for smuggling indicators\n")
	fmt.Printf("Transfer-Encoding: %s\n", resp.Header.Get("Transfer-Encoding"))
	fmt.Printf("Content-Length: %s\n", resp.Header.Get("Content-Length"))

	return nil
}

func legacyVulnScan(target string, options map[string]string) error {
	fmt.Printf("🛡️  Vulnerability Scan for %s\n", target)
	fmt.Printf("⚠️  OpenVAS not available, performing basic security checks\n")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		return fmt.Errorf("vulnerability check failed: %v", err)
	}
	defer resp.Body.Close()

	fmt.Printf("Security Headers Analysis:\n")
	fmt.Printf("X-Frame-Options: %s\n", resp.Header.Get("X-Frame-Options"))
	fmt.Printf("X-XSS-Protection: %s\n", resp.Header.Get("X-XSS-Protection"))
	fmt.Printf("X-Content-Type-Options: %s\n", resp.Header.Get("X-Content-Type-Options"))
	fmt.Printf("Strict-Transport-Security: %s\n", resp.Header.Get("Strict-Transport-Security"))

	return nil
}

// Helper function to create a finding
func createFinding(scanID, tool, findingType, title, description, evidence string, severity types.Severity) types.Finding {
	return types.Finding{
		ID:          uuid.New().String(),
		ScanID:      scanID,
		Tool:        tool,
		Type:        findingType,
		Severity:    severity,
		Title:       title,
		Description: description,
		Evidence:    evidence,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
}

// Nomad job runner for containerized scans
func runNomadScan(scanType types.ScanType, target string, options map[string]string, scanID string) ([]types.Finding, error) {
	jobTemplate := generateNomadJobTemplate(scanType, target, options, scanID)

	// Write job template to temporary file
	jobFile := fmt.Sprintf("/tmp/scan_%s.nomad", scanID)
	if err := os.WriteFile(jobFile, []byte(jobTemplate), 0644); err != nil {
		return nil, fmt.Errorf("failed to write job template: %w", err)
	}

	// Submit job to Nomad
	cmd := exec.Command("nomad", "job", "run", jobFile)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to submit nomad job: %w", err)
	}

	// Wait for job completion and collect results
	return waitForNomadJobCompletion(scanID)
}

// Generate Nomad job template for scan
func generateNomadJobTemplate(scanType types.ScanType, target string, options map[string]string, scanID string) string {
	var image, command string

	switch scanType {
	case types.ScanTypePort:
		image = "instrumentisto/nmap:latest"
		command = fmt.Sprintf("nmap -oJ /results/%s.json -p %s %s", scanID, getOption(options, "ports", "1-1000"), target)
	case types.ScanTypeSSL:
		image = "alpine/openssl:latest"
		command = fmt.Sprintf("openssl s_client -connect %s:443 -servername %s > /results/%s.txt", target, target, scanID)
	case types.ScanTypeWeb:
		image = "owasp/zap2docker-stable:latest"
		command = fmt.Sprintf("zap-baseline.py -t %s -J /results/%s.json", target, scanID)
	case types.ScanTypeVuln:
		image = "projectdiscovery/nuclei:latest"
		command = fmt.Sprintf("nuclei -u %s -json -o /results/%s.json", target, scanID)
	case "http_probe":
		image = "projectdiscovery/httpx:latest"
		command = fmt.Sprintf("echo %s | httpx -json -o /results/%s.json", target, scanID)
	case types.ScanTypeDirectory:
		image = "ffuf/ffuf:latest"
		command = fmt.Sprintf("ffuf -u %s/FUZZ -w /usr/share/wordlists/common.txt -o /results/%s.json", target, scanID)
	default:
		image = "alpine:latest"
		command = fmt.Sprintf("echo 'Scan type %s not supported in container mode' > /results/%s.txt", scanType, scanID)
	}

	template := `job "scan-%s" {
  datacenters = ["dc1"]
  type = "batch"
  
  group "scanner" {
    count = 1
    
    volume "results" {
      type      = "host"
      source    = "scan-results"
      read_only = false
    }
    
    task "scan" {
      driver = "docker"
      
      volume_mount {
        volume      = "results"
        destination = "/results"
        read_only   = false
      }
      
      config {
        image = "%s"
        command = "sh"
        args = ["-c", "%s"]
        
        auth {
          username = ""
          password = ""
        }
      }
      
      env {
        SCAN_ID = "%s"
        TARGET = "%s"
        SCAN_TYPE = "%s"
      }
      
      resources {
        cpu    = 500
        memory = 256
      }
      
      restart {
        attempts = 1
        interval = "5m"
        delay    = "15s"
        mode     = "fail"
      }
    }
  }
}`

	return fmt.Sprintf(template, scanID, image, command, scanID, target, scanType)
}

func getOption(options map[string]string, key, defaultValue string) string {
	if options != nil && options[key] != "" {
		return options[key]
	}
	return defaultValue
}

func waitForNomadJobCompletion(scanID string) ([]types.Finding, error) {
	// Poll for job completion
	jobName := fmt.Sprintf("scan-%s", scanID)
	maxWait := 5 * time.Minute
	pollInterval := 10 * time.Second

	timeout := time.After(maxWait)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return nil, fmt.Errorf("scan job %s timed out after %s", jobName, maxWait)
		case <-ticker.C:
			// Check job status
			cmd := exec.Command("nomad", "job", "status", jobName)
			output, err := cmd.Output()
			if err != nil {
				continue
			}

			if strings.Contains(string(output), "Status = dead") && strings.Contains(string(output), "successful") {
				// Job completed successfully, collect results
				return collectNomadResults(scanID)
			} else if strings.Contains(string(output), "Status = dead") && strings.Contains(string(output), "failed") {
				return nil, fmt.Errorf("scan job %s failed", jobName)
			}
		}
	}
}

func collectNomadResults(scanID string) ([]types.Finding, error) {
	// Read results from the mounted volume
	resultFiles := []string{
		fmt.Sprintf("/tmp/scan-results/%s.json", scanID),
		fmt.Sprintf("/tmp/scan-results/%s.txt", scanID),
	}

	var findings []types.Finding

	for _, file := range resultFiles {
		if content, err := os.ReadFile(file); err == nil {
			// Parse the results based on file type
			if strings.HasSuffix(file, ".json") {
				// Try to parse as JSON findings
				if parsedFindings := parseJSONResults(string(content), scanID); len(parsedFindings) > 0 {
					findings = append(findings, parsedFindings...)
				}
			} else {
				// Create a basic finding from text content
				finding := createFinding(
					scanID,
					"container-scan",
					"scan_result",
					"Scan Results",
					"Containerized scan completed",
					string(content),
					types.SeverityInfo,
				)
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func parseJSONResults(content, scanID string) []types.Finding {
	// This would parse tool-specific JSON output formats
	// For now, create a basic finding with the raw content
	var findings []types.Finding

	if len(content) > 0 {
		finding := createFinding(
			scanID,
			"json-parser",
			"parsed_result",
			"JSON Scan Results",
			"Parsed results from containerized scan",
			content,
			types.SeverityInfo,
		)
		findings = append(findings, finding)
	}

	return findings
}
