package cmd

import (
	"archive/zip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/security"
	"github.com/spf13/cobra"
)

// closeAndLogError is a helper function to handle deferred Close() errors
func closeAndLogError(c io.Closer, name string) {
	if err := c.Close(); err != nil {
		log.Error("Failed to close resource", "name", name, "error", err)
	}
}

var infraCmd = &cobra.Command{
	Use:   "infra",
	Short: "Infrastructure management for Nomad and PostgreSQL",
	Long: `Manage the shells infrastructure including Nomad cluster setup, 
PostgreSQL deployment, and scanner containers.

This command provides complete infrastructure automation:
- Install and configure Nomad cluster
- Deploy PostgreSQL in containers
- Build scanner container images
- Monitor infrastructure status

Examples:
  shells infra setup     # Complete infrastructure setup
  shells infra status    # Check infrastructure status
  shells infra nomad install
  shells infra postgres deploy
  shells infra containers build`,
}

var infraSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Complete infrastructure setup",
	Long: `Performs complete infrastructure setup including:
1. Install Nomad cluster
2. Deploy PostgreSQL database
3. Build scanner containers
4. Configure networking and storage

This will set up the entire shells infrastructure from scratch.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("🚀 Starting shells infrastructure setup\n\n")

		// Check if running as root
		if os.Geteuid() != 0 {
			fmt.Printf("⚠️  Some operations require root privileges\n")
			fmt.Printf("💡 Run with: sudo ./shells infra setup\n\n")
		}

		steps := []struct {
			name string
			fn   func() error
		}{
			{"Install Nomad", installNomad},
			{"Configure Nomad", configureNomad},
			{"Start Nomad", startNomad},
			{"Deploy PostgreSQL", deployPostgreSQL},
			{"Build Scanner Containers", buildScannerContainers},
			{"Configure Database", configureDatabase},
		}

		for i, step := range steps {
			fmt.Printf("📋 Step %d/%d: %s\n", i+1, len(steps), step.name)
			if err := step.fn(); err != nil {
				return fmt.Errorf("failed at step '%s': %w", step.name, err)
			}
			fmt.Printf("✅ %s completed\n\n", step.name)
		}

		fmt.Printf("🎉 Infrastructure setup completed successfully!\n")
		fmt.Printf("🔧 Run 'shells infra status' to verify all components\n")
		return nil
	},
}

var infraStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check infrastructure status",
	Long:  `Check the status of all infrastructure components including Nomad, PostgreSQL, and containers.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("📊 Shells Infrastructure Status\n")
		fmt.Printf("═══════════════════════════════════════\n\n")

		// Check Nomad
		fmt.Printf("🏗️  Nomad Cluster:\n")
		if err := checkNomadStatus(); err != nil {
			fmt.Printf("  ❌ %v\n", err)
		} else {
			fmt.Printf("  ✅ Running\n")
		}

		// Check PostgreSQL
		fmt.Printf("\n🐘 PostgreSQL Database:\n")
		if err := checkPostgreSQLStatus(); err != nil {
			fmt.Printf("  ❌ %v\n", err)
		} else {
			fmt.Printf("  ✅ Running\n")
		}

		// Check containers
		fmt.Printf("\n🐳 Scanner Containers:\n")
		if err := checkContainerStatus(); err != nil {
			fmt.Printf("  ❌ %v\n", err)
		} else {
			fmt.Printf("  ✅ Built and available\n")
		}

		// Check connectivity
		fmt.Printf("\n🔗 Connectivity:\n")
		if err := checkConnectivity(); err != nil {
			fmt.Printf("  ❌ %v\n", err)
		} else {
			fmt.Printf("  ✅ All services reachable\n")
		}

		return nil
	},
}

// Nomad subcommands
var infraNomadCmd = &cobra.Command{
	Use:   "nomad",
	Short: "Nomad cluster management",
	Long:  `Install, configure, and manage the Nomad cluster.`,
}

var infraNomadInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install Nomad binary",
	RunE: func(cmd *cobra.Command, args []string) error {
		return installNomad()
	},
}

var infraNomadConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Configure Nomad cluster",
	RunE: func(cmd *cobra.Command, args []string) error {
		return configureNomad()
	},
}

var infraNomadStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start Nomad agent",
	RunE: func(cmd *cobra.Command, args []string) error {
		return startNomad()
	},
}

var infraNomadStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop Nomad agent",
	RunE: func(cmd *cobra.Command, args []string) error {
		return stopNomad()
	},
}

// PostgreSQL subcommands
var infraPostgresCmd = &cobra.Command{
	Use:   "postgres",
	Short: "PostgreSQL database management",
	Long:  `Deploy and manage PostgreSQL database in Nomad containers.`,
}

var infraPostgresDeployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Deploy PostgreSQL database",
	RunE: func(cmd *cobra.Command, args []string) error {
		return deployPostgreSQL()
	},
}

var infraPostgresStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop PostgreSQL database",
	RunE: func(cmd *cobra.Command, args []string) error {
		return stopPostgreSQL()
	},
}

// Containers subcommands
var infraContainersCmd = &cobra.Command{
	Use:   "containers",
	Short: "Scanner container management",
	Long:  `Build and manage scanner container images.`,
}

var infraContainersBuildCmd = &cobra.Command{
	Use:   "build",
	Short: "Build all scanner containers",
	RunE: func(cmd *cobra.Command, args []string) error {
		return buildScannerContainers()
	},
}

var infraContainersListCmd = &cobra.Command{
	Use:   "list",
	Short: "List scanner containers",
	RunE: func(cmd *cobra.Command, args []string) error {
		return listScannerContainers()
	},
}

// Implementation functions

func installNomad() error {
	log.Info("Installing Nomad")

	// Check if already installed
	if _, err := exec.LookPath("nomad"); err == nil {
		out, err := exec.Command("nomad", "version").Output()
		if err == nil {
			log.Info("Nomad already installed", "version", string(out))
			return nil
		}
	}

	// Determine architecture
	arch := "amd64"
	if runtime.GOARCH == "arm64" {
		arch = "arm64"
	}

	version := "1.7.2"
	url := fmt.Sprintf("https://releases.hashicorp.com/nomad/%s/nomad_%s_linux_%s.zip", version, version, arch)

	log.Info("Downloading Nomad", "version", version, "arch", arch)

	// Download
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download Nomad: %w", err)
	}
	defer closeAndLogError(resp.Body, "HTTP response body")

	tmpFile := "/tmp/nomad.zip"
	out, err := os.Create(tmpFile)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer closeAndLogError(out, "nomad.zip file")

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to save download: %w", err)
	}

	// Extract
	r, err := zip.OpenReader(tmpFile)
	if err != nil {
		return fmt.Errorf("failed to open zip: %w", err)
	}
	defer closeAndLogError(r, "zip reader")

	for _, f := range r.File {
		if f.Name == "nomad" {
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("failed to open nomad binary: %w", err)
			}
			defer closeAndLogError(rc, "zip file entry")

			outFile, err := os.OpenFile("/tmp/nomad", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
			if err != nil {
				return fmt.Errorf("failed to create nomad binary: %w", err)
			}
			defer closeAndLogError(outFile, "nomad binary file")

			_, err = io.Copy(outFile, rc)
			if err != nil {
				return fmt.Errorf("failed to extract nomad binary: %w", err)
			}
			break
		}
	}

	// Move to /usr/local/bin (requires root)
	if os.Geteuid() == 0 {
		err = os.Rename("/tmp/nomad", "/usr/local/bin/nomad")
		if err != nil {
			return fmt.Errorf("failed to install nomad: %w", err)
		}
		log.Info("Nomad installed successfully", "path", "/usr/local/bin/nomad")
	} else {
		log.Warn("Manual installation required", "command", "sudo mv /tmp/nomad /usr/local/bin/nomad")
	}

	// Cleanup
	os.Remove(tmpFile)

	return nil
}

func configureNomad() error {
	log.Info("Configuring Nomad")

	configDir := "/etc/nomad.d"
	if os.Geteuid() != 0 {
		configDir = filepath.Join(os.Getenv("HOME"), ".nomad.d")
	}

	err := os.MkdirAll(configDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	config := `datacenter = "dc1"
data_dir = "/opt/nomad/data"
log_level = "INFO"
log_file = "/opt/nomad/logs/"

bind_addr = "0.0.0.0"

server {
  enabled = true
  bootstrap_expect = 1
}

client {
  enabled = true
  host_volume "postgres-data" {
    path = "/opt/nomad/volumes/postgres"
    read_only = false
  }
}

consul {
  address = "127.0.0.1:8500"
}

ports {
  http = 4646
  rpc  = 4647
  serf = 4648
}

acl {
  enabled = false
}

telemetry {
  prometheus_metrics = true
}
`

	configPath := filepath.Join(configDir, "nomad.hcl")
	err = os.WriteFile(configPath, []byte(config), 0644)
	if err != nil {
		return fmt.Errorf("failed to write nomad config: %w", err)
	}

	// Create data directories
	dataDirs := []string{"/opt/nomad/data", "/opt/nomad/logs", "/opt/nomad/volumes/postgres"}
	for _, dir := range dataDirs {
		if os.Geteuid() == 0 {
			err = os.MkdirAll(dir, 0755)
			if err != nil {
				log.Warn("Failed to create directory", "dir", dir, "error", err)
			}
		} else {
			log.Warn("Manual directory creation required", "command", fmt.Sprintf("sudo mkdir -p %s", dir))
		}
	}

	log.Info("Nomad configuration written", "path", configPath)
	return nil
}

func startNomad() error {
	log.Info("Starting Nomad agent")

	// Check if already running
	if err := exec.Command("pgrep", "nomad").Run(); err == nil {
		log.Info("Nomad is already running")
		return nil
	}

	configDir := "/etc/nomad.d"
	if os.Geteuid() != 0 {
		configDir = filepath.Join(os.Getenv("HOME"), ".nomad.d")
	}

	configPath := filepath.Join(configDir, "nomad.hcl")

	// Start Nomad in background
	cmd := exec.Command("nomad", "agent", "-config", configPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("failed to start nomad: %w", err)
	}

	// Wait a bit for startup
	time.Sleep(3 * time.Second)

	// Check if it's running
	if err := checkNomadStatus(); err != nil {
		return fmt.Errorf("nomad failed to start properly: %w", err)
	}

	log.Info("Nomad agent started successfully", "web-ui", "http://localhost:4646")

	return nil
}

func stopNomad() error {
	log.Info("Stopping Nomad agent")

	err := exec.Command("pkill", "nomad").Run()
	if err != nil {
		return fmt.Errorf("failed to stop nomad: %w", err)
	}

	log.Info("Nomad agent stopped")
	return nil
}

func deployPostgreSQL() error {
	log.Info("Deploying PostgreSQL database")

	jobPath := "/opt/shells/deployments/nomad/postgres.nomad"

	// Submit the job
	cmd := exec.Command("nomad", "job", "run", jobPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to deploy PostgreSQL: %w\nOutput: %s", err, string(output))
	}

	log.Info("PostgreSQL job submitted to Nomad", "output", string(output))

	// Wait for deployment
	log.Info("Waiting for PostgreSQL to be ready")
	for i := 0; i < 30; i++ {
		if err := checkPostgreSQLStatus(); err == nil {
			log.Info("PostgreSQL is ready")
			return nil
		}
		time.Sleep(2 * time.Second)
		fmt.Printf(".")
	}

	log.Warn("PostgreSQL deployment may still be starting", "check-command", "nomad job status shells-postgres")

	return nil
}

func stopPostgreSQL() error {
	log.Info("Stopping PostgreSQL database")

	cmd := exec.Command("nomad", "job", "stop", "shells-postgres")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop PostgreSQL: %w\nOutput: %s", err, string(output))
	}

	log.Info("PostgreSQL job stopped", "output", string(output))

	return nil
}

func buildScannerContainers() error {
	log.Info("Building scanner containers")

	containers := []struct {
		name  string
		tools []string
	}{
		{"shells-nmap", []string{"nmap", "masscan"}},
		{"shells-web", []string{"httpx", "nuclei", "subfinder"}},
		{"shells-ssl", []string{"openssl", "sslscan", "testssl.sh"}},
		{"shells-dns", []string{"dig", "nslookup", "dnsrecon"}},
	}

	for _, container := range containers {
		log.Info("Building container", "name", container.name)

		dockerfile := generateDockerfile(container.tools)
		
		// Create secure temporary file for Dockerfile
		tempFile, err := security.CreateSecureTempFile("Dockerfile_", ".dockerfile")
		if err != nil {
			return fmt.Errorf("failed to create secure temp file: %w", err)
		}
		defer closeAndLogError(tempFile, "Dockerfile temp file")
		
		if _, err := tempFile.Write([]byte(dockerfile)); err != nil {
			return fmt.Errorf("failed to write dockerfile for %s: %w", container.name, err)
		}
		
		dockerfilePath := tempFile.Name()

		cmd := exec.Command("docker", "build", "-t", container.name, "-f", dockerfilePath, ".")
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Error("Failed to build container", "name", container.name, "error", err, "output", string(output))
			continue
		}

		log.Info("Built container successfully", "name", container.name)
	}

	return nil
}

func generateDockerfile(tools []string) string {
	dockerfile := `FROM alpine:latest

RUN apk add --no-cache \
    curl \
    wget \
    bash \
    ca-certificates \
    git`

	for _, tool := range tools {
		switch tool {
		case "nmap":
			dockerfile += " \\\n    nmap"
		case "masscan":
			dockerfile += " \\\n    masscan"
		case "httpx":
			dockerfile += `

# Install Go
RUN apk add --no-cache go
ENV PATH="/root/go/bin:${PATH}"
ENV GOPATH="/root/go"
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`
		case "nuclei":
			dockerfile += `
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`
		case "subfinder":
			dockerfile += `
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`
		case "openssl":
			dockerfile += " \\\n    openssl"
		case "sslscan":
			dockerfile += " \\\n    && git clone https://github.com/rbsec/sslscan.git /tmp/sslscan \\\n    && cd /tmp/sslscan && make static && cp sslscan /usr/local/bin/"
		case "testssl.sh":
			dockerfile += `
RUN wget -O /usr/local/bin/testssl.sh https://raw.githubusercontent.com/drwetter/testssl.sh/3.1dev/testssl.sh \
    && chmod +x /usr/local/bin/testssl.sh`
		case "dig", "nslookup":
			dockerfile += " \\\n    bind-tools"
		case "dnsrecon":
			dockerfile += " \\\n    python3 py3-pip \\\n    && pip3 install dnsrecon"
		}
	}

	dockerfile += `

WORKDIR /tmp
ENTRYPOINT ["/bin/bash"]
`

	return dockerfile
}

func listScannerContainers() error {
	fmt.Printf("🐳 Scanner Containers:\n")

	cmd := exec.Command("docker", "images", "--filter", "reference=shells-*", "--format", "table {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	fmt.Printf("%s\n", string(output))
	return nil
}

func configureDatabase() error {
	log.Info("Configuring database connection")

	// Update config to use PostgreSQL
	configPath := "/opt/shells/.shells.yaml"

	// Read current config
	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	// Replace SQLite with PostgreSQL
	newContent := strings.ReplaceAll(string(content),
		`database:
  driver: "sqlite3"
  dsn: "/tmp/shells.db"`,
		`database:
  driver: "postgres"
  dsn: "${DATABASE_URL:-postgres://shells:shells@localhost:5432/shells?sslmode=disable}"`)

	err = os.WriteFile(configPath, []byte(newContent), 0644)
	if err != nil {
		return fmt.Errorf("failed to update config: %w", err)
	}

	log.Info("Database configuration updated to PostgreSQL")
	return nil
}

// Status check functions

func checkNomadStatus() error {
	cmd := exec.Command("nomad", "status")
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("nomad not running or not accessible")
	}
	return nil
}

func checkPostgreSQLStatus() error {
	cmd := exec.Command("nomad", "job", "status", "shells-postgres")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("PostgreSQL job not found")
	}

	if !strings.Contains(string(output), "running") {
		return fmt.Errorf("PostgreSQL not running")
	}

	return nil
}

func checkContainerStatus() error {
	cmd := exec.Command("docker", "images", "-q", "shells-nmap")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("Docker not available")
	}

	if len(strings.TrimSpace(string(output))) == 0 {
		return fmt.Errorf("Scanner containers not built")
	}

	return nil
}

func checkConnectivity() error {
	// Test Nomad API
	resp, err := http.Get("http://localhost:4646/v1/status/leader")
	if err != nil {
		return fmt.Errorf("Nomad API not reachable: %w", err)
	}
	resp.Body.Close()

	// Test PostgreSQL connection (via Nomad service)
	// This would need to be implemented based on service discovery

	return nil
}

func init() {
	// Add main infra command
	rootCmd.AddCommand(infraCmd)

	// Add subcommands
	infraCmd.AddCommand(infraSetupCmd)
	infraCmd.AddCommand(infraStatusCmd)

	// Nomad subcommands
	infraCmd.AddCommand(infraNomadCmd)
	infraNomadCmd.AddCommand(infraNomadInstallCmd)
	infraNomadCmd.AddCommand(infraNomadConfigCmd)
	infraNomadCmd.AddCommand(infraNomadStartCmd)
	infraNomadCmd.AddCommand(infraNomadStopCmd)

	// PostgreSQL subcommands
	infraCmd.AddCommand(infraPostgresCmd)
	infraPostgresCmd.AddCommand(infraPostgresDeployCmd)
	infraPostgresCmd.AddCommand(infraPostgresStopCmd)

	// Containers subcommands
	infraCmd.AddCommand(infraContainersCmd)
	infraContainersCmd.AddCommand(infraContainersBuildCmd)
	infraContainersCmd.AddCommand(infraContainersListCmd)
}
