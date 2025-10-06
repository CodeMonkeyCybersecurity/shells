package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/pkg/workers"
	"github.com/spf13/cobra"
)

var workersCmd = &cobra.Command{
	Use:   "workers",
	Short: "Manage bug bounty worker services (GraphCrawler, IDORD)",
	Long: `Manage the Python worker services that provide GraphQL scanning (GraphCrawler)
and IDOR detection (IDORD) capabilities.

Commands:
  setup  - Clone and set up worker environment
  start  - Start the worker service
  stop   - Stop the worker service
  status - Check worker service health`,
}

var workersSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Set up the worker environment (clone GraphCrawler and IDORD)",
	Long: `Clone GraphCrawler and IDORD repositories, create Python virtual environment,
and install all dependencies. This only needs to be run once.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(" Setting up worker environment...")

		// Get project root
		projectRoot, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}

		workersDir := filepath.Join(projectRoot, "workers")

		// Create workers directory
		if err := os.MkdirAll(workersDir, 0755); err != nil {
			return fmt.Errorf("failed to create workers directory: %w", err)
		}

		// Clone GraphCrawler
		fmt.Println(" Cloning GraphCrawler...")
		graphCrawlerDir := filepath.Join(workersDir, "GraphCrawler")
		if _, err := os.Stat(graphCrawlerDir); os.IsNotExist(err) {
			cloneCmd := exec.Command("git", "clone", "https://github.com/gsmith257-cyber/GraphCrawler.git", graphCrawlerDir)
			cloneCmd.Stdout = os.Stdout
			cloneCmd.Stderr = os.Stderr
			if err := cloneCmd.Run(); err != nil {
				return fmt.Errorf("failed to clone GraphCrawler: %w", err)
			}
		} else {
			fmt.Println("   GraphCrawler already exists, skipping clone")
		}

		// Clone IDORD (AyemunHossain/IDORD - actively maintained version)
		fmt.Println(" Cloning IDORD...")
		idordDir := filepath.Join(workersDir, "IDORD")
		if _, err := os.Stat(idordDir); os.IsNotExist(err) {
			cloneCmd := exec.Command("git", "clone", "https://github.com/AyemunHossain/IDORD.git", idordDir)
			cloneCmd.Stdout = os.Stdout
			cloneCmd.Stderr = os.Stderr
			if err := cloneCmd.Run(); err != nil {
				return fmt.Errorf("failed to clone IDORD: %w", err)
			}
		} else {
			fmt.Println("   IDORD already exists, skipping clone")
		}

		// Update requirements.txt files for Python 3.12 compatibility
		fmt.Println(" Updating requirements for Python 3.12 compatibility...")
		if err := updateGraphCrawlerRequirements(graphCrawlerDir); err != nil {
			fmt.Printf("⚠️  Warning: Failed to update GraphCrawler requirements: %v\n", err)
		}
		if err := updateIDORDRequirements(idordDir); err != nil {
			fmt.Printf("⚠️  Warning: Failed to update IDORD requirements: %v\n", err)
		}

		// Create Python virtual environment
		fmt.Println(" Creating Python virtual environment...")
		venvDir := filepath.Join(workersDir, "venv")
		if _, err := os.Stat(venvDir); os.IsNotExist(err) {
			venvCmd := exec.Command("python3", "-m", "venv", venvDir)
			venvCmd.Stdout = os.Stdout
			venvCmd.Stderr = os.Stderr
			if err := venvCmd.Run(); err != nil {
				return fmt.Errorf("failed to create virtual environment: %w", err)
			}
		} else {
			fmt.Println("   Virtual environment already exists, skipping creation")
		}

		// Install dependencies
		fmt.Println(" Installing dependencies...")
		pipBin := filepath.Join(venvDir, "bin", "pip")

		// Install FastAPI and dependencies
		installCmd := exec.Command(pipBin, "install", "fastapi", "uvicorn[standard]", "httpx", "pydantic")
		installCmd.Stdout = os.Stdout
		installCmd.Stderr = os.Stderr
		if err := installCmd.Run(); err != nil {
			return fmt.Errorf("failed to install FastAPI dependencies: %w", err)
		}

		// Install GraphCrawler dependencies
		graphCrawlerReqs := filepath.Join(graphCrawlerDir, "requirements.txt")
		if _, err := os.Stat(graphCrawlerReqs); err == nil {
			installCmd = exec.Command(pipBin, "install", "-r", graphCrawlerReqs)
			installCmd.Stdout = os.Stdout
			installCmd.Stderr = os.Stderr
			if err := installCmd.Run(); err != nil {
				fmt.Printf("⚠️  Warning: Failed to install GraphCrawler requirements: %v\n", err)
			}
		}

		// Install IDORD dependencies
		idordReqs := filepath.Join(idordDir, "requirements.txt")
		if _, err := os.Stat(idordReqs); err == nil {
			installCmd = exec.Command(pipBin, "install", "-r", idordReqs)
			installCmd.Stdout = os.Stdout
			installCmd.Stderr = os.Stderr
			if err := installCmd.Run(); err != nil {
				fmt.Printf("⚠️  Warning: Failed to install IDORD requirements: %v\n", err)
			}
		}

		fmt.Println("\n Worker environment setup complete!")
		fmt.Println("\nNext steps:")
		fmt.Println("  shells workers start    - Start the worker service")
		fmt.Println("  shells serve --workers  - Start API and workers together")

		return nil
	},
}

var workersStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the worker service",
	Long:  `Start the FastAPI worker service that provides GraphQL and IDOR scanning.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(" Starting worker service...")

		// Get project root
		projectRoot, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}

		workersDir := filepath.Join(projectRoot, "workers")
		serviceDir := filepath.Join(workersDir, "service")
		venvBin := filepath.Join(workersDir, "venv", "bin", "uvicorn")

		// Check if setup has been run
		if _, err := os.Stat(venvBin); os.IsNotExist(err) {
			return fmt.Errorf("worker environment not set up. Run: shells workers setup")
		}

		// Start uvicorn
		startCmd := exec.Command(venvBin, "main:app", "--host", "0.0.0.0", "--port", "5000")
		startCmd.Dir = serviceDir
		startCmd.Stdout = os.Stdout
		startCmd.Stderr = os.Stderr

		if err := startCmd.Start(); err != nil {
			return fmt.Errorf("failed to start worker service: %w", err)
		}

		// Save PID for stopping later
		pidFile := filepath.Join(workersDir, "worker.pid")
		if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", startCmd.Process.Pid)), 0644); err != nil {
			fmt.Printf("⚠️  Warning: Failed to save PID file: %v\n", err)
		}

		// Wait for service to be ready
		time.Sleep(2 * time.Second)

		fmt.Println(" Worker service started on http://localhost:5000")
		fmt.Println("\nCheck health: curl http://localhost:5000/health")

		return startCmd.Wait()
	},
}

var workersStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the worker service",
	Long:  `Stop the running worker service.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("🛑 Stopping worker service...")

		projectRoot, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get working directory: %w", err)
		}

		pidFile := filepath.Join(projectRoot, "workers", "worker.pid")
		pidData, err := os.ReadFile(pidFile)
		if err != nil {
			// Try pkill as fallback
			killCmd := exec.Command("pkill", "-f", "uvicorn.*workers.service.main")
			if err := killCmd.Run(); err != nil {
				return fmt.Errorf("no worker service found running")
			}
			fmt.Println(" Worker service stopped")
			return nil
		}

		// Kill by PID
		killCmd := exec.Command("kill", string(pidData))
		if err := killCmd.Run(); err != nil {
			return fmt.Errorf("failed to stop worker service: %w", err)
		}

		// Remove PID file
		os.Remove(pidFile)

		fmt.Println(" Worker service stopped")
		return nil
	},
}

var workersStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check worker service health",
	Long:  `Check if the worker service is running and healthy.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		client := workers.NewClient("http://localhost:5000")

		if err := client.Health(); err != nil {
			fmt.Println("❌ Worker service is not healthy")
			return err
		}

		fmt.Println(" Worker service is healthy")
		fmt.Println("🌐 URL: http://localhost:5000")
		fmt.Println(" API docs: http://localhost:5000/docs")

		return nil
	},
}

func init() {
	rootCmd.AddCommand(workersCmd)
	workersCmd.AddCommand(workersSetupCmd)
	workersCmd.AddCommand(workersStartCmd)
	workersCmd.AddCommand(workersStopCmd)
	workersCmd.AddCommand(workersStatusCmd)
}

// updateGraphCrawlerRequirements updates GraphCrawler requirements.txt for Python 3.12 compatibility
func updateGraphCrawlerRequirements(dir string) error {
	reqFile := filepath.Join(dir, "requirements.txt")

	// Python 3.12-compatible versions
	content := `aiohttp>=3.9.0
aiosignal>=1.3.1
async-timeout>=4.0.3
attrs>=23.1.0
backoff>=2.2.1
certifi>=2023.7.22
charset-normalizer>=3.3.0
frozenlist>=1.4.0
gql>=3.5.0
graphql-core>=3.2.3
idna>=3.4
multidict>=6.0.4
requests>=2.31.0
urllib3>=2.0.7
yarl>=1.9.3
`

	return os.WriteFile(reqFile, []byte(content), 0644)
}

// updateIDORDRequirements updates IDORD requirements.txt for Python 3.12 compatibility
func updateIDORDRequirements(dir string) error {
	reqFile := filepath.Join(dir, "requirements.txt")

	// Python 3.12-compatible versions
	content := `asgiref>=3.7.2
attrs>=23.1.0
Automat>=22.10.0
beautifulsoup4>=4.12.2
certifi>=2023.7.22
cffi>=1.16.0
charset-normalizer>=3.3.0
constantly>=23.10.4
cryptography>=41.0.0
cssselect>=1.2.0
Django>=4.2.0
filelock>=3.13.0
hyperlink>=21.0.0
idna>=3.4
incremental>=22.10.0
itemadapter>=0.8.0
itemloaders>=1.1.0
jmespath>=1.0.1
lxml>=4.9.3
parsel>=1.8.1
Protego>=0.3.0
proxyscrape>=0.3.0
pyasn1>=0.5.0
pyasn1-modules>=0.3.0
pycparser>=2.21
PyDispatcher>=2.0.7
pyOpenSSL>=23.3.0
queuelib>=1.6.2
requests>=2.31.0
requests-file>=1.5.1
Scrapy>=2.11.0
service-identity>=23.1.0
six>=1.16.0
soupsieve>=2.5
sqlparse>=0.4.4
tldextract>=5.0.0
Twisted>=23.10.0
typing_extensions>=4.8.0
urllib3>=2.1.0
w3lib>=2.1.2
zope.interface>=6.1
`

	return os.WriteFile(reqFile, []byte(content), 0644)
}
