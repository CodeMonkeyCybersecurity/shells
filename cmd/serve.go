package cmd

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/api"
	"github.com/CodeMonkeyCybersecurity/shells/internal/config"
	"github.com/CodeMonkeyCybersecurity/shells/internal/database"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/workers"
	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Shells API server (web dashboard + worker service + API endpoints)",
	Long: `Start the all-in-one Shells server that provides:

AUTOMATIC SERVICES:
  ✅ PostgreSQL database setup and migrations
  ✅ Web dashboard at http://localhost:8080
  ✅ Python worker service for GraphQL/IDOR scanning
  ✅ REST API at http://localhost:8080/api/v1/*

API ENDPOINTS:
  - /api/v1/hera/*          - Hera browser extension (phishing detection)
                              Real-time URL analysis, WHOIS lookups, threat intel
  - /health                 - Health check and database status
  - /                       - Web dashboard for scan results

AUTHENTICATION:
  API endpoints require API key via:
    - Authorization: Bearer <key> header
    - SHELLS_API_KEY environment variable
    - Auto-generated for local development (see security warning)

Example:
  shells serve                                      # Start everything on default ports
  shells serve --port 8080 --workers-port 5000     # Custom ports
  SHELLS_API_KEY=secret shells serve               # Production with API key
  shells serve --tls-cert cert.pem --tls-key key.pem # HTTPS mode
`,
	RunE: runServe,
}

var (
	serverPort  int
	serverHost  string
	enableCORS  bool
	tlsCert     string
	tlsKey      string
	workersPort int
)

func init() {
	rootCmd.AddCommand(serveCmd)

	// No config file flag needed - using flags + env vars from root.go
	serveCmd.Flags().IntVar(&serverPort, "port", 8080, "Port to listen on")
	serveCmd.Flags().StringVar(&serverHost, "host", "0.0.0.0", "Host to bind to")
	serveCmd.Flags().BoolVar(&enableCORS, "cors", true, "Enable CORS for browser extensions")
	serveCmd.Flags().StringVar(&tlsCert, "tls-cert", "", "Path to TLS certificate (optional)")
	serveCmd.Flags().StringVar(&tlsKey, "tls-key", "", "Path to TLS private key (optional)")
	serveCmd.Flags().IntVar(&workersPort, "workers-port", 5000, "Port for worker service")
}

func runServe(cmd *cobra.Command, args []string) error {
	// Configuration comes from flags + env vars (set in root.go init())
	// No YAML files needed
	viper.AutomaticEnv()
	viper.SetEnvPrefix("SHELLS")

	var cfg config.Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate TLS configuration
	if tlsCert != "" || tlsKey != "" {
		if tlsCert == "" || tlsKey == "" {
			return fmt.Errorf("both --tls-cert and --tls-key must be provided for TLS")
		}

		if _, err := os.Stat(tlsCert); err != nil {
			return fmt.Errorf("TLS cert file not found or not readable: %w", err)
		}
		if _, err := os.Stat(tlsKey); err != nil {
			return fmt.Errorf("TLS key file not found or not readable: %w", err)
		}
	}

	// Initialize logger
	log, err := logger.New(cfg.Logger)
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	log = log.WithComponent("api-server")

	log.Infow("Starting Shells API server",
		"host", serverHost,
		"port", serverPort,
		"cors_enabled", enableCORS,
		"tls_enabled", tlsCert != "",
		"config_file", viper.ConfigFileUsed(),
		"workers_port", workersPort,
	)

	// Start worker service automatically
	workerProcess, err := startWorkerService(log, workersPort)
	if err != nil {
		log.Warnw("Failed to start worker service - continuing without workers",
			"error", err,
			"note", "Run 'shells workers setup' to configure workers",
		)
	} else {
		log.Infow("Worker service started",
			"port", workersPort,
			"pid", workerProcess.Process.Pid,
		)
		// Ensure worker process is killed on shutdown
		defer func() {
			if workerProcess != nil && workerProcess.Process != nil {
				log.Infow("Stopping worker service")
				workerProcess.Process.Kill()
			}
		}()
	}

	// Initialize database
	store, err := database.NewStore(cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer store.Close()

	// Type assert to get underlying *database.Store for DB() access
	sqlStore, ok := store.(*database.Store)
	if !ok {
		return fmt.Errorf("store is not a SQL store - cannot access database connection")
	}

	log.Infow("Database connected",
		"driver", cfg.Database.Driver,
	)

	// P2 FIX: Removed sqlite3-specific warning (PostgreSQL-only now)
	// PostgreSQL handles concurrency natively

	// API key for authentication (optional for local development)
	apiKey := cfg.Security.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("SHELLS_API_KEY")
	}

	if apiKey == "" {
		// Auto-generate for local development
		apiKey = "dev-local-" + fmt.Sprintf("%d", time.Now().Unix())
		log.Warnw("No API key configured - using auto-generated key for local development",
			"auto_generated_key", apiKey,
			"security_warning", "For production, set SHELLS_API_KEY environment variable",
			"component", "api_server",
		)
		log.Warn("⚠️  SECURITY WARNING: Using auto-generated API key for local development")
		log.Warn("   For production use, set SHELLS_API_KEY environment variable")
		log.Warn("   Example: export SHELLS_API_KEY=$(openssl rand -hex 32)")
	} else {
		log.Infow("API key loaded",
			"source", func() string {
				if cfg.Security.APIKey != "" {
					return "config"
				}
				return "environment variable"
			}(),
			"component", "api_server",
		)
	}

	// Set Gin mode
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create Gin router
	router := gin.New()

	// Middleware
	router.Use(gin.Recovery())
	router.Use(api.LoggingMiddleware(log))

	// CORS middleware for browser extensions
	if enableCORS {
		router.Use(api.CORSMiddleware())
	}

	// Health check (no auth required)
	router.GET("/health", func(c *gin.Context) {
		healthy := true
		checks := make(map[string]interface{})

		// Check database connection
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		if err := sqlStore.DB().PingContext(ctx); err != nil {
			healthy = false
			checks["database"] = map[string]interface{}{
				"status": "unhealthy",
				"error":  err.Error(),
			}
		} else {
			checks["database"] = map[string]interface{}{
				"status": "healthy",
				"driver": cfg.Database.Driver,
			}
		}

		status := http.StatusOK
		if !healthy {
			status = http.StatusServiceUnavailable
		}

		c.JSON(status, gin.H{
			"healthy":   healthy,
			"checks":    checks,
			"timestamp": time.Now().Unix(),
			"version":   "0.1.0",
		})
	})

	// Dashboard UI routes (no auth required for viewing)
	api.RegisterDashboardRoutes(router, sqlStore.DB(), log)

	// API routes
	v1 := router.Group("/api/v1")
	{
		// Authentication middleware for all API routes
		v1.Use(api.AuthMiddleware(apiKey, log))

		// Rate limiting middleware
		v1.Use(api.RateLimitMiddleware(cfg.Security.RateLimit))

		// Register Hera routes
		api.RegisterHeraRoutes(v1, sqlStore.DB(), log)
	}

	// Create HTTP server
	addr := fmt.Sprintf("%s:%d", serverHost, serverPort)
	server := &http.Server{
		Addr:           addr,
		Handler:        router,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	// Start server in goroutine
	serverErrors := make(chan error, 1)
	go func() {
		log.Infow("HTTP server listening",
			"address", addr,
			"tls", tlsCert != "",
		)

		if tlsCert != "" && tlsKey != "" {
			serverErrors <- server.ListenAndServeTLS(tlsCert, tlsKey)
		} else {
			serverErrors <- server.ListenAndServe()
		}
	}()

	// Wait for interrupt signal or server error
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		return fmt.Errorf("server error: %w", err)

	case sig := <-shutdown:
		log.Infow("Received shutdown signal",
			"signal", sig.String(),
		)

		// Graceful shutdown with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Errorw("Failed to shutdown gracefully",
				"error", err,
			)
			return fmt.Errorf("server shutdown failed: %w", err)
		}

		log.Infow("Server shutdown complete")
	}

	return nil
}

// startWorkerService starts the Python worker service
func startWorkerService(log *logger.Logger, port int) (*exec.Cmd, error) {
	// Get project root
	projectRoot, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get working directory: %w", err)
	}

	workersDir := filepath.Join(projectRoot, "workers")
	serviceDir := filepath.Join(workersDir, "service")
	venvBin := filepath.Join(workersDir, "venv", "bin", "uvicorn")

	// Check if worker environment exists
	if _, err := os.Stat(venvBin); os.IsNotExist(err) {
		return nil, fmt.Errorf("worker environment not set up (run: shells workers setup)")
	}

	// Check if service directory exists
	if _, err := os.Stat(serviceDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("worker service directory not found: %s", serviceDir)
	}

	// Start uvicorn
	cmd := exec.Command(venvBin, "main:app", "--host", "0.0.0.0", "--port", fmt.Sprintf("%d", port))
	cmd.Dir = serviceDir

	// Redirect output to prevent blocking
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start worker service: %w", err)
	}

	// Wait a moment for service to start
	time.Sleep(2 * time.Second)

	// Verify service is healthy
	client := workers.NewClient(fmt.Sprintf("http://localhost:%d", port))
	if err := client.Health(); err != nil {
		cmd.Process.Kill()
		return nil, fmt.Errorf("worker service failed health check: %w", err)
	}

	return cmd, nil
}
