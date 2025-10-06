package config

import (
	"time"
)

type Config struct {
	Logger       LoggerConfig       `mapstructure:"logger"`
	Database     DatabaseConfig     `mapstructure:"database"`
	Redis        RedisConfig        `mapstructure:"redis"`
	Worker       WorkerConfig       `mapstructure:"worker"`
	Telemetry    TelemetryConfig    `mapstructure:"telemetry"`
	Security     SecurityConfig     `mapstructure:"security"`
	Tools        ToolsConfig        `mapstructure:"tools"`
	Platforms    BugBountyPlatforms `mapstructure:"platforms"`
	ShodanAPIKey string             `mapstructure:"shodan_api_key"`
	CensysAPIKey string             `mapstructure:"censys_api_key"`
	CensysSecret string             `mapstructure:"censys_secret"`
}

type LoggerConfig struct {
	Level       string   `mapstructure:"level"`
	Format      string   `mapstructure:"format"`
	OutputPaths []string `mapstructure:"output_paths"`
}

type DatabaseConfig struct {
	Driver          string        `mapstructure:"driver"`
	DSN             string        `mapstructure:"dsn"`
	MaxConnections  int           `mapstructure:"max_connections"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
}

type RedisConfig struct {
	Addr         string        `mapstructure:"addr"`
	Password     string        `mapstructure:"password"`
	DB           int           `mapstructure:"db"`
	MaxRetries   int           `mapstructure:"max_retries"`
	DialTimeout  time.Duration `mapstructure:"dial_timeout"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

type WorkerConfig struct {
	Count             int           `mapstructure:"count"`
	QueuePollInterval time.Duration `mapstructure:"queue_poll_interval"`
	MaxRetries        int           `mapstructure:"max_retries"`
	RetryDelay        time.Duration `mapstructure:"retry_delay"`
}

type TelemetryConfig struct {
	Enabled      bool    `mapstructure:"enabled"`
	ServiceName  string  `mapstructure:"service_name"`
	ExporterType string  `mapstructure:"exporter_type"`
	Endpoint     string  `mapstructure:"endpoint"`
	SampleRate   float64 `mapstructure:"sample_rate"`
}

type SecurityConfig struct {
	RateLimit  RateLimitConfig `mapstructure:"rate_limit"`
	ScopeFile  string          `mapstructure:"scope_file"`
	APIKey     string          `mapstructure:"api_key"`
	EnableAuth bool            `mapstructure:"enable_auth"`
}

type RateLimitConfig struct {
	RequestsPerSecond int `mapstructure:"requests_per_second"`
	BurstSize         int `mapstructure:"burst_size"`
}

type ToolsConfig struct {
	Nmap          NmapConfig          `mapstructure:"nmap"`
	SSL           SSLConfig           `mapstructure:"ssl"`
	ZAP           ZAPConfig           `mapstructure:"zap"`
	OpenVAS       OpenVASConfig       `mapstructure:"openvas"`
	Nikto         NiktoConfig         `mapstructure:"nikto"`
	Nuclei        NucleiConfig        `mapstructure:"nuclei"`
	HTTPX         HTTPXConfig         `mapstructure:"httpx"`
	JavaScript    JSConfig            `mapstructure:"javascript"`
	OAuth2        OAuth2ToolConfig    `mapstructure:"oauth2"`
	SCIM          SCIMConfig          `mapstructure:"scim"`
	Smuggling     SmugglingConfig     `mapstructure:"smuggling"`
	BusinessLogic BusinessLogicConfig `mapstructure:"business_logic"`
	Prowler       ProwlerConfig       `mapstructure:"prowler"`
	Favicon       FaviconConfig       `mapstructure:"favicon"`
}

type NmapConfig struct {
	BinaryPath string            `mapstructure:"binary_path"`
	Timeout    time.Duration     `mapstructure:"timeout"`
	Profiles   map[string]string `mapstructure:"profiles"`
}

type SSLConfig struct {
	Timeout         time.Duration `mapstructure:"timeout"`
	FollowRedirects bool          `mapstructure:"follow_redirects"`
	CheckRevocation bool          `mapstructure:"check_revocation"`
}

type ZAPConfig struct {
	APIEndpoint string        `mapstructure:"api_endpoint"`
	APIKey      string        `mapstructure:"api_key"`
	Timeout     time.Duration `mapstructure:"timeout"`
}

type OpenVASConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type NiktoConfig struct {
	BinaryPath string        `mapstructure:"binary_path"`
	Timeout    time.Duration `mapstructure:"timeout"`
}

type NucleiConfig struct {
	BinaryPath      string        `mapstructure:"binary_path"`
	TemplatesPath   string        `mapstructure:"templates_path"`
	CustomTemplates string        `mapstructure:"custom_templates"`
	Timeout         time.Duration `mapstructure:"timeout"`
	RateLimit       int           `mapstructure:"rate_limit"`
	BulkSize        int           `mapstructure:"bulk_size"`
	Concurrency     int           `mapstructure:"concurrency"`
	Retries         int           `mapstructure:"retries"`
}

type HTTPXConfig struct {
	BinaryPath      string        `mapstructure:"binary_path"`
	Timeout         time.Duration `mapstructure:"timeout"`
	Threads         int           `mapstructure:"threads"`
	RateLimit       int           `mapstructure:"rate_limit"`
	Retries         int           `mapstructure:"retries"`
	FollowRedirects bool          `mapstructure:"follow_redirects"`
	ProbeAllIPs     bool          `mapstructure:"probe_all_ips"`
}

type JSConfig struct {
	LinkFinderPath   string        `mapstructure:"linkfinder_path"`
	SecretFinderPath string        `mapstructure:"secretfinder_path"`
	RetireJSPath     string        `mapstructure:"retirejs_path"`
	Timeout          time.Duration `mapstructure:"timeout"`
}

type OAuth2ToolConfig struct {
	DefaultClientID string        `mapstructure:"default_client_id"`
	Timeout         time.Duration `mapstructure:"timeout"`
}

type SCIMConfig struct {
	DiscoveryTimeout   time.Duration `mapstructure:"discovery_timeout"`
	MaxBulkOperations  int           `mapstructure:"max_bulk_operations"`
	TestAuthentication bool          `mapstructure:"test_authentication"`
	TestFilters        bool          `mapstructure:"test_filters"`
	TestBulkOps        bool          `mapstructure:"test_bulk_ops"`
	TestProvisions     bool          `mapstructure:"test_provisions"`
	Timeout            time.Duration `mapstructure:"timeout"`
	MaxRetries         int           `mapstructure:"max_retries"`
	UserAgent          string        `mapstructure:"user_agent"`
	FollowRedirects    bool          `mapstructure:"follow_redirects"`
	VerifySSL          bool          `mapstructure:"verify_ssl"`
}

type SmugglingConfig struct {
	Techniques                 []string      `mapstructure:"techniques"`
	DifferentialDelay          time.Duration `mapstructure:"differential_delay"`
	MaxPayloadSize             int           `mapstructure:"max_payload_size"`
	Timeout                    time.Duration `mapstructure:"timeout"`
	MaxRetries                 int           `mapstructure:"max_retries"`
	UserAgent                  string        `mapstructure:"user_agent"`
	FollowRedirects            bool          `mapstructure:"follow_redirects"`
	VerifySSL                  bool          `mapstructure:"verify_ssl"`
	EnableTimingAnalysis       bool          `mapstructure:"enable_timing_analysis"`
	EnableDifferentialAnalysis bool          `mapstructure:"enable_differential_analysis"`
}

type BusinessLogicConfig struct {
	// General settings
	Timeout         time.Duration `mapstructure:"timeout"`
	MaxRetries      int           `mapstructure:"max_retries"`
	UserAgent       string        `mapstructure:"user_agent"`
	FollowRedirects bool          `mapstructure:"follow_redirects"`
	VerifySSL       bool          `mapstructure:"verify_ssl"`
	VerboseOutput   bool          `mapstructure:"verbose_output"`
	MaintainSession bool          `mapstructure:"maintain_session"`

	// Password reset testing
	PasswordReset PasswordResetConfig `mapstructure:"password_reset"`

	// Workflow testing
	Workflow WorkflowConfig `mapstructure:"workflow"`

	// Race condition testing
	RaceCondition RaceConditionConfig `mapstructure:"race_condition"`

	// MFA bypass testing
	MFABypass MFABypassConfig `mapstructure:"mfa_bypass"`

	// Account recovery testing
	AccountRecovery AccountRecoveryConfig `mapstructure:"account_recovery"`

	// E-commerce testing
	Ecommerce EcommerceConfig `mapstructure:"ecommerce"`

	// Reporting
	Reporting ReportingConfig `mapstructure:"reporting"`
}

type PasswordResetConfig struct {
	TestTokenEntropy  bool          `mapstructure:"test_token_entropy"`
	TestHostHeader    bool          `mapstructure:"test_host_header"`
	TestUserEnum      bool          `mapstructure:"test_user_enum"`
	TestRaceCondition bool          `mapstructure:"test_race_condition"`
	TokenSamples      int           `mapstructure:"token_samples"`
	BruteForceThreads int           `mapstructure:"brute_force_threads"`
	RequestDelay      time.Duration `mapstructure:"request_delay"`
	MaxTokenLength    int           `mapstructure:"max_token_length"`
	MinTokenEntropy   float64       `mapstructure:"min_token_entropy"`
}

type WorkflowConfig struct {
	MaxDepth           int           `mapstructure:"max_depth"`
	MaxStates          int           `mapstructure:"max_states"`
	TestPrivileges     bool          `mapstructure:"test_privileges"`
	TestStateSkipping  bool          `mapstructure:"test_state_skipping"`
	TestStepReordering bool          `mapstructure:"test_step_reordering"`
	TestParallelExec   bool          `mapstructure:"test_parallel_exec"`
	TestValueManip     bool          `mapstructure:"test_value_manip"`
	TestAuthFlaws      bool          `mapstructure:"test_auth_flaws"`
	TestTimeVulns      bool          `mapstructure:"test_time_vulns"`
	AnalysisTimeout    time.Duration `mapstructure:"analysis_timeout"`
	StateTimeout       time.Duration `mapstructure:"state_timeout"`
}

type RaceConditionConfig struct {
	MaxWorkers         int           `mapstructure:"max_workers"`
	TestPayments       bool          `mapstructure:"test_payments"`
	TestInventory      bool          `mapstructure:"test_inventory"`
	TestAuth           bool          `mapstructure:"test_auth"`
	TestBusinessLogic  bool          `mapstructure:"test_business_logic"`
	TestResourceAlloc  bool          `mapstructure:"test_resource_alloc"`
	RequestDelay       time.Duration `mapstructure:"request_delay"`
	ConcurrentAttempts int           `mapstructure:"concurrent_attempts"`
	DetectionThreshold float64       `mapstructure:"detection_threshold"`
}

type MFABypassConfig struct {
	TestRememberMe     bool          `mapstructure:"test_remember_me"`
	TestBackupCodes    bool          `mapstructure:"test_backup_codes"`
	TestRecoveryFlow   bool          `mapstructure:"test_recovery_flow"`
	TestSessionUpgrade bool          `mapstructure:"test_session_upgrade"`
	TestRaceCondition  bool          `mapstructure:"test_race_condition"`
	TestResponseManip  bool          `mapstructure:"test_response_manip"`
	TestTokenReuse     bool          `mapstructure:"test_token_reuse"`
	TestCookieManip    bool          `mapstructure:"test_cookie_manip"`
	TestAPIEndpoints   bool          `mapstructure:"test_api_endpoints"`
	TestFlowManip      bool          `mapstructure:"test_flow_manip"`
	SessionTimeout     time.Duration `mapstructure:"session_timeout"`
	MaxAttempts        int           `mapstructure:"max_attempts"`
}

type AccountRecoveryConfig struct {
	TestAllMethods      bool          `mapstructure:"test_all_methods"`
	TestSecQuestions    bool          `mapstructure:"test_sec_questions"`
	TestSMSRecovery     bool          `mapstructure:"test_sms_recovery"`
	TestEmailRecovery   bool          `mapstructure:"test_email_recovery"`
	TestBackupCodes     bool          `mapstructure:"test_backup_codes"`
	TestSocialRecovery  bool          `mapstructure:"test_social_recovery"`
	TestBiometric       bool          `mapstructure:"test_biometric"`
	TestAdminRecovery   bool          `mapstructure:"test_admin_recovery"`
	TestDeviceRecovery  bool          `mapstructure:"test_device_recovery"`
	TestMethodChaining  bool          `mapstructure:"test_method_chaining"`
	TestCrossMethod     bool          `mapstructure:"test_cross_method"`
	RecoveryTimeout     time.Duration `mapstructure:"recovery_timeout"`
	MaxRecoveryAttempts int           `mapstructure:"max_recovery_attempts"`
}

type EcommerceConfig struct {
	TestShoppingCart    bool      `mapstructure:"test_shopping_cart"`
	TestPaymentLogic    bool      `mapstructure:"test_payment_logic"`
	TestPricingLogic    bool      `mapstructure:"test_pricing_logic"`
	TestCouponLogic     bool      `mapstructure:"test_coupon_logic"`
	TestNegativeValues  bool      `mapstructure:"test_negative_values"`
	TestIntegerOverflow bool      `mapstructure:"test_integer_overflow"`
	TestCartManip       bool      `mapstructure:"test_cart_manip"`
	TestPriceManip      bool      `mapstructure:"test_price_manip"`
	TestCurrencyConf    bool      `mapstructure:"test_currency_conf"`
	TestRaceConditions  bool      `mapstructure:"test_race_conditions"`
	MaxCartItems        int       `mapstructure:"max_cart_items"`
	PriceTestValues     []float64 `mapstructure:"price_test_values"`
	CurrencyTestList    []string  `mapstructure:"currency_test_list"`
}

type ReportingConfig struct {
	GenerateHTML          bool          `mapstructure:"generate_html"`
	GenerateJSON          bool          `mapstructure:"generate_json"`
	GeneratePDF           bool          `mapstructure:"generate_pdf"`
	GenerateCSV           bool          `mapstructure:"generate_csv"`
	IncludeBusinessImpact bool          `mapstructure:"include_business_impact"`
	IncludePoCDetails     bool          `mapstructure:"include_poc_details"`
	IncludeCharts         bool          `mapstructure:"include_charts"`
	IncludeTimeline       bool          `mapstructure:"include_timeline"`
	ReportTimeout         time.Duration `mapstructure:"report_timeout"`
	OutputDirectory       string        `mapstructure:"output_directory"`
	ReportTemplate        string        `mapstructure:"report_template"`
	MaxReportSize         int           `mapstructure:"max_report_size"`
}

type ProwlerConfig struct {
	NomadAddr    string        `mapstructure:"nomad_addr"`
	DockerImage  string        `mapstructure:"docker_image"`
	OutputFormat string        `mapstructure:"output_format"`
	ParallelJobs int           `mapstructure:"parallel_jobs"`
	Timeout      time.Duration `mapstructure:"timeout"`
	AWSProfile   string        `mapstructure:"aws_profile"`
	CacheDir     string        `mapstructure:"cache_dir"`
}

type FaviconConfig struct {
	Timeout        time.Duration `mapstructure:"timeout"`
	UserAgent      string        `mapstructure:"user_agent"`
	CacheDir       string        `mapstructure:"cache_dir"`
	ShodanAPIKey   string        `mapstructure:"shodan_api_key"`
	MaxConcurrency int           `mapstructure:"max_concurrency"`
	EnableShodan   bool          `mapstructure:"enable_shodan"`
	EnableCache    bool          `mapstructure:"enable_cache"`
	CustomDatabase string        `mapstructure:"custom_database"`
}

// BugBountyPlatforms contains configuration for all bug bounty platform integrations
type BugBountyPlatforms struct {
	HackerOne HackerOneConfig   `mapstructure:"hackerone"`
	Bugcrowd  BugcrowdConfig    `mapstructure:"bugcrowd"`
	AWS       AWSBountyConfig   `mapstructure:"aws"`
	Azure     AzureBountyConfig `mapstructure:"azure"`
	GCP       GCPBountyConfig   `mapstructure:"gcp"`
}

// HackerOneConfig configures HackerOne API integration
type HackerOneConfig struct {
	Enabled         bool          `mapstructure:"enabled"`
	APIUsername     string        `mapstructure:"api_username"`
	APIToken        string        `mapstructure:"api_token"`
	BaseURL         string        `mapstructure:"base_url"`
	Timeout         time.Duration `mapstructure:"timeout"`
	AutoSubmit      bool          `mapstructure:"auto_submit"`
	MinimumSeverity string        `mapstructure:"minimum_severity"` // critical, high, medium, low
	DraftMode       bool          `mapstructure:"draft_mode"`       // Create as draft instead of submitting
}

// BugcrowdConfig configures Bugcrowd API integration
type BugcrowdConfig struct {
	Enabled         bool          `mapstructure:"enabled"`
	APIToken        string        `mapstructure:"api_token"`
	BaseURL         string        `mapstructure:"base_url"`
	Timeout         time.Duration `mapstructure:"timeout"`
	AutoSubmit      bool          `mapstructure:"auto_submit"`
	MinimumSeverity string        `mapstructure:"minimum_severity"` // P1, P2, P3, P4, P5
	DraftMode       bool          `mapstructure:"draft_mode"`
}

// AWSBountyConfig configures AWS Vulnerability Research Program integration (via HackerOne)
type AWSBountyConfig struct {
	Enabled         bool          `mapstructure:"enabled"`
	ProgramHandle   string        `mapstructure:"program_handle"` // Default: "amazonvrp"
	UseHackerOne    bool          `mapstructure:"use_hackerone"`  // AWS uses HackerOne
	APIUsername     string        `mapstructure:"api_username"`
	APIToken        string        `mapstructure:"api_token"`
	Timeout         time.Duration `mapstructure:"timeout"`
	AutoSubmit      bool          `mapstructure:"auto_submit"`
	MinimumSeverity string        `mapstructure:"minimum_severity"`
}

// AzureBountyConfig configures Microsoft Azure Bug Bounty integration
type AzureBountyConfig struct {
	Enabled         bool          `mapstructure:"enabled"`
	ReportingEmail  string        `mapstructure:"reporting_email"` // MSRC email
	ProgramType     string        `mapstructure:"program_type"`    // "azure" or "azure-devops"
	Timeout         time.Duration `mapstructure:"timeout"`
	AutoSubmit      bool          `mapstructure:"auto_submit"`
	MinimumSeverity string        `mapstructure:"minimum_severity"` // Critical, Important, Moderate, Low
}

// GCPBountyConfig configures Google Cloud Platform bug bounty integration
type GCPBountyConfig struct {
	Enabled         bool          `mapstructure:"enabled"`
	ReportingURL    string        `mapstructure:"reporting_url"` // Google VRP URL
	Timeout         time.Duration `mapstructure:"timeout"`
	AutoSubmit      bool          `mapstructure:"auto_submit"`
	MinimumSeverity string        `mapstructure:"minimum_severity"`
}

// Validate is deprecated - configuration now comes from flags + env vars with defaults set in cmd/root.go
// Kept for backward compatibility but does nothing
func (c *Config) Validate() error {
	return nil
}

// DefaultConfig is deprecated - defaults are now set in cmd/root.go via viper.SetDefault()
// Kept for backward compatibility with tests that may call it directly
func DefaultConfig() *Config {
	return &Config{
		Logger: LoggerConfig{
			Level:       "info",
			Format:      "console",
			OutputPaths: []string{"stdout"},
		},
		Database: DatabaseConfig{
			Driver:          "postgres",
			DSN:             "postgres://shells:shells_password@localhost:5432/shells?sslmode=disable",
			MaxConnections:  25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 1 * time.Hour,
		},
		Redis: RedisConfig{
			Addr:         "localhost:6379",
			DB:           0,
			MaxRetries:   3,
			DialTimeout:  5 * time.Second,
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
		},
		Worker: WorkerConfig{
			Count:             3,
			QueuePollInterval: 5 * time.Second,
			MaxRetries:        3,
			RetryDelay:        10 * time.Second,
		},
		Telemetry: TelemetryConfig{
			Enabled:      true,
			ServiceName:  "shells",
			ExporterType: "otlp",
			Endpoint:     "localhost:4317",
			SampleRate:   1.0,
		},
		Security: SecurityConfig{
			RateLimit: RateLimitConfig{
				RequestsPerSecond: 10,
				BurstSize:         20,
			},
			EnableAuth: false,
		},
		Tools: ToolsConfig{
			Nmap: NmapConfig{
				BinaryPath: "nmap",
				Timeout:    30 * time.Minute,
				Profiles: map[string]string{
					"default":  "-sS -sV -O",
					"fast":     "-T4 -F",
					"thorough": "-sS -sV -sC -O -A",
				},
			},
			SSL: SSLConfig{
				Timeout:         10 * time.Second,
				FollowRedirects: true,
				CheckRevocation: true,
			},
			Nuclei: NucleiConfig{
				BinaryPath:    "nuclei",
				TemplatesPath: "",
				Timeout:       30 * time.Minute,
				RateLimit:     150,
				BulkSize:      25,
				Concurrency:   25,
				Retries:       2,
			},
			HTTPX: HTTPXConfig{
				BinaryPath:      "httpx",
				Timeout:         10 * time.Second,
				Threads:         50,
				RateLimit:       150,
				Retries:         2,
				FollowRedirects: true,
				ProbeAllIPs:     false,
			},
			JavaScript: JSConfig{
				LinkFinderPath:   "linkfinder",
				SecretFinderPath: "secretfinder",
				RetireJSPath:     "retire",
				Timeout:          10 * time.Minute,
			},
			OAuth2: OAuth2ToolConfig{
				DefaultClientID: "",
				Timeout:         15 * time.Minute,
			},
			SCIM: SCIMConfig{
				DiscoveryTimeout:   5 * time.Minute,
				MaxBulkOperations:  10,
				TestAuthentication: true,
				TestFilters:        true,
				TestBulkOps:        true,
				TestProvisions:     true,
				Timeout:            30 * time.Second,
				MaxRetries:         3,
				UserAgent:          "shells-scim-scanner/1.0",
				FollowRedirects:    true,
				VerifySSL:          true,
			},
			Smuggling: SmugglingConfig{
				Techniques:                 []string{"cl.te", "te.cl", "te.te", "http2"},
				DifferentialDelay:          5 * time.Second,
				MaxPayloadSize:             1048576, // 1MB
				Timeout:                    30 * time.Second,
				MaxRetries:                 3,
				UserAgent:                  "shells-smuggling-scanner/1.0",
				FollowRedirects:            false,
				VerifySSL:                  true,
				EnableTimingAnalysis:       true,
				EnableDifferentialAnalysis: true,
			},
			BusinessLogic: BusinessLogicConfig{
				Timeout:         30 * time.Second,
				MaxRetries:      3,
				UserAgent:       "shells-business-logic-scanner/1.0",
				FollowRedirects: true,
				VerifySSL:       true,
				VerboseOutput:   false,
				MaintainSession: true,
				PasswordReset: PasswordResetConfig{
					TestTokenEntropy:  true,
					TestHostHeader:    true,
					TestUserEnum:      true,
					TestRaceCondition: true,
					TokenSamples:      100,
					BruteForceThreads: 50,
					RequestDelay:      100 * time.Millisecond,
					MaxTokenLength:    256,
					MinTokenEntropy:   32.0,
				},
				Workflow: WorkflowConfig{
					MaxDepth:           10,
					MaxStates:          100,
					TestPrivileges:     true,
					TestStateSkipping:  true,
					TestStepReordering: true,
					TestParallelExec:   true,
					TestValueManip:     true,
					TestAuthFlaws:      true,
					TestTimeVulns:      true,
					AnalysisTimeout:    5 * time.Minute,
					StateTimeout:       30 * time.Second,
				},
				RaceCondition: RaceConditionConfig{
					MaxWorkers:         20,
					TestPayments:       true,
					TestInventory:      true,
					TestAuth:           true,
					TestBusinessLogic:  true,
					TestResourceAlloc:  true,
					RequestDelay:       0,
					ConcurrentAttempts: 10,
					DetectionThreshold: 0.8,
				},
				MFABypass: MFABypassConfig{
					TestRememberMe:     true,
					TestBackupCodes:    true,
					TestRecoveryFlow:   true,
					TestSessionUpgrade: true,
					TestRaceCondition:  true,
					TestResponseManip:  true,
					TestTokenReuse:     true,
					TestCookieManip:    true,
					TestAPIEndpoints:   true,
					TestFlowManip:      true,
					SessionTimeout:     15 * time.Minute,
					MaxAttempts:        5,
				},
				AccountRecovery: AccountRecoveryConfig{
					TestAllMethods:      true,
					TestSecQuestions:    true,
					TestSMSRecovery:     true,
					TestEmailRecovery:   true,
					TestBackupCodes:     true,
					TestSocialRecovery:  false,
					TestBiometric:       false,
					TestAdminRecovery:   false,
					TestDeviceRecovery:  false,
					TestMethodChaining:  true,
					TestCrossMethod:     true,
					RecoveryTimeout:     2 * time.Minute,
					MaxRecoveryAttempts: 3,
				},
				Ecommerce: EcommerceConfig{
					TestShoppingCart:    true,
					TestPaymentLogic:    true,
					TestPricingLogic:    true,
					TestCouponLogic:     true,
					TestNegativeValues:  true,
					TestIntegerOverflow: true,
					TestCartManip:       true,
					TestPriceManip:      true,
					TestCurrencyConf:    true,
					TestRaceConditions:  true,
					MaxCartItems:        1000,
					PriceTestValues:     []float64{-1.0, 0.0, 0.01, 999999.99, 2147483647.0},
					CurrencyTestList:    []string{"USD", "EUR", "GBP", "JPY", "CAD", "AUD"},
				},
				Reporting: ReportingConfig{
					GenerateHTML:          true,
					GenerateJSON:          true,
					GeneratePDF:           false,
					GenerateCSV:           false,
					IncludeBusinessImpact: true,
					IncludePoCDetails:     true,
					IncludeCharts:         true,
					IncludeTimeline:       true,
					ReportTimeout:         10 * time.Minute,
					OutputDirectory:       "reports",
					ReportTemplate:        "default",
					MaxReportSize:         100 * 1024 * 1024, // 100MB
				},
			},
			Prowler: ProwlerConfig{
				NomadAddr:    "http://localhost:4646",
				DockerImage:  "toniblyx/prowler:latest",
				OutputFormat: "json",
				ParallelJobs: 5,
				Timeout:      30 * time.Minute,
				AWSProfile:   "",
				CacheDir:     "",
			},
			Favicon: FaviconConfig{
				Timeout:        10 * time.Second,
				UserAgent:      "Mozilla/5.0 (compatible; FaviconScanner/1.0; Bug Bounty Research)",
				CacheDir:       "",
				ShodanAPIKey:   "",
				MaxConcurrency: 10,
				EnableShodan:   false,
				EnableCache:    true,
				CustomDatabase: "",
			},
		},
		Platforms: BugBountyPlatforms{
			HackerOne: HackerOneConfig{
				Enabled:         false,
				BaseURL:         "https://api.hackerone.com/v1",
				Timeout:         30 * time.Second,
				AutoSubmit:      false,
				MinimumSeverity: "medium",
				DraftMode:       true,
			},
			Bugcrowd: BugcrowdConfig{
				Enabled:         false,
				BaseURL:         "https://api.bugcrowd.com",
				Timeout:         30 * time.Second,
				AutoSubmit:      false,
				MinimumSeverity: "P3",
				DraftMode:       true,
			},
			AWS: AWSBountyConfig{
				Enabled:         false,
				ProgramHandle:   "amazonvrp",
				UseHackerOne:    true,
				Timeout:         30 * time.Second,
				AutoSubmit:      false,
				MinimumSeverity: "medium",
			},
			Azure: AzureBountyConfig{
				Enabled:         false,
				ReportingEmail:  "secure@microsoft.com",
				ProgramType:     "azure",
				Timeout:         30 * time.Second,
				AutoSubmit:      false,
				MinimumSeverity: "Important",
			},
			GCP: GCPBountyConfig{
				Enabled:         false,
				ReportingURL:    "https://www.google.com/about/appsecurity/",
				Timeout:         30 * time.Second,
				AutoSubmit:      false,
				MinimumSeverity: "medium",
			},
		},
	}
}
