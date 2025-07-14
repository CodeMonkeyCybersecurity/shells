package config

import (
	"time"
)

type Config struct {
	Logger    LoggerConfig    `mapstructure:"logger"`
	Database  DatabaseConfig  `mapstructure:"database"`
	Redis     RedisConfig     `mapstructure:"redis"`
	Worker    WorkerConfig    `mapstructure:"worker"`
	Telemetry TelemetryConfig `mapstructure:"telemetry"`
	Security  SecurityConfig  `mapstructure:"security"`
	Tools     ToolsConfig     `mapstructure:"tools"`
}

type LoggerConfig struct {
	Level       string `mapstructure:"level"`
	Format      string `mapstructure:"format"`
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
	Enabled      bool   `mapstructure:"enabled"`
	ServiceName  string `mapstructure:"service_name"`
	ExporterType string `mapstructure:"exporter_type"`
	Endpoint     string `mapstructure:"endpoint"`
	SampleRate   float64 `mapstructure:"sample_rate"`
}

type SecurityConfig struct {
	RateLimit    RateLimitConfig `mapstructure:"rate_limit"`
	ScopeFile    string          `mapstructure:"scope_file"`
	APIKey       string          `mapstructure:"api_key"`
	EnableAuth   bool            `mapstructure:"enable_auth"`
}

type RateLimitConfig struct {
	RequestsPerSecond int `mapstructure:"requests_per_second"`
	BurstSize         int `mapstructure:"burst_size"`
}

type ToolsConfig struct {
	Nmap       NmapConfig       `mapstructure:"nmap"`
	SSL        SSLConfig        `mapstructure:"ssl"`
	ZAP        ZAPConfig        `mapstructure:"zap"`
	OpenVAS    OpenVASConfig    `mapstructure:"openvas"`
	Nikto      NiktoConfig      `mapstructure:"nikto"`
	Nuclei     NucleiConfig     `mapstructure:"nuclei"`
	HTTPX      HTTPXConfig      `mapstructure:"httpx"`
	JavaScript JSConfig         `mapstructure:"javascript"`
	OAuth2     OAuth2ToolConfig `mapstructure:"oauth2"`
}

type NmapConfig struct {
	BinaryPath string            `mapstructure:"binary_path"`
	Timeout    time.Duration     `mapstructure:"timeout"`
	Profiles   map[string]string `mapstructure:"profiles"`
}

type SSLConfig struct {
	Timeout          time.Duration `mapstructure:"timeout"`
	FollowRedirects  bool          `mapstructure:"follow_redirects"`
	CheckRevocation  bool          `mapstructure:"check_revocation"`
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

func (c *Config) Validate() error {
	if c.Logger.Level == "" {
		c.Logger.Level = "info"
	}
	
	if c.Logger.Format == "" {
		c.Logger.Format = "json"
	}
	
	if c.Database.Driver == "" {
		c.Database.Driver = "sqlite3"
	}
	
	if c.Redis.Addr == "" {
		c.Redis.Addr = "localhost:6379"
	}
	
	if c.Worker.Count < 1 {
		c.Worker.Count = 1
	}
	
	if c.Worker.QueuePollInterval == 0 {
		c.Worker.QueuePollInterval = 5 * time.Second
	}
	
	if c.Security.RateLimit.RequestsPerSecond == 0 {
		c.Security.RateLimit.RequestsPerSecond = 10
	}
	
	if c.Telemetry.ServiceName == "" {
		c.Telemetry.ServiceName = "shells"
	}
	
	return nil
}

func DefaultConfig() *Config {
	return &Config{
		Logger: LoggerConfig{
			Level:  "info",
			Format: "json",
			OutputPaths: []string{"stdout"},
		},
		Database: DatabaseConfig{
			Driver:          "sqlite3",
			DSN:             "shells.db",
			MaxConnections:  10,
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
		},
	}
}