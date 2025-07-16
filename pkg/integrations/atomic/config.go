package atomic

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultConfig provides safe defaults for bug bounty testing
var DefaultConfig = Config{
	AtomicsPath:       getDefaultAtomicsPath(),
	SafetyMode:        true,  // Always enabled for bug bounties
	DryRun:            false,
	Timeout:           30 * time.Second,
	SandboxMode:       true,  // Recommended for safety
	DockerImage:       "atomicredteam/atomic-red-team-execution:latest",
	MemoryLimit:       "512m",
	CPULimit:          "0.5",
	AllowedTechniques: BugBountySafeTechniques,
}

// LoadConfig loads atomic configuration from file
func LoadConfig(configPath string) (*Config, error) {
	config := DefaultConfig

	if configPath == "" {
		return &config, nil
	}

	// Check if config file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return &config, nil // Return defaults if no config file
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var configData struct {
		Atomic Config `yaml:"atomic"`
	}

	if err := yaml.Unmarshal(data, &configData); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %v", err)
	}

	// Merge with defaults
	mergedConfig := mergeConfigs(config, configData.Atomic)
	
	// Validate safety constraints
	if err := validateConfig(&mergedConfig); err != nil {
		return nil, fmt.Errorf("config validation failed: %v", err)
	}

	return &mergedConfig, nil
}

// SaveConfig saves configuration to file
func SaveConfig(config Config, configPath string) error {
	configData := struct {
		Atomic Config `yaml:"atomic"`
	}{
		Atomic: config,
	}

	data, err := yaml.Marshal(configData)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	// Ensure directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	return os.WriteFile(configPath, data, 0644)
}

// mergeConfigs merges user config with defaults
func mergeConfigs(defaultConfig, userConfig Config) Config {
	merged := defaultConfig

	// Override non-zero values from user config
	if userConfig.AtomicsPath != "" {
		merged.AtomicsPath = userConfig.AtomicsPath
	}
	
	// Safety mode cannot be disabled for bug bounties
	merged.SafetyMode = true
	
	if userConfig.Timeout > 0 {
		merged.Timeout = userConfig.Timeout
	}
	
	// Allow dry run to be configured
	merged.DryRun = userConfig.DryRun
	
	// Sandbox mode can be configured but recommended
	merged.SandboxMode = userConfig.SandboxMode
	
	if userConfig.DockerImage != "" {
		merged.DockerImage = userConfig.DockerImage
	}
	
	if userConfig.MemoryLimit != "" {
		merged.MemoryLimit = userConfig.MemoryLimit
	}
	
	if userConfig.CPULimit != "" {
		merged.CPULimit = userConfig.CPULimit
	}
	
	// Merge allowed techniques (intersection with safe techniques)
	if len(userConfig.AllowedTechniques) > 0 {
		merged.AllowedTechniques = intersectTechniques(userConfig.AllowedTechniques, BugBountySafeTechniques)
	}

	return merged
}

// validateConfig ensures configuration meets safety requirements
func validateConfig(config *Config) error {
	// Safety mode must always be enabled
	if !config.SafetyMode {
		return fmt.Errorf("safety mode cannot be disabled for bug bounty testing")
	}

	// Validate timeout constraints
	if config.Timeout > 5*time.Minute {
		return fmt.Errorf("timeout cannot exceed 5 minutes for safety")
	}

	if config.Timeout < 1*time.Second {
		return fmt.Errorf("timeout cannot be less than 1 second")
	}

	// Validate atomics path
	if config.AtomicsPath != "" {
		if _, err := os.Stat(config.AtomicsPath); os.IsNotExist(err) {
			return fmt.Errorf("atomics path does not exist: %s", config.AtomicsPath)
		}
	}

	// Validate allowed techniques are subset of safe techniques
	for _, technique := range config.AllowedTechniques {
		if !isTechniqueSafe(technique) {
			return fmt.Errorf("technique %s is not approved for bug bounty testing", technique)
		}
	}

	// Validate Docker constraints
	if config.SandboxMode {
		if err := validateDockerConfig(config); err != nil {
			return fmt.Errorf("docker configuration invalid: %v", err)
		}
	}

	return nil
}

// validateDockerConfig validates Docker-related configuration
func validateDockerConfig(config *Config) error {
	// Validate memory limit format
	if config.MemoryLimit != "" {
		if !isValidMemoryLimit(config.MemoryLimit) {
			return fmt.Errorf("invalid memory limit format: %s", config.MemoryLimit)
		}
	}

	// Validate CPU limit format
	if config.CPULimit != "" {
		if !isValidCPULimit(config.CPULimit) {
			return fmt.Errorf("invalid CPU limit format: %s", config.CPULimit)
		}
	}

	return nil
}

// Helper functions

func getDefaultAtomicsPath() string {
	// Try common locations for Atomic Red Team
	possiblePaths := []string{
		filepath.Join(os.Getenv("HOME"), ".atomic-red-team", "atomics"),
		filepath.Join(".", "atomics"),
		"/opt/atomic-red-team/atomics",
		"./atomic-red-team/atomics",
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Return default path even if it doesn't exist
	return filepath.Join(os.Getenv("HOME"), ".atomic-red-team", "atomics")
}

func intersectTechniques(userTechniques, safeTechniques []string) []string {
	safeMap := make(map[string]bool)
	for _, technique := range safeTechniques {
		safeMap[technique] = true
	}

	var intersection []string
	for _, technique := range userTechniques {
		if safeMap[technique] {
			intersection = append(intersection, technique)
		}
	}

	return intersection
}

func isTechniqueSafe(technique string) bool {
	for _, safeTechnique := range BugBountySafeTechniques {
		if technique == safeTechnique {
			return true
		}
	}
	return false
}

func isValidMemoryLimit(limit string) bool {
	// Simple validation for Docker memory limits (e.g., "512m", "1g")
	if len(limit) < 2 {
		return false
	}
	
	unit := limit[len(limit)-1:]
	return unit == "m" || unit == "g" || unit == "k"
}

func isValidCPULimit(limit string) bool {
	// Simple validation for Docker CPU limits (e.g., "0.5", "1.0", "2")
	if limit == "" {
		return false
	}
	
	// Should be a valid float
	_, err := fmt.Sscanf(limit, "%f", new(float64))
	return err == nil
}

// ConfigValidator provides configuration validation utilities
type ConfigValidator struct {
	strictMode bool
}

// NewConfigValidator creates a new configuration validator
func NewConfigValidator(strictMode bool) *ConfigValidator {
	return &ConfigValidator{
		strictMode: strictMode,
	}
}

// ValidateForBugBounty validates configuration specifically for bug bounty testing
func (v *ConfigValidator) ValidateForBugBounty(config *Config) []string {
	var warnings []string

	// Check safety settings
	if !config.SafetyMode {
		warnings = append(warnings, "Safety mode should always be enabled for bug bounty testing")
	}

	if !config.SandboxMode {
		warnings = append(warnings, "Sandbox mode is recommended for bug bounty testing")
	}

	if !config.DryRun && v.strictMode {
		warnings = append(warnings, "Consider using dry-run mode for initial testing")
	}

	// Check timeout settings
	if config.Timeout > 60*time.Second {
		warnings = append(warnings, "Long timeouts may indicate potentially disruptive tests")
	}

	// Check technique allowlist
	if len(config.AllowedTechniques) > len(BugBountySafeTechniques)/2 {
		warnings = append(warnings, "Large number of allowed techniques - consider being more selective")
	}

	// Check Docker configuration
	if config.SandboxMode {
		if config.MemoryLimit == "" {
			warnings = append(warnings, "Memory limit not set for Docker sandbox")
		}
		if config.CPULimit == "" {
			warnings = append(warnings, "CPU limit not set for Docker sandbox")
		}
	}

	return warnings
}

// GenerateExampleConfig generates an example configuration file
func GenerateExampleConfig() string {
	example := `# Atomic Red Team Configuration for Bug Bounty Testing
atomic:
  # Path to Atomic Red Team atomics directory
  atomics_path: "~/.atomic-red-team/atomics"
  
  # Safety mode (always true for bug bounties)
  safety_mode: true
  
  # Dry run mode (show what would be executed)
  dry_run: false
  
  # Execution timeout
  timeout: "30s"
  
  # Docker sandbox mode (recommended)
  sandbox: true
  
  # Docker configuration
  docker_image: "atomicredteam/atomic-red-team-execution:latest"
  memory_limit: "512m"
  cpu_limit: "0.5"
  
  # Allowed techniques (subset of safe techniques)
  allowed_techniques:
    - "T1087"    # Account Discovery
    - "T1083"    # File and Directory Discovery
    - "T1057"    # Process Discovery
    - "T1552"    # Unsecured Credentials
    - "T1530"    # Data from Cloud Storage Object
    - "T1190"    # Exploit Public-Facing Application
    - "T1078"    # Valid Accounts

# Example usage:
# shells atomic demo --vuln-type SSRF --target https://example.com --dry-run
# shells atomic list --vuln-type PUBLIC_S3_BUCKET
# shells atomic report --findings findings.json --output report.html
`
	return example
}

// ConfigManager provides high-level configuration management
type ConfigManager struct {
	configPath string
	validator  *ConfigValidator
}

// NewConfigManager creates a new configuration manager
func NewConfigManager(configPath string) *ConfigManager {
	return &ConfigManager{
		configPath: configPath,
		validator:  NewConfigValidator(true),
	}
}

// LoadOrCreate loads existing config or creates default
func (m *ConfigManager) LoadOrCreate() (*Config, error) {
	config, err := LoadConfig(m.configPath)
	if err != nil {
		return nil, err
	}

	// Validate for bug bounty usage
	warnings := m.validator.ValidateForBugBounty(config)
	if len(warnings) > 0 {
		fmt.Printf("⚠️  Configuration warnings:\n")
		for _, warning := range warnings {
			fmt.Printf("   - %s\n", warning)
		}
		fmt.Println()
	}

	return config, nil
}

// Save saves configuration to file
func (m *ConfigManager) Save(config Config) error {
	return SaveConfig(config, m.configPath)
}

// Reset resets configuration to safe defaults
func (m *ConfigManager) Reset() error {
	return m.Save(DefaultConfig)
}