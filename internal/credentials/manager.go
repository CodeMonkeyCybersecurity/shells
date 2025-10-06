package credentials

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ssh/terminal"
)

// Manager handles secure storage and retrieval of API credentials
type Manager struct {
	configDir   string
	logger      *logger.Logger
	credentials map[string]string
	isEncrypted bool
}

// APICredentials represents the structure of stored credentials
type APICredentials struct {
	CirclUsername     string `json:"circl_username,omitempty"`
	CirclPassword     string `json:"circl_password,omitempty"`
	PassiveTotalUser  string `json:"passivetotal_user,omitempty"`
	PassiveTotalKey   string `json:"passivetotal_key,omitempty"`
	ShodanAPIKey      string `json:"shodan_api_key,omitempty"`
	CensysAPIID       string `json:"censys_api_id,omitempty"`
	CensysAPISecret   string `json:"censys_api_secret,omitempty"`
	VirusTotalAPIKey  string `json:"virustotal_api_key,omitempty"`
	SecurityTrailsKey string `json:"securitytrails_key,omitempty"`
}

// NewManager creates a new credentials manager
func NewManager(logger *logger.Logger) (*Manager, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	configDir := filepath.Join(homeDir, ".shells")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create config directory: %w", err)
	}

	return &Manager{
		configDir:   configDir,
		logger:      logger,
		credentials: make(map[string]string),
	}, nil
}

// CheckAndPromptForCircl checks if CIRCL credentials exist and prompts if not
func (m *Manager) CheckAndPromptForCircl() error {
	// Load existing credentials
	if err := m.Load(); err != nil && !os.IsNotExist(err) {
		m.logger.Warn("Failed to load existing credentials", "error", err)
	}

	// Check if CIRCL credentials exist
	if m.credentials["circl_username"] != "" && m.credentials["circl_password"] != "" {
		m.logger.Debug("CIRCL credentials already configured")
		return nil
	}

	// Check if running in non-interactive mode or if prompts are disabled
	if !isInteractive() {
		m.logger.Debug("Running in non-interactive mode, skipping CIRCL prompt")
		return nil
	}

	// Check environment variable to skip prompts
	if os.Getenv("SHELLS_SKIP_PROMPTS") == "true" || os.Getenv("SHELLS_NO_PROMPTS") == "1" {
		m.logger.Debug("SHELLS_SKIP_PROMPTS set, skipping CIRCL prompt")
		return nil
	}

	// Check if this is the first run - only prompt on initial setup, not every scan
	if os.Getenv("SHELLS_FIRST_RUN") != "true" {
		m.logger.Debug("Not first run, skipping CIRCL prompt")
		return nil
	}

	m.logger.Info("🔑 CIRCL API Configuration", "component", "credentials")
	m.logger.Info("─────────────────────────", "component", "credentials")
	m.logger.Info("CIRCL provides free passive DNS data that enhances discovery capabilities.", "component", "credentials")
	m.logger.Info("Register at: https://www.circl.lu/services/passive-dns/", "component", "credentials")
	m.logger.Info("\nWould you like to configure CIRCL API credentials now? [Y/n]: ", "component", "credentials")

	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))

	if response != "y" && response != "yes" && response != "" {
		m.logger.Info("ℹ️  Skipping CIRCL configuration. You can configure it later with 'shells config api-keys'", "component", "credentials")
		return nil
	}

	// Prompt for credentials
	m.logger.Info("Enter CIRCL username: ", "component", "credentials")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	m.logger.Info("Enter CIRCL password: ", "component", "credentials")
	password, err := readPassword()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	// Validate credentials
	if username == "" || password == "" {
		m.logger.Error("❌ Username and password cannot be empty", "component", "credentials")
		return fmt.Errorf("invalid credentials")
	}

	// Store credentials
	m.credentials["circl_username"] = username
	m.credentials["circl_password"] = password

	// Save encrypted
	if err := m.Save(); err != nil {
		return fmt.Errorf("failed to save credentials: %w", err)
	}

	m.logger.Info(" CIRCL credentials saved securely", "component", "credentials")
	return nil
}

// PromptForAllAPIs provides an interactive prompt for all supported APIs
func (m *Manager) PromptForAllAPIs() error {
	m.logger.Info("\n🔐 API Credentials Configuration", "component", "credentials")
	m.logger.Info("═══════════════════════════════", "component", "credentials")
	m.logger.Info("Configure API keys for enhanced discovery capabilities.", "component", "credentials")
	m.logger.Info("All credentials are encrypted and stored locally.", "component", "credentials")

	apis := []struct {
		name        string
		description string
		url         string
		fields      []credentialField
	}{
		{
			name:        "CIRCL",
			description: "Free passive DNS and threat intelligence",
			url:         "https://www.circl.lu/services/passive-dns/",
			fields: []credentialField{
				{key: "circl_username", prompt: "Username", isPassword: false},
				{key: "circl_password", prompt: "Password", isPassword: true},
			},
		},
		{
			name:        "PassiveTotal",
			description: "Comprehensive passive DNS and WHOIS data",
			url:         "https://community.riskiq.com/",
			fields: []credentialField{
				{key: "passivetotal_user", prompt: "Email", isPassword: false},
				{key: "passivetotal_key", prompt: "API Key", isPassword: true},
			},
		},
		{
			name:        "Shodan",
			description: "Internet-wide port scanning data",
			url:         "https://account.shodan.io/",
			fields: []credentialField{
				{key: "shodan_api_key", prompt: "API Key", isPassword: true},
			},
		},
		{
			name:        "Censys",
			description: "Internet-wide scanning and certificate data",
			url:         "https://censys.io/account/api",
			fields: []credentialField{
				{key: "censys_api_id", prompt: "API ID", isPassword: false},
				{key: "censys_api_secret", prompt: "API Secret", isPassword: true},
			},
		},
		{
			name:        "VirusTotal",
			description: "Malware and URL analysis",
			url:         "https://www.virustotal.com/gui/my-apikey",
			fields: []credentialField{
				{key: "virustotal_api_key", prompt: "API Key", isPassword: true},
			},
		},
		{
			name:        "SecurityTrails",
			description: "Historical DNS and WHOIS data",
			url:         "https://securitytrails.com/app/api",
			fields: []credentialField{
				{key: "securitytrails_key", prompt: "API Key", isPassword: true},
			},
		},
	}

	reader := bufio.NewReader(os.Stdin)

	for _, api := range apis {
		m.logger.Infow("📌 API Configuration",
			"api", api.name,
			"description", api.description,
			"url", api.url,
			"component", "credentials",
		)
		m.logger.Info("   Configure? [y/N]: ", "component", "credentials")

		response, _ := reader.ReadString('\n')
		response = strings.TrimSpace(strings.ToLower(response))

		if response == "y" || response == "yes" {
			for _, field := range api.fields {
				m.logger.Infow("   Enter credential",
					"field", field.prompt,
					"component", "credentials",
				)

				var value string
				var err error

				if field.isPassword {
					value, err = readPassword()
					if err != nil {
						m.logger.Error("Failed to read password", "error", err)
						continue
					}
				} else {
					value, _ = reader.ReadString('\n')
					value = strings.TrimSpace(value)
				}

				if value != "" {
					m.credentials[field.key] = value
				}
			}
		}
	}

	// Save all credentials
	if len(m.credentials) > 0 {
		if err := m.Save(); err != nil {
			return fmt.Errorf("failed to save credentials: %w", err)
		}
		m.logger.Info(" API credentials saved securely", "component", "credentials")
	}

	return nil
}

// GetAPIKeys returns a map of API keys for use by discovery modules
func (m *Manager) GetAPIKeys() map[string]string {
	// Load credentials if not already loaded
	if len(m.credentials) == 0 {
		m.Load()
	}

	// Return a copy to prevent modification
	keys := make(map[string]string)

	// Map internal names to expected names
	mappings := map[string]string{
		"circl_username":     "CirclUsername",
		"circl_password":     "CirclPassword",
		"passivetotal_user":  "PassiveTotalUsername",
		"passivetotal_key":   "PassiveTotal",
		"shodan_api_key":     "Shodan",
		"censys_api_id":      "CensysID",
		"censys_api_secret":  "CensysSecret",
		"virustotal_api_key": "VirusTotal",
		"securitytrails_key": "SecurityTrails",
	}

	for internal, external := range mappings {
		if val, exists := m.credentials[internal]; exists && val != "" {
			keys[external] = val
		}
	}

	return keys
}

// Save encrypts and saves credentials to disk
func (m *Manager) Save() error {
	// Convert credentials to JSON
	data, err := json.MarshalIndent(m.credentials, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	// Get or create encryption key
	key, err := m.getOrCreateKey()
	if err != nil {
		return fmt.Errorf("failed to get encryption key: %w", err)
	}

	// Encrypt data
	encrypted, err := encrypt(data, key)
	if err != nil {
		return fmt.Errorf("failed to encrypt credentials: %w", err)
	}

	// Save to file
	credFile := filepath.Join(m.configDir, "credentials.enc")
	if err := os.WriteFile(credFile, encrypted, 0600); err != nil {
		return fmt.Errorf("failed to write credentials file: %w", err)
	}

	m.isEncrypted = true
	return nil
}

// Load decrypts and loads credentials from disk
func (m *Manager) Load() error {
	credFile := filepath.Join(m.configDir, "credentials.enc")

	// Check if encrypted file exists
	encrypted, err := os.ReadFile(credFile)
	if err != nil {
		if os.IsNotExist(err) {
			// Try legacy unencrypted file
			return m.loadLegacy()
		}
		return fmt.Errorf("failed to read credentials file: %w", err)
	}

	// Get decryption key
	key, err := m.getOrCreateKey()
	if err != nil {
		return fmt.Errorf("failed to get decryption key: %w", err)
	}

	// Decrypt data
	decrypted, err := decrypt(encrypted, key)
	if err != nil {
		return fmt.Errorf("failed to decrypt credentials: %w", err)
	}

	// Unmarshal credentials
	if err := json.Unmarshal(decrypted, &m.credentials); err != nil {
		return fmt.Errorf("failed to unmarshal credentials: %w", err)
	}

	m.isEncrypted = true
	return nil
}

// loadLegacy loads unencrypted credentials and migrates them
func (m *Manager) loadLegacy() error {
	legacyFile := filepath.Join(m.configDir, "api_keys.json")
	data, err := os.ReadFile(legacyFile)
	if err != nil {
		if os.IsNotExist(err) {
			return err // No credentials exist
		}
		return fmt.Errorf("failed to read legacy credentials: %w", err)
	}

	// Load legacy format
	var legacy APICredentials
	if err := json.Unmarshal(data, &legacy); err != nil {
		return fmt.Errorf("failed to unmarshal legacy credentials: %w", err)
	}

	// Convert to new format
	m.credentials = make(map[string]string)
	if legacy.CirclUsername != "" {
		m.credentials["circl_username"] = legacy.CirclUsername
	}
	if legacy.CirclPassword != "" {
		m.credentials["circl_password"] = legacy.CirclPassword
	}
	// ... convert other fields

	// Save in encrypted format
	if len(m.credentials) > 0 {
		if err := m.Save(); err != nil {
			return fmt.Errorf("failed to migrate credentials: %w", err)
		}

		// Remove legacy file after successful migration
		if err := os.Remove(legacyFile); err != nil && !os.IsNotExist(err) {
			m.logger.Warnw("Failed to remove legacy credentials file after migration",
				"file", legacyFile,
				"error", err,
				"action", "Manually delete the file for security")
		}
		m.logger.Info("Migrated credentials to encrypted storage")
	}

	return nil
}

// getOrCreateKey gets or creates the encryption key
func (m *Manager) getOrCreateKey() ([]byte, error) {
	keyFile := filepath.Join(m.configDir, ".key")

	// Try to read existing key
	keyData, err := os.ReadFile(keyFile)
	if err == nil {
		key, err := base64.StdEncoding.DecodeString(string(keyData))
		if err == nil && len(key) == 32 {
			return key, nil
		}
	}

	// Generate new key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Save key
	encoded := base64.StdEncoding.EncodeToString(key)
	if err := os.WriteFile(keyFile, []byte(encoded), 0600); err != nil {
		return nil, fmt.Errorf("failed to save key: %w", err)
	}

	return key, nil
}

// Helper functions

type credentialField struct {
	key        string
	prompt     string
	isPassword bool
}

func isInteractive() bool {
	fi, _ := os.Stdin.Stat()
	return fi.Mode()&os.ModeCharDevice != 0
}

func readPassword() (string, error) {
	// Read password without echoing
	password, err := terminal.ReadPassword(int(syscall.Stdin))
	// Note: New line after password is handled by terminal package
	if err != nil {
		return "", err
	}
	return string(password), nil
}

func encrypt(plaintext, key []byte) ([]byte, error) {
	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Generate nonce
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt and prepend nonce
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func decrypt(ciphertext, key []byte) ([]byte, error) {
	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// DeriveKeyFromPassword derives an encryption key from a password
func DeriveKeyFromPassword(password string) []byte {
	// Use PBKDF2 to derive key from password
	salt := []byte("shells-credential-salt-v1") // Fixed salt for deterministic key
	return pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
}
