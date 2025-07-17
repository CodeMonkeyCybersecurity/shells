package recovery

import (
	"time"
)

// Config holds configuration for recovery testing
type Config struct {
	TokenSamples      int
	TestHostHeader    bool
	TestTokenEntropy  bool
	BruteForceThreads int
	RequestDelay      time.Duration
	Timeout           time.Duration
}

// DefaultConfig returns default configuration
func DefaultConfig() *Config {
	return &Config{
		TokenSamples:      100,
		TestHostHeader:    true,
		TestTokenEntropy:  true,
		BruteForceThreads: 50,
		RequestDelay:      100 * time.Millisecond,
		Timeout:           30 * time.Second,
	}
}

// Email represents an intercepted email
type Email struct {
	To      string
	From    string
	Subject string
	Body    string
	Headers map[string]string
}

// TokenAnalysis contains token analysis results
type TokenAnalysis struct {
	Entropy       float64
	IsPredictable bool
	Pattern       string
	NextPredicted string
	CommonPrefix  string
	CommonSuffix  string
}