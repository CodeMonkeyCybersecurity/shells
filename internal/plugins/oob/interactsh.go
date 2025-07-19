package oob

import (
	"context"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/core"
	"github.com/CodeMonkeyCybersecurity/shells/pkg/types"
)

// OOBConfig represents configuration for out-of-band testing
type OOBConfig struct {
	PollDuration         time.Duration
	CollaboratorDuration time.Duration
}

// interactshScanner is a stub implementation (disabled due to dependency issues)
type interactshScanner struct {
	config OOBConfig
	logger interface {
		Info(msg string, keysAndValues ...interface{})
		Error(msg string, keysAndValues ...interface{})
		Debug(msg string, keysAndValues ...interface{})
	}
}

// NewInteractshScanner creates a new OOB scanner (stub implementation)
func NewInteractshScanner(config OOBConfig, logger interface {
	Info(msg string, keysAndValues ...interface{})
	Error(msg string, keysAndValues ...interface{})
	Debug(msg string, keysAndValues ...interface{})
}) (core.Scanner, error) {
	return &interactshScanner{
		config: config,
		logger: logger,
	}, nil
}

func (s *interactshScanner) Name() string {
	return "interactsh"
}

func (s *interactshScanner) Type() types.ScanType {
	return types.ScanType("oob")
}

func (s *interactshScanner) Validate(target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}
	return nil
}

func (s *interactshScanner) Scan(ctx context.Context, target string, options map[string]string) ([]types.Finding, error) {
	s.logger.Info("OOB scanner is currently disabled due to dependency issues")
	return []types.Finding{}, fmt.Errorf("OOB scanner is temporarily disabled")
}
