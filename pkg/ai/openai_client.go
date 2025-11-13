// pkg/ai/openai_client.go
//
// OpenAI/Azure OpenAI Client for AI-powered report generation
//
// IMPLEMENTATION OVERVIEW:
// This package provides AI-powered vulnerability report generation using OpenAI or Azure OpenAI.
// It integrates with the Artemis orchestrator pipeline to automatically generate professional
// bug bounty reports from discovered vulnerabilities.
//
// FEATURES:
// - Dual provider support (OpenAI and Azure OpenAI)
// - Multiple report formats (bug bounty, markdown, HTML, JSON, MSRC email)
// - Platform-specific formatting (HackerOne, Bugcrowd, Azure MSRC, AWS VRP)
// - Cost tracking and budget controls
// - Batch report generation for multiple platforms
// - Structured JSON completions for programmatic use
//
// INTEGRATION POINTS:
// - internal/orchestrator/phase_reporting.go: Calls generateAIReportsIfEnabled()
// - internal/config/config.go: AIConfig with provider, API keys, model settings
// - pkg/email/smtp_sender.go: SMTP integration for Azure MSRC email submissions
// - pkg/platforms/azure/client.go: Uses AI reports + SMTP for automatic Azure submission
//
// CONFIGURATION:
// Enable AI reports in config:
//   ai:
//     enabled: true
//     provider: "openai"  # or "azure"
//     api_key: "sk-..."   # OpenAI API key (or set via OPENAI_API_KEY env var)
//     model: "gpt-4-turbo"
//     max_tokens: 4000
//     temperature: 0.7
//     max_cost_per_report: 1.0
//     enable_cost_tracking: true
//
// For Azure OpenAI:
//   ai:
//     provider: "azure"
//     azure_endpoint: "https://your-resource.openai.azure.com/"
//     azure_api_key: "..."
//     azure_deployment: "gpt-4"
//     azure_api_version: "2024-02-15-preview"
//
// USAGE:
//   cfg := ai.Config{Provider: "openai", APIKey: "sk-...", Model: "gpt-4-turbo"}
//   client, err := ai.NewClient(cfg, logger)
//   generator := ai.NewReportGenerator(client, logger)
//   report, err := generator.GenerateReport(ctx, ai.ReportRequest{
//       Findings: findings,
//       Target: "example.com",
//       Format: ai.FormatBugBounty,
//       Platform: "hackerone",
//   })
//
// SECURITY NOTE: API keys should be set via environment variables or secure config only
// COST NOTE: GPT-4 API calls cost money - use wisely and enable cost tracking
// INTEGRATION NOTE: Pipeline.aiClient field must be initialized in orchestrator constructor

package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
	"github.com/sashabaranov/go-openai"
)

// Client provides AI-powered report generation capabilities
type Client struct {
	client  *openai.Client
	logger  *logger.Logger
	config  Config
	enabled bool
}

// Config contains OpenAI/Azure OpenAI configuration
type Config struct {
	// Provider: "openai" or "azure"
	Provider string

	// For OpenAI
	APIKey string
	Model  string // e.g., "gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"

	// For Azure OpenAI
	AzureEndpoint    string
	AzureAPIKey      string
	AzureDeployment  string
	AzureAPIVersion  string

	// Generation settings
	MaxTokens        int
	Temperature      float32
	EnableStreaming  bool
	Timeout          time.Duration

	// Cost controls
	MaxCostPerReport float64 // Maximum cost in USD per report
	EnableCostTracking bool
}

// NewClient creates a new AI client
func NewClient(cfg Config, logger *logger.Logger) (*Client, error) {
	if cfg.APIKey == "" && cfg.AzureAPIKey == "" {
		return &Client{
			enabled: false,
			logger:  logger,
			config:  cfg,
		}, nil
	}

	var client *openai.Client

	switch cfg.Provider {
	case "azure":
		if cfg.AzureEndpoint == "" || cfg.AzureAPIKey == "" {
			return nil, fmt.Errorf("azure endpoint and API key required for Azure OpenAI")
		}

		config := openai.DefaultAzureConfig(cfg.AzureAPIKey, cfg.AzureEndpoint)
		config.AzureModelMapperFunc = func(model string) string {
			return cfg.AzureDeployment
		}
		if cfg.AzureAPIVersion != "" {
			config.APIVersion = cfg.AzureAPIVersion
		}
		client = openai.NewClientWithConfig(config)

	case "openai":
		fallthrough
	default:
		if cfg.APIKey == "" {
			return nil, fmt.Errorf("API key required for OpenAI")
		}
		client = openai.NewClient(cfg.APIKey)
	}

	// Set defaults
	if cfg.Model == "" {
		cfg.Model = "gpt-4-turbo"
	}
	if cfg.MaxTokens == 0 {
		cfg.MaxTokens = 4000
	}
	if cfg.Temperature == 0 {
		cfg.Temperature = 0.7
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second
	}

	logger.Infow("AI client initialized",
		"provider", cfg.Provider,
		"model", cfg.Model,
		"max_tokens", cfg.MaxTokens,
	)

	return &Client{
		client:  client,
		logger:  logger,
		config:  cfg,
		enabled: true,
	}, nil
}

// IsEnabled returns whether the AI client is enabled
func (c *Client) IsEnabled() bool {
	return c.enabled
}

// GenerateCompletion generates a completion from a prompt
func (c *Client) GenerateCompletion(ctx context.Context, prompt string) (string, error) {
	if !c.enabled {
		return "", fmt.Errorf("AI client not enabled - configure API keys")
	}

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	c.logger.Debugw("Generating AI completion",
		"model", c.config.Model,
		"max_tokens", c.config.MaxTokens,
		"prompt_length", len(prompt),
	)

	start := time.Now()

	req := openai.ChatCompletionRequest{
		Model:       c.config.Model,
		MaxTokens:   c.config.MaxTokens,
		Temperature: c.config.Temperature,
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleSystem,
				Content: "You are a professional security researcher writing bug bounty reports. Generate clear, actionable, evidence-based vulnerability reports.",
			},
			{
				Role:    openai.ChatMessageRoleUser,
				Content: prompt,
			},
		},
	}

	resp, err := c.client.CreateChatCompletion(ctx, req)
	if err != nil {
		c.logger.Errorw("AI completion failed",
			"error", err,
			"model", c.config.Model,
		)
		return "", fmt.Errorf("AI completion failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("no completion choices returned")
	}

	content := resp.Choices[0].Message.Content
	duration := time.Since(start)

	// Log usage for cost tracking
	c.logger.Infow("AI completion generated",
		"model", c.config.Model,
		"prompt_tokens", resp.Usage.PromptTokens,
		"completion_tokens", resp.Usage.CompletionTokens,
		"total_tokens", resp.Usage.TotalTokens,
		"duration_seconds", duration.Seconds(),
		"response_length", len(content),
	)

	// Estimate cost (approximate - actual pricing varies)
	estimatedCost := c.estimateCost(resp.Usage)
	if c.config.EnableCostTracking && estimatedCost > c.config.MaxCostPerReport {
		c.logger.Warnw("Report generation exceeded cost limit",
			"estimated_cost_usd", estimatedCost,
			"max_cost_usd", c.config.MaxCostPerReport,
		)
	}

	return content, nil
}

// GenerateStructuredCompletion generates a JSON-structured completion
func (c *Client) GenerateStructuredCompletion(ctx context.Context, prompt string, responseFormat interface{}) error {
	if !c.enabled {
		return fmt.Errorf("AI client not enabled - configure API keys")
	}

	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()

	req := openai.ChatCompletionRequest{
		Model:       c.config.Model,
		MaxTokens:   c.config.MaxTokens,
		Temperature: c.config.Temperature,
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleSystem,
				Content: "You are a professional security researcher. Generate responses in valid JSON format only.",
			},
			{
				Role:    openai.ChatMessageRoleUser,
				Content: prompt,
			},
		},
		ResponseFormat: &openai.ChatCompletionResponseFormat{
			Type: openai.ChatCompletionResponseFormatTypeJSONObject,
		},
	}

	resp, err := c.client.CreateChatCompletion(ctx, req)
	if err != nil {
		return fmt.Errorf("AI completion failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return fmt.Errorf("no completion choices returned")
	}

	content := resp.Choices[0].Message.Content

	// Parse JSON response
	if err := json.Unmarshal([]byte(content), responseFormat); err != nil {
		c.logger.Errorw("Failed to parse AI JSON response",
			"error", err,
			"content", content,
		)
		return fmt.Errorf("failed to parse AI response: %w", err)
	}

	return nil
}

// estimateCost estimates the cost of a completion
// Note: These are approximate rates and may change
func (c *Client) estimateCost(usage openai.Usage) float64 {
	// Approximate pricing (as of 2024-2025)
	var inputCostPer1K, outputCostPer1K float64

	switch c.config.Model {
	case "gpt-4-turbo", "gpt-4-turbo-preview":
		inputCostPer1K = 0.01
		outputCostPer1K = 0.03
	case "gpt-4":
		inputCostPer1K = 0.03
		outputCostPer1K = 0.06
	case "gpt-3.5-turbo":
		inputCostPer1K = 0.0015
		outputCostPer1K = 0.002
	default:
		// Conservative estimate for unknown models
		inputCostPer1K = 0.01
		outputCostPer1K = 0.03
	}

	inputCost := (float64(usage.PromptTokens) / 1000.0) * inputCostPer1K
	outputCost := (float64(usage.CompletionTokens) / 1000.0) * outputCostPer1K

	return inputCost + outputCost
}

// Close closes the AI client
func (c *Client) Close() error {
	c.enabled = false
	return nil
}
