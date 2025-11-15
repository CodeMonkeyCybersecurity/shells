package scope

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
)

// HackerOneClient implements the HackerOne API client
type HackerOneClient struct {
	logger     *logger.Logger
	httpClient *http.Client
	baseURL    string
	username   string
	apiKey     string
}

// NewHackerOneClient creates a new HackerOne client
func NewHackerOneClient(logger *logger.Logger) *HackerOneClient {
	return &HackerOneClient{
		logger:     logger,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    "https://api.hackerone.com/v1",
	}
}

// Configure sets the API credentials
func (c *HackerOneClient) Configure(username, apiKey string) {
	c.username = username
	c.apiKey = apiKey
}

// GetProgram fetches a program's details including scope
func (c *HackerOneClient) GetProgram(ctx context.Context, handle string) (*Program, error) {
	if c.username == "" || c.apiKey == "" {
		// Try to fetch public program info without auth
		return c.getPublicProgram(ctx, handle)
	}

	url := fmt.Sprintf("%s/hackers/programs/%s", c.baseURL, handle)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.username, c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HackerOne API error: %d - %s", resp.StatusCode, string(body))
	}

	var apiResp struct {
		Data struct {
			ID         string `json:"id"`
			Type       string `json:"type"`
			Attributes struct {
				Handle          string  `json:"handle"`
				Name            string  `json:"name"`
				SubmissionState string  `json:"submission_state"`
				TriageActive    bool    `json:"triage_active"`
				OffersSwag      bool    `json:"offers_swag"`
				OffersBounties  bool    `json:"offers_bounties"`
				PolicyHTML      string  `json:"policy_html"`
				MaxBountyAmount float64 `json:"maximum_bounty_amount"`
			} `json:"attributes"`
			Relationships struct {
				StructuredScopes struct {
					Data []struct {
						ID   string `json:"id"`
						Type string `json:"type"`
					} `json:"data"`
				} `json:"structured_scopes"`
			} `json:"relationships"`
		} `json:"data"`
		Included []struct {
			ID         string `json:"id"`
			Type       string `json:"type"`
			Attributes struct {
				AssetType             string `json:"asset_type"`
				AssetIdentifier       string `json:"asset_identifier"`
				Instruction           string `json:"instruction"`
				MaxSeverity           string `json:"max_severity"`
				EligibleForBounty     bool   `json:"eligible_for_bounty"`
				EligibleForSubmission bool   `json:"eligible_for_submission"`
			} `json:"attributes"`
		} `json:"included"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}

	// Convert to our Program structure
	program := &Program{
		Platform:   PlatformHackerOne,
		Handle:     apiResp.Data.Attributes.Handle,
		Name:       apiResp.Data.Attributes.Name,
		URL:        fmt.Sprintf("https://hackerone.com/%s", handle),
		MaxBounty:  apiResp.Data.Attributes.MaxBountyAmount,
		Active:     apiResp.Data.Attributes.SubmissionState == "open",
		LastSynced: time.Now(),
		Scope:      []ScopeItem{},
		OutOfScope: []ScopeItem{},
		Metadata: map[string]string{
			"triage_active":   fmt.Sprintf("%v", apiResp.Data.Attributes.TriageActive),
			"offers_swag":     fmt.Sprintf("%v", apiResp.Data.Attributes.OffersSwag),
			"offers_bounties": fmt.Sprintf("%v", apiResp.Data.Attributes.OffersBounties),
		},
	}

	// Generate program ID
	program.ID = fmt.Sprintf("h1_%s", program.Handle)

	// Parse HTML policy for testing guidelines
	program.TestingGuidelines = c.extractTextFromHTML(apiResp.Data.Attributes.PolicyHTML)

	// Process structured scopes
	for _, scope := range apiResp.Included {
		item := ScopeItem{
			ID:           fmt.Sprintf("h1_scope_%s", scope.ID),
			Value:        scope.Attributes.AssetIdentifier,
			Instructions: scope.Attributes.Instruction,
			MaxSeverity:  scope.Attributes.MaxSeverity,
			LastUpdated:  time.Now(),
			Metadata: map[string]string{
				"h1_scope_id": scope.ID,
			},
		}

		// Determine scope type
		switch scope.Attributes.AssetType {
		case "Domain":
			item.Type = ScopeTypeDomain
		case "URL":
			item.Type = ScopeTypeURL
		case "IP_ADDRESS":
			item.Type = ScopeTypeIP
		case "CIDR":
			item.Type = ScopeTypeIPRange
		case "WILDCARD":
			item.Type = ScopeTypeWildcard
		case "API":
			item.Type = ScopeTypeAPI
		case "MOBILE_APP_BINARY":
			item.Type = ScopeTypeMobile
		case "SOURCE_CODE":
			item.Type = ScopeTypeSource
		case "EXECUTABLE":
			item.Type = ScopeTypeExecutable
		case "HARDWARE":
			item.Type = ScopeTypeHardware
		default:
			item.Type = ScopeTypeOther
		}

		// Determine if in or out of scope
		if scope.Attributes.EligibleForSubmission {
			item.Status = ScopeStatusInScope
			program.Scope = append(program.Scope, item)
		} else {
			item.Status = ScopeStatusOutOfScope
			program.OutOfScope = append(program.OutOfScope, item)
		}
	}

	return program, nil
}

// getPublicProgram fetches public program information without authentication
func (c *HackerOneClient) getPublicProgram(ctx context.Context, handle string) (*Program, error) {
	// This would scrape the public program page or use a public API endpoint
	// For now, return a basic structure
	return &Program{
		Platform:   PlatformHackerOne,
		Handle:     handle,
		Name:       handle,
		URL:        fmt.Sprintf("https://hackerone.com/%s", handle),
		Active:     true,
		LastSynced: time.Now(),
		ID:         fmt.Sprintf("h1_%s", handle),
		Metadata: map[string]string{
			"source": "public",
		},
	}, nil
}

// ListPrograms lists available programs
func (c *HackerOneClient) ListPrograms(ctx context.Context) ([]*Program, error) {
	// Implementation would list all programs the user has access to
	// This requires proper API credentials
	return []*Program{}, nil
}

// extractTextFromHTML extracts plain text from HTML
func (c *HackerOneClient) extractTextFromHTML(html string) string {
	// Simple HTML stripping - in production use a proper HTML parser
	// This is a placeholder implementation
	text := html
	// Remove common HTML tags
	tags := []string{"<p>", "</p>", "<br>", "<br/>", "<div>", "</div>",
		"<span>", "</span>", "<strong>", "</strong>", "<em>", "</em>",
		"<ul>", "</ul>", "<ol>", "</ol>", "<li>", "</li>"}

	for _, tag := range tags {
		text = strings.ReplaceAll(text, tag, " ")
	}

	// Clean up extra spaces
	text = strings.TrimSpace(text)
	text = regexp.MustCompile(`\s+`).ReplaceAllString(text, " ")

	return text
}
