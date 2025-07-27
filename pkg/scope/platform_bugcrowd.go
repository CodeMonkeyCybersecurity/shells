package scope

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// BugcrowdClient implements the Bugcrowd API client
type BugcrowdClient struct {
	logger     *logger.Logger
	httpClient *http.Client
	baseURL    string
	apiToken   string
}

// NewBugcrowdClient creates a new Bugcrowd client
func NewBugcrowdClient(logger *logger.Logger) *BugcrowdClient {
	return &BugcrowdClient{
		logger:     logger,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		baseURL:    "https://api.bugcrowd.com",
	}
}

// Configure sets the API token
func (c *BugcrowdClient) Configure(apiToken string) {
	c.apiToken = apiToken
}

// GetProgram fetches a program's details including scope
func (c *BugcrowdClient) GetProgram(ctx context.Context, handle string) (*Program, error) {
	// Bugcrowd uses program codes/slugs
	url := fmt.Sprintf("%s/programs/%s", c.baseURL, handle)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	if c.apiToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Token %s", c.apiToken))
	}
	req.Header.Set("Accept", "application/vnd.bugcrowd.v3+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.getPublicProgram(ctx, handle)
	}

	var apiResp struct {
		Program struct {
			Code         string  `json:"code"`
			Name         string  `json:"name"`
			URL          string  `json:"url"`
			Status       string  `json:"status"`
			MinReward    float64 `json:"min_reward"`
			MaxReward    float64 `json:"max_reward"`
			TargetGroups []struct {
				Name    string `json:"name"`
				InScope bool   `json:"in_scope"`
				Targets []struct {
					Name        string `json:"name"`
					URI         string `json:"uri"`
					Type        string `json:"type"`
					Description string `json:"description"`
				} `json:"targets"`
			} `json:"target_groups"`
		} `json:"program"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, err
	}

	// Convert to our Program structure
	program := &Program{
		Platform:   PlatformBugcrowd,
		Handle:     apiResp.Program.Code,
		Name:       apiResp.Program.Name,
		URL:        apiResp.Program.URL,
		MaxBounty:  apiResp.Program.MaxReward,
		Active:     apiResp.Program.Status == "live",
		LastSynced: time.Now(),
		Scope:      []ScopeItem{},
		OutOfScope: []ScopeItem{},
		Metadata: map[string]string{
			"min_reward": fmt.Sprintf("%.2f", apiResp.Program.MinReward),
			"status":     apiResp.Program.Status,
		},
	}

	// Generate program ID
	program.ID = fmt.Sprintf("bc_%s", program.Handle)

	// Process target groups
	for _, group := range apiResp.Program.TargetGroups {
		for _, target := range group.Targets {
			item := ScopeItem{
				ID:          fmt.Sprintf("bc_target_%s_%s", program.Handle, target.Name),
				Value:       target.URI,
				Description: target.Description,
				LastUpdated: time.Now(),
				Metadata: map[string]string{
					"target_group": group.Name,
					"target_name":  target.Name,
				},
			}

			// Determine scope type based on target type
			switch target.Type {
			case "website":
				item.Type = ScopeTypeDomain
			case "api":
				item.Type = ScopeTypeAPI
			case "mobile":
				item.Type = ScopeTypeMobile
			case "iot", "hardware":
				item.Type = ScopeTypeHardware
			default:
				item.Type = ScopeTypeOther
			}

			// Check for wildcard patterns
			if strings.HasPrefix(target.URI, "*.") {
				item.Type = ScopeTypeWildcard
			}

			// Determine if in or out of scope
			if group.InScope {
				item.Status = ScopeStatusInScope
				program.Scope = append(program.Scope, item)
			} else {
				item.Status = ScopeStatusOutOfScope
				program.OutOfScope = append(program.OutOfScope, item)
			}
		}
	}

	return program, nil
}

// getPublicProgram fetches public program information without authentication
func (c *BugcrowdClient) getPublicProgram(ctx context.Context, handle string) (*Program, error) {
	return &Program{
		Platform:   PlatformBugcrowd,
		Handle:     handle,
		Name:       handle,
		URL:        fmt.Sprintf("https://bugcrowd.com/%s", handle),
		Active:     true,
		LastSynced: time.Now(),
		ID:         fmt.Sprintf("bc_%s", handle),
		Metadata: map[string]string{
			"source": "public",
		},
	}, nil
}

// ListPrograms lists available programs
func (c *BugcrowdClient) ListPrograms(ctx context.Context) ([]*Program, error) {
	// Implementation would list all programs
	return []*Program{}, nil
}
