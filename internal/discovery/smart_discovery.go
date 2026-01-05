package discovery

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// SmartDiscovery implements intelligent attack surface discovery
// that prioritizes high-value targets for bug bounty hunting
type SmartDiscovery struct {
	config          *DiscoveryConfig
	logger          *logger.Logger
	priorityQueue   *PriorityQueue
	assetClassifier *AssetClassifier
	mutex           sync.RWMutex
}

// SmartAssetPriority represents the priority score of an asset in smart discovery
type SmartAssetPriority struct {
	Asset    *Asset
	Score    int
	Reasons  []string
	Features AssetFeatures
}

// AssetFeatures represents high-value features of an asset
type AssetFeatures struct {
	HasAuthentication bool
	HasAPI            bool
	HasPayment        bool
	HasFileUpload     bool
	HasAdminInterface bool
	HasUserData       bool
	IsInternal        bool
	Technology        []string
	Endpoints         []string
	Parameters        []string
}

// AssetClassifier classifies and scores assets based on bug bounty value
type AssetClassifier struct {
	patterns map[string]PatternRule
	logger   *logger.Logger
}

// PatternRule defines a pattern and its associated score
type PatternRule struct {
	Pattern *regexp.Regexp
	Score   int
	Type    string
	Reason  string
}

// NewSmartDiscovery creates a new smart discovery module
func NewSmartDiscovery(config *DiscoveryConfig, logger *logger.Logger) *SmartDiscovery {
	classifier := NewAssetClassifier(logger)

	return &SmartDiscovery{
		config:          config,
		logger:          logger,
		priorityQueue:   NewPriorityQueue(),
		assetClassifier: classifier,
	}
}

// NewAssetClassifier creates a classifier for high-value assets
func NewAssetClassifier(logger *logger.Logger) *AssetClassifier {
	patterns := map[string]PatternRule{
		// Authentication endpoints - Highest value
		"auth_login": {
			Pattern: regexp.MustCompile(`(?i)(login|signin|authenticate|auth/v\d+)`),
			Score:   100,
			Type:    "authentication",
			Reason:  "Authentication endpoint - potential for auth bypass",
		},
		"auth_oauth": {
			Pattern: regexp.MustCompile(`(?i)(oauth|oauth2|authorize|token)`),
			Score:   100,
			Type:    "authentication",
			Reason:  "OAuth endpoint - potential for token theft/bypass",
		},
		"auth_saml": {
			Pattern: regexp.MustCompile(`(?i)(saml|sso|federation|idp)`),
			Score:   100,
			Type:    "authentication",
			Reason:  "SAML/SSO endpoint - potential for assertion attacks",
		},
		"auth_jwt": {
			Pattern: regexp.MustCompile(`(?i)(jwt|bearer|refresh.*token)`),
			Score:   95,
			Type:    "authentication",
			Reason:  "JWT endpoint - potential for algorithm confusion",
		},
		"auth_reset": {
			Pattern: regexp.MustCompile(`(?i)(password.*reset|forgot.*password|recover)`),
			Score:   90,
			Type:    "authentication",
			Reason:  "Password reset - potential for account takeover",
		},

		// API endpoints - Very high value
		"api_graphql": {
			Pattern: regexp.MustCompile(`(?i)(graphql|gql)`),
			Score:   95,
			Type:    "api",
			Reason:  "GraphQL endpoint - potential for introspection/injection",
		},
		"api_rest": {
			Pattern: regexp.MustCompile(`(?i)(/api/v\d+|/rest/|/v\d+/)`),
			Score:   90,
			Type:    "api",
			Reason:  "REST API - potential for authorization bypass",
		},
		"api_internal": {
			Pattern: regexp.MustCompile(`(?i)(internal.*api|private.*api|admin.*api)`),
			Score:   95,
			Type:    "api",
			Reason:  "Internal API - high value target",
		},

		// Payment/Financial - Critical for business logic
		"payment_checkout": {
			Pattern: regexp.MustCompile(`(?i)(checkout|payment|pay|purchase)`),
			Score:   90,
			Type:    "payment",
			Reason:  "Payment endpoint - potential for price manipulation",
		},
		"payment_transfer": {
			Pattern: regexp.MustCompile(`(?i)(transfer|withdraw|deposit|balance)`),
			Score:   85,
			Type:    "payment",
			Reason:  "Financial transaction - business logic flaws",
		},
		"payment_billing": {
			Pattern: regexp.MustCompile(`(?i)(billing|invoice|subscription|credit)`),
			Score:   80,
			Type:    "payment",
			Reason:  "Billing endpoint - potential for fraud",
		},

		// Admin/Management - High privilege targets
		"admin_panel": {
			Pattern: regexp.MustCompile(`(?i)(admin|administrator|manage|dashboard)`),
			Score:   85,
			Type:    "admin",
			Reason:  "Admin interface - potential for privilege escalation",
		},
		"admin_config": {
			Pattern: regexp.MustCompile(`(?i)(config|settings|preferences|setup)`),
			Score:   75,
			Type:    "admin",
			Reason:  "Configuration endpoint - potential for tampering",
		},

		// User data access - IDOR/Access control
		"user_profile": {
			Pattern: regexp.MustCompile(`(?i)(profile|account|user/\d+|member)`),
			Score:   75,
			Type:    "user_data",
			Reason:  "User data endpoint - potential for IDOR",
		},
		"user_docs": {
			Pattern: regexp.MustCompile(`(?i)(document|file|download|attachment)`),
			Score:   70,
			Type:    "user_data",
			Reason:  "Document access - potential for unauthorized access",
		},

		// File operations - Various vulnerabilities
		"file_upload": {
			Pattern: regexp.MustCompile(`(?i)(upload|import|attach)`),
			Score:   75,
			Type:    "file_ops",
			Reason:  "File upload - potential for RCE/XSS",
		},
		"file_download": {
			Pattern: regexp.MustCompile(`(?i)(download|export|backup)`),
			Score:   65,
			Type:    "file_ops",
			Reason:  "File download - potential for path traversal",
		},

		// SSRF candidates
		"ssrf_webhook": {
			Pattern: regexp.MustCompile(`(?i)(webhook|callback|notify|hook)`),
			Score:   70,
			Type:    "ssrf",
			Reason:  "Webhook endpoint - potential for SSRF",
		},
		"ssrf_url": {
			Pattern: regexp.MustCompile(`(?i)(url=|uri=|link=|fetch|proxy)`),
			Score:   65,
			Type:    "ssrf",
			Reason:  "URL parameter - potential for SSRF",
		},

		// Development/Testing - Often vulnerable
		"dev_endpoint": {
			Pattern: regexp.MustCompile(`(?i)(dev|test|debug|staging)`),
			Score:   60,
			Type:    "development",
			Reason:  "Development endpoint - often less secure",
		},
		"dev_docs": {
			Pattern: regexp.MustCompile(`(?i)(swagger|api-doc|openapi|graphiql)`),
			Score:   65,
			Type:    "development",
			Reason:  "API documentation - information disclosure",
		},
	}

	return &AssetClassifier{
		patterns: patterns,
		logger:   logger,
	}
}

// ClassifyAndScore analyzes an asset and returns its priority score
func (ac *AssetClassifier) ClassifyAndScore(asset *Asset) *SmartAssetPriority {
	priority := &SmartAssetPriority{
		Asset:    asset,
		Score:    0,
		Reasons:  []string{},
		Features: AssetFeatures{},
	}

	// Check URL patterns
	assetURL := asset.Value
	for _, rule := range ac.patterns {
		if rule.Pattern.MatchString(assetURL) {
			priority.Score += rule.Score
			priority.Reasons = append(priority.Reasons, rule.Reason)

			// Update features based on type
			switch rule.Type {
			case "authentication":
				priority.Features.HasAuthentication = true
			case "api":
				priority.Features.HasAPI = true
			case "payment":
				priority.Features.HasPayment = true
			case "admin":
				priority.Features.HasAdminInterface = true
			case "user_data":
				priority.Features.HasUserData = true
			case "file_ops":
				if strings.Contains(rule.Reason, "upload") {
					priority.Features.HasFileUpload = true
				}
			}
		}
	}

	// Check for internal/private indicators
	if strings.Contains(assetURL, "internal") || strings.Contains(assetURL, "private") {
		priority.Score += 20
		priority.Features.IsInternal = true
		priority.Reasons = append(priority.Reasons, "Internal resource - should not be exposed")
	}

	// Check technology stack for vulnerable components
	if asset.Technology != nil {
		priority.Features.Technology = asset.Technology
		for _, tech := range asset.Technology {
			tech = strings.ToLower(tech)
			switch {
			case strings.Contains(tech, "wordpress"):
				priority.Score += 30
				priority.Reasons = append(priority.Reasons, "WordPress - common plugin vulnerabilities")
			case strings.Contains(tech, "jenkins"):
				priority.Score += 40
				priority.Reasons = append(priority.Reasons, "Jenkins - often misconfigured")
			case strings.Contains(tech, "phpmyadmin"):
				priority.Score += 50
				priority.Reasons = append(priority.Reasons, "phpMyAdmin - database access")
			case strings.Contains(tech, "tomcat"):
				priority.Score += 35
				priority.Reasons = append(priority.Reasons, "Tomcat - potential for manager access")
			}
		}
	}

	// Boost score for multiple high-value features
	featureCount := 0
	if priority.Features.HasAuthentication {
		featureCount++
	}
	if priority.Features.HasAPI {
		featureCount++
	}
	if priority.Features.HasPayment {
		featureCount++
	}
	if priority.Features.HasAdminInterface {
		featureCount++
	}

	if featureCount > 1 {
		priority.Score += featureCount * 10
		priority.Reasons = append(priority.Reasons,
			fmt.Sprintf("Multiple high-value features (%d)", featureCount))
	}

	return priority
}

// DiscoverWithPriority performs smart discovery that prioritizes high-value assets
func (sd *SmartDiscovery) DiscoverWithPriority(ctx context.Context, target string) ([]*SmartAssetPriority, error) {
	sd.logger.Info("Starting smart discovery with prioritization",
		"target", target)

	// Phase 1: Quick reconnaissance for high-value endpoints
	highValueEndpoints := sd.quickRecon(ctx, target)

	// Phase 2: Classify and prioritize discovered assets
	var priorities []*SmartAssetPriority
	for _, endpoint := range highValueEndpoints {
		asset := &Asset{
			Type:  AssetTypeAPI,
			Value: endpoint,
		}
		priority := sd.assetClassifier.ClassifyAndScore(asset)
		if priority.Score > 50 { // Only keep high-value assets
			priorities = append(priorities, priority)
		}
	}

	// Phase 3: Sort by priority score
	sort.Slice(priorities, func(i, j int) bool {
		return priorities[i].Score > priorities[j].Score
	})

	// Phase 4: Deep scan top priority targets first
	sd.logger.Info("Prioritized assets for scanning",
		"total", len(priorities),
		"top_score", priorities[0].Score)

	return priorities, nil
}

// quickRecon performs fast reconnaissance for high-value endpoints
func (sd *SmartDiscovery) quickRecon(ctx context.Context, target string) []string {
	var endpoints []string
	var mutex sync.Mutex
	var wg sync.WaitGroup

	// Common high-value paths to check
	highValuePaths := []string{
		// Authentication
		"/login", "/signin", "/auth", "/authenticate",
		"/oauth", "/oauth2", "/saml", "/sso",
		"/api/auth", "/api/login", "/api/v1/auth",
		"/.well-known/openid-configuration",

		// APIs
		"/api", "/api/v1", "/api/v2", "/graphql", "/gql",
		"/rest", "/services", "/api-docs", "/swagger",
		"/swagger.json", "/openapi.json",

		// Admin
		"/admin", "/administrator", "/manage", "/dashboard",
		"/console", "/portal", "/control-panel",

		// Payment
		"/checkout", "/payment", "/billing", "/subscribe",
		"/cart", "/order", "/invoice",

		// User data
		"/profile", "/account", "/user", "/me",
		"/settings", "/preferences",

		// File operations
		"/upload", "/download", "/files", "/documents",
		"/attachments", "/media",

		// Webhooks/SSRF
		"/webhook", "/callback", "/notify",
		"/proxy", "/fetch", "/url",

		// Development
		"/dev", "/test", "/staging", "/debug",
		"/.git", "/.env", "/config", "/backup",
	}

	// Check paths in parallel
	for _, path := range highValuePaths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()

			fullURL := fmt.Sprintf("https://%s%s", target, p)
			if sd.checkEndpoint(ctx, fullURL) {
				mutex.Lock()
				endpoints = append(endpoints, fullURL)
				mutex.Unlock()
			}
		}(path)
	}

	wg.Wait()
	return endpoints
}

// checkEndpoint quickly checks if an endpoint exists and is interesting
func (sd *SmartDiscovery) checkEndpoint(ctx context.Context, url string) bool {
	// This is a simplified check - in reality, you'd make HTTP requests
	// and analyze responses for signs of interesting functionality
	return true // Placeholder
}

// GetHighValueTargets returns a prioritized list of targets for scanning
func (sd *SmartDiscovery) GetHighValueTargets(assets []*Asset) []*SmartAssetPriority {
	var priorities []*SmartAssetPriority

	for _, asset := range assets {
		priority := sd.assetClassifier.ClassifyAndScore(asset)
		if priority.Score > 30 { // Configurable threshold
			priorities = append(priorities, priority)
		}
	}

	// Sort by score descending
	sort.Slice(priorities, func(i, j int) bool {
		return priorities[i].Score > priorities[j].Score
	})

	return priorities
}

// PriorityQueue manages assets by priority for scanning
type PriorityQueue struct {
	items []*SmartAssetPriority
	mutex sync.RWMutex
}

func NewPriorityQueue() *PriorityQueue {
	return &PriorityQueue{
		items: make([]*SmartAssetPriority, 0),
	}
}

func (pq *PriorityQueue) Push(item *SmartAssetPriority) {
	pq.mutex.Lock()
	defer pq.mutex.Unlock()

	pq.items = append(pq.items, item)
	// Keep sorted
	sort.Slice(pq.items, func(i, j int) bool {
		return pq.items[i].Score > pq.items[j].Score
	})
}

func (pq *PriorityQueue) Pop() *SmartAssetPriority {
	pq.mutex.Lock()
	defer pq.mutex.Unlock()

	if len(pq.items) == 0 {
		return nil
	}

	item := pq.items[0]
	pq.items = pq.items[1:]
	return item
}

func (pq *PriorityQueue) Len() int {
	pq.mutex.RLock()
	defer pq.mutex.RUnlock()
	return len(pq.items)
}
