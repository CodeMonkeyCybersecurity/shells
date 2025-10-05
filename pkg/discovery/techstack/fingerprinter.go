package techstack

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/httpclient"
	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// TechFingerprinter identifies technology stacks from various sources
type TechFingerprinter struct {
	client       *http.Client
	logger       *logger.Logger
	fingerprints map[string]TechFingerprint
	mu           sync.RWMutex
}

// TechFingerprint represents a technology detection pattern
type TechFingerprint struct {
	Name        string
	Category    string
	Patterns    []Pattern
	Implies     []string // Technologies this implies
	Excludes    []string // Technologies this excludes
	Website     string
	Description string
}

// Pattern represents a detection pattern
type Pattern struct {
	Type     string // header, body, cookie, meta, script, url
	Pattern  string // Regex pattern
	Version  string // Version extraction pattern
	compiled *regexp.Regexp
}

// Technology represents a detected technology
type Technology struct {
	Name        string
	Category    string
	Version     string
	Confidence  float64
	Evidence    []string
	Website     string
	Description string
	Implies     []string
}

// NewTechFingerprinter creates a new technology fingerprinter
func NewTechFingerprinter(logger *logger.Logger) *TechFingerprinter {
	// Use secure HTTP client factory with 30s timeout
	// SSRF protection disabled for public website fingerprinting
	httpClient := httpclient.NewSecureClient(httpclient.SecureClientConfig{
		Timeout:    30 * time.Second,
		EnableSSRF: false, // Fingerprinting user-provided targets
	})

	tf := &TechFingerprinter{
		client:       httpClient,
		logger:       logger,
		fingerprints: make(map[string]TechFingerprint),
	}

	// Initialize fingerprints
	tf.loadFingerprints()

	return tf
}

// loadFingerprints loads technology fingerprints
func (t *TechFingerprinter) loadFingerprints() {
	fingerprints := []TechFingerprint{
		// Web Servers
		{
			Name:     "Nginx",
			Category: "Web Server",
			Patterns: []Pattern{
				{Type: "header", Pattern: "Server.*nginx(?:/([\\d.]+))?", Version: "$1"},
				{Type: "header", Pattern: "X-Powered-By.*nginx", Version: ""},
			},
			Website: "https://nginx.org",
		},
		{
			Name:     "Apache",
			Category: "Web Server",
			Patterns: []Pattern{
				{Type: "header", Pattern: "Server.*Apache(?:/([\\d.]+))?", Version: "$1"},
				{Type: "header", Pattern: "Server.*Apache-Coyote", Version: ""},
			},
			Website: "https://httpd.apache.org",
		},
		{
			Name:     "Microsoft IIS",
			Category: "Web Server",
			Patterns: []Pattern{
				{Type: "header", Pattern: "Server.*Microsoft-IIS(?:/([\\d.]+))?", Version: "$1"},
				{Type: "header", Pattern: "X-Powered-By.*ASP\\.NET", Version: ""},
			},
			Implies: []string{"Windows Server"},
			Website: "https://www.iis.net",
		},

		// Programming Languages
		{
			Name:     "PHP",
			Category: "Programming Language",
			Patterns: []Pattern{
				{Type: "header", Pattern: "X-Powered-By.*PHP(?:/([\\d.]+))?", Version: "$1"},
				{Type: "cookie", Pattern: "PHPSESSID", Version: ""},
				{Type: "body", Pattern: "<\\?php", Version: ""},
			},
			Website: "https://php.net",
		},
		{
			Name:     "Python",
			Category: "Programming Language",
			Patterns: []Pattern{
				{Type: "header", Pattern: "Server.*Python(?:/([\\d.]+))?", Version: "$1"},
				{Type: "header", Pattern: "X-Powered-By.*Python", Version: ""},
			},
			Website: "https://python.org",
		},
		{
			Name:     "Ruby",
			Category: "Programming Language",
			Patterns: []Pattern{
				{Type: "header", Pattern: "X-Powered-By.*Ruby(?:/([\\d.]+))?", Version: "$1"},
				{Type: "header", Pattern: "Server.*Phusion Passenger", Version: ""},
				{Type: "header", Pattern: "X-Runtime.*Ruby", Version: ""},
			},
			Website: "https://ruby-lang.org",
		},
		{
			Name:     "Java",
			Category: "Programming Language",
			Patterns: []Pattern{
				{Type: "cookie", Pattern: "JSESSIONID", Version: ""},
				{Type: "header", Pattern: "X-Powered-By.*Servlet", Version: ""},
			},
			Website: "https://java.com",
		},

		// Frameworks
		{
			Name:     "Django",
			Category: "Web Framework",
			Patterns: []Pattern{
				{Type: "header", Pattern: "X-Powered-By.*Django", Version: ""},
				{Type: "cookie", Pattern: "csrftoken", Version: ""},
				{Type: "body", Pattern: "csrfmiddlewaretoken", Version: ""},
			},
			Implies: []string{"Python"},
			Website: "https://djangoproject.com",
		},
		{
			Name:     "Ruby on Rails",
			Category: "Web Framework",
			Patterns: []Pattern{
				{Type: "header", Pattern: "X-Powered-By.*Rails", Version: ""},
				{Type: "header", Pattern: "Server.*WEBrick", Version: ""},
				{Type: "cookie", Pattern: "_rails_session", Version: ""},
				{Type: "meta", Pattern: "csrf-token", Version: ""},
			},
			Implies: []string{"Ruby"},
			Website: "https://rubyonrails.org",
		},
		{
			Name:     "Laravel",
			Category: "Web Framework",
			Patterns: []Pattern{
				{Type: "cookie", Pattern: "laravel_session", Version: ""},
				{Type: "header", Pattern: "X-Powered-By.*Laravel", Version: ""},
			},
			Implies: []string{"PHP"},
			Website: "https://laravel.com",
		},
		{
			Name:     "Express",
			Category: "Web Framework",
			Patterns: []Pattern{
				{Type: "header", Pattern: "X-Powered-By.*Express", Version: ""},
			},
			Implies: []string{"Node.js"},
			Website: "https://expressjs.com",
		},
		{
			Name:     "Spring",
			Category: "Web Framework",
			Patterns: []Pattern{
				{Type: "header", Pattern: "X-Application-Context", Version: ""},
				{Type: "body", Pattern: "org\\.springframework", Version: ""},
			},
			Implies: []string{"Java"},
			Website: "https://spring.io",
		},

		// CMS
		{
			Name:     "WordPress",
			Category: "CMS",
			Patterns: []Pattern{
				{Type: "body", Pattern: "wp-content", Version: ""},
				{Type: "body", Pattern: "wp-includes", Version: ""},
				{Type: "meta", Pattern: "generator.*WordPress\\s*([\\d.]+)?", Version: "$1"},
				{Type: "header", Pattern: "X-Powered-By.*WordPress", Version: ""},
			},
			Implies: []string{"PHP", "MySQL"},
			Website: "https://wordpress.org",
		},
		{
			Name:     "Drupal",
			Category: "CMS",
			Patterns: []Pattern{
				{Type: "header", Pattern: "X-Generator.*Drupal\\s*([\\d.]+)?", Version: "$1"},
				{Type: "body", Pattern: "Drupal\\.settings", Version: ""},
				{Type: "body", Pattern: "/sites/default/", Version: ""},
			},
			Implies: []string{"PHP"},
			Website: "https://drupal.org",
		},
		{
			Name:     "Joomla",
			Category: "CMS",
			Patterns: []Pattern{
				{Type: "meta", Pattern: "generator.*Joomla.*([\\d.]+)?", Version: "$1"},
				{Type: "body", Pattern: "/media/jui/", Version: ""},
				{Type: "header", Pattern: "X-Content-Encoded-By.*Joomla", Version: ""},
			},
			Implies: []string{"PHP"},
			Website: "https://joomla.org",
		},

		// JavaScript Libraries
		{
			Name:     "jQuery",
			Category: "JavaScript Library",
			Patterns: []Pattern{
				{Type: "script", Pattern: "jquery(?:-([\\d.]+))?\\.(?:min\\.)?js", Version: "$1"},
				{Type: "body", Pattern: "jQuery\\.fn\\.jquery\\s*=\\s*[\"']([\\d.]+)", Version: "$1"},
			},
			Website: "https://jquery.com",
		},
		{
			Name:     "React",
			Category: "JavaScript Framework",
			Patterns: []Pattern{
				{Type: "body", Pattern: "React\\.version\\s*=\\s*[\"']([\\d.]+)", Version: "$1"},
				{Type: "body", Pattern: "_react.*([\\d.]+)", Version: "$1"},
				{Type: "script", Pattern: "react(?:-([\\d.]+))?\\.(?:min\\.)?js", Version: "$1"},
			},
			Website: "https://reactjs.org",
		},
		{
			Name:     "Vue.js",
			Category: "JavaScript Framework",
			Patterns: []Pattern{
				{Type: "body", Pattern: "Vue\\.version\\s*=\\s*[\"']([\\d.]+)", Version: "$1"},
				{Type: "script", Pattern: "vue(?:\\.([\\d.]+))?\\.(?:min\\.)?js", Version: "$1"},
			},
			Website: "https://vuejs.org",
		},
		{
			Name:     "Angular",
			Category: "JavaScript Framework",
			Patterns: []Pattern{
				{Type: "body", Pattern: "ng-version=\"([\\d.]+)\"", Version: "$1"},
				{Type: "script", Pattern: "angular(?:\\.([\\d.]+))?\\.(?:min\\.)?js", Version: "$1"},
			},
			Website: "https://angular.io",
		},

		// Databases
		{
			Name:     "MySQL",
			Category: "Database",
			Patterns: []Pattern{
				{Type: "body", Pattern: "mysqladmin", Version: ""},
			},
			Website: "https://mysql.com",
		},
		{
			Name:     "PostgreSQL",
			Category: "Database",
			Patterns: []Pattern{
				{Type: "body", Pattern: "postgresql", Version: ""},
			},
			Website: "https://postgresql.org",
		},
		{
			Name:     "MongoDB",
			Category: "Database",
			Patterns: []Pattern{
				{Type: "body", Pattern: "mongodb", Version: ""},
			},
			Website: "https://mongodb.com",
		},

		// Analytics
		{
			Name:     "Google Analytics",
			Category: "Analytics",
			Patterns: []Pattern{
				{Type: "script", Pattern: "google-analytics\\.com/(?:ga|analytics)\\.js", Version: ""},
				{Type: "body", Pattern: "GoogleAnalyticsObject", Version: ""},
			},
			Website: "https://analytics.google.com",
		},

		// CDN
		{
			Name:     "Cloudflare",
			Category: "CDN",
			Patterns: []Pattern{
				{Type: "header", Pattern: "Server.*cloudflare", Version: ""},
				{Type: "header", Pattern: "CF-RAY", Version: ""},
			},
			Website: "https://cloudflare.com",
		},
		{
			Name:     "Amazon CloudFront",
			Category: "CDN",
			Patterns: []Pattern{
				{Type: "header", Pattern: "Via.*CloudFront", Version: ""},
				{Type: "header", Pattern: "X-Amz-Cf-Id", Version: ""},
			},
			Website: "https://aws.amazon.com/cloudfront",
		},

		// Security
		{
			Name:     "reCAPTCHA",
			Category: "Security",
			Patterns: []Pattern{
				{Type: "script", Pattern: "google\\.com/recaptcha", Version: ""},
				{Type: "body", Pattern: "g-recaptcha", Version: ""},
			},
			Website: "https://google.com/recaptcha",
		},
		{
			Name:     "Cloudflare Turnstile",
			Category: "Security",
			Patterns: []Pattern{
				{Type: "script", Pattern: "challenges\\.cloudflare\\.com/turnstile", Version: ""},
				{Type: "body", Pattern: "cf-turnstile", Version: ""},
			},
			Website: "https://cloudflare.com/products/turnstile",
		},
	}

	// Compile patterns and add to map
	for _, fp := range fingerprints {
		for i := range fp.Patterns {
			pattern := &fp.Patterns[i]
			if compiled, err := regexp.Compile(pattern.Pattern); err == nil {
				pattern.compiled = compiled
			}
		}
		t.fingerprints[fp.Name] = fp
	}
}

// FingerprintURL fingerprints technologies from a URL
func (t *TechFingerprinter) FingerprintURL(ctx context.Context, url string) ([]Technology, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Set common headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read body (limited to prevent memory issues)
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return nil, err
	}

	return t.analyzeResponse(resp, body)
}

// analyzeResponse analyzes HTTP response for technology fingerprints
func (t *TechFingerprinter) analyzeResponse(resp *http.Response, body []byte) ([]Technology, error) {
	detectedTech := make(map[string]*Technology)
	bodyStr := string(body)

	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, fingerprint := range t.fingerprints {
		tech := &Technology{
			Name:        fingerprint.Name,
			Category:    fingerprint.Category,
			Website:     fingerprint.Website,
			Description: fingerprint.Description,
			Implies:     fingerprint.Implies,
			Evidence:    []string{},
			Confidence:  0.0,
		}

		matchCount := 0

		for _, pattern := range fingerprint.Patterns {
			if pattern.compiled == nil {
				continue
			}

			var matched bool
			var version string

			switch pattern.Type {
			case "header":
				// Check all headers
				for key, values := range resp.Header {
					for _, value := range values {
						headerStr := fmt.Sprintf("%s: %s", key, value)
						if matches := pattern.compiled.FindStringSubmatch(headerStr); len(matches) > 0 {
							matched = true
							if pattern.Version != "" && len(matches) > 1 {
								version = matches[1]
							}
							tech.Evidence = append(tech.Evidence, fmt.Sprintf("Header: %s", key))
						}
					}
				}

			case "body":
				if matches := pattern.compiled.FindStringSubmatch(bodyStr); len(matches) > 0 {
					matched = true
					if pattern.Version != "" && len(matches) > 1 {
						version = matches[1]
					}
					tech.Evidence = append(tech.Evidence, fmt.Sprintf("Body pattern: %s", pattern.Pattern))
				}

			case "cookie":
				cookies := resp.Header.Get("Set-Cookie")
				if pattern.compiled.MatchString(cookies) {
					matched = true
					tech.Evidence = append(tech.Evidence, "Cookie pattern match")
				}

			case "meta":
				// Extract meta tags
				metaRegex := regexp.MustCompile(`<meta[^>]*>`)
				metas := metaRegex.FindAllString(bodyStr, -1)
				for _, meta := range metas {
					if pattern.compiled.MatchString(meta) {
						matched = true
						if matches := pattern.compiled.FindStringSubmatch(meta); len(matches) > 1 && pattern.Version != "" {
							version = matches[1]
						}
						tech.Evidence = append(tech.Evidence, "Meta tag pattern match")
					}
				}

			case "script":
				// Extract script tags
				scriptRegex := regexp.MustCompile(`<script[^>]*src="([^"]+)"`)
				scripts := scriptRegex.FindAllStringSubmatch(bodyStr, -1)
				for _, script := range scripts {
					if len(script) > 1 {
						if matches := pattern.compiled.FindStringSubmatch(script[1]); len(matches) > 0 {
							matched = true
							if pattern.Version != "" && len(matches) > 1 {
								version = matches[1]
							}
							tech.Evidence = append(tech.Evidence, fmt.Sprintf("Script: %s", script[1]))
						}
					}
				}

			case "url":
				if pattern.compiled.MatchString(resp.Request.URL.String()) {
					matched = true
					tech.Evidence = append(tech.Evidence, "URL pattern match")
				}
			}

			if matched {
				matchCount++
				if version != "" && tech.Version == "" {
					tech.Version = version
				}
			}
		}

		// Calculate confidence based on matches
		if matchCount > 0 {
			tech.Confidence = float64(matchCount) / float64(len(fingerprint.Patterns))
			if tech.Confidence > 1.0 {
				tech.Confidence = 1.0
			}
			detectedTech[tech.Name] = tech
		}
	}

	// Process implies relationships
	t.processImplies(detectedTech)

	// Process excludes relationships
	t.processExcludes(detectedTech)

	// Convert to slice
	var technologies []Technology
	for _, tech := range detectedTech {
		technologies = append(technologies, *tech)
	}

	return technologies, nil
}

// processImplies adds implied technologies
func (t *TechFingerprinter) processImplies(detectedTech map[string]*Technology) {
	changed := true
	for changed {
		changed = false
		for _, tech := range detectedTech {
			for _, impliedName := range tech.Implies {
				if _, exists := detectedTech[impliedName]; !exists {
					if fp, ok := t.fingerprints[impliedName]; ok {
						impliedTech := &Technology{
							Name:        fp.Name,
							Category:    fp.Category,
							Website:     fp.Website,
							Description: fp.Description,
							Confidence:  0.7, // Lower confidence for implied
							Evidence:    []string{fmt.Sprintf("Implied by %s", tech.Name)},
						}
						detectedTech[impliedName] = impliedTech
						changed = true
					}
				}
			}
		}
	}
}

// processExcludes removes excluded technologies
func (t *TechFingerprinter) processExcludes(detectedTech map[string]*Technology) {
	for _, tech := range detectedTech {
		if fp, ok := t.fingerprints[tech.Name]; ok {
			for _, excludedName := range fp.Excludes {
				delete(detectedTech, excludedName)
			}
		}
	}
}

// FingerprintHeaders fingerprints technologies from headers only
func (t *TechFingerprinter) FingerprintHeaders(headers http.Header) []Technology {
	var technologies []Technology

	// Common header-based detections
	headerDetections := map[string]map[string]string{
		"Server": {
			"nginx":      "Nginx",
			"apache":     "Apache",
			"iis":        "Microsoft IIS",
			"cloudflare": "Cloudflare",
		},
		"X-Powered-By": {
			"PHP":     "PHP",
			"ASP.NET": "ASP.NET",
			"Express": "Express",
		},
	}

	for header, patterns := range headerDetections {
		if value := headers.Get(header); value != "" {
			valueLower := strings.ToLower(value)
			for pattern, techName := range patterns {
				if strings.Contains(valueLower, strings.ToLower(pattern)) {
					tech := Technology{
						Name:       techName,
						Confidence: 0.9,
						Evidence:   []string{fmt.Sprintf("Header %s: %s", header, value)},
					}

					// Extract version if present
					versionRegex := regexp.MustCompile(`/(\d+\.\d+(?:\.\d+)?)`)
					if matches := versionRegex.FindStringSubmatch(value); len(matches) > 1 {
						tech.Version = matches[1]
					}

					technologies = append(technologies, tech)
				}
			}
		}
	}

	return technologies
}

// GetCategories returns all available technology categories
func (t *TechFingerprinter) GetCategories() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	categoryMap := make(map[string]bool)
	for _, fp := range t.fingerprints {
		categoryMap[fp.Category] = true
	}

	var categories []string
	for cat := range categoryMap {
		categories = append(categories, cat)
	}

	return categories
}
