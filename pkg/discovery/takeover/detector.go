package takeover

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/httpclient"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// TakeoverDetector detects subdomain takeover vulnerabilities
type TakeoverDetector struct {
	client     *http.Client
	dnsTimeout time.Duration
	logger     *logger.Logger
	signatures map[string]TakeoverSignature
}

// TakeoverSignature defines patterns for detecting takeover vulnerabilities
type TakeoverSignature struct {
	Service       string
	CNAMEPatterns []string
	HTTPPatterns  []string
	Fingerprints  []string
	Documentation string
	Severity      string
}

// TakeoverResult represents a potential takeover vulnerability
type TakeoverResult struct {
	Subdomain     string
	Service       string
	CNAME         string
	Vulnerable    bool
	Severity      string
	Evidence      []string
	Documentation string
}

// NewTakeoverDetector creates a new takeover detector
func NewTakeoverDetector(logger *logger.Logger) *TakeoverDetector {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	detector := &TakeoverDetector{
		client:     client,
		dnsTimeout: 5 * time.Second,
		logger:     logger,
		signatures: make(map[string]TakeoverSignature),
	}

	// Initialize signatures
	detector.loadSignatures()

	return detector
}

// loadSignatures loads known subdomain takeover signatures
func (t *TakeoverDetector) loadSignatures() {
	t.signatures = map[string]TakeoverSignature{
		"github": {
			Service:       "GitHub Pages",
			CNAMEPatterns: []string{".github.io", ".github.com"},
			HTTPPatterns:  []string{"There isn't a GitHub Pages site here"},
			Fingerprints:  []string{"404", "GitHub Pages"},
			Severity:      "HIGH",
			Documentation: "https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site",
		},
		"aws_s3": {
			Service:       "AWS S3",
			CNAMEPatterns: []string{".s3.amazonaws.com", ".s3-website"},
			HTTPPatterns:  []string{"NoSuchBucket", "The specified bucket does not exist"},
			Fingerprints:  []string{"404", "Amazon S3"},
			Severity:      "HIGH",
			Documentation: "https://aws.amazon.com/s3/",
		},
		"heroku": {
			Service:       "Heroku",
			CNAMEPatterns: []string{".herokuapp.com", ".herokussl.com"},
			HTTPPatterns:  []string{"No such app", "There's nothing here, yet"},
			Fingerprints:  []string{"404", "Heroku"},
			Severity:      "HIGH",
			Documentation: "https://devcenter.heroku.com/articles/custom-domains",
		},
		"shopify": {
			Service:       "Shopify",
			CNAMEPatterns: []string{".myshopify.com", "shops.myshopify.com"},
			HTTPPatterns:  []string{"Sorry, this shop is currently unavailable"},
			Fingerprints:  []string{"404", "Shopify"},
			Severity:      "MEDIUM",
			Documentation: "https://help.shopify.com/en/manual/domains/add-a-domain",
		},
		"tumblr": {
			Service:       "Tumblr",
			CNAMEPatterns: []string{"domains.tumblr.com"},
			HTTPPatterns:  []string{"Whatever you were looking for doesn't currently exist at this address"},
			Fingerprints:  []string{"404", "Tumblr"},
			Severity:      "MEDIUM",
			Documentation: "https://help.tumblr.com/hc/en-us/articles/231256548-Custom-domains",
		},
		"wordpress": {
			Service:       "WordPress.com",
			CNAMEPatterns: []string{".wordpress.com"},
			HTTPPatterns:  []string{"Do you want to register"},
			Fingerprints:  []string{"WordPress.com"},
			Severity:      "MEDIUM",
			Documentation: "https://wordpress.com/support/domains/",
		},
		"ghost": {
			Service:       "Ghost",
			CNAMEPatterns: []string{".ghost.io"},
			HTTPPatterns:  []string{"The thing you were looking for is no longer here"},
			Fingerprints:  []string{"404", "Ghost"},
			Severity:      "MEDIUM",
			Documentation: "https://ghost.org/docs/config/#url",
		},
		"surge": {
			Service:       "Surge.sh",
			CNAMEPatterns: []string{".surge.sh"},
			HTTPPatterns:  []string{"project not found"},
			Fingerprints:  []string{"404", "Surge"},
			Severity:      "HIGH",
			Documentation: "https://surge.sh/help/adding-a-custom-domain",
		},
		"netlify": {
			Service:       "Netlify",
			CNAMEPatterns: []string{".netlify.com", ".netlify.app"},
			HTTPPatterns:  []string{"Not Found - Request ID:"},
			Fingerprints:  []string{"404", "Netlify"},
			Severity:      "HIGH",
			Documentation: "https://docs.netlify.com/domains-https/custom-domains/",
		},
		"bitbucket": {
			Service:       "Bitbucket",
			CNAMEPatterns: []string{".bitbucket.io"},
			HTTPPatterns:  []string{"Repository not found"},
			Fingerprints:  []string{"404", "Bitbucket"},
			Severity:      "HIGH",
			Documentation: "https://support.atlassian.com/bitbucket-cloud/docs/publishing-a-website-on-bitbucket-cloud/",
		},
		"unbounce": {
			Service:       "Unbounce",
			CNAMEPatterns: []string{".unbouncepages.com"},
			HTTPPatterns:  []string{"The requested URL was not found on this server"},
			Fingerprints:  []string{"404", "Unbounce"},
			Severity:      "MEDIUM",
			Documentation: "https://documentation.unbounce.com/hc/en-us/articles/204012034-Set-Up-Your-Domain-in-Unbounce",
		},
		"tictail": {
			Service:       "Tictail",
			CNAMEPatterns: []string{".tictail.com"},
			HTTPPatterns:  []string{"Building a brand of your own?"},
			Fingerprints:  []string{"Tictail"},
			Severity:      "MEDIUM",
			Documentation: "https://tictail.com",
		},
		"campaignmonitor": {
			Service:       "Campaign Monitor",
			CNAMEPatterns: []string{".createsend.com"},
			HTTPPatterns:  []string{"Double check the URL"},
			Fingerprints:  []string{"404", "Campaign Monitor"},
			Severity:      "MEDIUM",
			Documentation: "https://help.campaignmonitor.com/",
		},
		"cargocollective": {
			Service:       "Cargo Collective",
			CNAMEPatterns: []string{".cargocollective.com"},
			HTTPPatterns:  []string{"404 Not Found"},
			Fingerprints:  []string{"404", "Cargo"},
			Severity:      "MEDIUM",
			Documentation: "https://support.cargocollective.com/",
		},
		"statuspage": {
			Service:       "StatusPage",
			CNAMEPatterns: []string{".statuspage.io"},
			HTTPPatterns:  []string{"Hosted Status Pages for Your Company"},
			Fingerprints:  []string{"StatusPage"},
			Severity:      "MEDIUM",
			Documentation: "https://help.statuspage.io/",
		},
		"helpjuice": {
			Service:       "HelpJuice",
			CNAMEPatterns: []string{".helpjuice.com"},
			HTTPPatterns:  []string{"We could not find what you're looking for"},
			Fingerprints:  []string{"404", "Helpjuice"},
			Severity:      "MEDIUM",
			Documentation: "https://help.helpjuice.com/",
		},
		"helpscout": {
			Service:       "HelpScout",
			CNAMEPatterns: []string{".helpscoutdocs.com"},
			HTTPPatterns:  []string{"No settings were found for this company"},
			Fingerprints:  []string{"404", "Help Scout"},
			Severity:      "MEDIUM",
			Documentation: "https://docs.helpscout.com/",
		},
		"cargo": {
			Service:       "Cargo",
			CNAMEPatterns: []string{".cargocollective.com"},
			HTTPPatterns:  []string{"If you're moving your domain away from Cargo"},
			Fingerprints:  []string{"Cargo"},
			Severity:      "MEDIUM",
			Documentation: "https://support.cargocollective.com/",
		},
		"feedpress": {
			Service:       "FeedPress",
			CNAMEPatterns: []string{".feedpress.me"},
			HTTPPatterns:  []string{"The feed has not been found"},
			Fingerprints:  []string{"404", "FeedPress"},
			Severity:      "MEDIUM",
			Documentation: "https://feedpress.com/",
		},
		"freshdesk": {
			Service:       "Freshdesk",
			CNAMEPatterns: []string{".freshdesk.com"},
			HTTPPatterns:  []string{"May be this is still fresh"},
			Fingerprints:  []string{"404", "Freshdesk"},
			Severity:      "MEDIUM",
			Documentation: "https://support.freshdesk.com/",
		},
		"getresponse": {
			Service:       "GetResponse",
			CNAMEPatterns: []string{".getresponse.com"},
			HTTPPatterns:  []string{"With GetResponse Landing Pages"},
			Fingerprints:  []string{"GetResponse"},
			Severity:      "MEDIUM",
			Documentation: "https://www.getresponse.com/",
		},
		"gitbook": {
			Service:       "GitBook",
			CNAMEPatterns: []string{".gitbook.io"},
			HTTPPatterns:  []string{"If you need specifics, here's where to find us"},
			Fingerprints:  []string{"404", "GitBook"},
			Severity:      "MEDIUM",
			Documentation: "https://docs.gitbook.com/",
		},
		"jetbrains": {
			Service:       "JetBrains",
			CNAMEPatterns: []string{".youtrack.cloud"},
			HTTPPatterns:  []string{"is not a registered InCloud YouTrack"},
			Fingerprints:  []string{"404", "JetBrains"},
			Severity:      "MEDIUM",
			Documentation: "https://www.jetbrains.com/youtrack/",
		},
		"azure": {
			Service:       "Microsoft Azure",
			CNAMEPatterns: []string{".azurewebsites.net", ".cloudapp.net", ".trafficmanager.net"},
			HTTPPatterns:  []string{"404 Web Site not found"},
			Fingerprints:  []string{"404", "Microsoft Azure"},
			Severity:      "HIGH",
			Documentation: "https://docs.microsoft.com/en-us/azure/",
		},
		"cloudfront": {
			Service:       "AWS CloudFront",
			CNAMEPatterns: []string{".cloudfront.net"},
			HTTPPatterns:  []string{"ERROR: The request could not be satisfied", "CloudFront"},
			Fingerprints:  []string{"403", "CloudFront"},
			Severity:      "HIGH",
			Documentation: "https://aws.amazon.com/cloudfront/",
		},
	}
}

// CheckSubdomain checks if a subdomain is vulnerable to takeover
func (t *TakeoverDetector) CheckSubdomain(ctx context.Context, subdomain string) (*TakeoverResult, error) {
	result := &TakeoverResult{
		Subdomain:  subdomain,
		Vulnerable: false,
		Evidence:   []string{},
	}

	// Get CNAME record
	cname, err := t.getCNAME(subdomain)
	if err != nil {
		// No CNAME, not vulnerable to CNAME takeover
		return result, nil
	}

	result.CNAME = cname

	// Check against known signatures
	for _, signature := range t.signatures {
		if t.matchesCNAME(cname, signature.CNAMEPatterns) {
			// Potential vulnerability, check HTTP response
			if t.checkHTTPResponse(ctx, subdomain, signature) {
				result.Vulnerable = true
				result.Service = signature.Service
				result.Severity = signature.Severity
				result.Documentation = signature.Documentation
				result.Evidence = append(result.Evidence,
					fmt.Sprintf("CNAME points to %s", cname),
					fmt.Sprintf("Service identified as %s", signature.Service),
					"HTTP response indicates unclaimed service")

				t.logger.Info("Subdomain takeover vulnerability detected",
					"subdomain", subdomain,
					"service", signature.Service,
					"cname", cname,
					"severity", signature.Severity)

				return result, nil
			}
		}
	}

	// Check for dangling CNAMEs (NXDOMAIN)
	if t.isDanglingCNAME(cname) {
		result.Vulnerable = true
		result.Severity = "HIGH"
		result.Evidence = append(result.Evidence,
			fmt.Sprintf("CNAME points to non-existent domain: %s", cname),
			"Dangling CNAME detected")

		t.logger.Info("Dangling CNAME detected",
			"subdomain", subdomain,
			"cname", cname)
	}

	return result, nil
}

// getCNAME retrieves the CNAME record for a domain
func (t *TakeoverDetector) getCNAME(domain string) (string, error) {
	cname, err := net.LookupCNAME(domain)
	if err != nil {
		return "", err
	}

	// If CNAME is same as domain, no CNAME exists
	if strings.TrimSuffix(cname, ".") == strings.TrimSuffix(domain, ".") {
		return "", fmt.Errorf("no CNAME record")
	}

	return strings.TrimSuffix(cname, "."), nil
}

// matchesCNAME checks if a CNAME matches any patterns
func (t *TakeoverDetector) matchesCNAME(cname string, patterns []string) bool {
	cnameLC := strings.ToLower(cname)
	for _, pattern := range patterns {
		if strings.Contains(cnameLC, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// checkHTTPResponse checks if HTTP response indicates vulnerability
func (t *TakeoverDetector) checkHTTPResponse(ctx context.Context, domain string, signature TakeoverSignature) bool {
	// Try both HTTP and HTTPS
	protocols := []string{"https://", "http://"}

	for _, protocol := range protocols {
		url := protocol + domain

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		resp, err := t.client.Do(req)
		if err != nil {
			continue
		}
		defer httpclient.CloseBody(resp)

		// Read limited body
		body := make([]byte, 50000) // 50KB should be enough
		n, _ := resp.Body.Read(body)
		bodyStr := string(body[:n])

		// Check patterns
		for _, pattern := range signature.HTTPPatterns {
			if strings.Contains(bodyStr, pattern) {
				return true
			}
		}

		// Check fingerprints in headers
		for _, fingerprint := range signature.Fingerprints {
			for key, values := range resp.Header {
				for _, value := range values {
					if strings.Contains(strings.ToLower(value), strings.ToLower(fingerprint)) {
						return true
					}
				}
				if strings.Contains(strings.ToLower(key), strings.ToLower(fingerprint)) {
					return true
				}
			}
		}
	}

	return false
}

// isDanglingCNAME checks if a CNAME points to a non-existent domain
func (t *TakeoverDetector) isDanglingCNAME(cname string) bool {
	_, err := net.LookupHost(cname)
	return err != nil && strings.Contains(err.Error(), "no such host")
}

// BulkCheck checks multiple subdomains for takeover vulnerabilities
func (t *TakeoverDetector) BulkCheck(ctx context.Context, subdomains []string) ([]*TakeoverResult, error) {
	var results []*TakeoverResult

	for _, subdomain := range subdomains {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
			result, err := t.CheckSubdomain(ctx, subdomain)
			if err != nil {
				t.logger.Error("Failed to check subdomain", "subdomain", subdomain, "error", err)
				continue
			}

			if result.Vulnerable {
				results = append(results, result)
			}
		}
	}

	return results, nil
}

// GetVulnerableServices returns a list of services we check for
func (t *TakeoverDetector) GetVulnerableServices() []string {
	var services []string
	for _, sig := range t.signatures {
		services = append(services, sig.Service)
	}
	return services
}
