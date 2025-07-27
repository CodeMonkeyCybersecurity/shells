package infrastructure

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// CloudDetector interface for cloud-specific asset discovery
type CloudDetector interface {
	DiscoverAssets(ctx context.Context, target string) []InfrastructureAsset
	GetCloudInfo(ctx context.Context, asset InfrastructureAsset) *CloudInfo
}

// AWSDetector discovers AWS assets
type AWSDetector struct {
	logger     *logger.Logger
	config     *DiscoveryConfig
	httpClient *http.Client
	patterns   map[string]*regexp.Regexp
}

// NewAWSDetector creates a new AWS detector
func NewAWSDetector(logger *logger.Logger, config *DiscoveryConfig) *AWSDetector {
	detector := &AWSDetector{
		logger: logger,
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
		patterns: make(map[string]*regexp.Regexp),
	}

	detector.initializePatterns()
	return detector
}

// initializePatterns initializes AWS-specific regex patterns
func (a *AWSDetector) initializePatterns() {
	// S3 bucket patterns
	a.patterns["s3_subdomain"] = regexp.MustCompile(`^([a-z0-9.-]+)\.s3\.([a-z0-9-]+)\.amazonaws\.com$`)
	a.patterns["s3_path"] = regexp.MustCompile(`^s3\.([a-z0-9-]+)\.amazonaws\.com/([a-z0-9.-]+)`)
	a.patterns["s3_virtualhosted"] = regexp.MustCompile(`^([a-z0-9.-]+)\.s3-([a-z0-9-]+)\.amazonaws\.com$`)

	// CloudFront patterns
	a.patterns["cloudfront"] = regexp.MustCompile(`([a-z0-9]+)\.cloudfront\.net$`)

	// ELB patterns
	a.patterns["elb_classic"] = regexp.MustCompile(`([a-z0-9-]+)-(\d+)\.([a-z0-9-]+)\.elb\.amazonaws\.com$`)
	a.patterns["elb_application"] = regexp.MustCompile(`([a-z0-9-]+)-(\d+)\.([a-z0-9-]+)\.elb\.amazonaws\.com$`)
	a.patterns["elb_network"] = regexp.MustCompile(`([a-z0-9-]+)-([a-f0-9]+)\.elb\.([a-z0-9-]+)\.amazonaws\.com$`)

	// API Gateway patterns
	a.patterns["api_gateway"] = regexp.MustCompile(`([a-z0-9]+)\.execute-api\.([a-z0-9-]+)\.amazonaws\.com`)

	// Lambda function URLs
	a.patterns["lambda_url"] = regexp.MustCompile(`([a-z0-9]+)\.lambda-url\.([a-z0-9-]+)\.on\.aws`)

	// RDS patterns
	a.patterns["rds"] = regexp.MustCompile(`([a-z0-9-]+)\.([a-z0-9-]+)\.rds\.amazonaws\.com`)

	// ElastiCache patterns
	a.patterns["elasticache"] = regexp.MustCompile(`([a-z0-9-]+)\.([a-z0-9]+)\.cache\.amazonaws\.com`)
}

// DiscoverAssets discovers AWS assets for a given target
func (a *AWSDetector) DiscoverAssets(ctx context.Context, target string) []InfrastructureAsset {
	assets := []InfrastructureAsset{}

	// Extract domain from target
	domain := extractDomainFromTarget(target)

	a.logger.Info("Starting AWS asset discovery", "target", target, "domain", domain)

	// S3 bucket discovery
	s3Assets := a.discoverS3Buckets(ctx, domain)
	assets = append(assets, s3Assets...)

	// CloudFront distribution discovery
	cfAssets := a.discoverCloudFrontDistributions(ctx, domain)
	assets = append(assets, cfAssets...)

	// ELB discovery
	elbAssets := a.discoverELBs(ctx, domain)
	assets = append(assets, elbAssets...)

	// API Gateway discovery
	apiAssets := a.discoverAPIGateways(ctx, domain)
	assets = append(assets, apiAssets...)

	// Lambda Function URLs
	lambdaAssets := a.discoverLambdaURLs(ctx, domain)
	assets = append(assets, lambdaAssets...)

	a.logger.Info("AWS asset discovery completed",
		"target", target,
		"assets_found", len(assets))

	return assets
}

// discoverS3Buckets discovers S3 buckets using various enumeration techniques
func (a *AWSDetector) discoverS3Buckets(ctx context.Context, domain string) []InfrastructureAsset {
	assets := []InfrastructureAsset{}

	// Generate S3 bucket name candidates
	bucketCandidates := a.generateS3BucketNames(domain)

	regions := []string{"us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"}

	for _, bucket := range bucketCandidates {
		for _, region := range regions {
			select {
			case <-ctx.Done():
				return assets
			default:
			}

			// Test different S3 URL formats
			urls := []string{
				fmt.Sprintf("https://%s.s3.amazonaws.com", bucket),
				fmt.Sprintf("https://%s.s3.%s.amazonaws.com", bucket, region),
				fmt.Sprintf("https://s3.amazonaws.com/%s", bucket),
				fmt.Sprintf("https://s3.%s.amazonaws.com/%s", region, bucket),
			}

			for _, url := range urls {
				if bucketInfo := a.testS3Bucket(ctx, url, bucket, region); bucketInfo != nil {
					asset := InfrastructureAsset{
						ID:         generateAssetID(AssetTypeCloudStorage, bucket),
						Type:       AssetTypeCloudStorage,
						Value:      bucket,
						Source:     "s3_enumeration",
						Confidence: bucketInfo.Confidence,
						Priority:   a.calculateS3Priority(bucketInfo),
						Tags:       []string{"s3", "aws", "cloud_storage"},
						CloudInfo: &CloudInfo{
							Provider:     CloudProviderAWS,
							Service:      "s3",
							Region:       region,
							ResourceID:   bucket,
							PublicAccess: bucketInfo.PublicAccess,
							Metadata:     bucketInfo.Metadata,
						},
						Metadata:     bucketInfo.RawMetadata,
						DiscoveredAt: time.Now(),
					}

					// Add additional tags based on bucket properties
					if bucketInfo.PublicAccess {
						asset.Tags = append(asset.Tags, "public_access")
						asset.Priority = PriorityHigh
					}
					if bucketInfo.WebsiteEnabled {
						asset.Tags = append(asset.Tags, "website_enabled")
					}
					if bucketInfo.HasSensitiveContent {
						asset.Tags = append(asset.Tags, "sensitive_content")
						asset.Priority = PriorityCritical
					}

					assets = append(assets, asset)
					break // Found bucket, no need to test other URLs
				}
			}
		}
	}

	return assets
}

// S3BucketInfo represents information about an S3 bucket
type S3BucketInfo struct {
	Name                string
	Region              string
	PublicAccess        bool
	WebsiteEnabled      bool
	HasSensitiveContent bool
	Permissions         []string
	Confidence          float64
	Metadata            map[string]string
	RawMetadata         map[string]interface{}
}

// generateS3BucketNames generates potential S3 bucket names based on domain
func (a *AWSDetector) generateS3BucketNames(domain string) []string {
	buckets := []string{}

	// Base domain variations
	baseName := strings.Replace(domain, ".", "-", -1)
	baseName = strings.Replace(baseName, "_", "-", -1)

	// Common S3 bucket patterns
	patterns := []string{
		"%s",
		"%s-backup",
		"%s-backups",
		"%s-data",
		"%s-assets",
		"%s-static",
		"%s-media",
		"%s-files",
		"%s-uploads",
		"%s-public",
		"%s-private",
		"%s-dev",
		"%s-staging",
		"%s-prod",
		"%s-production",
		"%s-test",
		"%s-testing",
		"backup-%s",
		"data-%s",
		"assets-%s",
		"static-%s",
		"media-%s",
		"files-%s",
		"uploads-%s",
		"public-%s",
		"private-%s",
		"dev-%s",
		"staging-%s",
		"prod-%s",
		"production-%s",
		"test-%s",
		"testing-%s",
	}

	// Add custom patterns from config
	if len(a.config.S3BucketPatterns) > 0 {
		patterns = append(patterns, a.config.S3BucketPatterns...)
	}

	for _, pattern := range patterns {
		bucket := fmt.Sprintf(pattern, baseName)
		if isValidS3BucketName(bucket) {
			buckets = append(buckets, bucket)
		}
	}

	// Add subdomain-based variations
	parts := strings.Split(domain, ".")
	if len(parts) > 1 {
		subdomain := parts[0]
		mainDomain := strings.Join(parts[1:], "")

		subdomainBuckets := []string{
			subdomain,
			subdomain + "-" + mainDomain,
			mainDomain + "-" + subdomain,
		}

		for _, bucket := range subdomainBuckets {
			if isValidS3BucketName(bucket) {
				buckets = append(buckets, bucket)
			}
		}
	}

	return removeDuplicates(buckets)
}

// testS3Bucket tests if an S3 bucket exists and gathers information
func (a *AWSDetector) testS3Bucket(ctx context.Context, url, bucket, region string) *S3BucketInfo {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	bucketInfo := &S3BucketInfo{
		Name:        bucket,
		Region:      region,
		Confidence:  0.0,
		Metadata:    make(map[string]string),
		RawMetadata: make(map[string]interface{}),
	}

	// Analyze response
	switch resp.StatusCode {
	case 200:
		// Bucket exists and is publicly readable
		bucketInfo.PublicAccess = true
		bucketInfo.Confidence = 1.0

		// Check for sensitive content patterns
		if containsSensitiveContent(bodyStr) {
			bucketInfo.HasSensitiveContent = true
		}

		// Parse bucket listing if available
		if strings.Contains(bodyStr, "<ListBucketResult") {
			bucketInfo.Permissions = append(bucketInfo.Permissions, "s3:ListBucket")
		}

	case 403:
		// Bucket exists but access is forbidden
		bucketInfo.PublicAccess = false
		bucketInfo.Confidence = 0.8

		// Check for specific AWS error messages
		if strings.Contains(bodyStr, "AccessDenied") {
			bucketInfo.Metadata["access_status"] = "denied"
		}

	case 404:
		// Bucket doesn't exist or is not accessible
		return nil

	case 301, 307:
		// Redirect - bucket exists but in different region
		location := resp.Header.Get("Location")
		if location != "" {
			bucketInfo.Confidence = 0.9
			bucketInfo.Metadata["redirect_location"] = location

			// Extract region from redirect location
			if regionMatch := regexp.MustCompile(`s3\.([a-z0-9-]+)\.amazonaws\.com`).FindStringSubmatch(location); len(regionMatch) > 1 {
				bucketInfo.Region = regionMatch[1]
			}
		}

	default:
		return nil
	}

	// Check for website configuration
	if resp.Header.Get("x-amz-website-redirect-location") != "" ||
		strings.Contains(bodyStr, "<WebsiteConfiguration") {
		bucketInfo.WebsiteEnabled = true
	}

	// Store response headers for additional metadata
	bucketInfo.Metadata["server"] = resp.Header.Get("Server")
	bucketInfo.Metadata["x-amz-bucket-region"] = resp.Header.Get("x-amz-bucket-region")
	bucketInfo.Metadata["x-amz-request-id"] = resp.Header.Get("x-amz-request-id")

	return bucketInfo
}

// calculateS3Priority calculates priority for S3 bucket
func (a *AWSDetector) calculateS3Priority(bucketInfo *S3BucketInfo) int {
	priority := PriorityMedium

	if bucketInfo.PublicAccess {
		priority = PriorityHigh
	}

	if bucketInfo.HasSensitiveContent {
		priority = PriorityCritical
	}

	return priority
}

// discoverCloudFrontDistributions discovers CloudFront distributions
func (a *AWSDetector) discoverCloudFrontDistributions(ctx context.Context, domain string) []InfrastructureAsset {
	assets := []InfrastructureAsset{}

	// CloudFront discovery is typically done through:
	// 1. DNS enumeration looking for *.cloudfront.net domains
	// 2. HTTP header analysis for CloudFront indicators
	// 3. SSL certificate analysis

	// This is a simplified implementation
	candidates := []string{
		domain + ".cloudfront.net",
		strings.Replace(domain, ".", "", -1) + ".cloudfront.net",
	}

	for _, candidate := range candidates {
		if cfInfo := a.testCloudFrontDistribution(ctx, candidate); cfInfo != nil {
			asset := InfrastructureAsset{
				ID:         generateAssetID(AssetTypeCDN, candidate),
				Type:       AssetTypeCDN,
				Value:      candidate,
				Source:     "cloudfront_enumeration",
				Confidence: cfInfo.Confidence,
				Priority:   PriorityMedium,
				Tags:       []string{"cloudfront", "aws", "cdn"},
				CloudInfo: &CloudInfo{
					Provider:   CloudProviderAWS,
					Service:    "cloudfront",
					ResourceID: cfInfo.DistributionID,
					Metadata:   cfInfo.Metadata,
				},
				CDNInfo: &CDNInfo{
					Provider:     "CloudFront",
					OriginServer: cfInfo.OriginServer,
					Headers:      cfInfo.Headers,
				},
				Metadata:     cfInfo.RawMetadata,
				DiscoveredAt: time.Now(),
			}

			assets = append(assets, asset)
		}
	}

	return assets
}

// CloudFrontInfo represents CloudFront distribution information
type CloudFrontInfo struct {
	DistributionID string
	OriginServer   string
	Headers        []string
	Confidence     float64
	Metadata       map[string]string
	RawMetadata    map[string]interface{}
}

// testCloudFrontDistribution tests for CloudFront distribution
func (a *AWSDetector) testCloudFrontDistribution(ctx context.Context, candidate string) *CloudFrontInfo {
	url := "https://" + candidate
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check for CloudFront headers
	cfHeaders := []string{
		"x-amz-cf-id",
		"x-amz-cf-pop",
		"x-cache",
		"via",
	}

	info := &CloudFrontInfo{
		Headers:     []string{},
		Confidence:  0.0,
		Metadata:    make(map[string]string),
		RawMetadata: make(map[string]interface{}),
	}

	headerCount := 0
	for _, header := range cfHeaders {
		if value := resp.Header.Get(header); value != "" {
			info.Headers = append(info.Headers, fmt.Sprintf("%s: %s", header, value))
			info.Metadata[header] = value
			headerCount++
		}
	}

	// Calculate confidence based on CloudFront indicators
	if headerCount >= 2 {
		info.Confidence = 0.9
	} else if headerCount == 1 {
		info.Confidence = 0.7
	} else if strings.Contains(candidate, "cloudfront.net") {
		info.Confidence = 0.5
	}

	if info.Confidence > 0 {
		return info
	}

	return nil
}

// discoverELBs discovers Elastic Load Balancers
func (a *AWSDetector) discoverELBs(ctx context.Context, domain string) []InfrastructureAsset {
	// ELB discovery implementation
	// This would involve DNS enumeration and pattern matching
	return []InfrastructureAsset{}
}

// discoverAPIGateways discovers API Gateway endpoints
func (a *AWSDetector) discoverAPIGateways(ctx context.Context, domain string) []InfrastructureAsset {
	// API Gateway discovery implementation
	// This would involve testing common API Gateway patterns
	return []InfrastructureAsset{}
}

// discoverLambdaURLs discovers Lambda function URLs
func (a *AWSDetector) discoverLambdaURLs(ctx context.Context, domain string) []InfrastructureAsset {
	// Lambda URL discovery implementation
	return []InfrastructureAsset{}
}

// GetCloudInfo gets detailed cloud information for an asset
func (a *AWSDetector) GetCloudInfo(ctx context.Context, asset InfrastructureAsset) *CloudInfo {
	// Detailed cloud information retrieval
	return nil
}

// Helper functions

func extractDomainFromTarget(target string) string {
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	parts := strings.Split(target, "/")
	domain := parts[0]

	// Remove port if present
	if colonIndex := strings.LastIndex(domain, ":"); colonIndex != -1 {
		domain = domain[:colonIndex]
	}

	return domain
}

func isValidS3BucketName(name string) bool {
	// S3 bucket naming rules
	if len(name) < 3 || len(name) > 63 {
		return false
	}

	// Must start and end with alphanumeric
	if !regexp.MustCompile(`^[a-z0-9].*[a-z0-9]$`).MatchString(name) {
		return false
	}

	// Cannot contain uppercase letters, spaces, or invalid characters
	if regexp.MustCompile(`[^a-z0-9.-]`).MatchString(name) {
		return false
	}

	// Cannot be formatted as IP address
	if regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`).MatchString(name) {
		return false
	}

	return true
}

func containsSensitiveContent(content string) bool {
	sensitivePatterns := []string{
		"password", "passwd", "pwd", "secret", "key", "token",
		"credential", "auth", "login", "admin", "config",
		"database", "db", "sql", "backup", "dump",
		"private", "confidential", "internal", "restricted",
	}

	contentLower := strings.ToLower(content)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(contentLower, pattern) {
			return true
		}
	}

	return false
}

func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	result := []string{}

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}

	return result
}

// Additional cloud detectors (Azure, GCP, Cloudflare) would be implemented similarly
// For brevity, I'll create placeholder implementations

// AzureDetector discovers Azure assets
type AzureDetector struct {
	logger     *logger.Logger
	config     *DiscoveryConfig
	httpClient *http.Client
}

func NewAzureDetector(logger *logger.Logger, config *DiscoveryConfig) *AzureDetector {
	return &AzureDetector{
		logger: logger,
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}
}

func (a *AzureDetector) DiscoverAssets(ctx context.Context, target string) []InfrastructureAsset {
	// Azure-specific discovery logic would be implemented here
	// Including Azure Blob Storage, App Services, Functions, etc.
	return []InfrastructureAsset{}
}

func (a *AzureDetector) GetCloudInfo(ctx context.Context, asset InfrastructureAsset) *CloudInfo {
	return nil
}

// GCPDetector discovers Google Cloud Platform assets
type GCPDetector struct {
	logger     *logger.Logger
	config     *DiscoveryConfig
	httpClient *http.Client
}

func NewGCPDetector(logger *logger.Logger, config *DiscoveryConfig) *GCPDetector {
	return &GCPDetector{
		logger: logger,
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}
}

func (a *GCPDetector) DiscoverAssets(ctx context.Context, target string) []InfrastructureAsset {
	// GCP-specific discovery logic would be implemented here
	// Including Cloud Storage buckets, App Engine, Cloud Functions, etc.
	return []InfrastructureAsset{}
}

func (a *GCPDetector) GetCloudInfo(ctx context.Context, asset InfrastructureAsset) *CloudInfo {
	return nil
}

// CloudflareDetector discovers Cloudflare assets
type CloudflareDetector struct {
	logger     *logger.Logger
	config     *DiscoveryConfig
	httpClient *http.Client
}

func NewCloudflareDetector(logger *logger.Logger, config *DiscoveryConfig) *CloudflareDetector {
	return &CloudflareDetector{
		logger: logger,
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}
}

func (a *CloudflareDetector) DiscoverAssets(ctx context.Context, target string) []InfrastructureAsset {
	// Cloudflare-specific discovery logic would be implemented here
	// Including Workers, Pages, R2 storage, etc.
	return []InfrastructureAsset{}
}

func (a *CloudflareDetector) GetCloudInfo(ctx context.Context, asset InfrastructureAsset) *CloudInfo {
	return nil
}
