package infrastructure

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/CodeMonkeyCybersecurity/artemis/internal/httpclient"
	"github.com/CodeMonkeyCybersecurity/artemis/internal/logger"
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

	a.logger.Infow("Starting AWS asset discovery", "target", target, "domain", domain)

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
	defer httpclient.CloseBody(resp)

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
	defer httpclient.CloseBody(resp)

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
	patterns   map[string]*regexp.Regexp
}

func NewAzureDetector(logger *logger.Logger, config *DiscoveryConfig) *AzureDetector {
	detector := &AzureDetector{
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

// initializePatterns initializes Azure-specific regex patterns
func (a *AzureDetector) initializePatterns() {
	// Blob Storage patterns
	a.patterns["blob_storage"] = regexp.MustCompile(`^([a-z0-9]+)\.blob\.core\.windows\.net$`)

	// App Services patterns
	a.patterns["app_service"] = regexp.MustCompile(`^([a-z0-9-]+)\.azurewebsites\.net$`)
	a.patterns["app_service_slot"] = regexp.MustCompile(`^([a-z0-9-]+)-([a-z0-9]+)\.azurewebsites\.net$`)

	// Azure Functions patterns
	a.patterns["function_app"] = regexp.MustCompile(`^([a-z0-9-]+)\.azurewebsites\.net/api/`)

	// Azure Kubernetes Service (AKS) patterns
	a.patterns["aks"] = regexp.MustCompile(`^([a-z0-9-]+)\.([a-z0-9-]+)\.azmk8s\.io$`)

	// Azure Container Instances patterns
	a.patterns["aci"] = regexp.MustCompile(`^([a-z0-9-]+)\.([a-z0-9-]+)\.azurecontainer\.io$`)

	// Azure CDN patterns
	a.patterns["cdn"] = regexp.MustCompile(`^([a-z0-9-]+)\.azureedge\.net$`)

	// Azure API Management patterns
	a.patterns["apim"] = regexp.MustCompile(`^([a-z0-9-]+)\.azure-api\.net$`)
}

func (a *AzureDetector) DiscoverAssets(ctx context.Context, target string) []InfrastructureAsset {
	assets := []InfrastructureAsset{}

	domain := extractDomainFromTarget(target)

	a.logger.Infow("Starting Azure asset discovery", "target", target, "domain", domain)

	// Blob Storage discovery
	blobAssets := a.discoverBlobStorage(ctx, domain)
	assets = append(assets, blobAssets...)

	// App Services discovery
	appAssets := a.discoverAppServices(ctx, domain)
	assets = append(assets, appAssets...)

	// Azure Functions discovery
	funcAssets := a.discoverFunctions(ctx, domain)
	assets = append(assets, funcAssets...)

	// AKS discovery
	aksAssets := a.discoverAKS(ctx, domain)
	assets = append(assets, aksAssets...)

	a.logger.Info("Azure asset discovery completed",
		"target", target,
		"assets_found", len(assets))

	return assets
}

// discoverBlobStorage discovers Azure Blob Storage accounts
func (a *AzureDetector) discoverBlobStorage(ctx context.Context, domain string) []InfrastructureAsset {
	assets := []InfrastructureAsset{}

	// Generate storage account name candidates
	storageNames := a.generateStorageNames(domain)

	for _, storageName := range storageNames {
		select {
		case <-ctx.Done():
			return assets
		default:
		}

		// Test Blob Storage URL
		url := fmt.Sprintf("https://%s.blob.core.windows.net", storageName)

		if blobInfo := a.testBlobStorage(ctx, url, storageName); blobInfo != nil {
			asset := InfrastructureAsset{
				ID:         generateAssetID(AssetTypeCloudStorage, storageName),
				Type:       AssetTypeCloudStorage,
				Value:      storageName,
				Source:     "azure_blob_enumeration",
				Confidence: blobInfo.Confidence,
				Priority:   a.calculateBlobPriority(blobInfo),
				Tags:       []string{"blob", "azure", "cloud_storage"},
				CloudInfo: &CloudInfo{
					Provider:     CloudProviderAzure,
					Service:      "blob",
					ResourceID:   storageName,
					PublicAccess: blobInfo.PublicAccess,
					Metadata:     blobInfo.Metadata,
				},
				Metadata:     blobInfo.RawMetadata,
				DiscoveredAt: time.Now(),
			}

			if blobInfo.PublicAccess {
				asset.Tags = append(asset.Tags, "public_access")
				asset.Priority = PriorityHigh
			}

			assets = append(assets, asset)
		}
	}

	return assets
}

// BlobStorageInfo represents Azure Blob Storage information
type BlobStorageInfo struct {
	Name         string
	PublicAccess bool
	Confidence   float64
	Metadata     map[string]string
	RawMetadata  map[string]interface{}
}

// generateStorageNames generates potential Azure storage account names
func (a *AzureDetector) generateStorageNames(domain string) []string {
	storageNames := []string{}

	// Azure storage names: 3-24 chars, lowercase alphanumeric only
	baseName := strings.Replace(domain, ".", "", -1)
	baseName = strings.Replace(baseName, "-", "", -1)
	baseName = strings.Replace(baseName, "_", "", -1)
	baseName = strings.ToLower(baseName)

	// Truncate if too long
	if len(baseName) > 20 {
		baseName = baseName[:20]
	}

	// Common Azure storage patterns
	patterns := []string{
		"%s",
		"%sdata",
		"%sstorage",
		"%sblob",
		"%sfiles",
		"%spublic",
		"%sprivate",
		"%sbackup",
		"data%s",
		"storage%s",
		"blob%s",
	}

	for _, pattern := range patterns {
		name := fmt.Sprintf(pattern, baseName)
		if isValidAzureStorageName(name) {
			storageNames = append(storageNames, name)
		}
	}

	return removeDuplicates(storageNames)
}

// testBlobStorage tests if Azure Blob Storage account exists
func (a *AzureDetector) testBlobStorage(ctx context.Context, url, storageName string) *BlobStorageInfo {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	blobInfo := &BlobStorageInfo{
		Name:        storageName,
		Confidence:  0.0,
		Metadata:    make(map[string]string),
		RawMetadata: make(map[string]interface{}),
	}

	// Analyze response
	switch resp.StatusCode {
	case 200:
		// Storage account exists and is publicly readable
		blobInfo.PublicAccess = true
		blobInfo.Confidence = 1.0

	case 404:
		// Account doesn't exist
		return nil

	case 400:
		// Account exists but access denied
		blobInfo.PublicAccess = false
		blobInfo.Confidence = 0.8

	default:
		return nil
	}

	// Store response headers
	blobInfo.Metadata["server"] = resp.Header.Get("Server")
	blobInfo.Metadata["x-ms-request-id"] = resp.Header.Get("x-ms-request-id")
	blobInfo.Metadata["x-ms-version"] = resp.Header.Get("x-ms-version")

	return blobInfo
}

// calculateBlobPriority calculates priority for Azure Blob Storage
func (a *AzureDetector) calculateBlobPriority(blobInfo *BlobStorageInfo) int {
	if blobInfo.PublicAccess {
		return PriorityHigh
	}
	return PriorityMedium
}

// discoverAppServices discovers Azure App Services
func (a *AzureDetector) discoverAppServices(ctx context.Context, domain string) []InfrastructureAsset {
	assets := []InfrastructureAsset{}

	// Generate app service name candidates
	appNames := a.generateAppServiceNames(domain)

	for _, appName := range appNames {
		select {
		case <-ctx.Done():
			return assets
		default:
		}

		url := fmt.Sprintf("https://%s.azurewebsites.net", appName)

		if appInfo := a.testAppService(ctx, url, appName); appInfo != nil {
			asset := InfrastructureAsset{
				ID:         generateAssetID(AssetTypeWebApp, appName),
				Type:       AssetTypeWebApp,
				Value:      fmt.Sprintf("%s.azurewebsites.net", appName),
				Source:     "azure_app_enumeration",
				Confidence: appInfo.Confidence,
				Priority:   PriorityMedium,
				Tags:       []string{"app_service", "azure", "web_app"},
				CloudInfo: &CloudInfo{
					Provider:   CloudProviderAzure,
					Service:    "app_service",
					ResourceID: appName,
					Metadata:   appInfo.Metadata,
				},
				Metadata:     appInfo.RawMetadata,
				DiscoveredAt: time.Now(),
			}

			assets = append(assets, asset)
		}
	}

	return assets
}

// AppServiceInfo represents Azure App Service information
type AppServiceInfo struct {
	Name        string
	Confidence  float64
	Metadata    map[string]string
	RawMetadata map[string]interface{}
}

// generateAppServiceNames generates potential Azure App Service names
func (a *AzureDetector) generateAppServiceNames(domain string) []string {
	appNames := []string{}

	baseName := strings.Replace(domain, ".", "-", -1)

	patterns := []string{
		"%s",
		"%s-api",
		"%s-app",
		"%s-web",
		"%s-dev",
		"%s-staging",
		"%s-prod",
		"api-%s",
		"app-%s",
		"web-%s",
	}

	for _, pattern := range patterns {
		name := fmt.Sprintf(pattern, baseName)
		appNames = append(appNames, name)
	}

	return removeDuplicates(appNames)
}

// testAppService tests if Azure App Service exists
func (a *AzureDetector) testAppService(ctx context.Context, url, appName string) *AppServiceInfo {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer httpclient.CloseBody(resp)

	// Check for Azure App Service indicators
	server := resp.Header.Get("Server")
	if !strings.Contains(server, "Microsoft") && !strings.Contains(server, "IIS") {
		return nil
	}

	appInfo := &AppServiceInfo{
		Name:        appName,
		Confidence:  0.7,
		Metadata:    make(map[string]string),
		RawMetadata: make(map[string]interface{}),
	}

	appInfo.Metadata["server"] = server
	appInfo.Metadata["x-powered-by"] = resp.Header.Get("X-Powered-By")

	return appInfo
}

// discoverFunctions discovers Azure Functions
func (a *AzureDetector) discoverFunctions(ctx context.Context, domain string) []InfrastructureAsset {
	// Azure Functions use same *.azurewebsites.net domain as App Services
	// Differentiated by /api/ path and Function runtime headers
	assets := []InfrastructureAsset{}

	appNames := a.generateAppServiceNames(domain)

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, appName := range appNames {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			default:
			}

			url := fmt.Sprintf("https://%s.azurewebsites.net/api", name)

			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				return
			}

			resp, err := a.httpClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			// Check for Azure Functions indicators
			isFunctionApp := false

			// Check for Azure Functions specific headers
			if runtime := resp.Header.Get("X-Azure-Functionruntime"); runtime != "" {
				isFunctionApp = true
			}

			// Check for Functions-specific response patterns
			if resp.StatusCode == 401 || resp.StatusCode == 403 {
				// Functions often return 401/403 for unauthorized API access
				if contentType := resp.Header.Get("Content-Type"); strings.Contains(contentType, "json") {
					isFunctionApp = true
				}
			}

			if isFunctionApp {
				asset := InfrastructureAsset{
					Type:  AssetTypeFunction,
					Value: fmt.Sprintf("%s.azurewebsites.net", name),
					CloudInfo: &CloudInfo{
						Provider: CloudProviderAzure,
						Service:  "functions",
						Region:   resp.Header.Get("X-Azure-Ref"),
					},
					Priority: 80, // Functions are high-value targets
					Metadata: map[string]interface{}{
						"runtime":     resp.Header.Get("X-Azure-Functionruntime"),
						"app_name":    name,
						"api_path":    "/api",
						"status_code": resp.StatusCode,
					},
				}

				mu.Lock()
				assets = append(assets, asset)
				mu.Unlock()

				a.logger.Infow("Azure Functions app discovered",
					"app_name", name,
					"url", asset.Value,
					"runtime", resp.Header.Get("X-Azure-Functionruntime"),
				)
			}
		}(appName)
	}

	wg.Wait()
	return assets
}

// discoverAKS discovers Azure Kubernetes Service clusters
func (a *AzureDetector) discoverAKS(ctx context.Context, domain string) []InfrastructureAsset {
	// AKS clusters use *.*.azmk8s.io pattern
	// Format: <cluster-name>.<region>.azmk8s.io
	// Typically private, but public clusters expose API endpoints
	assets := []InfrastructureAsset{}

	// Generate cluster name candidates
	clusterNames := a.generateAKSNames(domain)

	// Common Azure regions
	regions := []string{
		"eastus", "eastus2", "westus", "westus2", "centralus",
		"northeurope", "westeurope", "uksouth", "ukwest",
		"southeastasia", "eastasia", "australiaeast", "australiasoutheast",
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, clusterName := range clusterNames {
		for _, region := range regions {
			wg.Add(1)
			go func(cluster, reg string) {
				defer wg.Done()

				select {
				case <-ctx.Done():
					return
				default:
				}

				// AKS API endpoint format
				url := fmt.Sprintf("https://%s.%s.azmk8s.io", cluster, reg)

				req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
				if err != nil {
					return
				}

				resp, err := a.httpClient.Do(req)
				if err != nil {
					// DNS resolution failure means cluster doesn't exist
					return
				}
				defer resp.Body.Close()

				// AKS clusters typically return 403 Forbidden for unauthenticated access
				// or redirect to Azure AD login
				if resp.StatusCode == 403 || resp.StatusCode == 401 {
					asset := InfrastructureAsset{
						Type:  AssetTypeKubernetes,
						Value: fmt.Sprintf("%s.%s.azmk8s.io", cluster, reg),
						CloudInfo: &CloudInfo{
							Provider: CloudProviderAzure,
							Service:  "aks",
							Region:   reg,
						},
						Priority: 90, // Kubernetes clusters are critical assets
						Metadata: map[string]interface{}{
							"cluster_name": cluster,
							"region":       reg,
							"access":       "private", // Requires authentication
							"status_code":  resp.StatusCode,
						},
					}

					mu.Lock()
					assets = append(assets, asset)
					mu.Unlock()

					a.logger.Infow("Azure AKS cluster discovered",
						"cluster_name", cluster,
						"region", reg,
						"url", asset.Value,
					)
				}
			}(clusterName, region)
		}
	}

	wg.Wait()
	return assets
}

// generateAKSNames generates potential AKS cluster names from domain
func (a *AzureDetector) generateAKSNames(domain string) []string {
	names := []string{}

	// Remove TLD
	baseName := strings.TrimSuffix(domain, filepath.Ext(domain))
	baseName = strings.ReplaceAll(baseName, ".", "-")

	// Common AKS naming patterns
	patterns := []string{
		"%s",
		"%s-aks",
		"%s-cluster",
		"%s-k8s",
		"aks-%s",
		"k8s-%s",
		"%s-prod",
		"%s-dev",
		"%s-staging",
	}

	for _, pattern := range patterns {
		name := fmt.Sprintf(pattern, baseName)
		names = append(names, name)
	}

	return names
}

func (a *AzureDetector) GetCloudInfo(ctx context.Context, asset InfrastructureAsset) *CloudInfo {
	// Detailed cloud information retrieval
	return nil
}

// isValidAzureStorageName validates Azure storage account naming rules
func isValidAzureStorageName(name string) bool {
	// Must be 3-24 characters
	if len(name) < 3 || len(name) > 24 {
		return false
	}

	// Must be lowercase letters and numbers only
	if !regexp.MustCompile(`^[a-z0-9]+$`).MatchString(name) {
		return false
	}

	return true
}

// GCPDetector discovers Google Cloud Platform assets
type GCPDetector struct {
	logger     *logger.Logger
	config     *DiscoveryConfig
	httpClient *http.Client
	patterns   map[string]*regexp.Regexp
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
		patterns: map[string]*regexp.Regexp{
			"storage":        regexp.MustCompile(`\.storage\.googleapis\.com$`),
			"appengine":      regexp.MustCompile(`\.appspot\.com$`),
			"functions":      regexp.MustCompile(`\.cloudfunctions\.net$`),
			"run":            regexp.MustCompile(`\.run\.app$`),
			"firebase":       regexp.MustCompile(`\.firebaseapp\.com$`),
			"firebase_db":    regexp.MustCompile(`\.firebaseio\.com$`),
			"cloudfront_gcp": regexp.MustCompile(`\.web\.app$`),
		},
	}
}

func (g *GCPDetector) DiscoverAssets(ctx context.Context, target string) []InfrastructureAsset {
	g.logger.Infow("Starting GCP asset discovery",
		"target", target,
	)

	assets := []InfrastructureAsset{}

	// Check if target matches GCP patterns
	for service, pattern := range g.patterns {
		if pattern.MatchString(target) {
			g.logger.Infow("Target matches GCP pattern",
				"target", target,
				"service", service,
			)
		}
	}

	// Discover different GCP services in parallel
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Cloud Storage buckets
	wg.Add(1)
	go func() {
		defer wg.Done()
		storageAssets := g.discoverCloudStorage(ctx, target)
		mu.Lock()
		assets = append(assets, storageAssets...)
		mu.Unlock()
	}()

	// App Engine
	wg.Add(1)
	go func() {
		defer wg.Done()
		appEngineAssets := g.discoverAppEngine(ctx, target)
		mu.Lock()
		assets = append(assets, appEngineAssets...)
		mu.Unlock()
	}()

	// Cloud Functions
	wg.Add(1)
	go func() {
		defer wg.Done()
		functionAssets := g.discoverCloudFunctions(ctx, target)
		mu.Lock()
		assets = append(assets, functionAssets...)
		mu.Unlock()
	}()

	// Cloud Run
	wg.Add(1)
	go func() {
		defer wg.Done()
		runAssets := g.discoverCloudRun(ctx, target)
		mu.Lock()
		assets = append(assets, runAssets...)
		mu.Unlock()
	}()

	wg.Wait()

	g.logger.Infow("GCP asset discovery completed",
		"target", target,
		"assets_found", len(assets),
	)

	return assets
}

// discoverCloudStorage discovers GCS buckets
func (g *GCPDetector) discoverCloudStorage(ctx context.Context, domain string) []InfrastructureAsset {
	assets := []InfrastructureAsset{}

	// Generate bucket name candidates
	bucketNames := g.generateBucketNames(domain)

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, bucketName := range bucketNames {
		wg.Add(1)
		go func(bucket string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			default:
			}

			// Test GCS bucket URL
			url := fmt.Sprintf("https://storage.googleapis.com/%s", bucket)

			if bucketInfo := g.testCloudStorage(ctx, url, bucket); bucketInfo != nil {
				asset := InfrastructureAsset{
					Type:  AssetTypeCloudStorage,
					Value: fmt.Sprintf("%s.storage.googleapis.com", bucket),
					CloudInfo: &CloudInfo{
						Provider:     CloudProviderGCP,
						Service:      "storage",
						PublicAccess: bucketInfo.PublicAccess,
						Region:       bucketInfo.Region,
					},
					Priority: bucketInfo.Priority,
					Metadata: map[string]interface{}{
						"bucket_name":   bucket,
						"access":        bucketInfo.Access,
						"storage_class": bucketInfo.StorageClass,
					},
				}

				mu.Lock()
				assets = append(assets, asset)
				mu.Unlock()

				g.logger.Infow("GCS bucket discovered",
					"bucket", bucket,
					"public_access", bucketInfo.PublicAccess,
					"priority", bucketInfo.Priority,
				)
			}
		}(bucketName)
	}

	wg.Wait()
	return assets
}

// generateBucketNames generates potential GCS bucket names
func (g *GCPDetector) generateBucketNames(domain string) []string {
	names := []string{}

	// Remove TLD
	baseName := strings.TrimSuffix(domain, filepath.Ext(domain))
	baseName = strings.ReplaceAll(baseName, ".", "-")

	// Common GCS bucket naming patterns
	patterns := []string{
		"%s",
		"%s-bucket",
		"%s-storage",
		"%s-backup",
		"%s-data",
		"%s-uploads",
		"%s-static",
		"%s-assets",
		"%s-prod",
		"%s-dev",
		"%s-staging",
		"gs-%s",
		"gcs-%s",
	}

	for _, pattern := range patterns {
		name := fmt.Sprintf(pattern, baseName)
		names = append(names, name)
	}

	return names
}

type gcsBucketInfo struct {
	BucketName   string
	PublicAccess bool
	Access       string
	Region       string
	StorageClass string
	Priority     int
}

// testCloudStorage tests GCS bucket accessibility
func (g *GCPDetector) testCloudStorage(ctx context.Context, url, bucketName string) *gcsBucketInfo {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode == 404 {
		return nil // Bucket doesn't exist
	}

	bucketInfo := &gcsBucketInfo{
		BucketName: bucketName,
	}

	// Analyze access level
	switch resp.StatusCode {
	case 200:
		bucketInfo.PublicAccess = true
		bucketInfo.Access = "public_read"
		bucketInfo.Priority = 95 // Critical: Public bucket
	case 403:
		bucketInfo.PublicAccess = false
		bucketInfo.Access = "private"
		bucketInfo.Priority = 70 // Medium: Private bucket exists
	case 401:
		bucketInfo.PublicAccess = false
		bucketInfo.Access = "auth_required"
		bucketInfo.Priority = 75 // Private bucket, authentication required
	}

	// Extract region and storage class from headers if available
	if location := resp.Header.Get("X-Goog-Storage-Class"); location != "" {
		bucketInfo.StorageClass = location
	}

	return bucketInfo
}

// discoverAppEngine discovers App Engine applications
func (g *GCPDetector) discoverAppEngine(ctx context.Context, domain string) []InfrastructureAsset {
	assets := []InfrastructureAsset{}

	appNames := g.generateAppEngineNames(domain)

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, appName := range appNames {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			default:
			}

			url := fmt.Sprintf("https://%s.appspot.com", name)

			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				return
			}

			resp, err := g.httpClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			// App Engine apps typically respond with 200, 302, or 404
			if resp.StatusCode != 404 {
				asset := InfrastructureAsset{
					Type:  AssetTypeWebApp,
					Value: fmt.Sprintf("%s.appspot.com", name),
					CloudInfo: &CloudInfo{
						Provider: CloudProviderGCP,
						Service:  "appengine",
					},
					Priority: 80, // App Engine is high-value
					Metadata: map[string]interface{}{
						"app_name":    name,
						"status_code": fmt.Sprintf("%d", resp.StatusCode),
						"server":      resp.Header.Get("Server"),
					},
				}

				mu.Lock()
				assets = append(assets, asset)
				mu.Unlock()

				g.logger.Infow("App Engine application discovered",
					"app_name", name,
					"url", asset.Value,
				)
			}
		}(appName)
	}

	wg.Wait()
	return assets
}

// generateAppEngineNames generates potential App Engine names
func (g *GCPDetector) generateAppEngineNames(domain string) []string {
	names := []string{}

	baseName := strings.TrimSuffix(domain, filepath.Ext(domain))
	baseName = strings.ReplaceAll(baseName, ".", "-")

	patterns := []string{
		"%s",
		"%s-app",
		"%s-api",
		"%s-web",
		"%s-prod",
		"%s-dev",
		"%s-staging",
		"app-%s",
		"api-%s",
	}

	for _, pattern := range patterns {
		name := fmt.Sprintf(pattern, baseName)
		names = append(names, name)
	}

	return names
}

// discoverCloudFunctions discovers Cloud Functions
func (g *GCPDetector) discoverCloudFunctions(ctx context.Context, domain string) []InfrastructureAsset {
	assets := []InfrastructureAsset{}

	functionNames := g.generateFunctionNames(domain)

	// Cloud Functions regions
	regions := []string{
		"us-central1", "us-east1", "us-west1",
		"europe-west1", "europe-west2", "europe-west3",
		"asia-east1", "asia-northeast1", "asia-southeast1",
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, funcName := range functionNames {
		for _, region := range regions {
			wg.Add(1)
			go func(fn, reg string) {
				defer wg.Done()

				select {
				case <-ctx.Done():
					return
				default:
				}

				// Cloud Functions URL format: https://<region>-<project-id>.cloudfunctions.net/<function-name>
				// We can't know project-id, but test common patterns
				url := fmt.Sprintf("https://%s-%s.cloudfunctions.net/%s", reg, fn, fn)

				req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
				if err != nil {
					return
				}

				resp, err := g.httpClient.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()

				// Cloud Functions return various status codes (200, 403, 401, 500)
				if resp.StatusCode != 404 {
					asset := InfrastructureAsset{
						Type:  AssetTypeFunction,
						Value: fmt.Sprintf("%s-%s.cloudfunctions.net/%s", reg, fn, fn),
						CloudInfo: &CloudInfo{
							Provider: CloudProviderGCP,
							Service:  "functions",
							Region:   reg,
						},
						Priority: 85, // Functions are valuable targets
						Metadata: map[string]interface{}{
							"function_name": fn,
							"region":        reg,
							"status_code":   fmt.Sprintf("%d", resp.StatusCode),
						},
					}

					mu.Lock()
					assets = append(assets, asset)
					mu.Unlock()

					g.logger.Infow("Cloud Function discovered",
						"function_name", fn,
						"region", reg,
						"url", asset.Value,
					)
				}
			}(funcName, region)
		}
	}

	wg.Wait()
	return assets
}

// generateFunctionNames generates potential Cloud Function names
func (g *GCPDetector) generateFunctionNames(domain string) []string {
	names := []string{}

	baseName := strings.TrimSuffix(domain, filepath.Ext(domain))
	baseName = strings.ReplaceAll(baseName, ".", "-")

	patterns := []string{
		"%s",
		"%s-function",
		"%s-api",
		"%s-handler",
		"function-%s",
		"api-%s",
	}

	for _, pattern := range patterns {
		name := fmt.Sprintf(pattern, baseName)
		names = append(names, name)
	}

	return names
}

// discoverCloudRun discovers Cloud Run services
func (g *GCPDetector) discoverCloudRun(ctx context.Context, domain string) []InfrastructureAsset {
	assets := []InfrastructureAsset{}

	serviceNames := g.generateCloudRunNames(domain)

	// Cloud Run regions
	regions := []string{
		"us-central1", "us-east1", "us-west1",
		"europe-west1", "europe-west2", "europe-west3",
		"asia-east1", "asia-northeast1", "asia-southeast1",
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, serviceName := range serviceNames {
		for _, region := range regions {
			wg.Add(1)
			go func(svc, reg string) {
				defer wg.Done()

				select {
				case <-ctx.Done():
					return
				default:
				}

				// Cloud Run URL format: https://<service-name>-<random-hash>-<region>.run.app
				// Test without hash (some services use predictable names)
				url := fmt.Sprintf("https://%s-%s.run.app", svc, reg)

				req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
				if err != nil {
					return
				}

				resp, err := g.httpClient.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()

				// Cloud Run returns 200, 403, 401, 500, etc. for valid services
				if resp.StatusCode != 404 {
					asset := InfrastructureAsset{
						Type:  AssetTypeWebApp,
						Value: fmt.Sprintf("%s-%s.run.app", svc, reg),
						CloudInfo: &CloudInfo{
							Provider: CloudProviderGCP,
							Service:  "run",
							Region:   reg,
						},
						Priority: 80, // Cloud Run is high-value
						Metadata: map[string]interface{}{
							"service_name": svc,
							"region":       reg,
							"status_code":  fmt.Sprintf("%d", resp.StatusCode),
						},
					}

					mu.Lock()
					assets = append(assets, asset)
					mu.Unlock()

					g.logger.Infow("Cloud Run service discovered",
						"service_name", svc,
						"region", reg,
						"url", asset.Value,
					)
				}
			}(serviceName, region)
		}
	}

	wg.Wait()
	return assets
}

// generateCloudRunNames generates potential Cloud Run service names
func (g *GCPDetector) generateCloudRunNames(domain string) []string {
	names := []string{}

	baseName := strings.TrimSuffix(domain, filepath.Ext(domain))
	baseName = strings.ReplaceAll(baseName, ".", "-")

	patterns := []string{
		"%s",
		"%s-service",
		"%s-api",
		"%s-web",
		"%s-app",
		"service-%s",
		"api-%s",
	}

	for _, pattern := range patterns {
		name := fmt.Sprintf(pattern, baseName)
		names = append(names, name)
	}

	return names
}

func (g *GCPDetector) GetCloudInfo(ctx context.Context, asset InfrastructureAsset) *CloudInfo {
	// Detailed cloud information retrieval
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
