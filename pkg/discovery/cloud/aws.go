package cloud

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// AWSDiscovery discovers AWS assets
type AWSDiscovery struct {
	client *http.Client
	logger *logger.Logger
}

// NewAWSDiscovery creates a new AWS discovery client
func NewAWSDiscovery(logger *logger.Logger) *AWSDiscovery {
	return &AWSDiscovery{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: logger,
	}
}

// S3Bucket represents an S3 bucket
type S3Bucket struct {
	Name       string
	Region     string
	URL        string
	IsPublic   bool
	Exists     bool
	HasListing bool
	Objects    []S3Object
}

// S3Object represents an object in S3
type S3Object struct {
	Key          string
	Size         int64
	LastModified time.Time
}

// DiscoverS3Buckets discovers S3 buckets for a domain
func (a *AWSDiscovery) DiscoverS3Buckets(ctx context.Context, domain string) ([]S3Bucket, error) {
	var buckets []S3Bucket
	
	// Extract base name from domain
	baseName := extractBaseName(domain)
	
	// Generate potential bucket names
	bucketNames := a.generateBucketNames(baseName, domain)
	
	// Check each potential bucket
	for _, bucketName := range bucketNames {
		bucket := a.checkS3Bucket(ctx, bucketName)
		if bucket != nil && bucket.Exists {
			buckets = append(buckets, *bucket)
		}
	}
	
	a.logger.Info("S3 bucket discovery completed",
		"domain", domain,
		"candidates_checked", len(bucketNames),
		"buckets_found", len(buckets))
	
	return buckets, nil
}

// generateBucketNames generates potential S3 bucket names
func (a *AWSDiscovery) generateBucketNames(baseName, domain string) []string {
	var names []string
	
	// Common patterns
	patterns := []string{
		"%s",
		"%s-backup",
		"%s-backups",
		"%s-logs",
		"%s-assets",
		"%s-static",
		"%s-images",
		"%s-media",
		"%s-uploads",
		"%s-files",
		"%s-data",
		"%s-content",
		"%s-archive",
		"%s-public",
		"%s-private",
		"%s-dev",
		"%s-staging",
		"%s-prod",
		"%s-production",
		"%s-test",
		"%s-www",
		"%s-web",
		"%s-api",
		"%s-cdn",
		"%s-storage",
		"backup-%s",
		"assets-%s",
		"static-%s",
		"media-%s",
		"files-%s",
		"data-%s",
		"www-%s",
		"web-%s",
		"cdn-%s",
	}
	
	// Apply patterns to base name
	for _, pattern := range patterns {
		names = append(names, fmt.Sprintf(pattern, baseName))
	}
	
	// Also try with full domain
	names = append(names, domain)
	names = append(names, strings.ReplaceAll(domain, ".", "-"))
	
	// Add year-based variations
	currentYear := time.Now().Year()
	for year := currentYear - 3; year <= currentYear; year++ {
		names = append(names, fmt.Sprintf("%s-%d", baseName, year))
		names = append(names, fmt.Sprintf("%s%d", baseName, year))
	}
	
	// Remove duplicates
	uniqueNames := make(map[string]bool)
	var result []string
	for _, name := range names {
		// S3 bucket names must be lowercase
		name = strings.ToLower(name)
		if !uniqueNames[name] && isValidBucketName(name) {
			uniqueNames[name] = true
			result = append(result, name)
		}
	}
	
	return result
}

// checkS3Bucket checks if an S3 bucket exists and its properties
func (a *AWSDiscovery) checkS3Bucket(ctx context.Context, bucketName string) *S3Bucket {
	bucket := &S3Bucket{
		Name: bucketName,
		URL:  fmt.Sprintf("https://%s.s3.amazonaws.com", bucketName),
	}
	
	// Try to access the bucket
	req, err := http.NewRequestWithContext(ctx, "GET", bucket.URL, nil)
	if err != nil {
		return bucket
	}
	
	resp, err := a.client.Do(req)
	if err != nil {
		return bucket
	}
	defer resp.Body.Close()
	
	bucket.Exists = resp.StatusCode != 404
	
	if !bucket.Exists {
		return bucket
	}
	
	// Check if bucket is public (returns 200 for listing or 403 for access denied)
	if resp.StatusCode == 200 {
		bucket.IsPublic = true
		bucket.HasListing = true
		
		// Try to parse bucket listing
		var listResult s3ListBucketResult
		if err := xml.NewDecoder(resp.Body).Decode(&listResult); err == nil {
			for _, obj := range listResult.Contents {
				bucket.Objects = append(bucket.Objects, S3Object{
					Key:          obj.Key,
					Size:         obj.Size,
					LastModified: obj.LastModified,
				})
			}
		}
	} else if resp.StatusCode == 403 {
		// Bucket exists but we don't have permission
		bucket.IsPublic = false
		
		// Try to determine region from headers
		if region := resp.Header.Get("x-amz-bucket-region"); region != "" {
			bucket.Region = region
		}
	}
	
	// Try alternate URLs if main URL failed
	if !bucket.IsPublic {
		// Try path-style URL
		pathURL := fmt.Sprintf("https://s3.amazonaws.com/%s", bucketName)
		if a.tryURL(ctx, pathURL) {
			bucket.URL = pathURL
			bucket.IsPublic = true
		}
		
		// Try regional endpoints
		regions := []string{"us-east-1", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-northeast-1"}
		for _, region := range regions {
			regionalURL := fmt.Sprintf("https://%s.s3-%s.amazonaws.com", bucketName, region)
			if a.tryURL(ctx, regionalURL) {
				bucket.URL = regionalURL
				bucket.Region = region
				bucket.IsPublic = true
				break
			}
		}
	}
	
	return bucket
}

// tryURL attempts to access a URL
func (a *AWSDiscovery) tryURL(ctx context.Context, url string) bool {
	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return false
	}
	
	resp, err := a.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return resp.StatusCode == 200
}

// s3ListBucketResult represents S3 bucket listing XML
type s3ListBucketResult struct {
	XMLName  xml.Name      `xml:"ListBucketResult"`
	Contents []s3Object    `xml:"Contents"`
}

type s3Object struct {
	Key          string    `xml:"Key"`
	Size         int64     `xml:"Size"`
	LastModified time.Time `xml:"LastModified"`
}

// DiscoverCloudFront discovers CloudFront distributions
func (a *AWSDiscovery) DiscoverCloudFront(ctx context.Context, domain string) ([]CloudFrontDistribution, error) {
	var distributions []CloudFrontDistribution
	
	// Check if domain is a CloudFront distribution
	if strings.HasSuffix(domain, ".cloudfront.net") {
		dist := CloudFrontDistribution{
			Domain:    domain,
			IsActive:  a.checkCloudFrontDomain(ctx, domain),
		}
		if dist.IsActive {
			distributions = append(distributions, dist)
		}
	}
	
	// Try common CloudFront patterns
	baseName := extractBaseName(domain)
	patterns := []string{
		"%s.cloudfront.net",
		"%s-cdn.cloudfront.net",
		"%s-static.cloudfront.net",
		"%s-assets.cloudfront.net",
		"%s-media.cloudfront.net",
		"%s-images.cloudfront.net",
	}
	
	for _, pattern := range patterns {
		cfDomain := fmt.Sprintf(pattern, baseName)
		if a.checkCloudFrontDomain(ctx, cfDomain) {
			distributions = append(distributions, CloudFrontDistribution{
				Domain:   cfDomain,
				IsActive: true,
			})
		}
	}
	
	return distributions, nil
}

// CloudFrontDistribution represents a CloudFront distribution
type CloudFrontDistribution struct {
	Domain   string
	IsActive bool
	Origins  []string
}

// checkCloudFrontDomain checks if a CloudFront domain exists
func (a *AWSDiscovery) checkCloudFrontDomain(ctx context.Context, domain string) bool {
	url := fmt.Sprintf("https://%s", domain)
	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return false
	}
	
	resp, err := a.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	return resp.StatusCode != 404
}

// DiscoverEC2Metadata attempts to find exposed EC2 metadata
func (a *AWSDiscovery) DiscoverEC2Metadata(ctx context.Context, urls []string) ([]EC2MetadataExposure, error) {
	var exposures []EC2MetadataExposure
	
	metadataPaths := []string{
		"/latest/meta-data/",
		"/latest/meta-data/ami-id",
		"/latest/meta-data/instance-id",
		"/latest/meta-data/public-keys/",
		"/latest/user-data",
		"/latest/dynamic/instance-identity/document",
	}
	
	for _, baseURL := range urls {
		for _, path := range metadataPaths {
			exposure := a.checkMetadataEndpoint(ctx, baseURL, path)
			if exposure != nil {
				exposures = append(exposures, *exposure)
			}
		}
	}
	
	return exposures, nil
}

// EC2MetadataExposure represents exposed EC2 metadata
type EC2MetadataExposure struct {
	URL          string
	Path         string
	IsExposed    bool
	ResponseData string
}

// checkMetadataEndpoint checks for exposed EC2 metadata
func (a *AWSDiscovery) checkMetadataEndpoint(ctx context.Context, baseURL, path string) *EC2MetadataExposure {
	// Common metadata URLs
	metadataURLs := []string{
		baseURL + "/latest/meta-data" + path,
		baseURL + "/169.254.169.254" + path,
		baseURL + "/metadata" + path,
	}
	
	for _, url := range metadataURLs {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		
		// EC2 metadata requires specific header in newer instances
		req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
		
		resp, err := a.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		
		if resp.StatusCode == 200 {
			// Read limited response
			buf := make([]byte, 1024)
			n, _ := resp.Body.Read(buf)
			
			return &EC2MetadataExposure{
				URL:          url,
				Path:         path,
				IsExposed:    true,
				ResponseData: string(buf[:n]),
			}
		}
	}
	
	return nil
}

// DiscoverElasticBeanstalk discovers Elastic Beanstalk applications
func (a *AWSDiscovery) DiscoverElasticBeanstalk(ctx context.Context, domain string) ([]ElasticBeanstalkApp, error) {
	var apps []ElasticBeanstalkApp
	
	// Elastic Beanstalk URL patterns
	regions := []string{
		"us-east-1", "us-east-2", "us-west-1", "us-west-2",
		"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
		"ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2",
		"sa-east-1", "ca-central-1", "ap-south-1",
	}
	
	baseName := extractBaseName(domain)
	appNames := []string{baseName, baseName + "-dev", baseName + "-prod", baseName + "-staging"}
	
	for _, appName := range appNames {
		for _, region := range regions {
			ebURL := fmt.Sprintf("http://%s.%s.elasticbeanstalk.com", appName, region)
			if a.checkElasticBeanstalkApp(ctx, ebURL) {
				apps = append(apps, ElasticBeanstalkApp{
					Name:   appName,
					Region: region,
					URL:    ebURL,
				})
			}
		}
	}
	
	return apps, nil
}

// ElasticBeanstalkApp represents an Elastic Beanstalk application
type ElasticBeanstalkApp struct {
	Name   string
	Region string
	URL    string
}

// checkElasticBeanstalkApp checks if an EB app exists
func (a *AWSDiscovery) checkElasticBeanstalkApp(ctx context.Context, url string) bool {
	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return false
	}
	
	resp, err := a.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	// EB apps usually return 200 or redirect
	return resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302
}

// Helper functions

func extractBaseName(domain string) string {
	// Remove common prefixes
	domain = strings.TrimPrefix(domain, "www.")
	domain = strings.TrimPrefix(domain, "mail.")
	
	// Get first part of domain
	parts := strings.Split(domain, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return domain
}

func isValidBucketName(name string) bool {
	// S3 bucket naming rules
	if len(name) < 3 || len(name) > 63 {
		return false
	}
	
	// Must start and end with lowercase letter or number
	matched, _ := regexp.MatchString(`^[a-z0-9][a-z0-9.-]*[a-z0-9]$`, name)
	if !matched {
		return false
	}
	
	// Cannot have consecutive periods or dashes
	if strings.Contains(name, "..") || strings.Contains(name, "--") {
		return false
	}
	
	// Cannot be formatted as IP address
	ipPattern := regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	if ipPattern.MatchString(name) {
		return false
	}
	
	return true
}

// DiscoverLambdaFunctions attempts to discover Lambda function URLs
func (a *AWSDiscovery) DiscoverLambdaFunctions(ctx context.Context, domain string) ([]LambdaFunction, error) {
	var functions []LambdaFunction
	
	// Lambda function URL patterns
	baseName := extractBaseName(domain)
	functionNames := []string{
		baseName,
		baseName + "-api",
		baseName + "-function",
		baseName + "-lambda",
		"api-" + baseName,
		"lambda-" + baseName,
	}
	
	regions := []string{
		"us-east-1", "us-east-2", "us-west-1", "us-west-2",
		"eu-west-1", "eu-west-2", "eu-central-1",
		"ap-southeast-1", "ap-northeast-1",
	}
	
	for _, funcName := range functionNames {
		for _, region := range regions {
			// Lambda function URL format
			lambdaURL := fmt.Sprintf("https://%s.lambda-url.%s.on.aws", funcName, region)
			if a.checkLambdaURL(ctx, lambdaURL) {
				functions = append(functions, LambdaFunction{
					Name:   funcName,
					Region: region,
					URL:    lambdaURL,
				})
			}
		}
	}
	
	return functions, nil
}

// LambdaFunction represents a Lambda function
type LambdaFunction struct {
	Name   string
	Region string
	URL    string
}

// checkLambdaURL checks if a Lambda function URL exists
func (a *AWSDiscovery) checkLambdaURL(ctx context.Context, url string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	
	resp, err := a.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	// Lambda URLs typically return 200, 403, or custom responses
	return resp.StatusCode != 404
}