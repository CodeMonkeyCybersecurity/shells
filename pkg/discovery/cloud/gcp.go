package cloud

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/CodeMonkeyCybersecurity/shells/internal/logger"
)

// GCPDiscovery discovers Google Cloud Platform assets
type GCPDiscovery struct {
	client *http.Client
	logger *logger.Logger
}

// NewGCPDiscovery creates a new GCP discovery client
func NewGCPDiscovery(logger *logger.Logger) *GCPDiscovery {
	return &GCPDiscovery{
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: logger,
	}
}

// GCSBucket represents a Google Cloud Storage bucket
type GCSBucket struct {
	Name       string
	URL        string
	IsPublic   bool
	Exists     bool
	HasListing bool
	Objects    []GCSObject
}

// GCSObject represents an object in GCS
type GCSObject struct {
	Name         string
	Size         int64
	LastModified time.Time
	ContentType  string
}

// DiscoverGCSBuckets discovers Google Cloud Storage buckets
func (g *GCPDiscovery) DiscoverGCSBuckets(ctx context.Context, domain string) ([]GCSBucket, error) {
	var buckets []GCSBucket

	baseName := extractBaseName(domain)

	// Generate potential bucket names
	bucketNames := g.generateBucketNames(baseName, domain)

	// Check each potential bucket
	for _, bucketName := range bucketNames {
		bucket := g.checkGCSBucket(ctx, bucketName)
		if bucket != nil && bucket.Exists {
			buckets = append(buckets, *bucket)
		}
	}

	g.logger.Info("GCS bucket discovery completed",
		"domain", domain,
		"candidates_checked", len(bucketNames),
		"buckets_found", len(buckets))

	return buckets, nil
}

// generateBucketNames generates potential GCS bucket names
func (g *GCPDiscovery) generateBucketNames(baseName, domain string) []string {
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
		"%s-gcs",
		"%s-bucket",
		"backup-%s",
		"assets-%s",
		"static-%s",
		"media-%s",
		"files-%s",
		"data-%s",
		"gcs-%s",
		"bucket-%s",
	}

	// Apply patterns
	for _, pattern := range patterns {
		names = append(names, fmt.Sprintf(pattern, baseName))
	}

	// Also try with full domain
	names = append(names, domain)
	names = append(names, strings.ReplaceAll(domain, ".", "-"))
	names = append(names, strings.ReplaceAll(domain, ".", "_"))

	// Add project-based names (common GCP pattern)
	projectPatterns := []string{
		"%s-project",
		"project-%s",
		"%s-prod-bucket",
		"%s-dev-bucket",
		"%s-staging-bucket",
	}

	for _, pattern := range projectPatterns {
		names = append(names, fmt.Sprintf(pattern, baseName))
	}

	// Remove duplicates and validate
	uniqueNames := make(map[string]bool)
	var result []string
	for _, name := range names {
		name = strings.ToLower(name)
		if !uniqueNames[name] && isValidGCSBucketName(name) {
			uniqueNames[name] = true
			result = append(result, name)
		}
	}

	return result
}

// checkGCSBucket checks if a GCS bucket exists
func (g *GCPDiscovery) checkGCSBucket(ctx context.Context, bucketName string) *GCSBucket {
	bucket := &GCSBucket{
		Name: bucketName,
		URL:  fmt.Sprintf("https://storage.googleapis.com/%s", bucketName),
	}

	// Try to list bucket contents
	req, err := http.NewRequestWithContext(ctx, "GET", bucket.URL, nil)
	if err != nil {
		return bucket
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return bucket
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case 200:
		// Bucket exists and is publicly readable
		bucket.Exists = true
		bucket.IsPublic = true
		bucket.HasListing = true

		// Parse XML listing
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // Limit to 1MB
		var listing gcsListBucketResult
		if err := xml.Unmarshal(body, &listing); err == nil {
			for _, obj := range listing.Contents {
				bucket.Objects = append(bucket.Objects, GCSObject{
					Name:         obj.Key,
					Size:         obj.Size,
					LastModified: obj.LastModified,
				})
			}
		}

	case 403:
		// Bucket exists but we don't have permission
		bucket.Exists = true
		bucket.IsPublic = false

	case 404:
		// Bucket doesn't exist
		bucket.Exists = false
	}

	// Also check the JSON API
	if !bucket.Exists {
		jsonURL := fmt.Sprintf("https://www.googleapis.com/storage/v1/b/%s", bucketName)
		jsonReq, _ := http.NewRequestWithContext(ctx, "GET", jsonURL, nil)
		if jsonResp, err := g.client.Do(jsonReq); err == nil {
			defer jsonResp.Body.Close()
			if jsonResp.StatusCode == 200 || jsonResp.StatusCode == 403 {
				bucket.Exists = true
				bucket.IsPublic = jsonResp.StatusCode == 200
			}
		}
	}

	return bucket
}

// gcsListBucketResult represents GCS bucket listing XML
type gcsListBucketResult struct {
	XMLName  xml.Name    `xml:"ListBucketResult"`
	Contents []gcsObject `xml:"Contents"`
}

type gcsObject struct {
	Key          string    `xml:"Key"`
	Size         int64     `xml:"Size"`
	LastModified time.Time `xml:"LastModified"`
}

// DiscoverAppEngine discovers Google App Engine applications
func (g *GCPDiscovery) DiscoverAppEngine(ctx context.Context, domain string) ([]AppEngineApp, error) {
	var apps []AppEngineApp

	baseName := extractBaseName(domain)

	// Common App Engine project patterns
	projectIDs := []string{
		baseName,
		baseName + "-app",
		baseName + "-api",
		baseName + "-web",
		baseName + "-dev",
		baseName + "-staging",
		baseName + "-prod",
		baseName + "-production",
		baseName + "-test",
		"app-" + baseName,
		"api-" + baseName,
		"web-" + baseName,
	}

	// Check multiple regions
	regions := []string{
		"",                     // Default (us-central)
		"uc", "us", "ue", "ul", // US regions
		"et", "ew", "eb", // Europe regions
		"an", "as", "ar", // Asia regions
		"oc", "os", // Oceania regions
	}

	for _, projectID := range projectIDs {
		for _, region := range regions {
			var appURL string
			if region == "" {
				appURL = fmt.Sprintf("https://%s.appspot.com", projectID)
			} else {
				appURL = fmt.Sprintf("https://%s.%s.r.appspot.com", projectID, region)
			}

			if g.checkAppEngine(ctx, appURL) {
				apps = append(apps, AppEngineApp{
					ProjectID: projectID,
					Region:    region,
					URL:       appURL,
				})
			}
		}
	}

	return apps, nil
}

// AppEngineApp represents a Google App Engine application
type AppEngineApp struct {
	ProjectID string
	Region    string
	URL       string
}

// checkAppEngine checks if an App Engine app exists
func (g *GCPDiscovery) checkAppEngine(ctx context.Context, url string) bool {
	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return false
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// App Engine apps typically return 200 or redirect
	return resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302
}

// DiscoverCloudRun discovers Cloud Run services
func (g *GCPDiscovery) DiscoverCloudRun(ctx context.Context, domain string) ([]CloudRunService, error) {
	var services []CloudRunService

	baseName := extractBaseName(domain)

	// Common service names
	serviceNames := []string{
		baseName,
		baseName + "-api",
		baseName + "-app",
		baseName + "-service",
		baseName + "-web",
		"api-" + baseName,
		"app-" + baseName,
		"service-" + baseName,
		"web-" + baseName,
	}

	// GCP regions with Cloud Run
	regions := []string{
		"us-central1", "us-east1", "us-east4", "us-west1", "us-west2", "us-west3", "us-west4",
		"europe-west1", "europe-west2", "europe-west3", "europe-west4", "europe-west6",
		"europe-north1", "europe-central2",
		"asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3",
		"asia-southeast1", "asia-southeast2", "asia-south1", "asia-south2",
		"australia-southeast1", "australia-southeast2",
		"northamerica-northeast1", "northamerica-northeast2",
		"southamerica-east1", "southamerica-west1",
	}

	for _, serviceName := range serviceNames {
		for _, region := range regions {
			runURL := fmt.Sprintf("https://%s-%s.a.run.app", serviceName, region)
			if g.checkCloudRun(ctx, runURL) {
				services = append(services, CloudRunService{
					Name:   serviceName,
					Region: region,
					URL:    runURL,
				})
			}
		}
	}

	return services, nil
}

// CloudRunService represents a Cloud Run service
type CloudRunService struct {
	Name   string
	Region string
	URL    string
}

// checkCloudRun checks if a Cloud Run service exists
func (g *GCPDiscovery) checkCloudRun(ctx context.Context, url string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Cloud Run services return 200, 401, 403, or custom responses
	return resp.StatusCode != 404
}

// DiscoverCloudFunctions discovers Google Cloud Functions
func (g *GCPDiscovery) DiscoverCloudFunctions(ctx context.Context, domain string) ([]CloudFunction, error) {
	var functions []CloudFunction

	baseName := extractBaseName(domain)

	// Common function names
	functionNames := []string{
		baseName,
		baseName + "-function",
		baseName + "-func",
		baseName + "-api",
		baseName + "-webhook",
		"function-" + baseName,
		"func-" + baseName,
		"api-" + baseName,
		"webhook-" + baseName,
	}

	// Common project IDs
	projectIDs := []string{
		baseName,
		baseName + "-project",
		baseName + "-prod",
		baseName + "-dev",
	}

	// Cloud Functions regions
	regions := []string{
		"us-central1", "us-east1", "us-east4", "us-west1", "us-west2", "us-west3", "us-west4",
		"europe-west1", "europe-west2", "europe-west3", "europe-west6",
		"asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3",
		"asia-southeast1", "asia-southeast2", "asia-south1",
		"australia-southeast1",
		"northamerica-northeast1",
		"southamerica-east1",
	}

	for _, projectID := range projectIDs {
		for _, funcName := range functionNames {
			for _, region := range regions {
				funcURL := fmt.Sprintf("https://%s-%s.cloudfunctions.net/%s", region, projectID, funcName)
				if g.checkCloudFunction(ctx, funcURL) {
					functions = append(functions, CloudFunction{
						Name:      funcName,
						ProjectID: projectID,
						Region:    region,
						URL:       funcURL,
					})
				}
			}
		}
	}

	return functions, nil
}

// CloudFunction represents a Google Cloud Function
type CloudFunction struct {
	Name      string
	ProjectID string
	Region    string
	URL       string
}

// checkCloudFunction checks if a Cloud Function exists
func (g *GCPDiscovery) checkCloudFunction(ctx context.Context, url string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Cloud Functions typically return 200, 401, 403, or function responses
	return resp.StatusCode != 404
}

// DiscoverFirebaseApps discovers Firebase applications
func (g *GCPDiscovery) DiscoverFirebaseApps(ctx context.Context, domain string) ([]FirebaseApp, error) {
	var apps []FirebaseApp

	baseName := extractBaseName(domain)

	// Firebase project patterns
	projectNames := []string{
		baseName,
		baseName + "-app",
		baseName + "-web",
		baseName + "-firebase",
		baseName + "-fb",
		"app-" + baseName,
		"web-" + baseName,
		"firebase-" + baseName,
		"fb-" + baseName,
	}

	for _, projectName := range projectNames {
		// Check Firebase Hosting
		hostingURL := fmt.Sprintf("https://%s.web.app", projectName)
		if g.checkFirebaseHosting(ctx, hostingURL) {
			apps = append(apps, FirebaseApp{
				ProjectID: projectName,
				Type:      "Hosting",
				URL:       hostingURL,
			})
		}

		// Also check .firebaseapp.com
		firebaseURL := fmt.Sprintf("https://%s.firebaseapp.com", projectName)
		if g.checkFirebaseHosting(ctx, firebaseURL) {
			apps = append(apps, FirebaseApp{
				ProjectID: projectName,
				Type:      "Hosting",
				URL:       firebaseURL,
			})
		}

		// Check Realtime Database
		dbURL := fmt.Sprintf("https://%s.firebaseio.com", projectName)
		if g.checkFirebaseDatabase(ctx, dbURL) {
			apps = append(apps, FirebaseApp{
				ProjectID: projectName,
				Type:      "Realtime Database",
				URL:       dbURL,
			})
		}

		// Check Firestore (requires different approach)
		// This is more complex as Firestore doesn't have predictable URLs
	}

	return apps, nil
}

// FirebaseApp represents a Firebase application
type FirebaseApp struct {
	ProjectID string
	Type      string
	URL       string
}

// checkFirebaseHosting checks if Firebase Hosting exists
func (g *GCPDiscovery) checkFirebaseHosting(ctx context.Context, url string) bool {
	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return false
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 302
}

// checkFirebaseDatabase checks if Firebase Realtime Database exists
func (g *GCPDiscovery) checkFirebaseDatabase(ctx context.Context, url string) bool {
	// Try to access .json endpoint
	jsonURL := url + "/.json"
	req, err := http.NewRequestWithContext(ctx, "GET", jsonURL, nil)
	if err != nil {
		return false
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Database exists if we get 200 (public) or 401 (auth required)
	return resp.StatusCode == 200 || resp.StatusCode == 401
}

// DiscoverBigQueryDatasets attempts to discover BigQuery datasets
func (g *GCPDiscovery) DiscoverBigQueryDatasets(ctx context.Context, domain string) ([]BigQueryDataset, error) {
	var datasets []BigQueryDataset

	baseName := extractBaseName(domain)

	// Common dataset names
	datasetNames := []string{
		baseName,
		baseName + "_data",
		baseName + "_analytics",
		baseName + "_logs",
		baseName + "_events",
		"data_" + baseName,
		"analytics_" + baseName,
		"logs_" + baseName,
		"events_" + baseName,
	}

	// Common project patterns
	projectIDs := []string{
		baseName,
		baseName + "-project",
		baseName + "-data",
		baseName + "-analytics",
	}

	// Note: BigQuery doesn't have predictable public URLs
	// This would require using the BigQuery API with credentials
	// For now, we'll return common patterns for documentation

	for _, projectID := range projectIDs {
		for _, datasetName := range datasetNames {
			datasets = append(datasets, BigQueryDataset{
				ProjectID: projectID,
				DatasetID: datasetName,
				// BigQuery doesn't have direct URLs
			})
		}
	}

	return datasets, nil
}

// BigQueryDataset represents a BigQuery dataset
type BigQueryDataset struct {
	ProjectID string
	DatasetID string
}

// Helper functions

func isValidGCSBucketName(name string) bool {
	// GCS bucket naming rules
	if len(name) < 3 || len(name) > 63 {
		return false
	}

	// Must start and end with letter or number
	// Can contain lowercase letters, numbers, hyphens, underscores, periods
	matched, _ := regexp.MatchString(`^[a-z0-9][a-z0-9._-]*[a-z0-9]$`, name)
	return matched
}
