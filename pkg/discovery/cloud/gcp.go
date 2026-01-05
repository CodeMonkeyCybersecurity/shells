package cloud

import (
	"context"
	"encoding/xml"
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

// GCPAssets represents all discovered GCP assets
type GCPAssets struct {
	ProjectIDs         []string
	GCSBuckets         []GCSBucket
	AppEngineApps      []AppEngineApp
	CloudRunServices   []CloudRunService
	CloudFunctions     []CloudFunction
	FirebaseApps       []FirebaseApp
	BigQueryDatasets   []BigQueryDataset
	ComputeInstances   []ComputeInstance
	GKEClusters        []GKECluster
	PubSubTopics       []PubSubTopic
	CloudSQLInstances  []CloudSQLInstance
	CloudBuildConfigs  []CloudBuildConfig
	SourceRepositories []SourceRepository
	MetadataExposures  []GCPMetadataExposure
	APIEndpoints       []GCPAPIEndpoint
	Secrets            []GCPSecret
	ServiceAccounts    []ServiceAccount
}

// DiscoverAll performs comprehensive GCP asset discovery
func (g *GCPDiscovery) DiscoverAll(ctx context.Context, domain string, urls []string) (*GCPAssets, error) {
	assets := &GCPAssets{}

	// Run all discovery functions concurrently
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Discover GCS buckets
	wg.Add(1)
	go func() {
		defer wg.Done()
		if buckets, err := g.DiscoverGCSBuckets(ctx, domain); err == nil {
			mu.Lock()
			assets.GCSBuckets = buckets
			mu.Unlock()
		}
	}()

	// Discover App Engine apps
	wg.Add(1)
	go func() {
		defer wg.Done()
		if apps, err := g.DiscoverAppEngine(ctx, domain); err == nil {
			mu.Lock()
			assets.AppEngineApps = apps
			mu.Unlock()
		}
	}()

	// Discover Cloud Run services
	wg.Add(1)
	go func() {
		defer wg.Done()
		if services, err := g.DiscoverCloudRun(ctx, domain); err == nil {
			mu.Lock()
			assets.CloudRunServices = services
			mu.Unlock()
		}
	}()

	// Discover Cloud Functions
	wg.Add(1)
	go func() {
		defer wg.Done()
		if functions, err := g.DiscoverCloudFunctions(ctx, domain); err == nil {
			mu.Lock()
			assets.CloudFunctions = functions
			mu.Unlock()
		}
	}()

	// Discover Firebase apps
	wg.Add(1)
	go func() {
		defer wg.Done()
		if apps, err := g.DiscoverFirebaseApps(ctx, domain); err == nil {
			mu.Lock()
			assets.FirebaseApps = apps
			mu.Unlock()
		}
	}()

	// Discover BigQuery datasets
	wg.Add(1)
	go func() {
		defer wg.Done()
		if datasets, err := g.DiscoverBigQueryDatasets(ctx, domain); err == nil {
			mu.Lock()
			assets.BigQueryDatasets = datasets
			mu.Unlock()
		}
	}()

	// Discover Compute Engine instances
	wg.Add(1)
	go func() {
		defer wg.Done()
		if instances, err := g.DiscoverComputeEngine(ctx, domain); err == nil {
			mu.Lock()
			assets.ComputeInstances = instances
			mu.Unlock()
		}
	}()

	// Discover GKE clusters
	wg.Add(1)
	go func() {
		defer wg.Done()
		if clusters, err := g.DiscoverGKEClusters(ctx, domain); err == nil {
			mu.Lock()
			assets.GKEClusters = clusters
			mu.Unlock()
		}
	}()

	// Discover Pub/Sub topics
	wg.Add(1)
	go func() {
		defer wg.Done()
		if topics, err := g.DiscoverPubSubTopics(ctx, domain); err == nil {
			mu.Lock()
			assets.PubSubTopics = topics
			mu.Unlock()
		}
	}()

	// Discover Cloud SQL instances
	wg.Add(1)
	go func() {
		defer wg.Done()
		if instances, err := g.DiscoverCloudSQL(ctx, domain); err == nil {
			mu.Lock()
			assets.CloudSQLInstances = instances
			mu.Unlock()
		}
	}()

	// Discover Cloud Build configs
	wg.Add(1)
	go func() {
		defer wg.Done()
		if configs, err := g.DiscoverCloudBuild(ctx, domain); err == nil {
			mu.Lock()
			assets.CloudBuildConfigs = configs
			mu.Unlock()
		}
	}()

	// Discover Source Repositories
	wg.Add(1)
	go func() {
		defer wg.Done()
		if repos, err := g.DiscoverSourceRepositories(ctx, domain); err == nil {
			mu.Lock()
			assets.SourceRepositories = repos
			mu.Unlock()
		}
	}()

	// Discover GCP APIs
	wg.Add(1)
	go func() {
		defer wg.Done()
		if endpoints, err := g.DiscoverGCPAPIs(ctx, domain); err == nil {
			mu.Lock()
			assets.APIEndpoints = endpoints
			mu.Unlock()
		}
	}()

	// Discover secrets
	wg.Add(1)
	go func() {
		defer wg.Done()
		if secrets, err := g.DiscoverGCPSecrets(ctx, domain); err == nil {
			mu.Lock()
			assets.Secrets = secrets
			mu.Unlock()
		}
	}()

	// Discover project IDs
	wg.Add(1)
	go func() {
		defer wg.Done()
		if projectIDs, err := g.DiscoverProjectIDs(ctx, domain); err == nil {
			mu.Lock()
			assets.ProjectIDs = projectIDs
			mu.Unlock()
		}
	}()

	// Discover service accounts
	wg.Add(1)
	go func() {
		defer wg.Done()
		if accounts, err := g.DiscoverServiceAccounts(ctx, domain); err == nil {
			mu.Lock()
			assets.ServiceAccounts = accounts
			mu.Unlock()
		}
	}()

	// Check for metadata exposure if URLs provided
	if len(urls) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if exposures, err := g.DiscoverGCPMetadata(ctx, urls); err == nil {
				mu.Lock()
				assets.MetadataExposures = exposures
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Log summary
	g.logger.Info("GCP discovery completed",
		"domain", domain,
		"project_ids", len(assets.ProjectIDs),
		"gcs_buckets", len(assets.GCSBuckets),
		"app_engine_apps", len(assets.AppEngineApps),
		"cloud_run_services", len(assets.CloudRunServices),
		"cloud_functions", len(assets.CloudFunctions),
		"firebase_apps", len(assets.FirebaseApps),
		"bigquery_datasets", len(assets.BigQueryDatasets),
		"compute_instances", len(assets.ComputeInstances),
		"gke_clusters", len(assets.GKEClusters),
		"pubsub_topics", len(assets.PubSubTopics),
		"cloud_sql_instances", len(assets.CloudSQLInstances),
		"cloud_build_configs", len(assets.CloudBuildConfigs),
		"source_repositories", len(assets.SourceRepositories),
		"api_endpoints", len(assets.APIEndpoints),
		"secrets", len(assets.Secrets),
		"service_accounts", len(assets.ServiceAccounts),
		"metadata_exposures", len(assets.MetadataExposures))

	return assets, nil
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
	defer httpclient.CloseBody(resp)

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
	defer httpclient.CloseBody(resp)

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
	defer httpclient.CloseBody(resp)

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
	defer httpclient.CloseBody(resp)

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
	defer httpclient.CloseBody(resp)

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
	defer httpclient.CloseBody(resp)

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
		baseName + "_prod",
		baseName + "_staging",
		baseName + "_dev",
		baseName + "_raw",
		baseName + "_processed",
		baseName + "_warehouse",
		baseName + "_lake",
		baseName + "_metrics",
		baseName + "_reporting",
		"data_" + baseName,
		"analytics_" + baseName,
		"logs_" + baseName,
		"events_" + baseName,
		"raw_" + baseName,
		"processed_" + baseName,
		"warehouse_" + baseName,
		"dw_" + baseName,
		"dl_" + baseName,
	}

	// Common project patterns
	projectIDs := []string{
		baseName,
		baseName + "-project",
		baseName + "-data",
		baseName + "-analytics",
		baseName + "-prod",
		baseName + "-staging",
		baseName + "-dev",
		baseName + "-bigquery",
		baseName + "-bq",
		baseName + "-warehouse",
		baseName + "-dw",
		baseName + "-lake",
		baseName + "-dl",
		"data-" + baseName,
		"analytics-" + baseName,
		"bigquery-" + baseName,
		"bq-" + baseName,
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

// DiscoverComputeEngine discovers Compute Engine instances
func (g *GCPDiscovery) DiscoverComputeEngine(ctx context.Context, domain string) ([]ComputeInstance, error) {
	var instances []ComputeInstance

	// Note: Compute Engine instances don't have predictable public URLs
	// This would require using the Compute Engine API with credentials
	// We'll return common naming patterns for documentation

	baseName := extractBaseName(domain)

	// Common instance name patterns
	instanceNames := []string{
		baseName,
		baseName + "-vm",
		baseName + "-instance",
		baseName + "-server",
		baseName + "-web",
		baseName + "-api",
		baseName + "-db",
		baseName + "-prod",
		baseName + "-staging",
		baseName + "-dev",
		"vm-" + baseName,
		"instance-" + baseName,
		"server-" + baseName,
	}

	// Common zones
	zones := []string{
		"us-central1-a", "us-central1-b", "us-central1-c", "us-central1-f",
		"us-east1-b", "us-east1-c", "us-east1-d",
		"us-west1-a", "us-west1-b", "us-west1-c",
		"europe-west1-b", "europe-west1-c", "europe-west1-d",
		"asia-east1-a", "asia-east1-b", "asia-east1-c",
	}

	for _, instanceName := range instanceNames {
		for _, zone := range zones {
			instances = append(instances, ComputeInstance{
				Name: instanceName,
				Zone: zone,
			})
		}
	}

	return instances, nil
}

// ComputeInstance represents a Compute Engine instance
type ComputeInstance struct {
	Name string
	Zone string
}

// DiscoverGKEClusters discovers Google Kubernetes Engine clusters
func (g *GCPDiscovery) DiscoverGKEClusters(ctx context.Context, domain string) ([]GKECluster, error) {
	var clusters []GKECluster

	baseName := extractBaseName(domain)

	// Common GKE cluster names
	clusterNames := []string{
		baseName,
		baseName + "-cluster",
		baseName + "-gke",
		baseName + "-k8s",
		baseName + "-kube",
		baseName + "-prod",
		baseName + "-staging",
		baseName + "-dev",
		"gke-" + baseName,
		"k8s-" + baseName,
		"kube-" + baseName,
		"cluster-" + baseName,
	}

	// Common regions/zones for GKE
	locations := []string{
		"us-central1", "us-east1", "us-west1",
		"europe-west1", "europe-west2",
		"asia-east1", "asia-southeast1",
	}

	for _, clusterName := range clusterNames {
		for _, location := range locations {
			clusters = append(clusters, GKECluster{
				Name:     clusterName,
				Location: location,
			})
		}
	}

	return clusters, nil
}

// GKECluster represents a Google Kubernetes Engine cluster
type GKECluster struct {
	Name     string
	Location string
}

// DiscoverPubSubTopics discovers Pub/Sub topics
func (g *GCPDiscovery) DiscoverPubSubTopics(ctx context.Context, domain string) ([]PubSubTopic, error) {
	var topics []PubSubTopic

	baseName := extractBaseName(domain)

	// Common topic name patterns
	topicNames := []string{
		baseName,
		baseName + "-events",
		baseName + "-messages",
		baseName + "-notifications",
		baseName + "-updates",
		baseName + "-logs",
		baseName + "-audit",
		baseName + "-analytics",
		"events-" + baseName,
		"messages-" + baseName,
		"notifications-" + baseName,
		"topic-" + baseName,
	}

	// Common project patterns
	projectIDs := []string{
		baseName,
		baseName + "-project",
		baseName + "-prod",
		baseName + "-dev",
	}

	for _, projectID := range projectIDs {
		for _, topicName := range topicNames {
			topics = append(topics, PubSubTopic{
				ProjectID: projectID,
				TopicName: topicName,
			})
		}
	}

	return topics, nil
}

// PubSubTopic represents a Pub/Sub topic
type PubSubTopic struct {
	ProjectID string
	TopicName string
}

// DiscoverCloudSQL discovers Cloud SQL instances
func (g *GCPDiscovery) DiscoverCloudSQL(ctx context.Context, domain string) ([]CloudSQLInstance, error) {
	var instances []CloudSQLInstance

	baseName := extractBaseName(domain)

	// Common Cloud SQL instance names
	instanceNames := []string{
		baseName,
		baseName + "-db",
		baseName + "-sql",
		baseName + "-mysql",
		baseName + "-postgres",
		baseName + "-database",
		baseName + "-prod",
		baseName + "-staging",
		baseName + "-dev",
		"db-" + baseName,
		"sql-" + baseName,
		"mysql-" + baseName,
		"postgres-" + baseName,
	}

	// Common project patterns
	projectIDs := []string{
		baseName,
		baseName + "-project",
		baseName + "-prod",
		baseName + "-dev",
	}

	for _, projectID := range projectIDs {
		for _, instanceName := range instanceNames {
			instances = append(instances, CloudSQLInstance{
				ProjectID:    projectID,
				InstanceName: instanceName,
			})
		}
	}

	return instances, nil
}

// CloudSQLInstance represents a Cloud SQL instance
type CloudSQLInstance struct {
	ProjectID    string
	InstanceName string
}

// DiscoverCloudBuild discovers Cloud Build configurations
func (g *GCPDiscovery) DiscoverCloudBuild(ctx context.Context, domain string) ([]CloudBuildConfig, error) {
	var configs []CloudBuildConfig

	baseName := extractBaseName(domain)

	// Check for Cloud Build configuration files in common GCS buckets
	bucketNames := []string{
		baseName + "-builds",
		baseName + "-artifacts",
		baseName + "-cloudbuild",
		"builds-" + baseName,
		"artifacts-" + baseName,
		"cloudbuild-" + baseName,
	}

	for _, bucketName := range bucketNames {
		bucket := g.checkGCSBucket(ctx, bucketName)
		if bucket != nil && bucket.Exists {
			configs = append(configs, CloudBuildConfig{
				BucketName: bucketName,
				URL:        bucket.URL,
			})
		}
	}

	return configs, nil
}

// CloudBuildConfig represents a Cloud Build configuration
type CloudBuildConfig struct {
	BucketName string
	URL        string
}

// DiscoverSourceRepositories discovers Cloud Source Repositories
func (g *GCPDiscovery) DiscoverSourceRepositories(ctx context.Context, domain string) ([]SourceRepository, error) {
	var repos []SourceRepository

	baseName := extractBaseName(domain)

	// Common repository names
	repoNames := []string{
		baseName,
		baseName + "-code",
		baseName + "-repo",
		baseName + "-source",
		baseName + "-app",
		baseName + "-api",
		baseName + "-web",
		baseName + "-backend",
		baseName + "-frontend",
	}

	// Common project patterns
	projectIDs := []string{
		baseName,
		baseName + "-project",
		baseName + "-dev",
		baseName + "-prod",
	}

	for _, projectID := range projectIDs {
		for _, repoName := range repoNames {
			repos = append(repos, SourceRepository{
				ProjectID: projectID,
				RepoName:  repoName,
			})
		}
	}

	return repos, nil
}

// SourceRepository represents a Cloud Source Repository
type SourceRepository struct {
	ProjectID string
	RepoName  string
}

// DiscoverGCPMetadata attempts to find exposed GCP metadata
func (g *GCPDiscovery) DiscoverGCPMetadata(ctx context.Context, urls []string) ([]GCPMetadataExposure, error) {
	var exposures []GCPMetadataExposure

	metadataPaths := []string{
		"/computeMetadata/v1/",
		"/computeMetadata/v1/project/project-id",
		"/computeMetadata/v1/project/numeric-project-id",
		"/computeMetadata/v1/project/attributes/",
		"/computeMetadata/v1/instance/service-accounts/",
		"/computeMetadata/v1/instance/service-accounts/default/token",
		"/computeMetadata/v1/instance/hostname",
		"/computeMetadata/v1/instance/id",
		"/computeMetadata/v1/instance/zone",
		"/computeMetadata/v1/instance/attributes/",
	}

	for _, baseURL := range urls {
		for _, path := range metadataPaths {
			exposure := g.checkMetadataEndpoint(ctx, baseURL, path)
			if exposure != nil {
				exposures = append(exposures, *exposure)
			}
		}
	}

	return exposures, nil
}

// GCPMetadataExposure represents exposed GCP metadata
type GCPMetadataExposure struct {
	URL          string
	Path         string
	IsExposed    bool
	ResponseData string
}

// checkMetadataEndpoint checks for exposed GCP metadata
func (g *GCPDiscovery) checkMetadataEndpoint(ctx context.Context, baseURL, path string) *GCPMetadataExposure {
	// Common metadata URLs
	metadataURLs := []string{
		baseURL + path,
		baseURL + "/169.254.169.254" + path,
		baseURL + "/metadata.google.internal" + path,
		baseURL + "/metadata" + path,
	}

	for _, url := range metadataURLs {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		// GCP metadata requires specific header
		req.Header.Set("Metadata-Flavor", "Google")

		resp, err := g.client.Do(req)
		if err != nil {
			continue
		}
		defer httpclient.CloseBody(resp)

		if resp.StatusCode == 200 {
			// Read limited response
			buf := make([]byte, 1024)
			n, _ := resp.Body.Read(buf)

			return &GCPMetadataExposure{
				URL:          url,
				Path:         path,
				IsExposed:    true,
				ResponseData: string(buf[:n]),
			}
		}
	}

	return nil
}

// DiscoverGCPAPIs attempts to discover exposed GCP APIs
func (g *GCPDiscovery) DiscoverGCPAPIs(ctx context.Context, domain string) ([]GCPAPIEndpoint, error) {
	var endpoints []GCPAPIEndpoint

	baseName := extractBaseName(domain)

	// Common API endpoint patterns
	apiPatterns := []string{
		"%s-dot-appspot.com",
		"%s.googleapis.com",
		"%s-uc.a.run.app",
		"%s.cloudfunctions.net",
		"%s.firebaseio.com",
		"%s.web.app",
		"%s.firebaseapp.com",
	}

	// Common API service names
	serviceNames := []string{
		baseName,
		baseName + "-api",
		baseName + "-service",
		baseName + "-backend",
		"api-" + baseName,
		"service-" + baseName,
		"backend-" + baseName,
	}

	for _, serviceName := range serviceNames {
		for _, pattern := range apiPatterns {
			apiURL := fmt.Sprintf("https://"+pattern, serviceName)
			if g.checkAPIEndpoint(ctx, apiURL) {
				endpoints = append(endpoints, GCPAPIEndpoint{
					ServiceName: serviceName,
					URL:         apiURL,
					IsActive:    true,
				})
			}
		}
	}

	return endpoints, nil
}

// GCPAPIEndpoint represents a GCP API endpoint
type GCPAPIEndpoint struct {
	ServiceName string
	URL         string
	IsActive    bool
}

// checkAPIEndpoint checks if an API endpoint is active
func (g *GCPDiscovery) checkAPIEndpoint(ctx context.Context, url string) bool {
	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return false
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return false
	}
	defer httpclient.CloseBody(resp)

	// API endpoints typically return 200, 401, 403, or custom responses
	return resp.StatusCode != 404
}

// DiscoverGCPSecrets attempts to discover Secret Manager secrets
func (g *GCPDiscovery) DiscoverGCPSecrets(ctx context.Context, domain string) ([]GCPSecret, error) {
	var secrets []GCPSecret

	baseName := extractBaseName(domain)

	// Common secret name patterns
	secretNames := []string{
		baseName + "-api-key",
		baseName + "-secret",
		baseName + "-credentials",
		baseName + "-password",
		baseName + "-token",
		baseName + "-config",
		baseName + "-env",
		"api-key-" + baseName,
		"secret-" + baseName,
		"credentials-" + baseName,
		"password-" + baseName,
		"token-" + baseName,
	}

	// Common project patterns
	projectIDs := []string{
		baseName,
		baseName + "-project",
		baseName + "-prod",
		baseName + "-dev",
	}

	for _, projectID := range projectIDs {
		for _, secretName := range secretNames {
			secrets = append(secrets, GCPSecret{
				ProjectID:  projectID,
				SecretName: secretName,
			})
		}
	}

	return secrets, nil
}

// GCPSecret represents a Secret Manager secret
type GCPSecret struct {
	ProjectID  string
	SecretName string
}

// DiscoverServiceAccounts attempts to discover GCP service accounts
func (g *GCPDiscovery) DiscoverServiceAccounts(ctx context.Context, domain string) ([]ServiceAccount, error) {
	var accounts []ServiceAccount

	baseName := extractBaseName(domain)

	// Common service account patterns
	accountNames := []string{
		baseName,
		baseName + "-sa",
		baseName + "-service",
		baseName + "-svc",
		baseName + "-app",
		baseName + "-api",
		baseName + "-worker",
		baseName + "-admin",
		baseName + "-deploy",
		baseName + "-ci",
		baseName + "-cd",
		baseName + "-gke",
		baseName + "-compute",
		"service-" + baseName,
		"sa-" + baseName,
		"svc-" + baseName,
		"app-" + baseName,
		"api-" + baseName,
	}

	// Common project patterns
	projectIDs := g.generateProjectIDs(baseName, domain)

	for _, projectID := range projectIDs {
		for _, accountName := range accountNames {
			accounts = append(accounts, ServiceAccount{
				Email:     fmt.Sprintf("%s@%s.iam.gserviceaccount.com", accountName, projectID),
				ProjectID: projectID,
				Name:      accountName,
			})
		}
	}

	return accounts, nil
}

// ServiceAccount represents a GCP service account
type ServiceAccount struct {
	Email     string
	ProjectID string
	Name      string
}

// DiscoverProjectIDs attempts to discover GCP project IDs through various methods
func (g *GCPDiscovery) DiscoverProjectIDs(ctx context.Context, domain string) ([]string, error) {
	baseName := extractBaseName(domain)
	projectIDs := g.generateProjectIDs(baseName, domain)

	// Additional discovery through exposed endpoints
	var discoveredIDs []string

	// Check common GCS buckets for project IDs
	bucketNames := []string{
		baseName,
		baseName + "-backup",
		baseName + "-logs",
		baseName + "-artifacts",
	}

	for _, bucketName := range bucketNames {
		bucket := g.checkGCSBucket(ctx, bucketName)
		if bucket != nil && bucket.Exists && bucket.HasListing {
			// Sometimes project IDs are exposed in bucket listings
			g.logger.Debug("Found accessible bucket, may contain project info", "bucket", bucketName)
		}
	}

	// Check Firebase config endpoints which often expose project IDs
	firebaseConfigURL := fmt.Sprintf("https://%s.web.app/__/firebase/init.json", baseName)
	if data := g.fetchURL(ctx, firebaseConfigURL); data != "" {
		// Parse for project ID
		if projectID := extractProjectIDFromJSON(data); projectID != "" {
			discoveredIDs = append(discoveredIDs, projectID)
		}
	}

	// Combine generated and discovered IDs
	allIDs := append(projectIDs, discoveredIDs...)
	return deduplicateStrings(allIDs), nil
}

// generateProjectIDs generates potential GCP project IDs
func (g *GCPDiscovery) generateProjectIDs(baseName, domain string) []string {
	var projectIDs []string

	// GCP project ID patterns
	patterns := []string{
		"%s",
		"%s-project",
		"%s-prod",
		"%s-production",
		"%s-dev",
		"%s-development",
		"%s-staging",
		"%s-stage",
		"%s-test",
		"%s-qa",
		"%s-demo",
		"%s-poc",
		"%s-pilot",
		"%s-sandbox",
		"%s-lab",
		"%s-experiment",
		"%s-data",
		"%s-analytics",
		"%s-ml",
		"%s-ai",
		"%s-api",
		"%s-app",
		"%s-web",
		"%s-mobile",
		"%s-backend",
		"%s-frontend",
		"%s-infra",
		"%s-infrastructure",
		"%s-platform",
		"%s-core",
		"%s-main",
		"%s-primary",
		"%s-secondary",
		"%s-backup",
		"%s-dr",
		"%s-recovery",
		"%s-archive",
		"%s-logs",
		"%s-monitoring",
		"%s-metrics",
		"%s-billing",
		"%s-finance",
		"%s-ops",
		"%s-operations",
		"%s-security",
		"%s-compliance",
		"%s-audit",
		"project-%s",
		"gcp-%s",
		"google-%s",
		"g-%s",
	}

	// Apply patterns
	for _, pattern := range patterns {
		projectID := fmt.Sprintf(pattern, baseName)
		if isValidProjectID(projectID) {
			projectIDs = append(projectIDs, projectID)
		}
	}

	// Add numeric suffixes
	for i := 1; i <= 5; i++ {
		projectID := fmt.Sprintf("%s-%d", baseName, i)
		if isValidProjectID(projectID) {
			projectIDs = append(projectIDs, projectID)
		}
	}

	// Add year-based variations
	currentYear := time.Now().Year()
	for year := currentYear - 3; year <= currentYear; year++ {
		projectID := fmt.Sprintf("%s-%d", baseName, year)
		if isValidProjectID(projectID) {
			projectIDs = append(projectIDs, projectID)
		}
	}

	// Try with company variations
	if strings.Contains(domain, ".") {
		parts := strings.Split(domain, ".")
		for _, part := range parts {
			if part != "com" && part != "org" && part != "net" && part != "io" {
				cleanPart := strings.ToLower(regexp.MustCompile(`[^a-z0-9-]`).ReplaceAllString(part, "-"))
				if isValidProjectID(cleanPart) {
					projectIDs = append(projectIDs, cleanPart)
				}
			}
		}
	}

	return deduplicateStrings(projectIDs)
}

// fetchURL fetches content from a URL
func (g *GCPDiscovery) fetchURL(ctx context.Context, url string) string {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return ""
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return ""
	}
	defer httpclient.CloseBody(resp)

	if resp.StatusCode == 200 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // Limit to 1MB
		return string(data)
	}

	return ""
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

func isValidProjectID(id string) bool {
	// GCP project ID rules: 6-30 chars, lowercase letters, numbers, hyphens
	if len(id) < 6 || len(id) > 30 {
		return false
	}

	// Must start with lowercase letter
	// Can contain lowercase letters, numbers, and hyphens
	// Cannot end with hyphen
	matched, _ := regexp.MatchString(`^[a-z][a-z0-9-]*[a-z0-9]$`, id)
	return matched
}

func extractProjectIDFromJSON(data string) string {
	// Simple regex to extract project ID from Firebase config
	re := regexp.MustCompile(`"projectId"\s*:\s*"([^"]+)"`)
	matches := re.FindStringSubmatch(data)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func deduplicateStrings(items []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}
