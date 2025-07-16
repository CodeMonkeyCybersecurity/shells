package dns

import (
	"time"
)

type DNSHistory struct {
	Domain      string                        `json:"domain"`
	Subdomains  map[string][]HistoricalRecord `json:"subdomains"`
	IPHistory   map[string][]IPRecord         `json:"ip_history"`
	NSHistory   []NameserverRecord            `json:"ns_history"`
	MXHistory   []MXRecord                    `json:"mx_history"`
	Findings    []Finding                     `json:"findings"`
	LastUpdated time.Time                     `json:"last_updated"`
}

type HistoricalRecord struct {
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Source    string    `json:"source"`
}

type IPRecord struct {
	IP        string    `json:"ip"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Source    string    `json:"source"`
}

type NameserverRecord struct {
	NS        string    `json:"ns"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Source    string    `json:"source"`
}

type MXRecord struct {
	MX        string    `json:"mx"`
	Priority  int       `json:"priority"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Source    string    `json:"source"`
}

type Finding struct {
	Type     string   `json:"type"`
	Severity string   `json:"severity"`
	Domain   string   `json:"domain"`
	Details  string   `json:"details"`
	IP       string   `json:"ip,omitempty"`
	CVEs     []string `json:"cves,omitempty"`
}

type EnumerationResult struct {
	Subdomains []Subdomain `json:"subdomains"`
	Patterns   []Pattern   `json:"patterns"`
	Statistics Statistics  `json:"statistics"`
}

type Subdomain struct {
	Name         string    `json:"name"`
	IPs          []string  `json:"ips"`
	Status       string    `json:"status"`
	Source       string    `json:"source"`
	FirstSeen    time.Time `json:"first_seen"`
	Technologies []string  `json:"technologies"`
	Ports        []int     `json:"ports"`
}

type Pattern struct {
	Type       string   `json:"type"`
	Pattern    string   `json:"pattern"`
	Examples   []string `json:"examples"`
	Confidence float64  `json:"confidence"`
}

type Statistics struct {
	TotalSubdomains  int            `json:"total_subdomains"`
	ActiveSubdomains int            `json:"active_subdomains"`
	UniqueIPs        int            `json:"unique_ips"`
	Sources          map[string]int `json:"sources"`
}

type SecurityTrailsResponse struct {
	Records []SecurityTrailsRecord `json:"records"`
}

type SecurityTrailsRecord struct {
	Type   string    `json:"type"`
	Values []string  `json:"values"`
	First  time.Time `json:"first_seen"`
	Last   time.Time `json:"last_seen"`
}

type DNSDBResponse struct {
	Data []DNSDBRecord `json:"data"`
}

type DNSDBRecord struct {
	RRName    string    `json:"rrname"`
	RRType    string    `json:"rrtype"`
	RData     string    `json:"rdata"`
	TimeFirst time.Time `json:"time_first"`
	TimeLast  time.Time `json:"time_last"`
}

type ViewDNSResponse struct {
	Query struct {
		Tool   string `json:"tool"`
		Domain string `json:"domain"`
	} `json:"query"`
	Response struct {
		Records []ViewDNSRecord `json:"records"`
	} `json:"response"`
}

type ViewDNSRecord struct {
	Date     string `json:"date"`
	IP       string `json:"ip"`
	Location string `json:"location"`
	Owner    string `json:"owner"`
}

type PatternAnalysis struct {
	HasDevPattern      bool     `json:"has_dev_pattern"`
	HasRegionalPattern bool     `json:"has_regional_pattern"`
	HasAPIPattern      bool     `json:"has_api_pattern"`
	HasStagingPattern  bool     `json:"has_staging_pattern"`
	CustomPatterns     []string `json:"custom_patterns"`
}

type DNSCheck struct {
	Type     string `json:"type"`
	Target   string `json:"target"`
	Expected string `json:"expected"`
	Found    bool   `json:"found"`
	Details  string `json:"details"`
}
