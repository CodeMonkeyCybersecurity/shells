package hackerone

// API response types for HackerOne

type programsResponse struct {
	Data []programData `json:"data"`
}

type programResponse struct {
	Data programData `json:"data"`
}

type programData struct {
	ID            string               `json:"id"`
	Type          string               `json:"type"`
	Attributes    programAttributes    `json:"attributes"`
	Relationships programRelationships `json:"relationships,omitempty"`
}

type programAttributes struct {
	Handle          string `json:"handle"`
	Name            string `json:"name"`
	About           string `json:"about"`
	SubmissionState string `json:"submission_state"` // open, paused, disabled
}

type programRelationships struct {
	StructuredScopes structuredScopes `json:"structured_scopes,omitempty"`
}

type structuredScopes struct {
	Data []scopeData `json:"data"`
}

type scopeData struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	Attributes scopeAttributes `json:"attributes"`
}

type scopeAttributes struct {
	AssetType         string `json:"asset_type"`
	AssetIdentifier   string `json:"asset_identifier"`
	Instruction       string `json:"instruction"`
	MaxSeverity       string `json:"max_severity"`
	EligibleForBounty bool   `json:"eligible_for_bounty"`
}

// Report creation types

type createReportPayload struct {
	Data createReportData `json:"data"`
}

type createReportData struct {
	Type       string           `json:"type"`
	Attributes reportAttributes `json:"attributes"`
}

type reportAttributes struct {
	TeamHandle               string `json:"team_handle"`
	Title                    string `json:"title"`
	VulnerabilityInformation string `json:"vulnerability_information"`
	Severity                 string `json:"severity,omitempty"`
	ImpactDescription        string `json:"impact,omitempty"`
}

type createReportResponse struct {
	Data createReportResponseData `json:"data"`
}

type createReportResponseData struct {
	ID         string                         `json:"id"`
	Type       string                         `json:"type"`
	Attributes createReportResponseAttributes `json:"attributes"`
}

type createReportResponseAttributes struct {
	State string `json:"state"`
	Title string `json:"title"`
}
