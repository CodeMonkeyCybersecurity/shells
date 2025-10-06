package bugcrowd

// API response types for Bugcrowd

type programsResponse struct {
	Programs []programData `json:"programs"`
}

type programData struct {
	UUID        string       `json:"uuid"`
	Code        string       `json:"code"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	State       string       `json:"state"` // active, paused, archived
	Targets     []targetData `json:"targets,omitempty"`
}

type targetData struct {
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	Category    string `json:"category"` // website, api, mobile, etc.
	Description string `json:"description"`
	InScope     bool   `json:"in_scope"`
}

// Submission creation types

type createSubmissionPayload struct {
	Submission submissionData `json:"submission"`
}

type submissionData struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	VrtID       string `json:"vrt_id,omitempty"` // Vulnerability Rating Taxonomy ID
	URL         string `json:"url"`
	Priority    string `json:"priority"` // P1, P2, P3, P4, P5
	Impact      string `json:"impact,omitempty"`
}

type createSubmissionResponse struct {
	UUID     string `json:"uuid"`
	Title    string `json:"title"`
	State    string `json:"state"`
	Priority string `json:"priority"`
}
