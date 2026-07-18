package preflight

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityBlocking Severity = "blocking"
)

type Diagnostic struct {
	Code        string   `json:"code"`
	Severity    Severity `json:"severity"`
	Summary     string   `json:"summary"`
	Remediation string   `json:"remediation,omitempty"`
	Overridable bool     `json:"overridable"`
}

type Report struct {
	Runnable    bool         `json:"runnable"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}
