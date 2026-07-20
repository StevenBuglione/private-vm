package scan

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityBlocking Severity = "blocking"
)

type Finding struct {
	Code         string   `json:"code"`
	Severity     Severity `json:"severity"`
	RelativePath string   `json:"path,omitempty"`
	Detail       string   `json:"detail"`
	Identifier   string   `json:"identifier,omitempty"`
}

func (finding Finding) valid() bool {
	return validIdentity(finding.Code) &&
		(finding.Severity == SeverityInfo || finding.Severity == SeverityWarning || finding.Severity == SeverityBlocking) &&
		finding.Detail != "" && len(finding.Detail) <= 1024 &&
		len(finding.RelativePath) <= MaximumInventoryPathBytes &&
		(finding.Identifier == "" || validIdentity(finding.Identifier))
}
