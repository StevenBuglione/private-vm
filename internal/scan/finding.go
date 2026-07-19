package scan

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityBlocking Severity = "blocking"
)

type Finding struct {
	Code         string
	Severity     Severity
	RelativePath string
	Detail       string
	Identifier   string
}

func (finding Finding) valid() bool {
	return validIdentity(finding.Code) &&
		(finding.Severity == SeverityInfo || finding.Severity == SeverityWarning || finding.Severity == SeverityBlocking) &&
		finding.Detail != "" && len(finding.Detail) <= 1024 &&
		len(finding.RelativePath) <= MaximumInventoryPathBytes &&
		(finding.Identifier == "" || validIdentity(finding.Identifier))
}
