package policy

type FindingSeverity string

const (
	Info     FindingSeverity = "info"
	Warning  FindingSeverity = "warning"
	Blocking FindingSeverity = "blocking"
)

type Finding struct {
	Code     string
	Path     string
	Severity FindingSeverity
	Detail   string
}

type ScanSummary struct {
	MalwareDetected bool
	ScanErrors      int
	SkippedFiles    int
	EncryptedFiles  int
	BlockedTypes    int
	Findings        []Finding
}

type Rules struct {
	RejectOnMalware     bool
	RejectOnScanError   bool
	RejectOnSkippedFile bool
	RejectEncrypted     bool
	BlockExecutables    bool
	BlockScripts        bool
	BlockDiskImages     bool
}

func (r Rules) Approve(s ScanSummary) bool {
	if r.RejectOnMalware && s.MalwareDetected {
		return false
	}
	if r.RejectOnScanError && s.ScanErrors > 0 {
		return false
	}
	if r.RejectOnSkippedFile && s.SkippedFiles > 0 {
		return false
	}
	if r.RejectEncrypted && s.EncryptedFiles > 0 {
		return false
	}
	if (r.BlockExecutables || r.BlockScripts || r.BlockDiskImages) && s.BlockedTypes > 0 {
		return false
	}
	for _, f := range s.Findings {
		if f.Severity == Blocking {
			return false
		}
	}
	return true
}
