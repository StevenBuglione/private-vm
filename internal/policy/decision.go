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
	validated           bool
	rejectOnMalware     bool
	rejectOnScanError   bool
	rejectOnSkippedFile bool
	rejectEncrypted     bool
	blockExecutables    bool
	blockScripts        bool
	blockDiskImages     bool
	sanitizeDocuments   bool
	reencodeMedia       bool
	stripMetadata       bool
}

func (r Rules) Approve(s ScanSummary) bool {
	if !r.validated || s.ScanErrors < 0 || s.SkippedFiles < 0 || s.EncryptedFiles < 0 || s.BlockedTypes < 0 {
		return false
	}
	if r.rejectOnMalware && s.MalwareDetected {
		return false
	}
	if r.rejectOnScanError && s.ScanErrors > 0 {
		return false
	}
	if r.rejectOnSkippedFile && s.SkippedFiles > 0 {
		return false
	}
	if r.rejectEncrypted && s.EncryptedFiles > 0 {
		return false
	}
	if (r.blockExecutables || r.blockScripts || r.blockDiskImages) && s.BlockedTypes > 0 {
		return false
	}
	for _, f := range s.Findings {
		if f.Severity != Info && f.Severity != Warning && f.Severity != Blocking {
			return false
		}
		if f.Severity == Blocking {
			return false
		}
	}
	return true
}

func (r Rules) RejectOnMalware() bool     { return r.rejectOnMalware }
func (r Rules) RejectOnScanError() bool   { return r.rejectOnScanError }
func (r Rules) RejectOnSkippedFile() bool { return r.rejectOnSkippedFile }
func (r Rules) RejectEncrypted() bool     { return r.rejectEncrypted }
func (r Rules) BlockExecutables() bool    { return r.blockExecutables }
func (r Rules) BlockScripts() bool        { return r.blockScripts }
func (r Rules) BlockDiskImages() bool     { return r.blockDiskImages }
func (r Rules) SanitizeDocuments() bool   { return r.sanitizeDocuments }
func (r Rules) ReencodeMedia() bool       { return r.reencodeMedia }
func (r Rules) StripMetadata() bool       { return r.stripMetadata }
