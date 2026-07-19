package torrent

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"path"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/StevenBuglione/private-vm/internal/secret"
	"golang.org/x/text/unicode/norm"
)

const (
	MaximumFiles          = 100_000
	MaximumPathBytes      = 1024
	MaximumDisplayName    = 255
	QuarantineMountPath   = "/mnt/quarantine"
	QuarantineDownloadDir = "/mnt/quarantine/payload"
)

type State string

const (
	StateEmpty             State = "EMPTY"
	StateMetadataFetching  State = "METADATA_FETCHING"
	StateSelectionRequired State = "FILE_SELECTION_REQUIRED"
	StateCapacityVerified  State = "CAPACITY_VERIFIED"
	StateDownloading       State = "DOWNLOADING"
	StatePaused            State = "DOWNLOAD_PAUSED"
	StateDownloadComplete  State = "DOWNLOAD_COMPLETE"
	StateSealing           State = "QUARANTINE_SEALING"
	StateSealed            State = "QUARANTINE_SEALED"
)

type Handle struct {
	value string
}

// NewHandle validates a qBittorrent content identifier for a typed Backend.
// The returned handle redacts formatting and rejects serialization.
func NewHandle(value string) (Handle, error) {
	if len(value) != 40 && len(value) != 64 {
		return Handle{}, invalidRequest()
	}
	for _, current := range value {
		if !(current >= '0' && current <= '9') && !(current >= 'a' && current <= 'f') {
			return Handle{}, invalidRequest()
		}
	}
	return Handle{value: value}, nil
}

func (handle Handle) valid() bool {
	_, err := NewHandle(handle.value)
	return err == nil
}

func (Handle) String() string   { return "[REDACTED TORRENT HANDLE]" }
func (Handle) GoString() string { return "[REDACTED TORRENT HANDLE]" }
func (Handle) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("[REDACTED TORRENT HANDLE]"))
}
func (Handle) MarshalJSON() ([]byte, error)   { return nil, secret.ErrSerialization }
func (Handle) MarshalText() ([]byte, error)   { return nil, secret.ErrSerialization }
func (Handle) MarshalBinary() ([]byte, error) { return nil, secret.ErrSerialization }
func (Handle) GobEncode() ([]byte, error)     { return nil, secret.ErrSerialization }
func (Handle) MarshalXML(*xml.Encoder, xml.StartElement) error {
	return secret.ErrSerialization
}

type RawFile struct {
	Index uint32
	Path  string
	Size  uint64
}

type RawMetadata struct {
	Available   bool
	PayloadRead uint64
	DisplayName string
	Files       []RawFile
}

type File struct {
	Index         uint32
	DisplayPath   string
	SizeBytes     uint64
	Selected      bool
	SuspectedType string
	HazardCodes   []string
}

type Metadata struct {
	DisplayName       string
	Files             []File
	TotalSizeBytes    uint64
	SelectedSizeBytes uint64
	PayloadPaused     bool
}

func (Metadata) MarshalJSON() ([]byte, error) { return nil, secret.ErrSerialization }

type CapacityBudget struct {
	QuarantineAvailableBytes uint64
	ScanAvailableBytes       uint64
	ReconstructionAvailable  uint64
	DestinationAvailable     uint64
	RootOverlayBudgetBytes   uint64
	ArchiveExpansionBytes    uint64
	ReconstructionBytes      uint64
	MaximumSelectedBytes     uint64
}

type CapacityPlan struct {
	SelectedBytes       uint64
	QuarantineRequired  uint64
	ScanRequired        uint64
	ReconstructionNeed  uint64
	DestinationRequired uint64
	SessionRequired     uint64
	SafetyMargin        uint64
}

type Progress struct {
	CompletedBytes uint64
	TotalBytes     uint64
}

type Status struct {
	SchemaVersion int      `json:"schema_version"`
	State         State    `json:"state"`
	Progress      Progress `json:"progress"`
	Code          string   `json:"code"`
	Remediation   string   `json:"remediation"`
}

type FileDigest struct {
	Path        string
	SizeBytes   uint64
	SHA256      [32]byte
	SourceIndex uint32
}

type Manifest struct {
	files []FileDigest
}

func newManifest(files []FileDigest) (Manifest, error) {
	if len(files) == 0 || len(files) > MaximumFiles {
		return Manifest{}, sealFailed()
	}
	copyFiles := make([]FileDigest, len(files))
	copy(copyFiles, files)
	for index := range copyFiles {
		if copyFiles[index].SizeBytes == 0 || validateRelativePath(copyFiles[index].Path) != nil || allZero(copyFiles[index].SHA256[:]) {
			clearManifest(copyFiles)
			return Manifest{}, sealFailed()
		}
	}
	return Manifest{files: copyFiles}, nil
}

func (manifest *Manifest) Destroy() {
	if manifest == nil {
		return
	}
	clearManifest(manifest.files)
	manifest.files = nil
}

func (Manifest) String() string   { return "[REDACTED TORRENT MANIFEST]" }
func (Manifest) GoString() string { return "[REDACTED TORRENT MANIFEST]" }
func (Manifest) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("[REDACTED TORRENT MANIFEST]"))
}
func (Manifest) MarshalJSON() ([]byte, error)   { return nil, secret.ErrSerialization }
func (Manifest) MarshalText() ([]byte, error)   { return nil, secret.ErrSerialization }
func (Manifest) MarshalBinary() ([]byte, error) { return nil, secret.ErrSerialization }
func (Manifest) GobEncode() ([]byte, error)     { return nil, secret.ErrSerialization }

func validateMetadata(raw RawMetadata) (Metadata, error) {
	if !raw.Available || raw.PayloadRead != 0 || len(raw.DisplayName) == 0 || len(raw.DisplayName) > MaximumDisplayName ||
		!utf8.ValidString(raw.DisplayName) || strings.ContainsAny(raw.DisplayName, "\x00\r\n") || len(raw.Files) == 0 || len(raw.Files) > MaximumFiles {
		return Metadata{}, unsafeMetadata()
	}
	result := Metadata{DisplayName: raw.DisplayName, Files: make([]File, 0, len(raw.Files)), PayloadPaused: true}
	seen := make(map[string]struct{}, len(raw.Files))
	seenFolded := make(map[string]struct{}, len(raw.Files))
	for expectedIndex, rawFile := range raw.Files {
		if rawFile.Index != uint32(expectedIndex) || rawFile.Size == 0 {
			return Metadata{}, unsafeMetadata()
		}
		if err := validateRelativePath(rawFile.Path); err != nil {
			return Metadata{}, err
		}
		normalized := norm.NFC.String(rawFile.Path)
		folded := strings.ToLower(normalized)
		if _, exists := seen[normalized]; exists {
			return Metadata{}, unsafeMetadata()
		}
		if _, exists := seenFolded[folded]; exists {
			return Metadata{}, unsafeMetadata()
		}
		seen[normalized] = struct{}{}
		seenFolded[folded] = struct{}{}
		fileType, hazards := classifyPath(normalized)
		result.Files = append(result.Files, File{Index: rawFile.Index, DisplayPath: normalized, SizeBytes: rawFile.Size, SuspectedType: fileType, HazardCodes: hazards})
		var overflow bool
		result.TotalSizeBytes, overflow = checkedAdd(result.TotalSizeBytes, rawFile.Size)
		if overflow {
			return Metadata{}, unsafeMetadata()
		}
	}
	return result, nil
}

func validateRelativePath(value string) error {
	if value == "" || len(value) > MaximumPathBytes || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n\\") || strings.HasPrefix(value, "/") || path.Clean(value) != value {
		return unsafeMetadata()
	}
	for _, element := range strings.Split(value, "/") {
		if element == "" || element == "." || element == ".." || len(element) > 255 || windowsReservedName(element) {
			return unsafeMetadata()
		}
	}
	return nil
}

func windowsReservedName(value string) bool {
	base := strings.TrimSuffix(strings.ToLower(value), path.Ext(value))
	switch base {
	case "con", "prn", "aux", "nul", "clock$":
		return true
	}
	if len(base) == 4 && (strings.HasPrefix(base, "com") || strings.HasPrefix(base, "lpt")) && base[3] >= '1' && base[3] <= '9' {
		return true
	}
	return false
}

func classifyPath(value string) (string, []string) {
	extension := strings.ToLower(path.Ext(value))
	var kind string
	var hazards []string
	switch extension {
	case ".exe", ".com", ".scr", ".dll", ".msi", ".appimage", ".apk":
		kind, hazards = "executable", []string{"TYPE_EXECUTABLE"}
	case ".bat", ".cmd", ".ps1", ".sh", ".js", ".vbs", ".py", ".pl":
		kind, hazards = "script", []string{"TYPE_SCRIPT"}
	case ".deb", ".rpm", ".pkg", ".jar":
		kind, hazards = "package", []string{"TYPE_PACKAGE"}
	case ".iso", ".img", ".vhd", ".vhdx", ".vmdk", ".qcow", ".qcow2":
		kind, hazards = "disk-image", []string{"TYPE_DISK_IMAGE"}
	case ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar":
		kind, hazards = "archive", []string{"TYPE_ARCHIVE"}
	case ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp":
		kind = "document"
	case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".tif", ".tiff", ".bmp":
		kind = "image"
	case ".mp3", ".wav", ".flac", ".ogg", ".mp4", ".mkv", ".webm", ".mov":
		kind = "media"
	case ".txt", ".md", ".csv":
		kind = "text"
	default:
		kind, hazards = "unknown", []string{"TYPE_UNKNOWN"}
	}
	return kind, hazards
}

func hasBlockedType(file File) bool {
	return slices.Contains(file.HazardCodes, "TYPE_EXECUTABLE") || slices.Contains(file.HazardCodes, "TYPE_SCRIPT") ||
		slices.Contains(file.HazardCodes, "TYPE_PACKAGE") || slices.Contains(file.HazardCodes, "TYPE_DISK_IMAGE")
}

func hasArchive(file File) bool { return slices.Contains(file.HazardCodes, "TYPE_ARCHIVE") }

func checkedAdd(left, right uint64) (uint64, bool) {
	result := left + right
	return result, result < left
}

func allZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}

func clearManifest(files []FileDigest) {
	for index := range files {
		files[index].Path = ""
		clear(files[index].SHA256[:])
	}
	clear(files)
}

var _ json.Marshaler = Handle{}
var _ json.Marshaler = Metadata{}
var _ json.Marshaler = Manifest{}
