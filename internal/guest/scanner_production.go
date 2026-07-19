package guest

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/StevenBuglione/private-vm/internal/policy"
	"github.com/StevenBuglione/private-vm/internal/scan"
	"golang.org/x/sys/unix"
)

const (
	productionScannerStateDirectory = "/var/lib/private-vm/scanner"
	productionScannerPhasePath      = "/etc/private-vm/scanner-phase.json"
	productionScannerBootModePath   = "/sys/firmware/qemu_fw_cfg/by_name/opt/private-vm/scanner-boot-mode/raw"
	productionScannerPolicyPath     = "/etc/private-vm/policy.safe.toml"
	productionScannerToolchainPath  = "/etc/private-vm/scanner-toolchain.json"
	productionScannerQuarantine     = "/mnt/quarantine"
	productionScannerDevice         = "/dev/disk/by-id/virtio-quarantine"
	productionScannerSandbox        = "/run/private-vm/scanner-sandbox"
	productionScannerClamdSocket    = "/run/clamav/clamd.ctl"
	productionScannerOfflineUnit    = "private-vm-scanner-stage-offline.service"
	maximumScannerMetadataBytes     = 256 << 10
)

var (
	clamVersionPattern          = regexp.MustCompile(`^ClamAV ([A-Za-z0-9._+-]{1,128})/([0-9]{1,20})/`)
	scannerToolIDPattern        = regexp.MustCompile(`^[a-z0-9][a-z0-9+._-]*$`)
	scannerToolPackagePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]*$`)
	scannerToolCommandPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]*$`)
	scannerSourceCommitPattern  = regexp.MustCompile(`^(unknown|[0-9a-f]{40}(-dirty)?)$`)
	scannerFlakeLockHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	productionScannerTools      = []struct {
		id       string
		commands []string
	}{
		{id: "clamav", commands: []string{"clamd", "clamscan", "freshclam"}},
		{id: "file", commands: []string{"file"}},
		{id: "poppler-utils", commands: []string{"pdfinfo"}},
		{id: "ghostscript", commands: []string{"gs"}},
		{id: "libreoffice", commands: []string{"libreoffice"}},
		{id: "ffmpeg", commands: []string{"ffmpeg", "ffprobe"}},
	}
)

type ProductionScannerConfig struct {
	StateDirectory string
	PhasePath      string
	BootModePath   string
	PolicyPath     string
	ToolchainPath  string
	QuarantineRoot string
	QuarantineDev  string
	SandboxRoot    string
	ClamdSocket    string
	Systemctl      string
	Clamscan       string
	File           string
	PDFInfo        string
	Ghostscript    string
	LibreOffice    string
	FFmpeg         string
	FFprobe        string
	Now            func() time.Time
	Command        ScannerCommandRunner
}

type ScannerCommandRunner interface {
	Run(context.Context, string, []string, uint64) ([]byte, error)
}

type scannerOSCommandRunner struct{}

func (scannerOSCommandRunner) Run(ctx context.Context, path string, arguments []string, maximum uint64) ([]byte, error) {
	if ctx == nil || path == "" || maximum == 0 || maximum > 1<<20 {
		return nil, errors.New("invalid scanner command")
	}
	command := exec.CommandContext(ctx, path, arguments...)
	command.Env = []string{"LANG=C.UTF-8"}
	var output boundedScannerOutput
	output.remaining = maximum
	command.Stdout = &output
	command.Stderr = io.Discard
	if err := command.Run(); err != nil || output.exceeded {
		clear(output.buffer.Bytes())
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("scanner command failed")
	}
	return bytes.Clone(output.buffer.Bytes()), nil
}

type boundedScannerOutput struct {
	buffer    bytes.Buffer
	remaining uint64
	exceeded  bool
}

func (output *boundedScannerOutput) Write(value []byte) (int, error) {
	if uint64(len(value)) > output.remaining {
		output.exceeded = true
		return 0, errors.New("scanner command output exceeded")
	}
	written, err := output.buffer.Write(value)
	output.remaining -= uint64(written)
	return written, err
}

func DefaultProductionScannerConfig() ProductionScannerConfig {
	return ProductionScannerConfig{
		StateDirectory: productionScannerStateDirectory,
		PhasePath:      productionScannerPhasePath, BootModePath: productionScannerBootModePath,
		PolicyPath:    productionScannerPolicyPath,
		ToolchainPath: productionScannerToolchainPath, QuarantineRoot: productionScannerQuarantine,
		QuarantineDev: productionScannerDevice, SandboxRoot: productionScannerSandbox,
		ClamdSocket: productionScannerClamdSocket,
		Systemctl:   "/run/current-system/sw/bin/systemctl", Clamscan: "/run/current-system/sw/bin/clamscan",
		File: "/run/current-system/sw/bin/file", PDFInfo: "/run/current-system/sw/bin/pdfinfo",
		Ghostscript: "/run/current-system/sw/bin/gs", LibreOffice: "/run/current-system/sw/bin/libreoffice",
		FFmpeg: "/run/current-system/sw/bin/ffmpeg", FFprobe: "/run/current-system/sw/bin/ffprobe",
		Now: time.Now, Command: scannerOSCommandRunner{},
	}
}

// NewProductionScannerService composes only fixed image-owned paths and tools.
// It performs no host mount and accepts no paths, commands or limits from RPC.
func NewProductionScannerService(identity Identity, reportKey *Token, configuration ProductionScannerConfig) (*ScannerService, error) {
	configuration = normalizeProductionScannerConfig(configuration)
	if err := validateProductionScannerConfig(configuration); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(configuration.SandboxRoot, 0o700); err != nil {
		return nil, scannerAdapterUnavailable("scanner tmpfs sandbox")
	}
	if info, err := os.Stat(configuration.SandboxRoot); err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return nil, scannerAdapterUnavailable("scanner tmpfs sandbox")
	}
	for _, executable := range []string{configuration.Systemctl, configuration.Clamscan} {
		if err := validateScannerExecutable(executable); err != nil {
			return nil, err
		}
	}
	toolchain, err := loadScannerToolchain(configuration.ToolchainPath)
	if err != nil {
		return nil, err
	}
	selectedPolicy, err := policy.Load(configuration.PolicyPath)
	if err != nil || selectedPolicy.Name() != "safe" || selectedPolicy.Mode() != policy.ModeSafe {
		return nil, scannerAdapterUnavailable("safe policy")
	}
	classifier, err := scan.NewCommandMIMEClassifier(configuration.File)
	if err != nil {
		return nil, err
	}
	dialer, err := scan.UnixClamdDialer(configuration.ClamdSocket)
	if err != nil {
		return nil, err
	}
	clamd := scan.ClamdClient{Dial: dialer, MaxInputBytes: selectedPolicy.Limits().MaxSingleFileBytes()}
	probe := &productionScannerBootProbe{
		phasePath: configuration.PhasePath, bootModePath: configuration.BootModePath,
		stateDirectory: configuration.StateDirectory,
		quarantineRoot: configuration.QuarantineRoot, quarantineDevice: configuration.QuarantineDev,
	}
	definitions := CoreScannerDefinitions{
		Manager: scan.DefinitionManager{
			Updater: productionDefinitionUpdater{
				command: configuration.Command, systemctl: configuration.Systemctl,
				clamscan: configuration.Clamscan, databaseDirectory: "/var/lib/clamav", now: configuration.Now,
			},
			Now: configuration.Now, MaximumAge: scan.DefaultMaximumDefinitionAge,
		},
		Probe: probe, Store: productionReceiptStore{directory: configuration.StateDirectory},
		Stager: productionScannerOfflineBootStager{
			command: configuration.Command, systemctl: configuration.Systemctl,
		},
	}
	documentProbe, err := scan.NewCommandDocumentProbe(configuration.PDFInfo, toolchain.versions["poppler-utils"])
	if err != nil {
		return nil, err
	}
	mediaProbe, err := scan.NewCommandMediaProbe(configuration.FFprobe, toolchain.versions["ffmpeg"])
	if err != nil {
		return nil, err
	}
	pdf, err := scan.PDFRasterTransformer(configuration.Ghostscript, toolchain.versions["ghostscript"])
	if err != nil {
		return nil, err
	}
	media, err := scan.MediaReencodeTransformer(configuration.FFmpeg, toolchain.versions["ffmpeg"])
	if err != nil {
		return nil, err
	}
	office, err := scan.NewLibreOfficeTransformer(configuration.LibreOffice, toolchain.versions["libreoffice"], configuration.SandboxRoot)
	if err != nil {
		return nil, err
	}
	sandbox := scan.ExtractionSandbox{
		ParentPath: configuration.SandboxRoot, Tmpfs: true, PrivateMountNamespace: true,
		WorkerUID: os.Geteuid(), WorkerGID: os.Getegid(),
	}
	reconstruction := &productionScannerReconstruction{
		root: configuration.QuarantineRoot, sandbox: sandbox, classifier: classifier, scanner: clamd,
		pdf: pdf, office: office, media: media, documentProbe: documentProbe, mediaProbe: mediaProbe,
		toolchain: toolchain, outputs: make(map[string]*scan.ReconstructedOutput),
	}
	baseTools, err := toolchain.evidence("clamav", "file")
	if err != nil {
		return nil, err
	}
	return NewScannerService(ScannerServiceConfig{
		Identity: identity, Definitions: definitions,
		Isolation:      CoreScannerIsolation{Manager: definitions.Manager, Probe: probe},
		Inventory:      CoreScannerInventory{RootPath: configuration.QuarantineRoot, Classifier: classifier},
		Malware:        CoreScannerMalware{RootPath: configuration.QuarantineRoot, Scanner: clamd},
		Reconstruction: reconstruction,
		Policies: ScannerPolicyResolverFunc(func(name string) (policy.Policy, error) {
			if name != selectedPolicy.Name() {
				return policy.Policy{}, scannerAdapterUnavailable("safe policy")
			}
			return selectedPolicy, nil
		}),
		Tools: baseTools, Now: configuration.Now, ControlTimeout: 5 * time.Minute,
	}, reportKey)
}

func normalizeProductionScannerConfig(configuration ProductionScannerConfig) ProductionScannerConfig {
	defaults := DefaultProductionScannerConfig()
	if configuration.StateDirectory == "" {
		configuration.StateDirectory = defaults.StateDirectory
	}
	if configuration.PhasePath == "" {
		configuration.PhasePath = defaults.PhasePath
	}
	if configuration.BootModePath == "" {
		configuration.BootModePath = defaults.BootModePath
	}
	if configuration.PolicyPath == "" {
		configuration.PolicyPath = defaults.PolicyPath
	}
	if configuration.ToolchainPath == "" {
		configuration.ToolchainPath = defaults.ToolchainPath
	}
	if configuration.QuarantineRoot == "" {
		configuration.QuarantineRoot = defaults.QuarantineRoot
	}
	if configuration.QuarantineDev == "" {
		configuration.QuarantineDev = defaults.QuarantineDev
	}
	if configuration.SandboxRoot == "" {
		configuration.SandboxRoot = defaults.SandboxRoot
	}
	if configuration.ClamdSocket == "" {
		configuration.ClamdSocket = defaults.ClamdSocket
	}
	for target, source := range map[*string]string{
		&configuration.Systemctl: defaults.Systemctl, &configuration.Clamscan: defaults.Clamscan,
		&configuration.File: defaults.File, &configuration.PDFInfo: defaults.PDFInfo,
		&configuration.Ghostscript: defaults.Ghostscript, &configuration.LibreOffice: defaults.LibreOffice,
		&configuration.FFmpeg: defaults.FFmpeg, &configuration.FFprobe: defaults.FFprobe,
	} {
		if *target == "" {
			*target = source
		}
	}
	if configuration.Now == nil {
		configuration.Now = time.Now
	}
	if configuration.Command == nil {
		configuration.Command = scannerOSCommandRunner{}
	}
	return configuration
}

func validateProductionScannerConfig(configuration ProductionScannerConfig) error {
	paths := []string{
		configuration.StateDirectory, configuration.PhasePath, configuration.BootModePath,
		configuration.PolicyPath, configuration.ToolchainPath,
		configuration.QuarantineRoot, configuration.QuarantineDev, configuration.SandboxRoot, configuration.ClamdSocket,
		configuration.Systemctl, configuration.Clamscan, configuration.File, configuration.PDFInfo,
		configuration.Ghostscript, configuration.LibreOffice, configuration.FFmpeg, configuration.FFprobe,
	}
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsRune(path, '\x00') {
			return scannerAdapterUnavailable("fixed production paths")
		}
	}
	if os.Geteuid() <= 0 || os.Getegid() <= 0 {
		return scannerAdapterUnavailable("unprivileged scanner worker")
	}
	return nil
}

type scannerToolchainDocument struct {
	SchemaVersion            int                    `json:"schema_version"`
	Project                  string                 `json:"project"`
	Role                     string                 `json:"role"`
	Architecture             string                 `json:"architecture"`
	SourceCommit             string                 `json:"source_commit"`
	FlakeLockSHA256          string                 `json:"flake_lock_sha256"`
	ArchiveExecutionContract string                 `json:"archive_execution_contract"`
	Tools                    []scannerToolchainTool `json:"tools"`
}

type scannerToolchainTool struct {
	ID       string   `json:"id"`
	Package  string   `json:"package"`
	Version  string   `json:"version"`
	Commands []string `json:"commands"`
	Purpose  string   `json:"purpose"`
}

type productionScannerToolchain struct{ versions map[string]string }

func loadScannerToolchain(path string) (productionScannerToolchain, error) {
	data, err := readFixedRegular(path, maximumScannerMetadataBytes)
	if err != nil {
		return productionScannerToolchain{}, scannerAdapterUnavailable("scanner tool manifest")
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document scannerToolchainDocument
	if err := decoder.Decode(&document); err != nil || decoder.Decode(&struct{}{}) != io.EOF || document.SchemaVersion != 1 || document.Project != "private-vm" ||
		document.Role != "scanner" || document.Architecture != scannerManifestArchitecture() || !scannerSourceCommitPattern.MatchString(document.SourceCommit) ||
		!scannerFlakeLockHashPattern.MatchString(document.FlakeLockSHA256) || document.ArchiveExecutionContract != "guestd-bounded-unprivileged-private-namespace" ||
		len(document.Tools) == 0 || len(document.Tools) > 64 {
		return productionScannerToolchain{}, scannerAdapterUnavailable("scanner tool manifest")
	}
	versions := make(map[string]string, len(document.Tools))
	for _, tool := range document.Tools {
		if !validScannerToolRecord(tool) || versions[tool.ID] != "" {
			return productionScannerToolchain{}, scannerAdapterUnavailable("scanner tool manifest")
		}
		versions[tool.ID] = tool.Version
	}
	for _, required := range productionScannerTools {
		if versions[required.id] == "" {
			return productionScannerToolchain{}, scannerAdapterUnavailable("scanner tool manifest")
		}
		commands := scannerToolCommands(document.Tools, required.id)
		for _, command := range required.commands {
			if !slices.Contains(commands, command) {
				return productionScannerToolchain{}, scannerAdapterUnavailable("scanner tool manifest")
			}
		}
	}
	return productionScannerToolchain{versions: versions}, nil
}

func validScannerToolRecord(tool scannerToolchainTool) bool {
	if len(tool.ID) == 0 || len(tool.ID) > 64 || !scannerToolIDPattern.MatchString(tool.ID) ||
		len(tool.Package) == 0 || len(tool.Package) > 128 || !scannerToolPackagePattern.MatchString(tool.Package) ||
		len(tool.Version) == 0 || len(tool.Version) > 128 || !validScannerManifestText(tool.Version, 128) ||
		len(tool.Purpose) == 0 || len(tool.Purpose) > 256 || !validScannerManifestText(tool.Purpose, 256) ||
		len(tool.Commands) == 0 || len(tool.Commands) > 32 {
		return false
	}
	seen := make(map[string]struct{}, len(tool.Commands))
	for _, command := range tool.Commands {
		if len(command) > 64 || !scannerToolCommandPattern.MatchString(command) {
			return false
		}
		if _, duplicate := seen[command]; duplicate {
			return false
		}
		seen[command] = struct{}{}
	}
	return true
}

func validScannerManifestText(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func scannerManifestArchitecture() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return "unsupported"
	}
}

func scannerToolCommands(tools []scannerToolchainTool, id string) []string {
	for _, tool := range tools {
		if tool.ID == id {
			return tool.Commands
		}
	}
	return nil
}

func (toolchain productionScannerToolchain) evidence(ids ...string) ([]scan.ToolEvidence, error) {
	evidence := make([]scan.ToolEvidence, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		version := toolchain.versions[id]
		if version == "" {
			return nil, scannerAdapterUnavailable("scanner tool manifest")
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, scannerAdapterUnavailable("scanner tool manifest")
		}
		seen[id] = struct{}{}
		evidence = append(evidence, scan.ToolEvidence{Name: id, Version: version})
	}
	return evidence, nil
}

type productionDefinitionUpdater struct {
	command           ScannerCommandRunner
	systemctl         string
	clamscan          string
	databaseDirectory string
	now               func() time.Time
}

// productionScannerOfflineBootStager exposes exactly one image-owned action:
// make the immutable scan-offline Nix specialisation the next boot target.
// The RPC caller cannot supply a unit, command, path or argument.
type productionScannerOfflineBootStager struct {
	command   ScannerCommandRunner
	systemctl string
}

func (stager productionScannerOfflineBootStager) Stage(ctx context.Context) error {
	if ctx == nil || stager.command == nil || stager.systemctl == "" {
		return scannerAdapterUnavailable("offline boot stager")
	}
	if _, err := stager.command.Run(ctx, stager.systemctl, []string{"start", productionScannerOfflineUnit}, 4096); err != nil {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, cleanupErr := stager.command.Run(cleanupContext, stager.systemctl, []string{"stop", productionScannerOfflineUnit}, 4096)
		cancel()
		if cleanupErr != nil {
			return &scan.Error{
				Code: "SCANNER_OFFLINE_BOOT_STAGE_CLEANUP_INCOMPLETE", Message: "The failed offline boot selection could not be stopped completely.",
				Remediation: "Destroy the scanner so its VM cleanup owner removes the retained overlay.",
			}
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return &scan.Error{
			Code: "SCANNER_OFFLINE_BOOT_STAGE_FAILED", Message: "The scanner offline specialisation could not be selected for the next boot.",
			Remediation: "Destroy the scanner and repeat its online update boot with the verified scanner image.",
		}
	}
	return nil
}

func (updater productionDefinitionUpdater) Update(ctx context.Context) (scan.DefinitionEvidence, error) {
	if updater.command == nil || updater.now == nil {
		return scan.DefinitionEvidence{}, scannerAdapterUnavailable("definition updater")
	}
	if _, err := updater.command.Run(ctx, updater.systemctl, []string{"start", "private-vm-scanner-definitions-update.service"}, 4096); err != nil {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, cleanupErr := updater.command.Run(cleanupContext, updater.systemctl, []string{"stop", "private-vm-scanner-definitions-update.service"}, 4096)
		cancel()
		if cleanupErr != nil {
			return scan.DefinitionEvidence{}, &scan.Error{
				Code: "SCANNER_UPDATE_CLEANUP_INCOMPLETE", Message: "The failed definition update could not be stopped completely.",
				Remediation: "Destroy the scanner so its VM cleanup owner terminates the update unit.",
			}
		}
		return scan.DefinitionEvidence{}, &scan.Error{
			Code: "SCANNER_UPDATE_FAILED", Message: "The fixed FreshClam update unit did not complete.",
			Remediation: "Keep Proton connected and retry the scanner update boot.",
		}
	}
	evidence, err := updater.evidence(ctx)
	if err != nil {
		return scan.DefinitionEvidence{}, err
	}
	// clamd may have started before the first database existed. A fixed restart
	// loads the newly authenticated database and is also safe for a no-change
	// FreshClam result.
	if _, err := updater.command.Run(ctx, updater.systemctl, []string{"restart", "clamav-daemon.service"}, 4096); err != nil {
		return scan.DefinitionEvidence{}, &scan.Error{
			Code: "SCANNER_UPDATE_FAILED", Message: "ClamAV could not load the verified definition set.",
			Remediation: "Destroy the scanner and repeat its online update boot.",
		}
	}
	return evidence, nil
}

func (updater productionDefinitionUpdater) evidence(ctx context.Context) (scan.DefinitionEvidence, error) {
	output, err := updater.command.Run(ctx, updater.clamscan, []string{"--version"}, 4096)
	if err != nil {
		return scan.DefinitionEvidence{}, scannerAdapterUnavailable("ClamAV definition identity")
	}
	defer clear(output)
	match := clamVersionPattern.FindSubmatch(bytes.TrimSpace(output))
	if len(match) != 3 {
		return scan.DefinitionEvidence{}, scannerAdapterUnavailable("ClamAV definition identity")
	}
	now := updater.now().UTC()
	oldest := time.Time{}
	for _, base := range []string{"main", "daily", "bytecode"} {
		selected := time.Time{}
		for _, extension := range []string{"cvd", "cld"} {
			path := filepath.Join(updater.databaseDirectory, base+"."+extension)
			info, statErr := os.Stat(path)
			if statErr == nil && info.Mode().IsRegular() && info.Size() > 0 {
				modified := info.ModTime().UTC()
				if modified.After(selected) {
					selected = modified
				}
			}
		}
		if selected.IsZero() {
			return scan.DefinitionEvidence{}, scannerAdapterUnavailable("official ClamAV databases")
		}
		if selected.After(now.Add(5 * time.Minute)) {
			return scan.DefinitionEvidence{}, scannerAdapterUnavailable("ClamAV database timestamp")
		}
		if oldest.IsZero() || selected.Before(oldest) {
			oldest = selected
		}
	}
	if oldest.IsZero() {
		return scan.DefinitionEvidence{}, scannerAdapterUnavailable("ClamAV database timestamp")
	}
	return scan.DefinitionEvidence{
		EngineVersion: string(match[1]), DatabaseVersion: string(match[2]), UpdatedAt: oldest,
		Official: true, Compatible: true, Complete: true,
	}, nil
}

type productionReceiptStore struct{ directory string }

type scannerReceiptDocument struct {
	SchemaVersion   int       `json:"schema_version"`
	OverlayIdentity string    `json:"overlay_identity"`
	EngineVersion   string    `json:"engine_version"`
	DatabaseVersion string    `json:"database_version"`
	UpdatedAt       time.Time `json:"updated_at"`
	Official        bool      `json:"official"`
	Compatible      bool      `json:"compatible"`
	Complete        bool      `json:"complete"`
}

func (store productionReceiptStore) Save(ctx context.Context, receipt scan.UpdateReceipt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	document := scannerReceiptDocument{
		SchemaVersion: 1, OverlayIdentity: receipt.OverlayIdentity,
		EngineVersion: receipt.Definitions.EngineVersion, DatabaseVersion: receipt.Definitions.DatabaseVersion,
		UpdatedAt: receipt.Definitions.UpdatedAt.UTC(), Official: receipt.Definitions.Official,
		Compatible: receipt.Definitions.Compatible, Complete: receipt.Definitions.Complete,
	}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) > maximumScannerMetadataBytes {
		return scannerAdapterUnavailable("definition receipt")
	}
	defer clear(encoded)
	return writeAtomicScannerState(store.directory, "definitions.json", encoded)
}

func (store productionReceiptStore) Load(ctx context.Context) (scan.UpdateReceipt, error) {
	if err := ctx.Err(); err != nil {
		return scan.UpdateReceipt{}, err
	}
	data, err := readFixedRegular(filepath.Join(store.directory, "definitions.json"), maximumScannerMetadataBytes)
	if err != nil {
		return scan.UpdateReceipt{}, scannerAdapterUnavailable("definition receipt")
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document scannerReceiptDocument
	if err := decoder.Decode(&document); err != nil || decoder.Decode(&struct{}{}) != io.EOF || document.SchemaVersion != 1 {
		return scan.UpdateReceipt{}, scannerAdapterUnavailable("definition receipt")
	}
	return scan.UpdateReceipt{
		OverlayIdentity: document.OverlayIdentity,
		Definitions: scan.DefinitionEvidence{
			EngineVersion: document.EngineVersion, DatabaseVersion: document.DatabaseVersion,
			UpdatedAt: document.UpdatedAt.UTC(), Official: document.Official,
			Compatible: document.Compatible, Complete: document.Complete,
		},
	}, nil
}

type scannerPhaseDocument struct {
	SchemaVersion           int      `json:"schema_version"`
	Role                    string   `json:"role"`
	Phase                   string   `json:"phase"`
	NetworkDevicePolicy     string   `json:"network_device_policy"`
	QuarantineDevicePolicy  string   `json:"quarantine_device_policy"`
	QuarantineMountOptions  []string `json:"quarantine_mount_options,omitempty"`
	DefinitionsUpdatePolicy string   `json:"definitions_update"`
}

type productionScannerBootProbe struct {
	phasePath        string
	bootModePath     string
	stateDirectory   string
	quarantineRoot   string
	quarantineDevice string
}

type scannerVPNVerifiedContextKey struct{}

func scannerVPNVerifiedContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, scannerVPNVerifiedContextKey{}, true)
}

func (probe *productionScannerBootProbe) Evidence(ctx context.Context) (scan.BootEvidence, error) {
	if err := ctx.Err(); err != nil {
		return scan.BootEvidence{}, err
	}
	phase, err := loadScannerPhase(probe.phasePath)
	if err != nil {
		return scan.BootEvidence{}, err
	}
	bootMode, err := loadScannerBootMode(probe.bootModePath)
	if err != nil || bootMode != phase.Phase {
		return scan.BootEvidence{}, &scan.Error{
			Code: "SCANNER_BOOT_MODE_MISMATCH", Message: "The scanner boot selection does not match the immutable guest phase.",
			Remediation: "Destroy the scanner and relaunch the verified scanner phase through the private-vm daemon.",
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) == 0 {
		return scan.BootEvidence{}, scannerAdapterUnavailable("guest interface evidence")
	}
	evidence := scan.BootEvidence{Interfaces: make([]scan.InterfaceEvidence, 0, len(interfaces))}
	for _, networkInterface := range interfaces {
		if networkInterface.Name == "" || len(networkInterface.Name) > 256 || strings.ContainsAny(networkInterface.Name, "\x00\r\n") {
			return scan.BootEvidence{}, scannerAdapterUnavailable("guest interface evidence")
		}
		evidence.Interfaces = append(evidence.Interfaces, scan.InterfaceEvidence{
			Name: networkInterface.Name, Loopback: networkInterface.Flags&net.FlagLoopback != 0,
		})
	}
	slices.SortFunc(evidence.Interfaces, func(left, right scan.InterfaceEvidence) int { return strings.Compare(left.Name, right.Name) })
	switch phase.Phase {
	case "definitions-update":
		devicePresent, deviceErr := pathExists(probe.quarantineDevice)
		mountPresent, mountErr := scannerMountPresent(probe.quarantineRoot)
		if phase.NetworkDevicePolicy != "proton-only" || phase.QuarantineDevicePolicy != "forbidden" || phase.DefinitionsUpdatePolicy != "enabled" ||
			len(phase.QuarantineMountOptions) != 0 || deviceErr != nil || mountErr != nil || devicePresent || mountPresent {
			return scan.BootEvidence{}, scannerAdapterUnavailable("scanner update isolation")
		}
		evidence.Phase = scan.PhaseUpdate
		evidence.VPNVerified, _ = ctx.Value(scannerVPNVerifiedContextKey{}).(bool)
	case "scan-offline":
		if phase.NetworkDevicePolicy != "forbidden" || phase.QuarantineDevicePolicy != "required-read-only" || phase.DefinitionsUpdatePolicy != "disabled" ||
			!slices.Equal(phase.QuarantineMountOptions, []string{"nodev", "noexec", "nosuid", "ro"}) {
			return scan.BootEvidence{}, scannerAdapterUnavailable("scanner offline isolation")
		}
		evidence.Phase = scan.PhaseOffline
		evidence.Quarantine, err = inspectQuarantineMount(probe.quarantineRoot, probe.quarantineDevice)
		if err != nil {
			return scan.BootEvidence{}, err
		}
	default:
		return scan.BootEvidence{}, scannerAdapterUnavailable("scanner boot phase")
	}
	evidence.OverlayIdentity, err = scannerOverlayIdentity(probe.stateDirectory, evidence.Phase == scan.PhaseUpdate)
	if err != nil {
		return scan.BootEvidence{}, err
	}
	return evidence, nil
}

func loadScannerPhase(path string) (scannerPhaseDocument, error) {
	data, err := readFixedRegular(path, 16<<10)
	if err != nil {
		return scannerPhaseDocument{}, scannerAdapterUnavailable("scanner boot phase")
	}
	defer clear(data)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document scannerPhaseDocument
	if err := decoder.Decode(&document); err != nil || decoder.Decode(&struct{}{}) != io.EOF || document.SchemaVersion != 1 || document.Role != "scanner" {
		return scannerPhaseDocument{}, scannerAdapterUnavailable("scanner boot phase")
	}
	return document, nil
}

func loadScannerBootMode(path string) (string, error) {
	data, err := readBoundedPseudoFile(path, 32)
	if err != nil {
		return "", err
	}
	defer clear(data)
	// QEMU string-backed fw_cfg entries may include their single terminating
	// NUL. Accept that representation only; whitespace and additional bytes
	// remain invalid.
	if data[len(data)-1] == 0 {
		data = data[:len(data)-1]
	}
	mode := string(data)
	if mode != "definitions-update" && mode != "scan-offline" {
		return "", errors.New("invalid scanner boot mode")
	}
	return mode, nil
}

func scannerOverlayIdentity(directory string, create bool) (string, error) {
	path := filepath.Join(directory, "overlay-id")
	data, err := readFixedRegular(path, 128)
	if err == nil {
		defer clear(data)
		value := strings.TrimSpace(string(data))
		decoded, decodeErr := hex.DecodeString(value)
		clear(decoded)
		if decodeErr != nil || len(value) != 64 {
			return "", scannerAdapterUnavailable("scanner overlay identity")
		}
		return value, nil
	}
	if !create || !errors.Is(err, os.ErrNotExist) {
		return "", scannerAdapterUnavailable("scanner overlay identity")
	}
	value := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		clear(value)
		return "", scannerAdapterUnavailable("scanner overlay identity")
	}
	encoded := []byte(hex.EncodeToString(value) + "\n")
	clear(value)
	if err := writeAtomicScannerState(directory, "overlay-id", encoded); err != nil {
		clear(encoded)
		return "", err
	}
	result := strings.TrimSpace(string(encoded))
	clear(encoded)
	return result, nil
}

func readFixedRegular(path string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maximum <= 0 || maximum > 1<<20 {
		return nil, errors.New("invalid fixed file")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "scanner-fixed-state")
	if file == nil {
		unix.Close(fd)
		return nil, errors.New("invalid fixed descriptor")
	}
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maximum || stat.Mode&0o022 != 0 {
		return nil, errors.New("unsafe fixed file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != stat.Size {
		clear(data)
		return nil, errors.New("fixed file read failed")
	}
	return data, nil
}

func writeAtomicScannerState(directory, name string, data []byte) error {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || filepath.Base(name) != name || name == "." || len(data) == 0 || len(data) > maximumScannerMetadataBytes {
		return scannerAdapterUnavailable("scanner state")
	}
	directoryFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return scannerAdapterUnavailable("scanner state")
	}
	defer unix.Close(directoryFD)
	temporary := "." + name + ".tmp"
	_ = unix.Unlinkat(directoryFD, temporary, 0)
	fd, err := unix.Openat(directoryFD, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return scannerAdapterUnavailable("scanner state")
	}
	file := os.NewFile(uintptr(fd), "scanner-state")
	if file == nil {
		unix.Close(fd)
		_ = unix.Unlinkat(directoryFD, temporary, 0)
		return scannerAdapterUnavailable("scanner state")
	}
	written, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(data) {
		_ = unix.Unlinkat(directoryFD, temporary, 0)
		return scannerAdapterUnavailable("scanner state")
	}
	if err := unix.Renameat(directoryFD, temporary, directoryFD, name); err != nil {
		_ = unix.Unlinkat(directoryFD, temporary, 0)
		return scannerAdapterUnavailable("scanner state")
	}
	if err := unix.Fsync(directoryFD); err != nil {
		return scannerAdapterUnavailable("scanner state")
	}
	return nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func scannerMountPresent(target string) (bool, error) {
	data, err := readBoundedPseudoFile("/proc/self/mountinfo", 1<<20)
	if err != nil {
		return false, err
	}
	defer clear(data)
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		fields := bytes.Fields(line)
		if len(fields) >= 5 && string(fields[4]) == target {
			return true, nil
		}
	}
	return false, nil
}

func validateScannerExecutable(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(resolved) {
		return scannerAdapterUnavailable("fixed scanner executable")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return scannerAdapterUnavailable("fixed scanner executable")
	}
	var stat unix.Stat_t
	if err := unix.Stat(resolved, &stat); err != nil || stat.Uid != 0 || stat.Nlink == 0 {
		return scannerAdapterUnavailable("fixed scanner executable")
	}
	return nil
}

func inspectQuarantineMount(target, device string) (scan.QuarantineEvidence, error) {
	resolvedDevice, err := filepath.EvalSymlinks(device)
	if err != nil || !filepath.IsAbs(resolvedDevice) {
		return scan.QuarantineEvidence{}, scannerAdapterUnavailable("quarantine device identity")
	}
	deviceInfo, err := os.Stat(resolvedDevice)
	if err != nil || deviceInfo.Mode()&os.ModeDevice == 0 {
		return scan.QuarantineEvidence{}, scannerAdapterUnavailable("quarantine device identity")
	}
	readOnlyData, err := readBoundedPseudoFile(filepath.Join("/sys/class/block", filepath.Base(resolvedDevice), "ro"), 16)
	if err != nil {
		return scan.QuarantineEvidence{}, scannerAdapterUnavailable("quarantine read-only evidence")
	}
	readOnly := strings.TrimSpace(string(readOnlyData)) == "1"
	clear(readOnlyData)
	data, err := readBoundedPseudoFile("/proc/self/mountinfo", 1<<20)
	if err != nil {
		return scan.QuarantineEvidence{}, scannerAdapterUnavailable("quarantine mount evidence")
	}
	defer clear(data)
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		fields := strings.Fields(string(line))
		separator := slices.Index(fields, "-")
		if len(fields) < 10 || separator < 6 || separator+3 >= len(fields) || fields[4] != target {
			continue
		}
		resolvedSource, sourceErr := filepath.EvalSymlinks(fields[separator+2])
		if sourceErr != nil || resolvedSource != resolvedDevice {
			return scan.QuarantineEvidence{}, scannerAdapterUnavailable("quarantine mount source")
		}
		security := make(map[string]bool)
		for _, optionSet := range []string{fields[5], fields[separator+3]} {
			for _, option := range strings.Split(optionSet, ",") {
				switch option {
				case "ro", "nodev", "noexec", "nosuid":
					security[option] = true
				}
			}
		}
		options := []string{"nodev", "noexec", "nosuid", "ro"}
		for _, option := range options {
			if !security[option] {
				return scan.QuarantineEvidence{}, scannerAdapterUnavailable("quarantine mount options")
			}
		}
		return scan.QuarantineEvidence{Attached: true, ReadOnly: readOnly, MountOptions: options}, nil
	}
	return scan.QuarantineEvidence{}, scannerAdapterUnavailable("quarantine mount evidence")
}

func readBoundedPseudoFile(path string, maximum int64) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || maximum <= 0 || maximum > 1<<20 {
		return nil, errors.New("invalid pseudo file")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "scanner-kernel-evidence")
	if file == nil {
		unix.Close(fd)
		return nil, errors.New("invalid pseudo descriptor")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(data) == 0 || int64(len(data)) > maximum {
		clear(data)
		return nil, errors.New("pseudo file read failed")
	}
	return data, nil
}

type productionScannerReconstruction struct {
	mu sync.Mutex

	root          string
	sandbox       scan.ExtractionSandbox
	classifier    scan.MIMEClassifier
	scanner       ScannerContentScanner
	pdf           scan.Transformer
	office        scan.Transformer
	media         scan.Transformer
	documentProbe scan.DocumentProbe
	mediaProbe    scan.MediaProbe
	toolchain     productionScannerToolchain
	outputs       map[string]*scan.ReconstructedOutput
	closed        bool
}

type productionReconstructionRun struct {
	adapter       *productionScannerReconstruction
	result        *ScannerReconstruction
	reconstructor scan.Reconstructor
	archiveLimits scan.ArchiveLimits
	entries       uint64
	expanded      uint64
	reported      map[string]struct{}
}

func (adapter *productionScannerReconstruction) Reconstruct(ctx context.Context, inventory scan.Inventory, summary scan.ScanSummary, selected policy.Policy) (ScannerReconstruction, error) {
	if adapter == nil || selected.Validate() != nil || selected.Mode() != policy.ModeSafe || adapter.scanner == nil || adapter.classifier == nil {
		return ScannerReconstruction{}, scannerAdapterUnavailable("reconstruction")
	}
	adapter.mu.Lock()
	if adapter.closed || len(adapter.outputs) != 0 {
		adapter.mu.Unlock()
		return ScannerReconstruction{}, scannerAdapterUnavailable("reconstruction state")
	}
	adapter.mu.Unlock()
	result := ScannerReconstruction{ArchiveInspectionComplete: true, ReconstructionComplete: true, OutputRescanComplete: true}
	clean := make(map[string]bool, len(summary.Findings))
	for _, finding := range summary.Findings {
		clean[finding.RelativePath] = finding.Code == "CLAMAV_CLEAN" && finding.Severity == scan.SeverityInfo
	}
	limits := selected.Limits()
	reconstructor := scan.Reconstructor{
		Policy: selected, Sandbox: adapter.sandbox, Classifier: adapter.classifier, Rescanner: adapter.scanner,
		PDF: adapter.pdf, OfficeRenderer: adapter.office, Media: adapter.media,
		DocumentProbe: adapter.documentProbe, MediaProbe: adapter.mediaProbe,
		Limits: scan.ReconstructionLimits{
			MaxOutputBytes: limits.MaxSingleFileBytes(), MaxImagePixels: 100_000_000,
			MaxDocumentPages: 2000, MaxDimension: 32768, MaxMediaDuration: 24 * 60 * 60,
			MaxMediaStreams: 32, MaxTextBytes: min(limits.MaxSingleFileBytes(), 64<<20),
		},
	}
	run := &productionReconstructionRun{
		adapter: adapter, result: &result, reconstructor: reconstructor,
		archiveLimits: scan.ArchiveLimits{
			MaxDepth: limits.MaxArchiveDepth(), MaxEntries: limits.MaxFiles(),
			MaxPathBytes: scan.MaximumInventoryPathBytes, MaxFileBytes: limits.MaxSingleFileBytes(),
			MaxExpandedBytes: limits.MaxExpandedBytes(), MaxExpansionRatio: limits.MaxExpansionRatio(),
		},
		reported: make(map[string]struct{}),
	}
	for _, entry := range inventory.Entries {
		if err := ctx.Err(); err != nil {
			_ = adapter.Cleanup(context.Background())
			return ScannerReconstruction{}, err
		}
		if !clean[entry.RelativePath] {
			continue
		}
		if err := run.processEntry(ctx, adapter.root, entry, entry.RelativePath, 0); err != nil {
			_ = adapter.Cleanup(context.Background())
			return ScannerReconstruction{}, err
		}
	}
	if len(result.Outputs) != 1 && len(result.Findings) == 0 {
		result.Findings = append(result.Findings, productionBlockingFinding("PROMOTION_SELECTION_REQUIRED", "", "The safe v1 workflow requires exactly one reconstructed output."))
	}
	return result, nil
}

func (toolchain productionScannerToolchain) reconstructionEvidence(transformation string, observed []scan.ToolEvidence) ([]scan.ToolEvidence, error) {
	var expected []scan.ToolEvidence
	var manifestIDs []string
	version := func(id string) string { return toolchain.versions[id] }
	switch transformation {
	case "pdf-raster-rebuild-v1":
		expected = []scan.ToolEvidence{
			{Name: "poppler-pdfinfo", Version: version("poppler-utils")},
			{Name: "ghostscript-pdfimage24", Version: version("ghostscript")},
			{Name: "poppler-pdfinfo", Version: version("poppler-utils")},
		}
		manifestIDs = []string{"poppler-utils", "ghostscript"}
	case "office-render-pdf-raster-rebuild-v1":
		expected = []scan.ToolEvidence{
			{Name: "libreoffice-headless-pdf", Version: version("libreoffice")},
			{Name: "poppler-pdfinfo", Version: version("poppler-utils")},
			{Name: "ghostscript-pdfimage24", Version: version("ghostscript")},
			{Name: "poppler-pdfinfo", Version: version("poppler-utils")},
		}
		manifestIDs = []string{"libreoffice", "poppler-utils", "ghostscript"}
	case "media-full-decode-aac-v1", "media-full-decode-h264-aac-v1":
		expected = []scan.ToolEvidence{
			{Name: "ffprobe-json", Version: version("ffmpeg")},
			{Name: "ffmpeg-h264-aac", Version: version("ffmpeg")},
			{Name: "ffprobe-json", Version: version("ffmpeg")},
		}
		manifestIDs = []string{"ffmpeg"}
	case "image-decode-strip-reencode-png-v1":
		expected = []scan.ToolEvidence{{Name: "go-image-png", Version: "go1.26"}}
	case "text-utf8-line-normalize-v1":
		expected = []scan.ToolEvidence{{Name: "private-vm-text-normalizer", Version: "1"}}
	default:
		return nil, scannerAdapterUnavailable("reconstruction tool evidence")
	}
	if !slices.Equal(observed, expected) {
		return nil, scannerAdapterUnavailable("reconstruction tool evidence")
	}
	if len(manifestIDs) == 0 {
		return slices.Clone(observed), nil
	}
	return toolchain.evidence(manifestIDs...)
}

func (run *productionReconstructionRun) processEntry(ctx context.Context, root string, entry scan.InventoryEntry, reportPath string, depth uint32) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !entry.ExtensionAgreement {
		run.result.Findings = append(run.result.Findings, productionBlockingFinding("TYPE_MISMATCH", reportPath, "The filename extension does not agree with the detected content type."))
		return nil
	}
	switch productionContentClass(entry.DetectedMIME) {
	case scan.ContentActive:
		run.result.Findings = append(run.result.Findings, productionBlockingFinding("ACTIVE_CONTENT_BLOCKED", reportPath, "Active content cannot be promoted by the safe policy."))
		return nil
	case scan.ContentUnsupported:
		run.result.Findings = append(run.result.Findings, productionBlockingFinding("SANITIZER_UNSUPPORTED_TYPE", reportPath, "This content type has no safe reconstruction backend."))
		return nil
	case scan.ContentArchive:
		if entry.DetectedMIME != "application/zip" && entry.DetectedMIME != "application/x-tar" {
			run.result.Findings = append(run.result.Findings, productionBlockingFinding("ARCHIVE_FORMAT_UNSUPPORTED", reportPath, "This archive encoding cannot be safely expanded by v1."))
			return nil
		}
		err := run.processArchive(ctx, root, entry, reportPath, depth)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		code := scan.ErrorCode(err)
		if archiveContentRejection(code) {
			run.result.Findings = append(run.result.Findings, productionBlockingFinding(code, reportPath, "The archive violated a bounded containment rule."))
			return nil
		}
		return err
	}
	reader, err := scan.OpenInventoryEntry(ctx, root, entry)
	if err != nil {
		return err
	}
	file, ok := reader.(*os.File)
	if !ok {
		reader.Close()
		return scannerAdapterUnavailable("reconstruction input")
	}
	output, reconstructErr := run.reconstructor.Reconstruct(ctx, file, entry)
	closeErr := file.Close()
	if reconstructErr != nil || closeErr != nil || output == nil {
		return errors.Join(reconstructErr, closeErr)
	}
	outputID, err := newScannerOutputID()
	if err != nil {
		_ = output.Cleanup()
		return err
	}
	run.adapter.mu.Lock()
	if run.adapter.closed || run.adapter.outputs[outputID] != nil {
		run.adapter.mu.Unlock()
		_ = output.Cleanup()
		return scannerAdapterUnavailable("reconstruction output")
	}
	run.adapter.outputs[outputID] = output
	run.adapter.mu.Unlock()
	run.result.Outputs = append(run.result.Outputs, scan.ReportSanitizedOutput{
		OutputID: outputID, LogicalName: sanitizedLogicalName(entry, output.DetectedMIME),
		SourceSHA256: entry.SHA256, SizeBytes: output.SizeBytes, SHA256: output.SHA256,
		DetectedMIME: output.DetectedMIME, Transformation: output.Transformation, RescanVerdict: "CLAMAV_CLEAN",
	})
	toolEvidence, err := run.adapter.toolchain.reconstructionEvidence(output.Transformation, output.Tools)
	if err != nil {
		_ = output.Cleanup()
		return err
	}
	run.result.Tools = append(run.result.Tools, toolEvidence...)
	return nil
}

func (run *productionReconstructionRun) processArchive(ctx context.Context, root string, entry scan.InventoryEntry, reportPath string, depth uint32) (returnedErr error) {
	if run.entries >= run.archiveLimits.MaxEntries || run.expanded >= run.archiveLimits.MaxExpandedBytes {
		return &scan.Error{Code: "ARCHIVE_LIMIT_REACHED", Message: "Archive content exceeds the cumulative extraction budget.", Remediation: "Reduce archive size or nesting and restart the workflow."}
	}
	limits := run.archiveLimits
	limits.MaxEntries -= run.entries
	limits.MaxExpandedBytes -= run.expanded
	reader, err := scan.OpenInventoryEntry(ctx, root, entry)
	if err != nil {
		return err
	}
	file, ok := reader.(*os.File)
	if !ok {
		reader.Close()
		return scannerAdapterUnavailable("archive input")
	}
	var plan scan.ArchivePlan
	switch entry.DetectedMIME {
	case "application/zip":
		plan, err = scan.InspectZIP(ctx, file, int64(entry.SizeBytes), depth, limits)
	case "application/x-tar":
		plan, err = scan.InspectTAR(ctx, file, entry.SizeBytes, depth, limits)
	}
	if err != nil {
		_ = file.Close()
		return err
	}
	if len(plan.Entries) == 0 || plan.ExpandedBytes == 0 {
		_ = file.Close()
		return &scan.Error{Code: "ARCHIVE_INVALID", Message: "The archive has no inspectable regular content.", Remediation: "Reject empty or uninspectable archives under the safe policy."}
	}
	run.entries += uint64(len(plan.Entries))
	run.expanded += plan.ExpandedBytes
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return &scan.Error{Code: "ARCHIVE_INVALID", Message: "The archive could not be rewound safely.", Remediation: "Reject the archive and restart scanning in a fresh scanner."}
	}
	var extraction *scan.Extraction
	switch entry.DetectedMIME {
	case "application/zip":
		extraction, err = scan.ExtractZIP(ctx, file, int64(entry.SizeBytes), depth, limits, run.adapter.sandbox, run.adapter.classifier)
	case "application/x-tar":
		extraction, err = scan.ExtractTAR(ctx, file, entry.SizeBytes, depth, limits, run.adapter.sandbox, run.adapter.classifier)
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil || extraction == nil {
		return errors.Join(err, closeErr)
	}
	defer func() {
		if cleanupErr := extraction.Cleanup(); cleanupErr != nil {
			returnedErr = errors.Join(cleanupErr, returnedErr)
		}
	}()
	manifest := extraction.Manifest()
	summary, err := scan.ScanInventory(ctx, manifest, func(openContext context.Context, member scan.InventoryEntry) (io.ReadCloser, error) {
		return scan.OpenInventoryEntry(openContext, extraction.RootPath(), member)
	}, run.adapter.scanner)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	if !summary.Complete || summary.ScannedFiles != uint64(len(manifest.Entries)) || len(summary.Findings) != len(manifest.Entries) {
		return scannerAdapterUnavailable("archive malware evidence")
	}
	for index, member := range manifest.Entries {
		memberPath, ok := archiveMemberReportPath(reportPath, member.RelativePath)
		if !ok {
			run.result.Findings = append(run.result.Findings, productionBlockingFinding("ARCHIVE_PATH_UNSAFE", reportPath, "A recursive archive member path exceeds the report and traversal bound."))
			continue
		}
		finding := summary.Findings[index]
		if finding.Code != "CLAMAV_CLEAN" || finding.Severity != scan.SeverityInfo {
			finding.RelativePath = memberPath
			run.result.Findings = append(run.result.Findings, finding)
			continue
		}
		if err := run.processEntry(ctx, extraction.RootPath(), member, memberPath, depth+1); err != nil {
			return err
		}
	}
	reportKey := entry.SHA256 + "\x00" + string(plan.Format) + "\x00" + hex.EncodeToString([]byte{byte(depth)})
	if _, exists := run.reported[reportKey]; !exists {
		run.reported[reportKey] = struct{}{}
		run.result.Archives = append(run.result.Archives, scan.ReportArchive{
			SourceSHA256: entry.SHA256, Format: plan.Format, Depth: plan.Depth,
			EntryCount: uint64(len(plan.Entries)), ExpandedBytes: plan.ExpandedBytes, Complete: true,
		})
	}
	return nil
}

func archiveMemberReportPath(parent, member string) (string, bool) {
	value := parent + "!/" + member
	return value, len(value) <= scan.MaximumInventoryPathBytes
}

func archiveContentRejection(code string) bool {
	switch code {
	case "ARCHIVE_INVALID", "ARCHIVE_ENCRYPTED", "ARCHIVE_LINK_REJECTED", "ARCHIVE_SPECIAL_FILE_REJECTED",
		"ARCHIVE_DUPLICATE_PATH", "ARCHIVE_LIMIT_REACHED", "ARCHIVE_PATH_UNSAFE", "ARCHIVE_EXTRACTION_FAILED",
		"SCAN_LIMIT_REACHED":
		return true
	default:
		return false
	}
}

func (adapter *productionScannerReconstruction) OpenApproved(ctx context.Context, outputID string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	adapter.mu.Lock()
	output := adapter.outputs[outputID]
	closed := adapter.closed
	adapter.mu.Unlock()
	if closed || output == nil {
		return nil, scannerAdapterUnavailable("approved output")
	}
	return output.Open()
}

func (adapter *productionScannerReconstruction) Cleanup(ctx context.Context) error {
	if adapter == nil {
		return nil
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	var cleanupErrors []error
	for outputID, output := range adapter.outputs {
		if err := ctx.Err(); err != nil {
			cleanupErrors = append(cleanupErrors, err)
			break
		}
		if err := output.Cleanup(); err != nil {
			cleanupErrors = append(cleanupErrors, err)
			continue
		}
		delete(adapter.outputs, outputID)
	}
	if len(cleanupErrors) == 0 {
		adapter.closed = true
	}
	return errors.Join(cleanupErrors...)
}

func productionBlockingFinding(code, relativePath, detail string) scan.Finding {
	if code == "" || len(code) > 64 {
		code = "SCAN_ERROR"
	}
	return scan.Finding{Code: code, Severity: scan.SeverityBlocking, RelativePath: relativePath, Detail: detail}
}

func productionContentClass(mime string) scan.ContentClass {
	switch mime {
	case "application/pdf":
		return scan.ContentPDF
	case "application/msword", "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation",
		"application/vnd.oasis.opendocument.text", "application/vnd.oasis.opendocument.spreadsheet", "application/vnd.oasis.opendocument.presentation":
		return scan.ContentOffice
	case "image/png", "image/jpeg":
		return scan.ContentImage
	case "text/plain":
		return scan.ContentText
	case "application/zip", "application/x-tar", "application/gzip", "application/x-7z-compressed", "application/x-rar-compressed":
		return scan.ContentArchive
	case "application/x-executable", "application/x-pie-executable", "application/x-sharedlib", "application/x-dosexec",
		"application/x-shellscript", "application/javascript", "text/javascript", "application/x-iso9660-image",
		"application/x-qemu-disk", "application/vnd.debian.binary-package", "application/x-rpm":
		return scan.ContentActive
	}
	if strings.HasPrefix(mime, "audio/") || strings.HasPrefix(mime, "video/") {
		return scan.ContentMedia
	}
	return scan.ContentUnsupported
}

func newScannerOutputID() (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		clear(value)
		return "", scannerAdapterUnavailable("output identity")
	}
	result := "scan-out-" + hex.EncodeToString(value)
	clear(value)
	return result, nil
}

func sanitizedLogicalName(entry scan.InventoryEntry, detectedMIME string) string {
	extension := ".bin"
	switch detectedMIME {
	case "application/pdf":
		extension = ".pdf"
	case "image/png":
		extension = ".png"
	case "audio/mp4":
		extension = ".m4a"
	case "video/mp4":
		extension = ".mp4"
	case "text/plain":
		extension = ".txt"
	}
	return "sanitized/" + entry.SHA256[:32] + extension
}
