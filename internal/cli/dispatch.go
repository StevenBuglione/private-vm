package cli

import (
	"context"

	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
)

type CommandID string

const (
	CommandWorkstationStart CommandID = "workstation.start"
	CommandTorrentRun       CommandID = "torrent.run"
	CommandTorrentAdd       CommandID = "torrent.add"
	CommandTorrentStart     CommandID = "torrent.start"
	CommandTorrentMetadata  CommandID = "torrent.metadata"
	CommandTorrentSelect    CommandID = "torrent.select"
	CommandTorrentPlan      CommandID = "torrent.plan"
	CommandTorrentDownload  CommandID = "torrent.download"
	CommandTorrentPause     CommandID = "torrent.pause"
	CommandTorrentResume    CommandID = "torrent.resume"
	CommandTorrentStatus    CommandID = "torrent.status"
	CommandTorrentComplete  CommandID = "torrent.complete"
	CommandScannerStart     CommandID = "scanner.start"
	CommandVPNImport        CommandID = "vpn.import"
	CommandVPNInspect       CommandID = "vpn.inspect"
	CommandVPNTest          CommandID = "vpn.test"
	CommandVPNRotate        CommandID = "vpn.rotate"
	CommandVPNRemove        CommandID = "vpn.remove"
)

type Intent interface {
	privateVMIntent()
}

type EmptyIntent struct{}

func (EmptyIntent) privateVMIntent() {}

type WorkstationIntent struct {
	Bundle string
	Audio  bool
	Memory string
	CPUs   int
}

func (WorkstationIntent) privateVMIntent() {}

type PlanWorkstationIntent struct {
	Bundle string
}

func (PlanWorkstationIntent) privateVMIntent() {}

type PlanTorrentIntent struct {
	Policy      string
	Destination string
}

func (PlanTorrentIntent) privateVMIntent() {}

type SessionIntent struct {
	SessionID string
}

func (SessionIntent) privateVMIntent() {}

type DesktopStopIntent struct {
	SessionID    string
	RequireClean bool
	Discard      bool
}

func (DesktopStopIntent) privateVMIntent() {}

type BundleIntent struct {
	Name string
}

func (BundleIntent) privateVMIntent() {}

type WorkspacePathIntent struct {
	SessionID string
	Path      string
}

func (WorkspacePathIntent) privateVMIntent() {}

type WorkspaceExportIntent struct {
	SessionID   string
	Destination string
}

func (WorkspaceExportIntent) privateVMIntent() {}

type WorkspaceVerifyIntent struct {
	Last     bool
	ExportID string
}

func (WorkspaceVerifyIntent) privateVMIntent() {}

type WorkspaceDiscardIntent struct {
	SessionID string
	All       bool
}

func (WorkspaceDiscardIntent) privateVMIntent() {}

type TorrentIntent struct {
	Policy string
}

func (TorrentIntent) privateVMIntent() {}

type TorrentInputIntent struct {
	MagnetTTY   bool
	MagnetStdin bool
	TorrentFile string
}

func (TorrentInputIntent) privateVMIntent() {}

type TorrentSelectionIntent struct {
	Files []uint32
}

func (TorrentSelectionIntent) privateVMIntent() {}

type ScannerIntent struct {
	SessionID string
}

func (ScannerIntent) privateVMIntent() {}

type ScanApprovalIntent struct {
	SessionID string
	OpenIn    string
	To        string
}

func (ScanApprovalIntent) privateVMIntent() {}

type VPNImportIntent struct {
	ProfileName string
	FromFile    string
	Stdin       bool
}

func (VPNImportIntent) privateVMIntent() {}

type VPNProfileIntent struct {
	ProfileName string
}

func (VPNProfileIntent) privateVMIntent() {}

type USBDeviceIntent struct {
	DeviceID string
}

func (USBDeviceIntent) privateVMIntent() {}

type USBPrepareIntent struct {
	Format string
}

func (USBPrepareIntent) privateVMIntent() {}

type ImageSelectionIntent struct {
	Role   string
	Bundle string
}

func (ImageSelectionIntent) privateVMIntent() {}

type ImageReferenceIntent struct {
	Reference string
}

func (ImageReferenceIntent) privateVMIntent() {}

type ImageTestIntent struct {
	Reference string
	Backend   string
}

func (ImageTestIntent) privateVMIntent() {}

type SessionReportIntent struct {
	SessionID  string
	ExportPath string
}

func (SessionReportIntent) privateVMIntent() {}

type SessionCleanupIntent struct {
	SessionID string
	All       bool
}

func (SessionCleanupIntent) privateVMIntent() {}

type PolicyNameIntent struct {
	Name string
}

func (PolicyNameIntent) privateVMIntent() {}

type PolicyFileIntent struct {
	Path string
}

func (PolicyFileIntent) privateVMIntent() {}

type SystemInstallIntent struct {
	DryRun bool
	Accept bool
}

func (SystemInstallIntent) privateVMIntent() {}

type SystemUninstallIntent struct {
	DryRun bool
}

func (SystemUninstallIntent) privateVMIntent() {}

type SystemDiagnosticsIntent struct {
	ExportPath string
}

func (SystemDiagnosticsIntent) privateVMIntent() {}

type Invoker interface {
	Invoke(context.Context, CommandID, Intent) (Result, error)
}

// Result is the audited presentation result returned by a semantic command
// implementation. Arbitrary JSON is deliberately impossible because Data is
// a sealed MachinePayload.
type Result struct {
	Code Code
	Data MachinePayload
}

type failClosedInvoker struct{}

func (failClosedInvoker) Invoke(context.Context, CommandID, Intent) (Result, error) {
	return Result{}, apperror.New(
		"NOT_IMPLEMENTED",
		exitcode.Runtime,
		"This security-sensitive workflow is not implemented.",
		"Do not use this path until its backlog acceptance tests pass.",
	)
}
