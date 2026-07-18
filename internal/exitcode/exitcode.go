package exitcode

const (
	OK             = 0
	Usage          = 2
	Preflight      = 10
	Configuration  = 11
	ImageTrust     = 12
	Network        = 13
	Storage        = 14
	Runtime        = 15
	GuestProtocol  = 16
	Torrent        = 17
	ScanRejected   = 18
	USBExport      = 19
	Transfer       = 20
	Cancelled      = 21
	DirtyWorkspace = 22
	Authorization  = 23
	Cleanup        = 24
	Internal       = 70
)
