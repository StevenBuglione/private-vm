package exitcode

const (
	OK            = 0
	Usage         = 2
	Preflight     = 10
	ImageTrust    = 11
	Authorization = 12
	Runtime       = 20
	PolicyReject  = 30
	Transfer      = 31
	Cleanup       = 40
	Internal      = 70
)
