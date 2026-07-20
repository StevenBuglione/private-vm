package recovery

import (
	"context"
	"errors"
)

const (
	StatusComplete   = "complete"
	StatusIncomplete = "incomplete"
)

// ArtifactCounts is intentionally closed instead of a free-form map so report
// consumers cannot receive an unreviewed resource class.
type ArtifactCounts struct {
	QEMUProcess int `json:"qemu_process"`
	Cgroup      int `json:"cgroup"`
	QMPSocket   int `json:"qmp_socket"`
	SPICESocket int `json:"spice_socket"`
	VSOCKCID    int `json:"vsock_cid"`
	TAP         int `json:"tap"`
	Veth        int `json:"veth"`
	NetNS       int `json:"network_namespace"`
	NFTables    int `json:"nftables"`
	USBClaim    int `json:"usb_claim"`
	Mount       int `json:"outer_mount"`
	Mapper      int `json:"device_mapper"`
	Loop        int `json:"loop_device"`
	Ciphertext  int `json:"ciphertext"`
	RuntimePath int `json:"runtime_path"`
}

func (c *ArtifactCounts) add(kind Kind) {
	switch kind {
	case KindQEMUProcess:
		c.QEMUProcess++
	case KindCgroup:
		c.Cgroup++
	case KindQMPSocket:
		c.QMPSocket++
	case KindSPICESocket:
		c.SPICESocket++
	case KindVSOCKCID:
		c.VSOCKCID++
	case KindTAP:
		c.TAP++
	case KindVeth:
		c.Veth++
	case KindNetNS:
		c.NetNS++
	case KindNFTables:
		c.NFTables++
	case KindUSBClaim:
		c.USBClaim++
	case KindMount:
		c.Mount++
	case KindMapper:
		c.Mapper++
	case KindLoop:
		c.Loop++
	case KindCiphertext:
		c.Ciphertext++
	case KindRuntimePath:
		c.RuntimePath++
	}
}

type Failure struct {
	Code        string `json:"code"`
	Kind        Kind   `json:"kind,omitempty"`
	SafeMessage string `json:"safe_message"`
	Remediation string `json:"remediation"`
	Retryable   bool   `json:"retryable"`
}

type Report struct {
	SchemaVersion           int            `json:"schema_version"`
	Code                    string         `json:"code"`
	Status                  string         `json:"status"`
	SessionsDiscovered      int            `json:"sessions_discovered"`
	SessionsRecovered       int            `json:"sessions_recovered"`
	KeyLossVerifiedSessions int            `json:"key_loss_verified_sessions"`
	BaseImagesVerified      bool           `json:"base_images_verified"`
	ArtifactsDiscovered     ArtifactCounts `json:"artifacts_discovered"`
	ArtifactsRecovered      ArtifactCounts `json:"artifacts_recovered"`
	Failures                []Failure      `json:"failures"`
}

func newReport() Report {
	return Report{
		SchemaVersion: 1,
		Code:          "RECOVERY_COMPLETED",
		Status:        StatusComplete,
		Failures:      make([]Failure, 0),
	}
}

func (r *Report) addFailure(failure Failure) {
	r.Failures = append(r.Failures, failure)
	r.Code = "ORPHAN_CLEANUP_FAILED"
	r.Status = StatusIncomplete
}

func (r Report) finish() Report {
	if len(r.Failures) != 0 || r.SessionsRecovered != r.SessionsDiscovered || !r.BaseImagesVerified {
		r.Code = "ORPHAN_CLEANUP_FAILED"
		r.Status = StatusIncomplete
	}
	if r.Failures == nil {
		r.Failures = make([]Failure, 0)
	}
	return r
}

func newFailure(code, message string) Failure {
	return Failure{
		Code:        code,
		SafeMessage: message,
		Remediation: "Preserve volatile recovery evidence, correct the host condition, and retry startup cleanup.",
		Retryable:   true,
	}
}

func withKind(failure Failure, kind Kind) Failure {
	if _, ok := knownKind[kind]; ok {
		failure.Kind = kind
	}
	return failure
}

func classifyFailure(err error, fallbackCode, fallbackMessage string) Failure {
	switch {
	case errors.Is(err, context.Canceled):
		return newFailure("RECOVERY_CANCELED", "Startup recovery was canceled before absence could be proven.")
	case errors.Is(err, context.DeadlineExceeded):
		return newFailure("RECOVERY_TIMEOUT", "A bounded startup recovery operation timed out before absence could be proven.")
	case errors.Is(err, ErrActiveOwner):
		failure := newFailure("RECOVERY_REGISTRY_CONFLICT", "A candidate session still has a current registry owner.")
		failure.Retryable = false
		return failure
	default:
		return newFailure(fallbackCode, fallbackMessage)
	}
}
