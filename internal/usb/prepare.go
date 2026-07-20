package usb

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/StevenBuglione/private-vm/internal/secret"
)

const (
	PrepareSchemaVersion = 1
	prepareChallengeSize = 16
	maximumPrepareAge    = 5 * time.Minute
)

type PreparePlan struct {
	SchemaVersion int       `json:"schema_version"`
	EnrollmentID  string    `json:"enrollment_id"`
	Fingerprint   string    `json:"identity_fingerprint"`
	CapacityBytes uint64    `json:"capacity_bytes"`
	Filesystem    string    `json:"filesystem"`
	Challenge     string    `json:"challenge"`
	CreatedAt     time.Time `json:"created_at"`
	FirstPrompt   string    `json:"first_confirmation"`
	SecondPrompt  string    `json:"second_confirmation"`
}

type Confirmation struct {
	First  string
	Second string
}

type PrepareState string

const (
	PreparePlanned           PrepareState = "PLANNED"
	PrepareConfirmed         PrepareState = "CONFIRMED"
	PrepareCommitStarted     PrepareState = "COMMIT_STARTED"
	PrepareDestinationReady  PrepareState = "DESTINATION_PREPARED"
	PrepareCanceledPrecommit PrepareState = "CANCELED_PRECOMMIT"
	PrepareIncomplete        PrepareState = "INCOMPLETE"
)

type PrepareEvent struct {
	Sequence uint64
	State    PrepareState
	Code     string
	Message  string
}

type PrepareReceipt struct {
	SchemaVersion int          `json:"schema_version"`
	EnrollmentID  string       `json:"enrollment_id"`
	Filesystem    string       `json:"filesystem"`
	CapacityBytes uint64       `json:"capacity_bytes"`
	Fingerprint   string       `json:"identity_fingerprint"`
	State         PrepareState `json:"state"`
}

type PrepareBackend interface {
	Prepare(context.Context, Claim, string, *secret.Bytes, func(PrepareEvent) error) (PrepareReceipt, error)
}

type PrepareAuthorizer interface {
	AuthorizePrepare(context.Context) error
}

type PrepareCoordinator struct {
	Claims     *ClaimManager
	Backend    PrepareBackend
	Authorizer PrepareAuthorizer
	Now        func() time.Time
}

func NewPreparePlan(enrollment Enrollment, device Device, now time.Time) (PreparePlan, error) {
	if err := enrollment.Validate(); err != nil {
		return PreparePlan{}, err
	}
	observed := device.Identity
	observed.PortBound = enrollment.Identity.PortBound
	if !enrollment.Identity.Matches(observed) || device.Mounted || device.ReadOnly || device.HostFilesystem {
		return PreparePlan{}, newError(CodeIdentityMismatch, "The current USB observation cannot be prepared.", "Inspect and re-enroll the exact dedicated device before retrying.", nil)
	}
	challengeBytes := make([]byte, prepareChallengeSize)
	if _, err := rand.Read(challengeBytes); err != nil {
		return PreparePlan{}, errors.New("generate USB preparation challenge")
	}
	fingerprint, err := enrollment.Identity.Fingerprint()
	if err != nil {
		return PreparePlan{}, err
	}
	challenge := hex.EncodeToString(challengeBytes)
	first := "ERASE " + enrollment.EnrollmentID
	second := "ERASE " + enrollment.EnrollmentID + " " + fingerprint[:16] + " " + challenge
	return PreparePlan{
		SchemaVersion: PrepareSchemaVersion, EnrollmentID: enrollment.EnrollmentID,
		Fingerprint: fingerprint, CapacityBytes: enrollment.Identity.Capacity,
		Filesystem: enrollment.Filesystem, Challenge: challenge, CreatedAt: now.UTC(),
		FirstPrompt: first, SecondPrompt: second,
	}, nil
}

func (p PreparePlan) Validate(enrollment Enrollment, confirmation Confirmation, now time.Time) error {
	if p.SchemaVersion != PrepareSchemaVersion || p.Filesystem != DefaultFilesystem ||
		p.EnrollmentID != enrollment.EnrollmentID || p.CapacityBytes != enrollment.Identity.Capacity ||
		len(p.Challenge) != prepareChallengeSize*2 || p.CreatedAt.IsZero() || now.Before(p.CreatedAt) || now.Sub(p.CreatedAt) > maximumPrepareAge {
		return newError(CodeConfirmation, "The destructive USB preparation plan is missing, stale or changed.", "Inspect the device again and repeat both exact confirmation steps.", nil)
	}
	fingerprint, err := enrollment.Identity.Fingerprint()
	if err != nil || p.Fingerprint != fingerprint || p.FirstPrompt != "ERASE "+enrollment.EnrollmentID ||
		p.SecondPrompt != "ERASE "+enrollment.EnrollmentID+" "+fingerprint[:16]+" "+p.Challenge {
		return newError(CodeConfirmation, "The destructive USB preparation identity changed.", "Inspect the device again and repeat both exact confirmation steps.", err)
	}
	if !constantTimeStringEqual(confirmation.First, p.FirstPrompt) ||
		!constantTimeStringEqual(confirmation.Second, p.SecondPrompt) {
		return newError(CodeConfirmation, "Both exact destructive USB confirmations are required.", "Enter the two displayed confirmation phrases exactly; do not reuse an earlier challenge.", nil)
	}
	return nil
}

func (c PrepareCoordinator) Prepare(
	ctx context.Context,
	claimID string,
	sessionID string,
	ownerUID uint32,
	enrollment Enrollment,
	plan PreparePlan,
	confirmation Confirmation,
	passphrase *secret.Bytes,
	events func(PrepareEvent) error,
) (PrepareReceipt, error) {
	if c.Claims == nil || c.Backend == nil || c.Authorizer == nil {
		return PrepareReceipt{}, errors.New("USB preparation coordinator is incomplete")
	}
	now := time.Now
	if c.Now != nil {
		now = c.Now
	}
	if err := plan.Validate(enrollment, confirmation, now()); err != nil {
		return PrepareReceipt{}, err
	}
	if passphrase == nil {
		return PrepareReceipt{}, newError(CodeConfirmation, "A volatile USB encryption passphrase is required.", "Enter the LUKS2 passphrase through the protected input prompt.", nil)
	}
	if events == nil {
		return PrepareReceipt{}, errors.New("USB preparation event sink is required")
	}
	sequence := uint64(0)
	emit := func(state PrepareState, code, message string) error {
		sequence++
		return events(PrepareEvent{Sequence: sequence, State: state, Code: code, Message: message})
	}
	if err := emit(PrepareConfirmed, "USB_PREPARE_CONFIRMED", "Both destructive USB confirmation steps were accepted."); err != nil {
		return PrepareReceipt{}, err
	}
	if err := ctx.Err(); err != nil {
		_ = emit(PrepareCanceledPrecommit, "USB_PREPARE_CANCELED_PRECOMMIT", "USB preparation was canceled before the destructive commit.")
		return PrepareReceipt{}, err
	}
	claim, err := c.Claims.Revalidate(ctx, claimID, sessionID, ownerUID, enrollment)
	if err != nil {
		return PrepareReceipt{}, err
	}
	// Authorization deliberately occurs after the final identity/mount
	// revalidation and immediately before the destructive backend begins.
	if err := c.Authorizer.AuthorizePrepare(ctx); err != nil {
		return PrepareReceipt{}, newError(CodeConfirmation, "Destructive USB preparation was not authorized.", "Approve the displayed org.private-vm.usb.prepare action and retry.", err)
	}
	if err := ctx.Err(); err != nil {
		_ = emit(PrepareCanceledPrecommit, "USB_PREPARE_CANCELED_PRECOMMIT", "USB preparation was canceled before the destructive commit.")
		return PrepareReceipt{}, err
	}
	if err := emit(PrepareCommitStarted, "USB_PREPARE_COMMIT_STARTED", "Exporter USB preparation entered its destructive phase."); err != nil {
		return PrepareReceipt{}, err
	}
	receipt, err := c.Backend.Prepare(ctx, claim, DefaultFilesystem, passphrase, func(event PrepareEvent) error {
		if event.Sequence != 0 || event.State == "" || strings.TrimSpace(event.Code) == "" || strings.TrimSpace(event.Message) == "" {
			return errors.New("USB preparation backend emitted an invalid event")
		}
		return emit(event.State, event.Code, event.Message)
	})
	if err != nil {
		_ = emit(PrepareIncomplete, "USB_PREPARE_INCOMPLETE", "USB preparation did not complete; do not trust the destination until exporter verification succeeds.")
		return PrepareReceipt{}, newError(CodeWriteFailed, "Exporter USB preparation failed.", "Leave the device attached, run cleanup, then inspect it again before retrying.", err)
	}
	if receipt.SchemaVersion != PrepareSchemaVersion || receipt.EnrollmentID != enrollment.EnrollmentID ||
		receipt.Filesystem != DefaultFilesystem || receipt.CapacityBytes != enrollment.Identity.Capacity ||
		receipt.Fingerprint != plan.Fingerprint || receipt.State != PrepareDestinationReady {
		_ = emit(PrepareIncomplete, "USB_PREPARE_INCOMPLETE", "Exporter USB preparation returned incomplete identity evidence.")
		return PrepareReceipt{}, newError(CodeIdentityMismatch, "Exporter USB post-format identity verification failed.", "Do not trust the destination; finalize cleanup and inspect the enrolled device again.", nil)
	}
	if err := emit(PrepareDestinationReady, "USB_DESTINATION_PREPARED", "The exporter verified the prepared LUKS2 and ext4 destination."); err != nil {
		return PrepareReceipt{}, err
	}
	return receipt, nil
}

func constantTimeStringEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func (p PreparePlan) String() string {
	return fmt.Sprintf("prepare %s (%d bytes, %s)", p.EnrollmentID, p.CapacityBytes, p.Filesystem)
}
