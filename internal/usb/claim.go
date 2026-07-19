package usb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

type DeviceClaim interface {
	Release(context.Context) error
	AuditAbsent(context.Context) error
}

type DeviceClaimer interface {
	Acquire(context.Context, Device) (DeviceClaim, error)
}

type Claim struct {
	ID           string
	EnrollmentID string
	SessionID    string
	OwnerUID     uint32
	Device       Device

	handle DeviceClaim
}

type ClaimManager struct {
	mu         sync.Mutex
	enumerator Enumerator
	claimer    DeviceClaimer
	claims     map[string]*Claim
	devices    map[string]string
}

func NewClaimManager(enumerator Enumerator, claimer DeviceClaimer) (*ClaimManager, error) {
	if enumerator.Source == nil || claimer == nil {
		return nil, errors.New("USB claim manager requires discovery and claim adapters")
	}
	return &ClaimManager{
		enumerator: enumerator, claimer: claimer,
		claims: make(map[string]*Claim), devices: make(map[string]string),
	}, nil
}

func (m *ClaimManager) Claim(ctx context.Context, sessionID string, ownerUID uint32, enrollment Enrollment) (Claim, error) {
	if sessionID == "" {
		return Claim{}, errors.New("USB claim requires a session")
	}
	device, err := m.enumerator.ResolveEnrollment(ctx, enrollment)
	if err != nil {
		return Claim{}, err
	}
	if err := ctx.Err(); err != nil {
		return Claim{}, err
	}
	claimID, err := randomClaimID()
	if err != nil {
		return Claim{}, errors.New("generate USB claim identifier")
	}
	m.mu.Lock()
	if _, exists := m.devices[device.Identity.USBGuardHash]; exists {
		m.mu.Unlock()
		return Claim{}, newError(CodeClaimConflict, "The enrolled USB is already claimed.", "Finish or clean up the existing exporter session before retrying.", nil)
	}
	// Reserve before invoking the adapter so concurrent callers cannot both
	// acquire the same physical identity. The empty value denotes acquisition.
	m.devices[device.Identity.USBGuardHash] = ""
	m.mu.Unlock()

	handle, err := m.claimer.Acquire(ctx, device)
	if err != nil {
		if handle != nil {
			cleanupErr := releaseAndAuditWithTimeout(ctx, handle)
			if cleanupErr != nil {
				m.retainFailedClaim(claimID, sessionID, ownerUID, enrollment.EnrollmentID, device, handle)
				return Claim{}, newError(CodeCleanupIncomplete, "A failed USB claim left incomplete cleanup.", "Run session cleanup before reconnecting the device.", cleanupErr)
			}
		}
		m.mu.Lock()
		delete(m.devices, device.Identity.USBGuardHash)
		m.mu.Unlock()
		return Claim{}, newError(CodeIdentityMismatch, "The USB claim could not be established.", "Reconnect the enrolled device and retry.", err)
	}
	if handle == nil {
		m.mu.Lock()
		delete(m.devices, device.Identity.USBGuardHash)
		m.mu.Unlock()
		return Claim{}, newError(CodeIdentityMismatch, "The USB claim adapter returned no ownership handle.", "Reconnect the enrolled device and retry.", nil)
	}
	if err := ctx.Err(); err != nil {
		cleanupErr := releaseAndAuditWithTimeout(ctx, handle)
		m.mu.Lock()
		if cleanupErr == nil {
			delete(m.devices, device.Identity.USBGuardHash)
		}
		m.mu.Unlock()
		if cleanupErr != nil {
			m.retainFailedClaim(claimID, sessionID, ownerUID, enrollment.EnrollmentID, device, handle)
			return Claim{}, newError(CodeCleanupIncomplete, "USB claim cancellation left incomplete cleanup.", "Run session cleanup before reconnecting the device.", cleanupErr)
		}
		return Claim{}, err
	}
	claim := &Claim{
		ID: claimID, EnrollmentID: enrollment.EnrollmentID, SessionID: sessionID,
		OwnerUID: ownerUID, Device: device, handle: handle,
	}
	m.mu.Lock()
	m.claims[claimID] = claim
	m.devices[device.Identity.USBGuardHash] = claimID
	m.mu.Unlock()
	return publicClaim(claim), nil
}

func (m *ClaimManager) Revalidate(ctx context.Context, claimID, sessionID string, ownerUID uint32, enrollment Enrollment) (Claim, error) {
	claim, err := m.getOwned(claimID, sessionID, ownerUID)
	if err != nil {
		return Claim{}, err
	}
	current, err := m.enumerator.ResolveEnrollment(ctx, enrollment)
	if err != nil {
		return Claim{}, err
	}
	if !sameKernelObservation(claim.Device, current) {
		return Claim{}, newError(CodeIdentityMismatch, "The claimed USB kernel identity changed.", "Abort the exporter, release the claim and inspect the device again.", nil)
	}
	return publicClaim(claim), nil
}

func (m *ClaimManager) Release(ctx context.Context, claimID, sessionID string, ownerUID uint32) error {
	claim, err := m.getOwned(claimID, sessionID, ownerUID)
	if err != nil {
		// Release is idempotent for a claim that is already absent.
		var usbError *Error
		if errors.As(err, &usbError) && usbError.Code == CodeNotEnrolled {
			return nil
		}
		return err
	}
	if err := releaseAndAudit(ctx, claim.handle); err != nil {
		return newError(CodeCleanupIncomplete, "The USB claim could not be fully released.", "Retry session cleanup before disconnecting the device.", err)
	}
	m.mu.Lock()
	delete(m.claims, claim.ID)
	delete(m.devices, claim.Device.Identity.USBGuardHash)
	m.mu.Unlock()
	return nil
}

func (m *ClaimManager) getOwned(claimID, sessionID string, ownerUID uint32) (*Claim, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	claim := m.claims[claimID]
	if claim == nil {
		return nil, newError(CodeNotEnrolled, "The USB claim does not exist.", "Inspect the exporter session and claim the enrolled device again.", nil)
	}
	if claim.SessionID != sessionID || claim.OwnerUID != ownerUID {
		return nil, newError(CodeIdentityMismatch, "The USB claim is owned by a different session.", "Use the claim returned for this exporter session.", nil)
	}
	copy := *claim
	return &copy, nil
}

func releaseAndAudit(ctx context.Context, claim DeviceClaim) error {
	if err := claim.Release(ctx); err != nil {
		return err
	}
	return claim.AuditAbsent(ctx)
}

func releaseAndAuditWithTimeout(parent context.Context, claim DeviceClaim) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 15*time.Second)
	defer cancel()
	return releaseAndAudit(ctx, claim)
}

func (m *ClaimManager) retainFailedClaim(claimID, sessionID string, ownerUID uint32, enrollmentID string, device Device, handle DeviceClaim) {
	claim := &Claim{
		ID: claimID, EnrollmentID: enrollmentID, SessionID: sessionID,
		OwnerUID: ownerUID, Device: device, handle: handle,
	}
	m.mu.Lock()
	m.claims[claimID] = claim
	m.devices[device.Identity.USBGuardHash] = claimID
	m.mu.Unlock()
}

func randomClaimID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "usbclaim-" + hex.EncodeToString(value), nil
}

func sameKernelObservation(a, b Device) bool {
	return a.DeviceID == b.DeviceID && a.SysfsPath == b.SysfsPath && a.BlockPath == b.BlockPath &&
		a.Bus == b.Bus && a.Address == b.Address && a.Identity.Matches(b.Identity) &&
		a.Mounted == b.Mounted && a.ReadOnly == b.ReadOnly && a.HostFilesystem == b.HostFilesystem
}

func publicClaim(claim *Claim) Claim {
	copy := *claim
	copy.handle = nil
	return copy
}
