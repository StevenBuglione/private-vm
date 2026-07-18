package guest

import (
	"context"
	"crypto/subtle"
	"errors"
	"slices"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/session"
	"google.golang.org/grpc/codes"
)

type HandshakeExpectation struct {
	SessionID            string
	RequestID            string
	Role                 session.Role
	ImageDigest          string
	SourceCommit         string
	Capabilities         []string
	MinimumProtocolMinor uint32
}

// Handshake performs the first authenticated request and verifies the guest's
// self-reported identity against the already verified image manifest. A caller
// must supply a deadline; a mismatch is fatal to the guest boot.
func Handshake(ctx context.Context, client privatevmv1.GuestCommonServiceClient, expected HandshakeExpectation) (*privatevmv1.GuestHelloResponse, error) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		return nil, errors.New("guest handshake requires a deadline")
	}
	if client == nil {
		return nil, errors.New("guest handshake client is required")
	}
	role, err := ProtoRole(expected.Role)
	if err != nil {
		return nil, err
	}
	response, err := client.Hello(ctx, &privatevmv1.GuestHelloRequest{Context: &privatevmv1.GuestContext{
		Context: &privatevmv1.RequestContext{
			ApiVersion: &privatevmv1.ApiVersion{Major: APIMajor, Minor: expected.MinimumProtocolMinor},
			RequestId:  expected.RequestID,
			SessionId:  expected.SessionID,
		},
		ExpectedRole: role,
	}})
	if err != nil {
		return nil, err
	}
	if err := VerifyHello(response, expected); err != nil {
		return nil, err
	}
	return response, nil
}

func VerifyHello(response *privatevmv1.GuestHelloResponse, expected HandshakeExpectation) error {
	role, err := ProtoRole(expected.Role)
	if err != nil {
		return err
	}
	if response == nil || response.GetApiVersion() == nil || response.GetApiVersion().GetMajor() != APIMajor || response.GetApiVersion().GetMinor() < expected.MinimumProtocolMinor {
		return identityMismatch("GUEST_PROTOCOL_VERSION_MISMATCH", "The guest protocol does not meet the host requirement.", "Upgrade the host and guest images together.")
	}
	if response.GetRole() != role {
		return identityMismatch("GUEST_ROLE_MISMATCH", "The guest role does not match the planned session.", "Destroy the guest and verify the selected image manifest before retrying.")
	}
	if !constantTimeStringEqual(response.GetImageDigest(), expected.ImageDigest) || !constantTimeStringEqual(response.GetSourceCommit(), expected.SourceCommit) {
		return identityMismatch("GUEST_IMAGE_IDENTITY_MISMATCH", "The guest build identity does not match the verified image manifest.", "Destroy the guest, remove the cached image, and pull a verified replacement.")
	}
	if !sameCapabilities(response.GetCapabilities(), expected.Capabilities) {
		return identityMismatch("GUEST_CAPABILITY_MISMATCH", "The guest capability set does not match the verified image manifest.", "Destroy the guest and install a verified role image.")
	}
	if len(response.GetBootNonce()) != BootNonceSize || allZero(response.GetBootNonce()) || response.GetOsRelease() == "" || response.GetGuestdVersion() == "" {
		return identityMismatch("GUEST_IDENTITY_INCOMPLETE", "The guest returned an incomplete boot identity.", "Destroy the guest and install a verified role image.")
	}
	return nil
}

func identityMismatch(code, message, remediation string) error {
	return guestRPCError(codes.FailedPrecondition, code, message, remediation, false)
}

func constantTimeStringEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func sameCapabilities(actual, expected []string) bool {
	actualCopy := slices.Clone(actual)
	expectedCopy := slices.Clone(expected)
	slices.Sort(actualCopy)
	slices.Sort(expectedCopy)
	if len(actualCopy) != len(expectedCopy) {
		return false
	}
	for index := range actualCopy {
		if index > 0 && actualCopy[index] == actualCopy[index-1] {
			return false
		}
		if actualCopy[index] != expectedCopy[index] {
			return false
		}
	}
	return true
}

func allZero(value []byte) bool {
	var combined byte
	for _, current := range value {
		combined |= current
	}
	return combined == 0
}
