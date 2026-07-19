// private-vm-guest-smoke is a test-only client used by NixOS role-image gates.
// It is not included in any production package or image.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/guest"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/mdlayher/vsock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	expectedRole         = ""
	expectedSourceCommit = ""
	expectedVersion      = ""
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "private-vm guest smoke failed:", err)
		os.Exit(1)
	}
	fmt.Println("private-vm authenticated guest VSOCK ready")
}

func run() error {
	role := session.Role(expectedRole)
	if err := session.ValidateRole(role); err != nil {
		return errors.New("test client has no valid compile-time role")
	}
	protoRole, err := guest.ProtoRole(role)
	if err != nil {
		return errors.New("test client role cannot be encoded")
	}
	expectedCapabilities, err := guest.Capabilities(role)
	if err != nil {
		return errors.New("test client capability map is invalid")
	}
	localCID, err := vsock.ContextID()
	if err != nil {
		return errors.New("read local VSOCK context ID")
	}

	wrongBytes := bytes.Repeat([]byte{0xa5}, guest.TokenSize)
	wrongToken, err := guest.TokenFromBytes(wrongBytes)
	clear(wrongBytes)
	if err != nil {
		return errors.New("create negative-test capability")
	}
	_, wrongErr := hello(wrongToken, protoRole, localCID)
	wrongToken.Destroy()
	if status.Code(wrongErr) != codes.Unauthenticated {
		return errors.New("guestd accepted an incorrect boot capability")
	}

	token, err := guest.ReadToken(guest.FWCfgTokenPath)
	if err != nil {
		return errors.New("read synthetic fw_cfg capability")
	}
	defer token.Destroy()
	response, err := hello(token, protoRole, localCID)
	if err != nil {
		return fmt.Errorf("authenticated Hello failed: %w", err)
	}
	if response.GetApiVersion().GetMajor() != guest.APIMajor || response.GetApiVersion().GetMinor() != guest.APIMinor ||
		response.GetRole() != protoRole || !slices.Equal(response.GetCapabilities(), expectedCapabilities) ||
		len(response.GetBootNonce()) != guest.TokenSize || response.GetSourceCommit() != expectedSourceCommit ||
		response.GetOsRelease() == "" || response.GetGuestdVersion() != expectedVersion {
		return errors.New("authenticated Hello returned incomplete or mismatched identity")
	}
	return nil
}

func hello(token *guest.Token, role privatevmv1.GuestRole, localCID uint32) (*privatevmv1.GuestHelloResponse, error) {
	connection, err := guest.Dial(guest.ClientConfig{
		CID:            localCID,
		Port:           guest.DefaultPort,
		Token:          token,
		MaxMessageSize: guest.DefaultMaxMessageSize,
	})
	if err != nil {
		return nil, errors.New("create local VSOCK client")
	}
	defer connection.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return privatevmv1.NewGuestCommonServiceClient(connection).Hello(ctx, &privatevmv1.GuestHelloRequest{
		Context: &privatevmv1.GuestContext{
			Context: &privatevmv1.RequestContext{
				ApiVersion: &privatevmv1.ApiVersion{Major: guest.APIMajor, Minor: guest.APIMinor},
				RequestId:  "nix-vsock-smoke-0001",
				SessionId:  "pvm-00000000000000000000000000000000",
			},
			ExpectedRole: role,
		},
	})
}
