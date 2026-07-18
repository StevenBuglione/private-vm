package guest

import (
	"net"
	"testing"

	"github.com/mdlayher/vsock"
)

func TestTransportCredentialsRejectNonVSOCK(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	credentials := VSOCKTransportCredentials()
	if _, _, err := credentials.ClientHandshake(t.Context(), "", left); err == nil {
		t.Fatal("client credentials accepted a non-VSOCK connection")
	}
	if _, _, err := credentials.ServerHandshake(right); err == nil {
		t.Fatal("server credentials accepted a non-VSOCK connection")
	}
}

func TestTransportCredentialsAcceptVSOCKAddresses(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	connection := &addressedConn{
		connection: left,
		local:      &vsock.Addr{ContextID: vsock.Host, Port: DefaultPort},
		remote:     &vsock.Addr{ContextID: 3, Port: DefaultPort},
	}
	credentials := VSOCKTransportCredentials()
	secured, auth, err := credentials.ClientHandshake(t.Context(), "", connection)
	if err != nil {
		t.Fatal(err)
	}
	defer secured.Close()
	if auth.AuthType() != "private-vm-vsock" {
		t.Fatalf("AuthType = %q", auth.AuthType())
	}
}
