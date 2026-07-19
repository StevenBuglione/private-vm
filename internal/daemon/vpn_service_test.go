package daemon

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/secret"
	"github.com/StevenBuglione/private-vm/internal/vpn"
	"google.golang.org/grpc/codes"
)

type vpnLookupFunc func(context.Context, string, string) ([]netip.Addr, error)

func (fn vpnLookupFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return fn(ctx, network, host)
}

func TestVPNProfileRPCVolatileLifecycleAndDaemonShutdown(t *testing.T) {
	server, socket, _ := newUnstartedTestServer(t, 0)
	server.options.Service.VPNResolver = vpn.NewEndpointResolverWithLookup(vpnLookupFunc(func(_ context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip" || host != "vpn.proton.test." {
			t.Fatal("resolver request was not absolute and bounded")
		}
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}))
	done := startTestServer(t, server)
	connection, client := dialTestDaemon(t, socket)

	fixture := []byte(daemonVPNFixture())
	for _, processValue := range append(append([]string{}, os.Args...), os.Environ()...) {
		if strings.Contains(processValue, string(fixture)) || strings.Contains(processValue, daemonVPNKey(0x11)) {
			t.Fatal("synthetic VPN credential appeared in process arguments or environment")
		}
	}
	stream, err := client.ImportVPNProfile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(vpnBegin("proton-p2p")); err != nil {
		t.Fatal(err)
	}
	first := append([]byte(nil), fixture[:31]...)
	second := append([]byte(nil), fixture[31:]...)
	if err := stream.Send(vpnChunk(first)); err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(vpnChunk(second)); err != nil {
		t.Fatal(err)
	}
	clear(first)
	clear(second)
	clear(fixture)
	imported, err := stream.CloseAndRecv()
	if err != nil {
		t.Fatal(err)
	}
	if !imported.GetPresent() || imported.GetRotation() != "resolution_required" || imported.GetGeneration() == 0 {
		t.Fatalf("import status = %+v", imported)
	}

	request := &privatevmv1.VPNProfileRequest{Context: validRequestContext(""), ProfileName: "proton-p2p"}
	inspected, err := client.InspectVPNProfile(t.Context(), request)
	if err != nil || inspected.GetGeneration() != imported.GetGeneration() {
		t.Fatalf("inspect status = %+v, %v", inspected, err)
	}
	verified, err := client.TestVPNProfile(t.Context(), request)
	if err != nil || verified.GetRotation() != "current" || verified.GetCode() != "VPN_PROFILE_CURRENT" {
		t.Fatalf("test status = %+v, %v", verified, err)
	}
	removed, err := client.RemoveVPNProfile(t.Context(), request)
	if err != nil || removed.GetPresent() || removed.GetRotation() != "not_imported" {
		t.Fatalf("remove status = %+v, %v", removed, err)
	}
	_ = connection.Close()
	stopTestServer(t, server, done)

	sourceBytes := []byte(daemonVPNFixture())
	source, err := secret.New(sourceBytes)
	clear(sourceBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Destroy()
	if _, err := server.profiles.Import(uint32(os.Geteuid()), "after-stop", source); !errors.Is(err, vpn.ErrStoreClosed) {
		t.Fatalf("daemon shutdown did not close volatile store: %v", err)
	}
}

func TestVPNProfileRPCRejectsFramingAndCanceledPartialImport(t *testing.T) {
	server, socket, _ := newUnstartedTestServer(t, 0)
	done := startTestServer(t, server)
	connection, client := dialTestDaemon(t, socket)
	defer connection.Close()

	dataFirst, err := client.ImportVPNProfile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	rejected := bytes.Repeat([]byte{0x5a}, 32)
	if err := dataFirst.Send(vpnChunk(rejected)); err != nil {
		t.Fatal(err)
	}
	_, err = dataFirst.CloseAndRecv()
	assertRPCError(t, err, codes.InvalidArgument, "VPN_PROFILE_BEGIN_REQUIRED")

	oversized, err := client.ImportVPNProfile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := oversized.Send(vpnBegin("oversized")); err != nil {
		t.Fatal(err)
	}
	if err := oversized.Send(vpnChunk(bytes.Repeat([]byte{'x'}, maximumVPNProfileChunkBytes+1))); err != nil {
		t.Fatal(err)
	}
	_, err = oversized.CloseAndRecv()
	assertRPCError(t, err, codes.InvalidArgument, "VPN_PROFILE_STREAM_INVALID")

	canceledContext, cancel := context.WithCancel(t.Context())
	partial, err := client.ImportVPNProfile(canceledContext)
	if err != nil {
		t.Fatal(err)
	}
	if err := partial.Send(vpnBegin("partial")); err != nil {
		t.Fatal(err)
	}
	if err := partial.Send(vpnChunk([]byte("[Interface]\nPrivateKey = "))); err != nil {
		t.Fatal(err)
	}
	cancel()
	_, _ = partial.CloseAndRecv()
	status, err := client.InspectVPNProfile(t.Context(), &privatevmv1.VPNProfileRequest{Context: validRequestContext(""), ProfileName: "partial"})
	if err != nil || status.GetPresent() {
		t.Fatalf("canceled partial import persisted: status=%+v err=%v", status, err)
	}

	stopTestServer(t, server, done)
}

func vpnBegin(name string) *privatevmv1.VPNProfileImportFrame {
	return &privatevmv1.VPNProfileImportFrame{Frame: &privatevmv1.VPNProfileImportFrame_Begin{Begin: &privatevmv1.VPNProfileImportBegin{
		Context: validRequestContext(""), ProfileName: name,
	}}}
}

func vpnChunk(value []byte) *privatevmv1.VPNProfileImportFrame {
	return &privatevmv1.VPNProfileImportFrame{Frame: &privatevmv1.VPNProfileImportFrame_Chunk{Chunk: &privatevmv1.VPNProfileChunk{Data: value}}}
}

func daemonVPNFixture() string {
	return "[Interface]\nPrivateKey = " + daemonVPNKey(0x11) +
		"\nAddress = 10.2.0.2/32\nDNS = 10.2.0.1\n\n[Peer]\nPublicKey = " + daemonVPNKey(0x22) +
		"\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.proton.test:51820\n"
}

func daemonVPNKey(value byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{value}, 32))
}
