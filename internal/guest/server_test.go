package guest

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestAuthenticatedHelloAndRoleRestrictedRegistration(t *testing.T) {
	token := mustToken(t, 0x11)
	server, connection := startTestServer(t, testConfig(t, session.RoleWorkstation, token), token)
	services := server.GetServiceInfo()
	if _, ok := services["privatevm.v1.GuestCommonService"]; !ok {
		t.Fatal("common service was not registered")
	}
	if _, ok := services["privatevm.v1.WorkstationGuestService"]; !ok {
		t.Fatal("workstation service was not registered")
	}
	for _, forbidden := range []string{"privatevm.v1.DownloaderGuestService", "privatevm.v1.ScannerGuestService", "privatevm.v1.ExporterGuestService"} {
		if _, ok := services[forbidden]; ok {
			t.Fatalf("wrong-role service registered: %s", forbidden)
		}
	}

	response, err := privatevmv1.NewGuestCommonServiceClient(connection).Hello(t.Context(), helloRequest(session.RoleWorkstation, APIMajor, APIMinor))
	if err != nil {
		t.Fatal(err)
	}
	wantCapabilities, _ := Capabilities(session.RoleWorkstation)
	if response.GetRole() != privatevmv1.GuestRole_GUEST_ROLE_WORKSTATION || !slices.Equal(response.GetCapabilities(), wantCapabilities) {
		t.Fatalf("unexpected identity: role=%s capabilities=%v", response.GetRole(), response.GetCapabilities())
	}
	response.BootNonce[0] ^= 0xff
	second, err := privatevmv1.NewGuestCommonServiceClient(connection).Hello(t.Context(), helloRequest(session.RoleWorkstation, APIMajor, APIMinor))
	if err != nil {
		t.Fatal(err)
	}
	if second.BootNonce[0] != 1 {
		t.Fatal("Hello exposed the server's boot nonce backing array")
	}

	_, err = privatevmv1.NewDownloaderGuestServiceClient(connection).VerifyVPN(t.Context(), &privatevmv1.VerifyVPNRequest{})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("wrong-role method code = %s, want Unimplemented", status.Code(err))
	}
}

func TestEachRoleRegistersOnlyItsService(t *testing.T) {
	roles := []struct {
		role    session.Role
		service string
	}{
		{session.RoleWorkstation, "privatevm.v1.WorkstationGuestService"},
		{session.RoleDownloader, "privatevm.v1.DownloaderGuestService"},
		{session.RoleScanner, "privatevm.v1.ScannerGuestService"},
		{session.RoleExporter, "privatevm.v1.ExporterGuestService"},
	}
	for index, test := range roles {
		t.Run(string(test.role), func(t *testing.T) {
			token := mustToken(t, byte(index+1))
			server, err := newServer(testConfig(t, test.role, token), false)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Stop()
			services := server.GetServiceInfo()
			if len(services) != 2 {
				t.Fatalf("registered services = %v", services)
			}
			if _, ok := services[test.service]; !ok {
				t.Fatalf("missing role service %s", test.service)
			}
			capabilities, err := Capabilities(test.role)
			if err != nil || len(capabilities) == 0 {
				t.Fatalf("Capabilities() = %v, %v", capabilities, err)
			}
		})
	}
}

func TestWrongOrMissingTokenRejectedBeforeHandlers(t *testing.T) {
	expected := mustToken(t, 0x21)
	config := testConfig(t, session.RoleWorkstation, expected)
	_, correctConnection := startTestServer(t, config, expected)
	_, err := privatevmv1.NewGuestCommonServiceClient(correctConnection).Hello(t.Context(), helloRequest(session.RoleWorkstation, APIMajor, APIMinor))
	if err != nil {
		t.Fatalf("correct token rejected: %v", err)
	}
	duplicateContext, err := expected.outgoingContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, err = privatevmv1.NewGuestCommonServiceClient(correctConnection).Hello(duplicateContext, helloRequest(session.RoleWorkstation, APIMajor, APIMinor))
	assertAuthenticationFailure(t, err)

	wrong := mustToken(t, 0x22)
	_, wrongConnection := startTestServer(t, config, wrong)
	_, err = privatevmv1.NewGuestCommonServiceClient(wrongConnection).Hello(t.Context(), helloRequest(session.RoleWorkstation, APIMajor, APIMinor))
	assertAuthenticationFailure(t, err)

	_, missingConnection := startTestServer(t, config, nil)
	_, err = privatevmv1.NewGuestCommonServiceClient(missingConnection).Hello(t.Context(), helloRequest(session.RoleWorkstation, APIMajor, APIMinor))
	assertAuthenticationFailure(t, err)
}

func TestStreamingAuthenticationRunsBeforeHandler(t *testing.T) {
	expected := mustToken(t, 0x31)
	config := testConfig(t, session.RoleWorkstation, expected)
	_, connection := startTestServer(t, config, nil)
	stream, err := privatevmv1.NewGuestCommonServiceClient(connection).StreamEvents(t.Context(), &privatevmv1.GuestStatusRequest{})
	if err == nil {
		_, err = stream.Recv()
	}
	assertAuthenticationFailure(t, err)
}

func TestHelloRejectsProtocolAndRoleMismatch(t *testing.T) {
	token := mustToken(t, 0x41)
	_, connection := startTestServer(t, testConfig(t, session.RoleScanner, token), token)
	client := privatevmv1.NewGuestCommonServiceClient(connection)
	for _, test := range []struct {
		name    string
		request *privatevmv1.GuestHelloRequest
		code    string
	}{
		{"major", helloRequest(session.RoleScanner, APIMajor+1, 0), "GUEST_PROTOCOL_VERSION_MISMATCH"},
		{"minor", helloRequest(session.RoleScanner, APIMajor, APIMinor+1), "GUEST_PROTOCOL_VERSION_MISMATCH"},
		{"role", helloRequest(session.RoleExporter, APIMajor, APIMinor), "GUEST_ROLE_MISMATCH"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := client.Hello(t.Context(), test.request)
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), test.code) {
				t.Fatalf("Hello error = %v", err)
			}
		})
	}
}

func TestRoleContextRejectedBeforeMatchingRoleHandler(t *testing.T) {
	token := mustToken(t, 0x45)
	_, connection := startTestServer(t, testConfig(t, session.RoleWorkstation, token), token)
	client := privatevmv1.NewWorkstationGuestServiceClient(connection)
	wrongContext := helloRequest(session.RoleDownloader, APIMajor, APIMinor).GetContext()
	_, err := client.GetWorkspaceState(t.Context(), &privatevmv1.WorkspaceStateRequest{Context: wrongContext})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "GUEST_ROLE_MISMATCH") {
		t.Fatalf("wrong role context error = %v", err)
	}
	_, err = client.GetWorkspaceState(t.Context(), &privatevmv1.WorkspaceStateRequest{})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "GUEST_CONTEXT_REQUIRED") {
		t.Fatalf("missing context error = %v", err)
	}
}

func TestHandshakeVerifiesManifestIdentityAndRequiresDeadline(t *testing.T) {
	token := mustToken(t, 0x51)
	config := testConfig(t, session.RoleDownloader, token)
	_, connection := startTestServer(t, config, token)
	client := privatevmv1.NewGuestCommonServiceClient(connection)
	capabilities, _ := Capabilities(session.RoleDownloader)
	expectation := HandshakeExpectation{
		SessionID: testSessionID, RequestID: "request-123", Role: session.RoleDownloader,
		ImageDigest: config.Identity.ImageDigest, SourceCommit: config.Identity.SourceCommit,
		Capabilities: capabilities, MinimumProtocolMinor: APIMinor,
	}
	if _, err := Handshake(t.Context(), client, expectation); err == nil {
		t.Fatal("Handshake without a deadline succeeded")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := Handshake(ctx, client, expectation); err != nil {
		t.Fatal(err)
	}

	mismatches := []struct {
		name   string
		mutate func(*HandshakeExpectation)
		code   string
	}{
		{"digest", func(value *HandshakeExpectation) { value.ImageDigest = "sha256:wrong" }, "GUEST_IMAGE_IDENTITY_MISMATCH"},
		{"commit", func(value *HandshakeExpectation) { value.SourceCommit = "wrong" }, "GUEST_IMAGE_IDENTITY_MISMATCH"},
		{"capabilities", func(value *HandshakeExpectation) { value.Capabilities = []string{"other"} }, "GUEST_CAPABILITY_MISMATCH"},
	}
	for _, test := range mismatches {
		t.Run(test.name, func(t *testing.T) {
			changed := expectation
			test.mutate(&changed)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			_, err := Handshake(ctx, client, changed)
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), test.code) {
				t.Fatalf("Handshake error = %v", err)
			}
		})
	}
}

func TestTransferStreamRequiresAuthenticatedBeginContext(t *testing.T) {
	token := mustToken(t, 0x55)
	config := testConfig(t, session.RoleWorkstation, token)
	config.Workstation = receivingWorkstationServer{}
	_, connection := startTestServer(t, config, token)
	client := privatevmv1.NewWorkstationGuestServiceClient(connection)

	stream, err := client.ImportFile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Chunk{Chunk: &privatevmv1.TransferChunk{}}}); err != nil {
		t.Fatal(err)
	}
	_, err = stream.CloseAndRecv()
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "TRANSFER_BEGIN_REQUIRED") {
		t.Fatalf("first chunk error = %v", err)
	}

	stream, err = client.ImportFile(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Begin{Begin: &privatevmv1.TransferBegin{
		Context: &privatevmv1.RequestContext{
			ApiVersion: &privatevmv1.ApiVersion{Major: APIMajor, Minor: APIMinor},
			RequestId:  "request-123", SessionId: testSessionID,
		},
	}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.CloseAndRecv(); err != nil {
		t.Fatalf("valid begin rejected: %v", err)
	}
}

func TestServerRejectsCrossRoleHandler(t *testing.T) {
	token := mustToken(t, 0x61)
	config := testConfig(t, session.RoleDownloader, token)
	config.Workstation = workstationServer{}
	if _, err := newServer(config, false); err == nil {
		t.Fatal("server accepted a cross-role handler")
	}
}

func startTestServer(t *testing.T, config ServerConfig, clientToken *Token) (*grpc.Server, *grpc.ClientConn) {
	t.Helper()
	server, err := newServer(config, false)
	if err != nil {
		t.Fatal(err)
	}
	listener := bufconn.Listen(2 << 20)
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()

	options := []grpc.DialOption{
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	if clientToken != nil {
		options = append(options,
			grpc.WithChainUnaryInterceptor(clientToken.UnaryClientInterceptor()),
			grpc.WithChainStreamInterceptor(clientToken.StreamClientInterceptor()),
		)
	}
	connection, err := grpc.NewClient("passthrough:///guest-test", options...)
	if err != nil {
		server.Stop()
		listener.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		connection.Close()
		server.Stop()
		listener.Close()
		<-serveDone
	})
	return server, connection
}

func testConfig(t *testing.T, role session.Role, token *Token) ServerConfig {
	t.Helper()
	identity := Identity{
		Role: role, ImageDigest: "sha256:image", SourceCommit: "source-commit",
		BootNonce: append([]byte{1}, make([]byte, BootNonceSize-1)...),
		OSRelease: "26.05", GuestdVersion: "test",
	}
	return ServerConfig{Identity: identity, Token: token}
}

func helloRequest(role session.Role, major, minor uint32) *privatevmv1.GuestHelloRequest {
	protoRole, _ := ProtoRole(role)
	return &privatevmv1.GuestHelloRequest{Context: &privatevmv1.GuestContext{
		Context: &privatevmv1.RequestContext{
			ApiVersion: &privatevmv1.ApiVersion{Major: major, Minor: minor},
			RequestId:  "request-123", SessionId: testSessionID,
		},
		ExpectedRole: protoRole,
	}}
}

type receivingWorkstationServer struct {
	privatevmv1.UnimplementedWorkstationGuestServiceServer
}

func (receivingWorkstationServer) ImportFile(stream grpc.ClientStreamingServer[privatevmv1.TransferFrame, privatevmv1.TransferReceipt]) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	return stream.SendAndClose(&privatevmv1.TransferReceipt{})
}

const testSessionID = "pvm-11111111111111111111111111111111"

func mustToken(t *testing.T, value byte) *Token {
	t.Helper()
	token, err := TokenFromBytes(repeatedToken(value))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(token.Destroy)
	return token
}

func assertAuthenticationFailure(t *testing.T, err error) {
	t.Helper()
	if status.Code(err) != codes.Unauthenticated || !strings.Contains(err.Error(), "GUEST_AUTHENTICATION_FAILED") {
		t.Fatalf("authentication error = %v", err)
	}
	if strings.Contains(err.Error(), "ISEh") {
		t.Fatal("authentication error exposed token material")
	}
	grpcStatus := status.Convert(err)
	if len(grpcStatus.Details()) != 1 {
		t.Fatalf("authentication error details = %v", grpcStatus.Details())
	}
	detail, ok := grpcStatus.Details()[0].(*privatevmv1.ErrorDetail)
	if !ok || detail.GetCode() != "GUEST_AUTHENTICATION_FAILED" || detail.GetSafeMessage() == "" || detail.GetRemediation() == "" {
		t.Fatalf("authentication detail = %#v", grpcStatus.Details()[0])
	}
}
