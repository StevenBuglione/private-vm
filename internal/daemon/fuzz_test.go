package daemon

import (
	"testing"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"google.golang.org/protobuf/proto"
)

const (
	maximumDaemonFuzzInput = 64 << 10
	fuzzSessionID          = "pvm-00000000000000000000000000000000"
)

var fuzzResourceDefaults = &privatevmv1.ResourceRequest{
	Vcpus:       4,
	MemoryBytes: 8 << 30,
	RootBytes:   32 << 30,
}

// FuzzDaemonRPCInputs exercises only bounded, mutation-free request decoding,
// validation, and process-evidence parsing. Stateful handlers are covered by
// the Unix socket integration suite and are deliberately not invoked here.
func FuzzDaemonRPCInputs(f *testing.F) {
	contextWithoutSession := fuzzRequestContext("")
	contextWithSession := fuzzRequestContext(fuzzSessionID)
	seeds := []struct {
		kind    uint8
		message proto.Message
	}{
		{0, contextWithoutSession},
		{1, contextWithSession},
		{2, &privatevmv1.DoctorRequest{Context: contextWithoutSession, Strict: true}},
		{3, &privatevmv1.PlanSessionRequest{Context: contextWithoutSession, Role: privatevmv1.GuestRole_GUEST_ROLE_WORKSTATION, Resources: &privatevmv1.ResourceRequest{Vcpus: 4, MemoryBytes: 8 << 30, RootBytes: 32 << 30}}},
		{4, &privatevmv1.CreateSessionRequest{Context: contextWithoutSession, Role: privatevmv1.GuestRole_GUEST_ROLE_DOWNLOADER, Resources: &privatevmv1.ResourceRequest{Vcpus: 2, MemoryBytes: 4 << 30, RootBytes: 16 << 30, ScratchBytes: 64 << 30}}},
		{5, &privatevmv1.GetSessionRequest{Context: contextWithSession}},
		{6, &privatevmv1.ListSessionsRequest{Context: contextWithoutSession}},
		{7, &privatevmv1.StartRoleRequest{Context: contextWithSession}},
		{8, &privatevmv1.StopRoleRequest{Context: contextWithSession, RequireClean: true}},
		{9, &privatevmv1.AbortSessionRequest{Context: contextWithSession, ReasonCode: "FUZZ_FIXTURE_ABORT"}},
		{10, &privatevmv1.CleanupSessionRequest{Context: contextWithSession}},
		{11, &privatevmv1.ExportWorkspaceRequest{Context: contextWithSession, OutputId: "public-fuzz-output"}},
		{12, &privatevmv1.ClaimUSBRequest{Context: contextWithSession, EnrollmentId: "public-fuzz-enrollment"}},
		{13, &privatevmv1.ReleaseUSBRequest{Context: contextWithSession, ClaimId: "public-fuzz-claim"}},
		{14, &privatevmv1.TransferFrame{Frame: &privatevmv1.TransferFrame_Begin{Begin: &privatevmv1.TransferBegin{Context: contextWithSession, TransferId: "public-fuzz-transfer"}}}},
		{15, &privatevmv1.ResourceRequest{Vcpus: 64, MemoryBytes: 256 << 30, RootBytes: 2 << 40, ScratchBytes: 16 << 40}},
	}
	for _, seed := range seeds {
		addDaemonProtoSeed(f, seed.kind, seed.message)
	}
	f.Add(uint8(0), []byte{})
	f.Add(uint8(14), []byte{0xff, 0xff, 0xff})
	f.Add(uint8(16), []byte("123 (public fuzz peer) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242\n"))
	f.Add(uint8(17), []byte("pos:\t0\nflags:\t02000002\nPid:\t123\n"))
	f.Add(uint8(18), []byte("Name:\tpublic-fuzz-peer\nPid:\t123\nUid:\t1000\t1001\t1002\t1003\nGroups:\t7 8 4242\n"))

	f.Fuzz(func(t *testing.T, kind uint8, data []byte) {
		if len(data) > maximumDaemonFuzzInput {
			return
		}
		observe := func(err error) {
			if err != nil && len(err.Error()) > 4<<10 {
				t.Fatalf("validation returned an oversized error: %d bytes", len(err.Error()))
			}
		}
		unmarshal := func(message proto.Message) bool {
			return proto.Unmarshal(data, message) == nil
		}

		switch kind % 19 {
		case 0:
			request := &privatevmv1.RequestContext{}
			if unmarshal(request) {
				observe(validateRequestContext(request, false))
			}
		case 1:
			request := &privatevmv1.RequestContext{}
			if unmarshal(request) {
				observe(validateRequestContext(request, true))
			}
		case 2:
			request := &privatevmv1.DoctorRequest{}
			if unmarshal(request) {
				observe(validateRequestContext(request.GetContext(), false))
			}
		case 3:
			request := &privatevmv1.PlanSessionRequest{}
			if unmarshal(request) {
				observe(validateRequestContext(request.GetContext(), false))
				_, err := validateResources(request.GetResources(), fuzzResourceDefaults)
				observe(err)
				_, err = roleFromProto(request.GetRole())
				observe(err)
			}
		case 4:
			request := &privatevmv1.CreateSessionRequest{}
			if unmarshal(request) {
				observe(validateRequestContext(request.GetContext(), false))
				_, err := validateResources(request.GetResources(), fuzzResourceDefaults)
				observe(err)
				_, err = roleFromProto(request.GetRole())
				observe(err)
			}
		case 5:
			request := &privatevmv1.GetSessionRequest{}
			if unmarshal(request) {
				observe(validateRequestContext(request.GetContext(), true))
			}
		case 6:
			request := &privatevmv1.ListSessionsRequest{}
			if unmarshal(request) {
				observe(validateRequestContext(request.GetContext(), false))
			}
		case 7:
			request := &privatevmv1.StartRoleRequest{}
			if unmarshal(request) {
				observe(validateRequestContext(request.GetContext(), true))
			}
		case 8:
			request := &privatevmv1.StopRoleRequest{}
			if unmarshal(request) {
				observe(validateRequestContext(request.GetContext(), true))
			}
		case 9:
			request := &privatevmv1.AbortSessionRequest{}
			if unmarshal(request) {
				observe(validateRequestContext(request.GetContext(), true))
			}
		case 10:
			request := &privatevmv1.CleanupSessionRequest{}
			if unmarshal(request) {
				observe(validateRequestContext(request.GetContext(), true))
			}
		case 11:
			request := &privatevmv1.ExportWorkspaceRequest{}
			if unmarshal(request) {
				observe(validateRequestContext(request.GetContext(), true))
			}
		case 12:
			request := &privatevmv1.ClaimUSBRequest{}
			if unmarshal(request) {
				observe(validateRequestContext(request.GetContext(), true))
			}
		case 13:
			request := &privatevmv1.ReleaseUSBRequest{}
			if unmarshal(request) {
				observe(validateRequestContext(request.GetContext(), true))
			}
		case 14:
			frame := &privatevmv1.TransferFrame{}
			if unmarshal(frame) {
				observe(validateRequestContext(frame.GetBegin().GetContext(), true))
			}
		case 15:
			request := &privatevmv1.ResourceRequest{}
			if unmarshal(request) {
				_, err := validateResources(request, fuzzResourceDefaults)
				observe(err)
			}
		case 16:
			_, _, err := parseProcStat(data)
			observe(err)
		case 17:
			_, err := parsePidfdInfo(data)
			observe(err)
		case 18:
			_, _, _, err := parseProcStatus(data)
			observe(err)
		}
	})
}

func fuzzRequestContext(sessionID string) *privatevmv1.RequestContext {
	return &privatevmv1.RequestContext{
		ApiVersion: &privatevmv1.ApiVersion{Major: protocolMajor, Minor: protocolMinor},
		RequestId:  "request-fuzz-0001",
		SessionId:  sessionID,
	}
}

func addDaemonProtoSeed(f *testing.F, kind uint8, message proto.Message) {
	f.Helper()
	data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(kind, data)
}
