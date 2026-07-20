package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/session"
	"google.golang.org/grpc/codes"
)

const workspaceTestOutputID = "output-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type workspaceServiceRoles struct {
	imported  bool
	exported  bool
	verified  bool
	data      []byte
	exportErr error
}

func (*workspaceServiceRoles) PlanAllocation(session.Snapshot, session.LaunchPlan) session.AllocateFunc {
	return nil
}
func (*workspaceServiceRoles) Preflight(context.Context, session.Snapshot) error       { return nil }
func (*workspaceServiceRoles) VerifyImages(context.Context, session.Snapshot) error    { return nil }
func (*workspaceServiceRoles) StorageAllocation(session.Snapshot) session.AllocateFunc { return nil }
func (*workspaceServiceRoles) RuntimeAllocation(session.Snapshot) session.AllocateFunc { return nil }
func (*workspaceServiceRoles) WorkspaceState(context.Context, session.Snapshot) (string, error) {
	return "UNEXPORTED", nil
}
func (*workspaceServiceRoles) WorkspaceInventory(context.Context, session.Snapshot) (*privatevmv1.WorkspaceState, error) {
	return &privatevmv1.WorkspaceState{State: "UNEXPORTED", Entries: []*privatevmv1.WorkspaceEntry{{OutputId: workspaceTestOutputID, SizeBytes: 4}}}, nil
}
func (roles *workspaceServiceRoles) ImportWorkspace(_ context.Context, _ session.Snapshot, begin *privatevmv1.TransferBegin, receive func() (*privatevmv1.TransferFrame, error)) (*privatevmv1.TransferReceipt, error) {
	frame, err := receive()
	if err != nil || frame.GetChunk() == nil {
		return nil, io.ErrUnexpectedEOF
	}
	roles.data = append([]byte(nil), frame.GetChunk().GetData()...)
	end, err := receive()
	if err != nil || end.GetEnd() == nil {
		return nil, io.ErrUnexpectedEOF
	}
	roles.imported = true
	return &privatevmv1.TransferReceipt{TransferId: begin.GetTransferId(), Descriptor_: begin.GetDescriptor_(), ReceiverDigest: begin.GetDescriptor_().GetDigest()}, nil
}
func (roles *workspaceServiceRoles) ExportWorkspace(_ context.Context, _ session.Snapshot, outputID string, send func(*privatevmv1.TransferFrame) error) (*privatevmv1.TransferReceipt, error) {
	if roles.exportErr != nil {
		return nil, roles.exportErr
	}
	digest := sha256.Sum256(roles.data)
	descriptor := &privatevmv1.FileDescriptor{LogicalName: "redacted.txt", DetectedMime: "text/plain", SizeBytes: uint64(len(roles.data)), Digest: &privatevmv1.Hash{Algorithm: "sha256", Value: digest[:]}}
	for _, frame := range []*privatevmv1.TransferFrame{
		{Frame: &privatevmv1.TransferFrame_Begin{Begin: &privatevmv1.TransferBegin{TransferId: outputID, Descriptor_: descriptor}}},
		{Frame: &privatevmv1.TransferFrame_Chunk{Chunk: &privatevmv1.TransferChunk{Data: append([]byte(nil), roles.data...)}}},
		{Frame: &privatevmv1.TransferFrame_End{End: &privatevmv1.TransferEnd{TotalSize: uint64(len(roles.data)), Digest: descriptor.GetDigest()}}},
	} {
		if err := send(frame); err != nil {
			return nil, err
		}
	}
	roles.exported = true
	return &privatevmv1.TransferReceipt{TransferId: outputID, Descriptor_: descriptor, ReceiverDigest: descriptor.GetDigest()}, nil
}

type workspaceDestinationProviderFixture struct {
	plan         WorkspaceDestinationPlan
	prepareErr   error
	prepareCalls int
	transaction  *workspaceDestinationTransactionFixture
}

func (provider *workspaceDestinationProviderFixture) Prepare(_ context.Context, plan WorkspaceDestinationPlan) (WorkspaceDestinationTransaction, error) {
	provider.prepareCalls++
	provider.plan = plan
	if provider.prepareErr != nil {
		return nil, provider.prepareErr
	}
	return provider.transaction, nil
}

type workspaceDestinationTransactionFixture struct {
	receiveErr       error
	abortErr         error
	mismatch         bool
	skipSource       bool
	cancel           context.CancelFunc
	aborted          bool
	abortContextLive bool
	received         []byte
}

func (transaction *workspaceDestinationTransactionFixture) Receive(ctx context.Context, source WorkspaceDestinationSource) (WorkspaceDestinationReceipt, error) {
	if transaction.cancel != nil {
		transaction.cancel()
	}
	if transaction.skipSource {
		return WorkspaceDestinationReceipt{}, transaction.receiveErr
	}
	var begin *privatevmv1.TransferBegin
	var end *privatevmv1.TransferEnd
	sequence := uint64(0)
	relay, err := source(ctx, func(frame *privatevmv1.TransferFrame) error {
		if frame.GetBegin() != nil {
			if begin != nil {
				return errors.New("duplicate begin")
			}
			begin = frame.GetBegin()
			return nil
		}
		if chunk := frame.GetChunk(); chunk != nil {
			if begin == nil || end != nil || chunk.GetSequence() != sequence {
				return errors.New("invalid chunk")
			}
			sequence++
			transaction.received = append(transaction.received, chunk.GetData()...)
			return nil
		}
		if frame.GetEnd() == nil || begin == nil || end != nil {
			return errors.New("invalid end")
		}
		end = frame.GetEnd()
		return nil
	})
	if err != nil {
		return WorkspaceDestinationReceipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return WorkspaceDestinationReceipt{}, err
	}
	if transaction.receiveErr != nil {
		return WorkspaceDestinationReceipt{}, transaction.receiveErr
	}
	digest := sha256.Sum256(transaction.received)
	if begin == nil || end == nil || relay == nil || end.GetTotalSize() != uint64(len(transaction.received)) || !bytes.Equal(end.GetDigest().GetValue(), digest[:]) {
		return WorkspaceDestinationReceipt{}, errors.New("incomplete source framing")
	}
	if transaction.mismatch {
		digest[0] ^= 0xff
	}
	return WorkspaceDestinationReceipt{ReceiverDigest: &privatevmv1.Hash{Algorithm: "sha256", Value: digest[:]}, Persisted: true, Reread: true, CleanupComplete: true}, nil
}

func (transaction *workspaceDestinationTransactionFixture) Abort(ctx context.Context) error {
	transaction.aborted = true
	transaction.abortContextLive = ctx.Err() == nil
	return transaction.abortErr
}
func (roles *workspaceServiceRoles) VerifyWorkspaceExport(_ context.Context, _ session.Snapshot, _ string, _, _ *privatevmv1.Hash) (*privatevmv1.WorkspaceState, error) {
	roles.verified = true
	return &privatevmv1.WorkspaceState{State: "READY", Entries: []*privatevmv1.WorkspaceEntry{{OutputId: workspaceTestOutputID, SizeBytes: 4, Exported: true}}}, nil
}

func TestWorkspaceServiceRelaysAuthenticatedImportExportAndVerification(t *testing.T) {
	manager, identity, snapshot := activeWorkspaceSession(t)
	roles := &workspaceServiceRoles{}
	service := &Service{Sessions: manager, Roles: roles}
	ctx := context.WithValue(t.Context(), identityContextKey{}, identity)
	data := []byte("safe")
	digest := sha256.Sum256(data)
	begin := &privatevmv1.TransferBegin{Context: validRequestContext(snapshot.ID), TransferId: "transfer-12345678", Descriptor_: &privatevmv1.FileDescriptor{
		LogicalName: "trusted.txt", SizeBytes: uint64(len(data)), Digest: &privatevmv1.Hash{Algorithm: "sha256", Value: digest[:]},
	}}
	importStream := &importFixtureStream{ctx: ctx, frames: []*privatevmv1.TransferFrame{
		{Frame: &privatevmv1.TransferFrame_Begin{Begin: begin}},
		{Frame: &privatevmv1.TransferFrame_Chunk{Chunk: &privatevmv1.TransferChunk{Data: append([]byte(nil), data...)}}},
		{Frame: &privatevmv1.TransferFrame_End{End: &privatevmv1.TransferEnd{TotalSize: uint64(len(data)), Digest: begin.GetDescriptor_().GetDigest()}}},
	}}
	if err := service.ImportWorkspaceFile(importStream); err != nil || !roles.imported {
		t.Fatalf("import = %v, seen=%v", err, roles.imported)
	}
	state, err := service.GetWorkspaceState(ctx, &privatevmv1.HostWorkspaceStateRequest{Context: validRequestContext(snapshot.ID)})
	if err != nil || state.GetState() != "UNEXPORTED" {
		t.Fatalf("state = %#v, %v", state, err)
	}
	exportStream := &exportFixtureStream{ctx: ctx}
	if err := service.ExportWorkspaceFile(&privatevmv1.ExportWorkspaceRequest{Context: validRequestContext(snapshot.ID), OutputId: workspaceTestOutputID}, exportStream); err != nil || !roles.exported {
		t.Fatalf("export = %v, seen=%v", err, roles.exported)
	}
	verified, err := service.VerifyWorkspaceExport(ctx, &privatevmv1.VerifyWorkspaceExportRequest{
		Context: validRequestContext(snapshot.ID), OutputId: workspaceTestOutputID,
		DaemonDigest: &privatevmv1.Hash{Algorithm: "sha256", Value: digest[:]}, ReceiverDigest: &privatevmv1.Hash{Algorithm: "sha256", Value: digest[:]},
	})
	if err != nil || verified.GetState() != "READY" || !roles.verified {
		t.Fatalf("verify = %#v, %v, seen=%v", verified, err, roles.verified)
	}
}

func TestWorkspaceDestinationTransactionPersistsRereadsAndMarksReady(t *testing.T) {
	manager, identity, snapshot := activeWorkspaceSession(t)
	roles := &workspaceServiceRoles{data: []byte("safe")}
	transaction := &workspaceDestinationTransactionFixture{}
	provider := &workspaceDestinationProviderFixture{transaction: transaction}
	service := &Service{Sessions: manager, Roles: roles, WorkspaceDestinations: provider}
	ctx := context.WithValue(t.Context(), identityContextKey{}, identity)
	state, err := service.ExportWorkspaceToDestination(ctx, workspaceDestinationRequest(snapshot.ID, privatevmv1.WorkspaceExportDestination_WORKSPACE_EXPORT_DESTINATION_USB))
	if err != nil {
		t.Fatal(err)
	}
	if state.GetState() != "READY" || !roles.exported || !roles.verified || transaction.aborted || string(transaction.received) != "safe" {
		t.Fatalf("state=%#v roles=%#v transaction=%#v", state, roles, transaction)
	}
	if provider.plan.OwnerUID != identity.UID || provider.plan.SourceSession != snapshot.ID || provider.plan.OutputID != workspaceTestOutputID || provider.plan.Destination != privatevmv1.WorkspaceExportDestination_WORKSPACE_EXPORT_DESTINATION_USB {
		t.Fatalf("semantic plan = %#v", provider.plan)
	}
}

func TestWorkspaceDestinationPrepareFailureDoesNotOpenSource(t *testing.T) {
	manager, identity, snapshot := activeWorkspaceSession(t)
	roles := &workspaceServiceRoles{data: []byte("safe")}
	provider := &workspaceDestinationProviderFixture{prepareErr: errors.New("destination absent")}
	service := &Service{Sessions: manager, Roles: roles, WorkspaceDestinations: provider}
	ctx := context.WithValue(t.Context(), identityContextKey{}, identity)
	_, err := service.ExportWorkspaceToDestination(ctx, workspaceDestinationRequest(snapshot.ID, privatevmv1.WorkspaceExportDestination_WORKSPACE_EXPORT_DESTINATION_USB))
	assertRPCError(t, err, codes.FailedPrecondition, "WORKSPACE_DESTINATION_FAILED")
	if roles.exported || roles.verified {
		t.Fatal("workstation source opened before destination preparation")
	}
}

func TestWorkspaceDestinationFailureMismatchAndCleanup(t *testing.T) {
	for _, test := range []struct {
		name        string
		transaction *workspaceDestinationTransactionFixture
		grpcCode    codes.Code
		code        string
	}{
		{name: "receiver-failure", transaction: &workspaceDestinationTransactionFixture{receiveErr: errors.New("fsync failed")}, grpcCode: codes.FailedPrecondition, code: "WORKSPACE_DESTINATION_FAILED"},
		{name: "receiver-reread-mismatch", transaction: &workspaceDestinationTransactionFixture{mismatch: true}, grpcCode: codes.FailedPrecondition, code: "WORKSPACE_DESTINATION_FAILED"},
		{name: "cleanup-failure", transaction: &workspaceDestinationTransactionFixture{receiveErr: errors.New("write failed"), abortErr: errors.New("detach failed")}, grpcCode: codes.Internal, code: "WORKSPACE_DESTINATION_CLEANUP_INCOMPLETE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager, identity, snapshot := activeWorkspaceSession(t)
			roles := &workspaceServiceRoles{data: []byte("safe")}
			service := &Service{Sessions: manager, Roles: roles, WorkspaceDestinations: &workspaceDestinationProviderFixture{transaction: test.transaction}}
			ctx := context.WithValue(t.Context(), identityContextKey{}, identity)
			_, err := service.ExportWorkspaceToDestination(ctx, workspaceDestinationRequest(snapshot.ID, privatevmv1.WorkspaceExportDestination_WORKSPACE_EXPORT_DESTINATION_USB))
			assertRPCError(t, err, test.grpcCode, test.code)
			if !test.transaction.aborted || !test.transaction.abortContextLive || roles.verified {
				t.Fatalf("transaction=%#v verified=%v", test.transaction, roles.verified)
			}
		})
	}
}

func TestWorkspaceDestinationCancellationAndTimeoutAbortIndependently(t *testing.T) {
	for _, test := range []struct {
		name     string
		deadline bool
		code     string
	}{
		{name: "cancel", code: "REQUEST_CANCELED"},
		{name: "timeout", deadline: true, code: "REQUEST_TIMEOUT"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manager, identity, snapshot := activeWorkspaceSession(t)
			roles := &workspaceServiceRoles{data: []byte("safe")}
			base := context.WithValue(t.Context(), identityContextKey{}, identity)
			var ctx context.Context
			var cancel context.CancelFunc
			if test.deadline {
				ctx, cancel = context.WithDeadline(base, time.Now().Add(-time.Second))
			} else {
				ctx, cancel = context.WithCancel(base)
			}
			defer cancel()
			transaction := &workspaceDestinationTransactionFixture{cancel: cancel}
			service := &Service{Sessions: manager, Roles: roles, WorkspaceDestinations: &workspaceDestinationProviderFixture{transaction: transaction}}
			_, err := service.ExportWorkspaceToDestination(ctx, workspaceDestinationRequest(snapshot.ID, privatevmv1.WorkspaceExportDestination_WORKSPACE_EXPORT_DESTINATION_USB))
			assertRPCError(t, err, map[bool]codes.Code{false: codes.Canceled, true: codes.DeadlineExceeded}[test.deadline], test.code)
			if !transaction.aborted || !transaction.abortContextLive || roles.verified {
				t.Fatalf("transaction=%#v verified=%v", transaction, roles.verified)
			}
		})
	}
}

func TestWorkspaceEncryptedBundleFailsClosedBeforeProviderOrSource(t *testing.T) {
	manager, identity, snapshot := activeWorkspaceSession(t)
	roles := &workspaceServiceRoles{data: []byte("safe")}
	provider := &workspaceDestinationProviderFixture{transaction: &workspaceDestinationTransactionFixture{}}
	service := &Service{Sessions: manager, Roles: roles, WorkspaceDestinations: provider}
	ctx := context.WithValue(t.Context(), identityContextKey{}, identity)
	_, err := service.ExportWorkspaceToDestination(ctx, workspaceDestinationRequest(snapshot.ID, privatevmv1.WorkspaceExportDestination_WORKSPACE_EXPORT_DESTINATION_ENCRYPTED_BUNDLE))
	assertRPCError(t, err, codes.Unimplemented, "NOT_IMPLEMENTED")
	if provider.prepareCalls != 0 || roles.exported {
		t.Fatal("unsupported bundle destination opened a transaction")
	}
}

func workspaceDestinationRequest(sessionID string, destination privatevmv1.WorkspaceExportDestination) *privatevmv1.ExportWorkspaceToDestinationRequest {
	return &privatevmv1.ExportWorkspaceToDestinationRequest{Context: validRequestContext(sessionID), OutputId: workspaceTestOutputID, Destination: destination}
}

func activeWorkspaceSession(t *testing.T) (*session.Manager, PeerIdentity, session.Snapshot) {
	t.Helper()
	runtimeRoot := t.TempDir()
	if err := os.Chmod(runtimeRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	store, err := session.NewStore(runtimeRoot)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := session.NewManager(store, session.DefaultMaxSessionsPerOwner)
	if err != nil {
		t.Fatal(err)
	}
	identity := currentProcessIdentity(t)
	snapshot, err := manager.Create(identity.UID, session.RoleWorkstation)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []session.Phase{session.PhasePreflighted, session.PhaseImagesVerified, session.PhaseStorageReady, session.PhaseActive} {
		snapshot, err = manager.Transition(t.Context(), snapshot.ID, identity.UID, phase)
		if err != nil {
			t.Fatal(err)
		}
	}
	return manager, identity, snapshot
}
