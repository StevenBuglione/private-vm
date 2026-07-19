package daemon

import (
	"context"
	"crypto/sha256"
	"io"
	"os"
	"testing"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/session"
)

const workspaceTestOutputID = "output-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type workspaceServiceRoles struct {
	imported bool
	exported bool
	verified bool
	data     []byte
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
	digest := sha256.Sum256(roles.data)
	descriptor := &privatevmv1.FileDescriptor{LogicalName: "redacted.txt", SizeBytes: uint64(len(roles.data)), Digest: &privatevmv1.Hash{Algorithm: "sha256", Value: digest[:]}}
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
