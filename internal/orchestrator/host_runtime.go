package orchestrator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"

	"github.com/StevenBuglione/private-vm/internal/guest"
	"github.com/StevenBuglione/private-vm/internal/guestvpn"
	"github.com/StevenBuglione/private-vm/internal/image"
	"github.com/StevenBuglione/private-vm/internal/network"
	"github.com/StevenBuglione/private-vm/internal/qemu"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/vpn"
)

type OfficialCacheSelector struct {
	Cache       *image.Cache
	QEMUVersion string
}

func (selector OfficialCacheSelector) Select(ctx context.Context, snapshot session.Snapshot, plan session.LaunchPlan) (image.RuntimeImage, error) {
	if selector.Cache == nil || snapshot.Role != plan.Role || selector.QEMUVersion == "" {
		return image.RuntimeImage{}, ErrHostImageUnavailable
	}
	bundle := plan.ImageBundle
	if snapshot.Role != session.RoleWorkstation {
		bundle = ""
	}
	policy := image.CompatibilityPolicy{
		Role: string(snapshot.Role), Bundle: bundle, HostArchitecture: runtime.GOARCH,
		GuestAPIMajor: 1, GuestAPIMinor: 0, MinimumGuestAPIMinor: 0,
		HostQEMUVersion: selector.QEMUVersion, NixOSVersion: "26.05",
		Limits: image.DefaultVerificationLimits(),
	}
	verifier, err := image.NewOfficialVerifier(policy)
	if err != nil {
		return image.RuntimeImage{}, err
	}
	return selector.Cache.SelectRuntimeImage(ctx, image.RuntimeSelector{Role: string(snapshot.Role), Bundle: bundle}, verifier)
}

type RuntimeStack struct {
	mu sync.Mutex

	RuntimeRoot  string
	QEMUBinary   string
	ProfileName  string
	Profiles     *vpn.MemoryStore
	Resolver     *vpn.EndpointResolver
	Networks     *network.Manager
	CIDs         *guest.CIDAllocator
	Launcher     QEMULauncher
	ProbeTargets guestvpn.ProbeTargets
	prepared     map[string]vpn.ResolutionPlan
}

func NewRuntimeStack(runtimeRoot, qemuBinary, profileName string, profiles *vpn.MemoryStore, resolver *vpn.EndpointResolver, networks *network.Manager, cids *guest.CIDAllocator, launcher QEMULauncher, probeTargets guestvpn.ProbeTargets) (*RuntimeStack, error) {
	if !filepath.IsAbs(runtimeRoot) || filepath.Clean(runtimeRoot) != runtimeRoot || runtimeRoot == "/" ||
		!filepath.IsAbs(qemuBinary) || filepath.Clean(qemuBinary) != qemuBinary || profileName == "" ||
		profiles == nil || resolver == nil || networks == nil || cids == nil || nilLikeHost(launcher) {
		return nil, errors.New("production runtime stack is incomplete")
	}
	validatedTargets, err := guestvpn.NewProbeTargets(probeTargets.DNSName, probeTargets.IPv4, probeTargets.IPv6)
	if err != nil {
		return nil, errors.New("production VPN probe targets are invalid")
	}
	return &RuntimeStack{
		RuntimeRoot: runtimeRoot, QEMUBinary: qemuBinary, ProfileName: profileName,
		Profiles: profiles, Resolver: resolver, Networks: networks, CIDs: cids,
		Launcher: launcher, ProbeTargets: validatedTargets, prepared: make(map[string]vpn.ResolutionPlan),
	}, nil
}

func (stack *RuntimeStack) Prepare(ctx context.Context, snapshot session.Snapshot, plan session.LaunchPlan) error {
	if stack == nil || snapshot.Role != plan.Role || (snapshot.Role != session.RoleWorkstation && snapshot.Role != session.RoleDownloader) {
		return ErrHostRoleUnavailable
	}
	resolved, status, err := stack.Profiles.Resolve(ctx, snapshot.OwnerUID, stack.ProfileName, stack.Resolver)
	if err != nil || resolved == nil || status.Rotation != vpn.RotationCurrent {
		return errors.Join(ErrNetworkedNotVerified, err)
	}
	stack.mu.Lock()
	defer stack.mu.Unlock()
	if stack.prepared[snapshot.ID] != nil {
		return ErrHostPlanUnavailable
	}
	stack.prepared[snapshot.ID] = resolved
	return nil
}

func (stack *RuntimeStack) Forget(sessionID string) {
	if stack == nil {
		return
	}
	stack.mu.Lock()
	delete(stack.prepared, sessionID)
	stack.mu.Unlock()
}

func (stack *RuntimeStack) Start(ctx context.Context, request HostRuntimeRequest) (HostRuntime, error) {
	if stack == nil || request.Snapshot.Role != request.Plan.Role || request.Storage == nil ||
		(request.Snapshot.Role != session.RoleWorkstation && request.Snapshot.Role != session.RoleDownloader) {
		return nil, ErrHostRuntimeUnavailable
	}
	stack.mu.Lock()
	resolution := stack.prepared[request.Snapshot.ID]
	stack.mu.Unlock()
	if resolution == nil {
		return nil, ErrNetworkedNotVerified
	}

	resource := &hostRuntimeResource{stack: stack, sessionID: request.Snapshot.ID}
	fail := func(cause error) (HostRuntime, error) {
		if cleanupErr := resource.Stop(context.Background(), true); cleanupErr != nil {
			return resource, errors.Join(cause, cleanupErr)
		}
		return nil, cause
	}
	cid, err := stack.CIDs.Allocate()
	if err != nil {
		return nil, err
	}
	resource.cid = cid
	resource.cidOwned = true
	token, err := guest.NewToken()
	if err != nil {
		return fail(err)
	}
	resource.capability = token
	networkHandle, err := stack.Networks.Create(ctx, request.Snapshot.ID, request.Snapshot.OwnerUID, stack.ProfileName, stack.Profiles, resolution)
	if err != nil {
		return fail(err)
	}
	resource.network = networkHandle
	directories, err := createRuntimeSocketDirectories(stack.RuntimeRoot, request.Snapshot.ID)
	if err != nil {
		return fail(err)
	}
	resource.directories = directories
	lease, err := request.Storage.ActivateImages()
	if err != nil {
		return fail(err)
	}
	resource.images = lease

	spec, err := runtimeQEMUSpec(stack.QEMUBinary, request, cid, directories)
	if err != nil {
		return fail(err)
	}
	expectation := guest.HandshakeExpectation{
		SessionID: request.Snapshot.ID, Role: request.Snapshot.Role,
		ImageDigest: request.Image.ImageDigest, SourceCommit: request.Image.SourceCommit,
		Capabilities: append([]string(nil), request.Image.Capabilities...), MinimumProtocolMinor: 0,
	}
	networked, startErr := StartNetworked(ctx, StartNetworkedRequest{
		SessionID: request.Snapshot.ID, Role: request.Snapshot.Role, Spec: spec,
		Network: NetworkAdapter{Handle: networkHandle}, Capability: token,
		Launcher: stack.Launcher, Guests: VSOCKGuestConnector{Expected: expectation, ProbeTargets: stack.ProbeTargets},
		Egress:        networkPolicyAuditor{sessionID: request.Snapshot.ID, handle: networkHandle},
		LossResponder: inertHostLossResponder{},
	})
	if networked != nil {
		resource.networked = networked
		resource.capability = nil
		resource.network = nil
	}
	if startErr != nil {
		return fail(startErr)
	}
	if networked == nil {
		return fail(ErrHostRuntimeUnavailable)
	}
	stack.Forget(request.Snapshot.ID)
	return resource, nil
}

type hostRuntimeResource struct {
	mu sync.Mutex

	stack       *RuntimeStack
	sessionID   string
	cid         uint32
	cidOwned    bool
	capability  *guest.Token
	network     *network.Handle
	networked   *NetworkedRuntime
	images      qemu.RuntimeImageLease
	directories *runtimeSocketDirectories
}

func (resource *hostRuntimeResource) Stop(ctx context.Context, discard bool) error {
	if resource == nil {
		return nil
	}
	resource.mu.Lock()
	defer resource.mu.Unlock()
	if resource.networked != nil {
		if err := resource.networked.Stop(ctx, discard); err != nil {
			return err
		}
	} else {
		if resource.capability != nil {
			resource.capability.Destroy()
			resource.capability = nil
		}
		if resource.network != nil {
			if err := resource.network.Cleanup(ctx); err != nil {
				return err
			}
			resource.network = nil
		}
	}
	if resource.images != nil {
		if err := resource.images.Destroy(); err != nil {
			return err
		}
	}
	if resource.cidOwned {
		if !resource.stack.CIDs.Release(resource.cid) {
			return ErrHostRuntimeUnavailable
		}
		resource.cidOwned = false
	}
	if resource.directories != nil {
		if err := resource.directories.Cleanup(); err != nil {
			return err
		}
	}
	return nil
}

func (resource *hostRuntimeResource) Audit(ctx context.Context) error {
	if resource == nil {
		return ErrHostRuntimeUnavailable
	}
	resource.mu.Lock()
	defer resource.mu.Unlock()
	var audits []error
	if resource.networked != nil {
		audits = append(audits, resource.networked.Audit(ctx))
	} else if resource.capability != nil || resource.network != nil {
		audits = append(audits, ErrNetworkedCleanup)
	}
	if resource.images != nil {
		audits = append(audits, resource.images.Audit())
	}
	if resource.cidOwned || resource.stack.CIDs.Reserved(resource.cid) {
		audits = append(audits, guest.ErrCIDUnavailable)
	}
	if resource.directories != nil {
		audits = append(audits, resource.directories.Audit())
	}
	return errors.Join(audits...)
}

func (resource *hostRuntimeResource) WorkspaceState(ctx context.Context) (string, error) {
	resource.mu.Lock()
	networked := resource.networked
	resource.mu.Unlock()
	if networked == nil {
		return "", ErrHostRuntimeUnavailable
	}
	return networked.WorkspaceState(ctx)
}

func (resource *hostRuntimeResource) Torrent() (TorrentRelay, error) {
	resource.mu.Lock()
	networked := resource.networked
	resource.mu.Unlock()
	if networked == nil {
		return nil, ErrHostRuntimeUnavailable
	}
	return networked.Torrent()
}

func runtimeQEMUSpec(binary string, request HostRuntimeRequest, cid uint32, directories *runtimeSocketDirectories) (qemu.Spec, error) {
	if directories == nil || request.Storage.RootPath() == "" {
		return qemu.Spec{}, ErrHostRuntimeUnavailable
	}
	specification := qemu.Spec{
		Binary: binary, SessionID: request.Snapshot.ID, Name: request.Snapshot.ID,
		Role: request.Snapshot.Role, CPUs: request.Plan.VCPUs, MemoryBytes: request.Plan.MemoryBytes,
		Root:      qemu.Disk{Path: request.Storage.RootPath(), Format: "qcow2", Serial: "root"},
		QMPSocket: directories.QMPSocket(), SPICESocket: directories.SPICESocket(),
		VSOCKCID: cid, Networked: true, NetworkFD: 4, FWCfgTokenFD: 3,
	}
	if request.Snapshot.Role == session.RoleDownloader {
		if request.Storage.QuarantinePath() == "" {
			return qemu.Spec{}, ErrHostStorageUnavailable
		}
		specification.Data = []qemu.Disk{{Path: request.Storage.QuarantinePath(), Format: "raw", Serial: "quarantine"}}
	}
	if err := specification.Validate(); err != nil {
		return qemu.Spec{}, err
	}
	return specification, nil
}

type networkPolicyAuditor struct {
	sessionID string
	handle    *network.Handle
}

func (auditor networkPolicyAuditor) Verify(_ context.Context, sessionID string) (EgressProof, error) {
	if auditor.handle == nil || sessionID != auditor.sessionID {
		return EgressProof{}, ErrNetworkedNotVerified
	}
	inspection := auditor.handle.Inspect()
	ready := inspection.SchemaVersion == 1 && inspection.Ready && inspection.TAPReady &&
		inspection.IPv4EndpointCount+inspection.IPv6EndpointCount > 0
	return EgressProof{NamespacePolicyPresent: ready, HostPolicyPresent: ready, ForbiddenEgressZero: ready}, nil
}

type runtimeSocketDirectories struct {
	qmp   ownedRuntimeDirectory
	spice ownedRuntimeDirectory
}

type ownedRuntimeDirectory struct {
	path string
	dev  uint64
	ino  uint64
	uid  uint32
	gid  uint32
}

func createRuntimeSocketDirectories(runtimeRoot, sessionID string) (*runtimeSocketDirectories, error) {
	if session.ValidateID(sessionID) != nil {
		return nil, ErrHostRuntimeUnavailable
	}
	parent := filepath.Join(runtimeRoot, sessionID)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode().Perm() != 0o700 {
		return nil, ErrHostRuntimeUnavailable
	}
	directories := &runtimeSocketDirectories{}
	for _, item := range []struct {
		name        string
		destination *ownedRuntimeDirectory
	}{{"qmp", &directories.qmp}, {"spice", &directories.spice}} {
		path := filepath.Join(parent, item.name)
		if err := os.Mkdir(path, 0o700); err != nil {
			_ = directories.Cleanup()
			return nil, err
		}
		identity, err := inspectRuntimeDirectory(path)
		if err != nil {
			_ = directories.Cleanup()
			return nil, err
		}
		*item.destination = identity
	}
	return directories, nil
}

func inspectRuntimeDirectory(path string) (ownedRuntimeDirectory, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return ownedRuntimeDirectory{}, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return ownedRuntimeDirectory{}, ErrHostRuntimeUnavailable
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
		return ownedRuntimeDirectory{}, ErrHostRuntimeUnavailable
	}
	return ownedRuntimeDirectory{path: path, dev: uint64(stat.Dev), ino: stat.Ino, uid: stat.Uid, gid: stat.Gid}, nil
}

func (directories *runtimeSocketDirectories) QMPSocket() string {
	return filepath.Join(directories.qmp.path, "qmp.sock")
}

func (directories *runtimeSocketDirectories) SPICESocket() string {
	return filepath.Join(directories.spice.path, "spice.sock")
}

func (directories *runtimeSocketDirectories) Cleanup() error {
	if directories == nil {
		return nil
	}
	for _, directory := range []*ownedRuntimeDirectory{&directories.spice, &directories.qmp} {
		if directory.path == "" {
			continue
		}
		current, err := inspectRuntimeDirectory(directory.path)
		if errors.Is(err, os.ErrNotExist) {
			directory.path = ""
			continue
		}
		if err != nil || current.dev != directory.dev || current.ino != directory.ino || current.uid != directory.uid || current.gid != directory.gid {
			return ErrHostRuntimeUnavailable
		}
		if err := os.Remove(directory.path); err != nil {
			return err
		}
		directory.path = ""
	}
	return nil
}

func (directories *runtimeSocketDirectories) Audit() error {
	if directories == nil {
		return nil
	}
	for _, directory := range []ownedRuntimeDirectory{directories.qmp, directories.spice} {
		if directory.path != "" {
			return ErrHostRuntimeUnavailable
		}
	}
	return nil
}

var _ HostImageSelector = OfficialCacheSelector{}
var _ HostRuntimeStarter = (*RuntimeStack)(nil)
var _ HostRuntimePreparer = (*RuntimeStack)(nil)
var _ HostRuntime = (*hostRuntimeResource)(nil)
