package orchestrator

import (
	"context"
	"errors"
	"sync"
	"time"

	privatevmv1 "github.com/StevenBuglione/private-vm/gen/privatevm/v1"
	"github.com/StevenBuglione/private-vm/internal/guest"
	"github.com/StevenBuglione/private-vm/internal/image"
	"github.com/StevenBuglione/private-vm/internal/network"
	"github.com/StevenBuglione/private-vm/internal/qemu"
	"github.com/StevenBuglione/private-vm/internal/scan"
	"github.com/StevenBuglione/private-vm/internal/session"
	"github.com/StevenBuglione/private-vm/internal/vpn"
	"google.golang.org/grpc"
)

const scannerRuntimeCleanupTimeout = 30 * time.Second

var (
	ErrScannerRuntimeUnavailable = errors.New("production scanner runtime unavailable")
	ErrScannerIsolationInvalid   = errors.New("production scanner isolation contract invalid")
	ErrScannerPromotionPending   = errors.New("scanner destination relay is not composed")
)

// ScannerRuntimePlan is an immutable host-selected resource plan. Scanner
// sessions are created from a sealed downloader rather than the ordinary
// CreateSession RPC, so this closed plan is supplied by the daemon composition
// root and never accepted from a guest or CLI request.
type ScannerRuntimePlan struct {
	VCPUs       uint32
	MemoryBytes uint64
	RootBytes   uint64
}

func (plan ScannerRuntimePlan) launchPlan() (session.LaunchPlan, error) {
	result := session.LaunchPlan{
		Role: session.RoleScanner, PolicyName: "safe", VCPUs: plan.VCPUs,
		MemoryBytes: plan.MemoryBytes, RootBytes: plan.RootBytes,
	}
	if result.VCPUs == 0 || result.VCPUs > 64 || result.MemoryBytes < 512<<20 ||
		result.MemoryBytes > 256<<30 || result.MemoryBytes%(1<<20) != 0 || result.RootBytes == 0 || result.RootBytes > 2<<40 {
		return session.LaunchPlan{}, ErrScannerRuntimeUnavailable
	}
	return result, nil
}

type ScannerVMRequest struct {
	Snapshot   session.Snapshot
	Plan       session.LaunchPlan
	Image      image.RuntimeImage
	Storage    HostStorage
	Quarantine HostQuarantineLease
	Mode       qemu.ScannerMode
}

type ScannerVM interface {
	Client() (privatevmv1.ScannerGuestServiceClient, error)
	VerifyReport(scan.AuthenticatedReport) (scan.ScanReport, error)
	Stop(context.Context) error
	Audit(context.Context) error
}

type ScannerVMStarter interface {
	PrepareUpdate(context.Context, session.Snapshot) error
	Forget(string)
	StartScanner(context.Context, ScannerVMRequest) (ScannerVM, error)
}

// ScannerPromotionRelay is deliberately semantic. It receives no host path,
// QEMU option, device identity, socket, CID or capability. Implementations may
// stream only an output ID authenticated by report through the active scanner
// client and must complete the destination hash proof before returning.
type ScannerPromotionRelay interface {
	Promote(context.Context, session.Snapshot, scan.ScanReport, string, privatevmv1.ScannerGuestServiceClient) error
}

// FailClosedScannerPromotion keeps scanner approval unavailable until the
// workstation/exporter destination owner is composed. It is safe to install in
// production while rejection and cleanup remain fully operational.
type FailClosedScannerPromotion struct{}

func (FailClosedScannerPromotion) Promote(context.Context, session.Snapshot, scan.ScanReport, string, privatevmv1.ScannerGuestServiceClient) error {
	return ErrScannerPromotionPending
}

type scannerRuntimeState struct {
	sourceID   string
	plan       session.LaunchPlan
	image      image.RuntimeImage
	storage    HostStorage
	quarantine HostQuarantineLease
	update     ScannerVM
	offline    ScannerVM
}

// ProductionScannerRuntime owns the scanner-specific image, storage handoff
// and two serial VM boots. The session actor owns the cleanup functions it
// returns; this object only serializes access to the typed resources.
type ProductionScannerRuntime struct {
	mu sync.Mutex

	Sources   *HostRoles
	Images    HostImageSelector
	Storage   HostStorageAllocator
	VMs       ScannerVMStarter
	Promotion ScannerPromotionRelay
	plan      session.LaunchPlan
	states    map[string]*scannerRuntimeState
}

func NewProductionScannerRuntime(sources *HostRoles, images HostImageSelector, storage HostStorageAllocator, vms ScannerVMStarter, promotion ScannerPromotionRelay, plan ScannerRuntimePlan) (*ProductionScannerRuntime, error) {
	launchPlan, err := plan.launchPlan()
	if sources == nil || nilLikeHost(images) || nilLikeHost(storage) || nilLikeHost(vms) || nilLikeHost(promotion) || err != nil {
		return nil, ErrScannerRuntimeUnavailable
	}
	return &ProductionScannerRuntime{
		Sources: sources, Images: images, Storage: storage, VMs: vms, Promotion: promotion,
		plan: launchPlan, states: make(map[string]*scannerRuntimeState),
	}, nil
}

func (runtime *ProductionScannerRuntime) Preflight(ctx context.Context, source, scanner session.Snapshot) error {
	if runtime == nil || ctx == nil || source.Role != session.RoleDownloader || source.Phase != session.PhaseActive ||
		source.WorkflowState != "QUARANTINE_SEALED" || scanner.Role != session.RoleScanner || scanner.Phase != session.PhaseCreated ||
		scanner.WorkflowState != "UPDATE_VM_BOOTING" || source.OwnerUID != scanner.OwnerUID || source.ID == scanner.ID {
		return ErrScannerRuntimeUnavailable
	}
	state, err := runtime.Sources.state(source)
	if err != nil {
		return ErrScannerRuntimeUnavailable
	}
	runtime.Sources.mu.Lock()
	storageResource := state.storage
	processResource := state.runtime
	runtime.Sources.mu.Unlock()
	if storageResource == nil || storageResource.QuarantinePath() == "" || processResource == nil || processResource.Audit(ctx) != nil {
		return ErrScannerIsolationInvalid
	}
	return nil
}

func (runtime *ProductionScannerRuntime) VerifyImage(ctx context.Context, scanner session.Snapshot) error {
	if runtime == nil || ctx == nil || scanner.Role != session.RoleScanner {
		return ErrScannerRuntimeUnavailable
	}
	selected, err := runtime.Images.Select(ctx, scanner, runtime.plan)
	if err != nil || !validScannerImage(selected, runtime.plan) {
		return errors.Join(ErrHostImageUnavailable, err)
	}
	return nil
}

func (runtime *ProductionScannerRuntime) StorageAllocation(source, scanner session.Snapshot) session.AllocateFunc {
	return func(ctx context.Context) (session.CleanupFunc, session.AuditFunc, error) {
		if runtime == nil || ctx == nil {
			return nil, nil, ErrScannerRuntimeUnavailable
		}
		selected, err := runtime.Images.Select(ctx, scanner, runtime.plan)
		if err != nil || !validScannerImage(selected, runtime.plan) {
			return nil, nil, errors.Join(ErrHostImageUnavailable, err)
		}
		quarantine, err := runtime.Sources.AcquireSealedQuarantine(ctx, source)
		if err != nil {
			return nil, nil, err
		}
		storageResource, allocationErr := runtime.Storage.Allocate(ctx, scanner, runtime.plan, selected)
		if storageResource == nil {
			releaseErr := quarantine.Release(context.Background())
			return nil, nil, errors.Join(ErrHostStorageUnavailable, allocationErr, releaseErr)
		}
		state := &scannerRuntimeState{
			sourceID: source.ID, plan: runtime.plan, image: selected,
			storage: storageResource, quarantine: quarantine,
		}
		runtime.mu.Lock()
		if runtime.states == nil || runtime.states[scanner.ID] != nil {
			runtime.mu.Unlock()
			cleanupErr := errors.Join(storageResource.Cleanup(context.Background()), quarantine.Release(context.Background()))
			return nil, nil, errors.Join(ErrScannerRuntimeUnavailable, allocationErr, cleanupErr)
		}
		runtime.states[scanner.ID] = state
		runtime.mu.Unlock()

		cleanup := func(cleanupCtx context.Context) error {
			if err := storageResource.Cleanup(cleanupCtx); err != nil {
				return err
			}
			if err := quarantine.Release(cleanupCtx); err != nil {
				return err
			}
			runtime.VMs.Forget(scanner.ID)
			runtime.mu.Lock()
			if runtime.states[scanner.ID] == state {
				delete(runtime.states, scanner.ID)
			}
			runtime.mu.Unlock()
			return nil
		}
		audit := func(auditCtx context.Context) error {
			runtime.mu.Lock()
			present := runtime.states[scanner.ID] != nil
			runtime.mu.Unlock()
			if present {
				return ErrScannerRuntimeUnavailable
			}
			return errors.Join(storageResource.Audit(auditCtx), quarantine.Audit(auditCtx))
		}
		if allocationErr != nil {
			return cleanup, audit, allocationErr
		}
		return cleanup, audit, nil
	}
}

func (runtime *ProductionScannerRuntime) UpdateRuntimeAllocation(scanner session.Snapshot) session.AllocateFunc {
	return runtime.vmAllocation(scanner, qemu.ScannerModeUpdate)
}

func (runtime *ProductionScannerRuntime) OfflineRuntimeAllocation(scanner session.Snapshot) session.AllocateFunc {
	return runtime.vmAllocation(scanner, qemu.ScannerModeScan)
}

func (runtime *ProductionScannerRuntime) vmAllocation(scanner session.Snapshot, mode qemu.ScannerMode) session.AllocateFunc {
	return func(ctx context.Context) (session.CleanupFunc, session.AuditFunc, error) {
		state, err := runtime.state(scanner)
		if err != nil {
			return nil, nil, err
		}
		if mode == qemu.ScannerModeUpdate {
			if err := runtime.VMs.PrepareUpdate(ctx, scanner); err != nil {
				return nil, nil, err
			}
		} else {
			runtime.mu.Lock()
			update := state.update
			runtime.mu.Unlock()
			if update == nil || update.Audit(ctx) != nil {
				return nil, nil, ErrScannerIsolationInvalid
			}
		}
		vm, startErr := runtime.VMs.StartScanner(ctx, ScannerVMRequest{
			Snapshot: scanner, Plan: state.plan, Image: state.image, Storage: state.storage,
			Quarantine: state.quarantine, Mode: mode,
		})
		if vm == nil {
			return nil, nil, errors.Join(ErrScannerRuntimeUnavailable, startErr)
		}
		runtime.mu.Lock()
		current := runtime.states[scanner.ID]
		var occupied bool
		if current != state {
			occupied = true
		} else if mode == qemu.ScannerModeUpdate {
			occupied = state.update != nil
			if !occupied {
				state.update = vm
			}
		} else {
			occupied = state.offline != nil
			if !occupied {
				state.offline = vm
			}
		}
		runtime.mu.Unlock()
		if occupied {
			cleanupErr := vm.Stop(context.Background())
			return nil, nil, errors.Join(ErrScannerRuntimeUnavailable, startErr, cleanupErr)
		}
		cleanup := vm.Stop
		audit := vm.Audit
		if startErr != nil {
			return cleanup, audit, startErr
		}
		return cleanup, audit, nil
	}
}

func (runtime *ProductionScannerRuntime) UpdateClient(ctx context.Context, scanner session.Snapshot) (privatevmv1.ScannerGuestServiceClient, error) {
	state, err := runtime.state(scanner)
	if err != nil {
		return nil, err
	}
	runtime.mu.Lock()
	vm := state.update
	runtime.mu.Unlock()
	if vm == nil {
		return nil, ErrScannerRuntimeUnavailable
	}
	return vm.Client()
}

func (runtime *ProductionScannerRuntime) OfflineClient(ctx context.Context, scanner session.Snapshot) (privatevmv1.ScannerGuestServiceClient, error) {
	state, err := runtime.state(scanner)
	if err != nil {
		return nil, err
	}
	runtime.mu.Lock()
	vm := state.offline
	runtime.mu.Unlock()
	if vm == nil {
		return nil, ErrScannerRuntimeUnavailable
	}
	return vm.Client()
}

func (runtime *ProductionScannerRuntime) StopUpdate(ctx context.Context, scanner session.Snapshot) error {
	state, err := runtime.state(scanner)
	if err != nil {
		return err
	}
	runtime.mu.Lock()
	vm := state.update
	runtime.mu.Unlock()
	if vm == nil {
		return ErrScannerRuntimeUnavailable
	}
	if err := vm.Stop(ctx); err != nil {
		return err
	}
	return vm.Audit(ctx)
}

func (runtime *ProductionScannerRuntime) StopOffline(ctx context.Context, scanner session.Snapshot) error {
	state, err := runtime.state(scanner)
	if err != nil {
		return err
	}
	runtime.mu.Lock()
	vm := state.offline
	runtime.mu.Unlock()
	if vm == nil {
		return ErrScannerRuntimeUnavailable
	}
	if err := vm.Stop(ctx); err != nil {
		return err
	}
	return vm.Audit(ctx)
}

func (runtime *ProductionScannerRuntime) VerifyReport(_ context.Context, scanner session.Snapshot, envelope scan.AuthenticatedReport) (scan.ScanReport, error) {
	state, err := runtime.state(scanner)
	if err != nil {
		return scan.ScanReport{}, err
	}
	runtime.mu.Lock()
	vm := state.offline
	runtime.mu.Unlock()
	if vm == nil {
		return scan.ScanReport{}, ErrScannerRuntimeUnavailable
	}
	return vm.VerifyReport(envelope)
}

func (runtime *ProductionScannerRuntime) Promote(ctx context.Context, scanner session.Snapshot, report scan.ScanReport, destination string) error {
	if destination != "workstation" && destination != "usb" {
		return ErrScannerRuntimeUnavailable
	}
	client, err := runtime.OfflineClient(ctx, scanner)
	if err != nil {
		return err
	}
	return runtime.Promotion.Promote(ctx, scanner, report, destination, client)
}

func (runtime *ProductionScannerRuntime) state(scanner session.Snapshot) (*scannerRuntimeState, error) {
	if runtime == nil || session.ValidateID(scanner.ID) != nil || scanner.Role != session.RoleScanner {
		return nil, ErrScannerRuntimeUnavailable
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	state := runtime.states[scanner.ID]
	if state == nil {
		return nil, ErrScannerRuntimeUnavailable
	}
	return state, nil
}

func validScannerImage(selected image.RuntimeImage, plan session.LaunchPlan) bool {
	return selected.Entry.ImagePath != "" && selected.ManifestDigest != "" && selected.ImageDigest != "" &&
		selected.SourceCommit != "" && selected.VirtualSizeBytes != 0 && plan.RootBytes <= selected.VirtualSizeBytes
}

// PrepareUpdate resolves and freezes the Proton endpoint policy before any
// network resource is created. Guest-side tunnel configuration remains an
// independent authenticated scanner-image gate; host readiness is never
// treated as proof that freshclam may egress.
func (stack *RuntimeStack) PrepareUpdate(ctx context.Context, scanner session.Snapshot) error {
	if stack == nil || ctx == nil || scanner.Role != session.RoleScanner {
		return ErrScannerRuntimeUnavailable
	}
	resolved, status, err := stack.Profiles.Resolve(ctx, scanner.OwnerUID, stack.ProfileName, stack.Resolver)
	if err != nil || resolved == nil || status.Rotation != vpn.RotationCurrent {
		return errors.Join(ErrNetworkedNotVerified, err)
	}
	stack.mu.Lock()
	defer stack.mu.Unlock()
	if stack.prepared[scanner.ID] != nil {
		return ErrHostPlanUnavailable
	}
	stack.prepared[scanner.ID] = resolved
	return nil
}

func (stack *RuntimeStack) StartScanner(ctx context.Context, request ScannerVMRequest) (ScannerVM, error) {
	if stack == nil || ctx == nil || request.Snapshot.Role != session.RoleScanner || request.Plan.Role != session.RoleScanner ||
		request.Storage == nil || request.Quarantine == nil ||
		(request.Mode != qemu.ScannerModeUpdate && request.Mode != qemu.ScannerModeScan) {
		return nil, ErrScannerRuntimeUnavailable
	}
	if request.Mode == qemu.ScannerModeUpdate {
		stack.mu.Lock()
		resolution := stack.prepared[request.Snapshot.ID]
		stack.mu.Unlock()
		if resolution == nil {
			return nil, ErrNetworkedNotVerified
		}
	}

	resource := &scannerVMResource{stack: stack, sessionID: request.Snapshot.ID, mode: request.Mode}
	fail := func(cause error) (ScannerVM, error) {
		cleanupContext, cancel := context.WithTimeout(context.Background(), scannerRuntimeCleanupTimeout)
		cleanupErr := resource.Stop(cleanupContext)
		cancel()
		if cleanupErr != nil {
			return resource, errors.Join(cause, cleanupErr)
		}
		return nil, cause
	}
	cid, err := stack.CIDs.Allocate()
	if err != nil {
		return nil, err
	}
	resource.cid, resource.cidOwned = cid, true
	token, err := guest.NewToken()
	if err != nil {
		return fail(err)
	}
	resource.capability = token
	if request.Mode == qemu.ScannerModeUpdate {
		stack.mu.Lock()
		resolution := stack.prepared[request.Snapshot.ID]
		stack.mu.Unlock()
		networkHandle, createErr := stack.Networks.Create(ctx, request.Snapshot.ID, request.Snapshot.OwnerUID, stack.ProfileName, stack.Profiles, resolution)
		if createErr != nil {
			return fail(createErr)
		}
		resource.network = networkHandle
	}
	directories, err := createRuntimeSocketDirectories(stack.RuntimeRoot, request.Snapshot.ID)
	if err != nil {
		return fail(err)
	}
	resource.directories = directories
	images, err := request.Storage.ActivateImages()
	if err != nil {
		return fail(err)
	}
	resource.images = images
	specification, err := scannerQEMUSpec(stack.QEMUBinary, request, cid, directories)
	if err != nil {
		return fail(err)
	}
	expectation := guest.HandshakeExpectation{
		SessionID: request.Snapshot.ID, Role: session.RoleScanner,
		ImageDigest: request.Image.ImageDigest, SourceCommit: request.Image.SourceCommit,
		Capabilities: append([]string(nil), request.Image.Capabilities...), MinimumProtocolMinor: 0,
	}
	if request.Mode == qemu.ScannerModeUpdate {
		networked, startErr := StartNetworked(ctx, StartNetworkedRequest{
			SessionID: request.Snapshot.ID, Role: session.RoleScanner, ScannerUpdate: true, Spec: specification,
			Network: NetworkAdapter{Handle: resource.network}, Capability: token,
			Launcher: stack.Launcher, Guests: VSOCKGuestConnector{Expected: expectation, ProbeTargets: stack.ProbeTargets},
			Egress:        networkPolicyAuditor{sessionID: request.Snapshot.ID, handle: resource.network},
			LossResponder: inertHostLossResponder{},
		})
		if networked != nil {
			resource.networked = networked
			resource.capability = nil
			resource.network = nil
		}
		if startErr != nil || networked == nil {
			return fail(errors.Join(ErrScannerRuntimeUnavailable, startErr))
		}
		client, clientErr := networked.ScannerClient()
		if clientErr != nil {
			return fail(clientErr)
		}
		resource.client = client
		stack.Forget(request.Snapshot.ID)
		return resource, nil
	}
	capabilityFile, err := token.DupFile()
	if err != nil {
		return fail(err)
	}
	defer capabilityFile.Close()
	resource.process, err = stack.Launcher.Launch(ctx, specification, qemu.InheritedFiles{Capability: capabilityFile})
	if err != nil || resource.process == nil {
		return fail(errors.Join(ErrScannerRuntimeUnavailable, err))
	}
	connection, err := guest.Dial(guest.ClientConfig{CID: cid, Port: guest.DefaultPort, Token: token})
	if err != nil {
		return fail(err)
	}
	resource.connection = connection
	common := privatevmv1.NewGuestCommonServiceClient(connection)
	expectation.RequestID, err = newGuestRequestID()
	if err != nil {
		return fail(err)
	}
	handshakeContext, cancelHandshake := context.WithTimeout(ctx, 20*time.Second)
	_, err = guest.Handshake(handshakeContext, common, expectation)
	cancelHandshake()
	if err != nil {
		return fail(err)
	}
	resource.client = privatevmv1.NewScannerGuestServiceClient(connection)
	return resource, nil
}

func scannerQEMUSpec(binary string, request ScannerVMRequest, cid uint32, directories *runtimeSocketDirectories) (qemu.Spec, error) {
	if directories == nil || request.Storage.RootPath() == "" {
		return qemu.Spec{}, ErrScannerRuntimeUnavailable
	}
	specification := qemu.Spec{
		Binary: binary, SessionID: request.Snapshot.ID, Name: request.Snapshot.ID,
		Role: session.RoleScanner, ScannerMode: request.Mode,
		CPUs: request.Plan.VCPUs, MemoryBytes: request.Plan.MemoryBytes,
		Root:      qemu.Disk{Path: request.Storage.RootPath(), Format: "qcow2", Serial: "root"},
		QMPSocket: directories.QMPSocket(), SPICESocket: directories.SPICESocket(),
		VSOCKCID: cid, FWCfgTokenFD: 3,
	}
	switch request.Mode {
	case qemu.ScannerModeUpdate:
		specification.Networked = true
		specification.NetworkFD = 4
	case qemu.ScannerModeScan:
		path := request.Quarantine.Path()
		if path == "" {
			return qemu.Spec{}, ErrScannerIsolationInvalid
		}
		specification.Data = []qemu.Disk{{Path: path, Format: "raw", ReadOnly: true, Serial: "quarantine"}}
	default:
		return qemu.Spec{}, ErrScannerIsolationInvalid
	}
	if err := specification.Validate(); err != nil {
		return qemu.Spec{}, errors.Join(ErrScannerIsolationInvalid, err)
	}
	return specification, nil
}

type scannerVMResource struct {
	mu sync.Mutex

	stack           *RuntimeStack
	sessionID       string
	mode            qemu.ScannerMode
	cid             uint32
	cidOwned        bool
	capability      *guest.Token
	network         *network.Handle
	networked       *NetworkedRuntime
	process         ManagedProcess
	connection      *grpc.ClientConn
	client          privatevmv1.ScannerGuestServiceClient
	images          qemu.RuntimeImageLease
	directories     *runtimeSocketDirectories
	processGone     bool
	connectionGone  bool
	imagesGone      bool
	capabilityGone  bool
	networkGone     bool
	cidGone         bool
	directoriesGone bool
}

func (resource *scannerVMResource) Client() (privatevmv1.ScannerGuestServiceClient, error) {
	if resource == nil {
		return nil, ErrScannerRuntimeUnavailable
	}
	resource.mu.Lock()
	defer resource.mu.Unlock()
	if resource.client == nil || resource.processGone || resource.connectionGone {
		return nil, ErrScannerRuntimeUnavailable
	}
	return resource.client, nil
}

func (resource *scannerVMResource) VerifyReport(envelope scan.AuthenticatedReport) (scan.ScanReport, error) {
	if resource == nil {
		return scan.ScanReport{}, ErrScannerRuntimeUnavailable
	}
	resource.mu.Lock()
	defer resource.mu.Unlock()
	if resource.mode != qemu.ScannerModeScan || resource.capability == nil || resource.processGone {
		return scan.ScanReport{}, ErrScannerRuntimeUnavailable
	}
	return resource.capability.VerifyScannerReport(envelope)
}

func (resource *scannerVMResource) Stop(ctx context.Context) error {
	if resource == nil {
		return nil
	}
	resource.mu.Lock()
	defer resource.mu.Unlock()
	if resource.networked != nil && !resource.processGone {
		if err := resource.networked.Stop(ctx, true); err != nil {
			return err
		}
		resource.processGone = true
		resource.connectionGone = true
		resource.capabilityGone = true
		resource.networkGone = true
		resource.client = nil
	} else if !resource.processGone && resource.process != nil {
		_ = resource.process.Stop(ctx)
		waitContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		waitErr := resource.process.Wait(waitContext)
		waitTimedOut := errors.Is(waitErr, context.DeadlineExceeded)
		cancel()
		if waitTimedOut {
			return ErrScannerRuntimeUnavailable
		}
		resource.processGone = true
	} else if resource.process == nil {
		resource.processGone = true
	}
	var cleanupErrors []error
	if !resource.connectionGone {
		if resource.connection != nil {
			if err := resource.connection.Close(); err != nil {
				cleanupErrors = append(cleanupErrors, err)
			} else {
				resource.connectionGone = true
				resource.client = nil
			}
		} else {
			resource.connectionGone = true
		}
	}
	if !resource.imagesGone {
		if resource.images != nil {
			if err := resource.images.Destroy(); err != nil {
				cleanupErrors = append(cleanupErrors, err)
			} else {
				resource.imagesGone = true
			}
		} else {
			resource.imagesGone = true
		}
	}
	if !resource.capabilityGone {
		if resource.capability != nil {
			resource.capability.Destroy()
		}
		resource.capabilityGone = true
	}
	if !resource.networkGone {
		if resource.network != nil {
			if err := resource.network.Cleanup(ctx); err != nil {
				cleanupErrors = append(cleanupErrors, err)
			} else {
				resource.networkGone = true
			}
		} else {
			resource.networkGone = true
		}
	}
	if !resource.cidGone {
		if resource.cidOwned && !resource.stack.CIDs.Release(resource.cid) {
			cleanupErrors = append(cleanupErrors, ErrScannerRuntimeUnavailable)
		} else {
			resource.cidOwned = false
			resource.cidGone = true
		}
	}
	if !resource.directoriesGone {
		if resource.directories != nil {
			if err := resource.directories.Cleanup(); err != nil {
				cleanupErrors = append(cleanupErrors, err)
			} else {
				resource.directoriesGone = true
			}
		} else {
			resource.directoriesGone = true
		}
	}
	return errors.Join(cleanupErrors...)
}

func (resource *scannerVMResource) Audit(context.Context) error {
	if resource == nil {
		return ErrScannerRuntimeUnavailable
	}
	resource.mu.Lock()
	defer resource.mu.Unlock()
	var audits []error
	if !resource.processGone || !resource.connectionGone || !resource.imagesGone || !resource.capabilityGone ||
		!resource.networkGone || !resource.cidGone || !resource.directoriesGone {
		audits = append(audits, ErrScannerRuntimeUnavailable)
	}
	if resource.images != nil && resource.images.Audit() != nil {
		audits = append(audits, ErrScannerRuntimeUnavailable)
	}
	if resource.networked != nil && resource.networked.Audit(context.Background()) != nil {
		audits = append(audits, ErrScannerRuntimeUnavailable)
	}
	if resource.network != nil {
		inspection := resource.network.Inspect()
		if inspection.Ready || inspection.TAPReady || inspection.IPv4EndpointCount != 0 || inspection.IPv6EndpointCount != 0 {
			audits = append(audits, ErrScannerRuntimeUnavailable)
		}
	}
	if resource.stack != nil && resource.stack.CIDs.Reserved(resource.cid) {
		audits = append(audits, ErrScannerRuntimeUnavailable)
	}
	if resource.directories != nil && resource.directories.Audit() != nil {
		audits = append(audits, ErrScannerRuntimeUnavailable)
	}
	return errors.Join(audits...)
}

var _ ScannerVMStarter = (*RuntimeStack)(nil)
var _ ScannerVM = (*scannerVMResource)(nil)
