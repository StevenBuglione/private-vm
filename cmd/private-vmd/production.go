package main

import (
	"context"
	"errors"
	"net/netip"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"time"

	"github.com/StevenBuglione/private-vm/internal/config"
	"github.com/StevenBuglione/private-vm/internal/daemon"
	"github.com/StevenBuglione/private-vm/internal/guest"
	"github.com/StevenBuglione/private-vm/internal/guestvpn"
	"github.com/StevenBuglione/private-vm/internal/image"
	"github.com/StevenBuglione/private-vm/internal/network"
	"github.com/StevenBuglione/private-vm/internal/orchestrator"
	"github.com/StevenBuglione/private-vm/internal/qemu"
	"github.com/StevenBuglione/private-vm/internal/storage"
	"github.com/StevenBuglione/private-vm/internal/usb"
	"github.com/StevenBuglione/private-vm/internal/vpn"
)

var qemuVersionPattern = regexp.MustCompile(`(?m)^QEMU emulator version ([0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)`)

type productionHostServices struct {
	profiles   *vpn.MemoryStore
	resolver   *vpn.EndpointResolver
	roles      *orchestrator.HostRoles
	scanners   *daemon.GuestScannerRelay
	exporters  *orchestrator.ExporterRuntimeStack
	usbSources *usb.ApprovedSourceRegistry
}

func (services *productionHostServices) Close() {
	if services != nil && services.profiles != nil {
		services.profiles.Close()
	}
}

func composeProductionHost(ctx context.Context, cfg config.Config) (*productionHostServices, error) {
	if ctx == nil || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return nil, errors.New("the frozen v1 production host requires Linux on amd64")
	}
	runtimeConfig := cfg.Runtime()
	cache, err := image.NewCache(runtimeConfig.ImageCache(), 0)
	if err != nil {
		return nil, err
	}
	hostCapacity, err := storage.ProbeHostCapacity(runtimeConfig.Directory(), runtimeConfig.ScratchDirectory())
	if err != nil {
		return nil, err
	}
	capacity, err := storage.NewCapacityPool(hostCapacity)
	if err != nil {
		return nil, err
	}

	toolNames := []string{"qemu-system-x86_64", "qemu-img", "losetup", "cryptsetup", "mkfs.ext4", "ip", "nft", "sysctl"}
	tools := make(map[string]string, len(toolNames))
	for _, name := range toolNames {
		path, err := resolveProductionTool(name)
		if err != nil {
			return nil, err
		}
		tools[name] = path
	}
	qemuVersion, err := probeQEMUVersion(ctx, storage.OSRunner{}, tools["qemu-system-x86_64"])
	if err != nil {
		return nil, err
	}

	cgroupFactory, err := qemu.CurrentCgroupFactory()
	if err != nil {
		return nil, err
	}
	launcher, err := qemu.NewLauncher(cgroupFactory)
	if err != nil {
		return nil, err
	}
	networks, err := network.NewManager(network.ToolPaths{
		IP: tools["ip"], NFT: tools["nft"], Sysctl: tools["sysctl"], Tun: "/dev/net/tun",
	})
	if err != nil {
		return nil, err
	}
	runner := storage.OSRunner{}
	mounter := storage.UnixMounter{}
	storageStack := orchestrator.StorageStack{
		Capacity: capacity,
		Tmpfs: &storage.TmpfsManager{
			RuntimeRoot: runtimeConfig.Directory(), Mounter: mounter,
		},
		LUKS: &storage.LUKSManager{
			ScratchRoot: runtimeConfig.ScratchDirectory(), RuntimeRoot: runtimeConfig.Directory(),
			Tools:  storage.Tools{Losetup: tools["losetup"], Cryptsetup: tools["cryptsetup"], MkfsExt4: tools["mkfs.ext4"]},
			Runner: runner, Mounter: mounter, Inspector: storage.SystemDeviceInspector{},
			CleanupWait: time.Duration(runtimeConfig.CleanupTimeoutSeconds()) * time.Second,
		},
		Overlays: storage.OverlayManager{
			QEMUImg: tools["qemu-img"], Runner: runner, Registry: storage.NewImageUseRegistry(),
		},
		SmallScratchMax: runtimeConfig.SmallScratchMaxBytes(),
	}
	profiles := vpn.NewMemoryStore()
	resolver := vpn.NewEndpointResolver()
	probeTargets, err := productionProbeTargets(cfg.VPN())
	if err != nil {
		profiles.Close()
		return nil, err
	}
	cids := guest.NewDefaultCIDAllocator()
	runtimeStack, err := orchestrator.NewRuntimeStack(
		runtimeConfig.Directory(), tools["qemu-system-x86_64"], cfg.VPN().ProfileName(),
		profiles, resolver, networks, cids, orchestrator.QEMUAdapter{Launcher: launcher},
		probeTargets,
	)
	if err != nil {
		profiles.Close()
		return nil, err
	}
	selector := orchestrator.OfficialCacheSelector{Cache: cache, QEMUVersion: qemuVersion}
	roles, err := orchestrator.NewHostRoles(selector, storageStack, runtimeStack)
	if err != nil {
		profiles.Close()
		return nil, err
	}
	roles.Capacities = productionTorrentCapacitySource()
	approvedSources := usb.NewApprovedSourceRegistry()
	if err := roles.ConfigureApprovedSources(approvedSources); err != nil {
		profiles.Close()
		return nil, err
	}
	workstationPromotion, err := orchestrator.NewWorkstationScannerPromotion(roles)
	if err != nil {
		profiles.Close()
		return nil, err
	}
	usbPromotion, err := orchestrator.NewUSBScannerPromotion(approvedSources)
	if err != nil {
		profiles.Close()
		return nil, err
	}
	scannerPromotion, err := orchestrator.NewScannerPromotionRouter(workstationPromotion, usbPromotion)
	if err != nil {
		profiles.Close()
		return nil, err
	}
	scannerRuntime, err := orchestrator.NewProductionScannerRuntime(
		roles, selector, storageStack, runtimeStack, scannerPromotion,
		orchestrator.ScannerRuntimePlan{VCPUs: 4, MemoryBytes: 4 << 30, RootBytes: 32 << 30},
	)
	if err != nil {
		profiles.Close()
		return nil, err
	}
	scanners, err := daemon.NewGuestScannerRelay(scannerRuntimeDaemonAdapter{runtime: scannerRuntime})
	if err != nil {
		profiles.Close()
		return nil, err
	}
	exporters, err := orchestrator.NewExporterRuntimeStack(roles, runtimeConfig.Directory(), tools["qemu-system-x86_64"], cids, launcher)
	if err != nil {
		profiles.Close()
		return nil, err
	}
	return &productionHostServices{profiles: profiles, resolver: resolver, roles: roles, scanners: scanners, exporters: exporters, usbSources: approvedSources}, nil
}

func productionTorrentCapacitySource() orchestrator.PlannedTorrentCapacitySource {
	return orchestrator.PlannedTorrentCapacitySource{
		ScannerScratchBytes:         guest.DefaultProductionScannerConfig().SandboxMaxBytes,
		WorkstationDestinationBytes: 32 << 30,
		ArchiveExpansionBytes:       4 << 30,
		ReconstructionBytes:         1 << 30,
		MaximumSelectedBytes:        500 << 30,
	}
}

func productionProbeTargets(configuration config.VPN) (guestvpn.ProbeTargets, error) {
	ipv4, ipv4Err := netip.ParseAddrPort(configuration.ProbeIPv4())
	ipv6, ipv6Err := netip.ParseAddrPort(configuration.ProbeIPv6())
	if ipv4Err != nil || ipv6Err != nil {
		return guestvpn.ProbeTargets{}, errors.New("the configured VPN probe targets are invalid")
	}
	targets, err := guestvpn.NewProbeTargets(configuration.ProbeDNSName(), ipv4, ipv6)
	if err != nil {
		return guestvpn.ProbeTargets{}, errors.New("the configured VPN probe targets are invalid")
	}
	return targets, nil
}

func resolveProductionTool(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", errors.New("a required production host tool is unavailable")
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", errors.New("a required production host tool path is invalid")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(resolved) || filepath.Clean(resolved) != resolved {
		return "", errors.New("a required production host tool path is not trusted")
	}
	return resolved, nil
}

func probeQEMUVersion(ctx context.Context, runner storage.Runner, binary string) (string, error) {
	if ctx == nil || runner == nil {
		return "", errors.New("QEMU version probe is incomplete")
	}
	probeContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result, err := runner.Run(probeContext, storage.Command{Path: binary, Args: []string{"--version"}})
	if err != nil {
		return "", errors.New("the installed QEMU version could not be verified")
	}
	defer clear(result.Stdout)
	match := qemuVersionPattern.FindSubmatch(result.Stdout)
	if len(match) != 2 {
		return "", errors.New("the installed QEMU version is not recognized")
	}
	return string(match[1]), nil
}
