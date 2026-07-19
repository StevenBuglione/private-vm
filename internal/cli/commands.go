package cli

import (
	"strconv"

	"github.com/spf13/cobra"
)

type commandFactory struct {
	app *App
}

func (factory commandFactory) group(use, short string, children ...*cobra.Command) *cobra.Command {
	command := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  noArgs,
		RunE:  requireSubcommand,
	}
	command.AddCommand(children...)
	return command
}

func (factory commandFactory) operation(
	use, short string,
	id CommandID,
	args cobra.PositionalArgs,
	validate func(*cobra.Command) error,
	intent func([]string) Intent,
) *cobra.Command {
	if args == nil {
		args = noArgs
	}
	if intent == nil {
		intent = func([]string) Intent { return EmptyIntent{} }
	}
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  args,
		RunE: func(command *cobra.Command, args []string) error {
			if validate != nil {
				if err := validate(command); err != nil {
					return err
				}
			}
			return factory.app.invoke(command, id, intent(args))
		},
	}
}

func (factory commandFactory) simple(use string, id CommandID) *cobra.Command {
	return factory.operation(use, "Specified security workflow", id, noArgs, nil, nil)
}

func (factory commandFactory) commands() []*cobra.Command {
	return []*cobra.Command{
		factory.simple("init", "init"),
		factory.plan(),
		factory.desktop(),
		factory.workspace(),
		factory.torrent(),
		factory.scan(),
		factory.vpn(),
		factory.usb(),
		factory.images(),
		factory.session(),
		factory.policy(),
		factory.system(),
		factory.runAliases(),
	}
}

func (factory commandFactory) plan() *cobra.Command {
	var workstationBundle string
	workstation := factory.operation("workstation", "Plan a workstation", "plan.workstation", noArgs, func(*cobra.Command) error {
		return enum(workstationBundle, "bundle", "basic", "office", "development")
	}, func([]string) Intent { return PlanWorkstationIntent{Bundle: workstationBundle} })
	workstation.Flags().StringVar(&workstationBundle, "bundle", "", "basic, office, or development")

	var policy, destination string
	torrent := factory.operation("torrent", "Plan a torrent workflow", "plan.torrent", noArgs, func(*cobra.Command) error {
		if err := enum(policy, "policy", "safe", "quarantine"); err != nil {
			return err
		}
		return enum(destination, "destination", "usb")
	}, func([]string) Intent { return PlanTorrentIntent{Policy: policy, Destination: destination} })
	torrent.Flags().StringVar(&policy, "policy", "", "safe or quarantine")
	torrent.Flags().StringVar(&destination, "destination", "", "planned final destination")
	return factory.group("plan", "Plan a workflow without mutation", workstation, torrent)
}

func (factory commandFactory) desktop() *cobra.Command {
	start, _ := factory.workstationStart("start")
	connect := factory.optionalSession("connect", CommandDesktopConnect)
	status := factory.optionalSession("status", "desktop.status")
	restart := factory.optionalSession("restart-viewer", CommandDesktopRestart)

	var stopSession string
	var requireClean, discard bool
	stop := factory.operation("stop", "Stop a workstation", "desktop.stop", noArgs, func(*cobra.Command) error {
		if err := validateSessionID(stopSession, false); err != nil {
			return err
		}
		return validateExclusive(boolCount(requireClean, discard), false,
			"The stop policy flags are mutually exclusive.",
			"Choose either --require-clean or --discard; omitting both requires a clean workspace.")
	}, func([]string) Intent {
		return DesktopStopIntent{SessionID: stopSession, RequireClean: requireClean, Discard: discard}
	})
	stop.Flags().StringVar(&stopSession, "session", "", "session identifier")
	stop.Flags().BoolVar(&requireClean, "require-clean", false, "refuse to stop a dirty workspace")
	stop.Flags().BoolVar(&discard, "discard", false, "explicitly discard unexported workspace data")

	list := factory.simple("list", "desktop.bundles.list")
	inspect := factory.operation("inspect NAME", "Inspect one desktop bundle", "desktop.bundles.inspect", exactArgs(1), func(command *cobra.Command) error {
		return enum(command.Flags().Arg(0), "bundle", "basic", "office", "development")
	}, func(args []string) Intent { return BundleIntent{Name: args[0]} })
	bundles := factory.group("bundles", "Inspect desktop bundles", list, inspect)
	return factory.group("desktop", "Manage graphical workstations", start, connect, status, stop, restart, bundles)
}

func (factory commandFactory) workstationStart(use string) (*cobra.Command, *WorkstationIntent) {
	intent := &WorkstationIntent{}
	command := factory.operation(use, "Start a graphical workstation", CommandWorkstationStart, noArgs, func(command *cobra.Command) error {
		if !command.Flags().Changed("bundle") {
			intent.Bundle = factory.app.configuration.Desktop().Bundle()
		}
		if !command.Flags().Changed("audio") {
			intent.Audio = factory.app.configuration.Desktop().Audio()
		}
		if !command.Flags().Changed("memory") {
			intent.Memory = strconv.FormatUint(factory.app.configuration.Desktop().MemoryBytes(), 10) + "B"
		}
		if !command.Flags().Changed("cpus") {
			intent.CPUs = int(factory.app.configuration.Desktop().VCPUs())
		}
		if err := enum(intent.Bundle, "bundle", "basic", "office", "development"); err != nil {
			return err
		}
		return validateDesktopResources(intent.Memory, intent.CPUs, command.Flags().Changed("cpus"))
	}, func([]string) Intent { return *intent })
	command.Flags().StringVar(&intent.Bundle, "bundle", "basic", "basic, office, or development")
	command.Flags().BoolVar(&intent.Audio, "audio", false, "enable guest audio")
	command.Flags().StringVar(&intent.Memory, "memory", "", "bounded IEC memory size")
	command.Flags().IntVar(&intent.CPUs, "cpus", 0, "virtual CPU count")
	return command, intent
}

func (factory commandFactory) optionalSession(use string, id CommandID) *cobra.Command {
	var sessionID string
	command := factory.operation(use, "Operate on a workstation session", id, noArgs, func(*cobra.Command) error {
		return validateSessionID(sessionID, false)
	}, func([]string) Intent { return SessionIntent{SessionID: sessionID} })
	command.Flags().StringVar(&sessionID, "session", "", "session identifier")
	return command
}

func (factory commandFactory) workspace() *cobra.Command {
	var importSession string
	importCommand := factory.operation("import FILE", "Import one trusted host file", CommandWorkspaceImport, exactArgs(1), func(command *cobra.Command) error {
		if err := validatePath(command.Flags().Arg(0)); err != nil {
			return err
		}
		return validateSessionID(importSession, false)
	}, func(args []string) Intent { return WorkspacePathIntent{SessionID: importSession, Path: args[0]} })
	importCommand.Flags().StringVar(&importSession, "session", "", "session identifier")

	inbox := factory.optionalSessionOperation("inbox", CommandWorkspaceInbox)
	list := factory.optionalSessionOperation("list", CommandWorkspaceList)

	var inspectSession string
	inspect := factory.operation("inspect PATH", "Inspect a workspace path", "workspace.inspect", exactArgs(1), func(command *cobra.Command) error {
		if err := validatePath(command.Flags().Arg(0)); err != nil {
			return err
		}
		return validateSessionID(inspectSession, false)
	}, func(args []string) Intent { return WorkspacePathIntent{SessionID: inspectSession, Path: args[0]} })
	inspect.Flags().StringVar(&inspectSession, "session", "", "session identifier")

	var exportTo, exportSession string
	export := factory.operation("export OUTPUT", "Export an explicit workspace result", CommandWorkspaceExport, exactArgs(1), func(command *cobra.Command) error {
		if err := enum(exportTo, "export destination", "usb", "encrypted-bundle"); err != nil {
			return err
		}
		if err := validateOpaqueID(command.Flags().Arg(0), "workspace output", true); err != nil {
			return err
		}
		return validateSessionID(exportSession, false)
	}, func(args []string) Intent {
		return WorkspaceExportIntent{SessionID: exportSession, Destination: exportTo, OutputID: args[0]}
	})
	export.Flags().StringVar(&exportTo, "to", "", "usb or encrypted-bundle")
	export.Flags().StringVar(&exportSession, "session", "", "session identifier")

	var verifyLast bool
	var verifyExport, verifySession string
	verify := factory.operation("verify", "Verify a workspace export", CommandWorkspaceVerify, noArgs, func(*cobra.Command) error {
		if err := validateExclusive(boolCount(verifyLast, verifyExport != ""), true,
			"The workspace verification selectors are mutually exclusive.",
			"Choose exactly one of --last and --export."); err != nil {
			return err
		}
		if err := validateOpaqueID(verifyExport, "export", false); err != nil {
			return err
		}
		return validateSessionID(verifySession, false)
	}, func([]string) Intent {
		return WorkspaceVerifyIntent{SessionID: verifySession, Last: verifyLast, ExportID: verifyExport}
	})
	verify.Flags().BoolVar(&verifyLast, "last", false, "verify the last export")
	verify.Flags().StringVar(&verifyExport, "export", "", "export identifier")
	verify.Flags().StringVar(&verifySession, "session", "", "session identifier")

	var discardAll bool
	var discardSession string
	discard := factory.operation("discard", "Discard all workspace data", CommandWorkspaceDiscard, noArgs, func(*cobra.Command) error {
		if !discardAll {
			return usageError("Workspace discard requires --all.", "Pass --all to explicitly confirm the complete volatile workspace selection.")
		}
		return validateSessionID(discardSession, false)
	}, func([]string) Intent { return WorkspaceDiscardIntent{SessionID: discardSession, All: discardAll} })
	discard.Flags().BoolVar(&discardAll, "all", false, "discard the complete workspace")
	discard.Flags().StringVar(&discardSession, "session", "", "session identifier")

	return factory.group("workspace", "Transfer explicitly selected workspace files", importCommand, inbox, list, inspect, export, verify, discard)
}

func (factory commandFactory) optionalSessionOperation(use string, id CommandID) *cobra.Command {
	var sessionID string
	command := factory.operation(use, "Operate on an explicit workspace", id, noArgs, func(*cobra.Command) error {
		return validateSessionID(sessionID, false)
	}, func([]string) Intent { return SessionIntent{SessionID: sessionID} })
	command.Flags().StringVar(&sessionID, "session", "", "session identifier")
	return command
}

func (factory commandFactory) torrent() *cobra.Command {
	var startPolicy string
	start := factory.operation("start", "Start a torrent workflow", CommandTorrentStart, noArgs, func(*cobra.Command) error {
		return enum(startPolicy, "policy", "safe", "quarantine")
	}, func([]string) Intent { return TorrentIntent{Policy: startPolicy} })
	start.Flags().StringVar(&startPolicy, "policy", "safe", "safe or quarantine")

	var magnetTTY, magnetStdin bool
	var torrentFile string
	add := factory.operation("add", "Add a torrent through bounded secure input", CommandTorrentAdd, noArgs, func(*cobra.Command) error {
		selected := boolCount(magnetTTY, magnetStdin, torrentFile != "")
		if err := validateExclusive(selected, true,
			"Torrent input requires exactly one secure source.",
			"Choose hidden terminal input, --magnet-stdin, or --torrent-file."); err != nil {
			return err
		}
		if torrentFile != "" {
			return validatePath(torrentFile)
		}
		return nil
	}, func([]string) Intent {
		return TorrentInputIntent{MagnetTTY: magnetTTY, MagnetStdin: magnetStdin, TorrentFile: torrentFile}
	})
	add.Flags().BoolVar(&magnetTTY, "magnet-tty", false, "read one bounded magnet with terminal echo disabled")
	add.Flags().BoolVar(&magnetStdin, "magnet-stdin", false, "read one bounded magnet from standard input")
	add.Flags().StringVar(&torrentFile, "torrent-file", "", "stream one bounded .torrent file")

	var files string
	selectFiles := factory.operation("select", "Select torrent file indexes", CommandTorrentSelect, noArgs, func(*cobra.Command) error {
		return validateFileSelection(files)
	}, func([]string) Intent {
		indexes, _ := parseFileSelection(files)
		return TorrentSelectionIntent{Files: indexes}
	})
	selectFiles.Flags().StringVar(&files, "files", "", "comma-separated file indexes")

	children := []*cobra.Command{start, add, factory.simple("metadata", CommandTorrentMetadata), selectFiles}
	children = append(children,
		factory.simple("plan", CommandTorrentPlan),
		factory.simple("download", CommandTorrentDownload),
		factory.simple("pause", CommandTorrentPause),
		factory.simple("resume", CommandTorrentResume),
		factory.simple("status", CommandTorrentStatus),
		factory.simple("complete", CommandTorrentComplete),
	)
	return factory.group("torrent", "Acquire torrent content into quarantine", children...)
}

func (factory commandFactory) scan() *cobra.Command {
	requiredSession := func(use string, id CommandID) *cobra.Command {
		var sessionID string
		command := factory.operation(use, "Operate on a scanner session", id, noArgs, func(*cobra.Command) error {
			return validateSessionID(sessionID, true)
		}, func([]string) Intent { return ScannerIntent{SessionID: sessionID} })
		command.Flags().StringVar(&sessionID, "session", "", "required session identifier")
		return command
	}
	var startSession string
	start := factory.operation("start", "Start an offline scanner session", CommandScannerStart, noArgs, func(*cobra.Command) error {
		return validateSessionID(startSession, true)
	}, func([]string) Intent { return ScannerIntent{SessionID: startSession} })
	start.Flags().StringVar(&startSession, "session", "", "required session identifier")
	status := requiredSession("status", CommandScannerStatus)
	report := requiredSession("report", CommandScannerReport)
	reject := requiredSession("reject", CommandScannerReject)

	var sessionID, openIn, to string
	approve := factory.operation("approve", "Approve reconstructed output", CommandScannerApprove, noArgs, func(*cobra.Command) error {
		if err := validateSessionID(sessionID, true); err != nil {
			return err
		}
		if err := validateExclusive(boolCount(openIn != "", to != ""), true,
			"Scan approval requires exactly one destination.",
			"Choose either --open-in workstation or --to usb."); err != nil {
			return err
		}
		if err := optionalEnum(openIn, "open destination", "workstation"); err != nil {
			return err
		}
		return optionalEnum(to, "export destination", "usb")
	}, func([]string) Intent { return ScanApprovalIntent{SessionID: sessionID, OpenIn: openIn, To: to} })
	approve.Flags().StringVar(&sessionID, "session", "", "required session identifier")
	approve.Flags().StringVar(&openIn, "open-in", "", "workstation")
	approve.Flags().StringVar(&to, "to", "", "usb")
	return factory.group("scan", "Scan and reconstruct quarantined content", start, status, report, approve, reject)
}

func (factory commandFactory) vpn() *cobra.Command {
	secureImport := func(use string, id CommandID) *cobra.Command {
		var fromFile string
		var stdin bool
		command := factory.operation(use, "Import a volatile WireGuard profile", id, noArgs, func(*cobra.Command) error {
			if err := validateExclusive(boolCount(fromFile != "", stdin), false,
				"VPN import sources are mutually exclusive.",
				"Choose at most one of --from-file and --stdin."); err != nil {
				return err
			}
			if factory.app.options.NonInteractive && fromFile == "" && !stdin {
				return usageError("Non-interactive VPN import requires an explicit source.", "Choose --from-file or --stdin.")
			}
			if fromFile != "" {
				return validatePath(fromFile)
			}
			return nil
		}, func([]string) Intent {
			return VPNImportIntent{
				ProfileName: factory.app.configuration.VPN().ProfileName(),
				FromFile:    fromFile,
				Stdin:       stdin,
			}
		})
		command.Flags().StringVar(&fromFile, "from-file", "", "read a caller-owned private profile file")
		command.Flags().BoolVar(&stdin, "stdin", false, "read a bounded profile from standard input")
		return command
	}
	profileOperation := func(use string, id CommandID) *cobra.Command {
		return factory.operation(use, "Inspect or mutate the configured volatile VPN profile", id, noArgs, nil, func([]string) Intent {
			return VPNProfileIntent{ProfileName: factory.app.configuration.VPN().ProfileName()}
		})
	}
	return factory.group("vpn", "Manage a volatile Proton WireGuard profile",
		secureImport("import", CommandVPNImport),
		profileOperation("inspect", CommandVPNInspect),
		profileOperation("test", CommandVPNTest),
		secureImport("rotate", CommandVPNRotate),
		profileOperation("remove", CommandVPNRemove),
	)
}

func (factory commandFactory) usb() *cobra.Command {
	requiredDevice := func(use string, id CommandID) *cobra.Command {
		var device string
		command := factory.operation(use, "Operate on an exact USB identity", id, noArgs, func(*cobra.Command) error {
			return validateUSBDeviceID(device)
		}, func([]string) Intent { return USBDeviceIntent{DeviceID: device} })
		command.Flags().StringVar(&device, "device", "", "exact enrolled device identifier")
		return command
	}
	var enrollmentDevice, enrollmentLabel string
	var acceptPortBinding bool
	enroll := factory.operation("enroll", "Enroll one exact mass-storage-only USB identity", CommandUSBEnroll, noArgs, func(*cobra.Command) error {
		if err := validateUSBDeviceID(enrollmentDevice); err != nil {
			return err
		}
		return validateUSBLabel(enrollmentLabel)
	}, func([]string) Intent {
		return USBDeviceIntent{DeviceID: enrollmentDevice, Label: enrollmentLabel, AcceptPortBinding: acceptPortBinding}
	})
	enroll.Flags().StringVar(&enrollmentDevice, "device", "", "exact discovery identifier")
	enroll.Flags().StringVar(&enrollmentLabel, "label", "PRIVATE_VM_TRANSFER", "safe enrollment label")
	enroll.Flags().BoolVar(&acceptPortBinding, "accept-port-binding", false, "accept exact physical-port binding when no serial exists")
	var format string
	prepare := factory.operation("prepare", "Prepare an enrolled USB device", "usb.prepare", noArgs, func(*cobra.Command) error {
		if err := enum(format, "USB format", "luks2-ext4"); err != nil {
			return err
		}
		if factory.app.options.NonInteractive {
			return usageError("USB prepare requires an interactive confirmation.", "Run without --non-interactive and confirm the exact enrolled identity.")
		}
		return nil
	}, func([]string) Intent { return USBPrepareIntent{Format: format} })
	prepare.Flags().StringVar(&format, "format", "", "required format: luks2-ext4")
	return factory.group("usb", "Inspect, enroll and prepare exact USB devices",
		factory.simple("list", CommandUSBList),
		requiredDevice("inspect", CommandUSBInspect),
		enroll,
		prepare,
		factory.simple("verify", CommandUSBVerify),
		factory.simple("forget", CommandUSBForget),
	)
}

func (factory commandFactory) images() *cobra.Command {
	var syncRole, syncBundle string
	syncCommand := factory.operation("sync", "Synchronize official images", "images.sync", noArgs, func(*cobra.Command) error {
		return validateRoleBundle(syncRole, syncBundle, false)
	}, func([]string) Intent { return ImageSelectionIntent{Role: syncRole, Bundle: syncBundle} })
	syncCommand.Flags().StringVar(&syncRole, "role", "", "workstation, downloader, scanner, or exporter")
	syncCommand.Flags().StringVar(&syncBundle, "bundle", "", "workstation bundle")

	refCommand := func(use string, id CommandID) *cobra.Command {
		return factory.operation(use+" REF", "Operate on an OCI image reference", id, exactArgs(1), func(command *cobra.Command) error {
			return validateOCIReference(command.Flags().Arg(0))
		}, func(args []string) Intent { return ImageReferenceIntent{Reference: args[0]} })
	}

	var buildRole, buildBundle string
	build := factory.operation("build", "Build one official role image", "images.build", noArgs, func(*cobra.Command) error {
		return validateRoleBundle(buildRole, buildBundle, true)
	}, func([]string) Intent { return ImageSelectionIntent{Role: buildRole, Bundle: buildBundle} })
	build.Flags().StringVar(&buildRole, "role", "", "required role")
	build.Flags().StringVar(&buildBundle, "bundle", "", "workstation bundle")

	var backend string
	test := factory.operation("test REF", "Test one image", "images.test", exactArgs(1), func(command *cobra.Command) error {
		if err := validateOCIReference(command.Flags().Arg(0)); err != nil {
			return err
		}
		return enum(backend, "test backend", "qemu", "packer")
	}, func(args []string) Intent { return ImageTestIntent{Reference: args[0], Backend: backend} })
	test.Flags().StringVar(&backend, "backend", "qemu", "qemu or packer")

	return factory.group("images", "Build, synchronize and verify immutable images",
		factory.simple("list", "images.list"), syncCommand,
		refCommand("pull", "images.pull"), refCommand("verify", "images.verify"),
		refCommand("inspect", "images.inspect"), build, test,
		factory.simple("prune", "images.prune"),
	)
}

func validateRoleBundle(role, bundle string, roleRequired bool) error {
	if roleRequired {
		if err := enum(role, "role", "workstation", "downloader", "scanner", "exporter"); err != nil {
			return err
		}
	} else if err := optionalEnum(role, "role", "workstation", "downloader", "scanner", "exporter"); err != nil {
		return err
	}
	if err := optionalEnum(bundle, "bundle", "basic", "office", "development"); err != nil {
		return err
	}
	if bundle != "" && role != "workstation" {
		return usageError("Image bundles are valid only for the workstation role.", "Set --role workstation or omit --bundle.")
	}
	return nil
}

func (factory commandFactory) session() *cobra.Command {
	requiredSession := func(use string, id CommandID) *cobra.Command {
		var sessionID string
		command := factory.operation(use, "Operate on an exact session", id, noArgs, func(*cobra.Command) error {
			return validateSessionID(sessionID, true)
		}, func([]string) Intent { return SessionIntent{SessionID: sessionID} })
		command.Flags().StringVar(&sessionID, "session", "", "required session identifier")
		return command
	}

	var reportSession, reportExport string
	report := factory.operation("report", "Report one session", "session.report", noArgs, func(*cobra.Command) error {
		if err := validateSessionID(reportSession, true); err != nil {
			return err
		}
		if reportExport != "" {
			return validatePath(reportExport)
		}
		return nil
	}, func([]string) Intent { return SessionReportIntent{SessionID: reportSession, ExportPath: reportExport} })
	report.Flags().StringVar(&reportSession, "session", "", "required session identifier")
	report.Flags().StringVar(&reportExport, "export", "", "write a redacted report file")

	var cleanupSession string
	var cleanupAll bool
	cleanup := factory.operation("cleanup", "Clean verified private-vm resources", "session.cleanup", noArgs, func(*cobra.Command) error {
		if err := validateExclusive(boolCount(cleanupSession != "", cleanupAll), false,
			"Session cleanup selectors are mutually exclusive.",
			"Choose at most one of --session and --all."); err != nil {
			return err
		}
		return validateSessionID(cleanupSession, false)
	}, func([]string) Intent { return SessionCleanupIntent{SessionID: cleanupSession, All: cleanupAll} })
	cleanup.Flags().StringVar(&cleanupSession, "session", "", "session identifier")
	cleanup.Flags().BoolVar(&cleanupAll, "all", false, "clean all verified private-vm resources")

	return factory.group("session", "Inspect and clean volatile sessions",
		factory.simple("list", "session.list"), requiredSession("status", "session.status"), report,
		requiredSession("stop", "session.stop"), requiredSession("abort", "session.abort"), cleanup,
	)
}

func (factory commandFactory) policy() *cobra.Command {
	show := factory.operation("show NAME", "Show one content policy", "policy.show", exactArgs(1), func(command *cobra.Command) error {
		return validateOpaqueID(command.Flags().Arg(0), "policy", true)
	}, func(args []string) Intent { return PolicyNameIntent{Name: args[0]} })
	validate := factory.operation("validate FILE", "Validate one policy file", "policy.validate", exactArgs(1), func(command *cobra.Command) error {
		return validatePath(command.Flags().Arg(0))
	}, func(args []string) Intent { return PolicyFileIntent{Path: args[0]} })
	return factory.group("policy", "Inspect content policies", factory.simple("list", "policy.list"), show, validate)
}

func (factory commandFactory) system() *cobra.Command {
	var dryRun, accept bool
	install := factory.operation("install", "Install host integration", "system.install", noArgs, func(*cobra.Command) error {
		return validateExclusive(boolCount(dryRun, accept), true,
			"System install requires exactly one execution mode.",
			"Choose --dry-run to inspect changes or --accept to apply the reviewed plan.")
	}, func([]string) Intent { return SystemInstallIntent{DryRun: dryRun, Accept: accept} })
	install.Flags().BoolVar(&dryRun, "dry-run", false, "show the installation plan")
	install.Flags().BoolVar(&accept, "accept", false, "apply the reviewed installation plan")

	var uninstallDryRun bool
	uninstall := factory.operation("uninstall", "Plan host integration removal", "system.uninstall", noArgs, func(*cobra.Command) error {
		if !uninstallDryRun {
			return usageError("System uninstall requires --dry-run in v1.", "Use --dry-run to inspect the bounded removal plan.")
		}
		return nil
	}, func([]string) Intent { return SystemUninstallIntent{DryRun: uninstallDryRun} })
	uninstall.Flags().BoolVar(&uninstallDryRun, "dry-run", false, "show the removal plan")

	var diagnosticsExport string
	diagnostics := factory.operation("diagnostics", "Create a redacted diagnostic bundle", "system.diagnostics", noArgs, func(*cobra.Command) error {
		if diagnosticsExport != "" {
			return validatePath(diagnosticsExport)
		}
		return nil
	}, func([]string) Intent { return SystemDiagnosticsIntent{ExportPath: diagnosticsExport} })
	diagnostics.Flags().StringVar(&diagnosticsExport, "export", "", "review and write a redacted bundle")

	return factory.group("system", "Inspect or install host integration", factory.simple("status", "system.status"), install, uninstall, diagnostics)
}

func (factory commandFactory) runAliases() *cobra.Command {
	workstation, _ := factory.workstationStart("workstation")

	intent := &TorrentIntent{Policy: "safe"}
	torrent := factory.operation("torrent", "Run the complete torrent workflow", CommandTorrentRun, noArgs, func(*cobra.Command) error {
		return enum(intent.Policy, "policy", "safe", "quarantine")
	}, func([]string) Intent { return *intent })
	torrent.Flags().StringVar(&intent.Policy, "policy", "safe", "safe or quarantine")

	var scannerSession string
	scanner := factory.operation("scanner", "Run the scanner workflow", CommandScannerStart, noArgs, func(*cobra.Command) error {
		return validateSessionID(scannerSession, true)
	}, func([]string) Intent { return ScannerIntent{SessionID: scannerSession} })
	scanner.Flags().StringVar(&scannerSession, "session", "", "required session identifier")

	return factory.group("run", "Convenience aliases for complete planned workflows", workstation, torrent, scanner)
}

func boolCount(values ...bool) int {
	count := 0
	for _, value := range values {
		if value {
			count++
		}
	}
	return count
}
