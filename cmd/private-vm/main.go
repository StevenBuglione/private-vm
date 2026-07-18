package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/buildinfo"
	"github.com/StevenBuglione/private-vm/internal/config"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
	"github.com/StevenBuglione/private-vm/internal/preflight"
)

type globalOptions struct {
	configPath     string
	json           bool
	noColor        bool
	nonInteractive bool
	timeout        time.Duration
	logLevel       string
	strict         bool
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	opts := &globalOptions{}
	root := newRootCommand(opts, stdout, stderr)
	root.SetArgs(args)
	err := root.Execute()
	if err == nil {
		return exitcode.OK
	}
	var app *apperror.Error
	if !errors.As(err, &app) {
		app = apperror.Wrap("CLI_USAGE", exitcode.Usage, err.Error(), "Run private-vm --help for the supported command and option syntax.", err)
	}
	if opts.json {
		enc := json.NewEncoder(stderr)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(app)
	} else {
		fmt.Fprintf(stderr, "%s: %s\nremediation: %s\n", app.Code, app.Message, app.Remediation)
	}
	return app.ExitCode
}

func newRootCommand(opts *globalOptions, stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "private-vm",
		Short:         "Disposable graphical private-workstation orchestrator",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return apperror.Wrap("CLI_USAGE", exitcode.Usage, err.Error(), "Run private-vm --help for the supported command and option syntax.", err)
	})
	flags := root.PersistentFlags()
	flags.StringVar(&opts.configPath, "config", "", "explicit configuration file")
	flags.BoolVar(&opts.json, "json", false, "emit machine-readable JSON")
	flags.BoolVar(&opts.noColor, "no-color", false, "disable color")
	flags.BoolVar(&opts.nonInteractive, "non-interactive", false, "refuse interactive prompts")
	flags.DurationVar(&opts.timeout, "timeout", 5*time.Minute, "operation timeout")
	flags.StringVar(&opts.logLevel, "log-level", "info", "error, warn, info, or debug")
	flags.BoolVar(&opts.strict, "strict", false, "enable strict checks")

	root.AddCommand(versionCommand(opts), doctorCommand(opts), initCommand(), planCommand())
	root.AddCommand(desktopCommand(), workspaceCommand(), torrentCommand(), scanCommand())
	root.AddCommand(vpnCommand(), usbCommand(), imagesCommand(), sessionCommand())
	root.AddCommand(policyCommand(), configCommand(opts), systemCommand(), runAliasCommand())
	root.AddCommand(completionCommand(root))
	return root
}

func versionCommand(opts *globalOptions) *cobra.Command {
	return &cobra.Command{
		Use: "version", Short: "Print build information", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := buildinfo.Current()
			if opts.json {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(info)
			}
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "private-vm %s\ncommit: %s\nbuilt: %s\ngo: %s\nplatform: %s/%s\n", info.Version, info.Commit, info.Date, info.GoVersion, info.OS, info.Arch)
			return err
		},
	}
}

func doctorCommand(opts *globalOptions) *cobra.Command {
	var repairSafe bool
	cmd := &cobra.Command{
		Use: "doctor", Short: "Run read-only host diagnostics", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if repairSafe {
				return apperror.New("SAFE_REPAIR_NOT_IMPLEMENTED", exitcode.Preflight, "Safe repair is not implemented yet.", "Run doctor without --repair-safe and apply the displayed remediation manually.")
			}
			report := (preflight.Doctor{Strict: opts.strict}).Run()
			if opts.json {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(report); err != nil {
					return err
				}
			} else {
				for _, diagnostic := range report.Diagnostics {
					fmt.Fprintf(cmd.OutOrStdout(), "[%s] %s: %s\n", strings.ToUpper(string(diagnostic.Severity)), diagnostic.Code, diagnostic.Summary)
					if diagnostic.Remediation != "" {
						fmt.Fprintf(cmd.OutOrStdout(), "  remediation: %s\n", diagnostic.Remediation)
					}
				}
				fmt.Fprintf(cmd.OutOrStdout(), "\nrunnable: %t\n", report.Runnable)
			}
			if !report.Runnable {
				return apperror.New("HOST_PREFLIGHT_FAILED", exitcode.Preflight, "Host preflight has blocking diagnostics.", "Resolve every blocking diagnostic and rerun private-vm doctor --strict.")
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&repairSafe, "repair-safe", false, "repair only explicitly safe installation state")
	return cmd
}

func configCommand(opts *globalOptions) *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Inspect and validate non-secret configuration"}
	cmd.AddCommand(&cobra.Command{Use: "validate [FILE]", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		path := opts.configPath
		if len(args) == 1 {
			path = args[0]
		}
		cfg, err := config.Load(path)
		if err != nil {
			return apperror.Wrap("CONFIG_INVALID", exitcode.Configuration, "Configuration validation failed.", "Correct the reported field without placing secrets in TOML.", err)
		}
		if opts.json {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
				SchemaVersion int  `json:"schema_version"`
				OK            bool `json:"ok"`
			}{1, true})
		}
		_, err = fmt.Fprintf(cmd.OutOrStdout(), "configuration valid (schema %d, repository %s)\n", cfg.SchemaVersion, cfg.ImageSource.Repository)
		return err
	}})
	cmd.AddCommand(notImplementedCommand("show", "Show redacted effective configuration"), notImplementedCommand("get KEY", "Get one non-secret configuration value"), notImplementedCommand("set KEY VALUE", "Set one non-secret configuration value"))
	return cmd
}

func initCommand() *cobra.Command {
	return notImplementedCommand("init", "Initialize user configuration")
}

func planCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "plan", Short: "Plan a workflow without mutation"}
	cmd.AddCommand(notImplementedCommand("workstation", "Plan a workstation"), notImplementedCommand("torrent", "Plan a torrent workflow"))
	return cmd
}

func desktopCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "desktop", Short: "Manage graphical workstations"}
	cmd.AddCommand(namedCommands("start", "connect", "status", "stop", "restart-viewer")...)
	bundles := &cobra.Command{Use: "bundles", Short: "Inspect desktop bundles"}
	bundles.AddCommand(namedCommands("list", "inspect NAME")...)
	cmd.AddCommand(bundles)
	return cmd
}

func workspaceCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "workspace", Short: "Transfer explicitly selected workspace files"}
	cmd.AddCommand(namedCommands("import FILE", "inbox", "list", "inspect PATH", "export", "verify", "discard")...)
	return cmd
}

func torrentCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "torrent", Short: "Acquire torrent content into quarantine"}
	cmd.AddCommand(namedCommands("start", "metadata", "select", "plan", "download", "pause", "resume", "status", "complete")...)
	add := notImplementedCommand("add", "Add a torrent through a bounded secure input")
	add.Flags().Bool("magnet-stdin", false, "read a magnet from standard input")
	add.Flags().String("torrent-file", "", "stream a .torrent file")
	cmd.AddCommand(add)
	return cmd
}

func scanCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "scan", Short: "Scan and reconstruct quarantined content"}
	cmd.AddCommand(namedCommands("start", "status", "report", "approve", "reject")...)
	return cmd
}

func vpnCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "vpn", Short: "Manage a volatile Proton WireGuard profile"}
	cmd.AddCommand(namedCommands("import", "inspect", "test", "rotate", "remove")...)
	return cmd
}

func usbCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "usb", Short: "Inspect, enroll and prepare exact USB devices"}
	cmd.AddCommand(namedCommands("list", "inspect", "enroll", "prepare", "verify", "forget")...)
	return cmd
}

func imagesCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "images", Short: "Build, synchronize and verify immutable images"}
	cmd.AddCommand(namedCommands("list", "sync", "pull REF", "verify REF", "inspect REF", "build", "test REF", "prune")...)
	return cmd
}

func sessionCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "session", Short: "Inspect and clean volatile sessions"}
	cmd.AddCommand(namedCommands("list", "status", "report", "stop", "abort", "cleanup")...)
	return cmd
}

func policyCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "policy", Short: "Inspect content policies"}
	cmd.AddCommand(namedCommands("list", "show NAME", "validate FILE")...)
	return cmd
}

func systemCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "system", Short: "Inspect or install host integration"}
	cmd.AddCommand(namedCommands("status", "install", "uninstall", "diagnostics")...)
	return cmd
}

func runAliasCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "run", Short: "Convenience aliases for complete planned workflows"}
	cmd.AddCommand(namedCommands("workstation", "torrent", "scanner")...)
	return cmd
}

func completionCommand(root *cobra.Command) *cobra.Command {
	cmd := &cobra.Command{Use: "completion", Short: "Generate shell completion"}
	cmd.AddCommand(&cobra.Command{Use: "bash", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return root.GenBashCompletion(cmd.OutOrStdout()) }})
	cmd.AddCommand(&cobra.Command{Use: "zsh", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return root.GenZshCompletion(cmd.OutOrStdout()) }})
	cmd.AddCommand(&cobra.Command{Use: "fish", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error { return root.GenFishCompletion(cmd.OutOrStdout(), true) }})
	return cmd
}

func namedCommands(names ...string) []*cobra.Command {
	result := make([]*cobra.Command, 0, len(names))
	for _, name := range names {
		result = append(result, notImplementedCommand(name, "Specified security workflow"))
	}
	return result
}

func notImplementedCommand(use, short string) *cobra.Command {
	return &cobra.Command{Use: use, Short: short, RunE: func(_ *cobra.Command, _ []string) error {
		return apperror.New("NOT_IMPLEMENTED", exitcode.Runtime, "This security-sensitive workflow is not implemented.", "Do not use this path until its backlog acceptance tests pass.")
	}}
}
