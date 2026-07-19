package cli

import (
	"bytes"
	"context"
	"errors"
	"io"

	"github.com/spf13/cobra"

	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/buildinfo"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
	"github.com/StevenBuglione/private-vm/internal/preflight"
)

const maximumCompletionBytes = 1 << 20

// Dependencies are the narrow composition seams used by the command layer.
// Product orchestration remains behind Invoker rather than Cobra callbacks.
type Dependencies struct {
	Stdout    io.Writer
	Stderr    io.Writer
	Invoker   Invoker
	Doctor    func(context.Context, bool) preflight.Report
	BuildInfo func() buildinfo.Info
}

// App owns one immutable CLI invocation and its root command.
type App struct {
	options       Options
	stdout        io.Writer
	stderr        io.Writer
	invoker       Invoker
	doctor        func(context.Context, bool) preflight.Report
	buildInfo     func() buildinfo.Info
	machineOutput bool
	root          *cobra.Command
}

// New constructs the complete v1 command surface with fail-closed defaults.
func New(dependencies Dependencies) *App {
	if dependencies.Stdout == nil {
		dependencies.Stdout = io.Discard
	}
	if dependencies.Stderr == nil {
		dependencies.Stderr = io.Discard
	}
	if dependencies.Invoker == nil {
		dependencies.Invoker = failClosedInvoker{}
	}
	if dependencies.Doctor == nil {
		dependencies.Doctor = func(ctx context.Context, strict bool) preflight.Report {
			return (preflight.Doctor{Strict: strict}).RunContext(ctx)
		}
	}
	if dependencies.BuildInfo == nil {
		dependencies.BuildInfo = buildinfo.Current
	}
	app := &App{
		options:   defaultOptions(),
		stdout:    dependencies.Stdout,
		stderr:    dependencies.Stderr,
		invoker:   dependencies.Invoker,
		doctor:    dependencies.Doctor,
		buildInfo: dependencies.BuildInfo,
	}
	app.root = app.newRootCommand()
	return app
}

// Run executes one CLI invocation and returns the stable process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return New(Dependencies{Stdout: stdout, Stderr: stderr}).Execute(ctx, args)
}

// Execute runs the already-constructed application exactly once.
func (app *App) Execute(ctx context.Context, args []string) int {
	if ctx == nil {
		ctx = context.Background()
	}
	app.machineOutput = machineOutputRequested(args)
	app.options.JSON = app.machineOutput
	if app.machineOutput && (hasEnabledFlag(args, "--help") || hasEnabledFlag(args, "-h")) {
		return app.renderExit(usageError(
			"Machine output cannot be combined with help output.",
			"Run the command with --help for human reference, or omit --help when using --json.",
		))
	}
	app.root.SetArgs(args)
	err := app.root.ExecuteContext(ctx)
	if err == nil {
		return exitcode.OK
	}
	return app.renderExit(normalizeCommandError(err))
}

func (app *App) renderExit(applicationError *apperror.Error) int {
	envelope := NewErrorEnvelope(applicationError)
	if renderErr := NewRenderer(app.machineOutput).Error(app.stderr, applicationError); renderErr != nil {
		return exitcode.Internal
	}
	return envelope.ExitCode
}

func hasEnabledFlag(args []string, name string) bool {
	enabled := false
	for _, argument := range args {
		if argument == "--" {
			break
		}
		switch argument {
		case name, name + "=true":
			enabled = true
		case name + "=false":
			enabled = false
		}
	}
	return enabled
}

func machineOutputRequested(args []string) bool {
	enabled := false
	for _, argument := range args {
		if argument == "--" {
			break
		}
		switch argument {
		case "--json", "--json=true":
			enabled = true
		case "--json=false":
			enabled = false
		}
	}
	return enabled
}

func normalizeCommandError(err error) *apperror.Error {
	var applicationError *apperror.Error
	if errors.As(err, &applicationError) {
		return applicationError
	}
	return apperror.Wrap(
		"CLI_USAGE",
		exitcode.Usage,
		"The command or option syntax is invalid.",
		"Run private-vm --help and use only the documented commands and options.",
		err,
	)
}

func (app *App) newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "private-vm",
		Short:         "Disposable graphical private-workstation orchestrator",
		Args:          noArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			return validateGlobalOptions(app.options)
		},
		RunE: func(command *cobra.Command, _ []string) error {
			if app.options.Version {
				return app.renderVersion()
			}
			if app.options.JSON {
				return usageError(
					"Machine output requires a command.",
					"Select a documented command when using --json, or use --help without --json.",
				)
			}
			return command.Help()
		},
	}
	root.SetOut(app.stdout)
	root.SetErr(app.stderr)
	root.SetFlagErrorFunc(func(*cobra.Command, error) error {
		return usageError(
			"The command or option syntax is invalid.",
			"Run private-vm --help and use only the documented commands and options.",
		)
	})

	flags := root.PersistentFlags()
	flags.StringVar(&app.options.ConfigPath, "config", "", "explicit non-secret configuration file")
	flags.BoolVar(&app.options.JSON, "json", false, "emit machine-readable JSON")
	flags.BoolVar(&app.options.NoColor, "no-color", false, "disable color")
	flags.BoolVar(&app.options.NonInteractive, "non-interactive", false, "refuse interactive prompts")
	flags.DurationVar(&app.options.Timeout, "timeout", defaultTimeout, "bounded operation timeout")
	flags.StringVar(&app.options.LogLevel, "log-level", "info", "error, warn, info, or debug")
	flags.BoolVar(&app.options.Strict, "strict", false, "enable strict checks")
	root.Flags().BoolVar(&app.options.Version, "version", false, "print build information")

	factory := commandFactory{app: app}
	root.AddCommand(factory.commands()...)
	root.AddCommand(app.versionCommand(), app.doctorCommand(), app.completionCommand())
	return root
}

func (app *App) versionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print build information",
		Args:  noArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return app.renderVersion()
		},
	}
}

func (app *App) renderVersion() error {
	info := app.buildInfo()
	return NewRenderer(app.options.JSON).Success(app.stdout, CodeVersion, VersionPayload{
		Version: info.Version, Commit: info.Commit, Date: info.Date,
		GoVersion: info.GoVersion, OS: info.OS, Arch: info.Arch,
	})
}

func (app *App) doctorCommand() *cobra.Command {
	var repairSafe bool
	command := &cobra.Command{
		Use:   "doctor",
		Short: "Run read-only host diagnostics",
		Args:  noArgs,
		RunE: func(command *cobra.Command, _ []string) error {
			if repairSafe {
				return apperror.New(
					"SAFE_REPAIR_NOT_IMPLEMENTED",
					exitcode.Preflight,
					"Safe repair is not implemented.",
					"Run doctor without --repair-safe and apply the displayed remediation manually.",
				)
			}
			ctx, cancel := context.WithTimeout(command.Context(), app.options.Timeout)
			defer cancel()
			if err := ctx.Err(); err != nil {
				return contextError(err)
			}
			report := app.doctor(ctx, app.options.Strict)
			if err := ctx.Err(); err != nil {
				return contextError(err)
			}
			payload := doctorPayload(report)
			if err := NewRenderer(app.options.JSON).Success(app.stdout, CodeDoctorReport, payload); err != nil {
				return err
			}
			if !report.Runnable {
				return apperror.New(
					"HOST_PREFLIGHT_FAILED",
					exitcode.Preflight,
					"Host preflight has blocking diagnostics.",
					"Resolve every blocking diagnostic and rerun private-vm doctor --strict.",
				)
			}
			return nil
		},
	}
	command.Flags().BoolVar(&repairSafe, "repair-safe", false, "repair only explicitly safe installation state")
	return command
}

func doctorPayload(report preflight.Report) DoctorPayload {
	diagnostics := make([]DoctorDiagnostic, 0, len(report.Diagnostics))
	for _, diagnostic := range report.Diagnostics {
		diagnostics = append(diagnostics, DoctorDiagnostic{
			Code: diagnostic.Code, Severity: string(diagnostic.Severity), Summary: diagnostic.Summary,
			Remediation: diagnostic.Remediation, Overridable: diagnostic.Overridable,
		})
	}
	return DoctorPayload{Runnable: report.Runnable, Diagnostics: diagnostics}
}

func (app *App) completionCommand() *cobra.Command {
	completion := &cobra.Command{
		Use:   "completion",
		Short: "Generate a shell completion script",
		Args:  requireSubcommand,
		RunE:  requireSubcommand,
	}
	for _, shell := range []string{"bash", "zsh", "fish"} {
		shell := shell
		completion.AddCommand(&cobra.Command{
			Use:   shell,
			Short: "Generate " + shell + " completion",
			Args:  noArgs,
			RunE: func(*cobra.Command, []string) error {
				if app.options.JSON {
					return usageError(
						"Shell completion output is not a JSON record.",
						"Omit --json when generating a bounded shell completion script.",
					)
				}
				var output bytes.Buffer
				var err error
				switch shell {
				case "bash":
					err = app.root.GenBashCompletion(&output)
				case "zsh":
					err = app.root.GenZshCompletion(&output)
				case "fish":
					err = app.root.GenFishCompletion(&output, true)
				}
				if err != nil {
					return apperror.Wrap("COMPLETION_FAILED", exitcode.Internal, "Completion generation failed.", "Retry with a supported shell name.", err)
				}
				if output.Len() > maximumCompletionBytes {
					return apperror.New("COMPLETION_FAILED", exitcode.Internal, "Completion output exceeded its safety bound.", "Report the generated command surface to the maintainers.")
				}
				if _, err := io.Copy(app.stdout, &output); err != nil {
					return apperror.Wrap("COMPLETION_FAILED", exitcode.Internal, "Completion output could not be written.", "Retry with a writable output destination.", err)
				}
				return nil
			},
		})
	}
	return completion
}

func (app *App) invoke(command *cobra.Command, id CommandID, intent Intent) error {
	ctx, cancel := context.WithTimeout(command.Context(), app.options.Timeout)
	defer cancel()
	result, err := app.invoker.Invoke(ctx, id, intent)
	if ctx.Err() != nil {
		return contextError(ctx.Err())
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return contextError(context.Canceled)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return contextError(context.DeadlineExceeded)
		}
		return apperror.From(err)
	}
	if result.Code == "" || result.Data == nil {
		return apperror.New("INTERNAL_ERROR", exitcode.Internal, "The command returned an invalid result.", "Retry once; if the error persists, export a redacted diagnostic bundle.")
	}
	return NewRenderer(app.options.JSON).Success(app.stdout, result.Code, result.Data)
}

func contextError(err error) *apperror.Error {
	if err == context.Canceled {
		return apperror.New("OPERATION_CANCELLED", exitcode.Cancelled, "The operation was cancelled.", "Retry the command when ready.")
	}
	return apperror.New("OPERATION_TIMEOUT", exitcode.Runtime, "The operation exceeded its bounded timeout.", "Increase --timeout within the documented limit or resolve the stalled dependency.")
}
