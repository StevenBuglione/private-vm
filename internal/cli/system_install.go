package cli

import (
	"context"
	"errors"

	"github.com/StevenBuglione/private-vm/internal/apperror"
	"github.com/StevenBuglione/private-vm/internal/exitcode"
	"github.com/StevenBuglione/private-vm/internal/systeminstall"
)

type systemInstallInvoker struct {
	installer systeminstall.Installer
}

// NewSystemInstallInvoker composes the generic-archive installer adapter. It
// deliberately fails closed for every command owned by another orchestrator.
func NewSystemInstallInvoker(installer systeminstall.Installer) Invoker {
	return systemInstallInvoker{installer: installer}
}

func (invoker systemInstallInvoker) Invoke(ctx context.Context, id CommandID, intent Intent) (Result, error) {
	switch id {
	case "system.install":
		request, ok := intent.(SystemInstallIntent)
		if !ok {
			return Result{}, installError("SYSTEM_INSTALL_INVALID", "The install request is invalid.", "Use exactly one of --dry-run or --accept.")
		}
		var plan systeminstall.Plan
		var err error
		if request.DryRun {
			plan, err = invoker.installer.PlanInstall(ctx)
		} else if request.Accept {
			plan, err = invoker.installer.Install(ctx)
		} else {
			err = errors.New("execution mode missing")
		}
		if err != nil {
			return Result{}, normalizeInstallFailure(err, "install")
		}
		return Result{Code: CodeSystemPlan, Data: systemPlanPayload(plan, !request.DryRun)}, nil
	case "system.uninstall":
		request, ok := intent.(SystemUninstallIntent)
		if !ok {
			return Result{}, installError("SYSTEM_UNINSTALL_INVALID", "The uninstall request is invalid.", "Use exactly one of --dry-run or --accept.")
		}
		var plan systeminstall.Plan
		var err error
		if request.DryRun {
			plan, err = invoker.installer.PlanUninstall(ctx)
		} else if request.Accept {
			plan, err = invoker.installer.Uninstall(ctx)
		} else {
			err = errors.New("execution mode missing")
		}
		if err != nil {
			return Result{}, normalizeInstallFailure(err, "uninstall")
		}
		return Result{Code: CodeSystemPlan, Data: systemPlanPayload(plan, !request.DryRun)}, nil
	default:
		return Result{}, apperror.New(
			"NOT_IMPLEMENTED", exitcode.Runtime,
			"This security-sensitive workflow is not implemented.",
			"Do not use this path until its backlog acceptance tests pass.",
		)
	}
}

func systemPlanPayload(plan systeminstall.Plan, applied bool) SystemPlanPayload {
	changes := make([]SystemChangePayload, 0, len(plan.Changes))
	for _, change := range plan.Changes {
		changes = append(changes, SystemChangePayload{Operation: string(change.Operation), Path: change.Path})
	}
	return SystemPlanPayload{Action: plan.Action, Version: plan.Version, Applied: applied, Changes: changes}
}

func normalizeInstallFailure(err error, action string) error {
	if errors.Is(err, systeminstall.ErrRollbackIncomplete) {
		return apperror.New(
			"SYSTEM_ROLLBACK_INCOMPLETE", exitcode.Cleanup,
			"The host integration transaction could not prove complete rollback or staging cleanup.",
			"Do not retry blindly; inspect the fixed paths from the dry-run plan and run private-vm doctor --strict.",
		)
	}
	if errors.Is(err, context.Canceled) {
		return apperror.New("OPERATION_CANCELLED", exitcode.Cancelled, "The operation was cancelled.", "Review the unchanged or rolled-back installation state before retrying.")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return apperror.New("OPERATION_TIMEOUT", exitcode.Runtime, "The operation exceeded its bounded timeout.", "Inspect the service state and rerun the dry-run plan before retrying.")
	}
	operation := "INSTALL"
	if action == "uninstall" {
		operation = "UNINSTALL"
	}
	return installError(
		"SYSTEM_"+operation+"_FAILED",
		"The generic Linux "+action+" transaction failed closed.",
		"Correct the documented host or bundle condition, then rerun the dry-run plan.",
	)
}

func installError(code, message, remediation string) *apperror.Error {
	return apperror.New(code, exitcode.Preflight, message, remediation)
}
