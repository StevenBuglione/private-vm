#!/usr/bin/env python3
"""Fail-closed policy checks for active and dormant GitHub workflows."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml


ACTION_SHA = re.compile(r"^[0-9a-f]{40}$")
DOCKER_DIGEST = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-fA-F]{64}$")
MAX_WORKFLOW_BYTES = 1024 * 1024
PINNED_IMAGE_ACTIONS = [
    "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
    "DeterminateSystems/nix-installer-action@ef8a148080ab6020fd15196c2084a2eea5ff2d25",
]
IMAGE_MATRIX = {
    "workstation-basic": {
        "image_target": "image-workstation-basic",
        "contract_check": "workstation-bundles",
        "smoke_primary": "workstation-desktop",
        "smoke_secondary": "",
    },
    "workstation-office": {
        "image_target": "image-workstation-office",
        "contract_check": "",
        "smoke_primary": "workstation-office-desktop",
        "smoke_secondary": "",
    },
    "workstation-development": {
        "image_target": "image-workstation-development",
        "contract_check": "",
        "smoke_primary": "workstation-development-desktop",
        "smoke_secondary": "",
    },
    "downloader": {
        "image_target": "image-downloader",
        "contract_check": "",
        "smoke_primary": "downloader-desktop",
        "smoke_secondary": "",
    },
    "scanner": {
        "image_target": "image-scanner",
        "contract_check": "scanner-image-contract",
        "smoke_primary": "scanner-update",
        "smoke_secondary": "scanner-offline",
    },
    "exporter": {
        "image_target": "image-exporter",
        "contract_check": "",
        "smoke_primary": "exporter",
        "smoke_secondary": "",
    },
}


class PolicyError(ValueError):
    """A workflow violates repository security policy."""


def _mapping(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyError(f"{location}: expected a mapping")
    return value


def _is_true(value: Any) -> bool:
    return str(value).lower() == "true"


def _triggers(document: dict[str, Any]) -> dict[str, Any]:
    value = document.get("on")
    if isinstance(value, str):
        return {value: {}}
    if isinstance(value, list):
        return {str(item): {} for item in value}
    return _mapping(value, "on")


def _permissions(value: Any, location: str) -> dict[str, str]:
    mapping = _mapping(value, location)
    return {str(key): str(permission) for key, permission in mapping.items()}


def _has_write(permissions: dict[str, str]) -> bool:
    return any(value == "write" for value in permissions.values())


def _protected_publish_kind(
    triggers: dict[str, Any], job: dict[str, Any]
) -> str | None:
    environment = str(job.get("environment", ""))
    if environment == "release" and set(triggers) == {"push"}:
        push = triggers.get("push")
        if (
            isinstance(push, dict)
            and set(push) == {"tags"}
            and push.get("tags") == ["v*"]
        ):
            return "release"
    condition = " ".join(str(job.get("if", "")).split())
    if environment == "image-publish" and condition == (
        "github.event_name == 'push' && github.ref == 'refs/heads/main'"
    ):
        return "image"
    return None


def _validate_protected_permissions(
    permissions: dict[str, str], kind: str, location: str
) -> None:
    expected = {
        "contents": "write" if kind == "release" else "read",
        "packages": "write",
        "id-token": "write",
        "attestations": "write",
    }
    if permissions != expected:
        raise PolicyError(
            f"{location}: protected {kind} permissions must be exactly {expected}"
        )


def _validate_uses(reference: str, location: str) -> str:
    if reference.startswith("./"):
        raise PolicyError(
            f"{location}: local actions and reusable workflows are not approved"
        )
    if reference.startswith("docker://"):
        if not DOCKER_DIGEST.fullmatch(reference):
            raise PolicyError(
                f"{location}: container action must use a complete sha256 digest"
            )
        return "docker"
    if "@" not in reference:
        raise PolicyError(f"{location}: action reference has no immutable revision")
    action, revision = reference.rsplit("@", 1)
    if not action or not ACTION_SHA.fullmatch(revision):
        raise PolicyError(f"{location}: action reference must use a full 40-hex SHA")
    return action.lower()


def _validate_action(step: dict[str, Any], location: str) -> None:
    uses = step.get("uses")
    if not uses:
        return
    action = _validate_uses(str(uses), location)

    settings = step.get("with") or {}
    settings = _mapping(settings, f"{location}.with")
    if action == "actions/checkout":
        if str(settings.get("persist-credentials", "")).lower() != "false":
            raise PolicyError(f"{location}: checkout must disable persisted credentials")
    if action == "actions/setup-go" and _is_true(settings.get("cache", "false")):
        if settings.get("cache-dependency-path") != "go.sum":
            raise PolicyError(f"{location}: Go cache must be keyed by go.sum")
    if action == "actions/cache":
        raise PolicyError(
            f"{location}: explicit cache actions require a separately reviewed policy"
        )


def validate_workflow_text(source: str, name: str = "workflow") -> None:
    if len(source.encode()) > MAX_WORKFLOW_BYTES:
        raise PolicyError(f"{name}: workflow exceeds {MAX_WORKFLOW_BYTES} bytes")
    try:
        document = yaml.load(source, Loader=yaml.BaseLoader)
    except yaml.YAMLError as error:
        raise PolicyError(f"{name}: invalid YAML: {error}") from error
    document = _mapping(document, name)
    triggers = _triggers(document)
    if "pull_request_target" in triggers:
        raise PolicyError(f"{name}: pull_request_target is prohibited")
    if "pull_request" in triggers and re.search(
        r"\bsecrets\b", str(document), flags=re.IGNORECASE
    ):
        raise PolicyError(f"{name}: pull-request workflow must not reference secrets")

    top_permissions = _permissions(document.get("permissions"), f"{name}.permissions")
    if top_permissions != {"contents": "read"}:
        raise PolicyError(f"{name}: workflow permissions must be exactly contents: read")

    jobs = _mapping(document.get("jobs"), f"{name}.jobs")
    for job_name, raw_job in jobs.items():
        location = f"{name}.jobs.{job_name}"
        job = _mapping(raw_job, location)
        permissions = top_permissions
        if "permissions" in job:
            permissions = _permissions(job["permissions"], f"{location}.permissions")
        protected_kind = _protected_publish_kind(triggers, job)
        if protected_kind:
            _validate_protected_permissions(permissions, protected_kind, location)
        elif _has_write(permissions):
            raise PolicyError(
                f"{location}: write permissions require an isolated protected environment job"
            )
        if "pull_request" in triggers and not protected_kind:
            if job.get("secrets"):
                raise PolicyError(f"{location}: pull-request job must not receive secrets")
            for permission in ("packages", "id-token", "attestations"):
                if permissions.get(permission) == "write":
                    raise PolicyError(
                        f"{location}: pull-request job must not receive {permission}: write"
                    )

        if job.get("uses"):
            _validate_uses(str(job["uses"]), f"{location}.uses")

        steps = job.get("steps", [])
        if not isinstance(steps, list):
            raise PolicyError(f"{location}.steps: expected a list")
        for index, raw_step in enumerate(steps):
            step_location = f"{location}.steps[{index}]"
            step = _mapping(raw_step, step_location)
            _validate_action(step, step_location)


def validate_image_workflow_text(source: str, name: str = "image-build.yml") -> None:
    """Validate the active REL-002 build-only image matrix."""
    try:
        document = yaml.load(source, Loader=yaml.BaseLoader)
    except yaml.YAMLError as error:
        raise PolicyError(f"{name}: invalid YAML: {error}") from error
    document = _mapping(document, name)
    triggers = _triggers(document)
    if set(triggers) != {"pull_request", "push"}:
        raise PolicyError(f"{name}: image builds must run only for pull requests and main pushes")
    push = _mapping(triggers["push"], f"{name}.on.push")
    if push.get("branches") != ["main"]:
        raise PolicyError(f"{name}: push builds must target only main")

    jobs = _mapping(document.get("jobs"), f"{name}.jobs")
    if set(jobs) != {"image"}:
        raise PolicyError(f"{name}: REL-002 permits only the build-only image job")
    job = _mapping(jobs["image"], f"{name}.jobs.image")
    if job.get("runs-on") != "ubuntu-24.04":
        raise PolicyError(f"{name}: images must use the standard ubuntu-24.04 public runner")
    if job.get("timeout-minutes") != "90":
        raise PolicyError(f"{name}: image jobs must have the reviewed 90-minute ceiling")
    if _permissions(job.get("permissions"), f"{name}.jobs.image.permissions") != {
        "contents": "read"
    }:
        raise PolicyError(f"{name}: image jobs must have only contents: read")
    for prohibited_key in ("container", "environment", "needs", "secrets", "services"):
        if prohibited_key in job:
            raise PolicyError(f"{name}: image job must not set {prohibited_key}")

    strategy = _mapping(job.get("strategy"), f"{name}.jobs.image.strategy")
    if _is_true(strategy.get("fail-fast", "true")):
        raise PolicyError(f"{name}: one image failure must not cancel independent image jobs")
    matrix = _mapping(strategy.get("matrix"), f"{name}.jobs.image.strategy.matrix")
    include = matrix.get("include")
    if not isinstance(include, list):
        raise PolicyError(f"{name}: image matrix include must be a list")

    actual: dict[str, dict[str, str]] = {}
    required_fields = {
        "image",
        "image_target",
        "contract_check",
        "smoke_primary",
        "smoke_secondary",
    }
    for index, raw_entry in enumerate(include):
        entry = _mapping(raw_entry, f"{name}.matrix.include[{index}]")
        if set(entry) != required_fields:
            raise PolicyError(
                f"{name}.matrix.include[{index}]: fields must be exactly {sorted(required_fields)}"
            )
        image = str(entry["image"])
        if image in actual:
            raise PolicyError(f"{name}: duplicate image matrix entry: {image}")
        actual[image] = {
            field: str(entry[field]) for field in required_fields if field != "image"
        }
    if actual != IMAGE_MATRIX:
        raise PolicyError(f"{name}: image matrix does not match the six official images")

    environment = _mapping(job.get("env"), f"{name}.jobs.image.env")
    nix_config = str(environment.get("NIX_CONFIG", ""))
    if "max-jobs = 1" not in nix_config or "cores = 2" not in nix_config:
        raise PolicyError(f"{name}: public image builds must use the reviewed Nix limits")

    steps = job.get("steps")
    if not isinstance(steps, list):
        raise PolicyError(f"{name}.jobs.image.steps: expected a list")
    if len(steps) != 10:
        raise PolicyError(f"{name}: image job must contain exactly ten reviewed steps")
    actual_actions = [
        str(_mapping(steps[index], f"{name}.jobs.image.steps[{index}]").get("uses", ""))
        for index in range(2)
    ]
    if actual_actions != PINNED_IMAGE_ACTIONS:
        raise PolicyError(f"{name}: image job action set does not match the reviewed pins")
    if any(
        "uses" in _mapping(steps[index], f"{name}.jobs.image.steps[{index}]")
        for index in range(2, len(steps))
    ):
        raise PolicyError(f"{name}: image job permits actions only for checkout and Nix setup")
    named_steps: dict[str, dict[str, Any]] = {}
    for index, raw_step in enumerate(steps):
        step = _mapping(raw_step, f"{name}.jobs.image.steps[{index}]")
        step_name = str(step.get("name", ""))
        if step_name:
            if step_name in named_steps:
                raise PolicyError(f"{name}: duplicate image step name: {step_name}")
            named_steps[step_name] = step

    required_step_names = {
        "Reclaim disposable runner space and enforce capacity",
        "Build one canonical image",
        "Report canonical image closure",
        "Run image contract check",
        "Boot primary smoke test under TCG",
        "Boot secondary smoke test under TCG",
        "Report bounded failure diagnostics",
        "Reclaim Nix outputs",
    }
    if set(named_steps) != required_step_names:
        missing = sorted(required_step_names - set(named_steps))
        extra = sorted(set(named_steps) - required_step_names)
        raise PolicyError(f"{name}: image step set differs; missing={missing}, extra={extra}")
    if str(named_steps["Report bounded failure diagnostics"].get("if")) != "failure()":
        raise PolicyError(f"{name}: failure diagnostics must run only after failure")
    if str(named_steps["Reclaim Nix outputs"].get("if")) != "always()":
        raise PolicyError(f"{name}: final Nix reclamation must run on every outcome")

    build_run = str(named_steps["Build one canonical image"].get("run", ""))
    primary_run = str(named_steps["Boot primary smoke test under TCG"].get("run", ""))
    secondary_run = str(named_steps["Boot secondary smoke test under TCG"].get("run", ""))
    for location, command in (
        ("canonical image", build_run),
        ("primary TCG smoke", primary_run),
        ("secondary TCG smoke", secondary_run),
    ):
        if "nix build" not in command or "--no-link" not in command:
            raise PolicyError(f"{name}: {location} must use nix build --no-link")

    prohibited_publication = re.compile(
        r"(actions/upload-artifact|packages\s*:\s*write|id-token\s*:\s*write|"
        r"attestations\s*:\s*write|\bghcr\.io\b|\boras\b|\bdocker\s+push\b|"
        r"\bgh\s+|\bnix\s+copy\b|\bgit\s+push\b|\bcurl\b|\bwget\b|\bscp\b|"
        r"\brsync\b|\bsocat\b)",
        flags=re.IGNORECASE,
    )
    if prohibited_publication.search(source):
        raise PolicyError(f"{name}: REL-002 image jobs must not publish artifacts")


def workflow_paths(root: Path) -> list[Path]:
    workflow_dir = root / ".github" / "workflows"
    paths = sorted(workflow_dir.glob("*.yml"))
    paths += sorted(workflow_dir.glob("*.yaml"))
    paths += sorted(workflow_dir.glob("*.yml.template"))
    paths += sorted(workflow_dir.glob("*.yaml.template"))
    if not paths:
        raise PolicyError(f"{workflow_dir}: no workflows found")
    return paths


def _run_tool(command: list[str], timeout: int) -> None:
    try:
        subprocess.run(command, check=True, timeout=timeout)
    except FileNotFoundError as error:
        raise PolicyError(f"required workflow tool is unavailable: {command[0]}") from error
    except subprocess.TimeoutExpired as error:
        raise PolicyError(f"workflow tool timed out: {command[0]}") from error
    except subprocess.CalledProcessError as error:
        raise PolicyError(f"workflow tool rejected the source: {command[0]}") from error


def validate_repository(root: Path) -> None:
    paths = workflow_paths(root)
    for path in paths:
        source = path.read_text()
        relative_name = str(path.relative_to(root))
        validate_workflow_text(source, relative_name)
        if path.name == "image-build.yml":
            validate_image_workflow_text(source, relative_name)

    with tempfile.TemporaryDirectory(prefix="private-vm-workflows-") as temporary:
        audit_paths: list[str] = []
        for index, path in enumerate(paths):
            target = Path(temporary) / f"{index:02d}-{path.name.removesuffix('.template')}"
            shutil.copyfile(path, target)
            audit_paths.append(str(target))
        _run_tool(["actionlint", *audit_paths], timeout=60)
        _run_tool(
            [
                "zizmor",
                "--offline",
                "--no-ignores",
                "--min-severity",
                "low",
                *audit_paths,
            ],
            timeout=120,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args()
    try:
        validate_repository(arguments.root.resolve())
    except (OSError, PolicyError) as error:
        print(f"workflow policy failed: {error}")
        return 1
    print("workflow policy passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
