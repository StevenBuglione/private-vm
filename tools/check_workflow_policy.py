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
        validate_workflow_text(path.read_text(), str(path.relative_to(root)))

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
