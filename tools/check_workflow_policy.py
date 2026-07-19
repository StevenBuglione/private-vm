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
PINNED_RELEASE_PUBLISH_ACTIONS = [
    "actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10",
    "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16",
    "DeterminateSystems/nix-installer-action@ef8a148080ab6020fd15196c2084a2eea5ff2d25",
    "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
]
PINNED_RELEASE_VERIFY_ACTIONS = PINNED_RELEASE_PUBLISH_ACTIONS[:2]
RELEASE_PUBLISH_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "write",
    "attestations": "write",
}
SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
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
RELEASE_IMAGE_MATRIX = {
    "workstation-basic": {
        "image_target": "image-workstation-basic",
        "closure_target": "closure-workstation-basic",
        "role": "workstation",
        "bundle": "basic",
        "repository": "ghcr.io/stevenbuglione/private-vm/workstation-basic",
    },
    "workstation-office": {
        "image_target": "image-workstation-office",
        "closure_target": "closure-workstation-office",
        "role": "workstation",
        "bundle": "office",
        "repository": "ghcr.io/stevenbuglione/private-vm/workstation-office",
    },
    "workstation-development": {
        "image_target": "image-workstation-development",
        "closure_target": "closure-workstation-development",
        "role": "workstation",
        "bundle": "development",
        "repository": "ghcr.io/stevenbuglione/private-vm/workstation-development",
    },
    "downloader": {
        "image_target": "image-downloader",
        "closure_target": "closure-downloader",
        "role": "downloader",
        "bundle": "",
        "repository": "ghcr.io/stevenbuglione/private-vm/downloader",
    },
    "scanner": {
        "image_target": "image-scanner",
        "closure_target": "closure-scanner",
        "role": "scanner",
        "bundle": "",
        "repository": "ghcr.io/stevenbuglione/private-vm/scanner",
    },
    "exporter": {
        "image_target": "image-exporter",
        "closure_target": "closure-exporter",
        "role": "exporter",
        "bundle": "",
        "repository": "ghcr.io/stevenbuglione/private-vm/exporter",
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
    if environment == "image-publish" and set(triggers) == {"push"}:
        push = triggers.get("push")
        if (
            isinstance(push, dict)
            and set(push) == {"tags"}
            and push.get("tags") == ["v*"]
        ):
            return "image"
    return None


def _validate_protected_permissions(
    permissions: dict[str, str], kind: str, location: str
) -> None:
    expected = (
        {
            "contents": "write",
            "packages": "write",
            "id-token": "write",
            "attestations": "write",
        }
        if kind == "release"
        else RELEASE_PUBLISH_PERMISSIONS
    )
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
            if protected_kind == "image" and Path(name).name != "release.yml":
                raise PolicyError(
                    f"{location}: image publication is permitted only in release.yml"
                )
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


def _validate_release_matrix(job: dict[str, Any], name: str, job_name: str) -> None:
    location = f"{name}.jobs.{job_name}.strategy"
    strategy = _mapping(job.get("strategy"), location)
    if set(strategy) != {"fail-fast", "matrix"}:
        raise PolicyError(
            f"{location}: release strategy fields must be exactly fail-fast and matrix"
        )
    if _is_true(strategy.get("fail-fast", "true")):
        raise PolicyError(
            f"{name}: one release image failure must not cancel independent rows"
        )
    matrix = _mapping(strategy.get("matrix"), f"{location}.matrix")
    if set(matrix) != {"include"} or not isinstance(matrix.get("include"), list):
        raise PolicyError(f"{name}: release matrix must contain only an include list")

    required_fields = {
        "image",
        "image_target",
        "closure_target",
        "role",
        "bundle",
        "repository",
    }
    actual: dict[str, dict[str, str]] = {}
    for index, raw_entry in enumerate(matrix["include"]):
        entry = _mapping(raw_entry, f"{location}.matrix.include[{index}]")
        if set(entry) != required_fields:
            raise PolicyError(
                f"{name}: release matrix fields must be exactly {sorted(required_fields)}"
            )
        image = str(entry["image"])
        if image in actual:
            raise PolicyError(f"{name}: duplicate release image matrix entry: {image}")
        actual[image] = {
            field: str(entry[field]) for field in required_fields if field != "image"
        }
    if actual != RELEASE_IMAGE_MATRIX:
        raise PolicyError(f"{name}: release matrix does not match the six official images")


def _bounded_release_timeout(
    job: dict[str, Any], name: str, job_name: str, maximum: int
) -> None:
    try:
        timeout = int(str(job.get("timeout-minutes", "")))
    except ValueError as error:
        raise PolicyError(
            f"{name}: {job_name} timeout must be a bounded integer"
        ) from error
    if timeout < 1 or timeout > maximum:
        raise PolicyError(
            f"{name}: {job_name} timeout must be between 1 and {maximum} minutes"
        )


def _release_steps(job: dict[str, Any], name: str, job_name: str) -> list[dict[str, Any]]:
    raw_steps = job.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise PolicyError(f"{name}.jobs.{job_name}.steps: expected a non-empty list")
    steps: list[dict[str, Any]] = []
    for index, raw_step in enumerate(raw_steps):
        location = f"{name}.jobs.{job_name}.steps[{index}]"
        step = _mapping(raw_step, location)
        _validate_action(step, location)
        steps.append(step)
    return steps


def _release_action_set(
    steps: list[dict[str, Any]], expected: list[str], name: str, job_name: str
) -> None:
    actual = [str(step["uses"]) for step in steps if "uses" in step]
    if actual != expected:
        raise PolicyError(
            f"{name}: {job_name} action set and order do not match the reviewed pins"
        )


def _validate_release_setup_go(
    steps: list[dict[str, Any]], name: str, job_name: str
) -> None:
    setup = [
        step
        for step in steps
        if str(step.get("uses", "")).startswith("actions/setup-go@")
    ]
    if len(setup) != 1 or _mapping(
        setup[0].get("with"), f"{name}.jobs.{job_name}.setup-go.with"
    ) != {"go-version": "1.26.5", "cache": "false"}:
        raise PolicyError(
            f"{name}: {job_name} must use Go 1.26.5 with the action cache disabled"
        )


def _validate_release_checkout_history(
    steps: list[dict[str, Any]], name: str
) -> None:
    checkouts = [
        step
        for step in steps
        if str(step.get("uses", "")).startswith("actions/checkout@")
    ]
    if len(checkouts) != 1 or _mapping(
        checkouts[0].get("with"), f"{name}.jobs.publish.checkout.with"
    ) != {"persist-credentials": "false", "fetch-depth": "0"}:
        raise PolicyError(
            f"{name}: publish checkout must fetch full history without persisted credentials"
        )


def _step_runs(steps: list[dict[str, Any]], command: str) -> list[tuple[int, str]]:
    return [
        (index, str(step.get("run", "")))
        for index, step in enumerate(steps)
        if command in str(step.get("run", ""))
    ]


def _validate_release_attestation(
    steps: list[dict[str, Any]], name: str
) -> int:
    prepare = _step_runs(steps, "private-vm-image-release prepare")
    publish = _step_runs(steps, "private-vm-image-release publish")
    attest = [
        (index, step)
        for index, step in enumerate(steps)
        if str(step.get("uses", "")).startswith("actions/attest@")
    ]
    if len(prepare) != 1 or len(attest) != 1 or len(publish) != 1:
        raise PolicyError(
            f"{name}: publish must contain one prepare, attest and publish operation"
        )
    prepare_index, _ = prepare[0]
    attest_index, attest_step = attest[0]
    publish_index, publish_run = publish[0]
    for index in (prepare_index, attest_index, publish_index):
        if "if" in steps[index] or "continue-on-error" in steps[index]:
            raise PolicyError(
                f"{name}: prepare, attest and publish steps must fail closed"
            )
    if not prepare_index < attest_index < publish_index:
        raise PolicyError(f"{name}: release preparation, attestation and publication are out of order")
    if str(attest_step.get("id", "")) != "attest":
        raise PolicyError(f"{name}: attestation step id must be exactly attest")

    settings = _mapping(attest_step.get("with"), f"{name}.jobs.publish.attest.with")
    expected = {
        "subject-name": "image.qcow2.zst",
        "subject-digest": "${{ steps.prepare.outputs.subject_digest }}",
        "predicate-type": SLSA_PROVENANCE_V1,
        "predicate-path": "${{ steps.prepare.outputs.predicate_path }}",
    }
    if settings != expected:
        raise PolicyError(
            f"{name}: attestation inputs must use the exact compressed-image subject and custom SLSA predicate"
        )
    if "${{ steps.attest.outputs.bundle-path }}" not in publish_run:
        raise PolicyError(
            f"{name}: publish must consume the bounded local attestation bundle-path"
        )
    return publish_index


def _validate_stdin_publish_token(
    source: str, steps: list[dict[str, Any]], publish_index: int, name: str
) -> None:
    token = "${{ github.token }}"
    if source.count(token) != 1 or re.search(
        r"\$\{\{\s*secrets(?:\.|\[)|\b(?:GITHUB_TOKEN|GH_TOKEN|CR_PAT)\b",
        source,
        flags=re.IGNORECASE,
    ):
        raise PolicyError(
            f"{name}: the ephemeral GitHub token must appear exactly once in the publish pipe"
        )
    for step in steps:
        environment = step.get("env")
        if environment is not None and token in str(environment):
            raise PolicyError(f"{name}: registry credentials must not enter the environment")

    run = str(steps[publish_index].get("run", ""))
    lines = [line.strip() for line in run.splitlines() if line.strip()]
    token_lines = [line for line in lines if token in line]
    if "set +x" not in lines or len(token_lines) != 1:
        raise PolicyError(
            f"{name}: publish must disable tracing and use one direct non-logging token pipe"
        )
    token_line = token_lines[0]
    direct_pipe = re.compile(
        r"^printf '%s' '\$\{\{ github\.token \}\}' \| "
        r"(?:\./)?private-vm-image-release publish\b.*\s--token-stdin(?:\s|$)"
    )
    if not direct_pipe.fullmatch(token_line):
        raise PolicyError(
            f"{name}: publish credential handoff must be the exact printf-to---token-stdin pipe"
        )


def validate_release_workflow_text(source: str, name: str = "release.yml") -> None:
    """Validate the active REL-003 tag-only image publication workflow."""
    if len(source.encode()) > MAX_WORKFLOW_BYTES:
        raise PolicyError(f"{name}: workflow exceeds {MAX_WORKFLOW_BYTES} bytes")
    try:
        document = yaml.load(source, Loader=yaml.BaseLoader)
    except yaml.YAMLError as error:
        raise PolicyError(f"{name}: invalid YAML: {error}") from error
    document = _mapping(document, name)
    if document.get("name") != "Release":
        raise PolicyError(f"{name}: workflow name must be exactly Release")

    triggers = _triggers(document)
    if set(triggers) != {"push"}:
        raise PolicyError(f"{name}: release images must run only for tag pushes")
    push = _mapping(triggers["push"], f"{name}.on.push")
    if set(push) != {"tags"} or push.get("tags") != ["v*"]:
        raise PolicyError(f"{name}: release trigger must be exactly tags v*")
    if _permissions(document.get("permissions"), f"{name}.permissions") != {
        "contents": "read"
    }:
        raise PolicyError(f"{name}: workflow permissions must be exactly contents: read")

    jobs = _mapping(document.get("jobs"), f"{name}.jobs")
    if set(jobs) != {"publish", "verify"}:
        raise PolicyError(f"{name}: REL-003 permits only publish and verify jobs")
    publish = _mapping(jobs["publish"], f"{name}.jobs.publish")
    verify = _mapping(jobs["verify"], f"{name}.jobs.verify")

    for job_name, job, maximum_timeout in (
        ("publish", publish, 180),
        ("verify", verify, 60),
    ):
        if job.get("runs-on") != "ubuntu-24.04":
            raise PolicyError(
                f"{name}: {job_name} must use the standard ubuntu-24.04 public runner"
            )
        _bounded_release_timeout(job, name, job_name, maximum_timeout)
        _validate_release_matrix(job, name, job_name)
        if "if" in job:
            raise PolicyError(f"{name}: {job_name} must not override normal success gating")
        for prohibited_key in ("container", "secrets", "services"):
            if prohibited_key in job:
                raise PolicyError(f"{name}: {job_name} must not set {prohibited_key}")

    if publish.get("environment") != "image-publish" or "needs" in publish:
        raise PolicyError(
            f"{name}: publish must be isolated in only the image-publish environment"
        )
    if _permissions(
        publish.get("permissions"), f"{name}.jobs.publish.permissions"
    ) != RELEASE_PUBLISH_PERMISSIONS:
        raise PolicyError(f"{name}: publish permissions do not match the exact reviewed set")
    publish_environment = _mapping(publish.get("env"), f"{name}.jobs.publish.env")
    nix_config = str(publish_environment.get("NIX_CONFIG", ""))
    if set(publish_environment) != {"NIX_CONFIG"} or "max-jobs = 1" not in nix_config or "cores = 2" not in nix_config:
        raise PolicyError(f"{name}: publish must use only the reviewed serialized Nix limits")

    if verify.get("needs") != "publish" or "environment" in verify or "env" in verify:
        raise PolicyError(
            f"{name}: anonymous verification must be a separate fresh job after publish"
        )
    if _permissions(verify.get("permissions"), f"{name}.jobs.verify.permissions") != {
        "contents": "read"
    }:
        raise PolicyError(f"{name}: anonymous verification must have only contents: read")

    publish_steps = _release_steps(publish, name, "publish")
    verify_steps = _release_steps(verify, name, "verify")
    _release_action_set(
        publish_steps, PINNED_RELEASE_PUBLISH_ACTIONS, name, "publish"
    )
    _release_action_set(verify_steps, PINNED_RELEASE_VERIFY_ACTIONS, name, "verify")
    _validate_release_setup_go(publish_steps, name, "publish")
    _validate_release_setup_go(verify_steps, name, "verify")
    _validate_release_checkout_history(publish_steps, name)
    publish_index = _validate_release_attestation(publish_steps, name)
    _validate_stdin_publish_token(source, publish_steps, publish_index, name)

    anonymous = _step_runs(verify_steps, "private-vm-image-release verify-anonymous")
    if len(anonymous) != 1:
        raise PolicyError(
            f"{name}: verify must contain exactly one anonymous full-verification operation"
        )
    anonymous_index, anonymous_run = anonymous[0]
    if (
        "if" in verify_steps[anonymous_index]
        or "continue-on-error" in verify_steps[anonymous_index]
        or not re.match(
            r"^\s*(?:\./)?private-vm-image-release verify-anonymous(?:\s|$)",
            anonymous_run,
        )
        or re.search(r"(?:\|\||&&|[|;>])", anonymous_run)
    ):
        raise PolicyError(f"{name}: anonymous verification must execute once and fail closed")
    verify_text = "\n".join(
        str(step.get("run", "")) + "\n" + str(step.get("env", ""))
        for step in verify_steps
    ).lower()
    if re.search(
        r"(secrets|github\.token|authorization|credential|password|token|login|"
        r"\bcurl\b|\bwget\b|\bgh\b|\boras\b|"
        r"packages\s*:\s*(?:read|write)|id-token|attestations)",
        verify_text,
    ):
        raise PolicyError(f"{name}: anonymous verification contains an authentication fallback")

    prohibited = re.compile(
        r"(actions/(?:upload|download)-artifact|actions/cache|cache\s*:\s*true|"
        r"docker/|docker://|\bdocker\b|\bpodman\b|\bskopeo\b|"
        r"\boras\s+login\b|\bgh\s+(?:auth|release)\b|--password(?!-stdin)|"
        r"--token(?:[=\s])(?!stdin)|--tag\s+(?:latest|rc)\b|"
        r":(?:latest|rc)\b|\$\{\{\s*secrets(?:\.|\[)|"
        r"\b(?:GITHUB_TOKEN|GH_TOKEN|CR_PAT)\b)",
        flags=re.IGNORECASE,
    )
    if prohibited.search(source):
        raise PolicyError(
            f"{name}: release workflow contains artifact, cache, Docker, mutable-tag or authentication fallback behavior"
        )


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
        if path.name == "release.yml":
            validate_release_workflow_text(source, relative_name)

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
