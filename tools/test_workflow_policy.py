#!/usr/bin/env python3
"""Negative and positive tests for the GitHub workflow policy."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from unittest import mock

from check_workflow_policy import (
    PolicyError,
    _run_tool,
    validate_ci_workflow_text,
    validate_image_workflow_text,
    validate_release_workflow_text,
    validate_workflow_text,
)


PINNED_CHECKOUT = "actions/checkout@" + "a" * 40
PINNED_CACHE = "Actions/Cache@" + "b" * 40


def release_matrix() -> str:
    return """
          - image: workstation-basic
            image_target: image-workstation-basic
            closure_target: closure-workstation-basic
            role: workstation
            bundle: basic
            repository: ghcr.io/stevenbuglione/private-vm/workstation-basic
          - image: workstation-office
            image_target: image-workstation-office
            closure_target: closure-workstation-office
            role: workstation
            bundle: office
            repository: ghcr.io/stevenbuglione/private-vm/workstation-office
          - image: workstation-development
            image_target: image-workstation-development
            closure_target: closure-workstation-development
            role: workstation
            bundle: development
            repository: ghcr.io/stevenbuglione/private-vm/workstation-development
          - image: downloader
            image_target: image-downloader
            closure_target: closure-downloader
            role: downloader
            bundle: ""
            repository: ghcr.io/stevenbuglione/private-vm/downloader
          - image: scanner
            image_target: image-scanner
            closure_target: closure-scanner
            role: scanner
            bundle: ""
            repository: ghcr.io/stevenbuglione/private-vm/scanner
          - image: exporter
            image_target: image-exporter
            closure_target: closure-exporter
            role: exporter
            bundle: ""
            repository: ghcr.io/stevenbuglione/private-vm/exporter"""


def release_workflow() -> str:
    root = Path(__file__).resolve().parents[1]
    return (root / ".github" / "workflows" / "release.yml").read_text()


def ci_workflow() -> str:
    root = Path(__file__).resolve().parents[1]
    return (root / ".github" / "workflows" / "ci.yml").read_text()


def ci_workflow() -> str:
    root = Path(__file__).resolve().parents[1]
    return (root / ".github" / "workflows" / "ci.yml").read_text()


def workflow(
    *, trigger: str = "pull_request:", permissions: str = "contents: read", step: str
) -> str:
    return f"""
name: fixture
on:
  {trigger}
permissions:
  {permissions}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      {step}
"""


class WorkflowPolicyTests(unittest.TestCase):
    def image_workflow(self) -> str:
        root = Path(__file__).resolve().parents[1]
        return (root / ".github" / "workflows" / "image-build.yml").read_text()

    def active_release_workflow(self) -> str:
        root = Path(__file__).resolve().parents[1]
        return (root / ".github" / "workflows" / "release.yml").read_text()

    def test_accepts_fork_safe_pinned_workflow(self) -> None:
        validate_workflow_text(
            workflow(
                step=f"- uses: {PINNED_CHECKOUT}\n        with:\n          persist-credentials: false"
            ),
            "safe.yml",
        )

    def test_rejects_mutable_action_tag(self) -> None:
        with self.assertRaisesRegex(PolicyError, "full 40-hex SHA"):
            validate_workflow_text(
                workflow(
                    step="- uses: actions/checkout@v6\n        with:\n          persist-credentials: false"
                ),
                "tag.yml",
            )

    def test_rejects_pull_request_target(self) -> None:
        with self.assertRaisesRegex(PolicyError, "pull_request_target"):
            validate_workflow_text(
                workflow(
                    trigger="pull_request_target:",
                    step=f"- uses: {PINNED_CHECKOUT}\n        with:\n          persist-credentials: false",
                ),
                "target.yml",
            )

    def test_rejects_checkout_credentials(self) -> None:
        with self.assertRaisesRegex(PolicyError, "persisted credentials"):
            validate_workflow_text(
                workflow(step=f"- uses: {PINNED_CHECKOUT}"),
                "credentials.yml",
            )

    def test_checkout_name_is_case_insensitive(self) -> None:
        reference = "Actions/Checkout@" + "a" * 40
        with self.assertRaisesRegex(PolicyError, "persisted credentials"):
            validate_workflow_text(
                workflow(step=f"- uses: {reference}"),
                "case.yml",
            )

    def test_rejects_job_level_mutable_reusable_workflow(self) -> None:
        source = workflow(step="- run: go test ./...").replace(
            "    runs-on: ubuntu-latest\n    steps:\n      - run: go test ./...",
            "    uses: evil/repo/.github/workflows/pwn.yml@main",
        )
        with self.assertRaisesRegex(PolicyError, "full 40-hex SHA"):
            validate_workflow_text(source, "reusable.yml")

    def test_rejects_local_action(self) -> None:
        with self.assertRaisesRegex(PolicyError, "local actions"):
            validate_workflow_text(
                workflow(step="- uses: ./.github/actions/unreviewed"),
                "local.yml",
            )

    def test_rejects_short_container_digest(self) -> None:
        with self.assertRaisesRegex(PolicyError, "complete sha256"):
            validate_workflow_text(
                workflow(step="- uses: docker://alpine@sha256:abc"),
                "docker.yml",
            )

    def test_rejects_explicit_cache_action(self) -> None:
        with self.assertRaisesRegex(PolicyError, "separately reviewed policy"):
            validate_workflow_text(
                workflow(
                    step=f"- uses: {PINNED_CACHE}\n"
                    "        with:\n"
                    "          key: runner.os-runner.arch-hashFiles(go.sum)\n"
                    "          path: harmless"
                ),
                "cache.yml",
            )

    def test_rejects_pull_request_write_permission(self) -> None:
        with self.assertRaisesRegex(PolicyError, "workflow permissions"):
            validate_workflow_text(
                workflow(
                    permissions="contents: write",
                    step="- run: go test ./...",
                ),
                "write.yml",
            )

    def test_rejects_pull_request_oidc_permission(self) -> None:
        source = workflow(step="- run: go test ./...").replace(
            "    runs-on: ubuntu-latest",
            "    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n      id-token: write",
        )
        with self.assertRaisesRegex(PolicyError, "write permissions"):
            validate_workflow_text(source, "oidc.yml")

    def test_rejects_bracketed_pull_request_secret(self) -> None:
        source = workflow(step="- run: echo ${{ secrets['TOKEN'] }}")
        with self.assertRaisesRegex(PolicyError, "must not reference secrets"):
            validate_workflow_text(source, "secret.yml")

    def test_rejects_workflow_level_pull_request_secret(self) -> None:
        source = workflow(step="- run: go test ./...").replace(
            "permissions:\n  contents: read",
            "env:\n  TOKEN: ${{ secrets['TOKEN'] }}\npermissions:\n  contents: read",
        )
        with self.assertRaisesRegex(PolicyError, "must not reference secrets"):
            validate_workflow_text(source, "workflow-secret.yml")

    def test_rejects_extra_protected_write_scope(self) -> None:
        source = """
name: fixture
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  release:
    runs-on: ubuntu-latest
    environment: release
    permissions:
      contents: write
      packages: write
      id-token: write
      attestations: write
      issues: write
    steps:
      - run: true
"""
        with self.assertRaisesRegex(PolicyError, "protected release permissions"):
            validate_workflow_text(source, "scope.yml")

    def test_rejects_broad_release_tag_filter(self) -> None:
        source = """
name: fixture
on:
  push:
    tags: ["*"]
permissions:
  contents: read
jobs:
  release:
    runs-on: ubuntu-latest
    environment: release
    permissions:
      contents: write
      packages: write
      id-token: write
      attestations: write
    steps:
      - run: true
"""
        with self.assertRaisesRegex(PolicyError, "write permissions"):
            validate_workflow_text(source, "broad-tag.yml")

    def test_rejects_publish_condition_with_bypass(self) -> None:
        source = workflow(step="- run: go test ./...").replace(
            "    runs-on: ubuntu-latest",
            "    runs-on: ubuntu-latest\n"
            "    environment: release\n"
            "    if: github.event_name == 'push' && github.ref == 'refs/heads/main' || success()\n"
            "    permissions:\n"
            "      contents: write",
        )
        with self.assertRaisesRegex(PolicyError, "write permissions"):
            validate_workflow_text(source, "condition.yml")

    @mock.patch("check_workflow_policy.subprocess.run")
    def test_tool_timeout_is_bounded(self, run: mock.Mock) -> None:
        run.side_effect = subprocess.TimeoutExpired("actionlint", 60)
        with self.assertRaisesRegex(PolicyError, "timed out"):
            _run_tool(["actionlint", "workflow.yml"], timeout=60)

    @mock.patch("check_workflow_policy.subprocess.run")
    def test_cancellation_propagates(self, run: mock.Mock) -> None:
        run.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            _run_tool(["actionlint", "workflow.yml"], timeout=60)

    def test_accepts_official_build_only_image_matrix(self) -> None:
        validate_image_workflow_text(self.image_workflow())

    def test_accepts_combined_non_image_nix_build(self) -> None:
        validate_ci_workflow_text(ci_workflow())

    def test_ci_rejects_serial_non_image_nix_builds(self) -> None:
        source = ci_workflow().replace(
            "          nix build \\\n"
            "            .#checks.x86_64-linux.runtime-fuzz \\\n"
            "            .#checks.x86_64-linux.host-module-contract \\\n"
            "            .#checks.x86_64-linux.static-binaries \\\n"
            "            --no-link \\\n"
            "            --print-build-logs",
            "          nix build .#checks.x86_64-linux.runtime-fuzz --no-link --print-build-logs\n"
            "          nix build .#checks.x86_64-linux.host-module-contract --no-link --print-build-logs\n"
            "          nix build .#checks.x86_64-linux.static-binaries --no-link --print-build-logs",
            1,
        )
        self.assertNotEqual(source, ci_workflow())
        with self.assertRaisesRegex(PolicyError, "one combined nix build"):
            validate_ci_workflow_text(source)

    def test_image_matrix_rejects_duplicate_role(self) -> None:
        source = self.image_workflow().replace(
            "- image: exporter", "- image: scanner", 1
        )
        with self.assertRaisesRegex(PolicyError, "duplicate image matrix entry"):
            validate_image_workflow_text(source)

    def test_image_workflow_rejects_publication(self) -> None:
        source = self.image_workflow().replace(
            "permissions:\n  contents: read",
            "permissions:\n  contents: read\n  packages: write",
            1,
        )
        with self.assertRaisesRegex(PolicyError, "must not publish artifacts"):
            validate_image_workflow_text(source)

    def test_image_workflow_rejects_nonstandard_runner(self) -> None:
        source = self.image_workflow().replace("ubuntu-24.04", "self-hosted", 1)
        with self.assertRaisesRegex(PolicyError, "standard ubuntu-24.04"):
            validate_image_workflow_text(source)

    def test_image_workflow_requires_no_link_builds(self) -> None:
        source = self.image_workflow().replace(" --no-link", "", 1)
        with self.assertRaisesRegex(PolicyError, "canonical image build step"):
            validate_image_workflow_text(source)

    def test_image_workflow_rejects_canonical_output_path_drift(self) -> None:
        base = self.image_workflow()
        for description, source, message in (
            (
                "missing exact output emission",
                base.replace("              --print-out-paths", "", 1),
                "canonical image build step",
            ),
            (
                "missing ambiguity rejection",
                base.replace(
                    " || \"$image_output_path\" == *$'\\n'*",
                    "",
                    1,
                ),
                "canonical image build step",
            ),
            (
                "closure expression bypass",
                base.replace(
                    "${{ steps.canonical_image.outputs.image_output_path }}",
                    "${{ matrix.image_target }}",
                    1,
                ),
                "closure report",
            ),
            (
                "closure reevaluates flake",
                base.replace(
                    'nix path-info -Sh "$PVM_IMAGE_OUTPUT_PATH"',
                    'nix path-info -Sh ".#${{ matrix.image_target }}"',
                    1,
                ),
                "closure report",
            ),
        ):
            with self.subTest(description=description):
                self.assertNotEqual(source, base)
                with self.assertRaisesRegex(PolicyError, message):
                    validate_image_workflow_text(source)

    def test_accepts_official_tag_only_release_matrix(self) -> None:
        source = release_workflow()
        validate_workflow_text(source, "release.yml")
        validate_release_workflow_text(source, "release.yml")

    def test_accepts_active_release_workflow(self) -> None:
        source = self.active_release_workflow()
        validate_workflow_text(source, ".github/workflows/release.yml")
        validate_release_workflow_text(source, ".github/workflows/release.yml")

    def test_generic_policy_rejects_image_publish_in_another_workflow(self) -> None:
        with self.assertRaisesRegex(PolicyError, "only in release.yml"):
            validate_workflow_text(release_workflow(), "shadow-release.yml")

    def test_release_rejects_non_tag_trigger(self) -> None:
        source = release_workflow().replace(
            '  push:\n    tags: ["v*"]', "  push:\n    branches: [main]", 1
        )
        with self.assertRaisesRegex(PolicyError, "trigger must be exactly tags"):
            validate_release_workflow_text(source)

    def test_release_rejects_changed_or_duplicate_matrix(self) -> None:
        for description, source in (
            (
                "changed repository",
                release_workflow().replace(
                    "private-vm/workstation-basic",
                    "private-vm/workstation-basic-copy",
                    1,
                ),
            ),
            (
                "duplicate image",
                release_workflow().replace("- image: exporter", "- image: scanner", 1),
            ),
            (
                "extra field",
                release_workflow().replace(
                    "            image_target: image-exporter",
                    "            image_target: image-exporter\n            mutable_tag: latest",
                    1,
                ),
            ),
        ):
            with self.subTest(description=description):
                with self.assertRaises(PolicyError):
                    validate_release_workflow_text(source)

    def test_release_rejects_wrong_runner_environment_or_permissions(self) -> None:
        for description, source, message in (
            (
                "runner",
                release_workflow().replace("ubuntu-24.04", "self-hosted", 1),
                "standard ubuntu-24.04",
            ),
            (
                "environment",
                release_workflow().replace("image-publish", "release", 1),
                "image-publish environment",
            ),
            (
                "permission",
                release_workflow().replace("      packages: write\n", "", 1),
                "permissions",
            ),
        ):
            with self.subTest(description=description):
                with self.assertRaisesRegex(PolicyError, message):
                    validate_release_workflow_text(source)

    def test_release_rejects_action_or_attestation_drift(self) -> None:
        for description, source, message in (
            (
                "mutable attest action",
                release_workflow().replace(
                    "actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
                    "actions/attest@v4",
                    1,
                ),
                "full 40-hex SHA",
            ),
            (
                "wrapper action",
                release_workflow().replace("actions/attest@", "actions/attest-build-provenance@", 1),
                "action set",
            ),
            (
                "wrong subject",
                release_workflow().replace("subject-name: image.qcow2.zst", "subject-name: image.qcow2", 1),
                "exact compressed-image subject",
            ),
            (
                "shallow release checkout",
                release_workflow().replace("          fetch-depth: 0", "          fetch-depth: 1", 1),
                "fetch full history",
            ),
            (
                "default predicate",
                release_workflow().replace(
                    "          predicate-type: https://slsa.dev/provenance/v1\n"
                    "          predicate-path: ${{ steps.prepare.outputs.predicate_path }}\n",
                    "",
                    1,
                ),
                "exact compressed-image subject",
            ),
            (
                "missing bundle",
                release_workflow().replace("${{ steps.attest.outputs.bundle-path }}", "prepared/provenance.json", 1),
                "bundle-path",
            ),
        ):
            with self.subTest(description=description):
                with self.assertRaisesRegex(PolicyError, message):
                    validate_release_workflow_text(source)

    def test_release_rejects_toolchain_cache_or_secret_drift(self) -> None:
        for description, source, message in (
            (
                "Go version",
                release_workflow().replace('go-version: "1.26.5"', 'go-version: "1.27.0"', 1),
                "Go 1.26.5",
            ),
            (
                "Go cache",
                release_workflow().replace("          cache: false", "          cache: true", 1),
                "Go cache",
            ),
            (
                "secret fallback",
                release_workflow().replace(
                    "set +x",
                    "set +x\n          printf '%s' '${{ secrets.GHCR_TOKEN }}' >/dev/null",
                    1,
                ),
                "ephemeral GitHub token",
            ),
        ):
            with self.subTest(description=description):
                with self.assertRaisesRegex(PolicyError, message):
                    validate_release_workflow_text(source)

    def test_release_rejects_non_stdin_or_environment_credentials(self) -> None:
        for description, source in (
            (
                "token argument",
                release_workflow().replace(
                    "printf '%s' '${{ github.token }}' | private-vm-image-release publish",
                    "private-vm-image-release publish --token '${{ github.token }}'",
                    1,
                ),
            ),
            (
                "token environment",
                release_workflow().replace(
                    "        run: |\n          set +x",
                    "        env:\n          TOKEN: ${{ github.token }}\n        run: |\n          set +x",
                    1,
                ),
            ),
            (
                "tracing",
                release_workflow().replace("          set +x\n", "", 1),
            ),
        ):
            with self.subTest(description=description):
                with self.assertRaises(PolicyError):
                    validate_release_workflow_text(source)

    def test_release_rejects_non_anonymous_or_same_job_verification(self) -> None:
        for description, source, message in (
            (
                "missing dependency",
                release_workflow().replace("    needs: publish\n", "", 1),
                "separate fresh job",
            ),
            (
                "verify environment",
                release_workflow().replace(
                    "  verify:\n    needs: publish",
                    "  verify:\n    needs: publish\n    environment: image-publish",
                    1,
                ),
                "separate fresh job",
            ),
            (
                "authenticated fallback",
                release_workflow().replace(
                    "private-vm-image-release verify-anonymous",
                    "private-vm-image-release verify-anonymous --credential fallback",
                    1,
                ),
                "authentication fallback",
            ),
            (
                "ignored failure",
                release_workflow().replace(
                    '--bundle \'${{ matrix.bundle }}\' --timeout 30m',
                    '--bundle \'${{ matrix.bundle }}\' --timeout 30m || true',
                    1,
                ),
                "fail closed",
            ),
        ):
            with self.subTest(description=description):
                with self.assertRaisesRegex(PolicyError, message):
                    validate_release_workflow_text(source)

    def test_release_rejects_artifact_cache_docker_and_mutable_tags(self) -> None:
        base = release_workflow()
        for description, source in (
            (
                "artifact",
                base.replace(
                    "      - name: Prepare exact image release",
                    "      - uses: actions/upload-artifact@" + "a" * 40 + "\n"
                    "      - name: Prepare exact image release",
                    1,
                ),
            ),
            (
                "cache",
                base.replace(
                    "      - name: Prepare exact image release",
                    "      - uses: actions/cache@" + "a" * 40 + "\n"
                    "      - name: Prepare exact image release",
                    1,
                ),
            ),
            (
                "docker",
                base.replace(
                    "      - name: Prepare exact image release",
                    "      - uses: docker/login-action@" + "a" * 40 + "\n"
                    "      - name: Prepare exact image release",
                    1,
                ),
            ),
            (
                "mutable tag",
                base.replace(
                    "--token-stdin", "--tag latest --token-stdin", 1
                ),
            ),
        ):
            with self.subTest(description=description):
                with self.assertRaises(PolicyError):
                    validate_release_workflow_text(source)


if __name__ == "__main__":
    unittest.main()
