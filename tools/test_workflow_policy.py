#!/usr/bin/env python3
"""Negative and positive tests for the GitHub workflow policy."""

from __future__ import annotations

import subprocess
import unittest
from unittest import mock

from check_workflow_policy import PolicyError, _run_tool, validate_workflow_text


PINNED_CHECKOUT = "actions/checkout@" + "a" * 40
PINNED_CACHE = "Actions/Cache@" + "b" * 40


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


if __name__ == "__main__":
    unittest.main()
