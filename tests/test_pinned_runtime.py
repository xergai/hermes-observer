"""Synthetic preflight tests; no imported Hermes runtime or provider calls."""

import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


def load(name, filename):
    path = Path(__file__).resolve().parents[3] / "scripts/acceptance" / filename
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PinnedRuntimeTest(unittest.TestCase):
    def test_exact_clean_source_and_disposable_marker_are_required(self):
        runtime = load("hermes_pinned_runtime", "hermes_pinned_runtime.py")
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            with self.assertRaises(SystemExit):
                runtime.verify_disposable_home(home)
            (home / ".xerg-disposable").touch()
            self.assertEqual(runtime.verify_disposable_home(home), home)
            with patch.dict(os.environ, {"HERMES_SOURCE_DIR": directory, "HERMES_EXPECTED_VERSION": "0.21.0"}):
                with patch.object(runtime.subprocess, "check_output", side_effect=[runtime.PINS["0.21.0"], ""]):
                    self.assertEqual(runtime.verify_source(), (home, "0.21.0", runtime.PINS["0.21.0"]))
                for responses in [["different", ""], [runtime.PINS["0.21.0"], " M run_agent.py"]]:
                    with patch.object(runtime.subprocess, "check_output", side_effect=responses), self.assertRaises(SystemExit):
                        runtime.verify_source()

    def test_budget_acknowledgment_does_not_default_to_approval(self):
        runtime = load("hermes_pinned_runtime", "hermes_pinned_runtime.py")
        for value in ["", "0", "-1", "nan", "inf"]:
            with patch.dict(os.environ, {"HERMES_ACCEPTANCE_APPROVED_BUDGET_USD": value}), self.assertRaises(SystemExit):
                runtime.verify_live_budget()
        with patch.dict(os.environ, {"HERMES_ACCEPTANCE_APPROVED_BUDGET_USD": "1.25"}):
            self.assertEqual(runtime.verify_live_budget(), 1.25)

    def test_cli_uses_declared_pinned_entrypoint_and_disposable_working_directory(self):
        runtime = load("hermes_pinned_runtime", "hermes_pinned_runtime.py")
        with patch.dict(sys.modules, {"hermes_pinned_runtime": runtime}):
            cli = load("hermes_pinned_cli", "hermes-pinned-cli.py")
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve()
            source = home / "source"
            source.mkdir()
            (source / "pyproject.toml").write_text('[project]\nversion="0.21.0"\n[project.scripts]\nhermes="hermes_cli.main:main"\n')
            module = types.SimpleNamespace(__file__=str(source / "hermes_cli/main.py"), main=lambda: 19)
            with patch.dict(os.environ, {"HERMES_HOME": str(home), "HOME": str(home)}), \
                    patch.object(cli, "verify_live_budget", return_value=1), \
                    patch.object(cli, "verify_source", return_value=(source, "0.21.0", runtime.PINS["0.21.0"])), \
                    patch.object(cli, "verify_disposable_home", return_value=home), \
                    patch.object(cli.importlib, "import_module", return_value=module), \
                    patch.object(cli.os, "chdir") as chdir, patch.object(sys, "path", list(sys.path)), patch.object(sys, "argv", ["test", "--version"]):
                self.assertEqual(cli.main(), 19)
                chdir.assert_called_with(home)
                self.assertEqual(sys.path[0], str(source))
                module.__file__ = str(home / "different/main.py")
                with self.assertRaises(SystemExit):
                    cli.main()


class RetryScalarDiagnosticTest(unittest.TestCase):
    def setUp(self):
        runtime = load("hermes_pinned_runtime", "hermes_pinned_runtime.py")
        with patch.dict(sys.modules, {"hermes_pinned_runtime": runtime}):
            self.diagnostic = load("hermes_retry_diagnostic", "hermes-request-retry-diagnostic.py")
        self.ids = {}

    def hook(self, ordinal, hook, **fields):
        values = {"api_request_id": "PRIVATE_REQUEST_CANARY", "api_call_count": 1, **fields}
        return {"ordinal": ordinal, "hook": hook, "fields": {
            key: self.diagnostic.scalar_field(values, key, self.ids)
            for key in self.diagnostic.HOOK_FIELDS
        }}

    def test_duplicate_delivered_scalars_do_not_establish_a_unique_attempt(self):
        hooks = [
            self.hook(1, "pre_api_request", started_at=100.25, retry_count=0),
            self.hook(2, "pre_api_request", started_at=100.25, retry_count=0),
            self.hook(3, "post_api_request", started_at=100.25, ended_at=102, finish_reason="stop"),
        ]
        result = self.diagnostic.analyze_hook_joins(hooks)
        self.assertEqual(result["deliveredErrorHooks"], 0)
        self.assertTrue(result["sameAnonymousRequestId"])
        completion = result["completions"][0]
        self.assertEqual(completion["startedAtMatchCount"], 2)
        self.assertEqual(completion["matchingStartHookOrdinals"], [1, 2])
        self.assertTrue(completion["matchesLastPreStartedAt"])
        self.assertFalse(completion["uniqueExactStartedAtJoin"])

    def test_only_exact_unique_equality_matches_not_proximity_or_latest_start(self):
        starts = [
            self.hook(1, "pre_api_request", started_at=100, retry_count=0),
            self.hook(2, "pre_api_request", started_at=101, retry_count=0),
        ]
        for value, count, ordinals in [(100, 1, [1]), (101, 1, [2]), (101.01, 0, []), (None, 0, [])]:
            with self.subTest(started_at=value):
                hooks = [*starts, self.hook(3, "post_api_request", started_at=value, ended_at=102)]
                completion = self.diagnostic.analyze_hook_joins(hooks)["completions"][0]
                self.assertEqual(completion["startedAtMatchCount"], count)
                self.assertEqual(completion["matchingStartHookOrdinals"], ordinals)
                self.assertEqual(completion["uniqueExactStartedAtJoin"], count == 1)

    def test_scalar_projection_preserves_absence_and_excludes_content_and_native_ids(self):
        event = self.hook(1, "pre_api_request", retry_count=0, started_at=float("nan"),
                          finish_reason="PRIVATE_RESPONSE_CANARY", prompt="PRIVATE_PROMPT_CANARY")
        fields = event["fields"]
        self.assertEqual(fields["ended_at"], {"present": False})
        self.assertEqual(fields["retry_count"], {"present": True, "kind": "number", "value": 0})
        self.assertEqual(fields["started_at"], {"present": True, "kind": "non-numeric"})
        self.assertEqual(fields["finish_reason"], {"present": True, "kind": "enum", "value": "other"})
        self.assertEqual(fields["api_request_id"], {"present": True, "kind": "anonymous-id", "ordinal": 1})
        self.assertNotIn("PRIVATE_", json.dumps(event))
        for value in [False, True, float("inf"), {}, "100"]:
            self.assertEqual(self.diagnostic.scalar_field({"started_at": value}, "started_at", {}),
                             {"present": True, "kind": "non-numeric"})

    def test_rejected_retry_retains_the_error_without_inventing_a_completion(self):
        hooks = [
            self.hook(1, "pre_api_request", started_at=100, retry_count=0),
            self.hook(2, "pre_api_request", started_at=100, retry_count=0),
            self.hook(3, "api_request_error", started_at=100, ended_at=102, retry_count=0),
        ]
        result = self.diagnostic.analyze_hook_joins(hooks)
        self.assertEqual(result["deliveredErrorHooks"], 1)
        self.assertEqual(result["completions"], [])
        self.assertTrue(result["sameAnonymousRequestId"])
