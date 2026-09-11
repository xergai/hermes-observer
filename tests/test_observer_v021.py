"""Contract regressions, not credentialed Hermes certification."""

import importlib.util
import json
import queue
import sys
import tempfile
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from test_observer import load_plugin


class Context:
    def __init__(self):
        self.hooks = {}
        self.unload = None

    def register_hook(self, name, callback):
        self.hooks[name] = callback

    def on_unload(self, callback):
        self.unload = callback


class ObserverV021Test(unittest.TestCase):
    def test_native_api_times_are_additive_content_free_scalars_not_writer_times(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            plugin = load_plugin(home, "0.21.0")
            context = Context()
            plugin.register(context)
            shared = {"session_id": "s", "api_request_id": "r", "api_call_count": 1,
                      "started_at": 1789055075.2960255, "retry_count": 0}
            self.assertIsNone(context.hooks["pre_api_request"](**shared, request_messages=[{"role": "user", "content": "PRIVATE_PROMPT"}]))
            self.assertIsNone(context.hooks["post_api_request"](**shared, ended_at=1789055075.4841616,
                              usage={"input_tokens": 10, "output_tokens": 2}, response="PRIVATE_RESPONSE"))
            self.assertIsNone(context.hooks["api_request_error"](**shared, ended_at=1789055076.0, error="PRIVATE_ERROR"))
            self.assertIsNone(context.hooks["on_session_start"](session_id="s", started_at=1789055075.2960255))
            context.unload()
            events = [json.loads(line) for file in (home / "xerg/events").glob("*.jsonl") for line in file.read_text().splitlines()]
            boundaries = [event for event in events if event["phase"].startswith("api-request-")]
            self.assertEqual(len(boundaries), 3)
            self.assertEqual([event["started_at"] for event in boundaries], [shared["started_at"]] * 3)
            self.assertNotIn("ended_at", boundaries[0])
            self.assertEqual([event["ended_at"] for event in boundaries[1:]], [1789055075.4841616, 1789055076.0])
            self.assertTrue(all(event["retry_count"] == 0 and event["api_call_count"] == 1 for event in boundaries))
            self.assertTrue(all(isinstance(event["timestamp"], str) for event in boundaries))
            self.assertTrue(all(event["schema"] == "xerg.hermes.observer.v1" for event in boundaries))
            self.assertNotIn("started_at", next(event for event in events if event["phase"] == "session-start"))
            self.assertNotIn("PRIVATE_", json.dumps(events))

    def test_invalid_or_missing_native_api_times_are_not_coerced_to_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            plugin = load_plugin(home, "0.20.1")
            context = Context()
            plugin.register(context)
            for value in [None, True, False, "1789055075", "PRIVATE_TIME", float("nan"), float("inf"), -1, 0, 8640000000001, {}]:
                self.assertIsNone(context.hooks["pre_api_request"](session_id="s", api_request_id="r", started_at=value, ended_at=value))
            self.assertIsNone(context.hooks["post_api_request"](session_id="s", api_request_id="r"))
            context.unload()
            events = [json.loads(line) for file in (home / "xerg/events").glob("*.jsonl") for line in file.read_text().splitlines()]
            boundaries = [event for event in events if event["phase"].startswith("api-request-")]
            self.assertEqual(len(boundaries), 12)
            self.assertTrue(all("started_at" not in event and "ended_at" not in event for event in boundaries))
            self.assertNotIn("PRIVATE_", json.dumps(events))

    def test_version_specific_registration_and_executed_only_capabilities(self):
        for version, reason in [
            ("0.17.0", "registered"), ("0.19.0", "registered"),
            ("0.20.1", "registered"), ("0.20.6", "omitted-policy-dispatch"),
            ("0.21.0", "omitted-policy-dispatch"), ("", "omitted-unknown-runtime"),
            ("0.20.3", "omitted-unknown-runtime"), ("0.22.0", "omitted-unknown-runtime"),
        ]:
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                plugin = load_plugin(Path(directory), version)
                context = Context()
                plugin.register(context)
                eligible = reason == "registered"
                self.assertEqual("pre_tool_call" in context.hooks, eligible)
                args, result = {"content": "PRIVATE_REQUEST"}, {"text": "PRIVATE_RESULT"}
                self.assertIsNone(context.hooks["post_tool_call"](
                    session_id="s", tool_call_id="t", tool_name="write_file",
                    args=args, result=result, status="ok"))
                self.assertEqual(args, {"content": "PRIVATE_REQUEST"})
                self.assertEqual(result, {"text": "PRIVATE_RESULT"})
                context.unload()
                events = [json.loads(line) for file in (Path(directory) / "xerg/events").glob("*.jsonl") for line in file.read_text().splitlines()]
                health = [json.loads(file.read_text()) for file in (Path(directory) / "xerg/events").glob("observer-health-*.json")]
                for item in events + health:
                    self.assertEqual(item["pre_tool_observation"], reason)
                    self.assertEqual(item["tool_argument_comparison"], "eligible" if eligible else "unavailable")
                post = next(event for event in events if event["phase"] == "post")
                self.assertIn("executed_input_fingerprint", post)
                self.assertNotIn("input_fingerprint", post)
                self.assertNotIn("PRIVATE", json.dumps(events + health))
                self.assertFalse(any(event["phase"] == "pre" for event in events))

    def test_executing_version_wins_over_distribution_and_expected_version(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = load_plugin(Path(directory), None)
            runtime = types.ModuleType("hermes_cli")
            runtime.__version__ = "0.21.0"
            with patch.dict(sys.modules, {"hermes_cli": runtime}), patch.dict("os.environ", {"HERMES_EXPECTED_VERSION": "0.19.0"}), patch.object(plugin.importlib.metadata, "version", return_value="0.19.0"):
                context = Context()
                plugin.register(context)
                self.assertNotIn("pre_tool_call", context.hooks)
                context.unload()

    def test_pinned_dispatcher_harness_assertions_with_synthetic_dispatcher(self):
        # Harness self-test only: the separate acceptance command requires the
        # real pinned Hermes manager and refuses a substitute implementation.
        path = Path(__file__).resolve().parents[3] / "scripts/acceptance/hermes-profile-hooks.py"
        spec = importlib.util.spec_from_file_location("hermes_profile_hooks_test", path)
        harness = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(harness)
        with tempfile.TemporaryDirectory() as directory:
            plugin = load_plugin(Path(directory))
            context = Context()
            plugin.register(context)

            class Dispatcher:
                def invoke_hook(self, name, **kwargs):
                    result = context.hooks[name](**kwargs)
                    return [] if result is None else [result]

            harness.exercise_observer_contract(Dispatcher(), plugin)
            context.unload()
            events = [json.loads(line) for file in (Path(directory) / "xerg/events").glob("*.jsonl") for line in file.read_text().splitlines()]
            harness.assert_observer_contract(events)
            self.assertNotIn("PRIVATE_", json.dumps(events))

    def test_profiles_are_bound_at_registration_and_reload_is_unique(self):
        with tempfile.TemporaryDirectory() as directory:
            homes = [Path(directory) / "private-alpha", Path(directory) / "private-beta"]
            plugin = load_plugin(homes[0])
            selected = homes[0]
            module = types.ModuleType("hermes_constants")
            module.get_hermes_home = lambda: selected
            contexts = [Context(), Context()]
            with patch.dict(sys.modules, {"hermes_constants": module}):
                for home, context in zip(homes, contexts):
                    selected = home
                    plugin.register(context)
                for context in contexts:
                    self.assertIsNone(context.hooks["pre_tool_call"](
                        session_id="same-session", tool_call_id="same-tool", args={"x": 1}))
                for index, context in enumerate(contexts):
                    context.hooks["transform_terminal_output"](command="same-command", task_id="same-task", output="x" * (13 + index))
                for context in reversed(contexts):
                    context.hooks["post_tool_call"](session_id="same-session", tool_call_id="terminal", tool_name="terminal", task_id="same-task", args={"command": "same-command"}, result={"output": "x"}, status="ok")
                contexts[0].unload()
                selected = homes[0]
                replacement = Context()
                plugin.register(replacement)
                replacement.hooks["pre_tool_call"](session_id="same-session", args={"x": 1})
                replacement.unload()
                contexts[1].unload()
            plugin._shutdown()
            scopes = []
            for index, home in enumerate(homes):
                ledgers = list((home / "xerg/events").glob("*.jsonl"))
                self.assertEqual(len(ledgers), 2 if index == 0 else 1)
                events = [json.loads(line) for file in ledgers for line in file.read_text().splitlines()]
                own = {event["profile_scope_id"] for event in events}
                self.assertEqual(len(own), 1)
                scopes.append(own)
                self.assertNotIn("private-", json.dumps(events))
                terminal = next(event for event in events if event["event_type"] == "terminal-output")
                self.assertEqual(terminal["generated_bytes"], 13 + index)
                health = list((home / "xerg/events").glob("observer-health-*.json"))
                self.assertEqual(len(health), len(ledgers))
                self.assertTrue(all(json.loads(file.read_text())["state"] == "stopped" for file in health))
            self.assertNotEqual(scopes[0], scopes[1])

    def test_request_shapes_measure_only_hook_representations(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = load_plugin(Path(directory))
            forms = [
                [{"role": "tool", "content": "private-result"}],
                [{"role": "user", "content": [{"type": "tool_result", "content": "private-result"}]}],
                [{"type": "function_call_output", "call_id": "private-call", "output": "private-result"}],
            ]
            for messages in forms:
                sizes = plugin._prompt_sizes({"request_messages": messages, "conversation_history": ["x" * 9999]})
                self.assertEqual(sizes["input_messages_bytes"], len(plugin._json_bytes(messages)))
                self.assertEqual(sizes["model_input_tool_result_count"], 1)
                self.assertGreater(sizes["model_input_tool_result_bytes"], 0)
                self.assertEqual(sizes["model_input_tool_result_basis"], "hermes-request-hook")
            self.assertNotIn("model_input_tool_result_basis", plugin._prompt_sizes({"conversation_history": forms[0]}))
            self.assertNotIn("model_input_tool_result_basis", plugin._prompt_sizes({"request_messages": [object()]}))

    def test_callbacks_are_fail_neutral_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = load_plugin(Path(directory))
            context = Context()
            plugin.register(context)
            cycle = []
            cycle.append(cycle)
            self.assertIsNone(context.hooks["pre_tool_call"](args=cycle))
            self.assertIsNone(context.hooks["pre_api_request"](request_messages=[{"role": "user", "content": "x" * (2 * 1024 * 1024)}]))
            with patch.object(plugin, "_json_bytes", side_effect=RuntimeError("private-failure")):
                self.assertIsNone(context.hooks["pre_tool_call"](args={}))
            context.unload()
            contents = "".join(file.read_text() for file in (Path(directory) / "xerg/events").glob("*.jsonl"))
            self.assertNotIn("private-failure", contents)
            self.assertIn("dropped_event_count", contents)

    def test_queue_and_lock_exhaustion_do_not_block_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = load_plugin(Path(directory))
            context = Context()
            plugin.register(context)
            writer = plugin._WRITER
            with patch.object(writer.queue, "put_nowait", side_effect=queue.Full):
                self.assertIsNone(context.hooks["pre_tool_call"](args={}))
            writer.lock.acquire()
            try:
                self.assertIsNone(context.hooks["pre_tool_call"](args={}))
            finally:
                writer.lock.release()
            self.assertGreaterEqual(writer.dropped, 2)
            context.unload()
            self.assertIsNone(context.hooks["pre_tool_call"](args={}))

    def test_failed_writer_startup_is_neutral(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = load_plugin(Path(directory))
            context = Context()
            with patch.object(plugin, "_Writer", side_effect=PermissionError("private-path")):
                self.assertIsNone(plugin.register(context))
            self.assertEqual(context.hooks, {})
            plugin._shutdown()

    def test_ten_concurrent_children_keep_only_bounded_correlations(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = load_plugin(Path(directory))
            context = Context()
            plugin.register(context)

            def child(index):
                kwargs = {"parent_session_id": "parent", "parent_turn_id": "turn", "child_session_id": f"child-{index}", "child_subagent_id": f"agent-{index}"}
                self.assertIsNone(context.hooks["subagent_start"](**kwargs, child_goal="PRIVATE_GOAL"))
                self.assertIsNone(context.hooks["on_session_start"](session_id=f"child-{index}"))
                self.assertIsNone(context.hooks["subagent_stop"](**kwargs, child_status="partial" if index % 2 else "ok", child_summary="PRIVATE_SUMMARY", duration_ms=3))

            with ThreadPoolExecutor(max_workers=10) as executor:
                list(executor.map(child, range(10)))
            context.hooks["api_request_error"](session_id="parent", api_request_id="retry", retry_count=2, status_code=429, error="PRIVATE_ERROR")
            context.unload()
            contents = "".join(file.read_text() for file in (Path(directory) / "xerg/events").glob("*.jsonl"))
            self.assertNotIn("PRIVATE", contents)
            events = [json.loads(line) for line in contents.splitlines()]
            self.assertEqual(sum(event["phase"] == "subagent-stop" for event in events), 10)
            error = next(event for event in events if event["phase"] == "api-request-error")
            self.assertEqual(error["retry_count"], 2)
            self.assertEqual(error["status_code"], 429)

    def test_executed_arguments_and_spill_preview_do_not_read_files(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = load_plugin(Path(directory))
            context = Context()
            plugin.register(context)
            args = {"path": "/never/open/private", "content": "modified"}
            with patch("builtins.open", side_effect=AssertionError("file read")), patch.object(Path, "stat", side_effect=AssertionError("stat")):
                self.assertIsNone(context.hooks["post_tool_call"](session_id="s", tool_call_id="t", tool_name="write_file", args=args, status="ok", result="<persisted-output>/never/open/private</persisted-output>"))
                self.assertIsNone(context.hooks["post_tool_call"](session_id="s", tool_call_id="blocked", tool_name="write_file", args=args, status="blocked", result=None))
            context.unload()
            events = [json.loads(line) for file in (Path(directory) / "xerg/events").glob("*.jsonl") for line in file.read_text().splitlines()]
            post = next(event for event in events if event["phase"] == "post")
            self.assertEqual(len(post["executed_input_fingerprint"]), 64)
            self.assertEqual(post["status"], "ok")
            blocked = next(event for event in events if event.get("tool_call_id") == "blocked")
            self.assertNotIn("executed_input_fingerprint", blocked)
            self.assertNotIn("/never/open", json.dumps(events))
