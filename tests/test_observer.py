import importlib.util
import json
import os
import tempfile
import time
import unittest
from pathlib import Path


def load_plugin(home: Path):
    os.environ["HERMES_HOME"] = str(home)
    path = Path(__file__).parents[1] / "__init__.py"
    spec = importlib.util.spec_from_file_location("xerg_hermes_observer_test", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ObserverPrivacyTest(unittest.TestCase):
    def test_registers_the_v017_and_v019_hook_set(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = load_plugin(Path(directory))

            class Context:
                hooks = {}

                def register_hook(self, name, callback):
                    self.hooks[name] = callback

            context = Context()
            plugin.register(context)
            self.assertEqual(
                set(context.hooks),
                {
                    "pre_api_request",
                    "post_api_request",
                    "api_request_error",
                    "pre_tool_call",
                    "post_tool_call",
                    "transform_terminal_output",
                    "subagent_start",
                    "subagent_stop",
                    "on_session_start",
                    "on_session_end",
                    "on_session_finalize",
                },
            )
            health_path = next((Path(directory) / "xerg" / "events").glob("observer-health-*.json"))
            health = json.loads(health_path.read_text())
            self.assertEqual(health["schema"], "xerg.hermes.observer-health.v1")
            self.assertEqual(health["state"], "running")
            self.assertTrue(health["writer_healthy"])
            self.assertEqual(health_path.stat().st_mode & 0o777, 0o600)
            plugin._shutdown()
            stopped = json.loads(health_path.read_text())
            self.assertEqual(stopped["state"], "stopped")
            self.assertIn("stopped_at", stopped)

    def test_heartbeat_updates_health_without_growing_the_evidence_ledger(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            plugin = load_plugin(home)

            class Context:
                def register_hook(self, _name, _callback):
                    pass

            plugin.register(Context())
            writer = plugin._WRITER
            self.assertIsNotNone(writer)
            assert writer is not None
            deadline = time.time() + 1
            while writer.path.stat().st_size == 0 and time.time() < deadline:
                time.sleep(0.01)
            before = writer.path.read_text().splitlines()
            old_timestamp = time.time() - 120
            os.utime(writer.path, (old_timestamp, old_timestamp))
            writer._heartbeat_once()
            writer._heartbeat_once()
            after = writer.path.read_text().splitlines()
            self.assertEqual(after, before)
            self.assertGreater(writer.path.stat().st_mtime, old_timestamp)
            health = json.loads(writer.health_path.read_text())
            self.assertEqual(health["state"], "running")
            self.assertEqual(health["started_at"], json.loads(before[0])["started_at"])
            plugin._shutdown()

    def test_prunes_health_files_independently_from_ledgers(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            events = home / "xerg" / "events"
            events.mkdir(parents=True)
            old_health = events / "observer-health-999.json"
            old_ledger = events / "observer-999-1.jsonl"
            old_health.write_text("{}")
            old_ledger.write_text("{}\n")
            old_timestamp = time.time() - 8 * 86400
            os.utime(old_health, (old_timestamp, old_timestamp))
            os.utime(old_ledger, (old_timestamp, old_timestamp))
            plugin = load_plugin(home)

            class Context:
                def register_hook(self, _name, _callback):
                    pass

            plugin.register(Context())
            self.assertFalse(old_health.exists())
            self.assertFalse(old_ledger.exists())
            plugin._shutdown()

    def test_discards_sensitive_values_and_reports_truncation(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            plugin = load_plugin(home)
            secret_path = "/private/customer/secret.txt"
            secret_command = "cat /private/customer/secret.txt"
            secret_result = "customer-secret-result"
            plugin.on_pre_api_request(
                session_id="session-1",
                turn_id="turn-1",
                api_request_id="request-1",
                provider="anthropic",
                model="claude-sonnet-4-6",
                messages=[{"role": "user", "content": secret_result}],
                system_prompt=secret_command,
                tools=[{"name": "read_file", "description": secret_path}],
            )
            plugin.on_post_api_request(
                session_id="session-1",
                turn_id="turn-1",
                api_request_id="request-1",
                provider="anthropic",
                model="claude-sonnet-4-6",
                usage={"input_tokens": 10, "output_tokens": 2},
                duration_ms=5,
            )
            plugin.on_api_request_error(
                session_id="session-1",
                turn_id="turn-1",
                api_request_id="request-error",
                provider="anthropic",
                model="claude-sonnet-4-6",
                prompt_tokens=3,
                completion_tokens=0,
            )
            plugin.on_pre_tool_call(
                telemetry_schema_version="hermes.observer.v1",
                session_id="session-1",
                turn_id="turn-1",
                tool_call_id="tool-1",
                tool_name="write_file",
                args={"path": secret_path, "content": secret_result},
            )
            plugin.on_post_tool_call(
                session_id="session-1",
                tool_call_id="tool-1",
                tool_name="write_file",
                result=secret_result,
                status="ok",
            )
            plugin.on_pre_tool_call(
                session_id="session-1",
                turn_id="turn-1",
                task_id="task-1",
                tool_call_id="tool-2",
                tool_name="terminal",
                args={"command": secret_command},
            )
            plugin.transform_terminal_output(
                command=secret_command,
                output="x" * 50,
                task_id="task-1",
            )
            returned_output = (
                "xxxxxxxx\n\n... [OUTPUT TRUNCATED - 42 chars omitted "
                "out of 50 total] ...\n\n"
            )
            plugin.on_post_tool_call(
                session_id="session-1",
                turn_id="turn-1",
                task_id="task-1",
                tool_call_id="tool-2",
                tool_name="terminal",
                args={"command": secret_command},
                result=json.dumps({"output": returned_output, "status": "ok"}),
                status="ok",
            )
            plugin.on_subagent_start(
                parent_session_id="session-1",
                child_session_id="session-child",
                child_goal=secret_result,
            )
            plugin.on_session_start(session_id="session-child")
            plugin.on_subagent_stop(
                parent_session_id="session-1",
                child_session_id="session-child",
                child_summary=secret_result,
                child_status="ok",
                duration_ms=10,
            )
            plugin._shutdown()

            ledger = next((home / "xerg" / "events").glob("*.jsonl"))
            contents = ledger.read_text()
            self.assertNotIn(secret_path, contents)
            self.assertNotIn(secret_command, contents)
            self.assertNotIn(secret_result, contents)
            events = [json.loads(line) for line in contents.splitlines()]
            observer_status = next(
                event for event in events if event["event_type"] == "observer-status"
            )
            self.assertEqual(observer_status["plugin_version"], "0.30.0")
            self.assertEqual(
                observer_status["telemetry_schema_version"],
                "xerg.hermes.observer.v1",
            )
            self.assertEqual(observer_status["retention_days"], 7)
            self.assertTrue(observer_status["writer_healthy"])
            request_start = next(
                event for event in events if event["phase"] == "api-request-start"
            )
            self.assertEqual(request_start["input_messages_count"], 1)
            self.assertGreater(request_start["prompt_total_chars"], 0)
            self.assertGreater(request_start["prompt_total_bytes"], 0)
            self.assertGreater(request_start["system_prompt_bytes"], 0)
            self.assertGreater(request_start["tool_definitions_bytes"], 0)
            request_error = next(
                event for event in events if event["phase"] == "api-request-error"
            )
            self.assertEqual(request_error["input_tokens"], 3)
            tool_start = next(
                event
                for event in events
                if event["event_type"] == "tool" and event["phase"] == "pre"
            )
            self.assertTrue(tool_start["input_fingerprint"])
            self.assertTrue(tool_start["target_fingerprint"])
            terminal_event = next(
                event for event in events if event["event_type"] == "terminal-output"
            )
            self.assertEqual(terminal_event["generated_bytes"], 50)
            self.assertEqual(
                terminal_event["returned_bytes"], len(returned_output.encode("utf-8"))
            )
            self.assertEqual(terminal_event["truncated_bytes"], 42)
            self.assertEqual(terminal_event["terminal_measurement_basis"], "exact")
            delegation_events = [
                event for event in events if event["event_type"] == "delegation"
            ]
            self.assertEqual(len(delegation_events), 3)
            self.assertTrue(
                all(event["session_id"] == "session-1" for event in delegation_events)
            )
            self.assertIn("queue_wait_ms", delegation_events[1])
            self.assertEqual(ledger.stat().st_mode & 0o777, 0o600)

    def test_v020_structured_character_total_is_a_byte_floor(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            plugin = load_plugin(home)
            visible = (
                "head😀\n\n... [OUTPUT TRUNCATED - 10,000 chars omitted "
                "out of 12,345 total] ...\n\ntail"
            )
            spill_path = "/private/customer/never-dereference-this.log"
            plugin.transform_terminal_output(
                command="private-command",
                output=visible,
                task_id="task-v020",
            )
            plugin.on_post_tool_call(
                session_id="session-v020",
                task_id="task-v020",
                tool_call_id="tool-v020",
                tool_name="terminal",
                args={"command": "private-command"},
                result={
                    "output": visible,
                    "exit_code": 0,
                    "output_total_chars": 12345,
                    "full_output_path": spill_path,
                },
                status="ok",
            )
            plugin.on_post_tool_call(
                session_id="session-clamp",
                task_id="task-clamp",
                tool_call_id="tool-clamp",
                tool_name="terminal",
                result={
                    "output": "😀😀",
                    "exit_code": 0,
                    "output_total_chars": 1,
                    "full_output_path": "/private/also-never-dereference.log",
                },
                status="ok",
            )
            plugin._shutdown()

            ledger = next((home / "xerg" / "events").glob("*.jsonl"))
            contents = ledger.read_text()
            self.assertNotIn(spill_path, contents)
            events = [json.loads(line) for line in contents.splitlines()]
            terminal_event = next(
                event for event in events if event["event_type"] == "terminal-output"
            )
            self.assertEqual(
                terminal_event["terminal_measurement_basis"], "lower-bound"
            )
            self.assertTrue(terminal_event["spill_recoverable"])
            self.assertEqual(terminal_event["generated_bytes_lower_bound"], 12345)
            self.assertEqual(
                terminal_event["truncated_bytes_lower_bound"],
                12345 - len(visible),
            )
            self.assertNotIn("generated_bytes", terminal_event)
            self.assertNotIn("truncated_bytes", terminal_event)
            clamped_event = next(
                event
                for event in events
                if event.get("tool_call_id") == "tool-clamp"
                and event["event_type"] == "terminal-output"
            )
            self.assertEqual(clamped_event["generated_bytes_lower_bound"], 1)
            self.assertEqual(clamped_event["truncated_bytes_lower_bound"], 0)

    def test_comma_marker_is_a_fallback_and_missing_totals_stay_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            plugin = load_plugin(home)
            marker_output = (
                "head\n\n... [OUTPUT TRUNCATED - 9,999 chars omitted "
                "out of 10,100 total] ...\n\ntail"
            )
            plugin.on_post_tool_call(
                session_id="session-fallback",
                task_id="task-fallback",
                tool_call_id="tool-fallback",
                tool_name="terminal",
                result={"output": marker_output, "exit_code": 0},
                status="ok",
            )
            plugin.on_post_tool_call(
                session_id="session-unavailable",
                task_id="task-unavailable",
                tool_call_id="tool-unavailable",
                tool_name="terminal",
                result={
                    "output": "[OUTPUT TRUNCATED - nope chars omitted out of 100 total]",
                    "exit_code": 0,
                },
                status="ok",
            )
            plugin._shutdown()

            ledger = next((home / "xerg" / "events").glob("*.jsonl"))
            terminal_events = [
                event
                for event in (json.loads(line) for line in ledger.read_text().splitlines())
                if event["event_type"] == "terminal-output"
            ]
            fallback, unavailable = terminal_events
            self.assertEqual(fallback["terminal_measurement_basis"], "lower-bound")
            self.assertEqual(fallback["generated_bytes_lower_bound"], 10100)
            self.assertGreaterEqual(fallback["truncated_bytes_lower_bound"], 9999)
            self.assertNotIn("terminal_measurement_basis", unavailable)
            self.assertNotIn("generated_bytes", unavailable)
            self.assertNotIn("generated_bytes_lower_bound", unavailable)
            self.assertIn("returned_bytes", unavailable)

    def test_marker_floor_is_recomputed_after_the_final_visible_output_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            plugin = load_plugin(home)
            transformed_output = (
                "head\n\n... [OUTPUT TRUNCATED - 900 chars omitted "
                "out of 1,000 total] ...\n\ntail"
            )
            final_output = "😀tail"
            plugin.transform_terminal_output(
                command="bounded-command",
                output=transformed_output,
                task_id="task-final-cap",
            )
            plugin.on_post_tool_call(
                session_id="session-final-cap",
                task_id="task-final-cap",
                tool_call_id="tool-final-cap",
                tool_name="terminal",
                args={"command": "bounded-command"},
                result={"output": final_output, "exit_code": 0},
                status="ok",
            )
            plugin._shutdown()

            ledger = next((home / "xerg" / "events").glob("*.jsonl"))
            terminal_event = next(
                event
                for event in (
                    json.loads(line) for line in ledger.read_text().splitlines()
                )
                if event["event_type"] == "terminal-output"
            )
            self.assertEqual(
                terminal_event["terminal_measurement_basis"], "lower-bound"
            )
            self.assertEqual(terminal_event["generated_bytes_lower_bound"], 1000)
            self.assertEqual(
                terminal_event["truncated_bytes_lower_bound"],
                1000 - len(final_output),
            )


if __name__ == "__main__":
    unittest.main()
