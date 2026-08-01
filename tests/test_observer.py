import importlib.util
import json
import os
import tempfile
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
            self.assertEqual(observer_status["plugin_version"], "0.17.0")
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
            delegation_events = [
                event for event in events if event["event_type"] == "delegation"
            ]
            self.assertEqual(len(delegation_events), 3)
            self.assertTrue(
                all(event["session_id"] == "session-1" for event in delegation_events)
            )
            self.assertIn("queue_wait_ms", delegation_events[1])
            self.assertEqual(ledger.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
