"""Content-free, local-only observer for the Hermes v1 hook contract.

Hook payloads can contain commands, paths, arguments, results, prompts, and
assistant content. This module may inspect those values transiently to compute
sizes and keyed fingerprints, but it never writes the values themselves.
"""

from __future__ import annotations

import atexit
import contextvars
import hashlib
import hmac
import importlib.metadata
import json
import math
import os
import queue
import re
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "xerg.hermes.observer.v1"
HEALTH_SCHEMA = "xerg.hermes.observer-health.v1"
HERMES_OBSERVER_SCHEMA = "hermes.observer.v1"
PLUGIN_VERSION = "0.35.4"
DEFAULT_RETENTION_DAYS = 7
HEARTBEAT_INTERVAL_SECONDS = 60
MAX_QUEUE_SIZE = 2048
MAX_MEASUREMENT_CHARS = 1024 * 1024
MAX_MEASUREMENT_NODES = 8192
MAX_MEASUREMENT_DEPTH = 32
_TRUNCATION_RE = re.compile(
    r"\[OUTPUT TRUNCATED - (?P<omitted>[0-9][0-9,]*) chars omitted "
    r"out of (?P<total>[0-9][0-9,]*) total\]"
)
_WRITE_TOOLS = {"write_file", "patch", "edit_file"}
class _MeasurementUnavailable(ValueError):
    pass


def _hermes_home() -> Path:
    try:
        from hermes_constants import get_hermes_home
    except ImportError:
        return Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))
    return Path(get_hermes_home())


class _Scope:
    def __init__(self, home: Path) -> None:
        self.home = home
        self.hermes_version = _installed_hermes_version()
        self.pre_tool_observation = _pre_tool_observation(self.hermes_version)
        self.lifecycle_observation = _lifecycle_observation(self.hermes_version)
        self.tool_argument_comparison = (
            "eligible" if self.pre_tool_observation == "registered" else "unavailable"
        )
        self.profile_scope_id = hashlib.sha256(os.path.realpath(home).encode()).hexdigest()[:32]
        self.fingerprint_scope = uuid.uuid4().hex
        self.key = secrets.token_bytes(32)
        self.terminal_outputs: dict[str, list[tuple[int, int, str]]] = {}
        self.pending_delegations: dict[str, tuple[str, float] | None] = {}
        self.terminal_lock = threading.Lock()
        self.delegation_lock = threading.Lock()
        self.writer: _Writer | None = None
        self.closed = False


_CURRENT_SCOPE: contextvars.ContextVar[_Scope | None] = contextvars.ContextVar("xerg_observer_scope", default=None)
_DEFAULT_SCOPE: _Scope | None = None
_SCOPES: list[_Scope] = []


def _scope() -> _Scope:
    global _DEFAULT_SCOPE
    selected = _CURRENT_SCOPE.get()
    if selected is not None:
        return selected
    if _DEFAULT_SCOPE is None:
        _DEFAULT_SCOPE = _Scope(_hermes_home())
        _SCOPES.append(_DEFAULT_SCOPE)
    return _DEFAULT_SCOPE


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _text(value: Any) -> str:
    return value if isinstance(value, str) and len(value) <= 512 else ""


def _number(value: Any) -> int | float | None:
    return value if not isinstance(value, bool) and isinstance(value, (int, float)) and math.isfinite(value) and value >= 0 else None


def _nonnegative_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not math.isfinite(value) or value < 0 or int(value) != value:
        return None
    return int(value)


def _json_bytes(value: Any) -> bytes:
    _bounded_json(value)
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return encoded.encode("utf-8", errors="replace")


def _bounded_json(value: Any) -> None:
    # A node/character/depth budget bounds work before JSON materialization.
    # Unsupported values and cycles do not become made-up '<opaque>' evidence.
    stack = [(value, 0)]
    nodes, characters = 0, 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_MEASUREMENT_NODES or depth > MAX_MEASUREMENT_DEPTH:
            raise _MeasurementUnavailable()
        if isinstance(item, str):
            characters += len(item)
        elif item is None or isinstance(item, bool):
            pass
        elif isinstance(item, (int, float)):
            if not math.isfinite(item):
                raise _MeasurementUnavailable()
        elif isinstance(item, (dict, list)):
            if len(item) + nodes + len(stack) > MAX_MEASUREMENT_NODES:
                raise _MeasurementUnavailable()
            if isinstance(item, dict):
                for key, child in item.items():
                    if not isinstance(key, str):
                        raise _MeasurementUnavailable()
                    characters += len(key)
                    stack.append((child, depth + 1))
            else:
                stack.extend((child, depth + 1) for child in item)
        else:
            raise _MeasurementUnavailable()
        if characters > MAX_MEASUREMENT_CHARS:
            raise _MeasurementUnavailable()


def _content_chars(value: Any) -> int:
    _bounded_json(value)
    if value is None:
        return 0
    if isinstance(value, str):
        return len(value)
    return len(_json_bytes(value).decode("utf-8", errors="replace"))


def _content_bytes(value: Any) -> int:
    _bounded_json(value)
    if value is None:
        return 0
    if isinstance(value, str):
        return len(value.encode("utf-8", errors="replace"))
    return len(_json_bytes(value))


def _first_present(kwargs: dict[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        if name in kwargs and kwargs[name] is not None:
            return kwargs[name]
    return None


def _prompt_sizes(kwargs: dict[str, Any]) -> dict[str, Any]:
    messages = _first_present(
        kwargs, ("request_messages", "messages", "input_messages", "conversation", "conversation_history")
    )
    system_prompt = _first_present(
        kwargs, ("system_prompt", "system", "system_message", "instructions")
    )
    tool_definitions = _first_present(
        kwargs, ("tools", "tool_definitions", "tool_schemas", "available_tools")
    )
    result: dict[str, Any] = {}
    total_chars = 0
    total_bytes = 0
    if messages is not None:
        try:
            _bounded_json(messages)
        except _MeasurementUnavailable:
            return {"measurement_unavailable": True}
        result["input_messages_count"] = len(messages) if isinstance(messages, list) else 1
        result["input_messages_chars"] = _content_chars(messages)
        result["input_messages_bytes"] = _content_bytes(messages)
        total_chars += result["input_messages_chars"]
        total_bytes += result["input_messages_bytes"]
    if system_prompt is not None:
        result["system_prompt_chars"] = _content_chars(system_prompt)
        result["system_prompt_bytes"] = _content_bytes(system_prompt)
        total_chars += result["system_prompt_chars"]
        total_bytes += result["system_prompt_bytes"]
    if tool_definitions is not None:
        result["tool_definitions_count"] = (
            len(tool_definitions) if isinstance(tool_definitions, (list, dict)) else 1
        )
        result["tool_definitions_chars"] = _content_chars(tool_definitions)
        result["tool_definitions_bytes"] = _content_bytes(tool_definitions)
        total_chars += result["tool_definitions_chars"]
        total_bytes += result["tool_definitions_bytes"]
    if result:
        result["prompt_total_chars"] = total_chars
        result["prompt_total_bytes"] = total_bytes
    if "request_messages" in kwargs:
        measurement = _request_tool_results(kwargs["request_messages"])
        if measurement is not None:
            result.update(measurement)
        else:
            result["measurement_unavailable"] = True
    return result


def _request_tool_results(messages: Any) -> dict[str, Any] | None:
    if not isinstance(messages, list):
        return None
    results = []
    for message in messages:
        if not isinstance(message, dict):
            return None
        if message.get("type") == "function_call_output":
            if "output" not in message:
                return None
            results.append(message)
        elif message.get("role") in {"system", "developer", "user", "assistant", "tool"}:
            if message["role"] == "tool":
                if "content" not in message:
                    return None
                results.append(message)
            elif isinstance(message.get("content"), list):
                for block in message["content"]:
                    if not isinstance(block, dict):
                        return None
                    if block.get("type") == "tool_result":
                        results.append(block)
        elif message.get("type") not in {"message", "function_call", "reasoning"}:
            return None
    return {
        "model_input_tool_result_count": len(results),
        "model_input_tool_result_bytes": sum(len(_json_bytes(result)) for result in results),
        "model_input_tool_result_basis": "hermes-request-hook",
    }


def _fingerprint(value: Any) -> str:
    return hmac.new(_scope().key, _json_bytes(value), hashlib.sha256).hexdigest()


def _target(args: Any) -> Any:
    if not isinstance(args, dict):
        return None
    for key in ("path", "file_path", "filename", "target"):
        if key in args:
            return args[key]
    return None


def _task_key(kwargs: dict[str, Any]) -> str:
    task_id = _text(kwargs.get("task_id"))
    return task_id or f"thread:{threading.get_ident()}"


def _terminal_context_key(kwargs: dict[str, Any]) -> str:
    """Correlate terminal hooks without retaining the command or arguments."""
    command = kwargs.get("command")
    if command is None and isinstance(kwargs.get("args"), dict):
        command = kwargs["args"].get("command")
    command_key = _fingerprint(command) if command is not None else "unknown-command"
    return f"{_task_key(kwargs)}:{command_key}"


def _parsed_terminal_result(result: Any) -> Any:
    parsed = result
    if isinstance(result, str):
        try:
            parsed = json.loads(result)
        except (TypeError, ValueError):
            return result
    return parsed


def _terminal_output_bytes(result: Any) -> int:
    """Inspect the tool result transiently and return only model-facing output size."""
    parsed = _parsed_terminal_result(result)
    if isinstance(parsed, dict):
        output = parsed.get("output")
        if isinstance(output, str):
            return len(output.encode("utf-8", errors="replace"))
    return len(_json_bytes(result))


def _terminal_output_text(result: Any) -> str:
    parsed = _parsed_terminal_result(result)
    if isinstance(parsed, dict) and isinstance(parsed.get("output"), str):
        return parsed["output"]
    return parsed if isinstance(parsed, str) else ""


def _terminal_output_total_chars(result: Any) -> int | None:
    """Read only structured scalar metadata; never inspect the spill path."""
    parsed = _parsed_terminal_result(result)
    if not isinstance(parsed, dict):
        return None
    return _nonnegative_int(parsed.get("output_total_chars"))


def _marker_count(match: re.Match[str], name: str) -> int:
    return int(match.group(name).replace(",", ""))


def _installed_hermes_version() -> str:
    # Source checkouts need not have installed distribution metadata. Prefer
    # the executing runtime, never an acceptance/configuration override.
    try:
        from hermes_cli import __version__
        if isinstance(__version__, str) and __version__:
            return __version__
    except ImportError:
        pass
    try:
        return importlib.metadata.version("hermes-agent")
    except importlib.metadata.PackageNotFoundError:
        return ""


def _pre_tool_observation(version: str) -> str:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version)
    if not match:
        return "omitted-unknown-runtime"
    parsed = tuple(int(part) for part in match.groups())
    if (0, 17, 0) <= parsed <= (0, 20, 1):
        return "registered"
    if parsed in {(0, 20, 6), (0, 21, 0)}:
        # These pinned dispatchers can fail closed before our callback runs.
        return "omitted-policy-dispatch"
    return "omitted-unknown-runtime"


def _lifecycle_observation(version: str) -> str:
    if version == "0.20.1":
        return "complete-capable"
    if version in {"0.20.6", "0.21.0"}:
        return "partial"
    return "unknown"


class _Writer:
    def __init__(self, scope: _Scope) -> None:
        self.scope = scope
        home = scope.home
        self.directory = Path(
            os.environ.get("XERG_HERMES_EVENTS_DIR", home / "xerg" / "events")
        )
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            self.directory.chmod(0o700)
        except OSError:
            pass
        self.retention_days = self._retention_days()
        self._prune_ledgers()
        self._prune_health_files()
        stamp = uuid.uuid4().hex
        self.path = self.directory / f"observer-{os.getpid()}-{stamp}.jsonl"
        self.health_path = self.directory / f"observer-health-{os.getpid()}-{stamp}.json"
        descriptor = os.open(self.path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
        except OSError:
            pass
        self.file = os.fdopen(descriptor, "a", encoding="utf-8", buffering=1)
        self.queue: queue.Queue[dict[str, Any] | None] = queue.Queue(MAX_QUEUE_SIZE)
        self.dropped = 0
        self.lock = threading.Lock()
        self.health_lock = threading.Lock()
        self.stop_heartbeat = threading.Event()
        self.started_at = _now()
        self.hermes_version = scope.hermes_version
        self.writer_healthy = True
        self.closed = False
        self.thread = threading.Thread(target=self._run, name="xerg-observer-writer", daemon=True)
        self.thread.start()
        self._write_health("running")
        self.heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            name="xerg-observer-heartbeat",
            daemon=True,
        )
        self.heartbeat_thread.start()
        status = _base_event("observer-status", "startup")
        status.update(
            {
                "plugin_version": PLUGIN_VERSION,
                "telemetry_schema_version": SCHEMA,
                "retention_days": self.retention_days,
                "writer_healthy": True,
                "started_at": self.started_at,
            }
        )
        if self.hermes_version:
            status["hermes_version"] = self.hermes_version
        self.emit(status)

    def _retention_days(self) -> int:
        try:
            return max(
                1,
                int(
                    os.environ.get(
                        "XERG_HERMES_RETENTION_DAYS", DEFAULT_RETENTION_DAYS
                    )
                ),
            )
        except (TypeError, ValueError):
            return DEFAULT_RETENTION_DAYS

    def _prune_ledgers(self) -> None:
        cutoff = time.time() - self.retention_days * 86400
        for path in self.directory.glob("observer-*.jsonl"):
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
            except OSError:
                continue

    def _prune_health_files(self) -> None:
        cutoff = time.time() - self.retention_days * 86400
        for path in self.directory.glob("observer-health-*.json"):
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
            except OSError:
                continue

    def _health_payload(self, state: str, stopped_at: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema": HEALTH_SCHEMA,
            "profile_scope_id": self.scope.profile_scope_id,
            "state": state,
            "plugin_version": PLUGIN_VERSION,
            "writer_healthy": self.writer_healthy,
            "started_at": self.started_at,
            "updated_at": _now(),
            "pre_tool_observation": self.scope.pre_tool_observation,
            "tool_argument_comparison": self.scope.tool_argument_comparison,
            "lifecycle_observation": self.scope.lifecycle_observation,
            "upstream_suppression_count_available": False,
        }
        if self.hermes_version:
            payload["hermes_version"] = self.hermes_version
        if stopped_at:
            payload["stopped_at"] = stopped_at
        return payload

    def _write_health(self, state: str, stopped_at: str | None = None) -> None:
        payload = self._health_payload(state, stopped_at)
        temporary = self.directory / f".{self.health_path.name}.{uuid.uuid4().hex}.tmp"
        with self.health_lock:
            descriptor = os.open(
                temporary,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
                    handle.write("\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self.health_path)
                try:
                    self.health_path.chmod(0o600)
                except OSError:
                    pass
            finally:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass

    def _heartbeat_once(self) -> None:
        self._write_health("running")
        try:
            os.utime(self.path, None)
        except OSError:
            pass

    def _heartbeat_loop(self) -> None:
        while not self.stop_heartbeat.wait(HEARTBEAT_INTERVAL_SECONDS):
            try:
                self._heartbeat_once()
            except OSError:
                # A sidecar write failure will naturally age into stale
                # liveness. It does not prove the evidence writer is unhealthy.
                pass

    def emit(self, event: dict[str, Any]) -> None:
        event["profile_scope_id"] = self.scope.profile_scope_id
        event["fingerprint_scope"] = self.scope.fingerprint_scope
        if self.closed or not self.lock.acquire(blocking=False):
            self.dropped += 1
            return
        try:
            if self.dropped:
                status = _base_event("ledger-status", "dropped-events", _observer_scope=self.scope)
                status["dropped_event_count"] = self.dropped
                status["profile_scope_id"] = self.scope.profile_scope_id
                status["fingerprint_scope"] = self.scope.fingerprint_scope
                try:
                    self.queue.put_nowait(status)
                    self.dropped = 0
                except queue.Full:
                    self.dropped += 1
                    return
            try:
                self.queue.put_nowait(event)
            except queue.Full:
                self.dropped += 1
        finally:
            self.lock.release()

    def _run(self) -> None:
        try:
            while True:
                event = self.queue.get()
                if event is None:
                    break
                self.file.write(
                    json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
                )
        except OSError:
            self.writer_healthy = False
            try:
                self._write_health("running")
            except OSError:
                pass

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.stop_heartbeat.set()
        self.heartbeat_thread.join(timeout=1.0)
        stopped_at = _now()
        try:
            self._write_health("stopped", stopped_at)
        except OSError:
            pass
        with self.lock:
            if self.dropped:
                status = _base_event("ledger-status", "dropped-events", _observer_scope=self.scope)
                status["dropped_event_count"] = self.dropped
                status["profile_scope_id"] = self.scope.profile_scope_id
                status["fingerprint_scope"] = self.scope.fingerprint_scope
                try:
                    self.queue.put_nowait(status)
                    self.dropped = 0
                except queue.Full:
                    pass
        try:
            self.queue.put(None, timeout=0.2)
        except queue.Full:
            # The daemon will continue draining until process teardown. Do not
            # close its file handle underneath it.
            return
        self.thread.join(timeout=1.0)
        if not self.thread.is_alive():
            self.file.close()


_WRITER: _Writer | None = None
_WRITER_LOCK = threading.Lock()


def _writer() -> _Writer:
    global _WRITER
    scope = _scope()
    if scope.closed:
        raise _MeasurementUnavailable()
    if scope.writer is not None:
        return scope.writer
    # Registered callbacks always receive an eagerly prepared scope. This lazy
    # branch is only for direct legacy embedding, never callback disk work.
    if _CURRENT_SCOPE.get() is not None:
        raise _MeasurementUnavailable()
    with _WRITER_LOCK:
        if scope.writer is None:
            scope.writer = _Writer(scope)
        _WRITER = scope.writer
        return scope.writer


def _shutdown() -> None:
    global _WRITER, _DEFAULT_SCOPE
    with _WRITER_LOCK:
        _WRITER, _DEFAULT_SCOPE = None, None
        scopes = list(_SCOPES)
        _SCOPES.clear()
    for scope in scopes:
        _close_scope(scope)


def _close_scope(scope: _Scope) -> None:
    scope.closed = True
    if scope.writer is not None:
        scope.writer.close()
    scope.terminal_outputs.clear()
    scope.pending_delegations.clear()
    if scope in _SCOPES:
        _SCOPES.remove(scope)


atexit.register(_shutdown)


def _base_event(event_type: str, phase: str, **kwargs: Any) -> dict[str, Any]:
    scope = kwargs.get("_observer_scope") or _scope()
    event: dict[str, Any] = {
        "schema": SCHEMA,
        "telemetry_schema_version": kwargs.get(
            "telemetry_schema_version", HERMES_OBSERVER_SCHEMA
        ),
        "event_id": uuid.uuid4().hex,
        "timestamp": _now(),
        "event_type": event_type,
        "phase": phase,
        "fingerprint_scope": scope.fingerprint_scope,
        "profile_scope_id": scope.profile_scope_id,
        "pre_tool_observation": scope.pre_tool_observation,
        "tool_argument_comparison": scope.tool_argument_comparison,
        "hermes_version": scope.hermes_version,
        "lifecycle_observation": scope.lifecycle_observation,
        "upstream_suppression_count_available": False,
    }
    mapping = {
        "session_id": "session_id",
        "turn_id": "turn_id",
        "api_request_id": "api_request_id",
        "tool_call_id": "tool_call_id",
        "provider": "provider",
        "model": "model",
        "status": "status",
        "task": "task",
        "task_id": "task_id",
        "parent_turn_id": "parent_turn_id",
        "subagent_id": "subagent_id",
        "parent_subagent_id": "parent_subagent_id",
        "child_subagent_id": "child_subagent_id",
    }
    for source, target in mapping.items():
        value = _text(kwargs.get(source))
        if value:
            event[target] = value
    for key in ("retry_count", "status_code", "api_call_count"):
        value = _nonnegative_int(kwargs.get(key))
        if value is not None:
            event[key] = value
    if phase in {"api-request-start", "api-request-end", "api-request-error"}:
        # Native logical-call clocks are distinct from this writer's timestamp.
        # Preserve only delivered finite numeric seconds; missing or invalid
        # values must not become proof for joining multiple observed attempts.
        for key in ("started_at", "ended_at"):
            value = _number(kwargs.get(key))
            if value is not None and 0 < value <= 8640000000000:
                event[key] = value
    return event


def _emit(event_type: str, phase: str, **kwargs: Any) -> None:
    _writer().emit(_base_event(event_type, phase, **kwargs))


def on_session_start(**kwargs: Any) -> None:
    _emit("lifecycle", "session-start", **kwargs)
    session_id = _text(kwargs.get("session_id"))
    if not session_id:
        return
    scope = _scope()
    if not scope.delegation_lock.acquire(blocking=False):
        raise _MeasurementUnavailable()
    try:
        pending = scope.pending_delegations.pop(session_id, None)
    finally:
        scope.delegation_lock.release()
    if pending is None:
        return
    parent_session_id, queued_at = pending
    event = _base_event(
        "delegation",
        "subagent-running",
        **{**kwargs, "status": "running"},
    )
    event["session_id"] = parent_session_id
    event["parent_session_id"] = parent_session_id
    event["child_session_id"] = session_id
    event["queue_wait_ms"] = max(0, int((time.monotonic() - queued_at) * 1000))
    _writer().emit(event)


def on_session_end(**kwargs: Any) -> None:
    _emit("lifecycle", "session-end", **kwargs)


def on_session_finalize(**kwargs: Any) -> None:
    _emit("lifecycle", "session-finalize", **kwargs)


def on_pre_api_request(**kwargs: Any) -> None:
    event = _base_event("lifecycle", "api-request-start", **kwargs)
    event.update(_prompt_sizes(kwargs))
    _writer().emit(event)


def _usage_values(value: Any) -> dict[str, int | float]:
    if not isinstance(value, dict):
        return {}
    aliases = {
        "input_tokens": ("input_tokens", "prompt_tokens", "input"),
        "output_tokens": ("output_tokens", "completion_tokens", "output"),
        "cache_read_tokens": (
            "cache_read_tokens",
            "cache_read_input_tokens",
            "prompt_cache_hit_tokens",
        ),
        "cache_write_tokens": (
            "cache_write_tokens",
            "cache_creation_input_tokens",
            "prompt_cache_write_tokens",
        ),
        "reasoning_tokens": ("reasoning_tokens", "reasoning_output_tokens"),
    }
    result: dict[str, int | float] = {}
    for output, candidates in aliases.items():
        for key in candidates:
            number = _number(value.get(key))
            if number is not None:
                result[output] = number
                break
    return result


def _request_usage(kwargs: dict[str, Any]) -> dict[str, int | float]:
    candidates = [
        kwargs.get("usage"),
        kwargs.get("token_usage"),
        kwargs.get("response_usage"),
        kwargs,
    ]
    response = kwargs.get("response")
    if isinstance(response, dict):
        candidates.extend((response.get("usage"), response.get("usage_metadata")))
    for candidate in candidates:
        result = _usage_values(candidate)
        if result:
            return result
    return {}


def on_post_api_request(**kwargs: Any) -> None:
    event = _base_event("lifecycle", "api-request-end", **kwargs)
    duration = _number(kwargs.get("duration_ms"))
    if duration is None:
        api_duration = _number(kwargs.get("api_duration"))
        duration = api_duration * 1000 if api_duration is not None else None
    if duration is not None:
        event["duration_ms"] = duration
    event.update(_request_usage(kwargs))
    _writer().emit(event)


def on_api_request_error(**kwargs: Any) -> None:
    event = _base_event("api-error", "api-request-error", **kwargs)
    duration = _number(kwargs.get("duration_ms"))
    if duration is None:
        api_duration = _number(kwargs.get("api_duration"))
        duration = api_duration * 1000 if api_duration is not None else None
    if duration is not None:
        event["duration_ms"] = duration
    event.update(_request_usage(kwargs))
    _writer().emit(event)


def on_pre_tool_call(**kwargs: Any) -> None:
    args = kwargs.get("args")
    tool_name = _text(kwargs.get("tool_name")) or "tool"
    event = _base_event("tool", "pre", **kwargs)
    event["tool_name"] = tool_name
    event["input_bytes"] = len(_json_bytes(args))
    event["input_fingerprint"] = _fingerprint(args)
    target = _target(args)
    if tool_name in _WRITE_TOOLS and target is not None:
        event["target_fingerprint"] = _fingerprint(target)
    _writer().emit(event)


def on_post_tool_call(**kwargs: Any) -> None:
    tool_name = _text(kwargs.get("tool_name")) or "tool"
    event = _base_event("tool", "post", **kwargs)
    event["tool_name"] = tool_name
    event["returned_bytes"] = len(_json_bytes(kwargs.get("result")))
    if "args" in kwargs and kwargs.get("status") not in {"blocked", "cancelled", "canceled"}:
        event["executed_input_bytes"] = len(_json_bytes(kwargs["args"]))
        event["executed_input_fingerprint"] = _fingerprint(kwargs["args"])
        target = _target(kwargs["args"])
        if tool_name in _WRITE_TOOLS and target is not None:
            event["executed_target_fingerprint"] = _fingerprint(target)
    duration = _number(kwargs.get("duration_ms"))
    if duration is not None:
        event["duration_ms"] = duration
    _writer().emit(event)

    if tool_name == "delegate_task":
        result = kwargs.get("result")
        if isinstance(result, str):
            try:
                result = json.loads(result)
            except (ValueError, RecursionError):
                return
        _bounded_json(result)
        results = result.get("results") if isinstance(result, dict) else None
        if isinstance(results, list):
            if len(results) > 10:
                raise _MeasurementUnavailable()
            for item in results:
                if not isinstance(item, dict):
                    continue
                # Batch results do not identify a child session. Retain only
                # native categorical validation evidence, never result content.
                child_result = _base_event("delegation", "subagent-result", **kwargs)
                child_result.pop("status", None)
                status = item.get("status")
                if isinstance(status, str) and status in {"completed", "partial", "error", "failed", "cancelled", "canceled", "timeout", "running", "success", "interrupted"}:
                    child_result["status"] = status
                if isinstance(item.get("schema_valid"), bool):
                    child_result["schema_valid"] = item["schema_valid"]
                task_index = _nonnegative_int(item.get("task_index"))
                if task_index is not None:
                    child_result["task_index"] = task_index
                _writer().emit(child_result)

    if tool_name == "terminal":
        key = _terminal_context_key(kwargs)
        scope = _scope()
        if not scope.terminal_lock.acquire(blocking=False):
            raise _MeasurementUnavailable()
        try:
            pending = scope.terminal_outputs.get(key, [])
            captured = pending.pop(0) if pending else None
            if not pending:
                scope.terminal_outputs.pop(key, None)
        finally:
            scope.terminal_lock.release()
        output = _terminal_output_text(kwargs.get("result"))
        returned_bytes = _terminal_output_bytes(kwargs.get("result"))
        output_total_chars = _terminal_output_total_chars(kwargs.get("result"))
        terminal_event = _base_event("terminal-output", "terminal-output", **kwargs)
        terminal_event["tool_name"] = "terminal"
        terminal_event["returned_bytes"] = returned_bytes
        if output_total_chars is not None:
            # Hermes v0.20+ bounds capture before this observer hook. Its
            # character total is therefore a conservative UTF-8 byte floor.
            # Python len(str) counts Unicode codepoints, not UTF-16 units.
            generated_floor = output_total_chars
            truncated_floor = max(0, output_total_chars - len(output))
            terminal_event["terminal_measurement_basis"] = "lower-bound"
            terminal_event["spill_recoverable"] = True
            terminal_event["generated_bytes_lower_bound"] = generated_floor
            terminal_event["truncated_bytes_lower_bound"] = truncated_floor
        elif captured is not None:
            generated_bytes, truncated_bytes, basis = captured
            marker = _TRUNCATION_RE.search(output)
            if marker and basis == "exact":
                omitted_chars = _marker_count(marker, "omitted")
                truncated_bytes = max(
                    omitted_chars, generated_bytes - returned_bytes
                )
            elif basis == "lower-bound":
                # A later Hermes cap can shorten the output after the transform
                # hook. Recompute the conservative floor from the final
                # model-facing Unicode codepoint count.
                truncated_bytes = max(
                    truncated_bytes, generated_bytes - len(output), 0
                )
            terminal_event["terminal_measurement_basis"] = basis
            if basis == "exact":
                terminal_event["generated_bytes"] = generated_bytes
                terminal_event["truncated_bytes"] = truncated_bytes
            else:
                terminal_event["generated_bytes_lower_bound"] = generated_bytes
                terminal_event["truncated_bytes_lower_bound"] = truncated_bytes
        else:
            # Marker prose is a compatibility fallback only. Comma-formatted
            # counts are character totals and remain byte lower bounds.
            marker = _TRUNCATION_RE.search(output)
            if marker:
                total_chars = _marker_count(marker, "total")
                omitted_chars = _marker_count(marker, "omitted")
                terminal_event["terminal_measurement_basis"] = "lower-bound"
                terminal_event["generated_bytes_lower_bound"] = total_chars
                terminal_event["truncated_bytes_lower_bound"] = max(
                    omitted_chars, total_chars - len(output), 0
                )
        _writer().emit(terminal_event)


def transform_terminal_output(**kwargs: Any) -> None:
    output = kwargs.get("output", "")
    if not isinstance(output, str):
        raise _MeasurementUnavailable()
    _bounded_json(output)
    generated_bytes = len(output.encode("utf-8", errors="replace"))
    match = _TRUNCATION_RE.search(output)
    truncated_bytes = 0
    basis = "exact"
    if match:
        # Older Hermes versions can expose an earlier capture-truncation marker.
        # Preserve a conservative lower bound before the final tool-result cap.
        omitted_chars = _marker_count(match, "omitted")
        total_chars = _marker_count(match, "total")
        generated_bytes = total_chars
        truncated_bytes = max(omitted_chars, total_chars - len(output), 0)
        basis = "lower-bound"
    key = _terminal_context_key(kwargs)
    scope = _scope()
    if not scope.terminal_lock.acquire(blocking=False):
        raise _MeasurementUnavailable()
    try:
        if key not in scope.terminal_outputs and len(scope.terminal_outputs) >= MAX_QUEUE_SIZE:
            raise _MeasurementUnavailable()
        pending = scope.terminal_outputs.setdefault(key, [])
        if len(pending) >= 64:
            raise _MeasurementUnavailable()
        pending.append((generated_bytes, truncated_bytes, basis))
    finally:
        scope.terminal_lock.release()
    return None


def on_subagent_start(**kwargs: Any) -> None:
    event = _base_event("delegation", "subagent-start", **kwargs)
    parent = _text(kwargs.get("parent_session_id")) or _text(kwargs.get("session_id"))
    child = _text(kwargs.get("child_session_id")) or _text(kwargs.get("subagent_session_id"))
    if parent:
        event["session_id"] = parent
        event["parent_session_id"] = parent
    if child:
        event["child_session_id"] = child
        scope = _scope()
        if not scope.delegation_lock.acquire(blocking=False):
            raise _MeasurementUnavailable()
        try:
            if child not in scope.pending_delegations and len(scope.pending_delegations) >= MAX_QUEUE_SIZE:
                raise _MeasurementUnavailable()
            # Duplicate spawn identities are ambiguous, not a newer queue start.
            scope.pending_delegations[child] = (
                None if child in scope.pending_delegations else (parent, time.monotonic())
            )
        finally:
            scope.delegation_lock.release()
    wait = _number(kwargs.get("queue_wait_ms"))
    if wait is not None:
        event["queue_wait_ms"] = wait
    _writer().emit(event)


def on_subagent_stop(**kwargs: Any) -> None:
    event = _base_event("delegation", "subagent-stop", **kwargs)
    child_status = _text(kwargs.get("child_status"))
    if child_status:
        event["status"] = child_status
    parent = _text(kwargs.get("parent_session_id")) or _text(kwargs.get("session_id"))
    child = _text(kwargs.get("child_session_id")) or _text(kwargs.get("subagent_session_id"))
    if parent:
        event["session_id"] = parent
        event["parent_session_id"] = parent
    if child:
        event["child_session_id"] = child
        scope = _scope()
        if not scope.delegation_lock.acquire(blocking=False):
            raise _MeasurementUnavailable()
        try:
            scope.pending_delegations.pop(child, None)
        finally:
            scope.delegation_lock.release()
    duration = _number(kwargs.get("duration_ms"))
    if duration is not None:
        event["duration_ms"] = duration
    _writer().emit(event)


def register(ctx: Any) -> None:
    global _WRITER
    # Hermes pre-tool hooks fail closed on exceptions. All callbacks must be
    # neutral even when instrumentation is unavailable or malformed.
    try:
        scope = _Scope(_hermes_home())
        _SCOPES.append(scope)
        token = _CURRENT_SCOPE.set(scope)
        try:
            scope.writer = _Writer(scope)
            _WRITER = scope.writer  # legacy direct-embedding diagnostic handle
        finally:
            _CURRENT_SCOPE.reset(token)
    except Exception:
        return None

    def bind(callback):
        def observe(**kwargs: Any) -> None:
            if scope.closed:
                return None
            token = _CURRENT_SCOPE.set(scope)
            try:
                callback(**kwargs)
            except Exception:
                if scope.writer is not None:
                    scope.writer.dropped += 1
            finally:
                _CURRENT_SCOPE.reset(token)
            return None
        return observe

    for name, callback in (
        ("pre_api_request", on_pre_api_request),
        ("post_api_request", on_post_api_request),
        ("api_request_error", on_api_request_error),
        ("pre_tool_call", on_pre_tool_call),
        ("post_tool_call", on_post_tool_call),
        ("transform_terminal_output", transform_terminal_output),
        ("subagent_start", on_subagent_start),
        ("subagent_stop", on_subagent_stop),
        ("on_session_start", on_session_start),
        ("on_session_end", on_session_end),
        ("on_session_finalize", on_session_finalize),
    ):
        if name == "pre_tool_call" and scope.pre_tool_observation != "registered":
            continue
        ctx.register_hook(name, bind(callback))
    if callable(getattr(ctx, "on_unload", None)):
        ctx.on_unload(lambda: _close_scope(scope))
