"""Bounded Prometheus exporter owned by the Gateway Manager.

Two independent signal sources land in one registry:

* Manager HTTP outcomes (`zc_*`), counted exactly once per application request
  right after dispatch and before the response is written.
* A bounded re-export of per-daemon native counters (`zeroclaw_*`), polled from
  each child's loopback ``/metrics`` and labelled by an opaque ``daemon_slot``.

Everything here is deliberately closed-world: routes, error codes, components,
collection-failure reasons and the native allowlist are fixed sets. Nothing that
a model, a user or a remote process can influence ever becomes a label value —
Fly drops high-cardinality custom metrics silently, and a silent drop reads as
"zero errors", which is the exact lie this whole subsystem exists to prevent.
"""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import threading
import time
from typing import Callable, Iterator
import urllib.error
import urllib.request

from prometheus_client import CollectorRegistry, Counter, Gauge, generate_latest
from prometheus_client.core import CounterMetricFamily
from prometheus_client.parser import text_string_to_metric_families

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"

# ── closed-world label domains ───────────────────────────────────────────────

ROUTES: tuple[str, ...] = ("webhook", "upload", "pair", "warmup", "other")
OUTCOMES: tuple[str, ...] = ("success", "error")
#: Routes that get the full error catalog pre-initialised. The report only ever
#: divides by `webhook`; `upload` is shown separately; the rest are excluded, so
#: they only need the `unknown` fallback series.
REPORTED_ROUTES: tuple[str, ...] = ("webhook", "upload")

UNKNOWN = "unknown"

COMPONENTS: tuple[str, ...] = ("daemon", "manager", "provider", "request")

COLLECTION_FAILURE_REASONS: tuple[str, ...] = (
    "timeout",
    "http",
    "disabled",
    "parse",
    "budget",
    "family",
    "label",
    "internal",
)

REPORT_OUTCOMES: tuple[str, ...] = (
    "built",
    "query_failed",
    "send_failed",
    "accepted",
)

#: `component` is a function of the error code, never an independent axis.
#: Sources: `_CANONICAL_CHILD_ERRORS` in gateway_manager.py (child-echoed typed
#: errors) plus every Manager-classified `_manager_error`/`build_error_payload`
#: emit site. `tests/test_zeroclaw_metrics.py` re-derives both halves from the
#: manager source, so a new emit site fails the build instead of silently
#: degrading to `unknown`.
ERROR_CATALOG: dict[str, str] = {
    # canonical child errors — request
    "invalid_request": "request",
    "gateway_auth_failed": "request",
    "webhook_rate_limited": "request",
    "gateway_auth_rate_limited": "request",
    "unknown_agent": "request",
    "invalid_model": "request",
    "missing_model": "request",
    "missing_provider": "request",
    "unknown_provider": "request",
    # canonical child errors — daemon
    "previous_turn_stuck": "daemon",
    "provider_not_configured": "daemon",
    "daemon_internal_error": "daemon",
    # canonical child errors — provider
    "provider_initialization_failed": "provider",
    "vision_not_supported": "provider",
    "vision_provider_misconfigured": "provider",
    "provider_auth_failed": "provider",
    "provider_rate_limited": "provider",
    "provider_quota_exhausted": "provider",
    "provider_timeout": "provider",
    "provider_unavailable": "provider",
    "provider_model_not_found": "provider",
    "context_window_exceeded": "provider",
    "provider_request_rejected": "provider",
    "provider_error": "provider",
    # canonical child errors — manager-owned forwarding failures
    "child_unreachable": "manager",
    "gateway_timeout": "manager",
    # Manager-only codes
    "upstream_error": "daemon",
    "upload_rejected": "request",
    "upload_failed": "manager",
    "manager_internal_error": "manager",
    "daemon_start_failed": "manager",
    "daemon_capacity_exceeded": "manager",
}

# ── native allowlist ─────────────────────────────────────────────────────────

NATIVE_HEARTBEAT = "zeroclaw_heartbeat_ticks_total"
NATIVE_ERRORS = "zeroclaw_errors_total"
#: Only these `component` values are re-exported. An unexpected *value* of a
#: known label is dropped silently — `zeroclaw-log::observer_bridge` can project
#: `component="system"`, and a legitimate third producer must not make every
#: healthy scrape look like a collection failure.
NATIVE_ERROR_COMPONENTS: frozenset[str] = frozenset({"gateway", "heartbeat"})

MAX_BODY_BYTES = 1024 * 1024
MAX_SAMPLES = 10_000
DEFAULT_POLL_INTERVAL_SECS = 15.0
DEFAULT_TARGET_TIMEOUT_SECS = 2.0
DEFAULT_CYCLE_DEADLINE_SECS = 3.0
DEFAULT_STALE_SECS = 45.0
DEFAULT_EXPORTER_PORT = 2999


class ExporterConfigError(RuntimeError):
    """Raised at startup for a configuration that cannot be made safe."""


def validate_exporter_port(*, exporter_port: int, manager_base_port: int) -> None:
    """Reject an exporter port that could collide with the child allocator.

    `GatewayRegistry._allocate_port` only ever increments, and
    `recover_from_workspaces` seeds `_next_port` at `manager_base_port - 1 + 1`,
    so any port below the base is unreachable by construction. That is a
    property of the current base port, not a law: validate it so a changed
    `ZEROCLAW_MANAGER_BASE_PORT` fails loudly instead of silently handing the
    exporter port to a daemon.
    """
    if exporter_port < 1 or exporter_port > 65535:
        raise ExporterConfigError(f"exporter port out of range: {exporter_port}")
    if exporter_port >= manager_base_port:
        raise ExporterConfigError(
            "exporter port must stay below the child port range: "
            f"{exporter_port} >= manager_base_port {manager_base_port}"
        )


# ── target DTO ───────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class DaemonTarget:
    """Detached snapshot of one registered daemon.

    Deliberately immutable and value-only: the exporter must never hold a live
    `DaemonInstance`, and must never do network I/O while the registry lock is
    held.
    """

    user_key: str
    port: int
    pid: int
    started_at: float
    process_running: bool


@dataclass(slots=True)
class _NativeSnapshot:
    heartbeat_ticks: float
    errors: dict[str, float]


@dataclass(slots=True)
class _SlotState:
    user_key: str | None = None
    port: int = 0
    pid: int = 0
    started_at: float = 0.0
    expected: bool = False
    up: bool = False
    last_success: float = 0.0
    restarts: float = 0.0
    snapshot: _NativeSnapshot | None = None
    generation: int = 0
    in_flight: bool = False


class _NativeCollector:
    """Serves the per-slot native re-export from a frozen snapshot."""

    def __init__(self, exporter: "MetricsExporter") -> None:
        self._exporter = exporter

    def collect(self) -> Iterator[CounterMetricFamily]:
        heartbeat = CounterMetricFamily(
            "zeroclaw_heartbeat_ticks",
            "Child daemon heartbeat ticks (re-exported by the Gateway Manager)",
            labels=["daemon_slot"],
        )
        errors = CounterMetricFamily(
            "zeroclaw_errors",
            "Child daemon terminal errors (re-exported by the Gateway Manager)",
            labels=["daemon_slot", "component"],
        )
        for slot, snapshot in self._exporter.native_samples():
            heartbeat.add_metric([slot], snapshot.heartbeat_ticks)
            for component, value in sorted(snapshot.errors.items()):
                errors.add_metric([slot, component], value)
        yield heartbeat
        yield errors


class MetricsExporter:
    """Owns the Manager's Prometheus registry, child polling and the listener."""

    def __init__(
        self,
        *,
        targets_provider: Callable[[], list[DaemonTarget]],
        max_instances: int,
        child_host: str = "127.0.0.1",
        state_path: Path | None = None,
        poll_interval_secs: float = DEFAULT_POLL_INTERVAL_SECS,
        target_timeout_secs: float = DEFAULT_TARGET_TIMEOUT_SECS,
        cycle_deadline_secs: float = DEFAULT_CYCLE_DEADLINE_SECS,
        stale_secs: float = DEFAULT_STALE_SECS,
        clock: Callable[[], float] = time.time,
        fetch: Callable[[str, float], bytes] | None = None,
    ) -> None:
        if max_instances < 1:
            raise ExporterConfigError(
                f"max_instances must be >= 1 for a bounded worker pool: {max_instances}"
            )
        self._targets_provider = targets_provider
        self._max_instances = max_instances
        self._child_host = child_host
        self._state_path = state_path
        self._poll_interval = poll_interval_secs
        self._target_timeout = target_timeout_secs
        self._cycle_deadline = cycle_deadline_secs
        self._stale_secs = stale_secs
        self._clock = clock
        self._fetch = fetch or _http_get
        self._lock = threading.Lock()
        self._slots: list[_SlotState] = [
            _SlotState() for _ in range(max_instances)
        ]
        self._generation = 0
        self._snapshot_ts = 0.0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._httpd: ThreadingHTTPServer | None = None
        self._http_thread: threading.Thread | None = None
        # The pool is sized once from max_instances, NOT from len(targets):
        # after a cold boot there are zero targets, and a per-cycle
        # `max_workers=len(targets)` would raise on 0.
        self._pool = ThreadPoolExecutor(
            max_workers=max_instances, thread_name_prefix="zc-metrics"
        )

        self.registry = CollectorRegistry()
        self._build_metrics()
        self.registry.register(_NativeCollector(self))
        self.manager_start_time.set(self._clock())

    # ── metric construction ──────────────────────────────────────────────

    def _build_metrics(self) -> None:
        reg = self.registry
        self.http_requests = Counter(
            "zc_http_requests_total",
            "Gateway Manager HTTP requests by route and final outcome",
            ["route", "outcome"],
            registry=reg,
        )
        self.http_errors = Counter(
            "zc_http_errors_total",
            "Gateway Manager HTTP errors by canonical code",
            ["route", "error_code", "component"],
            registry=reg,
        )
        self.response_write_failures = Counter(
            "zc_http_response_write_failures_total",
            "Failures writing an already-built response",
            ["route"],
            registry=reg,
        )
        self.daemon_expected = Gauge(
            "zc_daemon_expected",
            "1 when a daemon slot holds a registered target",
            ["daemon_slot"],
            registry=reg,
        )
        self.daemon_scrape_up = Gauge(
            "zc_daemon_scrape_up",
            "1 when the slot produced a fresh parseable child scrape",
            ["daemon_slot"],
            registry=reg,
        )
        self.daemon_last_success = Gauge(
            "zc_daemon_last_success_timestamp_seconds",
            "Unix time of the last successful child poll for the slot",
            ["daemon_slot"],
            registry=reg,
        )
        self.daemon_process_start = Gauge(
            "zc_daemon_process_start_time_seconds",
            "Start time of the process occupying the slot, 0 when inactive",
            ["daemon_slot"],
            registry=reg,
        )
        self.daemon_restarts = Counter(
            "zc_daemon_restarts_total",
            "Process replacements observed in the slot while the Manager lived",
            ["daemon_slot"],
            registry=reg,
        )
        self.exporter_up = Gauge(
            "zc_metrics_exporter_up",
            "1 while the poll worker is updating the snapshot",
            registry=reg,
        )
        self.snapshot_timestamp = Gauge(
            "zc_metrics_snapshot_timestamp_seconds",
            "Unix time of the last completed poll cycle",
            registry=reg,
        )
        self.manager_start_time = Gauge(
            "zc_metrics_manager_start_time_seconds",
            "Gateway Manager start time — counter reset boundary",
            registry=reg,
        )
        self.collection_failures = Counter(
            "zc_metrics_collection_failures_total",
            "Child collection failures by bounded reason",
            ["reason"],
            registry=reg,
        )
        self.report_runs = Counter(
            "zc_error_report_runs_total",
            "Daily error report runs by outcome",
            ["outcome"],
            registry=reg,
        )
        self.report_last_accepted = Gauge(
            "zc_error_report_last_accepted_timestamp_seconds",
            "Unix time the bot accepted the last report send",
            registry=reg,
        )
        self._preinit()

    def _preinit(self) -> None:
        """Create every series that can ever exist, before the first request.

        A missing series and a zero series look identical downstream once
        `increase()` runs, so the whole closed world is materialised up front and
        `tests/test_zeroclaw_metrics.py` asserts the exact set size.
        """
        for route in ROUTES:
            for outcome in OUTCOMES:
                self.http_requests.labels(route=route, outcome=outcome)
            self.response_write_failures.labels(route=route)
            self.http_errors.labels(
                route=route, error_code=UNKNOWN, component=UNKNOWN
            )
        for route in REPORTED_ROUTES:
            for code, component in ERROR_CATALOG.items():
                self.http_errors.labels(
                    route=route, error_code=code, component=component
                )
        for reason in COLLECTION_FAILURE_REASONS:
            self.collection_failures.labels(reason=reason)
        for outcome in REPORT_OUTCOMES:
            self.report_runs.labels(outcome=outcome)
        for slot in range(self._max_instances):
            key = _slot_label(slot)
            self.daemon_expected.labels(daemon_slot=key).set(0)
            self.daemon_scrape_up.labels(daemon_slot=key).set(0)
            self.daemon_last_success.labels(daemon_slot=key).set(0)
            self.daemon_process_start.labels(daemon_slot=key).set(0)
            self.daemon_restarts.labels(daemon_slot=key)

    # ── HTTP instrumentation ─────────────────────────────────────────────

    def record_http(
        self,
        *,
        path: str,
        status_code: int,
        payload: dict[str, object] | None,
    ) -> None:
        """Count one application request. Called exactly once, after dispatch."""
        route = route_for_path(path)
        code = None
        component = None
        if isinstance(payload, dict):
            raw_code = payload.get("error_code")
            raw_component = payload.get("component")
            if isinstance(raw_code, str):
                code = raw_code
            if isinstance(raw_component, str):
                component = raw_component
        is_error = status_code >= 400 or code is not None
        self.http_requests.labels(
            route=route, outcome="error" if is_error else "success"
        ).inc()
        if not is_error:
            return
        if route not in REPORTED_ROUTES:
            # Routes outside the report only ever carry `unknown`. Resolving the
            # catalog here would mint a new series on first use, so the live
            # exposition would drift above the pre-initialised set — exactly the
            # silent growth Fly may drop. Measured on 2026-09-07: a stray request
            # to an unknown path created ("other", "invalid_request", "request")
            # in production and pushed the count from 69 to 70.
            self.http_errors.labels(
                route=route, error_code=UNKNOWN, component=UNKNOWN
            ).inc()
            return
        catalog_component = ERROR_CATALOG.get(code or "")
        if catalog_component is None:
            label_code, label_component = UNKNOWN, UNKNOWN
        else:
            label_code = code or UNKNOWN
            # The catalog owns the pairing: an emit site that drifts to another
            # component must not create a new series.
            label_component = catalog_component
            if component is not None and component != catalog_component:
                label_code, label_component = UNKNOWN, UNKNOWN
        self.http_errors.labels(
            route=route, error_code=label_code, component=label_component
        ).inc()

    def record_response_write_failure(self, *, path: str) -> None:
        self.response_write_failures.labels(route=route_for_path(path)).inc()

    def record_report_run(self, outcome: str) -> None:
        if outcome not in REPORT_OUTCOMES:
            return
        self.report_runs.labels(outcome=outcome).inc()
        if outcome == "accepted":
            self.report_last_accepted.set(self._clock())

    # ── child polling ────────────────────────────────────────────────────

    def native_samples(self) -> list[tuple[str, _NativeSnapshot]]:
        out: list[tuple[str, _NativeSnapshot]] = []
        with self._lock:
            for index, slot in enumerate(self._slots):
                if slot.snapshot is not None and slot.up:
                    out.append((_slot_label(index), slot.snapshot))
        return out

    def poll_once(self) -> None:
        try:
            targets = self._targets_provider()
        except Exception:
            self._record_failure("internal")
            targets = []
        pending: list[tuple[int, int, int, int]] = []
        with self._lock:
            self._generation += 1
            generation = self._generation
            self._sync_slots(targets)
            for index, slot in enumerate(self._slots):
                if not slot.expected or slot.in_flight:
                    continue
                slot.in_flight = True
                slot.generation = generation
                pending.append((index, slot.port, slot.pid, generation))
        futures: list[Future[None]] = [
            self._pool.submit(self._poll_target, index, port, pid, generation)
            for index, port, pid, generation in pending
        ]
        if futures:
            # Bounded wait only. Stragglers keep their slot busy (so the next
            # cycle does not pile a second poll onto the same target) and are
            # rejected on arrival by the generation/pid check.
            wait(futures, timeout=self._cycle_deadline)
        with self._lock:
            self._expire_stale(self._clock())
            self._snapshot_ts = self._clock()
            self._publish_locked()
        self.snapshot_timestamp.set(self._snapshot_ts)

    def _sync_slots(self, targets: list[DaemonTarget]) -> None:
        """Caller holds the lock."""
        by_user = {
            index: slot.user_key
            for index, slot in enumerate(self._slots)
            if slot.user_key is not None
        }
        seen: set[int] = set()
        for target in targets:
            index = next(
                (i for i, key in by_user.items() if key == target.user_key), None
            )
            if index is None:
                index = self._free_slot_locked(seen)
                if index is None:
                    self._record_failure_locked("budget")
                    continue
                self._reset_slot_locked(index)
                self._slots[index].user_key = target.user_key
                by_user[index] = target.user_key
            slot = self._slots[index]
            replaced = slot.expected and (
                slot.pid != target.pid or slot.started_at != target.started_at
            )
            if replaced:
                slot.restarts += 1
                slot.snapshot = None
                slot.up = False
                slot.last_success = 0.0
            slot.port = target.port
            slot.pid = target.pid
            slot.started_at = target.started_at
            slot.expected = True
            seen.add(index)
        for index, slot in enumerate(self._slots):
            if index in seen or slot.user_key is None:
                continue
            # Tombstone: the slot keeps its identity so a returning user lands
            # back on it (and a pid change then reads as a restart), but stops
            # advertising native samples.
            slot.expected = False
            slot.up = False
            slot.snapshot = None
            slot.started_at = 0.0

    def _free_slot_locked(self, seen: set[int]) -> int | None:
        for index, slot in enumerate(self._slots):
            if index in seen:
                continue
            if slot.user_key is None:
                return index
        for index, slot in enumerate(self._slots):
            if index in seen:
                continue
            if not slot.expected:
                return index
        return None

    def _reset_slot_locked(self, index: int) -> None:
        slot = self._slots[index]
        slot.user_key = None
        slot.port = 0
        slot.pid = 0
        slot.started_at = 0.0
        slot.expected = False
        slot.up = False
        slot.last_success = 0.0
        slot.snapshot = None

    def _poll_target(
        self, index: int, port: int, pid: int, generation: int
    ) -> None:
        snapshot: _NativeSnapshot | None = None
        reason: str | None = None
        try:
            url = f"http://{self._child_host}:{port}/metrics"
            body = self._fetch(url, self._target_timeout)
            if len(body) > MAX_BODY_BYTES:
                reason = "budget"
            else:
                snapshot, reason = _parse_child_exposition(body)
        except TimeoutError:
            reason = "timeout"
        except urllib.error.URLError as exc:
            reason = "timeout" if isinstance(exc.reason, TimeoutError) else "http"
        except OSError:
            reason = "http"
        except Exception:
            reason = "internal"
        now = self._clock()
        with self._lock:
            slot = self._slots[index]
            slot.in_flight = False
            stale_result = (
                slot.generation != generation
                or slot.pid != pid
                or not slot.expected
            )
            if stale_result:
                return
            if snapshot is not None:
                slot.snapshot = snapshot
                slot.up = True
                slot.last_success = now
            else:
                slot.up = False
                slot.snapshot = None
                if reason is not None:
                    self._record_failure_locked(reason)
                    self._write_state_locked(index, reason)

    def _expire_stale(self, now: float) -> None:
        """Caller holds the lock."""
        for slot in self._slots:
            if not slot.expected:
                continue
            if slot.up and now - slot.last_success > self._stale_secs:
                slot.up = False
                slot.snapshot = None

    def _publish_locked(self) -> None:
        for index, slot in enumerate(self._slots):
            key = _slot_label(index)
            self.daemon_expected.labels(daemon_slot=key).set(
                1 if slot.expected else 0
            )
            self.daemon_scrape_up.labels(daemon_slot=key).set(1 if slot.up else 0)
            self.daemon_last_success.labels(daemon_slot=key).set(slot.last_success)
            self.daemon_process_start.labels(daemon_slot=key).set(
                slot.started_at if slot.expected else 0.0
            )
            current = self.daemon_restarts.labels(daemon_slot=key)
            delta = slot.restarts - current._value.get()
            if delta > 0:
                current.inc(delta)

    def _record_failure(self, reason: str) -> None:
        with self._lock:
            self._record_failure_locked(reason)

    def _record_failure_locked(self, reason: str) -> None:
        if reason not in COLLECTION_FAILURE_REASONS:
            reason = "internal"
        self.collection_failures.labels(reason=reason).inc()

    def _write_state_locked(self, index: int, reason: str) -> None:
        """Bounded, atomic, label-free breadcrumb for the last failure.

        Never a JSONL append and never a place for a raw family name, a label
        value, a URL, a token or a user id — only the slot index and the enum.
        """
        if self._state_path is None:
            return
        payload = {
            "timestamp": round(self._clock(), 3),
            "daemon_slot": _slot_label(index),
            "reason": reason if reason in COLLECTION_FAILURE_REASONS else "internal",
            "family": NATIVE_ERRORS if reason in ("family", "label") else "unknown",
        }
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._state_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            os.replace(tmp, self._state_path)
        except OSError:
            pass

    # ── lifecycle ────────────────────────────────────────────────────────

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
                self.exporter_up.set(1)
            except Exception:
                # A dead worker must stop advancing the snapshot timestamp so
                # the reporter marks the interval as a gap. Never claim
                # self-heal that is not tested.
                self.exporter_up.set(0)
                self._record_failure("internal")
            self._stop.wait(self._poll_interval)
        self.exporter_up.set(0)

    def start_worker(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._loop, name="zc-metrics-worker", daemon=True
        )
        self._thread.start()

    def render(self) -> bytes:
        return generate_latest(self.registry)

    def start_listener(self, host: str, port: int) -> int:
        exporter = self

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                if self.path != "/metrics":
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = exporter.render()
                self.send_response(200)
                self.send_header("Content-Type", CONTENT_TYPE)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, _fmt: str, *_args: object) -> None:
                return

        httpd = ThreadingHTTPServer((host, port), _Handler)
        httpd.daemon_threads = True
        self._httpd = httpd
        self._http_thread = threading.Thread(
            target=httpd.serve_forever, name="zc-metrics-http", daemon=True
        )
        self._http_thread.start()
        return int(httpd.server_address[1])

    def stop(self) -> None:
        self._stop.set()
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        self._pool.shutdown(wait=False)


# ── helpers ──────────────────────────────────────────────────────────────────


def _slot_label(index: int) -> str:
    return f"{index:02d}"


def route_for_path(path: str) -> str:
    route = (path or "").split("?", 1)[0].strip("/")
    return route if route in ROUTES else "other"


def _http_get(url: str, timeout: float) -> bytes:
    deadline = time.monotonic() + timeout
    with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_BODY_BYTES:
            if time.monotonic() > deadline:
                raise TimeoutError("child metrics body read exceeded deadline")
            chunk = response.read(65536)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    return b"".join(chunks)


def _parse_child_exposition(body: bytes) -> tuple[_NativeSnapshot | None, str | None]:
    """Return (snapshot, failure_reason).

    Non-selected families are ignored without penalty. Inside a *selected*
    family, an unexpected label NAME / a missing expected label / unparseable
    structure is a bounded `label`/`parse` failure; an unexpected VALUE of a
    known label is dropped as silently as a non-selected family.
    """
    if len(body) > MAX_BODY_BYTES:
        return None, "budget"
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None, "parse"
    heartbeat: float | None = None
    errors: dict[str, float] = {}
    seen_samples = 0
    try:
        families = list(text_string_to_metric_families(text))
    except Exception:
        return None, "parse"
    for family in families:
        selected = _select_family(family.name)
        if selected is None:
            continue
        for sample in family.samples:
            seen_samples += 1
            if seen_samples > MAX_SAMPLES:
                return None, "budget"
            if selected == "heartbeat":
                if sample.name != NATIVE_HEARTBEAT:
                    continue
                if sample.labels:
                    return None, "label"
                heartbeat = float(sample.value)
            else:
                if sample.name != NATIVE_ERRORS:
                    continue
                if set(sample.labels) != {"component"}:
                    return None, "label"
                component = sample.labels["component"]
                if component not in NATIVE_ERROR_COMPONENTS:
                    continue
                errors[component] = float(sample.value)
    if heartbeat is None:
        # A disabled backend answers HTTP 200 with a hint comment and no
        # families at all. That is not a successful scrape.
        return None, "disabled"
    return _NativeSnapshot(heartbeat_ticks=heartbeat, errors=errors), None


def _select_family(name: str) -> str | None:
    base = name[: -len("_total")] if name.endswith("_total") else name
    if base == "zeroclaw_heartbeat_ticks":
        return "heartbeat"
    if base == "zeroclaw_errors":
        return "errors"
    return None
