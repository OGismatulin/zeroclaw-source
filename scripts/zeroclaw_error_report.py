"""Deterministic daily error report over Fly managed Prometheus.

The whole point of this script is the difference between "zero errors" and "we
did not look". Every number it prints is either backed by samples at both edges
of the window or is reported as `не измерено`. A missing family, a Manager
restart, an exporter gap or a failed query degrade the *completeness* line; they
never silently become 0.

Modes:

    zeroclaw_error_report.py --date 2026-09-06 --dry-run   # build, print, no state
    zeroclaw_error_report.py --date 2026-09-06 --send      # build, deliver, receipt
    zeroclaw_error_report.py --serve                       # 07:00 Asia/Bishkek worker
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import time
from typing import Callable, Sequence
import urllib.error
import urllib.request
from zoneinfo import ZoneInfo

DEFAULT_TIMEZONE = "Asia/Bishkek"
DEFAULT_SEND_HOUR = 7
DEFAULT_CATCHUP_UNTIL_HOUR = 10
DEFAULT_QUERY_TIMEOUT_SECS = 5.0
DEFAULT_QUERY_RETRIES = 2
DEFAULT_TOTAL_BUDGET_SECS = 60.0
#: Nominal exporter cadence. The real one is measured from the range vectors and
#: only falls back to this when there are too few points to measure.
DEFAULT_CADENCE_SECS = 15.0
STALE_FLOOR_SECS = 45.0
MAX_REPORT_CHARS = 3500
MAX_ERROR_ROWS = 12

RECEIPT_KINDS = ("report", "unavailable_notice")
RECEIPT_STATES = ("pending", "sending", "accepted", "failed", "unknown")


# ── window ───────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Window:
    date: dt.date
    timezone: str
    start_utc: dt.datetime
    end_utc: dt.datetime

    @property
    def duration_secs(self) -> int:
        return int((self.end_utc - self.start_utc).total_seconds())

    @property
    def range_selector(self) -> str:
        return f"{self.duration_secs}s"


def window_for_date(date: dt.date, tz: ZoneInfo) -> Window:
    """`[D 00:00, D+1 00:00)` in `tz`, converted to UTC.

    Computed through `zoneinfo`, never as `date ± fixed offset`: a DST or
    offset change makes the day 23 or 25 hours long, and a hard-coded offset
    would silently shift the whole report by an hour.
    """
    start_local = dt.datetime.combine(date, dt.time(0, 0), tzinfo=tz)
    end_local = dt.datetime.combine(
        date + dt.timedelta(days=1), dt.time(0, 0), tzinfo=tz
    )
    return Window(
        date=date,
        timezone=str(tz),
        start_utc=start_local.astimezone(dt.timezone.utc),
        end_utc=end_local.astimezone(dt.timezone.utc),
    )


# ── query client ─────────────────────────────────────────────────────────────


class QueryError(RuntimeError):
    def __init__(self, kind: str, detail: str = "") -> None:
        super().__init__(f"{kind}: {detail}" if detail else kind)
        self.kind = kind


def _validate_selector_value(value: str) -> str:
    """Selector values come from configuration, never from user input."""
    if not value or len(value) > 64:
        raise QueryError("selector", "empty or oversized selector value")
    for char in value:
        if not (char.isalnum() or char in "-_."):
            raise QueryError("selector", "selector value outside the allowlist")
    return value


class MetricsClient:
    """Read-only MetricsQL client with a bounded retry budget."""

    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        app: str,
        timeout_secs: float = DEFAULT_QUERY_TIMEOUT_SECS,
        retries: int = DEFAULT_QUERY_RETRIES,
        total_budget_secs: float = DEFAULT_TOTAL_BUDGET_SECS,
        fetch: Callable[[str, dict[str, str], dict[str, str], float], bytes]
        | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._token = token
        self.app = _validate_selector_value(app)
        self._timeout = timeout_secs
        self._retries = retries
        self._budget = total_budget_secs
        self._fetch = fetch or _http_get_json
        self._clock = clock
        self._sleep = sleep
        self._started = clock()

    def base_matcher(self) -> str:
        return f'app="{self.app}"'

    def _remaining(self) -> float:
        return self._budget - (self._clock() - self._started)

    @staticmethod
    def _authorization(token: str) -> str:
        """Fly org and read-only tokens carry their own scheme.

        `fly tokens create readonly` returns a macaroon that already starts with
        `FlyV1 `, and wrapping it in `Bearer` produces `Bearer FlyV1 ...`, which
        the metrics API rejects with 401. Measured against the live API on
        2026-09-07: `Bearer <macaroon>` -> 401, the macaroon verbatim -> 200.
        A full-access token (`fo1_...`) has no scheme and still needs `Bearer`.
        """
        candidate = token.strip()
        for scheme in ("FlyV1 ", "Bearer ", "FlyV1fm2_"):
            if candidate.startswith(scheme):
                return candidate
        return f"Bearer {candidate}"

    def _call(self, endpoint: str, params: dict[str, str]) -> dict:
        headers = {"Authorization": self._authorization(self._token)}
        attempt = 0
        while True:
            if self._remaining() <= 0:
                raise QueryError("timeout", "report budget exhausted")
            try:
                raw = self._fetch(
                    f"{self.base_url}{endpoint}",
                    params,
                    headers,
                    min(self._timeout, max(self._remaining(), 0.1)),
                )
                payload = json.loads(raw.decode("utf-8"))
            except QueryError as exc:
                # Auth is never retried: repeating a rejected credential cannot
                # start working, and a retry loop on 401 looks like an outage.
                if exc.kind == "auth" or attempt >= self._retries:
                    raise
                attempt += 1
                self._sleep(min(0.5 * attempt, self._remaining()))
                continue
            except (ValueError, urllib.error.URLError, OSError) as exc:
                if attempt >= self._retries:
                    raise QueryError("http", exc.__class__.__name__) from exc
                attempt += 1
                self._sleep(min(0.5 * attempt, self._remaining()))
                continue
            if payload.get("status") != "success":
                raise QueryError("parse", "response status is not success")
            return payload.get("data", {})

    def query(self, expr: str, at: dt.datetime) -> list[dict]:
        data = self._call(
            "/api/v1/query",
            {"query": expr, "time": _unix(at)},
        )
        return list(data.get("result", []))

    def query_range(
        self, expr: str, start: dt.datetime, end: dt.datetime, step_secs: float
    ) -> list[dict]:
        data = self._call(
            "/api/v1/query_range",
            {
                "query": expr,
                "start": _unix(start),
                "end": _unix(end),
                "step": str(int(max(step_secs, 1))),
            },
        )
        return list(data.get("result", []))


def _unix(moment: dt.datetime) -> str:
    return str(int(moment.timestamp()))


def _http_get_json(
    url: str, params: dict[str, str], headers: dict[str, str], timeout: float
) -> bytes:
    from urllib.parse import urlencode

    request = urllib.request.Request(
        f"{url}?{urlencode(params)}", headers=headers, method="GET"
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.read()
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise QueryError("auth", str(exc.code)) from exc
        raise QueryError("http", str(exc.code)) from exc
    except TimeoutError as exc:
        raise QueryError("timeout", "query timed out") from exc


# ── completeness ─────────────────────────────────────────────────────────────

COMPLETE = "полное"
INCOMPLETE = "неполное"
NO_DATA = "нет данных"


@dataclass(slots=True)
class Completeness:
    http: str = NO_DATA
    native: str = NO_DATA
    reasons: list[str] = field(default_factory=list)
    cadence_secs: float = DEFAULT_CADENCE_SECS

    def note(self, reason: str) -> None:
        if reason not in self.reasons:
            self.reasons.append(reason)


def _series_points(series: dict) -> list[tuple[float, float]]:
    points: list[tuple[float, float]] = []
    for raw_ts, raw_value in series.get("values", []):
        try:
            points.append((float(raw_ts), float(raw_value)))
        except (TypeError, ValueError):
            continue
    return points


def measure_cadence(points: Sequence[tuple[float, float]]) -> float:
    """Cadence measured from the samples, not assumed from configuration."""
    deltas: list[float] = []
    previous_value: float | None = None
    previous_ts: float | None = None
    for timestamp, value in points:
        if previous_value is not None and value != previous_value:
            if previous_ts is not None:
                deltas.append(timestamp - previous_ts)
            previous_ts = timestamp
        elif previous_value is None:
            previous_ts = timestamp
        previous_value = value
    if not deltas:
        return DEFAULT_CADENCE_SECS
    deltas.sort()
    return max(deltas[len(deltas) // 2], 1.0)


def assess_completeness(
    *,
    snapshot_series: list[dict],
    manager_start_series: list[dict],
    daemon_expected: list[dict],
    daemon_up: list[dict],
    daemon_last_success: list[dict],
    daemon_start: list[dict],
    window: Window,
) -> Completeness:
    """HTTP and native completeness are computed separately.

    A child restart corrupts only the native reconciliation; the Manager's own
    counter kept running. A Manager restart or an exporter gap corrupts both.
    """
    result = Completeness()
    if not snapshot_series:
        result.note("нет серий exporter'а за окно")
        return result

    instances = {_instance_of(series) for series in snapshot_series}
    if len(instances) > 1:
        result.note(f"несколько instance: {len(instances)} — не суммируются")

    http_ok = True
    for series in snapshot_series:
        points = _series_points(series)
        if len(points) < 2:
            result.note("слишком мало точек exporter'а для проверки непрерывности")
            http_ok = False
            continue
        cadence = measure_cadence(points)
        result.cadence_secs = cadence
        if points[0][0] > window.start_utc.timestamp() + 3 * cadence:
            result.note("нет данных на левом крае окна")
            http_ok = False
        if points[-1][0] < window.end_utc.timestamp() - 3 * cadence:
            result.note("нет данных на правом крае окна")
            http_ok = False
        # Two different holes, and only the first one used to be detected.
        # (a) The exporter is alive but its snapshot stopped advancing.
        for timestamp, value in points:
            if timestamp - value > 3 * cadence:
                result.note("разрыв наблюдения exporter'а")
                http_ok = False
                break
        # (b) The samples themselves stop: the app died, the scrape failed, the
        # series vanished. Prometheus simply has fewer points, the edges still
        # match, and the window reads "complete" — the exact false green this
        # report exists to prevent.
        for previous, current in zip(points, points[1:]):
            if current[0] - previous[0] > 3 * cadence:
                gap = int(current[0] - previous[0])
                result.note(f"пропуск samples {gap} с")
                http_ok = False
                break

    for series in manager_start_series:
        values = {value for _ts, value in _series_points(series)}
        if len(values) > 1:
            result.note("Manager перезапускался — счётчики сброшены")
            http_ok = False

    if not manager_start_series:
        result.note("нет отметки старта Manager — базовая линия неизвестна")
        http_ok = False

    result.http = COMPLETE if http_ok else INCOMPLETE

    native_ok = http_ok
    if not daemon_expected:
        result.note("нет данных о зарегистрированных daemon")
        native_ok = False
    expected_slots = {
        _slot_of(series)
        for series in daemon_expected
        if any(value > 0 for _ts, value in _series_points(series))
    }
    up_by_slot = {_slot_of(series): _series_points(series) for series in daemon_up}
    last_success_by_slot = {
        _slot_of(series): _series_points(series) for series in daemon_last_success
    }
    stale_limit = max(STALE_FLOOR_SECS, 3 * result.cadence_secs)
    if expected_slots and not daemon_start:
        # Without daemon start times a restart is undetectable, so native
        # reconciliation has no baseline. Absent input is "not measured", never
        # a pass.
        result.note("нет времени старта daemon — база сверки неизвестна")
        native_ok = False
    for slot in sorted(expected_slots):
        up_points = up_by_slot.get(slot, [])
        if not up_points or any(value < 1 for _ts, value in up_points):
            result.note(f"слот {slot}: наблюдение daemon прерывалось")
            native_ok = False
        success_points = last_success_by_slot.get(slot, [])
        if not success_points:
            result.note(f"слот {slot}: нет отметок последнего успешного опроса")
            native_ok = False
        for timestamp, value in success_points:
            if timestamp - value > stale_limit:
                result.note(f"слот {slot}: устаревший снимок daemon")
                native_ok = False
                break

    for series in daemon_start:
        values = {
            value for _ts, value in _series_points(series) if value > 0
        }
        if len(values) > 1:
            result.note("daemon перезапускался — native-счётчики сброшены")
            native_ok = False

    result.native = COMPLETE if native_ok else INCOMPLETE
    return result


def _instance_of(series: dict) -> str:
    return str(series.get("metric", {}).get("instance", ""))


def _slot_of(series: dict) -> str:
    return str(series.get("metric", {}).get("daemon_slot", "?"))


# ── report data ──────────────────────────────────────────────────────────────

MEASURED = "измерено"
UNMEASURED = "не измерено"


@dataclass(slots=True)
class Measurement:
    """A number that knows whether it was actually observed."""

    value: float | None
    state: str = MEASURED

    @property
    def measured(self) -> bool:
        return self.state == MEASURED and self.value is not None

    def render(self) -> str:
        return f"≈{_ru_number(self.value)}" if self.measured else UNMEASURED


@dataclass(slots=True)
class ReportData:
    window: Window
    completeness: Completeness
    webhook_requests: Measurement
    webhook_errors: Measurement
    webhook_by_code: list[tuple[str, str, float]]
    upload_errors: Measurement
    gateway_native_errors: Measurement
    daemon_restarts: Measurement


def _scalar(result: list[dict]) -> Measurement:
    """An absent family means "not measured", never 0.

    `or vector(0)` is deliberately not used: it turns "we never scraped this"
    into a confident zero, which is the single most dangerous output this
    report can produce.
    """
    if not result:
        return Measurement(None, UNMEASURED)
    total = 0.0
    for series in result:
        value = series.get("value")
        if not value or len(value) < 2:
            return Measurement(None, UNMEASURED)
        try:
            total += float(value[1])
        except (TypeError, ValueError):
            return Measurement(None, UNMEASURED)
    return Measurement(total)


def collect_report(client: MetricsClient, window: Window) -> ReportData:
    base = client.base_matcher()
    span = window.range_selector
    end = window.end_utc

    requests = client.query(
        f'sum(increase(zc_http_requests_total{{{base},route="webhook"}}[{span}]))',
        end,
    )
    errors = client.query(
        "sum(increase(zc_http_requests_total"
        f'{{{base},route="webhook",outcome="error"}}[{span}]))',
        end,
    )
    by_code = client.query(
        "sum by (error_code, component) (increase(zc_http_errors_total"
        f'{{{base},route="webhook"}}[{span}]))',
        end,
    )
    uploads = client.query(
        "sum(increase(zc_http_requests_total"
        f'{{{base},route="upload",outcome="error"}}[{span}]))',
        end,
    )
    native = client.query(
        "sum(increase(zeroclaw_errors_total"
        f'{{{base},component="gateway"}}[{span}]))',
        end,
    )
    restarts = client.query(
        f"sum(increase(zc_daemon_restarts_total{{{base}}}[{span}]))", end
    )

    step = DEFAULT_CADENCE_SECS
    snapshot_series = client.query_range(
        f"zc_metrics_snapshot_timestamp_seconds{{{base}}}",
        window.start_utc,
        window.end_utc,
        step,
    )
    completeness = assess_completeness(
        snapshot_series=snapshot_series,
        manager_start_series=client.query_range(
            f"zc_metrics_manager_start_time_seconds{{{base}}}",
            window.start_utc,
            window.end_utc,
            step,
        ),
        daemon_expected=client.query_range(
            f"zc_daemon_expected{{{base}}}", window.start_utc, window.end_utc, step
        ),
        daemon_up=client.query_range(
            f"zc_daemon_scrape_up{{{base}}}", window.start_utc, window.end_utc, step
        ),
        daemon_last_success=client.query_range(
            f"zc_daemon_last_success_timestamp_seconds{{{base}}}",
            window.start_utc,
            window.end_utc,
            step,
        ),
        daemon_start=client.query_range(
            f"zc_daemon_process_start_time_seconds{{{base}}}",
            window.start_utc,
            window.end_utc,
            step,
        ),
        window=window,
    )

    rows: list[tuple[str, str, float]] = []
    for series in by_code:
        metric = series.get("metric", {})
        value = series.get("value")
        if not value or len(value) < 2:
            continue
        try:
            amount = float(value[1])
        except (TypeError, ValueError):
            continue
        if amount <= 0:
            continue
        rows.append(
            (
                str(metric.get("error_code", "unknown")),
                str(metric.get("component", "unknown")),
                amount,
            )
        )
    rows.sort(key=lambda row: (-row[2], row[0]))

    return ReportData(
        window=window,
        completeness=completeness,
        webhook_requests=_scalar(requests),
        webhook_errors=_scalar(errors),
        webhook_by_code=rows[:MAX_ERROR_ROWS],
        upload_errors=_scalar(uploads),
        gateway_native_errors=_scalar(native),
        daemon_restarts=_scalar(restarts),
    )


def _ru_number(value: float | None) -> str:
    if value is None:
        return UNMEASURED
    rounded = round(value)
    if abs(value - rounded) < 0.05:
        return str(int(rounded))
    return f"{value:.1f}".replace(".", ",")


def render_report(data: ReportData) -> str:
    window = data.window
    start_local = window.start_utc.astimezone(ZoneInfo(window.timezone))
    end_local = window.end_utc.astimezone(ZoneInfo(window.timezone))
    lines = [
        f"*ZeroClaw* — окно {start_local:%d.%m} 00:00–{end_local:%d.%m} 00:00 "
        f"({window.timezone})",
        f"HTTP-наблюдение: {_with_reasons(data.completeness.http, data.completeness, 'http')}",
        f"Runtime-наблюдение: {_with_reasons(data.completeness.native, data.completeness, 'native')}",
    ]
    requests = data.webhook_requests
    errors = data.webhook_errors
    if requests.measured and requests.value == 0:
        lines.append("Запросов /webhook не было")
    elif requests.measured and errors.measured and requests.value:
        share = 100.0 * (errors.value or 0.0) / requests.value
        lines.append(
            f"Запросы /webhook: {requests.render()}; неуспешные: {errors.render()} "
            f"(≈{f'{share:.1f}'.replace('.', ',')}%)"
        )
    else:
        lines.append(
            f"Запросы /webhook: {requests.render()}; неуспешные: {errors.render()}"
        )
    if data.webhook_by_code:
        causes = ", ".join(
            f"{code} ≈{_ru_number(amount)}" for code, _component, amount in data.webhook_by_code
        )
        lines.append(f"Причины: {causes}")
    elif data.completeness.http == COMPLETE:
        lines.append("Причины: неуспешных запросов не зафиксировано")
    else:
        lines.append(f"Причины: {UNMEASURED}")
    lines.append(f"Ошибки /upload: {data.upload_errors.render()} (вне error-rate)")
    lines.append(
        f"Терминальные gateway failures: {data.gateway_native_errors.render()} "
        "(сверочный native-сигнал, не суммируется с HTTP)"
    )
    lines.append(f"Перезапуски daemon: {data.daemon_restarts.render()}")
    lines.append("Model/tool breakdown: не измеряется в v1")
    lines.append("Доставка ответа пользователю и bot-local ошибки: не измеряются")
    text = "\n".join(lines)
    return text[:MAX_REPORT_CHARS]


def _with_reasons(state: str, completeness: Completeness, scope: str) -> str:
    if state == COMPLETE or not completeness.reasons:
        return state
    return f"{state} — {'; '.join(completeness.reasons[:3])}"


def render_unavailable_notice(window: Window, kind: str) -> str:
    start_local = window.start_utc.astimezone(ZoneInfo(window.timezone))
    return (
        f"*ZeroClaw* — отчёт за {start_local:%d.%m} не построен\n"
        f"Причина: запрос к метрикам не удался ({kind})\n"
        "Это НЕ означает отсутствие ошибок — наблюдение недоступно."
    )


# ── delivery ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ReceiptKey:
    date: str
    timezone: str
    recipient: str
    kind: str

    def filename(self) -> str:
        safe_tz = self.timezone.replace("/", "-")
        return f"{self.date}__{safe_tz}__{self.recipient}__{self.kind}.json"


def _utc_stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ReceiptStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def path(self, key: ReceiptKey) -> Path:
        return self.root / key.filename()

    def load(self, key: ReceiptKey) -> dict | None:
        try:
            return json.loads(self.path(key).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def write(self, key: ReceiptKey, state: str, **extra: object) -> dict:
        if state not in RECEIPT_STATES:
            raise ValueError(f"unknown receipt state: {state}")
        receipt = {
            "date": key.date,
            "timezone": key.timezone,
            "recipient": key.recipient,
            "kind": key.kind,
            "state": state,
            "updated_at": _utc_stamp(),
            **extra,
        }
        self.root.mkdir(parents=True, exist_ok=True)
        target = self.path(key)
        tmp = target.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(receipt, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, target)
        # fsync the directory too: without it the rename can be lost on a crash
        # and a delivered report would look unsent.
        directory = os.open(self.root, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        return receipt


class DeliveryError(RuntimeError):
    pass


def classify_response(
    status: int, body: bytes, content_type: str
) -> tuple[str, str]:
    """Map the bot's `/zeroclaw/notify` contract onto a receipt state.

    Three distinct 4xx meanings live behind the same status code, so the body
    type decides, never a keyword scan of the free-form `description`:

    * text `Bad Request` / `Unauthorized` — the request never reached Telegram.
      Permanent `failed`, retrying it cannot help.
    * JSON `{"status":"error"}` — the bot accepted the payload and Telegram
      refused *after* the send was attempted. `unknown`: the endpoint returns no
      typed retryable flag and no sent-parts count, so a retry may duplicate.
    """
    text = body.decode("utf-8", errors="replace").strip()
    if status == 200:
        try:
            payload = json.loads(text)
        except ValueError:
            return "unknown", "200 with a non-JSON body"
        if isinstance(payload, dict) and payload.get("status") == "ok":
            return "accepted", "ok"
        return "unknown", "200 without status=ok"
    if status in (400, 401) and "json" not in content_type.lower():
        return "failed", f"{status} {text[:80]}"
    if status == 400:
        return "unknown", "400 status=error — send may have partially happened"
    if 500 <= status < 600:
        return "unknown", f"{status} upstream failure"
    return "unknown", f"unexpected status {status}"


def deliver(
    *,
    notify_url: str,
    notify_secret: str,
    recipient: int,
    message: str,
    timeout: float = 15.0,
    opener: Callable[[urllib.request.Request, float], tuple[int, bytes, str]]
    | None = None,
) -> tuple[str, str]:
    """Synchronous send with a validated receipt.

    `OperatorErrorNotifier` and `_post_operator_telegram` are deliberately not
    reused: the first is asynchronous and returns nothing to the caller, the
    second swallows every exception. Neither can produce a receipt.
    """
    payload = json.dumps({"user_id": recipient, "message": message}).encode("utf-8")
    request = urllib.request.Request(
        url=notify_url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Webhook-Secret": notify_secret,
        },
    )
    send = opener or _open_notify
    try:
        status, body, content_type = send(request, timeout)
    except urllib.error.HTTPError as exc:
        return classify_response(
            exc.code, exc.read(), exc.headers.get("Content-Type", "")
        )
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        return "unknown", f"transport failure: {exc.__class__.__name__}"
    return classify_response(status, body, content_type)


def _open_notify(
    request: urllib.request.Request, timeout: float
) -> tuple[int, bytes, str]:
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return (
            response.status,
            response.read(),
            response.headers.get("Content-Type", ""),
        )


# ── owner gate ───────────────────────────────────────────────────────────────


def owner_check(env: dict[str, str]) -> tuple[bool, str]:
    """Exactly one Machine may send.

    A missing owner ID disables sending outright. A copied config on a second
    Machine does not make it the owner — that is the whole point: two volumes
    with identical flags must not both deliver.
    """
    configured = (env.get("ZEROCLAW_REPORT_OWNER_MACHINE_ID") or "").strip()
    actual = (env.get("FLY_MACHINE_ID") or "").strip()
    if not configured:
        return False, "ZEROCLAW_REPORT_OWNER_MACHINE_ID is not set — sending disabled"
    if not actual:
        return False, "FLY_MACHINE_ID is not visible — cannot prove ownership"
    if configured != actual:
        return False, "not the owner Machine"
    return True, "owner"


class ProcessLock:
    """Local `flock` against two processes on the same volume.

    Not a distributed lock: cross-Machine exclusion is the owner-ID gate's job.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle = None

    def __enter__(self) -> "ProcessLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = open(self.path, "w", encoding="utf-8")  # noqa: SIM115
        try:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self._handle.close()
            self._handle = None
            raise DeliveryError("another report process holds the lock") from exc
        return self

    def __exit__(self, *_exc: object) -> None:
        if self._handle is not None:
            fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
            self._handle.close()
            self._handle = None


# ── orchestration ────────────────────────────────────────────────────────────


@dataclass(slots=True)
class ReportConfig:
    state_root: Path
    recipient: int
    timezone: str = DEFAULT_TIMEZONE
    notify_url: str = ""
    notify_secret: str = ""
    metrics_base_url: str = ""
    metrics_token: str = ""
    app: str = "ai-forge-zeroclaw"

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> "ReportConfig":
        env = dict(os.environ if env is None else env)
        data_root = Path(env.get("ZEROCLAW_DATA_ROOT", "/zeroclaw-data"))
        return cls(
            state_root=data_root / "observability" / "reports",
            recipient=int(env.get("ZEROCLAW_OPERATOR_USER_ID", "0") or 0),
            timezone=env.get("ZEROCLAW_REPORT_TIMEZONE", DEFAULT_TIMEZONE),
            notify_url=env.get("NOTIFY_URL", ""),
            notify_secret=env.get("NOTIFY_SECRET", ""),
            metrics_base_url=env.get(
                "ZEROCLAW_METRICS_QUERY_URL",
                "https://api.fly.io/prometheus/personal",
            ),
            metrics_token=env.get("ZEROCLAW_METRICS_QUERY_TOKEN", ""),
            app=env.get("FLY_APP_NAME", "ai-forge-zeroclaw"),
        )


def run_once(
    *,
    config: ReportConfig,
    date: dt.date,
    send: bool,
    retry_unknown: bool = False,
    client_factory: Callable[[ReportConfig], MetricsClient] | None = None,
    deliver_fn: Callable[..., tuple[str, str]] = deliver,
    env: dict[str, str] | None = None,
    exporter: object | None = None,
) -> dict:
    """Build one report and, when asked, deliver it exactly once."""
    env = dict(os.environ if env is None else env)
    tz = ZoneInfo(config.timezone)
    window = window_for_date(date, tz)
    store = ReceiptStore(config.state_root)
    key = ReceiptKey(
        date=date.isoformat(),
        timezone=config.timezone,
        recipient=str(config.recipient),
        kind="report",
    )
    factory = client_factory or _default_client
    outcome: dict[str, object] = {"date": date.isoformat(), "kind": "report"}

    try:
        client = factory(config)
        data = collect_report(client, window)
        message = render_report(data)
        outcome["kind"] = "report"
    except QueryError as exc:
        _bump(exporter, "query_failed")
        key = ReceiptKey(
            date=key.date,
            timezone=key.timezone,
            recipient=key.recipient,
            kind="unavailable_notice",
        )
        message = render_unavailable_notice(window, exc.kind)
        outcome["kind"] = "unavailable_notice"
        outcome["query_error"] = exc.kind
    else:
        _bump(exporter, "built")

    outcome["message"] = message
    if not send:
        outcome["state"] = "dry-run"
        return outcome

    allowed, reason = owner_check(env)
    if not allowed:
        outcome["state"] = "not-owner"
        outcome["reason"] = reason
        return outcome

    with ProcessLock(config.state_root / ".report.lock"):
        existing = store.load(key)
        if existing is not None:
            state = existing.get("state")
            if state == "accepted":
                outcome["state"] = "already-accepted"
                return outcome
            if state == "failed":
                outcome["state"] = "already-failed"
                return outcome
            if state == "sending" and not retry_unknown:
                # A durable `sending` means a previous process reached the
                # network and never came back. The bot may well have delivered
                # the message before dying, so this is exactly the `unknown`
                # case: promote it, then hold. Re-sending automatically here
                # would duplicate the operator's report after every crash.
                store.write(
                    key, "unknown", detail="process died after sending"
                )
                outcome["state"] = "unknown-held"
                return outcome
            if state == "unknown" and not retry_unknown:
                # An unknown send may already have reached Telegram. Retrying is
                # an explicit operator decision, not an automatic one.
                outcome["state"] = "unknown-held"
                return outcome
        # Durable `sending` BEFORE the network call: a crash between the two
        # must be visible as `sending`, never as "never attempted".
        store.write(key, "sending", attempted_at=_utc_stamp())
        state, detail = deliver_fn(
            notify_url=config.notify_url,
            notify_secret=config.notify_secret,
            recipient=config.recipient,
            message=message,
        )
        store.write(key, state, detail=detail)
    outcome["state"] = state
    outcome["detail"] = detail
    _bump(exporter, "accepted" if state == "accepted" else "send_failed")
    return outcome


def _bump(exporter: object | None, outcome: str) -> None:
    if exporter is None:
        return
    recorder = getattr(exporter, "record_report_run", None)
    if callable(recorder):
        try:
            recorder(outcome)
        except Exception:
            pass


def _default_client(config: ReportConfig) -> MetricsClient:
    if not config.metrics_token:
        raise QueryError("auth", "ZEROCLAW_METRICS_QUERY_TOKEN is not set")
    return MetricsClient(
        base_url=config.metrics_base_url,
        token=config.metrics_token,
        app=config.app,
    )


def due_date(
    now_local: dt.datetime,
    *,
    send_hour: int = DEFAULT_SEND_HOUR,
    catchup_until_hour: int = DEFAULT_CATCHUP_UNTIL_HOUR,
) -> dt.date | None:
    """Which calendar day is due right now, or None.

    The window is `[send_hour, catchup_until_hour)` so a Manager restarted at
    08:30 still delivers yesterday's report; past the catch-up hour it needs an
    explicit `--date`, because a report delivered at 19:00 is noise.
    """
    if send_hour <= now_local.hour < catchup_until_hour:
        return (now_local - dt.timedelta(days=1)).date()
    return None


def run_worker(
    *,
    config: ReportConfig,
    stop: Callable[[], bool],
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], dt.datetime] | None = None,
    send: bool = False,
    exporter: object | None = None,
    tick_secs: float = 60.0,
) -> None:
    tz = ZoneInfo(config.timezone)
    clock = now or (lambda: dt.datetime.now(tz))
    while not stop():
        target = due_date(clock())
        if target is not None:
            try:
                run_once(config=config, date=target, send=send, exporter=exporter)
            except DeliveryError:
                pass
            except Exception as exc:  # never let the worker die on one bad day
                print(
                    f"[zeroclaw-error-report] tick failed: {exc.__class__.__name__}",
                    flush=True,
                )
        sleep(tick_secs)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ZeroClaw daily error report")
    parser.add_argument("--date", help="calendar date in the report timezone")
    parser.add_argument("--dry-run", action="store_true", help="build only")
    parser.add_argument("--send", action="store_true", help="deliver to Telegram")
    parser.add_argument(
        "--retry-unknown",
        action="store_true",
        help="explicitly accept the risk of a duplicate for an unknown receipt",
    )
    parser.add_argument("--serve", action="store_true", help="run the daily worker")
    args = parser.parse_args(argv)

    config = ReportConfig.from_env()
    if args.serve:
        run_worker(config=config, stop=lambda: False, send=args.send)
        return 0

    tz = ZoneInfo(config.timezone)
    if args.date:
        target = dt.date.fromisoformat(args.date)
    else:
        target = (dt.datetime.now(tz) - dt.timedelta(days=1)).date()

    if args.send and args.dry_run:
        parser.error("--send and --dry-run are mutually exclusive")

    result = run_once(
        config=config,
        date=target,
        send=args.send,
        retry_unknown=args.retry_unknown,
    )
    print(result.get("message", ""))
    print(f"-- state: {result.get('state')} {result.get('detail', '')}", flush=True)
    return 0 if result.get("state") in ("dry-run", "accepted") else 1


if __name__ == "__main__":
    raise SystemExit(main())
