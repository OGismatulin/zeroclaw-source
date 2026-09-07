#!/usr/bin/env python3
"""Fork-side contract gate for the mirrored ZeroClaw Python runtime.

The Fly image is built from THIS repository, so the exporter, the reporter and
the Gateway Manager that actually reach production are the copies under
`scripts/` here. The full pytest suite lives in the integration repository; this
gate re-checks the invariants that would silently break production if a mirror
drifted, and it runs inside the same `Quality Gate` workflow that gates
`zc-fly-deploy.yml` — so a red assertion here blocks the deploy.

Stdlib only, plus `prometheus-client` (the exporter's parser/encoder).
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path
import re
import sys
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import zeroclaw_error_report as rep  # noqa: E402
import zeroclaw_metrics as zm  # noqa: E402

FAILURES: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        FAILURES.append(message)


def samples(exporter: zm.MetricsExporter, metric: str) -> dict:
    from prometheus_client.parser import text_string_to_metric_families

    found = {}
    for family in text_string_to_metric_families(exporter.render().decode()):
        for sample in family.samples:
            if sample.name == metric:
                found[tuple(sorted(sample.labels.items()))] = sample.value
    return found


def check_error_catalog() -> None:
    source = (ROOT / "scripts" / "gateway_manager.py").read_text(encoding="utf-8")
    emitted = set(re.findall(r'code="([a-z][a-z0-9_]*)"', source)) - {
        "invalid_pairing_code"
    }
    canonical = set(
        re.findall(r'^    "([a-z][a-z0-9_]*)": \(', source, flags=re.MULTILINE)
    )
    missing = (emitted | canonical) - set(zm.ERROR_CATALOG)
    check(not missing, f"error codes missing from ERROR_CATALOG: {sorted(missing)}")
    check(
        set(zm.ERROR_CATALOG.values()) == set(zm.COMPONENTS),
        "ERROR_CATALOG components drifted from the closed component set",
    )


def check_series_are_bounded() -> None:
    exporter = zm.MetricsExporter(targets_provider=lambda: [], max_instances=2)
    errors = samples(exporter, "zc_http_errors_total")
    expected = len(zm.REPORTED_ROUTES) * len(zm.ERROR_CATALOG) + len(zm.ROUTES)
    check(
        len(errors) == expected,
        f"zc_http_errors_total has {len(errors)} series, expected {expected} "
        "— a cartesian code×component product would be silently dropped by Fly",
    )
    check(
        len(samples(exporter, "zc_http_requests_total")) == len(zm.ROUTES) * 2,
        "zc_http_requests_total is not fully pre-initialised",
    )


def check_counting_is_exactly_once() -> None:
    exporter = zm.MetricsExporter(targets_provider=lambda: [], max_instances=2)
    exporter.record_http(path="/webhook", status_code=200, payload={"response": "ok"})
    exporter.record_http(
        path="/webhook",
        status_code=503,
        payload={"error_code": "child_unreachable", "component": "manager"},
    )
    requests = samples(exporter, "zc_http_requests_total")
    check(
        requests[(("outcome", "success"), ("route", "webhook"))] == 1,
        "success is not counted exactly once",
    )
    check(
        sum(samples(exporter, "zc_http_errors_total").values()) == 1,
        "error is not counted exactly once",
    )
    exporter.record_http(path="/nope", status_code=404, payload={"error_code": "x"})
    check(
        requests_route(exporter, "other") == 1,
        "unknown paths do not collapse onto route=other",
    )


def requests_route(exporter: zm.MetricsExporter, route: str) -> float:
    return sum(
        value
        for labels, value in samples(exporter, "zc_http_requests_total").items()
        if dict(labels).get("route") == route
    )


def check_native_filter() -> None:
    body = (
        "# TYPE zeroclaw_heartbeat_ticks_total counter\n"
        "zeroclaw_heartbeat_ticks_total 3\n"
        "# TYPE zeroclaw_errors_total counter\n"
        'zeroclaw_errors_total{component="gateway"} 2\n'
        'zeroclaw_errors_total{component="system"} 9\n'
        "# TYPE zeroclaw_tool_calls_total counter\n"
        'zeroclaw_tool_calls_total{tool="model_invented_name",status="ok"} 5\n'
    ).encode()
    exporter = zm.MetricsExporter(
        targets_provider=lambda: [
            zm.DaemonTarget(
                user_key="tg_1", port=3001, pid=1, started_at=1.0, process_running=True
            )
        ],
        max_instances=2,
        fetch=lambda _url, _timeout: body,
    )
    exporter.poll_once()
    rendered = exporter.render().decode()
    check("model_invented_name" not in rendered, "a tool label leaked into the export")
    check(
        "zeroclaw_tool_calls_total" not in rendered,
        "the tool family leaked into the export",
    )
    check(
        samples(exporter, "zc_daemon_scrape_up")[(("daemon_slot", "00"),)] == 1,
        "an unexpected known-label VALUE wrongly broke a healthy scrape",
    )
    check(
        sum(samples(exporter, "zc_metrics_collection_failures_total").values()) == 0,
        "a healthy scrape reported a collection failure",
    )


def check_exporter_port_floor() -> None:
    try:
        zm.validate_exporter_port(exporter_port=3001, manager_base_port=3001)
    except zm.ExporterConfigError:
        pass
    else:
        FAILURES.append("exporter port validation accepted a colliding port")
    zm.validate_exporter_port(exporter_port=2999, manager_base_port=3001)


def check_report_window_and_contract() -> None:
    window = rep.window_for_date(dt.date(2026, 9, 6), ZoneInfo("Asia/Bishkek"))
    check(
        window.start_utc == dt.datetime(2026, 9, 5, 18, 0, tzinfo=dt.timezone.utc),
        "the daily window is not the Asia/Bishkek calendar day",
    )
    check(rep._scalar([]).render() == rep.UNMEASURED, "an absent family became a zero")
    cases = [
        (200, b'{"status":"ok"}', "application/json", "accepted"),
        (400, b"Bad Request", "text/plain", "failed"),
        (401, b"Unauthorized", "text/plain", "failed"),
        (400, b'{"status":"error","description":"x"}', "application/json", "unknown"),
        (500, b"boom", "text/plain", "unknown"),
    ]
    for status, body, content_type, expected in cases:
        state, _ = rep.classify_response(status, body, content_type)
        check(
            state == expected,
            f"bot response {status}/{content_type} classified {state}, want {expected}",
        )
    allowed, _ = rep.owner_check({"FLY_MACHINE_ID": "a"})
    check(not allowed, "a missing owner Machine ID did not disable sending")
    allowed, _ = rep.owner_check(
        {"ZEROCLAW_REPORT_OWNER_MACHINE_ID": "a", "FLY_MACHINE_ID": "b"}
    )
    check(not allowed, "a non-owner Machine was allowed to send")


def check_child_secret_denylist() -> None:
    source = (ROOT / "scripts" / "gateway_manager.py").read_text(encoding="utf-8")
    for name in ("ZEROCLAW_METRICS_QUERY_TOKEN", "ZEROCLAW_REPORT_OWNER_MACHINE_ID"):
        check(
            f'"{name}",' in source,
            f"{name} is not removed from the child environment before Popen",
        )


def main() -> int:
    for probe in (
        check_error_catalog,
        check_series_are_bounded,
        check_counting_is_exactly_once,
        check_native_filter,
        check_exporter_port_floor,
        check_report_window_and_contract,
        check_child_secret_denylist,
    ):
        try:
            probe()
        except Exception as exc:  # a crashing probe is a failing probe
            FAILURES.append(f"{probe.__name__} raised {exc.__class__.__name__}: {exc}")
    if FAILURES:
        print("PYTHON RUNTIME GATE FAILED", file=sys.stderr)
        for failure in FAILURES:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("python runtime gate: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
