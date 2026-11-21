from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from verify_manual_digest_release import (
    APP,
    IMAGE,
    SOURCE_NAMES,
    Failure,
    parse_json,
    require,
    timestamp,
)


HOLD_EXIT = 10
WINDOW = 600
SCAN_TIMEOUT = 120
SCAN_LIMIT = 5
RETRY_INTERVAL = 60
FRESHNESS = 30
COMMAND_TIMEOUT = 15
MASTER_REF = "refs/heads/master"
SHA = r"[0-9a-f]{40}"
DIGEST = r"sha256:[0-9a-f]{64}"
IMAGE_TAG = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"
MACHINE_IMAGE = (
    rf"(?:{re.escape(IMAGE)}|registry\.fly\.io/{APP}|ogismatulin/zeroclaw)"
    rf"(?::{IMAGE_TAG})?(?:@{DIGEST})?"
)
BUSY_KINDS = ("turn", "task", "delegate", "run", "queue")
BUSY_CLASSES = ("live", "overdue", "overdue_unmanaged", "pending")
SOURCE_OUTCOMES = ("READ", "UNAVAILABLE", "UNKNOWN")
MACHINE_STATES = (
    "created",
    "started",
    "stopped",
    "suspended",
    "destroyed",
    "replacing",
    "starting",
    "stopping",
    "destroying",
    "updating",
    "suspending",
    "restarting",
    "failed",
    "migrated",
    "migrating",
)
REPORT_FIELDS = {"app", "state", "transport", "machine", "observed_at"}
INVENTORY_FIELDS = {"users", "sources", "busy", "busy_reasons", "unknown"}
FAILURE_FIELDS = {"stage", "kind", "rc", "rc_origin", "timed_out", "stderr_bytes"}
FAILURE_STAGES = ("access", "exec_probe", "machine_list", "image", "scan", "parse")
FAILURE_KINDS = (
    "nonzero",
    "invalid_envelope",
    "invalid_output",
    "timeout",
    "unavailable",
    "invalid_json",
    "invalid_shape",
    "not_found",
    "mismatch",
)


class Hold(Exception):
    pass


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise Hold("CONTROLLER_ERROR")


def utc_now():
    return datetime.now(timezone.utc)


def matches(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def digest(value):
    return matches(DIGEST, value) and value != "sha256:" + "0" * 64


def run(argv, timeout):
    return subprocess.run(argv, capture_output=True, timeout=timeout)


def bounded(deadline, maximum=COMMAND_TIMEOUT):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise Hold("BUSY_WINDOW")
    return min(remaining, maximum)


def command_json(argv, timeout, reason):
    try:
        result = run(argv, timeout)
        require(result.returncode == 0, "command failed")
        value = parse_json(result.stdout)
        require(isinstance(value, dict), "invalid command object")
        return value
    except (Failure, OSError, subprocess.TimeoutExpired):
        raise Hold(reason) from None


def read_machine(timeout):
    reason = "MACHINE_STATUS_FAILED"
    status = command_json(["fly", "status", "--app", APP, "--json"], timeout, reason)
    machines = status.get("Machines")
    if status.get("Name") != APP or not isinstance(machines, list):
        raise Hold(reason)
    if len(machines) != 1:
        raise Hold("ROSTER_DRIFT")
    machine = machines[0]
    try:
        require(isinstance(machine, dict), "invalid machine")
        config, image_ref = machine.get("config"), machine.get("image_ref")
        require(
            isinstance(config, dict) and isinstance(image_ref, dict),
            "invalid machine image",
        )
        require(
            matches(r"[0-9a-f]{14}", machine.get("id"))
            and matches(r"[0-7][0-9A-HJKMNP-TV-Z]{25}", machine.get("version"))
            and machine.get("state") in MACHINE_STATES
            and matches(MACHINE_IMAGE, config.get("image"))
            and digest(image_ref.get("digest")),
            "invalid machine identity",
        )
    except Failure:
        raise Hold(reason) from None
    return {
        "id": machine["id"],
        "version": machine["version"],
        "state": machine["state"],
        "config_image": config["image"],
        "digest": image_ref["digest"],
    }


def verify_master(repo, upstream, deadline):
    if not upstream:
        return
    reason = "MASTER_READ_FAILED"
    remote = command_json(
        ["gh", "api", f"repos/{repo}/git/ref/heads/master"], bounded(deadline), reason
    )
    ref = remote.get("object")
    if (
        remote.get("ref") != MASTER_REF
        or not isinstance(ref, dict)
        or ref.get("type") != "commit"
        or not matches(SHA, ref.get("sha"))
    ):
        raise Hold(reason)
    if ref["sha"] != upstream:
        raise Hold("SUPERSEDED")


def resolve_registry(tag):
    reason = "REGISTRY_FAILED"
    argv = [
        "docker",
        "buildx",
        "imagetools",
        "inspect",
        f"{IMAGE}:{tag}",
        "--format",
        "{{json .Manifest}}",
    ]
    registry = command_json(argv, COMMAND_TIMEOUT, reason)
    index = registry.get("digest")
    manifests = registry.get("manifests")
    if (
        not digest(index)
        or registry.get("mediaType")
        not in (
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
        )
        or not isinstance(manifests, list)
        or not all(
            isinstance(entry, dict) and isinstance(entry.get("platform"), dict)
            for entry in manifests
        )
    ):
        raise Hold(reason)
    amd64 = [
        entry
        for entry in manifests
        if entry["platform"].get("os") == "linux"
        and entry["platform"].get("architecture") == "amd64"
    ]
    if len(amd64) != 1:
        raise Hold(reason)
    child = amd64[0].get("digest")
    if (
        not digest(child)
        or child == index
        or amd64[0].get("mediaType")
        not in (
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        )
    ):
        raise Hold(reason)
    return index, child


def flyctl_version():
    try:
        version = run(["flyctl", "version"], COMMAND_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if version.returncode == 0:
        match = re.match(
            rb"\s*flyctl (v[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5})\b", version.stdout
        )
        if match:
            return match[1].decode("ascii")
    return None


def validate_diagnostics(failure):
    require(
        isinstance(failure, dict) and set(failure) == FAILURE_FIELDS,
        "invalid diagnostic fields",
    )
    rc, origin, count = failure["rc"], failure["rc_origin"], failure["stderr_bytes"]
    require(
        failure["stage"] in FAILURE_STAGES
        and failure["kind"] in FAILURE_KINDS
        and (
            (rc is None and origin is None)
            or (type(rc) is int and origin in ("outer", "inner"))
        )
        and type(failure["timed_out"]) is bool
        and (count is None or (type(count) is int and count >= 0)),
        "invalid diagnostics",
    )
    return failure


def project_inventory(report):
    users, sources = report["users"], report["sources"]
    busy, reasons, unknown = report["busy"], report["busy_reasons"], report["unknown"]
    require(
        isinstance(users, list)
        and bool(users)
        and all(matches(r"tg_[1-9][0-9]*", user) for user in users)
        and len(set(users)) == len(users)
        and isinstance(sources, dict)
        and set(sources) == set(users),
        "invalid user inventory",
    )
    state = report["state"]
    allowed = ("READ",) if state == "QUIET" else SOURCE_OUTCOMES
    require(
        all(
            isinstance(values, dict)
            and set(values) == set(SOURCE_NAMES)
            and all(outcome in allowed for outcome in values.values())
            for values in sources.values()
        ),
        "invalid source inventory",
    )
    require(
        isinstance(busy, list)
        and all(isinstance(item, str) and item for item in busy)
        and isinstance(reasons, dict)
        and set(reasons) <= set(busy)
        and isinstance(unknown, list)
        and all(isinstance(item, str) and item for item in unknown)
        and len(set(unknown)) == len(unknown),
        "invalid busy or unknown inventory",
    )
    require(
        (state == "QUIET" and not busy and not unknown)
        or (state == "BUSY" and bool(busy))
        or (state == "UNKNOWN" and not busy and bool(unknown)),
        "inconsistent scan state",
    )
    by_kind = dict.fromkeys(BUSY_KINDS, 0)
    by_reason = dict.fromkeys(BUSY_CLASSES, 0)
    for item in busy:
        parts = item.split("/", 2)
        require(
            len(parts) == 3
            and parts[0] in sources
            and parts[1] in BUSY_KINDS
            and bool(parts[2]),
            "invalid busy kind",
        )
        by_kind[parts[1]] += 1
    for detail in reasons.values():
        require(
            isinstance(detail, dict) and detail.get("class") in BUSY_CLASSES,
            "invalid busy class",
        )
        by_reason[detail["class"]] += 1
    return {
        "busy_count": len(busy),
        "busy_by_kind": by_kind,
        "busy_by_reason": by_reason,
        "unknown_count": len(unknown),
        "users_count": len(users),
    }


def project_scan(result, machine, started, finished):
    report = parse_json(result.stdout)
    require(
        isinstance(report, dict)
        and report.get("app") == APP
        and report.get("transport") == "machines"
        and report.get("machine") == machine["id"],
        "wrong scan target",
    )
    observed = timestamp(report.get("observed_at"))
    require(started <= observed <= finished, "unbounded observation time")
    state, execution = report.get("state"), report.get("exec")
    fields = set(report)
    image = report.get("image")
    expected = machine["config_image"]
    rc = result.returncode
    evidence = {"state": state, "exec": execution, "observed_at": observed.isoformat()}
    common_fields = REPORT_FIELDS | {"exec", "image"}
    if rc == 1 and state == "BUSY" and report.get("reason") == "image mismatch":
        required = common_fields | {"reason"}
        require(
            required <= fields <= required | {"failure"}
            and execution == "PASS"
            and matches(MACHINE_IMAGE, image)
            and image != expected,
            "invalid image drift report",
        )
        if "failure" in report:
            failure = validate_diagnostics(report["failure"])
            require(
                failure["stage"] == "image" and failure["kind"] == "mismatch",
                "invalid image diagnostics",
            )
            evidence["failure"] = failure
        return "TARGET_CHANGED", evidence
    if rc == 3 and state == "UNKNOWN" and "reason" in report:
        required = REPORT_FIELDS | {"reason", "failure"}
        require(
            required <= fields <= required | {"exec", "image"}
            and isinstance(report["reason"], str)
            and bool(report["reason"])
            and ("exec" not in report or execution == "PASS")
            and ("image" not in report or image == expected),
            "invalid failure report",
        )
        evidence["failure"] = validate_diagnostics(report["failure"])
        return "PROBE_FAILED", evidence
    require(
        (rc, state) in ((0, "QUIET"), (1, "BUSY"), (3, "UNKNOWN"))
        and fields == common_fields | INVENTORY_FIELDS
        and execution == "PASS"
        and image == expected,
        "invalid scan interface",
    )
    evidence.update(project_inventory(report))
    return state, evidence


def scan(checker, machine, deadline, receipt):
    timeout = bounded(deadline, SCAN_TIMEOUT)
    argv = [
        sys.executable,
        str(checker),
        "--quiescence",
        "--json",
        "--transport",
        "machines",
        "--machine",
        machine["id"],
        "--expected-image",
        machine["config_image"],
    ]
    started = utc_now()
    receipt.update(
        scan_started_at=started.isoformat(),
        observed_at=None,
        scan_finished_at=None,
        scanner_exit_code=None,
        state=None,
        exec=None,
        failure=None,
        busy_count=None,
        busy_by_kind=None,
        busy_by_reason=None,
        unknown_count=None,
        users_count=None,
    )
    try:
        result = run(argv, timeout)
    except subprocess.TimeoutExpired:
        raise Hold(
            "SCANNER_TIMEOUT" if timeout == SCAN_TIMEOUT else "BUSY_WINDOW"
        ) from None
    except OSError:
        raise Hold("INTEGRATION_UNAVAILABLE") from None
    finally:
        finished_monotonic = time.monotonic()
        finished = utc_now()
        receipt["scan_finished_at"] = finished.isoformat()
    receipt["scanner_exit_code"] = result.returncode
    try:
        outcome, evidence = project_scan(result, machine, started, finished)
    except Failure:
        raise Hold("INVALID_REPORT") from None
    receipt.update(evidence)
    return outcome, finished_monotonic


def deploy(receipt, machine, deadline, scan_finished):
    index = receipt["candidate_index_digest"]
    argv = ["flyctl", "deploy", "--app", APP, "--image", f"{IMAGE}@{index}"]
    started = utc_now().isoformat()
    now = time.monotonic()
    if now - scan_finished > FRESHNESS:
        raise Hold("STALE")
    if now >= deadline:
        raise Hold("BUSY_WINDOW")
    receipt.update(deploy_invoked=True, deploy_started_at=started, machine_after=None)
    try:
        result = run(argv, WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        raise Hold("DEPLOY_FAILED") from None
    receipt["deploy_exit_code"] = result.returncode
    if result.returncode != 0:
        raise Hold("DEPLOY_FAILED")
    try:
        after = read_machine(COMMAND_TIMEOUT)
    except Hold:
        raise Hold("POST_DEPLOY_DRIFT") from None
    receipt["machine_after"] = after
    if (
        after["state"] != "started"
        or after["version"] == machine["version"]
        or after["digest"] != receipt["candidate_amd64_digest"]
    ):
        raise Hold("POST_DEPLOY_DRIFT")


def decide(args, repo, receipt):
    if not args.preflight.is_file():
        raise Hold("INTEGRATION_UNAVAILABLE")
    receipt["flyctl_version"] = flyctl_version()
    if args.mode == "deploy":
        receipt["candidate_index_digest"], receipt["candidate_amd64_digest"] = (
            resolve_registry(args.image_tag)
        )
    deadline = time.monotonic() + WINDOW
    machine = read_machine(bounded(deadline))
    receipt["machine_before"] = machine
    if machine["state"] != "started":
        raise Hold("TARGET_CHANGED")
    verify_master(repo, args.upstream_sha, deadline)

    def recheck():
        current = read_machine(bounded(deadline))
        receipt["machine_after"] = current
        if current != machine:
            raise Hold("TARGET_CHANGED")
        verify_master(repo, args.upstream_sha, deadline)

    for number in range(1, SCAN_LIMIT + 1):
        receipt["scan"] = number
        outcome, finished = scan(args.preflight, machine, deadline, receipt)
        recheck()
        if outcome == "QUIET":
            if args.mode == "deploy":
                recheck()
                deploy(receipt, machine, deadline, finished)
            return
        if args.mode == "observe" or outcome != "BUSY" or receipt["unknown_count"]:
            raise Hold(outcome)
        if number == SCAN_LIMIT or deadline - time.monotonic() < RETRY_INTERVAL:
            raise Hold("BUSY_WINDOW")
        time.sleep(RETRY_INTERVAL)


def write_receipt(path, receipt):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", dir=path.parent, delete=False
        ) as output:
            temp = Path(output.name)
            json.dump(receipt, output, sort_keys=True)
            output.write("\n")
        temp.replace(path)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def main(argv=None):
    parser = SafeParser(
        description="Guard a legacy Fly deploy with a fresh quiescence scan"
    )
    parser.add_argument("--preflight", required=True, type=Path)
    parser.add_argument("--image-tag")
    parser.add_argument("--upstream-sha", required=True)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--mode", required=True, choices=("deploy", "observe"))
    try:
        args = parser.parse_args(argv)
    except Hold:
        print("HOLD/CONTROLLER_ERROR", file=sys.stderr)
        return HOLD_EXIT

    env = os.environ
    event = env.get("GITHUB_EVENT_NAME")
    metadata = {
        name: env.get(key) if matches(pattern, env.get(key)) else None
        for name, key, pattern in (
            ("run_id", "GITHUB_RUN_ID", r"[1-9][0-9]{0,19}"),
            ("run_attempt", "GITHUB_RUN_ATTEMPT", r"[1-9][0-9]{0,9}"),
            ("workflow_sha", "GITHUB_WORKFLOW_SHA", SHA),
        )
    }
    receipt = dict.fromkeys(
        (
            "scan",
            "state",
            "exec",
            "scanner_exit_code",
            "failure",
            "busy_count",
            "busy_by_kind",
            "busy_by_reason",
            "unknown_count",
            "users_count",
            "machine_before",
            "machine_after",
            "image_tag",
            "candidate_index_digest",
            "candidate_amd64_digest",
            "scan_started_at",
            "observed_at",
            "scan_finished_at",
            "deploy_started_at",
            "deploy_exit_code",
            "flyctl_version",
        )
    )
    receipt.update(
        decision="HOLD",
        reason_code="CONTROLLER_ERROR",
        mode=args.mode,
        event=event if event in ("workflow_run", "workflow_dispatch") else None,
        upstream_sha=args.upstream_sha if matches(SHA, args.upstream_sha) else None,
        deploy_invoked=False,
        **metadata,
    )
    observation = False
    written = False
    try:
        repo = env.get("GITHUB_REPOSITORY")
        if args.mode == "observe":
            if (
                event != "workflow_dispatch"
                or env.get("GITHUB_REF") != MASTER_REF
                or args.image_tag is not None
                or args.upstream_sha
            ):
                raise Hold("CONTROLLER_ERROR")
            observation = True
        elif event == "workflow_run":
            if (
                not receipt["upstream_sha"]
                or args.image_tag != "sha-" + args.upstream_sha[:7]
                or not matches(r"[A-Za-z0-9-]+/[A-Za-z0-9_][A-Za-z0-9_.-]*", repo)
            ):
                raise Hold("CONTROLLER_ERROR")
        elif event != "workflow_dispatch" or args.upstream_sha:
            raise Hold("CONTROLLER_ERROR")
        if args.mode == "deploy":
            if not matches(IMAGE_TAG, args.image_tag):
                raise Hold("CONTROLLER_ERROR")
            receipt["image_tag"] = args.image_tag

        decide(args, repo, receipt)
        receipt.update(decision="ALLOW", reason_code="QUIET")
    except Hold as exc:
        receipt["reason_code"] = exc.args[0]
    except Exception:
        receipt["reason_code"] = "CONTROLLER_ERROR"
    finally:
        try:
            write_receipt(args.receipt, receipt)
            written = True
        except Exception:
            print("HOLD/CONTROLLER_ERROR", file=sys.stderr)
    if not written:
        return HOLD_EXIT
    print(json.dumps(receipt, sort_keys=True))
    return 0 if observation or receipt["decision"] == "ALLOW" else HOLD_EXIT


if __name__ == "__main__":
    raise SystemExit(main())
