import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import verify_legacy_deploy_quiescence as gate
from verify_manual_digest_release import APP, IMAGE, SOURCE_NAMES


SECRET = "synthetic-private-value"
HEAD = "a" * 40
INDEX = "sha256:" + "b" * 64
AMD64 = "sha256:" + "c" * 64
CURRENT = "sha256:" + "d" * 64
MACHINE = "0123456789abcd"
VERSION = "01KDA9558HDNA6M9NKJY4RPRJE"
NEW_VERSION = "01KDA9558HDNA6M9NKJY4RPRJF"
CURRENT_IMAGE = f"{IMAGE}:sha-111f8ee"
MASTER = "refs/heads/master"
TAG = "sha-aaaaaaa"
ENV = {
    "GITHUB_EVENT_NAME": "workflow_run",
    "GITHUB_REF": MASTER,
    "GITHUB_REPOSITORY": "OGismatulin/zeroclaw-source",
    "GITHUB_RUN_ID": "12",
    "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_WORKFLOW_SHA": "e" * 40,
}
USER = "tg_123456"


def current_machine(**changes):
    return {
        "id": MACHINE,
        "version": VERSION,
        "state": "started",
        "config": {"image": CURRENT_IMAGE, "env": {"private": SECRET}},
        "image_ref": {"digest": CURRENT, "private": SECRET},
        "private": SECRET,
        **changes,
    }


def post_machine():
    return current_machine(
        version=NEW_VERSION,
        config={"image": f"{IMAGE}@{INDEX}"},
        image_ref={"digest": AMD64},
    )


def status(*machines):
    return {"Name": APP, "Machines": list(machines), "private": SECRET}


def remote_master(sha=HEAD):
    return {"ref": MASTER, "object": {"type": "commit", "sha": sha}, "private": SECRET}


def registry(index=INDEX, amd64=AMD64):
    return {
        "digest": index,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "digest": amd64,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "platform": {"os": "linux", "architecture": "amd64"},
            },
            {
                "digest": "sha256:" + "f" * 64,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "platform": {"os": "unknown", "architecture": "unknown"},
                "annotations": {"private": SECRET},
            },
        ],
        "private": SECRET,
    }


def report(state="QUIET", **overrides):
    users = [USER] if state == "QUIET" else [USER, "tg_234567", "tg_345678"]
    inventories = {user: dict.fromkeys(SOURCE_NAMES, "READ") for user in users}
    unknown = []
    if state == "UNKNOWN" or overrides.pop("unavailable", False):
        for user in users:
            for source in (SOURCE_NAMES[0], SOURCE_NAMES[-1], "run inventory"):
                unknown.append(f"{user}/{source}: unavailable")
                if source != "run inventory":
                    inventories[user][source] = "UNAVAILABLE"
    busy = [
        f"{USER}/{kind}/{SECRET}"
        for kind in ("turn", "task", "delegate", "run", "queue")
    ]
    return {
        "app": APP,
        "state": state,
        "transport": "machines",
        "machine": MACHINE,
        "exec": "PASS",
        "image": CURRENT_IMAGE,
        "users": users,
        "sources": inventories,
        "busy": busy if state == "BUSY" else [],
        "busy_reasons": {
            item: {
                "class": category,
                "last_advance_at": None,
                "terminal_due_at": None,
                "watchdog": False,
            }
            for item, category in zip(busy[3:], ("pending", "overdue_unmanaged"))
        }
        if state == "BUSY"
        else {},
        "unknown": unknown,
        **overrides,
    }


def probe_failure(rc=None, origin=None, kind="invalid_envelope", **overrides):
    return {
        "app": APP,
        "state": "UNKNOWN",
        "transport": "machines",
        "machine": MACHINE,
        "reason": SECRET,
        "failure": {
            "stage": "exec_probe",
            "kind": kind,
            "rc": rc,
            "rc_origin": origin,
            "timed_out": False,
            "stderr_bytes": len(SECRET),
        },
        **overrides,
    }


class FakeCommands:
    def __init__(self, checker):
        self.checker = str(checker)
        self.elapsed = 0
        self.delays = {}
        self.results = {}
        self.calls = Counter()
        self.sequence = []
        self.sleeps = []
        self.deploys = []

    def utc(self):
        return datetime(2026, 11, 21, tzinfo=timezone.utc) + timedelta(
            seconds=self.elapsed
        )

    def monotonic(self):
        return self.elapsed

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.elapsed += seconds

    def run(self, argv, *, capture_output, timeout):
        observed = self.utc().isoformat()
        if argv[:2] == ["flyctl", "deploy"]:
            key, rc, output = "deploy", 0, SECRET
            self.deploys.append(argv)
        elif argv[:2] == ["flyctl", "version"]:
            key, rc, output = "version", 0, f"flyctl v0.4.16 linux/amd64 {SECRET}"
        elif argv == ["fly", "status", "--app", APP, "--json"]:
            key, rc, output = (
                "status",
                0,
                status(post_machine() if self.deploys else current_machine()),
            )
        elif argv == [
            "gh",
            "api",
            "repos/OGismatulin/zeroclaw-source/git/ref/heads/master",
        ]:
            key, rc, output = "master", 0, remote_master()
        elif argv[:4] == ["docker", "buildx", "imagetools", "inspect"]:
            key, rc, output = "registry", 0, registry()
        elif argv[:2] == [sys.executable, self.checker]:
            key, rc, output = "scan", 0, report()
            if argv[2:] != [
                "--quiescence",
                "--json",
                "--transport",
                "machines",
                "--machine",
                MACHINE,
                "--expected-image",
                CURRENT_IMAGE,
            ]:
                raise ValueError(f"Unexpected scan command: {SECRET}")
        else:
            raise ValueError(f"Unexpected fake command: {SECRET}")
        self.calls[key] += 1
        self.sequence.append((key, timeout))
        index = self.calls[key] - 1
        alternatives = self.results.get(key, [])
        if index < len(alternatives):
            if isinstance(alternatives[index], Exception):
                raise alternatives[index]
            rc, output = alternatives[index]
        if key == "scan" and isinstance(output, dict):
            output = {"observed_at": observed, **output}
        delays = self.delays.get(key, [])
        if index < len(delays):
            if delays[index] > timeout:
                self.elapsed += timeout
                raise subprocess.TimeoutExpired(
                    argv, timeout, output=SECRET, stderr=SECRET
                )
            self.elapsed += delays[index]
        if not capture_output or not 0 < timeout <= 600:
            raise ValueError(f"Unbounded output or command: {SECRET}")
        if not isinstance(output, str):
            output = json.dumps(output)
        return subprocess.CompletedProcess(argv, rc, output.encode(), SECRET.encode())


class QuiescenceTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.checker = self.root / "checker.py"
        self.checker.touch()
        self.receipt = self.root / "evidence" / "result.json"
        self.commands = FakeCommands(self.checker)

    def check(
        self,
        reason,
        *,
        mode="deploy",
        env=None,
        tag=None,
        rc=None,
        deploys=0,
        scans=None,
    ):
        argv = [
            "--preflight",
            str(self.checker),
            "--receipt",
            str(self.receipt),
            "--mode",
            mode,
            "--upstream-sha",
            HEAD if mode == "deploy" else "",
        ]
        if mode == "deploy" or tag is not None:
            argv += ["--image-tag", tag if tag is not None else TAG]
        if env is None:
            env = (
                ENV
                if mode == "deploy"
                else {**ENV, "GITHUB_EVENT_NAME": "workflow_dispatch"}
            )
        if env.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and mode == "deploy":
            argv[argv.index("--upstream-sha") + 1] = ""
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.dict(os.environ, env, clear=True),
            patch.object(subprocess, "run", side_effect=self.commands.run),
            patch.object(gate, "utc_now", self.commands.utc),
            patch.object(gate.time, "monotonic", self.commands.monotonic),
            patch.object(gate.time, "sleep", self.commands.sleep),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            self.assertEqual(
                gate.main(argv),
                rc
                if rc is not None
                else 0
                if reason == "QUIET" or mode == "observe"
                else 10,
            )
        self.assertEqual(len(self.commands.deploys), deploys)
        if scans is not None:
            self.assertEqual(self.commands.calls["scan"], scans)
        raw = self.receipt.read_text()
        self.assertNotIn(SECRET, raw + stdout.getvalue() + stderr.getvalue())
        self.assertNotIn(USER, raw + stdout.getvalue() + stderr.getvalue())
        self.assertEqual(list(self.receipt.parent.iterdir()), [self.receipt])
        observed = json.loads(raw)
        self.assertEqual(observed["decision"], "ALLOW" if reason == "QUIET" else "HOLD")
        self.assertEqual(observed["reason_code"], reason)
        self.assertEqual(observed["deploy_invoked"], bool(deploys))
        return observed

    def test_busy_then_quiet_deploys_pinned_index_once(self):
        changed_index = "sha256:" + "f" * 64
        self.commands.results = {
            "scan": [(1, report("BUSY")), (0, report())],
            "registry": [(0, registry()), (0, registry(index=changed_index))],
        }
        receipt = self.check("QUIET", deploys=1, scans=2)
        self.assertEqual(self.commands.sleeps, [60])
        self.assertEqual(self.commands.calls["registry"], 1)
        self.assertEqual(
            self.commands.deploys,
            [["flyctl", "deploy", "--app", APP, "--image", f"{IMAGE}@{INDEX}"]],
        )
        self.assertEqual(receipt["candidate_amd64_digest"], AMD64)
        self.assertEqual(receipt["candidate_index_digest"], INDEX)
        self.assertEqual(receipt["machine_after"]["version"], NEW_VERSION)
        self.assertEqual(receipt["workflow_sha"], ENV["GITHUB_WORKFLOW_SHA"])
        self.assertEqual(receipt["flyctl_version"], "v0.4.16")
        self.assertEqual(
            [
                key
                for key, _ in self.commands.sequence
                if key in {"status", "master", "scan", "deploy"}
            ],
            [
                "status",
                "master",
                "scan",
                "status",
                "master",
                "scan",
                "status",
                "master",
                "status",
                "master",
                "deploy",
                "status",
            ],
        )

    def test_five_busy_scans_end_window(self):
        self.commands.results["scan"] = [(1, report("BUSY"))] * 6
        self.check("BUSY_WINDOW", scans=5)
        self.assertEqual(self.commands.sleeps, [60] * 4)

    def test_elapsed_window_stops_before_fifth_scan(self):
        self.commands.results["scan"] = [(1, report("BUSY"))] * 6
        self.commands.delays["scan"] = [120, 120, 120, 55]
        self.check("BUSY_WINDOW", scans=4)
        self.assertEqual(self.commands.sleeps, [60] * 3)
        self.assertEqual(
            [timeout for key, timeout in self.commands.sequence if key == "scan"],
            [120, 120, 120, 60],
        )

    def test_scanner_stops_at_the_remaining_window_budget(self):
        self.commands.results["scan"] = [(1, report("BUSY"))] * 6
        self.commands.delays["scan"] = [120, 120, 120, 90]
        self.check("BUSY_WINDOW", scans=4)
        self.assertEqual(self.commands.sleeps, [60] * 3)
        self.assertEqual(self.commands.elapsed, 600)

    def test_busy_with_unknown_holds_without_deploy(self):
        self.commands.results["scan"] = [(1, report("BUSY", unavailable=True))]
        receipt = self.check("BUSY", scans=1)
        self.assertEqual(self.commands.sleeps, [])
        self.assertEqual(receipt["busy_count"], 5)
        self.assertEqual(
            receipt["busy_by_kind"],
            dict.fromkeys(("turn", "task", "delegate", "run", "queue"), 1),
        )
        self.assertEqual(receipt["busy_by_reason"]["pending"], 1)
        self.assertEqual(receipt["busy_by_reason"]["overdue_unmanaged"], 1)
        self.assertEqual(receipt["unknown_count"], 9)
        self.assertEqual(receipt["machine_before"], receipt["machine_after"])

    def test_unknown_sources_hold(self):
        self.commands.results["scan"] = [(3, report("UNKNOWN"))]
        receipt = self.check("UNKNOWN", scans=1)
        self.assertEqual(receipt["unknown_count"], 9)
        self.assertEqual(receipt["users_count"], 3)

    def test_image_mismatch_holds_without_inventory(self):
        failure = probe_failure()["failure"] | {"stage": "image", "kind": "mismatch"}
        value = probe_failure(
            state="BUSY",
            exec="PASS",
            reason="image mismatch",
            image=f"{IMAGE}:changed",
            failure=failure,
        )
        self.commands.results["scan"] = [(1, value)]
        self.check("TARGET_CHANGED", scans=1)
        self.assertEqual(self.commands.sleeps, [])

    def test_probe_diagnostics_allowlist_preserves_unknown_and_inner_exit_codes(self):
        for failure in (
            probe_failure(),
            probe_failure(7, "inner", "nonzero"),
            probe_failure(9, "outer", "nonzero"),
        ):
            with self.subTest(diagnostic=failure["failure"]):
                self.commands = FakeCommands(self.checker)
                self.commands.results["scan"] = [(3, failure)]
                receipt = self.check("PROBE_FAILED", scans=1)
                self.assertEqual(receipt["failure"], failure["failure"])

    def test_invalid_reports_hold(self):
        for bad_report in (
            (0, report(users=[])),
            (0, report(users=[USER, USER])),
            (0, report(sources={USER: dict.fromkeys(SOURCE_NAMES, "UNAVAILABLE")})),
            (0, report(sources={USER: {"control_plane.db": "READ"}})),
            (0, report(reason=SECRET)),
            (0, report(failure=None)),
            (0, report(quiescence="NOT_REQUESTED")),
            (1, report()),
            (0, '{"app":"a","app":"b"}'),
            (0, report(busy={})),
            (0, report(busy_reasons=[])),
            (0, report(unknown=None)),
            (0, report(app=SECRET)),
            (0, report(machine="00000000000000")),
            (0, report(image=f"{IMAGE}:changed")),
            (0, report(transport="ssh")),
            (0, report(exec="FAIL")),
            (0, report(extra=[])),
            (1, report("BUSY", busy=[f"{USER}/other/{SECRET}"])),
            (1, report("BUSY", busy_reasons={SECRET: {"class": "pending"}})),
            (3, report("UNKNOWN", unknown=[])),
            (3, report("UNKNOWN", busy=[f"{USER}/task/{SECRET}"])),
            (3, probe_failure(failure={"stage": SECRET})),
            (3, probe_failure(False, "inner", "nonzero")),
            (3, probe_failure(7, None, "nonzero")),
            (3, probe_failure(kind=SECRET)),
            (3, probe_failure(exec=SECRET)),
        ):
            with self.subTest(raw=bad_report[0]):
                self.commands = FakeCommands(self.checker)
                self.commands.results["scan"] = [bad_report]
                self.check("INVALID_REPORT", scans=1)

    def test_scanner_subprocess_is_bounded_at_120_seconds(self):
        self.commands.delays["scan"] = [121]
        self.check("SCANNER_TIMEOUT", scans=1)
        self.assertEqual(
            [timeout for key, timeout in self.commands.sequence if key == "scan"], [120]
        )

    def test_observed_timestamp_must_fall_within_scan(self):
        for offset in (-1, 1):
            with self.subTest(offset=offset):
                self.commands = FakeCommands(self.checker)
                observed = self.commands.utc() + timedelta(seconds=offset)
                self.commands.results["scan"] = [
                    (0, report(observed_at=observed.isoformat()))
                ]
                self.check("INVALID_REPORT", scans=1)

    def test_post_scan_identity_and_roster_drift_hold(self):
        for changes in (
            {"id": "0123456789abce"},
            {"version": NEW_VERSION},
            {"state": "stopped"},
            {"config": {"image": f"{IMAGE}:changed"}},
            {"image_ref": {"digest": AMD64}},
        ):
            with self.subTest(changed=changes):
                self.commands = FakeCommands(self.checker)
                self.commands.results["status"] = [
                    (0, status(current_machine())),
                    (0, status(current_machine(**changes))),
                ]
                self.check("TARGET_CHANGED", scans=1)
        for machines in ([], [current_machine(), current_machine(state="stopped")]):
            with self.subTest(count=len(machines)):
                self.commands = FakeCommands(self.checker)
                self.commands.results["status"] = [(0, status(*machines))]
                self.check("ROSTER_DRIFT", scans=0)

    def test_busy_rechecks_identity_before_waiting(self):
        self.commands.results["status"] = [
            (0, status(current_machine())),
            (0, status(current_machine(version=NEW_VERSION))),
        ]
        self.commands.results["scan"] = [(1, report("BUSY"))]
        self.check("TARGET_CHANGED", scans=1)
        self.assertEqual(self.commands.sleeps, [])

    def test_master_change_holds_before_and_after_a_scan(self):
        for phase in range(3):
            with self.subTest(phase=phase):
                self.commands = FakeCommands(self.checker)
                self.commands.results["master"] = [(0, remote_master())] * phase + [
                    (0, remote_master("f" * 40))
                ]
                self.check("SUPERSEDED", scans=min(phase, 1))

    def test_final_identity_reads_count_against_freshness(self):
        self.commands.delays = {"status": [0, 6, 12], "master": [0, 6, 8]}
        self.check("STALE", scans=1)
        self.assertEqual(self.commands.calls["master"], 3)

    def test_expected_external_refusals_have_typed_reason(self):
        for tool, reason in (
            ("status", "MACHINE_STATUS_FAILED"),
            ("master", "MASTER_READ_FAILED"),
            ("registry", "REGISTRY_FAILED"),
        ):
            for value in ((1, SECRET), (0, '{"bad":'), (0, {"private": SECRET})):
                with self.subTest(tool=tool, rc=value[0]):
                    self.commands = FakeCommands(self.checker)
                    self.commands.results[tool] = [value]
                    self.check(reason, scans=0)

    def test_registry_rejects_ambiguous_and_missing_amd64(self):
        for manifests in (
            [],
            registry()["manifests"][:1] * 2,
            registry()["manifests"][1:],
        ):
            with self.subTest(count=len(manifests)):
                self.commands = FakeCommands(self.checker)
                self.commands.results["registry"] = [
                    (0, registry() | {"manifests": manifests})
                ]
                self.check("REGISTRY_FAILED", scans=0)

    def test_deploy_failure_and_post_deploy_drift_are_errors(self):
        self.commands.results["deploy"] = [(4, SECRET)]
        receipt = self.check("DEPLOY_FAILED", deploys=1, scans=1)
        self.assertEqual(receipt["deploy_exit_code"], 4)
        self.assertIsNotNone(receipt["deploy_started_at"])
        for bad_status in (
            status(current_machine()),
            status(post_machine() | {"image_ref": {"digest": CURRENT}}),
            status(post_machine() | {"state": "stopped"}),
            status(post_machine() | {"version": VERSION}),
        ):
            with self.subTest(machine=bad_status["Machines"][0]["state"]):
                self.commands = FakeCommands(self.checker)
                self.commands.results["status"] = [
                    (0, status(current_machine()))
                ] * 3 + [(0, bad_status)]
                receipt = self.check("POST_DEPLOY_DRIFT", deploys=1, scans=1)
                self.assertEqual(receipt["deploy_exit_code"], 0)

    def test_unexpected_exception_has_safe_receipt(self):
        self.commands.results["scan"] = [RuntimeError(SECRET)]
        self.check("CONTROLLER_ERROR", scans=1)

    def test_missing_pinned_checker_holds_without_calls(self):
        self.checker.unlink()
        self.check("INTEGRATION_UNAVAILABLE", scans=0)
        self.assertEqual(self.commands.calls, {})

    def test_observe_neither_resolves_tag_nor_deploys(self):
        for input_report, reason in (
            ((0, report()), "QUIET"),
            ((3, report("UNKNOWN")), "UNKNOWN"),
            ((1, report("BUSY")), "BUSY"),
        ):
            with self.subTest(reason=reason):
                self.commands = FakeCommands(self.checker)
                self.commands.results["scan"] = [input_report]
                receipt = self.check(reason, mode="observe", scans=1)
                self.assertIsNone(receipt["image_tag"])
                self.assertIsNone(receipt["candidate_amd64_digest"])
                self.assertEqual(self.commands.calls["registry"], 0)
                self.assertEqual(self.commands.calls["master"], 0)

    def test_observe_requires_exact_event_ref_and_no_tag(self):
        base_env = {**ENV, "GITHUB_EVENT_NAME": "workflow_dispatch"}
        for env, tag in (
            (ENV, None),
            (base_env | {"GITHUB_REF": "refs/heads/MASTER"}, None),
            (base_env, "tag"),
        ):
            with self.subTest(
                event=env["GITHUB_EVENT_NAME"], ref=env["GITHUB_REF"], tag=tag
            ):
                self.commands = FakeCommands(self.checker)
                self.check(
                    "CONTROLLER_ERROR", mode="observe", env=env, tag=tag, rc=10, scans=0
                )
                self.assertEqual(self.commands.calls, {})

    def test_manual_legacy_image_can_be_latest(self):
        receipt = self.check(
            "QUIET",
            env={**ENV, "GITHUB_EVENT_NAME": "workflow_dispatch"},
            tag="latest",
            deploys=1,
            scans=1,
        )
        self.assertEqual(receipt["image_tag"], "latest")
        self.assertIsNone(receipt["upstream_sha"])
        self.assertEqual(self.commands.calls["master"], 0)


if __name__ == "__main__":
    unittest.main()
