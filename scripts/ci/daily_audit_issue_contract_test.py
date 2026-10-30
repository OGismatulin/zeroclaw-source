from __future__ import annotations

import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "example/project"
PREFIX = "ci: Advisory scan failed — "
URL = "https://github.com/example/project/issues/101"
HAS_ARGS = ["api", f"repos/{REPOSITORY}", "--jq", ".has_issues"]
LIST_ARGS = [
    "api",
    "--paginate",
    f"repos/{REPOSITORY}/issues?state=open&per_page=100",
    "--slurp",
]
SENTINELS = (Path("/tmp/advisory-output.txt"), Path("/tmp/issue-body.md"))


def gh_stub() -> None:
    state_path = Path(os.environ["GH_STUB_STATE"])
    state = json.loads(state_path.read_text())
    args = sys.argv[2:]

    def finish(status: int, output: str = "", error: str = "") -> None:
        state.setdefault("calls", []).append({"argv": args, "status": status})
        state_path.write_text(json.dumps(state))
        sys.stdout.write(output)
        sys.stderr.write(error)
        raise SystemExit(status)

    if args == HAS_ARGS:
        if state.get("fail_has"):
            finish(21, error="repository API refused\n")
        finish(0, state.get("has_issues", "true") + "\n")
    if args == LIST_ARGS:
        if state.get("fail_list"):
            finish(22, error="issue API refused\n")
        finish(0, state.get("list_raw", json.dumps(state.get("pages", [[]]))))
    if args == [
        "issue",
        "list",
        "--repo",
        REPOSITORY,
        "--label",
        "security",
        "--state",
        "open",
        "--search",
        "Advisory scan failed in:title",
        "--json",
        "number",
        "--jq",
        "length",
    ]:
        finish(0, "0\n")
    if args[:2] == ["issue", "create"]:
        if "--label" in args:
            finish(42, error="could not add label: 'security' not found\n")
        if state.get("fail_create"):
            finish(23, error="issue create refused\n")
        if (
            len(args) != 8
            or args[2:4] != ["--repo", REPOSITORY]
            or args[4] != "--title"
            or args[6] != "--body-file"
        ):
            finish(97, error=f"unexpected gh argv: {args!r}\n")
        created = {
            "title": args[5],
            "user": {"login": "github-actions[bot]"},
            "html_url": URL,
            "labels": [],
        }
        state.setdefault("created", []).append(created)
        state.setdefault("pages", [[]])[-1].append(created)
        state["body"] = Path(args[7]).read_text()
        finish(0, URL + "\n")
    finish(97, error=f"unexpected gh argv: {args!r}\n")


def issue(**changes: object) -> dict:
    return {
        "title": PREFIX + "2020-01-01",
        "user": {"login": "github-actions[bot]"},
        "html_url": URL,
        "labels": [{"name": "security"}, {"name": "risk:high"}],
        **changes,
    }


def step(workflow: str, name: str) -> str:
    match = re.search(
        rf"^      - name: {re.escape(name)}\n.*?(?=^      - |\Z)",
        workflow,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"workflow step {name!r} missing")
    return match.group(0)


class DailyAuditIssueContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sentinels = {
            path: path.read_bytes() if path.exists() else None for path in SENTINELS
        }

    @classmethod
    def tearDownClass(cls) -> None:
        for path, before in cls.sentinels.items():
            after = path.read_bytes() if path.exists() else None
            if before != after:
                raise AssertionError(f"shared temporary file changed: {path}")

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.state_path = self.directory / "state.json"
        self.output = self.directory / "github-output"
        self.body = self.directory / "body.md"
        self.advisory = self.directory / "advisory.txt"
        self.advisory.write_text("fixture advisory\n")
        launcher = self.directory / "gh"
        launcher.write_text(
            '#!/bin/sh\nexec "$GH_STUB_PYTHON" "$GH_STUB_SCRIPT" --gh-stub "$@"\n'
        )
        launcher.chmod(0o755)
        self.env = {
            **os.environ,
            "PATH": f"{self.directory}{os.pathsep}{os.environ['PATH']}",
            "GH_STUB_PYTHON": sys.executable,
            "GH_STUB_SCRIPT": str(Path(__file__).resolve()),
            "GH_STUB_STATE": str(self.state_path),
            "GITHUB_REPOSITORY": REPOSITORY,
            "GITHUB_OUTPUT": str(self.output),
            "ADVISORY_OUTPUT": str(self.advisory),
            "ISSUE_BODY": str(self.body),
            "RUN_URL": "https://example.invalid/run/1",
        }

    def run_script(
        self, state: dict | None = None
    ) -> tuple[subprocess.CompletedProcess, dict]:
        if state is not None:
            self.state_path.write_text(json.dumps(state))
        self.output.write_text("")
        result = subprocess.run(
            [
                "bash",
                "--noprofile",
                "--norc",
                "-eo",
                "pipefail",
                str(ROOT / "scripts/ci/daily_audit_open_issue.sh"),
            ],
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )
        return result, json.loads(self.state_path.read_text())

    def assert_calls(self, state: dict, calls: list[tuple[list[str], int]]) -> None:
        self.assertEqual(
            state["calls"], [{"argv": argv, "status": status} for argv, status in calls]
        )

    def create_args(self) -> list[str]:
        return [
            "issue",
            "create",
            "--repo",
            REPOSITORY,
            "--title",
            PREFIX + datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"),
            "--body-file",
            str(self.body),
        ]

    def test_missing_labels_creates_once_and_second_run_returns_existing_url(
        self,
    ) -> None:
        result, state = self.run_script({"pages": [[]], "available_labels": []})
        self.assertEqual(result.returncode, 0, f"{result.stderr}\n{state['calls']!r}")
        self.assertEqual(self.output.read_text(), f"issue_url={URL}\n")
        self.assertEqual(len(state["created"]), 1)
        self.assertIn("Workflow run: https://example.invalid/run/1", state["body"])
        self.assertIn("```\nfixture advisory\n```", state["body"])
        self.assert_calls(
            state, [(HAS_ARGS, 0), (LIST_ARGS, 0), (self.create_args(), 0)]
        )
        result, repeated = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_text(), f"issue_url={URL}\n")
        self.assertEqual(len(repeated["created"]), 1)
        self.assert_calls(
            repeated,
            [
                (HAS_ARGS, 0),
                (LIST_ARGS, 0),
                (self.create_args(), 0),
                (HAS_ARGS, 0),
                (LIST_ARGS, 0),
            ],
        )

    def test_legacy_labelled_issue_and_second_page_are_deduplicated(self) -> None:
        for pages in ([[issue()]], [[issue(title="unrelated")], [issue()]]):
            with self.subTest(pages=pages):
                result, state = self.run_script({"pages": pages})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.output.read_text(), f"issue_url={URL}\n")
                self.assertEqual(state.get("created", []), [])
                self.assert_calls(state, [(HAS_ARGS, 0), (LIST_ARGS, 0)])

    def test_nullable_author_before_bot_issue_on_second_page_is_deduplicated(
        self,
    ) -> None:
        result, state = self.run_script(
            {"pages": [[issue(title="unrelated", user=None)], [issue()]]}
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_text(), f"issue_url={URL}\n")
        self.assertEqual(state.get("created", []), [])
        self.assert_calls(state, [(HAS_ARGS, 0), (LIST_ARGS, 0)])

    def test_nullable_author_does_not_suppress_creation_or_repeat_deduplication(
        self,
    ) -> None:
        result, state = self.run_script({"pages": [[issue(user=None)]]})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_text(), f"issue_url={URL}\n")
        self.assertEqual(len(state["created"]), 1)
        self.assert_calls(
            state, [(HAS_ARGS, 0), (LIST_ARGS, 0), (self.create_args(), 0)]
        )
        result, repeated = self.run_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.output.read_text(), f"issue_url={URL}\n")
        self.assertEqual(len(repeated["created"]), 1)
        self.assert_calls(
            repeated,
            [
                (HAS_ARGS, 0),
                (LIST_ARGS, 0),
                (self.create_args(), 0),
                (HAS_ARGS, 0),
                (LIST_ARGS, 0),
            ],
        )

    def test_pr_similar_title_and_foreign_author_do_not_suppress_creation(self) -> None:
        cases = (
            issue(pull_request={"url": "https://example.invalid/pr/1"}),
            issue(title="ci: Advisory scan failed - 2020-01-01"),
            issue(title="ci: Advisory scan failed —2020-01-01"),
            issue(title="prefix " + PREFIX + "2020-01-01"),
            issue(user={"login": "another-user"}),
            issue(user={"login": "GitHub-Actions[bot]"}),
        )
        for existing in cases:
            with self.subTest(issue=existing):
                result, state = self.run_script({"pages": [[existing]]})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(state["created"]), 1)
                self.assertEqual(self.output.read_text(), f"issue_url={URL}\n")
                self.assert_calls(
                    state, [(HAS_ARGS, 0), (LIST_ARGS, 0), (self.create_args(), 0)]
                )

    def test_disabled_issues_notice(self) -> None:
        result, state = self.run_script({"has_issues": "false"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("::notice::Repository issues are disabled", result.stdout)
        self.assertEqual(self.output.read_text(), "issue_url=\n")
        self.assertEqual(state.get("created", []), [])
        self.assert_calls(state, [(HAS_ARGS, 0)])

    def test_non_boolean_has_issues_is_error(self) -> None:
        for value in ("null", "1", "", "TRUE", "false\ntrue"):
            with self.subTest(value=value):
                result, state = self.run_script({"has_issues": value})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("::error::", result.stderr)
                self.assertNotIn("::notice::", result.stdout)
                self.assertEqual(self.output.read_text(), "")
                self.assertEqual(state.get("created", []), [])
                self.assert_calls(state, [(HAS_ARGS, 0)])

    def test_api_and_create_failures_stop_without_success_or_retry(self) -> None:
        for field, status, calls in (
            ("fail_has", 21, [(HAS_ARGS, 21)]),
            ("fail_list", 22, [(HAS_ARGS, 0), (LIST_ARGS, 22)]),
            (
                "fail_create",
                23,
                [(HAS_ARGS, 0), (LIST_ARGS, 0), (self.create_args(), 23)],
            ),
        ):
            with self.subTest(field=field):
                result, state = self.run_script({field: True})
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual(self.output.read_text(), "")
                self.assertEqual(state.get("created", []), [])
                self.assertNotIn("::notice::", result.stdout)
                self.assertNotIn(URL, result.stdout)
                self.assert_calls(state, calls)

    def test_invalid_json_and_unexpected_response_shapes_are_errors(self) -> None:
        for raw in (
            "not json",
            "null",
            "{}",
            "[]",
            '[{"message":"API error"}]',
            "[[null]]",
            "[[{}]]",
            '[[{"title":2,"user":{},"html_url":"x"}]]',
            json.dumps([[issue()], {"message": "bad second page"}]),
            json.dumps([[issue(user="invalid")]]),
            json.dumps([[issue(user=[])]]),
            json.dumps([[issue(user={})]]),
            json.dumps([[issue(user={"login": None})]]),
            json.dumps([[issue(user={"login": 1})]]),
            json.dumps(
                [[{key: value for key, value in issue().items() if key != "user"}]]
            ),
        ):
            with self.subTest(raw=raw):
                result, state = self.run_script({"list_raw": raw})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.output.read_text(), "")
                self.assertEqual(state.get("created", []), [])
                self.assert_calls(state, [(HAS_ARGS, 0), (LIST_ARGS, 0)])

    def test_workflow_calls_script_and_keeps_failure_conditions_and_concurrency(
        self,
    ) -> None:
        workflow = (ROOT / ".github/workflows/daily-audit.yml").read_text()
        opener = step(workflow, "Open issue on advisory failure")
        self.assertRegex(opener, r"(?m)^        if: steps\.scan\.outcome == 'failure'$")
        self.assertRegex(
            opener, r"(?m)^        run: bash scripts/ci/daily_audit_open_issue\.sh$"
        )
        propagate = step(workflow, "Propagate scan failure")
        self.assertRegex(
            propagate,
            r"(?m)^        if: always\(\) && steps\.scan\.outcome == 'failure'$",
        )
        self.assertRegex(propagate, r"(?m)^          exit 1$")
        self.assertIn(
            "concurrency:\n  group: daily-audit\n  cancel-in-progress: false\n",
            workflow,
        )
        scan = step(workflow, "Run advisory scan")
        self.assertIn("        continue-on-error: true\n", scan)
        self.assertIn(
            "cargo deny check advisories 2>&1 | tee /tmp/advisory-output.txt", scan
        )
        self.assertIn('exit "${PIPESTATUS[0]}"', scan)
        script = propagate.split("        run: |\n", 1)[1]
        script = "\n".join(line[10:] for line in script.splitlines())
        for issue_url in ("", URL):
            result = subprocess.run(
                ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
                env={**os.environ, "ISSUE_URL": issue_url},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("::error::Advisory scan failed.", result.stdout)

    def test_contract_suite_runs_in_required_lint_job(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        lint = re.search(
            r"^  lint:\n.*?(?=^  [\w-]+:\n|\Z)", ci, re.MULTILINE | re.DOTALL
        )
        self.assertIsNotNone(lint)
        self.assertIn(
            "run: python3 scripts/ci/daily_audit_issue_contract_test.py", lint.group()
        )
        self.assertIn(
            "run: python3 scripts/ci/zc_build_image_contract_test.py", lint.group()
        )
        gate = re.search(
            r"^  [\w-]+:\n    name: CI Required Gate\n.*?(?=^  [\w-]+:\n|\Z)",
            ci,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(gate)
        self.assertRegex(gate.group(), r"(?m)^    needs: \[[^\n]*\blint\b[^\n]*\]$")


if __name__ == "__main__":
    if sys.argv[1:2] == ["--gh-stub"]:
        gh_stub()
    else:
        unittest.main()
