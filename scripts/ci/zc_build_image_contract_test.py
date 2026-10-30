from __future__ import annotations

import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ROOT / ".github/workflows/zc-build-image.yml"
WORKFLOW = WORKFLOW_PATH.read_text(encoding="utf-8")
OUTPUT = "needs.classify-ref.outputs.is_master"
BUILD_IF = f"${{{{ {OUTPUT} == 'true' || {OUTPUT} == 'false' }}}}"
GROUP = (
    f"${{{{ {OUTPUT} == 'true' && 'zc-build-image-master' || "
    "format('zc-build-image-other-{0}', github.ref) }}"
)
LATEST = f"type=raw,value=latest,enable=${{{{ {OUTPUT} == 'true' }}}}"


def job_block(job_id: str, workflow: str = WORKFLOW) -> str:
    match = re.search(
        rf"^  {re.escape(job_id)}:\n.*?(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        workflow,
        flags=re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"job {job_id!r} not found in {WORKFLOW_PATH}")
    return match.group(0)


def ref_script(classify: str) -> str:
    match = re.search(
        r"^      - id: ref\n        shell: bash\n        run: \|\n"
        r"(?P<script>(?:          [^\n]*\n|\n)+)",
        classify,
        flags=re.MULTILINE,
    )
    if match is None:
        raise AssertionError("bash ref classification step not found")
    return textwrap.dedent(match.group("script"))


class ZcBuildImageContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.build = job_block("build")

    def test_classifier_produces_job_output_by_bytewise_shell_comparison(self) -> None:
        classify = job_block("classify-ref")
        self.assertRegex(
            classify, r"(?m)^      is_master: \$\{\{ steps.ref.outputs.is_master \}\}$"
        )
        script = ref_script(classify)
        self.assertIn('if [[ "$GITHUB_REF" == \'refs/heads/master\' ]]; then', script)
        self.assertNotIn("${{", script)
        self.assertNotIn("github.ref ==", WORKFLOW)

    def test_build_requires_valid_classifier_output(self) -> None:
        self.assertRegex(self.build, r"(?m)^    needs: classify-ref$")
        self.assertIn(f"    if: {BUILD_IF}\n", self.build)

    def test_concurrency_uses_disjoint_master_and_other_prefixes(self) -> None:
        self.assertIn(f"      group: {GROUP}\n", self.build)
        self.assertRegex(self.build, r"(?m)^      cancel-in-progress: true$")
        self.assertNotRegex(WORKFLOW, r"(?m)^concurrency:")

    def test_latest_is_gated_and_sha_image_contract_is_preserved(self) -> None:
        self.assertRegex(
            self.build, r"(?m)^          images: ghcr.io/ogismatulin/zeroclaw$"
        )
        self.assertEqual(self.build.count("type=raw,value=latest"), 1)
        self.assertIn(f"            {LATEST}\n", self.build)
        self.assertRegex(
            self.build, r"(?m)^            type=sha,prefix=sha-,format=short$"
        )
        self.assertIn("tags: ${{ steps.meta.outputs.tags }}", self.build)
        self.assertRegex(self.build, r"(?m)^          push: true$")

    def test_real_bash_classifier_ref_event_matrix(self) -> None:
        script = ref_script(job_block("classify-ref"))
        groups = []
        cases = (
            ("refs/heads/master", "push", "true"),
            ("refs/heads/master", "workflow_dispatch", "true"),
            ("refs/heads/feature/x", "workflow_dispatch", "false"),
            ("refs/tags/v1", "workflow_dispatch", "false"),
            ("refs/heads/MASTER", "workflow_dispatch", "false"),
            ("refs/heads/master/child", "workflow_dispatch", "false"),
            ("", "workflow_dispatch", "false"),
        )
        self.assertIn(f"      group: {GROUP}\n", self.build)
        self.assertIn(f"            {LATEST}\n", self.build)
        for ref, event, expected in cases:
            with (
                self.subTest(ref=ref, event=event),
                tempfile.TemporaryDirectory() as tmp,
            ):
                output = Path(tmp) / "output"
                env = {
                    **os.environ,
                    "GITHUB_REF": ref,
                    "GITHUB_EVENT_NAME": event,
                    "GITHUB_OUTPUT": str(output),
                }
                result = subprocess.run(
                    ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", script],
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(output.read_text(), f"is_master={expected}\n")
                is_master = output.read_text().strip().partition("=")[2]
                master_group, other_group = re.findall(
                    r"'(zc-build-image-[^']+)'", GROUP
                )
                group = master_group if is_master == "true" else other_group.format(ref)
                groups.append(group.casefold())
                self.assertEqual(is_master == "true", ref == "refs/heads/master")
        self.assertEqual(groups[0], groups[1])
        for group in groups[2:]:
            self.assertNotEqual(group, groups[0])

    def test_missing_and_invalid_outputs_block_build(self) -> None:
        self.assertIn(f"    if: {BUILD_IF}\n", self.build)
        allowed = re.findall(r"== '([^']+)'", BUILD_IF)
        for output in ("", "unexpected", "0", "true false", "true\nfalse"):
            with self.subTest(output=output):
                self.assertNotIn(output.casefold(), allowed)

    def test_contract_test_runs_in_required_lint_job(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        lint = job_block("lint", ci)
        self.assertIn("run: python3 scripts/ci/zc_build_image_contract_test.py", lint)
        gate = re.search(r"(?m)^  ([a-zA-Z0-9_-]+):\n    name: CI Required Gate$", ci)
        self.assertIsNotNone(gate)
        required = job_block(gate.group(1), ci)
        self.assertRegex(required, r"(?m)^    needs: \[[^\n]*\blint\b[^\n]*\]$")

    def test_unrecognized_job_and_step_formats_fail_closed(self) -> None:
        with self.assertRaisesRegex(AssertionError, "job 'classify-ref' not found"):
            job_block("classify-ref", "jobs:\n  unrelated:\n")
        with self.assertRaisesRegex(
            AssertionError, "bash ref classification step not found"
        ):
            ref_script("  classify-ref:\n    steps: []\n")


if __name__ == "__main__":
    unittest.main()
