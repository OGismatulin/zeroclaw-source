from __future__ import annotations

import json
import os
import re
import subprocess
import sys
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


def receipt_step(build: str) -> str:
    steps = re.findall(
        r"^      - [^\n]+\n.*?(?=^      - |\Z)",
        build,
        flags=re.MULTILINE | re.DOTALL,
    )
    matches = [step for step in steps if "        id: image-receipt\n" in step]
    if len(matches) != 1:
        raise AssertionError("exactly one image receipt step required")
    return matches[0]


def receipt_script(step: str) -> str:
    match = re.search(r"^        run: \|\n(.*)", step, flags=re.MULTILINE | re.DOTALL)
    if match is None:
        raise AssertionError("image receipt script not found")
    return textwrap.dedent(match.group(1))


class ZcBuildImageContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.build = job_block("build")

    def test_classifier_produces_job_output_by_bytewise_shell_comparison(self) -> None:
        classify = job_block("classify-ref")
        self.assertRegex(
            classify, r"(?m)^      is_master: \$\{\{ steps.ref.outputs.is_master \}\}$"
        )
        script = ref_script(classify)
        self.assertIn("if [[ \"$GITHUB_REF\" == 'refs/heads/master' ]]; then", script)
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

    def run_receipt(
        self,
        overrides: dict[str, str] | None = None,
        workflow: str = WORKFLOW,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, str] | None, bool]:
        step = receipt_step(job_block("build", workflow))
        bindings = dict(
            re.findall(
                r"^          (BUILD_[A-Z_]+): \$\{\{ ([^}]+) \}\}$", step, re.MULTILINE
            )
        )
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            subprocess.run(["git", "init", "-q", tmp], check=True, capture_output=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "-c",
                    "commit.gpgsign=false",
                    "-c",
                    "user.name=CI Fixture",
                    "-c",
                    "user.email=ci@example.invalid",
                    "commit",
                    "--allow-empty",
                    "-qm",
                    "fixture",
                ],
                cwd=tmp,
                check=True,
                capture_output=True,
            )
            head = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=tmp, text=True
            ).strip()
            context = {
                "github.sha": head,
                "steps.image.outputs.digest": "sha256:" + "a" * 64,
                "github.run_id": "12345",
                "github.ref": "refs/heads/master",
                **(overrides or {}),
            }
            env = {
                **os.environ,
                **{key: context.get(value, "") for key, value in bindings.items()},
            }
            script = directory / "receipt.py"
            script.write_text(receipt_script(step), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(script)],
                cwd=tmp,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            artifact = directory / "image-digest.json"
            payload = json.loads(artifact.read_text()) if artifact.exists() else None
            return result, payload, (directory / "injection-marker").exists()

    def test_receipt_uses_successful_build_digest_and_exact_run_context(self) -> None:
        self.assertRegex(
            self.build,
            r"(?m)^      - uses: docker/build-push-action@v6\n        id: image$",
        )
        step = receipt_step(self.build)
        self.assertIn("        shell: python\n", step)
        for key, expression in (
            ("BUILD_HEAD_SHA", "github.sha"),
            ("BUILD_IMAGE_DIGEST", "steps.image.outputs.digest"),
            ("BUILD_RUN_ID", "github.run_id"),
            ("BUILD_REF", "github.ref"),
        ):
            self.assertIn(f"          {key}: ${{{{ {expression} }}}}\n", step)
        self.assertNotIn("${{", receipt_script(step))
        self.assertNotRegex(step, r"(?m)^        (if|continue-on-error):")
        self.assertLess(
            self.build.index("id: image\n"), self.build.index("id: image-receipt\n")
        )
        result, payload, marker = self.run_receipt()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(payload), {"head_sha", "image_digest", "run_id"})
        self.assertRegex(payload["head_sha"], r"^[0-9a-f]{40}$")
        self.assertEqual(payload["image_digest"], "sha256:" + "a" * 64)
        self.assertEqual(payload["run_id"], "12345")
        self.assertFalse(marker)

    def test_upload_requires_the_exact_receipt_file_after_production(self) -> None:
        upload = self.build[
            self.build.index("      - name: Upload immutable image digest\n") :
        ]
        self.assertIn("        uses: actions/upload-artifact@v4\n", upload)
        self.assertIn("          name: zc-build-image-digest\n", upload)
        self.assertIn("          path: image-digest.json\n", upload)
        self.assertIn("          if-no-files-found: error\n", upload)
        self.assertNotRegex(upload, r"(?m)^        (if|continue-on-error):")
        self.assertLess(
            self.build.index("id: image-receipt\n"), self.build.index(upload)
        )

    def test_missing_producer_output_mutation_cannot_write_receipt(self) -> None:
        mutant = WORKFLOW.replace(
            "BUILD_IMAGE_DIGEST: ${{ steps.image.outputs.digest }}",
            "BUILD_IMAGE_DIGEST: ${{ steps.image.outputs.missing }}",
        )
        self.assertNotEqual(mutant, WORKFLOW)
        result, payload, marker = self.run_receipt(workflow=mutant)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid image receipt image_digest", result.stderr)
        self.assertIsNone(payload)
        self.assertFalse(marker)

    def test_invalid_digest_mutations_cannot_write_receipt(self) -> None:
        for digest in (
            "",
            "sha256:" + "a" * 63,
            "sha256:" + "a" * 65,
            "sha256:" + "A" * 64,
            "sha512:" + "a" * 64,
            "ghcr.io/ogismatulin/zeroclaw@sha256:" + "a" * 64,
            "sha256:" + "a" * 64 + "\n",
            "$(touch injection-marker)",
        ):
            with self.subTest(digest=digest):
                result, payload, marker = self.run_receipt(
                    {"steps.image.outputs.digest": digest}
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(payload)
                self.assertFalse(marker)

    def test_wrong_sha_mutation_cannot_write_receipt(self) -> None:
        for sha in (
            "b" * 40,
            "b" * 7,
            "B" * 40,
            "b" * 40 + "\n",
            "$(touch injection-marker)",
        ):
            with self.subTest(sha=sha):
                result, payload, marker = self.run_receipt({"github.sha": sha})
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(payload)
                self.assertFalse(marker)

    def test_invalid_run_id_and_ref_do_not_write_receipt(self) -> None:
        for key, value in (
            ("github.run_id", "0"),
            ("github.run_id", "-1"),
            ("github.run_id", "1\n2"),
            ("github.run_id", "$(touch injection-marker)"),
            ("github.ref", "master"),
            ("github.ref", "refs/heads/master\n"),
            ("github.ref", "refs/heads/x..y"),
        ):
            with self.subTest(key=key, value=value):
                result, payload, marker = self.run_receipt({key: value})
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(payload)
                self.assertFalse(marker)

    def test_feature_tag_and_shell_like_valid_ref_are_passed_as_data(self) -> None:
        for ref in (
            "refs/heads/feature/x",
            "refs/tags/v1",
            "refs/heads/$(touch${IFS}injection-marker)",
        ):
            with self.subTest(ref=ref):
                result, payload, marker = self.run_receipt({"github.ref": ref})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIsNotNone(payload)
                self.assertFalse(marker)

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
