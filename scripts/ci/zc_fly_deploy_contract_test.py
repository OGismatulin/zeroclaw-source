from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
import textwrap
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = (ROOT / ".github/workflows/zc-fly-deploy.yml").read_text()
MARKER = "[manual-digest-deploy-20261031]"
PIN = "d8f7884f2c9401f68f745fcc1afdc6ac5951b062"
DIGEST = "sha256:" + "a" * 64
CHILD = "sha256:" + "b" * 64
SHA = "c" * 40
PRIVATE_MARKER = "private-data-must-not-be-uploaded-83a09e"
GH_PAT_MARKER = "private-gh-pat-must-not-be-uploaded-92db47"
INPUTS = {
    "MANUAL_DIGEST": DIGEST,
    "EXPECTED_MASTER_SHA": SHA,
    "QUALITY_RUN_ID": "101",
    "BUILD_RUN_ID": "102",
    "SKIPPED_DEPLOY_RUN_ID": "103",
    "RELEASE_CUTOFF": "2026-10-30T00:00:00Z",
    "EXPECTED_MACHINE_ID": "08040d6c71e938",
    "EXPECTED_MACHINE_VERSION": "01K8ABCDEFGHJKMNPQRSTVWXYZ",
    "EXPECTED_MACHINE_DIGEST": "sha256:" + "d" * 64,
}


def steps(workflow=WORKFLOW):
    return re.findall(r"^      - .*?(?=^      - |\Z)", workflow, re.M | re.S)


def step(name, workflow=WORKFLOW):
    found = [
        block
        for block in steps(workflow)
        if block.startswith(f"      - name: {name}\n")
    ]
    if len(found) != 1:
        raise AssertionError(f"Missing or ambiguous workflow step: {name}")
    return found[0]


def script(name, workflow=WORKFLOW):
    match = re.search(
        r"^        run: \|\n((?:          [^\n]*\n|\n)+)", step(name, workflow), re.M
    )
    if not match:
        raise AssertionError(f"Missing shell script: {name}")
    return textwrap.dedent(match[1])


def auto_allowed(workflow, event, conclusion, message):
    match = re.search(r"^    if: >-\n((?:      [^\n]*\n)+)", workflow, re.M)
    if not match:
        raise AssertionError("Missing deploy job condition")
    expression = " ".join(line.strip() for line in match[1].splitlines())
    values = {
        "github.event_name": event,
        "github.event.workflow_run.conclusion": conclusion,
        "github.event.workflow_run.head_commit.message": message or "",
    }
    for key in sorted(values, key=len, reverse=True):
        expression = expression.replace(key, repr(values[key]))
    expression = (
        expression.replace("&&", " and ")
        .replace("||", " or ")
        .replace("!contains", "not contains")
    )
    return bool(
        eval(
            expression,
            {
                "__builtins__": {},
                "contains": lambda value, needle: needle.casefold() in value.casefold(),
            },
        )
    )


def require_contract(workflow):
    def require(condition, message):
        if not condition:
            raise AssertionError(message)

    require(
        auto_allowed(workflow, "workflow_run", "success", "ordinary master"),
        "ordinary master blocked",
    )
    for message in (None, "", "release " + MARKER):
        require(
            not auto_allowed(workflow, "workflow_run", "success", message),
            "auto release guard bypassed",
        )
    require(
        not auto_allowed(workflow, "workflow_run", "failure", "ordinary master"),
        "failed quality gate bypassed",
    )
    require(
        auto_allowed(workflow, "workflow_dispatch", None, None),
        "legacy dispatch blocked",
    )
    require(
        "    concurrency: zc-deploy-group\n" in workflow
        and "cancel-in-progress" not in workflow,
        "deploy serialization changed",
    )
    require("  actions: read\n" in workflow, "artifact read permission missing")
    declarations = workflow.partition("    inputs:\n")[2].partition(
        "  workflow_run:\n"
    )[0]
    require(
        len(re.findall(r"^      [a-z_]+:$", declarations, re.M)) == 10,
        "dispatch input contract changed",
    )
    mode = script("Select and validate deploy mode", workflow)
    require(
        'any(os.environ.get(key, "") for key in patterns)' in mode,
        "partial input can select legacy mode",
    )
    for key in INPUTS:
        require(f'"{key}": r"' in mode, "required digest input omitted")
    require(
        '"EXPECTED_MACHINE_VERSION": r"[0-7][0-9A-HJKMNP-TV-Z]{25}"' in mode,
        "Fly machine version pattern drift",
    )
    for block in steps(workflow):
        match = re.search(
            r"^        run: \|\n((?:          [^\n]*\n|\n)+)", block, re.M
        )
        if match:
            require("${{" not in match[1], "expression embedded in shell source")
        require("|| true" not in block, "failure suppressed")
        if "continue-on-error" in block:
            require(
                block.startswith("      - name: Warm up per-user daemons\n"),
                "digest failure ignored",
            )
    digest_steps = (
        "Verify private integration access",
        "Checkout pinned integration preflight",
        "Verify pinned integration code",
        "Download exact build digest artifact",
        "Inspect immutable registry image",
        "Prepare Fly CLI compatibility",
        "Verify fresh digest release state",
        "Deploy validated immutable digest",
        "Verify post-deploy digest and master",
    )
    for name in digest_steps:
        require(
            "        if: steps.mode.outputs.mode == 'digest'\n" in step(name, workflow),
            "digest step can fall back",
        )
    for name in ("Resolve legacy image tag", "Deploy legacy emergency image tag"):
        require(
            "        if: steps.mode.outputs.mode == 'legacy'\n" in step(name, workflow),
            "legacy fallback is not isolated",
        )
    checkout = step("Checkout pinned integration preflight", workflow)
    require(
        f"          ref: {PIN}\n" in checkout
        and "          token: ${{ secrets.GHCR_TOKEN }}\n" in checkout
        and "          persist-credentials: false\n" in checkout,
        "private checkout pin or credential changed",
    )
    auth = step("Verify private integration access", workflow)
    require(
        "GH_TOKEN: ${{ secrets.GHCR_TOKEN }}" in auth and PIN in auth,
        "private access not checked with checkout token",
    )
    pin = script("Verify pinned integration code", workflow)
    require(
        PIN in pin
        and "46367cf291636150e2f9eec6fe7017350a06f859f1a88e5e3395cef054df8a8b" in pin
        and "af3934c1b4cf1831cc0ece3f2998ef80c8ef404872c3adefdec7d618977ee812" in pin,
        "preflight integrity checks changed",
    )
    artifact = step("Download exact build digest artifact", workflow)
    require(
        "uses: actions/download-artifact@v4" in artifact
        and "name: zc-build-image-digest" in artifact
        and "run-id: ${{ inputs.build_run_id }}" in artifact
        and "github-token: ${{ github.token }}" in artifact,
        "producer artifact not bound to exact run",
    )
    inspect = script("Inspect immutable registry image", workflow)
    require(
        '["docker", "buildx", "imagetools", "inspect", "ghcr.io/ogismatulin/zeroclaw@" + os.environ["MANUAL_DIGEST"], "--format", "{{json .Manifest}}"]'
        in inspect
        and "capture_output=True, text=True, check=True" in inspect,
        "registry inspection is not digest bound",
    )
    require(
        "if len(matches) != 1:" in inspect and "runtime_image_digest=" in inspect,
        "registry runtime digest is not validated before deploy",
    )
    require(
        'if matches[0].get("mediaType") not in (' in inspect
        and '"mediaType": matches[0]["mediaType"]' in inspect,
        "registry child media type is not validated and preserved",
    )
    fresh_step = step("Verify fresh digest release state", workflow)
    require(
        "          GH_TOKEN: ${{ secrets.GHCR_TOKEN }}\n" in fresh_step,
        "release verifier is not using the ruleset-capable PAT secret",
    )
    fresh = script("Verify fresh digest release state", workflow)
    require("GH_TOKEN" not in fresh, "release PAT is referenced in shell source")
    require(
        "fly status --app ai-forge-zeroclaw --json" in fresh, "fresh Fly status missing"
    )
    require(
        '--quiescence --json --transport machines --machine "$EXPECTED_MACHINE_ID" --expected-image "$actual_image"'
        in fresh,
        "fresh pinned quiescence missing",
    )
    require(
        "preflight_exit_code=$?" in fresh
        and 'PREFLIGHT_EXIT_CODE="$preflight_exit_code" python3 scripts/ci/verify_manual_digest_release.py'
        in fresh,
        "preflight exit status lost",
    )
    require(
        '--producer manual-digest/producer/image-digest.json --registry manual-digest/registry.json --preflight "$private_dir/preflight.json" --preflight-finished "$private_dir/preflight-finished.txt"'
        in fresh,
        "verifier evidence contract changed",
    )
    require(
        '> "$private_dir/preflight-finished.txt"' in fresh
        and fresh.index("preflight_exit_code=$?")
        < fresh.index('> "$private_dir/preflight-finished.txt"')
        < fresh.index(
            'PREFLIGHT_EXIT_CODE="$preflight_exit_code" python3 scripts/ci/verify_manual_digest_release.py'
        )
        and 'datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")'
        in fresh,
        "preflight finish timestamp is not measured after the probe",
    )
    require(
        '> "$private_dir/fly-status.json" 2> "$private_dir/fly-status.stderr"' in fresh
        and '> "$private_dir/preflight.json" 2> "$private_dir/preflight.stderr"'
        in fresh
        and 'mktemp -d "$RUNNER_TEMP/manual-digest-private.XXXXXX"' in fresh,
        "raw runtime data can enter public evidence",
    )
    deploy = step("Deploy validated immutable digest", workflow)
    require(
        "VALIDATED_DIGEST: ${{ steps.release.outputs.image_digest }}" in deploy
        and 'flyctl deploy --image "ghcr.io/ogismatulin/zeroclaw@$VALIDATED_DIGEST"'
        in deploy,
        "deploy does not consume validated digest",
    )
    require(
        workflow.index("setup-flyctl@master")
        < workflow.index("      - name: Prepare Fly CLI compatibility")
        < workflow.index("      - name: Verify fresh digest release state")
        < workflow.index("      - name: Deploy validated immutable digest"),
        "setup or release verification order changed",
    )
    compatibility = script("Prepare Fly CLI compatibility", workflow)
    require(
        "command -v flyctl" in compatibility
        and 'ln -s "$flyctl_path" "$RUNNER_TEMP/manual-digest-fly-bin/fly"'
        in compatibility
        and '>> "$GITHUB_PATH"' in compatibility,
        "pinned preflight fly command unavailable",
    )
    require(
        workflow.index("      - name: Verify private integration access")
        < workflow.index("      - name: Checkout pinned integration preflight")
        < workflow.index("      - name: Verify pinned integration code")
        < workflow.index("      - name: Verify fresh digest release state"),
        "private preflight trust order changed",
    )
    require(
        workflow.index("      - name: Deploy validated immutable digest")
        < workflow.index("      - name: Verify post-deploy digest and master"),
        "post-deploy verification missing",
    )
    require(
        "EXPECTED_RUNTIME_DIGEST: ${{ steps.registry.outputs.runtime_image_digest }}"
        in step("Verify post-deploy digest and master", workflow),
        "post-deploy runtime digest is not bound to validated registry child",
    )
    require(
        'if len(status["Machines"]) != 1:'
        in script("Verify post-deploy digest and master", workflow),
        "post-deploy machine roster drift is not rejected",
    )
    upload = step("Preserve digest release evidence", workflow)
    paths = re.search(r"(?m)^          path: \|\n((?:            [^\n]+\n)+)", upload)
    require(
        paths is not None
        and set(line.strip() for line in paths[1].splitlines())
        == {
            "manual-digest/producer/image-digest.json",
            "manual-digest/registry.json",
            "manual-digest/fly-status.json",
            "manual-digest/preflight-summary.json",
            "manual-digest/preflight.exit-code",
            "manual-digest/post-fly-status.json",
            "manual-digest/post-master.json",
        },
        "raw or unbounded runtime evidence upload",
    )
    cleanup = step("Remove private release scratch", workflow)
    require(
        "        if: always() && steps.release.outputs.private_dir != ''\n" in cleanup
        and 'owner.read_text().strip() != os.environ["GITHUB_RUN_ID"]' in cleanup
        and "scratch.parent.resolve() != root" in cleanup
        and "path.unlink()" in cleanup
        and "scratch.rmdir()" in cleanup,
        "private scratch cleanup ownership or failure handling changed",
    )
    require(
        '"preflight-finished.txt"'
        in script("Remove private release scratch", workflow),
        "private finish timestamp cleanup missing",
    )


class ZcFlyDeployContractTest(unittest.TestCase):
    def run_script(self, name, env=None, workflow=WORKFLOW, cwd=None):
        if cwd is None:
            with tempfile.TemporaryDirectory() as tmp:
                return self.run_script(name, env, workflow, Path(tmp))
        output = cwd / "output"
        runner_temp = cwd / "runner-temp"
        runner_temp.mkdir(exist_ok=True)
        result = subprocess.run(
            ["bash", "--noprofile", "--norc", "-c", script(name, workflow)],
            env={
                **os.environ,
                **{key: "" for key in INPUTS},
                "INPUT_IMAGE_TAG": "",
                "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_SHA": SHA,
                "GITHUB_RUN_ID": "104",
                "GITHUB_OUTPUT": str(output),
                "RUNNER_TEMP": str(runner_temp),
                **(env or {}),
            },
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
        )
        return result, output.read_text() if output.exists() else ""

    def test_actual_workflow_contract(self):
        require_contract(WORKFLOW)

    def test_mode_requires_every_digest_input_and_rejects_mixed_or_malformed_values(
        self,
    ):
        result, output = self.run_script("Select and validate deploy mode", INPUTS)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, "mode=digest\n")
        for key in INPUTS:
            for bad in ("", " ", "bad\nmode=legacy", "$(touch injected)"):
                with self.subTest(key=key, bad=bad):
                    result, output = self.run_script(
                        "Select and validate deploy mode", {**INPUTS, key: bad}
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(output, "")
        for extra in (
            {"INPUT_IMAGE_TAG": "latest"},
            {"GITHUB_EVENT_NAME": "workflow_run"},
            {"RELEASE_CUTOFF": "2099-01-01T00:00:00Z"},
            {"RELEASE_CUTOFF": "2026-02-30T00:00:00Z"},
        ):
            result, output = self.run_script(
                "Select and validate deploy mode", {**INPUTS, **extra}
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output, "")

    def test_each_single_digest_side_input_prevents_legacy_fallback(self):
        for key, value in INPUTS.items():
            with self.subTest(key=key):
                result, output = self.run_script(
                    "Select and validate deploy mode", {key: value}
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output, "")

    def test_machine_version_uses_the_verifier_ulid_pattern(self):
        source = Path(__file__).with_name("verify_manual_digest_release.py").read_text()
        pattern = re.search(r'"EXPECTED_MACHINE_VERSION": r"([^"]+)"', source)[1]
        self.assertEqual(pattern, r"[0-7][0-9A-HJKMNP-TV-Z]{25}")
        self.assertIn(
            '"EXPECTED_MACHINE_VERSION": r"' + pattern + '"',
            script("Select and validate deploy mode"),
        )
        for invalid in (
            "01K8VALIDVERSION",
            "625",
            "8" + "A" * 25,
            "0" + "A" * 24,
            "0" + "A" * 26,
            "0" + "a" * 25,
            "0" + "I" * 25,
            "0" + "L" * 25,
            "0" + "O" * 25,
            "0" + "U" * 25,
        ):
            with self.subTest(version=invalid):
                result, output = self.run_script(
                    "Select and validate deploy mode",
                    {**INPUTS, "EXPECTED_MACHINE_VERSION": invalid},
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output, "")

    def test_legacy_dispatch_and_ordinary_upstream_tag_contract(self):
        for event, tag, upstream, expected in (
            ("workflow_dispatch", "", "", "sha-" + SHA[:7]),
            ("workflow_dispatch", "latest", "", "latest"),
            ("workflow_dispatch", "sha-123abcd", "", "sha-123abcd"),
            ("workflow_run", "", "e" * 40, "sha-eeeeeee"),
        ):
            env = {
                "GITHUB_EVENT_NAME": event,
                "INPUT_IMAGE_TAG": tag,
                "UPSTREAM_HEAD_SHA": upstream,
            }
            result, output = self.run_script("Select and validate deploy mode", env)
            self.assertEqual((result.returncode, output), (0, "mode=legacy\n"))
            result, output = self.run_script("Resolve legacy image tag", env)
            self.assertEqual((result.returncode, output), (0, f"tag={expected}\n"))

    def test_deploy_command_consumes_only_validator_output_without_shell_interpolation(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stub = root / "flyctl"
            stub.write_text(
                "#!/usr/bin/env python3\nimport json, os, sys\nfrom pathlib import Path\nPath(os.environ['CALLS']).write_text(json.dumps(sys.argv[1:]))\n"
            )
            stub.chmod(0o755)
            calls = root / "calls"
            env = {
                "VALIDATED_DIGEST": DIGEST,
                "MANUAL_DIGEST": "sha256:" + "f" * 64,
                "PATH": str(root) + os.pathsep + os.environ["PATH"],
                "CALLS": str(calls),
            }
            result, _ = self.run_script(
                "Deploy validated immutable digest", env, cwd=root
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                json.loads(calls.read_text()),
                ["deploy", "--image", "ghcr.io/ogismatulin/zeroclaw@" + DIGEST],
            )
            calls.unlink()
            for invalid in ("", DIGEST + ";touch injected", "$(touch injected)"):
                result, _ = self.run_script(
                    "Deploy validated immutable digest",
                    {**env, "VALIDATED_DIGEST": invalid},
                    cwd=root,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(calls.exists())
                self.assertFalse((root / "injected").exists())

    def test_private_access_failures_never_emit_credential(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stub = root / "gh"
            stub.write_text(
                "#!/usr/bin/env python3\nimport os, sys\nprint(os.environ['GH_TOKEN'], file=sys.stderr)\nraise SystemExit(int(os.environ['GH_FAIL']))\n"
            )
            stub.chmod(0o755)
            for code in (1, 0):
                env = {
                    "GH_TOKEN": "sensitive-test-token",
                    "GH_FAIL": str(code),
                    "PATH": str(root) + os.pathsep + os.environ["PATH"],
                }
                result, _ = self.run_script(
                    "Verify private integration access", env, cwd=root
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("sensitive-test-token", result.stdout + result.stderr)

    def test_fly_alias_uses_installed_flyctl_without_replacing_system_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stub = root / "flyctl"
            stub.write_text(
                "#!/usr/bin/env python3\nimport sys\nassert sys.argv[1:] == ['version']\n"
            )
            stub.chmod(0o755)
            path_file = root / "github-path"
            env = {
                "RUNNER_TEMP": str(root),
                "GITHUB_PATH": str(path_file),
                "PATH": str(root) + os.pathsep + os.environ["PATH"],
            }
            result, _ = self.run_script("Prepare Fly CLI compatibility", env, cwd=root)
            self.assertEqual(result.returncode, 0, result.stderr)
            alias = root / "manual-digest-fly-bin/fly"
            self.assertTrue(alias.is_symlink())
            self.assertEqual(alias.resolve(), stub.resolve())
            self.assertEqual(path_file.read_text(), str(alias.parent) + "\n")

    def test_fresh_status_and_preflight_failures_do_not_produce_deploy_permission(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "manual-digest/producer").mkdir(parents=True)
            pinned = (
                root
                / ".manual-digest-integration/.claude/skills/fly-template-sync/scripts"
            )
            pinned.mkdir(parents=True)
            (pinned / "fly_preflight.py").write_text(
                "import json, os, sys, time\nfrom pathlib import Path\nPath('preflight-called').touch()\nmarker = os.environ['PRIVATE_MARKER']\nprint(marker, file=sys.stderr)\nprint(os.environ['GH_TOKEN'], file=sys.stderr)\nprint(json.dumps({'state': 'UNKNOWN', 'exec': 'PASS', 'busy': [marker], 'unknown': [marker], 'users': [marker], 'sources': {marker: marker}, 'reason': marker, 'observed_at': '2000-01-01T00:00:00Z'}))\nPath('probe-finished-epoch').write_text(str(time.time()))\nraise SystemExit(int(os.environ['PREFLIGHT_STUB_RC']))\n"
            )
            verifier = root / "scripts/ci"
            verifier.mkdir(parents=True)
            (verifier / "verify_manual_digest_release.py").write_text(
                "import json, os, sys\nfrom datetime import datetime, timezone\nfrom pathlib import Path\ncode = os.environ['PREFLIGHT_EXIT_CODE']\nassert os.environ['GH_TOKEN'] == os.environ['EXPECTED_GH_TOKEN']\npath = Path(sys.argv[sys.argv.index('--preflight') + 1])\nassert os.environ['PRIVATE_MARKER'] in path.read_text()\nassert not path.is_relative_to(Path('manual-digest').resolve())\nassert json.loads(path.read_text())['observed_at'] == '2000-01-01T00:00:00Z'\nfinished = Path(sys.argv[sys.argv.index('--preflight-finished') + 1])\nassert finished.parent == path.parent\nstamp = datetime.fromisoformat(finished.read_text().strip().replace('Z', '+00:00'))\nassert float(Path('probe-finished-epoch').read_text()) <= stamp.timestamp() <= datetime.now(timezone.utc).timestamp()\nPath('verifier-finished').write_text(finished.read_text())\nPath('verifier-code').write_text(code)\nraise SystemExit(0 if code in ('0', '3') else 1)\n"
            )
            stub = root / "fly"
            stub.write_text(
                "#!/usr/bin/env python3\nimport json, os, sys\nassert sys.argv[1:] == ['status', '--app', 'ai-forge-zeroclaw', '--json']\nmarker = os.environ['PRIVATE_MARKER']\nprint(marker, file=sys.stderr)\nprint(os.environ['GH_TOKEN'], file=sys.stderr)\nprint(json.dumps({'Name': 'ai-forge-zeroclaw', 'env': marker, 'Machines': [{'id': os.environ['EXPECTED_MACHINE_ID'], 'version': os.environ['EXPECTED_MACHINE_VERSION'], 'state': 'started', 'config': {'image': 'ghcr.io/ogismatulin/zeroclaw:sha-old', 'env': {'SECRET': marker, 'PAT': os.environ['GH_TOKEN']}, 'other': marker}, 'image_ref': {'digest': os.environ['EXPECTED_MACHINE_DIGEST'], 'private': marker}, 'private': marker}]}))\nraise SystemExit(int(os.environ['FLY_STUB_RC']))\n"
            )
            stub.chmod(0o755)
            env = {
                **INPUTS,
                "PATH": str(root) + os.pathsep + os.environ["PATH"],
                "FLY_STUB_RC": "0",
                "PRIVATE_MARKER": PRIVATE_MARKER,
                "GH_TOKEN": GH_PAT_MARKER,
                "EXPECTED_GH_TOKEN": GH_PAT_MARKER,
            }
            for code in (0, 1, 2, 3, 127):
                result, _ = self.run_script(
                    "Verify fresh digest release state",
                    {**env, "PREFLIGHT_STUB_RC": str(code)},
                    cwd=root,
                )
                self.assertEqual((root / "verifier-code").read_text(), str(code))
                self.assertEqual(
                    (root / "manual-digest/preflight.exit-code").read_text(),
                    f"{code}\n",
                )
                self.assertEqual(result.returncode == 0, code in (0, 3), result.stderr)
                finished = (root / "verifier-finished").read_text()
                self.assertRegex(
                    finished,
                    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z\n$",
                )
                self.assertEqual(
                    datetime.fromisoformat(
                        finished.strip().replace("Z", "+00:00")
                    ).tzinfo,
                    timezone.utc,
                )
                self.assertFalse(
                    (root / "manual-digest/preflight-finished.txt").exists()
                )
                self.assertNotIn(PRIVATE_MARKER, result.stdout + result.stderr)
                self.assertNotIn(GH_PAT_MARKER, result.stdout + result.stderr)
                for path in (root / "manual-digest").rglob("*"):
                    if path.is_file():
                        self.assertNotIn(PRIVATE_MARKER, path.read_text(), str(path))
                        self.assertNotIn(GH_PAT_MARKER, path.read_text(), str(path))
                status = json.loads(
                    (root / "manual-digest/fly-status.json").read_text()
                )
                self.assertEqual(set(status), {"Name", "Machines"})
                self.assertEqual(
                    set(status["Machines"][0]),
                    {"id", "version", "state", "image_ref", "config"},
                )
                self.assertEqual(set(status["Machines"][0]["config"]), {"image"})
                self.assertEqual(set(status["Machines"][0]["image_ref"]), {"digest"})
            (root / "verifier-code").unlink()
            (root / "preflight-called").unlink()
            result, _ = self.run_script(
                "Verify fresh digest release state",
                {**env, "FLY_STUB_RC": "1", "PREFLIGHT_STUB_RC": "0"},
                cwd=root,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "verifier-code").exists())
            self.assertFalse((root / "preflight-called").exists())
            self.assertNotIn(PRIVATE_MARKER, result.stdout + result.stderr)
            self.assertNotIn(GH_PAT_MARKER, result.stdout + result.stderr)

    def test_registry_requires_exactly_one_linux_amd64_child_before_deploy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "manual-digest"
            evidence.mkdir()
            child = {
                "digest": CHILD,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "platform": {"os": "linux", "architecture": "amd64"},
            }
            registry = {
                "digest": DIGEST,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [child],
                "annotations": {"private": PRIVATE_MARKER},
            }
            path = evidence / "registry.json"
            payload = root / "registry-payload.json"
            payload.write_text(json.dumps(registry))
            docker = root / "docker"
            docker.write_text(
                "#!/usr/bin/env python3\nimport os, sys\nfrom pathlib import Path\nassert sys.argv[1:] == ['buildx', 'imagetools', 'inspect', 'ghcr.io/ogismatulin/zeroclaw@' + os.environ['MANUAL_DIGEST'], '--format', '{{json .Manifest}}']\nprint(Path(os.environ['REGISTRY_PAYLOAD']).read_text())\nprint(os.environ['PRIVATE_MARKER'], file=sys.stderr)\nraise SystemExit(int(os.environ['REGISTRY_EXIT']))\n"
            )
            docker.chmod(0o755)
            env = {
                **INPUTS,
                "REGISTRY_PAYLOAD": str(payload),
                "REGISTRY_EXIT": "0",
                "PRIVATE_MARKER": PRIVATE_MARKER,
                "PATH": str(root) + os.pathsep + os.environ["PATH"],
            }
            result, output = self.run_script(
                "Inspect immutable registry image", env, cwd=root
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output, "runtime_image_digest=" + CHILD + "\n")
            self.assertEqual(
                json.loads(path.read_text())["manifests"][0]["mediaType"],
                child["mediaType"],
            )
            self.assertNotIn(
                PRIVATE_MARKER, path.read_text() + result.stdout + result.stderr
            )
            for manifests in (
                None,
                [],
                [child, child],
                [{**child, "digest": "bad"}],
                [{**child, "digest": DIGEST}],
                [{**child, "mediaType": "application/vnd.oci.image.index.v1+json"}],
                [{key: value for key, value in child.items() if key != "mediaType"}],
                [{**child, "platform": {"os": "linux", "architecture": "arm64"}}],
            ):
                (root / "output").unlink(missing_ok=True)
                path.unlink(missing_ok=True)
                payload.write_text(json.dumps({**registry, "manifests": manifests}))
                result, output = self.run_script(
                    "Inspect immutable registry image", env, cwd=root
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(output, "")
                self.assertFalse(path.exists())
                self.assertNotIn(PRIVATE_MARKER, result.stdout + result.stderr)
            for raw, code in ((PRIVATE_MARKER, "0"), (json.dumps(registry), "1")):
                payload.write_text(raw)
                result, output = self.run_script(
                    "Inspect immutable registry image",
                    {**env, "REGISTRY_EXIT": code},
                    cwd=root,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(path.exists())
                self.assertNotIn(PRIVATE_MARKER, result.stdout + result.stderr)

    def test_real_inspect_output_reaches_real_verifier_and_digest_deploy(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "manual_digest_release_fixture",
            Path(__file__).with_name("verify_manual_digest_release_test.py"),
        )
        fixture_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture_module)
        for kind in (
            "valid-oci",
            "valid-docker",
            "missing-type",
            "bad-type",
            "ambiguous",
        ):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "manual-digest").mkdir()
                fixture = fixture_module.ManualDigestReleaseTest()
                fixture.setUp()
                descriptor = fixture.registry["manifests"][0]
                if kind == "valid-docker":
                    descriptor["mediaType"] = (
                        "application/vnd.docker.distribution.manifest.v2+json"
                    )
                elif kind == "missing-type":
                    descriptor.pop("mediaType")
                elif kind == "bad-type":
                    descriptor["mediaType"] = "application/vnd.oci.image.index.v1+json"
                elif kind == "ambiguous":
                    fixture.registry["manifests"].append(dict(descriptor))
                payload = root / "registry-payload.json"
                payload.write_text(json.dumps(fixture.registry))
                docker = root / "docker"
                docker.write_text(
                    "#!/usr/bin/env python3\nimport os, sys\nfrom pathlib import Path\nassert sys.argv[1:] == ['buildx', 'imagetools', 'inspect', 'ghcr.io/ogismatulin/zeroclaw@' + os.environ['MANUAL_DIGEST'], '--format', '{{json .Manifest}}']\nprint(Path(os.environ['REGISTRY_PAYLOAD']).read_text())\n"
                )
                docker.chmod(0o755)
                flyctl = root / "flyctl"
                flyctl.write_text(
                    "#!/usr/bin/env python3\nimport json, os, sys\nfrom pathlib import Path\nPath(os.environ['DEPLOY_CALLS']).write_text(json.dumps(sys.argv[1:]))\n"
                )
                flyctl.chmod(0o755)
                calls = root / "deploy-calls.json"
                env = {
                    **fixture.env,
                    "REGISTRY_PAYLOAD": str(payload),
                    "DEPLOY_CALLS": str(calls),
                    "PATH": str(root) + os.pathsep + os.environ["PATH"],
                }
                inspected, _ = self.run_script(
                    "Inspect immutable registry image", env, cwd=root
                )
                if not kind.startswith("valid-"):
                    self.assertNotEqual(inspected.returncode, 0, inspected.stderr)
                    self.assertEqual(fixture.calls, [])
                    self.assertFalse(calls.exists())
                    continue
                self.assertEqual(inspected.returncode, 0, inspected.stderr)
                normalized = json.loads(
                    (root / "manual-digest/registry.json").read_text()
                )
                verified = fixture_module.VERIFIER.verify(
                    fixture.env,
                    fixture.producer,
                    normalized,
                    fixture.preflight,
                    now=fixture_module.NOW,
                    runner=fixture.runner,
                    preflight_finished=fixture.finished,
                )
                self.assertEqual(
                    normalized["manifests"][0]["mediaType"], descriptor["mediaType"]
                )
                self.assertTrue(fixture.calls)
                deployed, _ = self.run_script(
                    "Deploy validated immutable digest",
                    {**env, "VALIDATED_DIGEST": verified["image_digest"]},
                    cwd=root,
                )
                self.assertEqual(deployed.returncode, 0, deployed.stderr)
                self.assertEqual(
                    json.loads(calls.read_text()),
                    [
                        "deploy",
                        "--image",
                        "ghcr.io/ogismatulin/zeroclaw@" + fixture.env["MANUAL_DIGEST"],
                    ],
                )

    def test_post_deploy_checks_validated_child_digest_version_and_master(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "manual-digest"
            evidence.mkdir()
            private = root / "private-runtime-data"
            private.mkdir()
            source_private = root / "source-private-data"
            source_private.mkdir()
            machine = {
                "id": INPUTS["EXPECTED_MACHINE_ID"],
                "version": "NEWVERSION",
                "state": "started",
                "config": {
                    "image": "registry.fly.io/ai-forge-zeroclaw:deployment-current",
                    "env": {"SECRET": PRIVATE_MARKER},
                    "private": PRIVATE_MARKER,
                },
                "image_ref": {"digest": CHILD, "private": PRIVATE_MARKER},
                "private": PRIVATE_MARKER,
            }
            status = {
                "Name": "ai-forge-zeroclaw",
                "Machines": [machine],
                "private": PRIVATE_MARKER,
            }
            master = {
                "ref": "refs/heads/master",
                "object": {"type": "commit", "sha": SHA},
                "private": PRIVATE_MARKER,
            }
            for name, value in (
                ("post-fly-status.json", status),
                ("post-master.json", master),
            ):
                (source_private / name).write_text(json.dumps(value))
            for command, source in (
                ("fly", "post-fly-status.json"),
                ("gh", "post-master.json"),
            ):
                stub = root / command
                stub.write_text(
                    "#!/usr/bin/env python3\nimport os, sys\nfrom pathlib import Path\nprint(os.environ['PRIVATE_MARKER'], file=sys.stderr)\nprint((Path(os.environ['SOURCE_PRIVATE_DIR']) / '"
                    + source
                    + "').read_text())\nraise SystemExit(int(os.environ['CLI_STUB_RC']))\n"
                )
                stub.chmod(0o755)
            env = {
                **INPUTS,
                "EXPECTED_RUNTIME_DIGEST": CHILD,
                "RELEASE_PRIVATE_DIR": str(private),
                "SOURCE_PRIVATE_DIR": str(source_private),
                "PRIVATE_MARKER": PRIVATE_MARKER,
                "CLI_STUB_RC": "0",
                "GITHUB_REPOSITORY": "OGismatulin/zeroclaw-source",
                "PATH": str(root) + os.pathsep + os.environ["PATH"],
            }
            result, _ = self.run_script(
                "Verify post-deploy digest and master", env, cwd=root
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn(PRIVATE_MARKER, result.stdout + result.stderr)
            for path in evidence.rglob("*"):
                if path.is_file():
                    self.assertNotIn(PRIVATE_MARKER, path.read_text(), str(path))
            self.assertEqual(
                set(
                    json.loads((evidence / "post-fly-status.json").read_text())[
                        "Machines"
                    ][0]["config"]
                ),
                {"image"},
            )
            self.assertEqual(
                set(json.loads((evidence / "post-master.json").read_text())),
                {"ref", "object"},
            )
            for target, key, bad in (
                (machine["image_ref"], "digest", DIGEST),
                (machine, "version", INPUTS["EXPECTED_MACHINE_VERSION"]),
                (machine, "state", "stopped"),
                (master["object"], "sha", "f" * 40),
            ):
                original = target[key]
                target[key] = bad
                (source_private / "post-fly-status.json").write_text(json.dumps(status))
                (source_private / "post-master.json").write_text(json.dumps(master))
                result, _ = self.run_script(
                    "Verify post-deploy digest and master", env, cwd=root
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(PRIVATE_MARKER, result.stdout + result.stderr)
                for path in evidence.rglob("*"):
                    if path.is_file():
                        self.assertNotIn(PRIVATE_MARKER, path.read_text(), str(path))
                target[key] = original
            status["Machines"].append({**machine, "id": "a" * 14})
            (source_private / "post-fly-status.json").write_text(json.dumps(status))
            (source_private / "post-master.json").write_text(json.dumps(master))
            result, _ = self.run_script(
                "Verify post-deploy digest and master", env, cwd=root
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("machine roster drift", result.stderr)
            self.assertNotIn(PRIVATE_MARKER, result.stdout + result.stderr)
            for path in evidence.rglob("*"):
                if path.is_file():
                    self.assertNotIn(PRIVATE_MARKER, path.read_text(), str(path))
            status["Machines"].pop()
            result, _ = self.run_script(
                "Verify post-deploy digest and master",
                {**env, "CLI_STUB_RC": "1"},
                cwd=root,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(PRIVATE_MARKER, result.stdout + result.stderr)

    def test_private_cleanup_requires_own_marker_exact_parent_and_known_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runner_temp = root / "runner-temp"
            runner_temp.mkdir()
            scratch = runner_temp / "manual-digest-private.ABC123"
            scratch.mkdir()
            owner = scratch / ".owner"
            owner.write_text("wrong-run")
            (scratch / "preflight.json").write_text(PRIVATE_MARKER)
            (scratch / "preflight-finished.txt").write_text(
                "2026-10-31T12:00:00.000000Z\n"
            )
            env = {"RELEASE_PRIVATE_DIR": str(scratch)}
            result, _ = self.run_script("Remove private release scratch", env, cwd=root)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(scratch.exists())
            owner.write_text("104\n")
            (scratch / "foreign").write_text(PRIVATE_MARKER)
            result, _ = self.run_script("Remove private release scratch", env, cwd=root)
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue((scratch / "foreign").exists())
            (scratch / "foreign").unlink()
            foreign = root / "foreign-secret"
            foreign.write_text(PRIVATE_MARKER)
            (scratch / "post-master.json").symlink_to(foreign)
            result, _ = self.run_script("Remove private release scratch", env, cwd=root)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(foreign.read_text(), PRIVATE_MARKER)
            (scratch / "post-master.json").unlink()
            result, _ = self.run_script("Remove private release scratch", env, cwd=root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(scratch.exists())
            self.assertNotIn(PRIVATE_MARKER, result.stdout + result.stderr)
            outside = root / "manual-digest-private.DEF456"
            outside.mkdir()
            (outside / ".owner").write_text("104\n")
            result, _ = self.run_script(
                "Remove private release scratch",
                {"RELEASE_PRIVATE_DIR": str(outside)},
                cwd=root,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertTrue(outside.exists())

    def test_negative_workflow_mutations_are_rejected(self):
        finished_block = re.search(
            r"(?m)^          python3 - <<'PY' > \"\$private_dir/preflight-finished\.txt\"\n.*?^          PY\n",
            WORKFLOW,
            re.S,
        ).group()
        probe_start = "          if python3 .manual-digest-integration/.claude/skills/fly-template-sync/scripts/fly_preflight.py"
        mutations = (
            WORKFLOW.replace(MARKER, "[wrong-marker]"),
            WORKFLOW.replace(
                "      github.event.workflow_run.head_commit.message &&\n", ""
            ),
            WORKFLOW.replace(
                'any(os.environ.get(key, "") for key in patterns)',
                'os.environ.get("MANUAL_DIGEST", "")',
            ),
            WORKFLOW.replace('              "BUILD_RUN_ID": r"[1-9][0-9]*",\n', ""),
            WORKFLOW.replace(
                "concurrency: zc-deploy-group", "concurrency: isolated-digest-group"
            ),
            WORKFLOW.replace(
                "    concurrency: zc-deploy-group",
                "    concurrency: zc-deploy-group\n    cancel-in-progress: true",
            ),
            WORKFLOW.replace("if: steps.mode.outputs.mode == 'legacy'", "if: always()"),
            WORKFLOW.replace("@\u0024VALIDATED_DIGEST", ":$VALIDATED_DIGEST"),
            WORKFLOW.replace(
                "steps.release.outputs.image_digest", "inputs.image_digest"
            ),
            WORKFLOW.replace(
                "run-id: ${{ inputs.build_run_id }}", "run-id: ${{ github.run_id }}"
            ),
            WORKFLOW.replace("if len(matches) != 1:", "if len(matches) > 1:"),
            WORKFLOW.replace("if len(matches) != 1:", "if len(matches) < 1:"),
            WORKFLOW.replace(
                "steps.registry.outputs.runtime_image_digest", "inputs.image_digest"
            ),
            WORKFLOW.replace(
                '> "$private_dir/preflight.json" 2> "$private_dir/preflight.stderr"; then',
                '> "$private_dir/preflight.json" 2> "$private_dir/preflight.stderr" || true; then',
            ),
            WORKFLOW.replace(
                '> "$private_dir/fly-status.json" 2> "$private_dir/fly-status.stderr"',
                "> manual-digest/raw-fly-status.json",
            ),
            WORKFLOW.replace(
                '> "$private_dir/preflight.json" 2> "$private_dir/preflight.stderr"',
                "> manual-digest/preflight.json",
            ),
            WORKFLOW.replace("          path: |\n", "          path: manual-digest/\n"),
            WORKFLOW.replace(
                "            manual-digest/preflight-summary.json\n",
                "            manual-digest/preflight-summary.json\n            manual-digest/preflight.stderr\n",
            ),
            WORKFLOW.replace(
                "          set -euo pipefail\n",
                "          echo '${{ secrets.FLY_API_TOKEN }}'\n",
                1,
            ),
            WORKFLOW.replace('if len(status["Machines"]) != 1:', "if False:"),
            WORKFLOW.replace(
                "if: always() && steps.release.outputs.private_dir != ''",
                "if: success()",
            ),
            WORKFLOW.replace('"mediaType": matches[0]["mediaType"], ', ""),
            WORKFLOW.replace(
                'if matches[0].get("mediaType") not in (',
                'if matches[0].get("mediaType") in (',
            ),
            WORKFLOW.replace(
                '"EXPECTED_MACHINE_VERSION": r"[0-7][0-9A-HJKMNP-TV-Z]{25}"',
                '"EXPECTED_MACHINE_VERSION": r"[A-Za-z0-9]+"',
            ),
            WORKFLOW.replace(
                ' --preflight-finished "$private_dir/preflight-finished.txt"', ""
            ),
            WORKFLOW.replace(
                '> "$private_dir/preflight-finished.txt"',
                '> "$private_dir/before-probe.txt"',
            ),
            WORKFLOW.replace(
                'datetime.now(timezone.utc).isoformat(timespec="microseconds")',
                'datetime(2000, 1, 1, tzinfo=timezone.utc).isoformat(timespec="microseconds")',
            ),
            WORKFLOW.replace('"preflight-finished.txt"', '"untracked-finished.txt"'),
            WORKFLOW.replace(finished_block, "").replace(
                probe_start, finished_block + probe_start
            ),
            WORKFLOW.replace(
                step("Verify fresh digest release state"),
                step("Verify fresh digest release state").replace(
                    "${{ secrets.GHCR_TOKEN }}", "${{ github.token }}"
                ),
            ),
            WORKFLOW.replace(
                step("Verify fresh digest release state"),
                step("Verify fresh digest release state").replace(
                    "          set -euo pipefail\n",
                    '          set -euo pipefail\n          echo "$GH_TOKEN"\n',
                ),
            ),
        )
        for index, workflow in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(AssertionError):
                require_contract(workflow)


if __name__ == "__main__":
    unittest.main()
