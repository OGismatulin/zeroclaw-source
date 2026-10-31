from __future__ import annotations

import contextlib
import copy
import io
import os
import importlib.util
import json
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    "verify_manual_digest_release",
    Path(__file__).with_name("verify_manual_digest_release.py"),
)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)
SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64
BASELINE = "sha256:" + "c" * 64
RUNTIME_DIGEST = "sha256:" + "d" * 64
NOW = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)
MARKER = "[manual-digest-deploy-20261031]"


def workflow_run(run_id, path, event="push", conclusion="success"):
    return {
        "id": run_id,
        "path": ".github/workflows/" + path,
        "event": event,
        "head_branch": "master",
        "head_sha": SHA,
        "status": "completed",
        "conclusion": conclusion,
        "created_at": "2026-10-31T11:10:00Z",
        "updated_at": "2026-10-31T11:20:00Z",
        "run_attempt": 1,
        "head_commit": {"id": SHA, "message": "release " + MARKER},
    }


class ManualDigestReleaseTest(unittest.TestCase):
    def setUp(self):
        self.env = {
            "MANUAL_DIGEST": DIGEST,
            "EXPECTED_MASTER_SHA": SHA,
            "QUALITY_RUN_ID": "101",
            "BUILD_RUN_ID": "102",
            "SKIPPED_DEPLOY_RUN_ID": "103",
            "RELEASE_CUTOFF": "2026-10-31T11:00:00Z",
            "EXPECTED_MACHINE_ID": "08040d6c71e938",
            "EXPECTED_MACHINE_VERSION": "01K8ABCDEFGHJKMNPQRSTVWXYZ",
            "EXPECTED_MACHINE_DIGEST": BASELINE,
            "GITHUB_REPOSITORY": "OGismatulin/zeroclaw-source",
            "GITHUB_RUN_ID": "104",
            "GITHUB_SHA": SHA,
            "GITHUB_REF": "refs/heads/master",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "PREFLIGHT_EXIT_CODE": "0",
        }
        self.producer = {"head_sha": SHA, "image_digest": DIGEST, "run_id": "102"}
        self.registry = {
            "digest": DIGEST,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "digest": RUNTIME_DIGEST,
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "platform": {"os": "linux", "architecture": "amd64"},
                }
            ],
        }
        self.machine = {
            "id": self.env["EXPECTED_MACHINE_ID"],
            "version": self.env["EXPECTED_MACHINE_VERSION"],
            "state": "started",
            "config": {"image": "ghcr.io/ogismatulin/zeroclaw:sha-old1234"},
            "image_ref": {"digest": BASELINE},
        }
        self.preflight = {
            "app": "ai-forge-zeroclaw",
            "state": "QUIET",
            "exec": "PASS",
            "transport": "ssh",
            "machine": self.machine["id"],
            "image": self.machine["config"]["image"],
            "observed_at": (NOW - timedelta(seconds=5)).isoformat(),
            "busy": [],
            "busy_reasons": {},
            "unknown": [],
            "users": ["tg_83292437"],
            "sources": {
                "tg_83292437": {
                    "state/jira_watch/analysis_queue.json": "READ",
                    "control_plane.db": "READ",
                    "logs/runtime-trace.jsonl": "READ",
                    "delegate_results": "READ",
                }
            },
        }
        self.finished = (NOW - timedelta(seconds=2)).isoformat()
        self.jobs = {}
        self.jobs_error = False
        self.jobs_count_delta = 0
        self.runs = {
            "ci.yml": [workflow_run(101, "ci.yml")],
            "zc-build-image.yml": [workflow_run(102, "zc-build-image.yml")],
            "zc-fly-deploy.yml": [
                workflow_run(103, "zc-fly-deploy.yml", "workflow_run", "skipped"),
                workflow_run(104, "zc-fly-deploy.yml", "workflow_dispatch", None),
            ],
        }
        self.runs["zc-fly-deploy.yml"][1]["status"] = "in_progress"
        self.repo_info = {
            "full_name": self.env["GITHUB_REPOSITORY"],
            "fork": False,
            "parent": None,
            "source": None,
        }
        self.ruleset = {
            "id": 201,
            "name": "zc-digest-freeze-" + SHA,
            "source": self.env["GITHUB_REPOSITORY"],
            "source_type": "Repository",
            "target": "branch",
            "enforcement": "active",
        }
        self.ruleset_pages = [[copy.deepcopy(self.ruleset)]]
        self.ruleset_detail = {
            **copy.deepcopy(self.ruleset),
            "bypass_actors": [],
            "conditions": {
                "ref_name": {"include": ["refs/heads/master"], "exclude": []}
            },
            "rules": [{"type": "update"}],
        }
        self.effective_pages = [
            [
                {
                    "type": "update",
                    "ruleset_id": 201,
                    "ruleset_source": self.env["GITHUB_REPOSITORY"],
                    "ruleset_source_type": "Repository",
                }
            ]
        ]
        self.freeze_error_endpoint = None
        self.master = SHA
        self.calls = []
        self.api_failure = False
        self.extra_page = None
        self.total_count_delta = 0
        self.fly_machines = [self.machine]

    def runner(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        self.assertNotIn("shell", kwargs)
        if argv[0] == "fly":
            self.assertEqual(
                argv, ["fly", "status", "--app", "ai-forge-zeroclaw", "--json"]
            )
            value = {"Name": "ai-forge-zeroclaw", "Machines": self.fly_machines}
        else:
            self.assertEqual(argv[:2], ["gh", "api"])
            self.assertIn("--paginate", argv)
            self.assertIn("--slurp", argv)
            endpoint = argv[-1]
            if self.api_failure:
                raise subprocess.CalledProcessError(
                    1, argv, stderr="secret-token-value"
                )
            if (
                self.freeze_error_endpoint is not None
                and self.freeze_error_endpoint in endpoint
            ):
                raise subprocess.CalledProcessError(
                    1, argv, stderr="secret-freeze-token"
                )
            if endpoint == "repos/" + self.env["GITHUB_REPOSITORY"]:
                value = [self.repo_info]
            elif endpoint.endswith("/rulesets?per_page=100"):
                value = self.ruleset_pages
            elif endpoint.endswith("/rulesets/201"):
                value = [self.ruleset_detail]
            elif endpoint.endswith("/rules/branches/master?per_page=100"):
                value = self.effective_pages
            elif endpoint.endswith("/git/ref/heads/master"):
                value = [
                    {
                        "ref": "refs/heads/master",
                        "object": {"type": "commit", "sha": self.master},
                    }
                ]
            elif "/actions/workflows/" in endpoint:
                path = endpoint.split("/actions/workflows/")[1].split("/")[0]
                runs = self.runs[path]
                pages = [runs]
                if self.extra_page and path == "zc-fly-deploy.yml":
                    pages.append([self.extra_page])
                total = sum(map(len, pages)) + self.total_count_delta
                value = [
                    {"total_count": total, "workflow_runs": page} for page in pages
                ]
            elif "/jobs?" in endpoint:
                if self.jobs_error:
                    raise subprocess.CalledProcessError(
                        1, argv, stderr="secret-job-token"
                    )
                run_id = int(endpoint.split("/actions/runs/")[1].split("/")[0])
                pages = self.jobs[run_id]
                count = sum(map(len, pages)) + self.jobs_count_delta
                value = [{"total_count": count, "jobs": page} for page in pages]
            else:
                run_id = int(endpoint.rsplit("/", 1)[1])
                value = [
                    next(
                        r
                        for runs in self.runs.values()
                        for r in runs
                        if r["id"] == run_id
                    )
                ]
        return subprocess.CompletedProcess(argv, 0, json.dumps(value), "")

    def verify(self):
        return VERIFIER.verify(
            self.env,
            self.producer,
            self.registry,
            self.preflight,
            NOW,
            self.runner,
            preflight_finished=self.finished,
        )

    def test_valid_release_returns_exact_immutable_image(self):
        result = self.verify()
        self.assertEqual(result["image"], "ghcr.io/ogismatulin/zeroclaw@" + DIGEST)
        self.assertEqual(result["master_sha"], SHA)
        self.assertTrue(self.calls)

    def test_active_freeze_is_checked_before_final_master_and_returned_in_receipt(self):
        result = self.verify()
        self.assertEqual(result["freeze_ruleset_id"], 201)
        endpoints = [argv[-1] for argv, _ in self.calls if argv[0] == "gh"]
        self.assertLess(
            endpoints.index("repos/" + self.env["GITHUB_REPOSITORY"] + "/rulesets/201"),
            endpoints.index(
                "repos/" + self.env["GITHUB_REPOSITORY"] + "/git/ref/heads/master"
            ),
        )
        self.assertTrue(
            any(endpoint.endswith("/rulesets?per_page=100") for endpoint in endpoints)
        )
        self.assertTrue(
            any(
                endpoint.endswith("/rules/branches/master?per_page=100")
                for endpoint in endpoints
            )
        )

    def test_freeze_missing_duplicate_or_foreign_ruleset_blocks(self):
        original = copy.deepcopy(self.ruleset_pages)
        cases = (
            [[]],
            [[{**self.ruleset, "source": "foreign/repo"}]],
            [[{**self.ruleset, "name": "wrong-name"}]],
            [original[0], copy.deepcopy(original[0])],
            [[{**self.ruleset, "id": 0}]],
            [[{**self.ruleset, "target": "tag"}]],
            [[{**self.ruleset, "enforcement": "disabled"}]],
            [None],
        )
        for index, pages in enumerate(cases):
            with self.subTest(index=index):
                self.ruleset_pages = pages
                with self.assertRaises(VERIFIER.Failure):
                    self.verify()
        self.ruleset_pages = [[], original[0]]
        self.verify()

    def test_freeze_detail_requires_explicit_no_bypass_exact_master_and_active_update(
        self,
    ):
        original = copy.deepcopy(self.ruleset_detail)
        cases = (
            ("bypass_actors", None),
            (
                "bypass_actors",
                [{"actor_id": 5, "actor_type": "Integration", "bypass_mode": "always"}],
            ),
            ("target", "tag"),
            ("enforcement", "evaluate"),
            ("source", "foreign/repo"),
            ("source_type", "Organization"),
            ("id", 202),
            ("name", "changed"),
            (
                "conditions",
                {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
            ),
            (
                "conditions",
                {
                    "ref_name": {
                        "include": ["refs/heads/master"],
                        "exclude": ["refs/heads/other"],
                    }
                },
            ),
            ("rules", []),
            ("rules", [{"type": "update"}, {"type": "deletion"}]),
            ("rules", [{"type": "deletion"}]),
            (
                "rules",
                [
                    {
                        "type": "update",
                        "parameters": {"update_allows_fetch_and_merge": True},
                    }
                ],
            ),
            (
                "rules",
                [
                    {
                        "type": "update",
                        "parameters": {"update_allows_fetch_and_merge": 0},
                    }
                ],
            ),
            ("rules", [{"type": "update", "parameters": {}}]),
            ("rules", [{"type": "update", "parameters": None}]),
            ("rules", [{"type": "update", "unknown": False}]),
            (
                "rules",
                [
                    {
                        "type": "update",
                        "parameters": {
                            "update_allows_fetch_and_merge": False,
                            "unknown": False,
                        },
                    }
                ],
            ),
        )
        for key, value in cases:
            with self.subTest(key=key, value=value):
                self.ruleset_detail = {**copy.deepcopy(original), key: value}
                with self.assertRaises(VERIFIER.Failure):
                    self.verify()
        self.ruleset_detail = copy.deepcopy(original)
        del self.ruleset_detail["bypass_actors"]
        with self.assertRaises(VERIFIER.Failure):
            self.verify()
        self.ruleset_detail = copy.deepcopy(original)
        self.ruleset_detail["rules"][0]["parameters"] = {
            "update_allows_fetch_and_merge": False
        }
        self.verify()

    def test_freeze_must_be_effective_for_the_exact_source_ruleset(self):
        update = copy.deepcopy(self.effective_pages[0][0])
        cases = (
            [[]],
            [[{**update, "ruleset_id": 202}]],
            [[{**update, "ruleset_id": "201"}]],
            [[{**update, "ruleset_source": "foreign/repo"}]],
            [[{**update, "ruleset_source_type": "Organization"}]],
            [[{**update, "type": "deletion"}]],
            [[{**update, "parameters": {"update_allows_fetch_and_merge": True}}]],
            [[{**update, "unknown": False}]],
            [[update], [copy.deepcopy(update)]],
        )
        for index, pages in enumerate(cases):
            with self.subTest(index=index):
                self.effective_pages = pages
                with self.assertRaises(VERIFIER.Failure):
                    self.verify()
        self.effective_pages = [
            [{**update, "parameters": {"update_allows_fetch_and_merge": False}}]
        ]
        self.verify()

    def test_freeze_requires_confirmed_nonfork_repository_and_no_parent_source(self):
        original = copy.deepcopy(self.repo_info)
        for key, value in (
            ("fork", True),
            ("fork", None),
            ("fork", 0),
            ("parent", {}),
            ("source", {}),
            ("full_name", "foreign/repo"),
        ):
            with self.subTest(key=key, value=value):
                self.repo_info = {**copy.deepcopy(original), key: value}
                with self.assertRaises(VERIFIER.Failure):
                    self.verify()
        self.repo_info = {"full_name": self.env["GITHUB_REPOSITORY"], "fork": False}
        self.verify()

    def test_freeze_api_unauthorized_or_incomplete_evidence_blocks_without_secrets(
        self,
    ):
        for endpoint in ("/rulesets?", "/rulesets/201", "/rules/branches/master"):
            with self.subTest(endpoint=endpoint):
                self.freeze_error_endpoint = endpoint
                with self.assertRaises(VERIFIER.Failure) as error:
                    self.verify()
                self.assertNotIn("secret-freeze-token", str(error.exception))
        self.freeze_error_endpoint = None

    def test_invalid_inputs_rejected_before_commands(self):
        cases = {
            "MANUAL_DIGEST": [
                "",
                "sha256:" + "0" * 64,
                DIGEST + ";echo BAD",
                DIGEST.upper(),
            ],
            "EXPECTED_MASTER_SHA": ["", "a" * 7, "0" * 40, SHA + "\n"],
            "QUALITY_RUN_ID": ["0", "001", "1;echo BAD"],
            "BUILD_RUN_ID": ["101"],
            "RELEASE_CUTOFF": [
                "2026-10-31",
                "2026-10-31T11:00:00+00:00",
                "2026-11-01T00:00:00Z",
            ],
            "EXPECTED_MACHINE_ID": ["", "0" * 14, "$(echo BAD)"],
            "EXPECTED_MACHINE_VERSION": ["0", "", "x y"],
            "EXPECTED_MACHINE_DIGEST": ["sha256:" + "0" * 64],
            "GITHUB_REPOSITORY": ["owner/repo/../../evil", "-evil/repo"],
            "GITHUB_REF": ["refs/heads/feature", "refs/heads/MASTER"],
            "GITHUB_EVENT_NAME": ["push"],
            "GITHUB_SHA": ["d" * 40],
            "PREFLIGHT_EXIT_CODE": ["1", "2", "-1"],
        }
        original = self.env.copy()
        for key, values in cases.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    self.env = {**original, key: value}
                    self.calls.clear()
                    with self.assertRaises(VERIFIER.Failure):
                        self.verify()
                    self.assertEqual(self.calls, [])
        self.env = original

    def test_master_head_mismatch_blocks(self):
        self.master = "d" * 40
        with self.assertRaises(VERIFIER.Failure):
            self.verify()

    def invalid_registry_cases(self):
        child = self.registry["manifests"][0]
        cases = [
            {key: value for key, value in self.registry.items() if key != "manifests"},
            {**self.registry, "manifests": None},
            {**self.registry, "manifests": []},
            {**self.registry, "manifests": [None]},
            {**self.registry, "manifests": [{**child, "platform": None}]},
            {
                **self.registry,
                "manifests": [
                    {**child, "platform": {"os": "linux", "architecture": "arm64"}}
                ],
            },
            {**self.registry, "manifests": [child, copy.deepcopy(child)]},
        ]
        for digest in (
            None,
            "",
            "sha256:" + "0" * 64,
            "sha256:" + "e" * 63,
            RUNTIME_DIGEST.upper(),
            DIGEST,
        ):
            cases.append({**self.registry, "manifests": [{**child, "digest": digest}]})
        for media_type in (
            None,
            "",
            "application/vnd.oci.image.index.v1+json",
            "unknown",
        ):
            cases.append(
                {**self.registry, "manifests": [{**child, "mediaType": media_type}]}
            )
        return cases

    def test_registry_requires_one_canonical_linux_amd64_manifest_before_commands(self):
        original = copy.deepcopy(self.registry)
        for index, registry in enumerate(self.invalid_registry_cases()):
            with self.subTest(index=index):
                self.registry = registry
                self.calls.clear()
                with self.assertRaises(VERIFIER.Failure):
                    self.verify()
                self.assertEqual(self.calls, [])
        self.registry = original
        for media_type in (
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        ):
            with self.subTest(valid_media_type=media_type):
                self.registry["manifests"][0]["mediaType"] = media_type
                self.verify()

    def test_expected_run_ids_must_use_original_attempt(self):
        for workflow, rows in self.runs.items():
            for run in rows:
                with self.subTest(workflow=workflow, run_id=run["id"]):
                    run["run_attempt"] = 2
                    with self.assertRaisesRegex(
                        VERIFIER.Failure, "expected producer attempt"
                    ):
                        self.verify()
                    run["run_attempt"] = 1

    def test_invalid_registry_never_emits_permission_or_reaches_deploy_stub(self):
        actual_verify = VERIFIER.verify
        deployments = []
        for index, registry in enumerate(self.invalid_registry_cases()):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                paths = [
                    root / name
                    for name in ("producer.json", "registry.json", "preflight.json")
                ]
                for path, value in zip(
                    paths, (self.producer, registry, self.preflight)
                ):
                    path.write_text(json.dumps(value))
                output = root / "github-output"
                argv = [
                    "verify",
                    "--producer",
                    str(paths[0]),
                    "--registry",
                    str(paths[1]),
                    "--preflight",
                    str(paths[2]),
                    "--preflight-finished",
                    str(root / "finished.txt"),
                ]
                (root / "finished.txt").write_text(self.finished)

                def verify_with_local_evidence(
                    env, producer, registry, preflight, *, preflight_finished=None
                ):
                    return actual_verify(
                        env,
                        producer,
                        registry,
                        preflight,
                        NOW,
                        self.runner,
                        preflight_finished=preflight_finished,
                    )

                with (
                    patch.object(VERIFIER.sys, "argv", argv),
                    patch.dict(
                        os.environ,
                        {**self.env, "GITHUB_OUTPUT": str(output)},
                        clear=True,
                    ),
                    patch.object(
                        VERIFIER, "verify", side_effect=verify_with_local_evidence
                    ),
                    contextlib.redirect_stdout(io.StringIO()),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    status = VERIFIER.main()
                if status == 0 and output.exists():
                    deployments.append(output.read_text())
                self.assertEqual(status, 1)
                self.assertFalse(output.exists())
        self.assertEqual(deployments, [])

    def test_producer_and_registry_must_bind_run_sha_and_index_digest(self):
        for target, key, value in (
            ("producer", "head_sha", "d" * 40),
            ("producer", "run_id", "999"),
            ("producer", "image_digest", BASELINE),
            ("registry", "digest", BASELINE),
            ("registry", "mediaType", "application/vnd.oci.image.manifest.v1+json"),
        ):
            with self.subTest(target=target, key=key):
                original = copy.deepcopy(getattr(self, target))
                getattr(self, target)[key] = value
                with self.assertRaises(VERIFIER.Failure):
                    self.verify()
                setattr(self, target, original)

    def previous_digest_dispatch(self, conclusion="failure", run_attempt=1):
        run = workflow_run(105, "zc-fly-deploy.yml", "workflow_dispatch", conclusion)
        run["run_attempt"] = run_attempt
        self.runs["zc-fly-deploy.yml"].append(run)
        self.jobs[105] = [
            [
                {
                    "id": 901,
                    "run_id": 105,
                    "run_attempt": attempt,
                    "head_sha": SHA,
                    "name": "Deploy app",
                    "status": "completed",
                    "conclusion": conclusion,
                    "steps": [
                        {
                            "number": 1,
                            "name": "Select and validate deploy mode",
                            "status": "completed",
                            "conclusion": "success",
                        },
                        {
                            "number": 2,
                            "name": "Resolve legacy image tag",
                            "status": "completed",
                            "conclusion": "skipped",
                        },
                        {
                            "number": 3,
                            "name": "Verify private integration access",
                            "status": "completed",
                            "conclusion": conclusion,
                        },
                        {
                            "number": 4,
                            "name": "Deploy validated immutable digest",
                            "status": "completed",
                            "conclusion": "skipped",
                        },
                        {
                            "number": 5,
                            "name": "Deploy legacy emergency image tag",
                            "status": "completed",
                            "conclusion": "skipped",
                        },
                    ],
                }
            ]
            for attempt in range(1, run_attempt + 1)
        ]
        for index, page in enumerate(self.jobs[105]):
            page[0]["id"] += index
        return run

    def test_failed_or_cancelled_same_head_digest_dispatch_without_deploy_can_recover(
        self,
    ):
        for conclusion in ("failure", "cancelled"):
            with self.subTest(conclusion=conclusion):
                self.previous_digest_dispatch(conclusion, run_attempt=2)
                self.verify()
                self.runs["zc-fly-deploy.yml"].pop()
                self.assertTrue(
                    any(
                        "/jobs?" in call[0][-1] and "filter=all" in call[0][-1]
                        for call in self.calls
                    )
                )

    def test_previous_dispatch_with_side_effect_wrong_identity_or_ambiguous_jobs_blocks(
        self,
    ):
        for key, value in (
            ("conclusion", "success"),
            ("head_sha", "e" * 40),
            ("event", "workflow_run"),
            ("head_branch", "feature"),
            ("head_commit", {"id": SHA, "message": "no marker"}),
            ("status", "in_progress"),
        ):
            with self.subTest(key=key):
                run = self.previous_digest_dispatch()
                run[key] = value
                with self.assertRaises(VERIFIER.Failure):
                    self.verify()
                self.runs["zc-fly-deploy.yml"].pop()
        for job_key, value in (
            ("steps", []),
            ("head_sha", "e" * 40),
            ("run_id", 999),
            ("run_attempt", 3),
            ("status", "in_progress"),
            ("name", "Other job"),
        ):
            with self.subTest(job_key=job_key):
                self.previous_digest_dispatch()
                self.jobs[105][0][0][job_key] = value
                with self.assertRaises(VERIFIER.Failure):
                    self.verify()
                self.runs["zc-fly-deploy.yml"].pop()
        for step in (
            "Deploy validated immutable digest",
            "Deploy legacy emergency image tag",
        ):
            with self.subTest(step=step):
                self.previous_digest_dispatch(run_attempt=2)
                for entry in self.jobs[105][0][0]["steps"]:
                    if entry["name"] == step:
                        entry["conclusion"] = "success"
                with self.assertRaises(VERIFIER.Failure):
                    self.verify()
                self.runs["zc-fly-deploy.yml"].pop()
        self.previous_digest_dispatch()
        for mode_step in (
            "Select and validate deploy mode",
            "Resolve legacy image tag",
        ):
            original = copy.deepcopy(self.jobs)
            for step in self.jobs[105][0][0]["steps"]:
                if step["name"] == mode_step:
                    step["conclusion"] = "failure"
            with self.assertRaises(VERIFIER.Failure):
                self.verify()
            self.jobs = original

    def test_recovery_requires_unambiguous_complete_jobs_and_digest_mode_evidence(self):
        self.previous_digest_dispatch(run_attempt=2)
        original = copy.deepcopy(self.jobs)
        mutations = (
            lambda jobs: jobs[105][1][0].update(id=901),
            lambda jobs: jobs[105][1][0].update(run_attempt=1),
            lambda jobs: jobs[105][0][0]["steps"].pop(),
            lambda jobs: jobs[105][0][0]["steps"].append(
                copy.deepcopy(jobs[105][0][0]["steps"][0])
            ),
            lambda jobs: jobs[105][0][0]["steps"][2].update(conclusion="skipped"),
            lambda jobs: jobs[105][0][0]["steps"][3].update(status="in_progress"),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.jobs = copy.deepcopy(original)
                mutate(self.jobs)
                with self.assertRaises(VERIFIER.Failure):
                    self.verify()

    def test_recovered_dispatch_direct_run_identity_drift_blocks(self):
        self.previous_digest_dispatch()
        original = self.runner

        def drift_runner(argv, **kwargs):
            result = original(argv, **kwargs)
            if argv[-1].endswith("/actions/runs/105"):
                changed = json.loads(result.stdout)
                changed[0]["head_sha"] = "e" * 40
                result.stdout = json.dumps(changed)
            return result

        with self.assertRaises(VERIFIER.Failure):
            VERIFIER.verify(
                self.env,
                self.producer,
                self.registry,
                self.preflight,
                NOW,
                drift_runner,
                preflight_finished=self.finished,
            )

    def test_recovery_jobs_api_error_incomplete_or_missing_attempt_blocks(self):
        self.previous_digest_dispatch(run_attempt=2)
        self.jobs_error = True
        with self.assertRaises(VERIFIER.Failure) as error:
            self.verify()
        self.assertNotIn("secret-job-token", str(error.exception))
        self.jobs_error = False
        self.jobs_count_delta = 1
        with self.assertRaises(VERIFIER.Failure):
            self.verify()
        self.jobs_count_delta = 0
        self.jobs[105].pop(0)
        with self.assertRaises(VERIFIER.Failure):
            self.verify()

    def test_completed_pr_only_runs_do_not_block_but_active_and_master_runs_do(self):
        for workflow in ("ci.yml", "zc-build-image.yml"):
            with self.subTest(workflow=workflow):
                run = workflow_run(999, workflow, "pull_request")
                run["head_branch"] = "feature"
                run["head_sha"] = "e" * 40
                self.runs[workflow].append(run)
                self.verify()
                run.update(status="in_progress", conclusion=None)
                with self.assertRaises(VERIFIER.Failure):
                    self.verify()
                run.update(
                    status="completed",
                    conclusion="success",
                    event="push",
                    head_branch="master",
                )
                with self.assertRaises(VERIFIER.Failure):
                    self.verify()
                self.runs[workflow].pop()

    def test_old_completed_history_is_classified_before_strict_identity(self):
        for workflow in self.runs:
            with self.subTest(workflow=workflow):
                run = {
                    "id": 999,
                    "status": "completed",
                    "created_at": "2026-10-30T00:00:00Z",
                    "updated_at": "2026-10-30T00:01:00Z",
                    "head_branch": None,
                }
                self.runs[workflow].append(run)
                self.verify()
                for field, value in (
                    ("id", 0),
                    ("created_at", "bad"),
                    ("updated_at", None),
                    ("status", None),
                ):
                    original = run[field]
                    run[field] = value
                    with self.assertRaises(VERIFIER.Failure):
                        self.verify()
                    run[field] = original
                self.runs[workflow].pop()

    def test_preflight_finished_timing_accepts_long_scan_and_bounds_all_gaps(self):
        self.preflight["observed_at"] = (NOW - timedelta(seconds=90)).isoformat()
        self.finished = (NOW - timedelta(seconds=5)).isoformat()
        self.verify()
        for observed, finished in ((-90, -40), (-130, -5), (-1, -5), (-5, 1)):
            with self.subTest(observed=observed, finished=finished):
                self.preflight["observed_at"] = (
                    NOW + timedelta(seconds=observed)
                ).isoformat()
                self.finished = (NOW + timedelta(seconds=finished)).isoformat()
                with self.assertRaises(VERIFIER.Failure):
                    self.verify()

    def test_preflight_finished_boundaries_and_invalid_timestamp(self):
        self.preflight["observed_at"] = (NOW - timedelta(seconds=150)).isoformat()
        self.finished = (NOW - timedelta(seconds=30)).isoformat()
        current = [NOW]
        original = self.runner

        def boundary_runner(argv, **kwargs):
            result = original(argv, **kwargs)
            current[0] = NOW + timedelta(seconds=90)
            return result

        VERIFIER.verify(
            self.env,
            self.producer,
            self.registry,
            self.preflight,
            lambda: current[0],
            boundary_runner,
            preflight_finished=self.finished,
        )
        for value in (None, "bad", "2026-10-31T11:59:58", "2026-10-31T11:59:58+01:00"):
            with self.subTest(value=value):
                with self.assertRaises(VERIFIER.Failure):
                    VERIFIER.verify(
                        self.env,
                        self.producer,
                        self.registry,
                        self.preflight,
                        NOW,
                        self.runner,
                        preflight_finished=value,
                    )

    def test_slow_verifier_and_repeated_full_verify_cannot_reuse_old_quiescence(self):
        self.preflight["observed_at"] = (NOW - timedelta(seconds=90)).isoformat()
        self.finished = (NOW - timedelta(seconds=5)).isoformat()
        current = [NOW]
        original = self.runner

        def delayed_runner(argv, **kwargs):
            result = original(argv, **kwargs)
            current[0] = NOW + timedelta(seconds=60)
            return result

        VERIFIER.verify(
            self.env,
            self.producer,
            self.registry,
            self.preflight,
            lambda: current[0],
            delayed_runner,
            preflight_finished=self.finished,
        )
        current[0] = NOW

        def too_slow_runner(argv, **kwargs):
            result = original(argv, **kwargs)
            current[0] = NOW + timedelta(seconds=91)
            return result

        with self.assertRaises(VERIFIER.Failure):
            VERIFIER.verify(
                self.env,
                self.producer,
                self.registry,
                self.preflight,
                lambda: current[0],
                too_slow_runner,
                preflight_finished=self.finished,
            )
        with self.assertRaises(VERIFIER.Failure):
            VERIFIER.verify(
                self.env,
                self.producer,
                self.registry,
                self.preflight,
                NOW + timedelta(seconds=31),
                self.runner,
                preflight_finished=self.finished,
            )

    def test_foreign_completed_deploy_on_second_page_blocks(self):
        self.extra_page = workflow_run(999, "zc-fly-deploy.yml", "workflow_dispatch")
        with self.assertRaises(VERIFIER.Failure):
            self.verify()

    def test_active_older_foreign_run_and_rerun_after_cutoff_block(self):
        for active in (True, False):
            with self.subTest(active=active):
                self.extra_page = workflow_run(
                    999, "zc-fly-deploy.yml", "workflow_dispatch"
                )
                self.extra_page["created_at"] = "2026-10-30T00:00:00Z"
                if active:
                    self.extra_page.update(
                        status="in_progress",
                        conclusion=None,
                        updated_at="2026-10-30T00:10:00Z",
                    )
                with self.assertRaises(VERIFIER.Failure):
                    self.verify()

    def test_foreign_completed_old_run_is_not_a_release_blocker(self):
        self.extra_page = workflow_run(999, "zc-fly-deploy.yml", "workflow_dispatch")
        self.extra_page.update(
            created_at="2026-10-30T00:00:00Z", updated_at="2026-10-30T00:10:00Z"
        )
        self.verify()

    def test_expected_ids_never_whitelist_wrong_workflow_event_head_or_outcome(self):
        for path, index, key, value in (
            ("ci.yml", 0, "path", ".github/workflows/unrelated.yml"),
            ("ci.yml", 0, "event", "workflow_dispatch"),
            ("ci.yml", 0, "head_branch", "feature"),
            ("ci.yml", 0, "head_sha", "d" * 40),
            ("ci.yml", 0, "conclusion", "failure"),
            ("zc-build-image.yml", 0, "event", "workflow_dispatch"),
            ("zc-fly-deploy.yml", 0, "conclusion", "success"),
            ("zc-fly-deploy.yml", 0, "event", "workflow_dispatch"),
            ("zc-fly-deploy.yml", 0, "head_commit", {"id": SHA, "message": "release"}),
            ("zc-fly-deploy.yml", 1, "status", "completed"),
        ):
            with self.subTest(path=path, key=key):
                original = copy.deepcopy(self.runs)
                self.runs[path][index][key] = value
                with self.assertRaises(VERIFIER.Failure):
                    self.verify()
                self.runs = original

    def test_api_access_error_and_incomplete_pagination_block_without_secrets(self):
        self.api_failure = True
        with self.assertRaises(VERIFIER.Failure) as error:
            self.verify()
        self.assertNotIn("secret-token-value", str(error.exception))
        self.api_failure = False
        self.total_count_delta = 1
        with self.assertRaises(VERIFIER.Failure):
            self.verify()

    def test_machine_roster_id_version_digest_and_state_must_match(self):
        for key, value in (
            ("id", "18040d6c71e938"),
            ("version", "01K8OTHER"),
            ("state", "stopped"),
            ("image_ref", {"digest": DIGEST}),
            ("image_ref", {}),
        ):
            with self.subTest(key=key):
                original = copy.deepcopy(self.machine)
                self.machine[key] = value
                with self.assertRaises(VERIFIER.Failure):
                    self.verify()
                self.machine.clear()
                self.machine.update(original)
        self.fly_machines.append(copy.deepcopy(self.machine))
        with self.assertRaises(VERIFIER.Failure):
            self.verify()

    def test_stale_future_busy_or_unbound_preflight_blocks(self):
        for key, value in (
            ("observed_at", (NOW - timedelta(seconds=123)).isoformat()),
            ("observed_at", (NOW + timedelta(seconds=1)).isoformat()),
            ("observed_at", "2026-10-30T00:00:00Z"),
            ("busy", ["tg_83292437/run/task"]),
            ("busy_reasons", {"task": {}}),
            ("exec", "FAIL"),
            ("state", "UNKNOWN"),
            ("image", "ghcr.io/ogismatulin/zeroclaw:other"),
            ("machine", "18040d6c71e938"),
            ("reason", "remote execution unavailable"),
            ("sources", {}),
            ("unknown", ["tg_83292437/run inventory: unavailable"]),
        ):
            with self.subTest(key=key):
                original = copy.deepcopy(self.preflight)
                self.preflight[key] = value
                with self.assertRaises(VERIFIER.Failure):
                    self.verify()
                self.preflight = original

    def test_only_exact_approved_unavailable_unknown_is_accepted(self):
        allowed = set(VERIFIER.ALLOWED_UNKNOWN)
        self.preflight.update(state="UNKNOWN", unknown=sorted(allowed))
        self.env["PREFLIGHT_EXIT_CODE"] = "3"
        for user in ("tg_585236623", "tg_88888", "tg_897389102"):
            self.preflight["users"].append(user)
            self.preflight["sources"][user] = {
                "state/jira_watch/analysis_queue.json": "UNAVAILABLE",
                "control_plane.db": "READ",
                "logs/runtime-trace.jsonl": "READ",
                "delegate_results": "UNAVAILABLE",
            }
        self.verify()
        for unknown in (
            [],
            ["tg_88888/control_plane.db: unavailable"],
            ["tg_88888/run inventory: permission denied"],
            sorted(allowed) + ["other"],
        ):
            with self.subTest(unknown=unknown):
                self.preflight["unknown"] = unknown
                with self.assertRaises(VERIFIER.Failure):
                    self.verify()

    def test_missing_expected_run_or_different_direct_run_blocks(self):
        removed = self.runs["ci.yml"].pop()
        with self.assertRaises(VERIFIER.Failure):
            self.verify()
        self.runs["ci.yml"].append(removed)
        original = self.runner

        def drift_runner(argv, **kwargs):
            result = original(argv, **kwargs)
            if argv[-1].endswith("/actions/runs/101"):
                changed = json.loads(result.stdout)
                changed[0]["head_sha"] = "d" * 40
                result.stdout = json.dumps(changed)
            return result

        with self.assertRaises(VERIFIER.Failure):
            VERIFIER.verify(
                self.env,
                self.producer,
                self.registry,
                self.preflight,
                NOW,
                drift_runner,
                preflight_finished=self.finished,
            )

    def test_preflight_exit_code_must_agree_with_receipt(self):
        self.env["PREFLIGHT_EXIT_CODE"] = "3"
        with self.assertRaises(VERIFIER.Failure):
            self.verify()

    def test_cli_outputs_digest_only_after_all_checks_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [
                root / name
                for name in ("producer.json", "registry.json", "preflight.json")
            ]
            for path, value in zip(
                paths, (self.producer, self.registry, self.preflight)
            ):
                path.write_text(json.dumps(value))
            output = root / "github-output"
            argv = [
                "verify",
                "--producer",
                str(paths[0]),
                "--registry",
                str(paths[1]),
                "--preflight",
                str(paths[2]),
                "--preflight-finished",
                str(root / "finished.txt"),
            ]
            (root / "finished.txt").write_text(self.finished)
            with (
                patch.object(VERIFIER.sys, "argv", argv),
                patch.dict(
                    os.environ, {**self.env, "GITHUB_OUTPUT": str(output)}, clear=True
                ),
            ):
                with (
                    patch.object(
                        VERIFIER, "verify", return_value={"image_digest": DIGEST}
                    ),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(VERIFIER.main(), 0)
                self.assertEqual(output.read_text(), "image_digest=" + DIGEST + "\n")
                output.unlink()
                with (
                    patch.object(
                        VERIFIER, "verify", side_effect=VERIFIER.Failure("gated")
                    ),
                    contextlib.redirect_stderr(io.StringIO()),
                ):
                    self.assertEqual(VERIFIER.main(), 1)
                self.assertFalse(output.exists())

    def test_duplicate_json_keys_and_non_json_command_output_fail_closed(self):
        with self.assertRaises(VERIFIER.Failure):
            VERIFIER.parse_json('{"digest":"one","digest":"two"}')
        with self.assertRaises(VERIFIER.Failure):
            VERIFIER.parse_json('{"value":NaN}')
        original = self.runner

        def bad_runner(argv, **kwargs):
            result = original(argv, **kwargs)
            result.stdout = "not json secret-token-value"
            return result

        with self.assertRaises(VERIFIER.Failure) as error:
            VERIFIER.verify(
                self.env,
                self.producer,
                self.registry,
                self.preflight,
                NOW,
                bad_runner,
                preflight_finished=self.finished,
            )
        self.assertNotIn("secret-token-value", str(error.exception))


if __name__ == "__main__":
    unittest.main()
