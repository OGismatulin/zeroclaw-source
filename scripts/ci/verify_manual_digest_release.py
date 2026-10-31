from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


APP = "ai-forge-zeroclaw"
IMAGE = "ghcr.io/ogismatulin/zeroclaw"
MARKER = "[manual-digest-deploy-20261031]"
WORKFLOWS = ("ci.yml", "zc-build-image.yml", "zc-fly-deploy.yml")
SOURCE_NAMES = (
    "state/jira_watch/analysis_queue.json",
    "control_plane.db",
    "logs/runtime-trace.jsonl",
    "delegate_results",
)
ALLOWED_UNKNOWN = frozenset(
    f"{user}/{source}: unavailable"
    for user in ("tg_585236623", "tg_88888", "tg_897389102")
    for source in (SOURCE_NAMES[0], "delegate_results", "run inventory")
)


class Failure(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Failure(message)


def parse_json(raw):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON field")
            result[key] = value
        return result

    try:
        return json.loads(
            raw,
            object_pairs_hook=unique_pairs,
            parse_constant=lambda value: require(False, "invalid JSON constant"),
        )
    except (ValueError, TypeError):
        raise Failure("invalid JSON evidence") from None


def timestamp(value, strict=False):
    pattern = (
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"
        if strict
        else r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)"
    )
    require(
        isinstance(value, str) and re.fullmatch(pattern, value), "invalid UTC timestamp"
    )
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise Failure("invalid UTC timestamp") from None


def validated_env(env, now):
    patterns = {
        "MANUAL_DIGEST": r"sha256:[0-9a-f]{64}",
        "EXPECTED_MASTER_SHA": r"[0-9a-f]{40}",
        "QUALITY_RUN_ID": r"[1-9][0-9]{0,19}",
        "BUILD_RUN_ID": r"[1-9][0-9]{0,19}",
        "SKIPPED_DEPLOY_RUN_ID": r"[1-9][0-9]{0,19}",
        "EXPECTED_MACHINE_ID": r"[0-9a-f]{14}",
        "EXPECTED_MACHINE_VERSION": r"[0-7][0-9A-HJKMNP-TV-Z]{25}",
        "EXPECTED_MACHINE_DIGEST": r"sha256:[0-9a-f]{64}",
        "GITHUB_REPOSITORY": r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*",
        "GITHUB_RUN_ID": r"[1-9][0-9]{0,19}",
        "PREFLIGHT_EXIT_CODE": r"[03]",
    }
    values = {}
    for key, pattern in patterns.items():
        value = env.get(key)
        require(
            isinstance(value, str) and re.fullmatch(pattern, value),
            "invalid release input: " + key,
        )
        require(
            key == "PREFLIGHT_EXIT_CODE" or set(value.removeprefix("sha256:")) != {"0"},
            "zero release input: " + key,
        )
        values[key] = value
    require(
        env.get("GITHUB_EVENT_NAME") == "workflow_dispatch", "manual dispatch required"
    )
    require(env.get("GITHUB_REF") == "refs/heads/master", "master ref required")
    require(
        env.get("GITHUB_SHA") == values["EXPECTED_MASTER_SHA"], "dispatch SHA mismatch"
    )
    ids = [
        values[key]
        for key in (
            "QUALITY_RUN_ID",
            "BUILD_RUN_ID",
            "SKIPPED_DEPLOY_RUN_ID",
            "GITHUB_RUN_ID",
        )
    ]
    require(len(set(ids)) == len(ids), "release run IDs must be distinct")
    values["cutoff"] = timestamp(env.get("RELEASE_CUTOFF"), strict=True)
    require(values["cutoff"] <= now, "release cutoff is in the future")
    return values


def command_json(argv, runner):
    try:
        result = runner(argv, capture_output=True, text=True, check=True, timeout=120)
        require(result.returncode == 0, "read-only evidence command failed")
        return parse_json(result.stdout)
    except (OSError, subprocess.SubprocessError):
        raise Failure("read-only evidence command failed") from None


def gh_pages(repo, endpoint, runner):
    path = f"repos/{repo}" + (f"/{endpoint}" if endpoint else "")
    pages = command_json(["gh", "api", "--paginate", "--slurp", path], runner)
    require(isinstance(pages, list) and pages, "missing GitHub API pages")
    require(all(isinstance(page, dict) for page in pages), "invalid GitHub API pages")
    return pages


def one_api(repo, endpoint, runner):
    pages = gh_pages(repo, endpoint, runner)
    require(len(pages) == 1, "ambiguous GitHub API response")
    return pages[0]


def gh_array(repo, endpoint, runner):
    pages = command_json(
        ["gh", "api", "--paginate", "--slurp", f"repos/{repo}/{endpoint}"], runner
    )
    require(
        isinstance(pages, list)
        and pages
        and all(isinstance(page, list) for page in pages),
        "invalid paginated rules API response",
    )
    rows = [row for page in pages for row in page]
    require(all(isinstance(row, dict) for row in rows), "invalid rules API inventory")
    return rows


def verify_update_rule(rule, effective=False):
    fields = {"type", "parameters"}
    if effective:
        fields.update(("ruleset_id", "ruleset_source", "ruleset_source_type"))
    require(
        isinstance(rule, dict) and rule.get("type") == "update" and set(rule) <= fields,
        "unknown update rule shape",
    )
    if "parameters" in rule:
        parameters = rule["parameters"]
        require(
            isinstance(parameters, dict)
            and set(parameters) == {"update_allows_fetch_and_merge"}
            and parameters["update_allows_fetch_and_merge"] is False,
            "unsafe or unknown update rule parameters",
        )


def verify_freeze(values, runner):
    repo = values["GITHUB_REPOSITORY"]
    repository = one_api(repo, "", runner)
    require(
        repository.get("full_name") == repo
        and repository.get("fork") is False
        and repository.get("parent") is None
        and repository.get("source") is None,
        "freeze requires confirmed nonfork repository",
    )
    name = "zc-digest-freeze-" + values["EXPECTED_MASTER_SHA"]
    rulesets = gh_array(repo, "rulesets?per_page=100", runner)
    require(
        all(
            type(row.get("id")) is int
            and row["id"] > 0
            and isinstance(row.get("name"), str)
            and row["name"]
            and isinstance(row.get("source"), str)
            and row["source"]
            for row in rulesets
        ),
        "incomplete ruleset inventory",
    )
    matches = [row for row in rulesets if row["name"] == name and row["source"] == repo]
    require(len(matches) == 1, "missing or ambiguous release freeze ruleset")
    selected = matches[0]
    require(
        selected.get("target") == "branch" and selected.get("enforcement") == "active",
        "release freeze list identity drift",
    )
    detail = one_api(repo, f"rulesets/{selected['id']}", runner)
    require(
        type(detail.get("id")) is int
        and detail["id"] == selected["id"]
        and detail.get("name") == name
        and detail.get("source") == repo
        and detail.get("source_type") == "Repository"
        and detail.get("target") == "branch"
        and detail.get("enforcement") == "active",
        "release freeze identity drift",
    )
    require(
        detail.get("bypass_actors") == [],
        "release freeze bypass actors absent or nonempty",
    )
    conditions = detail.get("conditions")
    require(
        isinstance(conditions, dict)
        and set(conditions) == {"ref_name"}
        and isinstance(conditions.get("ref_name"), dict)
        and conditions["ref_name"] == {"include": ["refs/heads/master"], "exclude": []},
        "release freeze master scope mismatch",
    )
    rules = detail.get("rules")
    require(
        isinstance(rules, list) and len(rules) == 1,
        "release freeze update rule missing or ambiguous",
    )
    verify_update_rule(rules[0])
    effective = gh_array(repo, "rules/branches/master?per_page=100", runner)
    matches = [
        rule
        for rule in effective
        if rule.get("type") == "update"
        and type(rule.get("ruleset_id")) is int
        and rule["ruleset_id"] == selected["id"]
    ]
    require(len(matches) == 1, "release freeze update is not uniquely effective")
    update = matches[0]
    require(
        update.get("ruleset_source") == repo
        and update.get("ruleset_source_type") == "Repository",
        "effective release freeze source mismatch",
    )
    verify_update_rule(update, effective=True)
    return selected["id"]


def run_window(run):
    require(isinstance(run, dict), "invalid workflow run")
    require(type(run.get("id")) is int and run["id"] > 0, "invalid workflow run ID")
    require(
        run.get("status")
        in ("requested", "waiting", "pending", "queued", "in_progress", "completed"),
        "unknown workflow run status",
    )
    created = timestamp(run.get("created_at"))
    updated = timestamp(run.get("updated_at"))
    require(created <= updated, "invalid workflow timestamps")
    return created, updated


def run_identity(run):
    run_window(run)
    require(
        type(run.get("run_attempt")) is int and run["run_attempt"] > 0,
        "invalid workflow run attempt",
    )
    require(isinstance(run.get("path"), str), "missing workflow identity")
    require(isinstance(run.get("event"), str), "missing workflow event")
    require(isinstance(run.get("head_branch"), str), "missing workflow ref")
    require(
        isinstance(run.get("head_sha"), str)
        and re.fullmatch(r"[0-9a-f]{40}", run["head_sha"]),
        "invalid workflow SHA",
    )
    if run["status"] == "completed":
        require(
            run.get("conclusion")
            in (
                "success",
                "failure",
                "neutral",
                "cancelled",
                "skipped",
                "timed_out",
                "action_required",
                "stale",
                "startup_failure",
            ),
            "missing workflow outcome",
        )
    else:
        require(run.get("conclusion") is None, "contradictory workflow outcome")
    return tuple(
        run.get(key)
        for key in (
            "id",
            "path",
            "event",
            "head_branch",
            "head_sha",
            "status",
            "conclusion",
            "run_attempt",
            "created_at",
            "updated_at",
        )
    )


def paginated_rows(repo, endpoint, key, runner):
    pages = gh_pages(repo, endpoint, runner)
    counts = [page.get("total_count") for page in pages]
    require(
        all(type(count) is int and count >= 0 for count in counts),
        "missing pagination count",
    )
    require(len(set(counts)) == 1, "inventory changed during pagination")
    rows = []
    for page in pages:
        require(isinstance(page.get(key), list), "missing paginated inventory")
        rows.extend(page[key])
    require(len(rows) == counts[0], "incomplete paginated inventory")
    return rows


def verify_prior_dispatch(values, row, runner):
    require(
        row["event"] == "workflow_dispatch"
        and row["status"] == "completed"
        and row.get("conclusion") in ("failure", "cancelled")
        and row["head_branch"] == "master"
        and row["head_sha"] == values["EXPECTED_MASTER_SHA"],
        "unexpected relevant workflow run",
    )
    repo = values["GITHUB_REPOSITORY"]
    jobs = paginated_rows(
        repo, f"actions/runs/{row['id']}/jobs?filter=all&per_page=100", "jobs", runner
    )
    require(
        len(jobs) == row["run_attempt"], "incomplete prior dispatch attempt inventory"
    )
    seen_ids = set()
    attempts = set()
    for job in jobs:
        require(
            isinstance(job, dict) and type(job.get("id")) is int and job["id"] > 0,
            "invalid prior dispatch job",
        )
        require(job["id"] not in seen_ids, "duplicate prior dispatch job")
        seen_ids.add(job["id"])
        attempt = job.get("run_attempt")
        require(
            type(attempt) is int
            and 1 <= attempt <= row["run_attempt"]
            and attempt not in attempts,
            "invalid prior dispatch attempt",
        )
        attempts.add(attempt)
        require(
            type(job.get("run_id")) is int
            and job["run_id"] == row["id"]
            and job.get("head_sha") == values["EXPECTED_MASTER_SHA"]
            and job.get("name") == "Deploy app"
            and job.get("status") == "completed"
            and job.get("conclusion") in ("failure", "cancelled"),
            "unproven prior dispatch job identity or outcome",
        )
        steps = job.get("steps")
        require(isinstance(steps, list) and steps, "missing prior dispatch steps")
        numbers = set()
        critical = {}
        required = {
            "Select and validate deploy mode": ("success",),
            "Resolve legacy image tag": ("skipped",),
            "Verify private integration access": ("success", "failure", "cancelled"),
            "Deploy validated immutable digest": ("skipped",),
            "Deploy legacy emergency image tag": ("skipped",),
        }
        for step in steps:
            require(
                isinstance(step, dict)
                and type(step.get("number")) is int
                and step["number"] > 0
                and step["number"] not in numbers
                and isinstance(step.get("name"), str)
                and step["name"]
                and step.get("status") == "completed"
                and step.get("conclusion")
                in ("success", "failure", "cancelled", "skipped"),
                "incomplete prior dispatch step evidence",
            )
            numbers.add(step["number"])
            if step["name"] in required:
                require(step["name"] not in critical, "ambiguous prior dispatch step")
                critical[step["name"]] = step["conclusion"]
        require(
            set(critical) == set(required)
            and all(critical[name] in outcomes for name, outcomes in required.items()),
            "prior dispatch may have deployed or mode is unproven",
        )
    require(
        attempts == set(range(1, row["run_attempt"] + 1)),
        "missing prior dispatch attempt",
    )


def verify_runs(values, clock, runner):
    repo = values["GITHUB_REPOSITORY"]
    sha = values["EXPECTED_MASTER_SHA"]
    expected = {
        int(values["QUALITY_RUN_ID"]): (WORKFLOWS[0], "push", "completed", "success"),
        int(values["BUILD_RUN_ID"]): (WORKFLOWS[1], "push", "completed", "success"),
        int(values["SKIPPED_DEPLOY_RUN_ID"]): (
            WORKFLOWS[2],
            "workflow_run",
            "completed",
            "skipped",
        ),
        int(values["GITHUB_RUN_ID"]): (
            WORKFLOWS[2],
            "workflow_dispatch",
            "in_progress",
            None,
        ),
    }
    found = {}
    for workflow in WORKFLOWS:
        rows = paginated_rows(
            repo,
            f"actions/workflows/{workflow}/runs?per_page=100",
            "workflow_runs",
            runner,
        )
        seen = set()
        for row in rows:
            created, updated = run_window(row)
            require(row["id"] not in seen, "duplicate paginated workflow run")
            seen.add(row["id"])
            require(updated <= clock(), "workflow timestamp is in the future")
            relevant = (
                created >= values["cutoff"]
                or updated >= values["cutoff"]
                or row["status"] != "completed"
            )
            if not relevant and row["id"] not in expected:
                continue
            identity = run_identity(row)
            require(
                row["path"] == ".github/workflows/" + workflow,
                "workflow inventory identity mismatch",
            )
            if (
                row["id"] not in expected
                and workflow != WORKFLOWS[2]
                and row["status"] == "completed"
                and row["event"] in ("pull_request", "pull_request_target")
            ):
                continue
            if row["id"] in expected:
                path, event, status, conclusion = expected[row["id"]]
                require(
                    (workflow, row["event"], row["status"], row.get("conclusion"))
                    == (path, event, status, conclusion),
                    "expected workflow identity or outcome mismatch",
                )
                require(
                    row["head_branch"] == "master" and row["head_sha"] == sha,
                    "expected workflow head mismatch",
                )
                require(
                    created >= values["cutoff"], "expected workflow predates cutoff"
                )
                require(
                    row["run_attempt"] == 1,
                    "rerun is not the expected producer attempt",
                )
            else:
                require(workflow == WORKFLOWS[2], "unexpected relevant workflow run")
                verify_prior_dispatch(values, row, runner)
            commit = row.get("head_commit")
            require(
                isinstance(commit, dict)
                and commit.get("id") == sha
                and isinstance(commit.get("message"), str)
                and MARKER in commit["message"],
                "release marker or head commit missing",
            )
            exact = one_api(repo, f"actions/runs/{row['id']}", runner)
            require(
                run_identity(exact) == identity and exact.get("head_commit") == commit,
                "workflow run drift",
            )
            if row["id"] in expected:
                found[row["id"]] = identity
    require(set(found) == set(expected), "expected release run missing")


def verify_preflight(values, preflight, machine, verifier_start, finished):
    require(isinstance(preflight, dict), "missing preflight evidence")
    require(
        preflight.get("app") == APP and preflight.get("machine") == machine["id"],
        "preflight machine mismatch",
    )
    require(
        preflight.get("image") == machine["config"]["image"], "preflight image mismatch"
    )
    require(
        preflight.get("exec") == "PASS"
        and preflight.get("transport") in ("ssh", "machines"),
        "preflight execution unverified",
    )
    require(
        "reason" not in preflight and "quiescence" not in preflight,
        "preflight failure or quiescence missing",
    )
    observed = timestamp(preflight.get("observed_at"))
    require(
        values["cutoff"] <= observed <= finished <= verifier_start
        and (finished - observed).total_seconds() <= 120
        and (verifier_start - finished).total_seconds() <= 30,
        "preflight is not fresh",
    )
    require(
        preflight.get("busy") == [] and preflight.get("busy_reasons") == {},
        "preflight reports busy work",
    )
    unknown = preflight.get("unknown")
    require(
        isinstance(unknown, list) and all(isinstance(item, str) for item in unknown),
        "invalid preflight unknown inventory",
    )
    require(len(set(unknown)) == len(unknown), "duplicate preflight unknown reason")
    state = preflight.get("state")
    require(
        (state == "QUIET" and values["PREFLIGHT_EXIT_CODE"] == "0" and not unknown)
        or (
            state == "UNKNOWN"
            and values["PREFLIGHT_EXIT_CODE"] == "3"
            and unknown
            and set(unknown) <= ALLOWED_UNKNOWN
        ),
        "preflight state or unknown reason not approved",
    )
    users = preflight.get("users")
    sources = preflight.get("sources")
    require(
        isinstance(users, list)
        and users
        and all(
            isinstance(user, str) and re.fullmatch(r"tg_[1-9][0-9]*", user)
            for user in users
        ),
        "missing preflight users",
    )
    require(
        len(set(users)) == len(users)
        and isinstance(sources, dict)
        and set(sources) == set(users),
        "incomplete preflight user inventory",
    )
    for user in users:
        inventory = sources[user]
        require(
            isinstance(inventory, dict) and set(inventory) == set(SOURCE_NAMES),
            "incomplete preflight source inventory",
        )
        for source, outcome in inventory.items():
            reason = f"{user}/{source}: unavailable"
            require(
                outcome == "READ"
                or (
                    outcome == "UNAVAILABLE"
                    and reason in unknown
                    and reason in ALLOWED_UNKNOWN
                ),
                "preflight source unavailable or unknown",
            )
            require(
                outcome != "READ" or reason not in unknown,
                "contradictory preflight source",
            )
    require(
        all(reason.split("/", 1)[0] in users for reason in unknown),
        "unknown reason outside user inventory",
    )


def verify(
    env,
    producer,
    registry,
    preflight,
    now=None,
    runner=subprocess.run,
    *,
    preflight_finished=None,
):
    clock = (
        now
        if callable(now)
        else (lambda: now)
        if now is not None
        else lambda: datetime.now(timezone.utc)
    )
    verifier_start = clock()
    finished = timestamp(preflight_finished)
    values = validated_env(env, verifier_start)
    require(
        isinstance(producer, dict)
        and producer.get("head_sha") == values["EXPECTED_MASTER_SHA"]
        and producer.get("image_digest") == values["MANUAL_DIGEST"]
        and producer.get("run_id") == values["BUILD_RUN_ID"],
        "producer artifact mismatch",
    )
    require(
        isinstance(registry, dict)
        and registry.get("digest") == values["MANUAL_DIGEST"]
        and registry.get("mediaType")
        in (
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
        ),
        "registry index digest mismatch",
    )
    manifests = registry.get("manifests")
    require(
        isinstance(manifests, list)
        and all(
            isinstance(entry, dict) and isinstance(entry.get("platform"), dict)
            for entry in manifests
        ),
        "invalid registry platform manifests",
    )
    matches = [
        entry
        for entry in manifests
        if entry["platform"].get("os") == "linux"
        and entry["platform"].get("architecture") == "amd64"
    ]
    require(len(matches) == 1, "missing or ambiguous registry amd64 manifest")
    runtime = matches[0]
    runtime_digest = runtime.get("digest")
    require(
        isinstance(runtime_digest, str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", runtime_digest)
        and runtime_digest != "sha256:" + "0" * 64
        and runtime_digest != values["MANUAL_DIGEST"]
        and runtime.get("mediaType")
        in (
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        ),
        "invalid registry amd64 manifest identity",
    )
    verify_runs(values, clock, runner)
    status = command_json(["fly", "status", "--app", APP, "--json"], runner)
    require(
        isinstance(status, dict) and status.get("Name") == APP,
        "Fly app identity mismatch",
    )
    machines = status.get("Machines")
    require(
        isinstance(machines, list)
        and len(machines) == 1
        and isinstance(machines[0], dict),
        "Fly machine roster drift",
    )
    machine = machines[0]
    require(
        machine.get("id") == values["EXPECTED_MACHINE_ID"]
        and machine.get("version") == values["EXPECTED_MACHINE_VERSION"]
        and machine.get("state") == "started",
        "Fly machine identity or version drift",
    )
    image_ref = machine.get("image_ref")
    config = machine.get("config")
    require(
        isinstance(image_ref, dict)
        and image_ref.get("digest") == values["EXPECTED_MACHINE_DIGEST"],
        "Fly image digest drift",
    )
    require(
        isinstance(config, dict)
        and isinstance(config.get("image"), str)
        and config["image"]
        and not re.search(r"\s", config["image"]),
        "missing Fly image reference",
    )
    freeze_ruleset_id = verify_freeze(values, runner)
    master = one_api(values["GITHUB_REPOSITORY"], "git/ref/heads/master", runner)
    require(
        master.get("ref") == "refs/heads/master"
        and isinstance(master.get("object"), dict)
        and master["object"].get("type") == "commit"
        and master["object"].get("sha") == values["EXPECTED_MASTER_SHA"],
        "remote master drift",
    )
    verify_preflight(values, preflight, machine, verifier_start, finished)
    verified_at = clock()
    require(
        verifier_start <= verified_at
        and (verified_at - verifier_start).total_seconds() <= 90
        and (verified_at - finished).total_seconds() <= 120,
        "verification exceeded quiescence freshness budget",
    )
    return {
        "status": "PASS",
        "freeze_ruleset_id": freeze_ruleset_id,
        "master_sha": values["EXPECTED_MASTER_SHA"],
        "image_digest": values["MANUAL_DIGEST"],
        "image": IMAGE + "@" + values["MANUAL_DIGEST"],
        "machine_id": machine["id"],
        "machine_version": machine["version"],
        "baseline_digest": image_ref["digest"],
        "verified_at": verified_at.isoformat(),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--producer", type=Path, required=True)
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--preflight", type=Path, required=True)
    parser.add_argument("--preflight-finished", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify(
            os.environ,
            *(
                parse_json(path.read_text())
                for path in (args.producer, args.registry, args.preflight)
            ),
            preflight_finished=args.preflight_finished.read_text().strip(),
        )
        output = os.environ.get("GITHUB_OUTPUT")
        require(isinstance(output, str) and output, "missing GitHub output destination")
        with Path(output).open("a", encoding="utf-8") as stream:
            stream.write("image_digest=" + result["image_digest"] + "\n")
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Failure, OSError, UnicodeError) as exc:
        message = (
            str(exc)
            if isinstance(exc, Failure)
            else "cannot read or write release evidence"
        )
        print(json.dumps({"status": "FAIL", "reason": message}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
