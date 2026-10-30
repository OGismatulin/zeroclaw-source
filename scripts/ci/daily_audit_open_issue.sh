set -euo pipefail

issues_enabled=$(gh api "repos/$GITHUB_REPOSITORY" --jq '.has_issues')
case "$issues_enabled" in
  true) ;;
  false)
    echo "issue_url=" >> "$GITHUB_OUTPUT"
    echo "::notice::Repository issues are disabled; skipping advisory issue creation."
    exit 0
    ;;
  *)
    echo "::error::Unable to verify whether repository issues are enabled." >&2
    exit 1
    ;;
esac

issues_json=$(gh api --paginate "repos/$GITHUB_REPOSITORY/issues?state=open&per_page=100" --slurp)
issue_url=$(printf '%s' "$issues_json" | python3 -c '
import json
import sys

try:
    pages = json.load(sys.stdin)
    if not isinstance(pages, list) or not pages:
        raise ValueError("expected a nonempty list of issue pages")
    matches = []
    for page in pages:
        if not isinstance(page, list):
            raise ValueError("expected an array for each issue page")
        for issue in page:
            if (
                not isinstance(issue, dict)
                or not isinstance(issue.get("title"), str)
                or not isinstance(issue.get("user"), dict)
                or not isinstance(issue["user"].get("login"), str)
                or not isinstance(issue.get("html_url"), str)
                or not issue["html_url"]
            ):
                raise ValueError("unexpected issue response shape")
            if (
                "pull_request" not in issue
                and issue["user"]["login"] == "github-actions[bot]"
                and issue["title"].startswith("ci: Advisory scan failed — ")
            ):
                matches.append(issue["html_url"])
    if matches:
        print(matches[0])
except (ValueError, TypeError) as error:
    print(f"::error::Unable to parse repository issues: {error}", file=sys.stderr)
    sys.exit(1)
')

if [[ -n "$issue_url" ]]; then
  echo "issue_url=$issue_url" >> "$GITHUB_OUTPUT"
  echo "An open advisory issue already exists — skipping duplicate."
  exit 0
fi

advisory_output=$(cat "${ADVISORY_OUTPUT:-/tmp/advisory-output.txt}")
issue_body=${ISSUE_BODY:-/tmp/issue-body.md}

{
  printf '## Advisory scan failed\n\n'
  printf 'Workflow run: %s\n\n' "${RUN_URL}"
  printf '```\n%s\n```\n\n' "${advisory_output}"
  printf 'Review `deny.toml` for the current ignore list. If this advisory is a known\n'
  printf 'acceptable risk, add an entry with a `reason` field. If it requires a\n'
  printf 'dependency update, open a tracking issue and link it here.\n\n'
  if [[ "$GITHUB_REPOSITORY" == "zeroclaw-labs/zeroclaw" ]]; then
    printf 'cc @JordanTheJet @Audacity88\n'
  fi
} > "$issue_body"

issue_url=$(gh issue create \
  --repo "$GITHUB_REPOSITORY" \
  --title "ci: Advisory scan failed — $(date -u +%Y-%m-%d)" \
  --body-file "$issue_body")
echo "issue_url=$issue_url" >> "$GITHUB_OUTPUT"
