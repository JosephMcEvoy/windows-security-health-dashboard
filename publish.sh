#!/usr/bin/env bash
#
# Creates the public GitHub repo and pushes this repository to it, then turns on
# the security features that are not on by default.
#
# Run it from inside the extracted repo directory:
#     chmod +x ../publish.sh && ../publish.sh
# or from anywhere:
#     ./publish.sh /path/to/windows-security-health-dashboard
#
# Requires either the GitHub CLI (gh) already authenticated, or a GITHUB_TOKEN
# environment variable with the "repo" scope.

set -euo pipefail

REPO_DIR="${1:-$(pwd)}"
OWNER="JosephMcEvoy"
NAME="windows-security-health-dashboard"
DESC="Remote Windows security posture triage: Defender, firewall, AppLocker/WDAC, SmartScreen, identity and policy in one read-only dashboard, with fleet scanning, baseline diffing and a self-contained interactive HTML report."

cd "$REPO_DIR"
if [ ! -f src/SecurityHealthDashboard.ps1 ]; then
  echo "error: run this from the repository directory (src/SecurityHealthDashboard.ps1 not found)" >&2
  exit 1
fi

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$1"; }

# ---------------------------------------------------------------- create repo
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  say "Creating $OWNER/$NAME with the GitHub CLI"
  gh repo create "$OWNER/$NAME" --public --description "$DESC" --disable-wiki 2>/dev/null \
    || echo "    (repo already exists, continuing)"
  API() { gh api "$@"; }
else
  : "${GITHUB_TOKEN:?set GITHUB_TOKEN (needs the 'repo' scope) or install and authenticate gh}"
  say "Creating $OWNER/$NAME via the REST API"
  curl -fsS -X POST https://api.github.com/user/repos \
    -H "Authorization: Bearer $GITHUB_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -d "{\"name\":\"$NAME\",\"description\":$(printf '%s' "$DESC" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))'),\"private\":false,\"has_wiki\":false,\"has_projects\":false,\"has_issues\":true,\"allow_squash_merge\":true,\"allow_merge_commit\":false,\"allow_rebase_merge\":false,\"delete_branch_on_merge\":true}" \
    >/dev/null || echo "    (repo already exists, continuing)"
  API() {
    local method=GET path="" ; local -a extra=()
    while [ $# -gt 0 ]; do
      case "$1" in
        -X|--method) method="$2"; shift 2 ;;
        -f|-F) extra+=("$2"); shift 2 ;;
        *) path="$1"; shift ;;
      esac
    done
    local body="{}"
    if [ ${#extra[@]} -gt 0 ]; then
      body=$(python3 -c '
import json,sys
d={}
for kv in sys.argv[1:]:
    k,_,v = kv.partition("=")
    if v in ("true","false"): v = v == "true"
    elif v.isdigit(): v = int(v)
    d[k]=v
print(json.dumps(d))' "${extra[@]}")
    fi
    curl -fsS -X "$method" "https://api.github.com/$path" \
      -H "Authorization: Bearer $GITHUB_TOKEN" \
      -H "Accept: application/vnd.github+json" \
      ${body:+-d "$body"} >/dev/null
  }
fi

# ----------------------------------------------------------------------- push
say "Pushing"
git remote remove origin 2>/dev/null || true
git remote add origin "https://github.com/$OWNER/$NAME.git"
git branch -M main
git push -u origin main

# ------------------------------------------------------- security hardening
# These are off by default on a new repository.
say "Enabling Dependabot alerts and automated security fixes"
API -X PUT "repos/$OWNER/$NAME/vulnerability-alerts"      || echo "    (skipped)"
API -X PUT "repos/$OWNER/$NAME/automated-security-fixes"  || echo "    (skipped)"

say "Enabling secret scanning and push protection"
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  gh api -X PATCH "repos/$OWNER/$NAME" \
    --input - >/dev/null <<'JSON' || echo "    (skipped)"
{"security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}}
JSON
else
  curl -fsS -X PATCH "https://api.github.com/repos/$OWNER/$NAME" \
    -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" \
    -d '{"security_and_analysis":{"secret_scanning":{"status":"enabled"},"secret_scanning_push_protection":{"status":"enabled"}}}' \
    >/dev/null || echo "    (skipped)"
fi

say "Protecting main"
# Require CI to pass and a review before merge. Adjust the contexts if you
# rename jobs. Solo maintainers often drop required_approving_review_count to 0.
PROT='{
  "required_status_checks": {
    "strict": true,
    "contexts": ["Static checks","PSScriptAnalyzer","Pester (ubuntu-latest)","Pester (windows-latest)","Windows PowerShell 5.1","Read-only + credential contract"]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true
}'
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  printf '%s' "$PROT" | gh api -X PUT "repos/$OWNER/$NAME/branches/main/protection" --input - >/dev/null \
    || echo "    (skipped - branch protection needs the repo to have at least one CI run, or a paid plan for some settings)"
else
  curl -fsS -X PUT "https://api.github.com/repos/$OWNER/$NAME/branches/main/protection" \
    -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" \
    -d "$PROT" >/dev/null || echo "    (skipped)"
fi

say "Adding topics"
TOPICS='{"names":["powershell","windows","security","defender","microsoft-defender","blue-team","dfir","sysadmin","windows-security","applocker","wdac","smartscreen","incident-response","security-tools","wpf"]}'
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  printf '%s' "$TOPICS" | gh api -X PUT "repos/$OWNER/$NAME/topics" --input - >/dev/null || echo "    (skipped)"
else
  curl -fsS -X PUT "https://api.github.com/repos/$OWNER/$NAME/topics" \
    -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" \
    -d "$TOPICS" >/dev/null || echo "    (skipped)"
fi

cat <<EOF

Done.  https://github.com/$OWNER/$NAME

Still to do by hand (they need the web UI):
  1. Settings -> General -> Features: make sure Discussions is on if you want the
     "Question or idea" issue link to work.
  2. Security -> Code security: confirm private vulnerability reporting is ON.
     That is what makes the "Report a vulnerability" link in SECURITY.md work.
  3. Watch the first CI run. The Windows smoke test scans the runner itself, so
     it is the one most likely to surface something environment-specific.
  4. Tag a release when you are happy:  git tag v1.5.0 && git push origin v1.5.0

EOF
