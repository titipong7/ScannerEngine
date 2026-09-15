#!/usr/bin/env bash
#
# The one thing CI is allowed to run on the server.
#
#   bash deploy/remote-deploy.sh <full 40-char commit sha>
#
# Kept separate from deploy.sh so the CI key can be locked to *this* command in
# ~/.ssh/authorized_keys and nothing else:
#
#   command="bash ~/ScannerEngine/deploy/remote-deploy.sh",no-port-forwarding,\
#   no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA... github-actions
#
# With that in place the key cannot open a shell even if the workflow, a repo
# collaborator, or GitHub itself is compromised — it can only deploy a commit
# that already exists in origin.

set -euo pipefail

die() { printf '\033[31merror: %s\033[0m\n' "$1" >&2; exit 1; }

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The commit arrives as an argument normally, or inside SSH_ORIGINAL_COMMAND
# when the key is locked to a forced command as above.
commit="${1:-}"
if [[ -z "$commit" && -n "${SSH_ORIGINAL_COMMAND:-}" ]]; then
	read -r -a parts <<<"$SSH_ORIGINAL_COMMAND"
	commit="${parts[-1]:-}"
fi

# Validate before it reaches git. This is the only untrusted input on the box,
# and the check is what makes the forced-command path safe: anything that is not
# a bare hex sha is rejected, so there is nothing to smuggle a shell through.
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die "expected a full 40-character commit sha, got '${commit:-<empty>}'"

cd "$REPO_DIR"

echo "==> Fetching origin"
git fetch --prune origin

git cat-file -e "${commit}^{commit}" 2>/dev/null || die "commit $commit is not in this repository"

# Which branch production tracks. Override with DEPLOY_BRANCH if you deploy from
# something other than main.
BRANCH="${DEPLOY_BRANCH:-main}"
git rev-parse --verify --quiet "origin/$BRANCH" >/dev/null ||
	die "origin/$BRANCH does not exist — create it, or set DEPLOY_BRANCH to the branch you deploy from"

# Refuse a commit that is not on that branch. A push to any other ref, or a
# rewritten history, must not become production.
if ! git merge-base --is-ancestor "$commit" "origin/$BRANCH"; then
	die "commit $commit is not an ancestor of origin/$BRANCH — refusing to deploy it"
fi

echo "==> Checking out $commit"
git checkout "$BRANCH" --quiet 2>/dev/null || git checkout -B "$BRANCH" "origin/$BRANCH" --quiet
git reset --hard "$commit" --quiet
git --no-pager log -1 --oneline

exec bash deploy/deploy.sh --no-pull
