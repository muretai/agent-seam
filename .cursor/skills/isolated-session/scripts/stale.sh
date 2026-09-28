#!/usr/bin/env bash
# The inventory this repo never had: what is still unlanded, and how old it is.
#
# The isolated-session rule has always said "do not leave an unmerged feat/*
# branch". Prose alone let fifteen branches, sixteen worktrees and twenty-two
# draft PRs accumulate, because nothing ever put the list in front of anyone.
# This script is that list. Exit 1 means something is past the deadline: land it
# or retire it today. Holding is not one of the options.
set -euo pipefail

days="${ISOLATED_SESSION_STALE_DAYS:-7}"
now="$(date +%s)"
problems=0

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "not a git repository" >&2
  exit 2
fi

common_git="$(cd "$(git rev-parse --git-common-dir)" && pwd)"
primary="$(dirname "$common_git")"
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/lib.sh"

if git symbolic-ref --quiet refs/remotes/origin/HEAD >/dev/null 2>&1; then
  base="$(git symbolic-ref --short refs/remotes/origin/HEAD | sed 's#^origin/##')"
else
  base="main"
fi
if ! git show-ref --verify --quiet "refs/heads/${base}"; then
  if git show-ref --verify --quiet "refs/heads/master"; then
    base="master"
  fi
fi

worktree_for_branch() {
  local want="refs/heads/$1"
  local wt=""
  while IFS= read -r line; do
    case "$line" in
      worktree\ *) wt="${line#worktree }" ;;
      branch\ *)
        if [[ "${line#branch }" == "$want" ]]; then
          printf '%s\n' "$wt"
          return 0
        fi
        ;;
    esac
  done < <(git -C "$primary" worktree list --porcelain)
  return 1
}

echo "== unlanded branches (base ${base}, deadline ${days}d) =="
while IFS=$'\t' read -r branch ts; do
  [[ "$branch" == "$base" || "$branch" == "master" || "$branch" == "develop" ]] && continue
  if git merge-base --is-ancestor "$branch" "$base" 2>/dev/null; then
    continue
  fi
  age=$(( (now - ts) / 86400 ))
  commits="$(git rev-list --count "${base}..${branch}" 2>/dev/null || echo '?')"
  wt="$(worktree_for_branch "$branch" || true)"
  note=""
  if [[ -n "$wt" ]]; then
    dirty="$(git -C "$wt" status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
    note="  worktree=${wt}"
    if [[ "$dirty" != "0" ]]; then
      note="${note} DIRTY(${dirty})"
    fi
  fi
  flag="   "
  if (( age > days )); then
    flag="!! "
    problems=$(( problems + 1 ))
  fi
  printf '%s%-48s %3dd  %s commits%s\n' "$flag" "$branch" "$age" "$commits" "$note"
done < <(git for-each-ref --format='%(refname:short)%09%(committerdate:unix)' refs/heads)

echo
echo "== worktrees with uncommitted work (look here BEFORE retiring anything) =="
found_dirty=0
while IFS= read -r wt; do
  dirty="$(git -C "$wt" status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "$dirty" != "0" ]]; then
    head="$(git -C "$wt" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
    printf '   %-70s %-40s %s file(s)\n' "$wt" "$head" "$dirty"
    found_dirty=1
  fi
done < <(git -C "$primary" worktree list --porcelain | awk '/^worktree /{print $2}')
[[ "$found_dirty" == "0" ]] && echo "   (none)"

# Who holds which folder right now. A GONE owner is a session that ended without
# finishing: ensure-worktree.sh takes such a folder over, finish-worktree.sh lands it.
echo
echo "== open sessions (one live owner per folder) =="
iso_sessions_report "$primary"

echo
echo "== open pull requests (deadline ${days}d) =="
if ! command -v gh >/dev/null 2>&1; then
  echo "   (gh not installed -- PR queue not checked)"
elif ! pr_json="$(gh pr list --state open --limit 100 --json number,title,isDraft,updatedAt 2>/dev/null)" ||
     [[ -z "$pr_json" ]]; then
  echo "   (gh could not list PRs -- not authenticated, or no remote)"
else
  # The python half prints the rows, then a final __STALE__=<n> line that bash
  # strips off. Counting through a marker line keeps stdout as the only channel.
  # The JSON travels in the environment, not on stdin: "python3 -" reads its
  # PROGRAM from stdin, so a heredoc leaves nothing there for json.load.
  pr_out="$(ISOLATED_SESSION_STALE_DAYS="$days" ISOLATED_SESSION_PR_JSON="$pr_json" python3 - <<'PYEOF'
import datetime, json, os

limit = int(os.environ.get("ISOLATED_SESSION_STALE_DAYS", "7"))
rows = json.loads(os.environ.get("ISOLATED_SESSION_PR_JSON") or "[]")
now = datetime.datetime.now(datetime.timezone.utc)
stale = 0
if not rows:
    print("   (none)")
for r in sorted(rows, key=lambda r: r["updatedAt"]):
    updated = datetime.datetime.fromisoformat(r["updatedAt"].replace("Z", "+00:00"))
    age = (now - updated).days
    kind = "DRAFT" if r["isDraft"] else "ready"
    flag = "   "
    if age > limit:
        flag = "!! "
        stale += 1
    print(f"{flag}#{r['number']:<5} {age:3d}d  {kind}  {r['title'][:70]}")
drafts = sum(1 for r in rows if r["isDraft"])
if drafts:
    print(f"   note: {drafts} of {len(rows)} open PRs are DRAFT -- the skill forbids")
    print("   a draft PR as a substitute for landing the work")
print(f"__STALE__={stale}")
PYEOF
)"
  printf '%s\n' "$pr_out" | grep -v '^__STALE__=' || true
  pr_stale="$(printf '%s' "$pr_out" | sed -n 's/^__STALE__=//p' | tail -1)"
  if [[ -n "${pr_stale:-}" && "$pr_stale" != "0" ]]; then
    problems=$(( problems + pr_stale ))
  fi
fi

echo
if (( problems > 0 )); then
  echo "${problems} item(s) past the ${days}-day deadline. Land each one, or retire it:"
  echo "  git tag archive/<branch> <branch> && git branch -D <branch>   # history is kept"
  exit 1
fi
echo "nothing past the ${days}-day deadline."
