#!/usr/bin/env bash
# Open (or re-enter) this session's worktree, and take the folder for this session.
#   ensure-worktree.sh "<task>"            a dev session: branch feat/<slug>
#   ensure-worktree.sh --design "<task>"   a design session: branch design/<slug>,
#                                          only in a repository with .cursor/design-paths
#   ensure-worktree.sh --at <sha> --into <dir> "<task>"
#                                          the same branch feat/<slug>, made AT A COMMIT
#                                          rather than at the tip of a base branch, in
#                                          <dir>, with the same lock and no-push hook
#                                          (lib.sh, iso_open_at). The primary-parked and
#                                          diverged-base gates are about where a NEW
#                                          session starts from, and do not apply to a
#                                          commit named outright. The reviewer spawn sites
#                                          open a reviewer's receipt branch the same way.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/lib.sh"

kind="dev"
at=""
into=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --design) kind="design"; shift ;;
    --at) [[ $# -ge 2 ]] || { echo "ensure-worktree: --at needs a commit" >&2; exit 2; }; at="$2"; shift 2 ;;
    --into) [[ $# -ge 2 ]] || { echo "ensure-worktree: --into needs a directory" >&2; exit 2; }; into="$2"; shift 2 ;;
    *) break ;;
  esac
done
task="${1:-}"
if [[ -z "$task" ]]; then
  echo "usage: ensure-worktree.sh [--design] \"<task>\" [base-branch]" >&2
  echo "       ensure-worktree.sh --at <sha> --into <dir> \"<task>\"" >&2
  exit 2
fi
if [[ -n "$at" || -n "$into" ]]; then
  if [[ -z "$at" || -z "$into" || "$kind" == "design" ]]; then
    echo "ensure-worktree: --at and --into go together, and not with --design" >&2
    exit 2
  fi
  [[ "$into" == /* ]] || into="$(pwd)/${into}"
fi
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "not a git repository" >&2
  exit 1
fi
# The slug carries a hash of the WHOLE task string, so two different tasks
# whose first 32 characters happen to agree cannot land on one branch. It stays
# deterministic, so re-running with the same task resumes the same worktree
# (lib.sh, iso_task_slug).
slug="$(iso_task_slug "$task")"
common_git="$(cd "$(git rev-parse --git-common-dir)" && pwd)"
primary="$(dirname "$common_git")"
repo="$(basename "$primary")"
if [[ -n "${2:-}" ]]; then
  base="$2"
elif git symbolic-ref --quiet refs/remotes/origin/HEAD >/dev/null 2>&1; then
  base="$(git symbolic-ref --short refs/remotes/origin/HEAD | sed 's#^origin/##')"
else
  base="main"
fi
prefix="feat"
[[ "$kind" == "design" ]] && prefix="design"
branch="${prefix}/${slug}"
worktree_root="${PARALLEL_WORKTREE_ROOT:-$primary/.worktrees}"
worktree="${worktree_root}/${slug}"
if [[ -n "$at" ]]; then
  worktree="$into"
fi

# A design session needs a repository that says which paths design owns. Without
# that list there is nothing to keep the two kinds apart, so the session does not
# open here: it opens in the repository that holds the design.
if [[ "$kind" == "design" && ! -f "$(iso_design_paths_file "$primary")" ]]; then
  {
    echo "refusing to start a design session: ${primary} declares no design paths"
    echo "  (no $(iso_design_paths_file "$primary"))"
    echo "Design work happens in the repository that owns the design -- the one whose"
    echo ".cursor/design-paths names the files you mean to change. Open the session there."
  } >&2
  exit 1
fi

owner="$(iso_owner)"
owner_kind="$(iso_owner_kind "$owner")"
if [[ "$owner_kind" == "cursor" ]] && iso_is_pid "$owner"; then
  {
    echo "note: this shell's owner is the Cursor window process (pid ${owner}), which every"
    echo "  Cursor Agent chat in the window shares. If the sessionStart context named a key,"
    echo "  export ISOLATED_SESSION_OWNER=cursor:<conversation_id> first, so two chats stay two."
  } >&2
fi

# This session takes the folder, or the script stops. One live owner per folder is
# the whole point: a second chat in the same worktree does not get a warning, it
# gets a refusal that names the first.
claim_lock() {
  local wt="$1"
  case "$(iso_lock_state "$wt" "$owner")" in
    mine) iso_lock_touch "$wt" "$owner" ;;
    free)
      iso_lock_write "$wt" "$owner" "$kind" "$branch" "$task"
      ;;
    dead)
      echo "note: ${wt} was held by a session that is gone ($(iso_lock_describe "$wt")); taking it over" >&2
      iso_lock_write "$wt" "$owner" "$kind" "$branch" "$task"
      ;;
    other)
      if [[ "${ISOLATED_SESSION_TAKEOVER:-0}" == "1" ]]; then
        echo "warning: evicting a live session from ${wt}: $(iso_lock_describe "$wt")" >&2
        iso_lock_write "$wt" "$owner" "$kind" "$branch" "$task"
      else
        {
          echo "refusing to start: ${wt} is open in another live session"
          echo "  $(iso_lock_describe "$wt")"
          echo "Two chats must not share a folder. Word this task differently to get a"
          echo "worktree of its own, or finish that session first."
          echo "ISOLATED_SESSION_TAKEOVER=1 evicts it -- only when that session is yours and idle."
          iso_lock_fix_hint "$wt" "$owner"
        } >&2
        exit 1
      fi
      ;;
  esac
}

report() {  # $1 worktree, $2 created
  echo "WORKTREE=$1"
  echo "BRANCH=${branch}"
  echo "BASE=${base}"
  echo "KIND=${kind}"
  echo "OWNER=${owner}"
  echo "OWNER_KIND=${owner_kind}"
  echo "CREATED=$2"
  echo "REPO=${repo}"
  # the no-push hook: installed (or confirmed) every time a session opens here; asked
  # from the worktree, so a worktree-scoped core.hooksPath is named too
  echo "PREPUSH=$(iso_prepush_line "$1")"
}

git_dir="$(git rev-parse --git-dir)"
toplevel="$(git rev-parse --show-toplevel)"
in_linked=0
if [[ -f "${toplevel}/.git" ]] || [[ "$git_dir" == *"/worktrees/"* ]]; then
  in_linked=1
fi
current_branch="$(git rev-parse --abbrev-ref HEAD)"
# (a checkout --at a commit is always made fresh: re-entering one could hand back a
# branch that has moved past the commit asked for)
if [[ -z "$at" && "$in_linked" == "1" && "$current_branch" == "$branch" ]]; then
  claim_lock "$toplevel"
  report "$toplevel" no
  exit 0
fi
if [[ -z "$at" ]] && [[ -d "$worktree/.git" || -f "$worktree/.git" ]]; then
  existing_branch="$(git -C "$worktree" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
  if [[ "$existing_branch" == "$branch" ]]; then
    claim_lock "$worktree"
    report "$worktree" no
    exit 0
  fi
fi
if git worktree list --porcelain | awk '/^branch / { print $2 }' | grep -qx "refs/heads/${branch}"; then
  echo "branch ${branch} is already checked out in another worktree" >&2
  git worktree list >&2
  exit 1
fi
if [[ -n "$at" ]]; then
  base="$(git rev-parse --verify --quiet "${at}^{commit}")" || {
    echo "ensure-worktree: --at ${at} is not a commit in ${primary}" >&2
    exit 2
  }
  iso_open_at "$primary" "$worktree" "$branch" "$base" "$owner" "$task" >/dev/null || exit 1
  report "$worktree" yes
  exit 0
fi
force="${ISOLATED_SESSION_FORCE:-0}"

# Gate 1: the primary checkout must be parked on BASE.
# A session branch that lives in the primary checkout stops being a session and
# becomes a second, permanent trunk -- which is how a four-day, multi-topic
# branch accumulated there without anyone noticing.
primary_head="$(git -C "$primary" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")"
if [[ "$primary_head" != "$base" && "$force" != "1" ]]; then
  {
    echo "refusing to start: the primary checkout is on ${primary_head}, not ${base}"
    echo "  ${primary}"
    echo "Land or park that branch first, then run this script again:"
    echo "  git -C '${primary}' switch ${base}"
    echo "Override with ISOLATED_SESSION_FORCE=1 only if you own that branch."
  } >&2
  exit 1
fi

mkdir -p "$worktree_root"
if git remote get-url origin >/dev/null 2>&1; then
  git fetch origin --quiet || true
fi
start_ref="$base"
remote_base="origin/${base}"
if git rev-parse --verify --quiet "$remote_base" >/dev/null; then
  if git show-ref --verify --quiet "refs/heads/${base}"; then
    if git merge-base --is-ancestor "$remote_base" "$base"; then
      start_ref="$base"
    elif git merge-base --is-ancestor "$base" "$remote_base"; then
      start_ref="$remote_base"
    elif [[ "$force" == "1" ]]; then
      echo "warning: ${base} and ${remote_base} have diverged; forced start from local ${base}" >&2
      start_ref="$base"
    else
      # Gate 2: a diverged BASE is a stop, not a warning. Branching from the
      # local side while the remote side moves is the machine that produces two
      # trunks; every session that scrolls past the warning widens the gap.
      ahead="$(git rev-list --count "${remote_base}..${base}")"
      behind="$(git rev-list --count "${base}..${remote_base}")"
      {
        echo "refusing to start: ${base} and ${remote_base} have diverged"
        echo "  ${base} is ${ahead} commit(s) ahead of and ${behind} behind ${remote_base}"
        echo "Reconcile the two before opening new sessions on top of them."
        echo "Override with ISOLATED_SESSION_FORCE=1 (the session doing the reconcile)."
      } >&2
      exit 1
    fi
  else
    start_ref="$remote_base"
  fi
fi
if git show-ref --verify --quiet "refs/heads/${branch}"; then
  # The branch exists but nothing has it checked out -- a killed session, or a
  # task whose slug collided. Resuming is usually right, but it has to be a
  # decision rather than a default.
  if [[ "${ISOLATED_SESSION_RESUME:-0}" != "1" ]]; then
    {
      echo "refusing to start: branch ${branch} already exists with no worktree"
      echo "  last commit: $(git log -1 --format='%cs %h %s' "$branch")"
      echo "Resume it with ISOLATED_SESSION_RESUME=1, or retire it:"
      echo "  git tag archive/${branch} ${branch} && git branch -D ${branch}"
    } >&2
    exit 1
  fi
  git worktree add "$worktree" "$branch"
else
  git worktree add --no-track -b "$branch" "$worktree" "$start_ref"
fi
claim_lock "$worktree"
report "$worktree" yes
