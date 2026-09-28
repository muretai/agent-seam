#!/usr/bin/env bash
# Take a session worktree that nobody live holds -- the one this chat opened directly,
# or one a killed session left behind. It never takes a folder from a live session.
#   claim-worktree.sh [worktree-path]     (default: the current directory)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/lib.sh"

root="$(cd "${1:-.}" && pwd)"
wt="$(iso_worktree_of "$root")" || { echo "not a git repository: ${root}" >&2; exit 1; }
if ! iso_is_linked "$wt"; then
  echo "refusing: ${wt} is the primary checkout, never a session folder -- run ensure-worktree.sh" >&2
  exit 1
fi
branch="$(git -C "$wt" rev-parse --abbrev-ref HEAD)"
kind="$(iso_kind_of_branch "$branch")"
owner="$(iso_owner)"
claimed="yes"
case "$(iso_lock_state "$wt" "$owner")" in
  mine) claimed="already"; iso_lock_touch "$wt" "$owner" ;;
  free) iso_lock_write "$wt" "$owner" "$kind" "$branch" "(claimed in place)" ;;
  dead)
    echo "note: taking over from a session that is gone ($(iso_lock_describe "$wt"))" >&2
    iso_lock_write "$wt" "$owner" "$kind" "$branch" "(claimed in place)"
    ;;
  other)
    if [[ "${ISOLATED_SESSION_TAKEOVER:-0}" == "1" ]]; then
      echo "warning: evicting a live session from ${wt}: $(iso_lock_describe "$wt")" >&2
      iso_lock_write "$wt" "$owner" "$kind" "$branch" "(claimed in place)"
    else
      { echo "refusing: ${wt} is held by another live session: $(iso_lock_describe "$wt")"
        iso_lock_fix_hint "$wt" "$owner"; } >&2
      exit 1
    fi
    ;;
esac
echo "WORKTREE=${wt}"
echo "BRANCH=${branch}"
echo "KIND=${kind}"
echo "OWNER=${owner}"
echo "OWNER_KIND=$(iso_owner_kind "$owner")"
echo "CLAIMED=${claimed}"
echo "PREPUSH=$(iso_prepush_line "$wt")"
