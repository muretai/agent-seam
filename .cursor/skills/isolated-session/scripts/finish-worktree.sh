#!/usr/bin/env bash
# Land this session's branch on BASE and remove the worktree (its lock goes with it).
# Must be run only when the user's task is actually done. Never pushes BASE.
#
# The landing is the one serial section of parallel work, so it is short and it is
# ordered: take the landing lock (one landing at a time per primary) -> fast-forward
# local BASE from origin/BASE, so the landing descends from what the other primary
# published (diverged: refuse) -> bring the branch onto that BASE (rebase; merge when
# the branch is already on origin) ->
# refuse a branch that edited a generated file -> run the tests the diff owes
# (tools/run_tests.py --affected) -> scan the diff (tools/sec_lint.py: a refusal stops
# the landing like a red test; needs-eyes lands and owes a reviewer) -> regenerate the
# ledgers on the tip (tools/ledger.py build) -> fast-forward BASE -> release, remove,
# delete -> when the scan said needs-eyes, spawn the reviewer session through herdr
# (scripts/herd-spawn.sh; never blocking, never failing the landing).
# A repository without those tools (a pinned copy of this skill) lands as before and
# says TESTS=none / SEC=none / LEDGER=none / REVIEW=none in the receipt.
# A landing its tests refused says MERGED=no with TESTS=, TESTS_RED= (the diff's own
# reds), TESTS_COULD_NOT_RUN= (suites the room refused -- a landing behind a wall), and
# TESTS_REFUSAL=environment|red: `environment` when only the room refused, `red` when any
# ordinary red is present. The two lists are disjoint.
#
# The guards are BASE's, never the branch's. The branch's TESTS run by design; the gate
# does not: this script re-runs itself from BASE's copy of this skill and of the gate
# tools before it sources anything (see "the code that judges a landing is BASE's"
# below), and the lint, the reviewer's brief and the spawner are read out of BASE's blobs
# (`git show BASE:path`), so a branch that rewrites any of them is judged by the copies
# main already had. And a diff that touches a gate file at all (the lint,
# the ledger, the runner, these scripts, the briefs, the hook configs) is needs-eyes
# whatever the lint said -- this script decides that itself, from the paths, because
# the lint is one of the files on that list.
set -euo pipefail

# Scratch files: an unpredictable name under TMPDIR, never /tmp/<name>-$$ (a planted
# symlink there would be followed as the operator).
finish_tmp() {
  mktemp "${TMPDIR:-/tmp}/finish-XXXXXX"
}

# The branch's code runs three times before the merge -- the ledger check, the tests,
# the ledger build (which imports the selector, the spec builder and the projector from
# the branch) -- and none of it may reach a push credential: git's helpers cleared, no
# terminal prompt, ssh disabled, gh pointed at an empty config (the keychain token is
# reached through hosts.yml, which is not there). A test that pushes to a local bare
# remote needs none of these (ISSUE(security-audit-2026-09-12-a-pre-push-hook-makes-the),
# ISSUE(security-audit-2026-09-12-the-wall-is-honest-about-3)).
#
# PYTHONNOUSERSITE is part of it for the same reason and one level down: a branch's own
# test run can write `usercustomize.py` into the USER SITE directory, which is outside the
# checkout -- so `git status --porcelain` after the tests stays green, the lint never sees
# it and no reviewer opens it -- and every later plain `python3` imports it at start-up. It
# reached the gate itself: the scan, the gate-file probe, the ledger build and the brief
# render are all `python3` (ISSUE(security-audit-2026-09-18-daily-2026-09-18-3)). The
# guards were BASE's for the FILE and not for the INTERPRETER that ran it.
#
# `credless` itself now lives in lib.sh, sourced below, because the daily engine and the
# weekly clock need the identical wall and two copies are how one of them goes stale
# (ISSUE(security-audit-2026-09-18-daily-2026-09-18-7)). It is ARMED once, at top level,
# right after the source: a `credless` called inside a `$( )` would otherwise make its own
# empty gh directory per call.

# EVERY python the landing runs on BASE's behalf goes through here, and none any other
# way -- and so does the SPAWNER, which runs pythons of its own: the generated-file check,
# the tests harness, the two summaries, BASE's lint and its gate-file table, the ledger
# build, the reviewer's brief, and herd-spawn.sh's re-render of that brief and its
# permission list. `-I` is isolated mode -- no user site directory (so the hook above is
# never imported) and no PYTHON* variable read -- and `credless` is the credential wall
# these already had. The branch's TESTS still run however they run; this is the GATE's
# interpreter, which is a different thing.
# `tests/test_gate_pythons_are_isolated.py` holds this paragraph to its word: it greps
# every `python3` a landing or the daily job can reach and fails on a bare one.
#
# `-I` also keeps the caller's directory off sys.path. Nothing here depends on that
# prepend: tools/ledger.py, tools/run_tests.py and tools/sec_lint.py each insert their own
# tools/ directory themselves, and the heredocs below import stdlib only.
landing_python() {
  credless python3 -I "$@"
}

# ... and the one python here that is NOT the gate's: the harness that runs THE BRANCH'S
# TESTS, and every child IT spawns. `-I` is per-process and reaches no child, so the wall a
# child gets is the ENVIRONMENT it inherits -- `tools/run_tests.py` spawns one process per
# test file with `dict(os.environ)` and takes that file's ok-or-fail from its exit code
# alone.
#
# This used to read `credless PYTHONNOUSERSITE= python3 -I`: the empty assignment was one
# more `NAME=VALUE` on credless's own `env` line and the LAST one won, and CPython reads an
# empty flag variable as not set at all. So the user site directory was ENABLED for every
# child, and one branch test writing `usercustomize.py` with
# `atexit.register(lambda: os._exit(0))` turned every later affected test green -- for
# every later landing by any session, from a file outside every checkout a guard here looks
# at (ISSUE(security-audit-2026-09-18-daily-2026-09-18-10)).
#
# The trade that clearing was made for is real and is still paid, by a different route.
# `cryptography` -- the relay/E2E layer's X25519 and ChaCha20-Poly1305, optional by
# CLAUDE.md principle 1 -- lives ONLY in `~/Library/Python/3.9/.../site-packages` on this
# machine, and without it `tests/test_dispatch_take.py` falls to the pure-Python Ed25519
# backend and times out on its ack deadline. So the wall goes back on
# (`PYTHONNOUSERSITE=1`). The directory travels in its own variable, not PYTHONPATH:
# the runner appends it AFTER interpreter startup and the stdlib. Neither a planted
# json.py nor startup customization in that directory runs ahead of the shim.
# The directory is still the operator's: a poisoned importable module planted there
# is still imported by later landings. ISSUE(the-lent-backend-is-the-operators)
# closes only with a pinned copy of the backend that belongs to the landing.
branch_tests_python() {
  credless PYTHONNOUSERSITE=1 MURETAI_TEST_BACKEND_PATH="${branch_tests_backend_path-}" python3 -I "$@"
}

# The files whose change is judged by eyes whatever the lint said: they decide what a
# landing runs, what it scans, who reviews it, and what a session may edit.
# The comparison folds case: the dev host's filesystem is case-insensitive (APFS,
# core.ignorecase=true), so `git mv tools/spec_build.py tools/Spec_build.py` is a path
# git lists as new and the OS opens as the old one -- `ledger.py build` would run the
# renamed file under its canonical name while a case-exact list called it not a gate
# (ISSUE(security-audit-2026-09-12-the-scanner-ignores-diff-2)). `tr`, not `${1,,}`:
# bash 3.2.
# The gate list -- the paths whose change is needs-eyes whatever the lint said -- is
# BASE's lint's own table (`tools/sec_lint.py --gate-files`), not a table of this
# script's: two tables kept in step by hand missed the weekly clock and the skill's
# SKILL.md (ISSUE(gate-lists-are-two-lists), ISSUE(security-audit-2026-09-12-a-type-change-is-con-02ca)).

branch="${1:-}"
worktree="${2:-}"
if [[ -z "$branch" || -z "$worktree" ]]; then
  echo "usage: finish-worktree.sh <branch> <worktree-path>" >&2
  exit 2
fi
if [[ ! -d "$worktree" ]]; then
  echo "worktree not found: ${worktree}" >&2
  exit 1
fi
worktree="$(cd "$worktree" && pwd)"
here="$(cd "$(dirname "$0")" && pwd)"

# --- the code that judges a landing is BASE's: re-run from BASE's own copy ----------
# Everything below this block -- lib.sh, assert-head.sh, the landing lease
# (landing-lease.sh/.py), the test runner, the ledger, the lint -- used to be taken from
# wherever THIS file was started, which is the branch's own tree whenever the operator ran
# the worktree's copy. So a branch cut before a gate fix ran the OLD gate (2026-09-22:
# three landings after 1596abac ran the old landing-lease.py and refused, "relay is not
# reachable"), and a branch that rewrote its own runner merged with a red test
# (ISSUE(finish-worktree-runs-the-worktree-s-own-lease-code)).
#
# So before anything is sourced, BASE's copy of this skill's scripts directory and of the
# gate tools is written out of BASE's BLOBS (`git cat-file blob`, regular files only -- a
# symlink at a gate path is never followed, in BASE, in the branch or in the primary's
# working tree) into a private directory (mktemp -d, mode 700), and THAT copy of this file
# is run with the same arguments. The directory lives until this process exits, so the
# lease release, the ledger and the review spawn after the fast-forward -- which moves the
# primary's working tree to the branch's code -- still run BASE's copy. Always the blobs,
# never the primary's working tree: a blob cannot be edited under us or swapped for a link.
#
# The one shape that stays open: an operator who runs a branch's EDITED copy of this file
# has handed the branch control before this block exists
# (ISSUE(branch-edited-finish-is-trusted-when-run-directly)); the documented call is the
# primary's copy, by absolute path.
#
# A copy of this file that lives OUTSIDE the repository being landed (a vendored skill
# driving another repository, a test harness) is nothing the branch wrote: when BASE
# carries no finish-worktree.sh of its own, that copy runs, still with BASE's tools. A copy
# INSIDE the repository with no BASE copy to hand over to is refused.
gate_scripts_rel=".cursor/skills/isolated-session/scripts"
gate_tools="tools/run_tests.py tools/affected_tests.py tools/sec_lint.py tools/audit_scope.py
            tools/ledger.py tools/backlog_build.py tools/spec_build.py company/ops/backlog_to_core.py"
here_real="$(cd "$here" && pwd -P)"
gate_dir=""
if [[ -n "${ISO_FINISH_GATE_DIR:-}" && "${ISO_FINISH_GATE_SELF:-}" == "$here_real" &&
      -d "${ISO_FINISH_GATE_DIR}" && ! -L "${ISO_FINISH_GATE_DIR}" && -O "${ISO_FINISH_GATE_DIR}" ]]; then
  gate_dir="$ISO_FINISH_GATE_DIR"
fi
gate_from_base="${ISO_FINISH_GATE_FROM:-}"
# never inherited: a test this landing runs starts its own finish, which gates itself
unset ISO_FINISH_GATE_DIR ISO_FINISH_GATE_SELF ISO_FINISH_GATE_FROM
if [[ -z "$gate_dir" ]]; then
  # One stderr line, before any lock, lease or ref is touched.
  gate_refuse() {
    echo "refusing to land ${branch}: $1; nothing moved." >&2
    exit 1
  }
  g_common="$(git -C "$worktree" rev-parse --git-common-dir 2>/dev/null)" ||
    gate_refuse "${worktree} is not a git checkout, so there is no BASE to take the gate code from"
  [[ "$g_common" == /* ]] || g_common="${worktree}/${g_common}"
  g_common="$(cd "$g_common" 2>/dev/null && pwd -P)" ||
    gate_refuse "could not resolve the git directory of ${worktree}"
  if git -C "$worktree" symbolic-ref --quiet refs/remotes/origin/HEAD >/dev/null 2>&1; then
    g_base="$(git -C "$worktree" symbolic-ref --short refs/remotes/origin/HEAD 2>/dev/null | sed 's#^origin/##')"
  else
    g_base="main"
  fi
  if ! git -C "$worktree" show-ref --verify --quiet "refs/heads/${g_base}" 2>/dev/null &&
     git -C "$worktree" show-ref --verify --quiet "refs/heads/master" 2>/dev/null; then
    g_base="master"
  fi
  g_sha="$(git -C "$worktree" rev-parse --verify --quiet "refs/heads/${g_base}^{commit}" 2>/dev/null)" ||
    gate_refuse "there is no branch ${g_base} in $(dirname "$g_common") to take the gate code from"
  # is the copy that was started part of the repository being landed?
  g_here_common="$(git -C "$here_real" rev-parse --git-common-dir 2>/dev/null || true)"
  g_here_inside="no"
  if [[ -n "$g_here_common" ]]; then
    [[ "$g_here_common" == /* ]] || g_here_common="${here_real}/${g_here_common}"
    g_here_common="$(cd "$g_here_common" 2>/dev/null && pwd -P || true)"
    if [[ "$g_here_common" == "$g_common" ]]; then
      g_here_inside="yes"
    fi
  fi
  g_dir="$(mktemp -d "${TMPDIR:-/tmp}/finish-gate-XXXXXX" 2>/dev/null)" ||
    gate_refuse "could not create a private directory for ${g_base}'s gate code under ${TMPDIR:-/tmp}"
  trap 'rm -rf "$g_dir"' EXIT
  chmod 700 "$g_dir" 2>/dev/null || gate_refuse "could not make ${g_dir} private"
  g_real="$(cd "$g_dir" && pwd -P)"
  # One path out of BASE's tree: 0 written, 1 not in BASE as a regular file, 2 failed.
  gate_put() {  # $1 path relative to the top of the tree
    local rec="" meta="" mode=""
    rec="$(git -C "$worktree" ls-tree --full-tree "$g_sha" -- "$1" 2>/dev/null)" || return 2
    [[ -n "$rec" && "${rec#*$'\t'}" == "$1" ]] || return 1
    meta="${rec%%$'\t'*}"
    mode="${meta%% *}"
    case "$mode" in
      100644|100755) ;;
      *) return 1 ;;
    esac
    mkdir -p "${g_dir}/$(dirname "$1")" 2>/dev/null || return 2
    git -C "$worktree" cat-file blob "${meta##* }" > "${g_dir}/$1" 2>/dev/null || return 2
    chmod 700 "${g_dir}/$1" 2>/dev/null || return 2
  }
  g_names="$(git -C "$worktree" ls-tree --full-tree --name-only "$g_sha" -- "${gate_scripts_rel}/" 2>/dev/null)" ||
    gate_refuse "could not list ${gate_scripts_rel} in ${g_base}"
  for g_path in $g_names $gate_tools; do
    case "$g_path" in
      *[!A-Za-z0-9._/-]*) continue ;;       # a name this block would have to quote: not ours
    esac
    g_rc=0
    gate_put "$g_path" || g_rc=$?
    [[ "$g_rc" != "2" ]] || gate_refuse "could not write ${g_base}:${g_path} into ${g_dir}"
  done
  if [[ -f "${g_dir}/${gate_scripts_rel}/finish-worktree.sh" && -f "${g_dir}/${gate_scripts_rel}/lib.sh" ]]; then
    g_run="${g_dir}/${gate_scripts_rel}/finish-worktree.sh"
    g_self="${g_real}/${gate_scripts_rel}"
    g_from="${g_base}@${g_sha}"
  elif [[ "$g_here_inside" == "yes" ]]; then
    gate_refuse "${g_base} carries no ${gate_scripts_rel}/finish-worktree.sh and lib.sh as regular files, and the copy started (${here}) belongs to the repository being landed; run a copy of the skill from outside it"
  else
    g_run="${here_real}/$(basename "$0")"
    g_self="$here_real"
    g_from=""
  fi
  set +e
  ISO_FINISH_GATE_DIR="$g_dir" ISO_FINISH_GATE_SELF="$g_self" ISO_FINISH_GATE_FROM="$g_from" \
    bash "$g_run" "$@"
  g_rc=$?
  set -e
  rm -rf "$g_dir"
  trap - EXIT
  exit "$g_rc"
fi
# From here on this is the gate's own run: `here` is BASE's scripts directory (or the
# outside copy above), and every gate tool comes from gate_dir -- never the worktree's.
gate_runner="${gate_dir}/tools/run_tests.py"
gate_ledger="${gate_dir}/tools/ledger.py"

. "$here/lib.sh"
iso_credless_arm

# --- behind a herd worker's wall, the landing is the launcher's to run ----------------
# A walled worker (herd-spawn.sh) cannot run the landing's gate: suites that build a wall,
# walk the process tree or write beside its HERD_DIR entry die of the wall, and the merge
# writes the primary, which the wall denies (2026-09-24: `32 ok, 1 skip, 5 fail` walled,
# all green from an operator's shell). The gate is not the worker's work, so it runs
# OUTSIDE the wall: the launcher herd-spawn.sh put outside it serves a landing REQUEST by
# running the PRIMARY's finish-worktree.sh, unwalled, on the branch and worktree the
# worker was STARTED on -- state the launcher holds, never anything this request says.
# The launcher marks the agent's environment with HERD_GATE_* (walled spawns only); this
# block only asks, waits, and prints what came back. It asks only for the landing the
# launcher would do anyway -- the same branch in the same worktree -- so a test fixture
# that runs finish on some OTHER branch from inside a worker still lands in the wall (and
# its suites say they could not run), and never sets the worker's real landing off.
# The variables are cleared either way: nothing this landing starts inherits the channel.
# The receipt that comes back carries the launcher's own GATE= line saying where it ran.
hg_channel="${HERD_GATE_CHANNEL:-}"
hg_branch="${HERD_GATE_BRANCH:-}"
hg_worktree="${HERD_GATE_WORKTREE:-}"
unset HERD_GATE_CHANNEL HERD_GATE_BRANCH HERD_GATE_WORKTREE
if [[ -n "$hg_channel" && "$branch" == "$hg_branch" && -n "$hg_worktree" &&
      "$(cd "$worktree" && pwd -P)" == "$hg_worktree" && -d "$hg_channel" && ! -L "$hg_channel" ]]; then
  set +e
  landing_python - "$hg_channel" "$branch" "$worktree" <<'PY'
import json, os, sys, time
chan, branch, worktree = sys.argv[1:4]
req, res = os.path.join(chan, "gate.request"), os.path.join(chan, "gate.result")
ACK_S, WAIT_S = 30, 6 * 3600


def refuse(why: str) -> None:
    print("refusing to land %s: %s; nothing moved." % (branch, why), file=sys.stderr)
    print("MERGED=no")
    sys.exit(1)


try:
    if os.path.lexists(res):
        os.unlink(res)                       # an answer to an EARLIER request is not ours
    tmp = "%s.%d" % (req, os.getpid())
    with open(tmp, "x", encoding="utf-8") as f:
        json.dump({"branch": branch, "worktree": worktree}, f)
    os.replace(tmp, req)
except OSError as e:
    refuse("behind the worker's wall the gate cannot run here, and the landing request "
           "could not be written to %s (%s)" % (chan, e.strerror or type(e).__name__))
print("the gate runs outside the worker's wall: landing %s was handed to the herd launcher; "
      "waiting for its receipt" % branch, file=sys.stderr, flush=True)
t0 = time.time()
while os.path.lexists(req):
    if time.time() - t0 > ACK_S:
        try:
            os.unlink(req)
        except OSError:
            pass
        refuse("behind the worker's wall the gate cannot run here, and the herd launcher did not "
               "take the landing request within %ds (is this worker still under its launcher?)" % ACK_S)
    time.sleep(0.2)
while not os.path.lexists(res):
    if time.time() - t0 > WAIT_S:
        refuse("the herd launcher took the landing request and gave no receipt within %ds" % WAIT_S)
    time.sleep(0.5)
try:
    with open(res, encoding="utf-8", errors="replace") as f:
        got = json.load(f)
    os.unlink(res)
    rc, out, err = int(got["rc"]), str(got["stdout"]), str(got["stderr"])
except (OSError, ValueError, KeyError, TypeError) as e:
    # the landing outside DID run: whether it moved BASE is the primary's to say, not ours
    print("the herd launcher ran the landing of %s outside the worker's wall, and its receipt "
          "could not be read (%s): look at the primary before landing again" % (branch, type(e).__name__),
          file=sys.stderr)
    sys.exit(1)
sys.stderr.write(err)
sys.stdout.write(out)
sys.exit(rc)
PY
  hg_rc=$?
  set -e
  exit "$hg_rc"
fi

# --- before anything prints a name somebody else chose ----------------------------
# Every such name goes through iso_safe_text, which spells out each code point in an
# invisible Unicode category. That answer comes from python3, and the old helper fell back
# to a byte-level `tr` in SILENCE whenever its python could not run -- a fallback that
# stops at 0x7F, so U+009B (the 8-bit CSI, erase-line in a UTF-8 terminal) and U+202E
# passed through it byte-identical, with no sign to the operator that anything had changed
# (ISSUE(security-audit-2026-09-18-daily-2026-09-18-3)). Asked once, here, because a
# landing that cannot print a name safely does not print it at all.
case "$(iso_safe_text_mode)" in
  python) ;;
  tr)
    # a machine with no python3 at all: worse than the category table, never nothing, and
    # said out loud rather than chosen quietly
    echo "note: names printed with the byte-level fallback (no python3)" >&2
    ;;
  *)
    {
      echo "refusing to land: this landing could not print safely -- a python3 is on PATH"
      echo "and iso_safe_text could not run it, so every name it would show you (a colliding"
      echo "path, a lint finding, a red test file) would fall to a byte-level fallback that"
      echo "leaves U+009B and U+202E intact. Fix python3, or remove it from PATH to accept"
      echo "the fallback deliberately. Nothing moved."
    } >&2
    exit 1
    ;;
esac

# ... and the branch name is a name somebody chose too. git accepts a C1 byte in a ref
# name (it refuses CR and the 0x00-0x1F range, not U+009B), and ${branch} is printed raw in
# every refusal, in BRANCH= on the receipt, in the exit notes and in the "waiting for the
# landing lock" line ANOTHER operator reads. Rather than escape it at each of those sinks
# and add the next one to the same list, a name carrying a code point that cannot be
# printed as itself is refused HERE -- before the landing lock, before assert-head.sh,
# before anything else prints at all. No honest branch has one
# (ISSUE(security-audit-2026-09-18-daily-2026-09-18-4)).
branch_safe="$(iso_safe_text "$branch")"
if [[ "$branch_safe" != "$branch" ]]; then
  {
    echo "refusing to land: the branch name carries a code point that cannot be printed as"
    echo "itself, so it is spelled out here and nowhere else:"
    echo "   ${branch_safe}"
    echo "Rename it (git branch -m) and run finish again; nothing moved, and no landing lock"
    echo "was taken."
  } >&2
  exit 1
fi

case "$branch" in
  main|master|develop)
    echo "refusing to finish a base branch (${branch})" >&2
    exit 1
    ;;
  cursor/*)
    echo "Cloud Agent: do not merge into main. Open a ready-for-review PR." >&2
    exit 3
    ;;
esac

"$here/assert-head.sh" "$branch" "$worktree"

if [[ -n "$(git -C "$worktree" status --porcelain)" ]]; then
  echo "uncommitted changes in worktree; commit or discard before finish" >&2
  git -C "$worktree" status -sb >&2
  exit 1
fi

git_common="$(git -C "$worktree" rev-parse --git-common-dir)"
if [[ "$git_common" != /* ]]; then
  git_common="$(cd "${worktree}/${git_common}" && pwd)"
else
  git_common="$(cd "$git_common" && pwd)"
fi
primary="$(dirname "$git_common")"
# Where a refusal tells the operator to find this skill's scripts: never the private
# directory this run came from, which is gone the moment it exits. The name stays spelled
# as $here's sibling so vendor.sh's closure still sees that finish needs dispatch-init.sh.
hint_init="$here/dispatch-init.sh"
if [[ -n "$gate_from_base" ]]; then
  hint_init="${primary}/${gate_scripts_rel}/${hint_init##*/}"
fi

if git -C "$worktree" symbolic-ref --quiet refs/remotes/origin/HEAD >/dev/null 2>&1; then
  base="$(git -C "$worktree" symbolic-ref --short refs/remotes/origin/HEAD | sed 's#^origin/##')"
else
  base="main"
fi
if ! git -C "$worktree" show-ref --verify --quiet "refs/heads/${base}"; then
  if git -C "$worktree" show-ref --verify --quiet "refs/heads/master"; then
    base="master"
  fi
fi

# A repository with .cursor/design-paths keeps two kinds of session apart: a design
# session (design/*) lands only files design owns, a dev session (feat/*) lands none
# of them. The check is here, at landing, because that is where the split is either
# real or decorative. ISOLATED_SESSION_CROSS=1 lands a crossing change on purpose.
kind="$(iso_kind_of_branch "$branch")"
if [[ -f "$(iso_design_paths_file "$primary")" ]]; then
  merge_base="$(git -C "$worktree" merge-base "$base" "$branch")"
  crossing=""
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    if iso_is_design_path "$primary" "$f"; then
      [[ "$kind" == "dev" ]] && crossing="${crossing}   ${f}"$'\n'
    else
      [[ "$kind" == "design" ]] && crossing="${crossing}   ${f}"$'\n'
    fi
  done < <(git -C "$worktree" diff --name-only "$merge_base" "$branch")
  if [[ -n "$crossing" ]]; then
    if [[ "${ISOLATED_SESSION_CROSS:-0}" == "1" ]]; then
      {
        echo "NOTE: ISOLATED_SESSION_CROSS=1 -- this ${kind} session lands files outside its paths:"
        printf '%s' "$crossing"
      } >&2
    else
      {
        if [[ "$kind" == "design" ]]; then
          echo "refusing to land ${branch}: a design session changed files design does not own:"
        else
          echo "refusing to land ${branch}: a dev session changed files that belong to design:"
        fi
        printf '%s' "$crossing"
        echo "The split is $(iso_design_paths_file "$primary"). Move those changes to a session of"
        echo "the other kind, or land with ISOLATED_SESSION_CROSS=1 when the change has to cross"
        echo "(and say why in the commit)."
      } >&2
      exit 1
    fi
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
  done < <(git -C "$worktree" worktree list --porcelain)
  return 1
}

# Is <rel>, in checkout <root>, a tracked GITLINK sitting over LIVE STATE?
#
# A gitlink (mode 160000) with no `.gitmodules` is an UNINITIALISED submodule to git, and
# git looks inside one for nothing: whatever a real directory of that name holds,
# `git diff`, `git diff --cached` and `git status --porcelain` all say clean, and
# `git ls-files --others [--ignored]` inside it prints NOTHING -- so `is_tracked_dirty`
# reports a checkout holding a running node's keys under such a path as having nothing to
# lose, and the collision walk's untracked-file enumeration reads "every file in it is
# git's to replace". `git merge --ff-only` of a range that turns that gitlink into a
# regular blob then reports `mode change 160000 => 100644` and the files under it are gone.
# Measured end to end at both sinks
# (ISSUE(security-audit-2026-09-18-daily-2026-09-18-6)).
#
# Two shapes are deliberately NOT live state:
#   * an EMPTY directory -- there is nothing to protect, so the same flip lands;
#   * a directory that is a CHECKOUT of its own (it has a `.git`): an initialised
#     submodule, or a linked worktree that a `git add -A` in the primary staged as a
#     gitlink, which is the ordinary shape of `.worktrees/<session>` here. Its contents are
#     git's own and are reachable from its own repository; treating it as unprotected state
#     makes every later landing in that primary refuse for a path no range even touches
#     (measured against the review-checkout suite).
# The directory is read with a glob, not `ls`, for ff_dirent's reason: bash reads a
# directory entry that `ls` cannot spell.
#
# The shape is read with ff_disk_form (below), not with `-d` on the incoming spelling: on a
# folding filesystem `-d "$root/agents.d"` answers about an `Agents.d` that is there under
# another name, and the refusal then prints a path that, as printed, is not on disk. A
# CASE VARIANT is deliberately NOT this shape -- the collision walk judges it and names
# BOTH spellings, which is the sentence an operator can act on. A SYMLINK to a directory
# IS: git unlinks the link to write the incoming blob, and the state behind it is as lost
# as if the directory had stood here itself (finding 5 of the 2026-09-18 review,
# ISSUE(security-audit-2026-09-18-daily-2026-09-18-13)).
ff_gitlink_live() {  # $1 root, $2 rel
  local root="$1" rel="$2" meta="" form=""
  meta="$(git -C "$root" -c core.quotepath=false ls-files -s -- ":(literal)${rel}" 2>/dev/null || true)"
  case "$meta" in
    160000\ *) ;;
    *) return 1 ;;
  esac
  form="$(ff_disk_form "$root" "$rel")"
  [[ "$form" == "dir" || "$form" == "link" ]] || return 1
  if [[ -e "${root}/${rel}/.git" ]]; then
    return 1
  fi
  [[ -n "$(shopt -s nullglob dotglob; printf '%s' "${root}/${rel}"/*)" ]]
}

# Every such path in checkout $1, one NUL-separated record each. This is the RANGE-BLIND
# half of the guard: the walk below refuses the flip the range actually carries, and this
# one keeps a checkout holding such state from being moved under the operator at all.
gitlink_over_live_state() {  # $1 dir
  local dir="$1" meta="" path=""
  while IFS= read -r -d '' meta; do
    case "$meta" in
      160000\ *) ;;
      *) continue ;;
    esac
    # `<mode> <object> <stage>` then a TAB then the path, in the tree's own spelling
    path="${meta#*$'\t'}"
    [[ -n "$path" && "$path" != "$meta" ]] || continue
    if ( ff_gitlink_live "$dir" "$path" ); then
      printf '%s\0' "$path"
    fi
  done < <(git -C "$dir" -c core.quotepath=false ls-files -s -z 2>/dev/null || true)
}

# The sentence that follows a "cannot merge" when the reason is the one git will not
# show: `git status -sb` prints NOTHING about a gitlink over live state, so a refusal
# that stops at `status` hands the operator a checkout that looks clean. Names the paths,
# each through iso_safe_text -- and a name that cannot be escaped is said to be one
# rather than printed raw, because this refusal is read immediately before somebody
# deletes something by hand.
say_gitlink_state() {  # $1 dir
  local dir="$1" rec="" esc="" any="no"
  while IFS= read -r -d '' rec; do
    [[ -n "$rec" ]] || continue
    if [[ "$any" == "no" ]]; then
      echo "these tracked gitlink(s) hold a directory that is NOT empty on disk:" >&2
      any="yes"
    fi
    if esc="$(iso_safe_text "$rec")"; then
      echo "   ${esc}" >&2
    else
      echo "   (a gitlink path this landing could not print safely)" >&2
    fi
  done < <(gitlink_over_live_state "$dir")
  if [[ "$any" == "yes" ]]; then
    {
      echo "git looks inside none of them -- to git they are uninitialised submodules, so"
      echo "diff, diff --cached and status --porcelain are all silent about what is in there."
      echo "A range that turns one into a regular file deletes what is under it without a"
      echo "word. Move that state aside (or initialise the submodule), then run finish again."
    } >&2
  fi
}

# A checkout with uncommitted TRACKED changes cannot be moved under the operator's
# feet. Used twice: the fast-forward of BASE from origin below, and the merge of the
# branch into BASE further down -- both move refs/heads/BASE and both bring whatever
# has it checked out along with it.
#
# The third question is the one git cannot be asked: a tracked gitlink over a non-empty
# directory is state to protect, and the two `--quiet` diffs above return 0 for it.
is_tracked_dirty() {
  local dir="$1"
  if ! git -C "$dir" diff --quiet; then
    return 0
  fi
  if ! git -C "$dir" diff --cached --quiet; then
    return 0
  fi
  if [[ -n "$(gitlink_over_live_state "$dir")" ]]; then
    return 0
  fi
  return 1
}

# What is ALREADY on disk where an incoming commit would create <rel> -- the path
# itself, tracked or not, ignored or not, or the first ancestor of it that is not a
# directory (a file where a directory has to be written is as much a collision as a
# file where a file would land). Prints what is in the way -- the path, and for a
# directory a few of the paths under it that would go with it -- one per line, and
# returns 0; silent and non-zero when the path is free.
#
# Why a plain existence test and not `git status`: `is_tracked_dirty` sees only TRACKED
# changes, and `git merge --ff-only` refuses only for untracked files it can SEE -- an
# IGNORED file it treats as expendable and deletes to make room for the incoming blob.
# `keys/`, `data/`, `agents.d/` and `node.env` are ignored in this repository and are a
# running node's live private state inside the primary checkout, so a commit reachable
# from origin/BASE that tracks such a path took an Ed25519 seed with it, with no refusal
# and no receipt line. Called through $( ), so `set -f` and IFS stay in the subshell.
#
# The question asked of git is "does it track a FILE at exactly this path", never "does
# it track anything at or under this path". `git ls-files --error-unmatch -- ':(literal)p'`
# answers the second: it exits 0 for a tracked directory PREFIX, and the walk asked it
# before the final-component test, so `git rm -r keys` plus a regular file named `keys`
# was skipped outright -- `is_tracked_dirty` saw nothing, the live files under `keys/`
# being ignored, and the fast-forward deleted the directory and the Ed25519 seed in it.
# One innocuous landing that tracks `keys/README.md` is all it takes to arm that; today
# `.claude`, `.cursor` and `apps` are tracked prefixes already. So: a tracked prefix is
# not a tracked file, and the final component is judged by what is actually there.
#
# ... and "what is actually there" is asked of the DIRECTORY ENTRY, byte for byte, never
# of a stat of the incoming spelling. The dev host's filesystem folds case (APFS,
# core.ignorecase=true): `[[ -d "$root/Keys" ]]` answers about `keys/`, while
# `git ls-files --others [--ignored] --exclude-standard -- ':(literal)Keys'` is byte-exact
# and prints nothing and exits 0 -- so the walk read an empty enumeration as "every file in
# it is tracked" and returned "no collision", and `git merge --ff-only`, whose own lstat
# folds too, landed on `keys/`, unlinked the ignored entries in it and wrote the file.
# Measured end to end: `keys/agent-a.key` gone, at BOTH sinks
# (ISSUE(security-audit-2026-09-18-daily-2026-09-18)).

# The REAL directory entry for the component $2 inside the directory $1. Prints one of:
#   "=<name>"  an entry exists under EXACTLY that spelling
#   "~<name>"  an entry exists only under ANOTHER spelling -- a case variant
#   "?"        something is there and could not be enumerated: fail closed
#   ""         nothing is there under any spelling
# A glob, not `ls`: bash reads a directory entry with a newline in it and `ls` does not,
# and the whole point of this helper is that the bytes are compared and not folded.
ff_dirent() {
  local dir="$1" want="$2" e="" name="" variant=""
  [[ -d "$dir" ]] || return 0
  if [[ ! -r "$dir" || ! -x "$dir" ]]; then
    printf '?'
    return 0
  fi
  shopt -s nullglob dotglob
  for e in "$dir"/*; do
    name="${e##*/}"
    if [[ "$name" == "$want" ]]; then
      printf '=%s' "$name"
      return 0
    fi
  done
  shopt -s nocasematch
  for e in "$dir"/*; do
    name="${e##*/}"
    if [[ "$name" == "$want" ]]; then
      variant="$name"
      break
    fi
  done
  shopt -u nocasematch
  if [[ -n "$variant" ]]; then
    printf '~%s' "$variant"
    return 0
  fi
  # The listing showed nothing and the name still resolves: something is reachable that
  # the enumeration did not show. That is not "free"; it is a check that did not answer.
  if [[ -e "${dir}/${want}" || -L "${dir}/${want}" ]]; then
    printf '?'
  fi
  return 0
}

# The on-disk FORM of <rel> in <root>, every component read from the real directory entry
# (ff_dirent) rather than stat'ed under the incoming spelling -- the distinction ff_dirent
# exists for. Prints exactly one of:
#   dir      a real directory, at exactly this spelling
#   link     a symlink at exactly this spelling that resolves to a directory
#   other    something else at exactly this spelling: a file, or a link to one
#   variant  nothing at this spelling, but an entry under a CASE VARIANT of it
#   unknown  something is there and could not be enumerated: fail closed
#   none     nothing under any spelling
# Sets shell options through ff_dirent, so every caller reads it through $( ).
ff_disk_form() {  # $1 root, $2 rel
  local root="$1" rest="$2" part="" parent="$root" ent=""
  while [[ -n "$rest" ]]; do
    part="${rest%%/*}"
    if [[ "$part" == "$rest" ]]; then rest=""; else rest="${rest#*/}"; fi
    [[ -n "$part" ]] || continue
    ent="$(ff_dirent "$parent" "$part")"
    case "$ent" in
      "") printf 'none'; return 0 ;;
      "?") printf 'unknown'; return 0 ;;
      "=${part}") ;;
      *) printf 'variant'; return 0 ;;
    esac
    parent="${parent}/${part}"
  done
  if [[ -L "$parent" ]]; then
    if [[ -d "$parent" ]]; then printf 'link'; else printf 'other'; fi
    return 0
  fi
  if [[ -d "$parent" ]]; then printf 'dir'; else printf 'other'; fi
  return 0
}

# One record per thing in the way, NUL-separated, appended to $3.
ff_emit() {
  printf '%s\0' "$2" >> "$1"
}

# The DIRECTORY arm, and the one the `Keys` bug lived in. git replaces a directory only by
# deleting what is in it, and it deletes an IGNORED file without a word, so the directory
# is in the way exactly when something under it is not git's. Emits $4 (the label an
# operator reads) and up to four of the paths under it -- four, because a refusal that
# prints a whole data directory is a refusal nobody reads -- and returns 0 when it is in
# the way; returns 1, emitting nothing, when every file in it is git's to replace. $5 is
# `yes` when the caller has already decided it is a collision and only wants the label and
# the contents. $2 is the ON-DISK spelling, which is the only spelling git's byte-exact
# pathspec matching will answer about.
ff_under() {  # $1 root, $2 rel (on disk), $3 hits, $4 label, $5 force
  local root="$1" rel="$2" hits="$3" label="$4" force="$5" u="" one="" n=0 i=0
  if ! u="$(finish_tmp)"; then
    ff_emit "$hits" "${label} (the untracked-file check could not run)"
    return 0
  fi
  # `-z`, so a path with a newline in it arrives as one record; `:(literal)` so a `*` in a
  # name cannot match some other path. A non-zero exit is a check that did not run, which
  # is a refusal -- never an empty answer read as "nothing there".
  if ! git -C "$root" ls-files --others --exclude-standard -z -- ":(literal)${rel}" > "$u" 2>/dev/null; then
    ff_emit "$hits" "${label} (the untracked-file check could not run)"
    rm -f "$u"
    return 0
  fi
  if ! git -C "$root" ls-files --others --ignored --exclude-standard -z -- ":(literal)${rel}" >> "$u" 2>/dev/null; then
    ff_emit "$hits" "${label} (the ignored-file check could not run)"
    rm -f "$u"
    return 0
  fi
  while IFS= read -r -d '' one; do
    if [[ -n "$one" ]]; then n=$(( n + 1 )); fi
  done < "$u"
  if [[ "$n" == "0" ]]; then
    rm -f "$u"
    if [[ "$force" == "yes" ]]; then
      ff_emit "$hits" "$label"
      return 0
    fi
    return 1
  fi
  ff_emit "$hits" "$label"
  while IFS= read -r -d '' one; do
    if [[ -z "$one" ]]; then continue; fi
    i=$(( i + 1 ))
    if [[ "$i" -gt 4 ]]; then break; fi
    ff_emit "$hits" "$one"
  done < "$u"
  rm -f "$u"
  return 0
}

# Is <rel> in <root> worth walking when the range does something to it OTHER than create
# it? Only a path that can be holding a running node's live state is, and there are three
# such shapes, not one:
#   * a real DIRECTORY at exactly this spelling -- the shape this test started as;
#   * a SYMLINK to a directory, which is the ordinary arrangement when the state lives on
#     another volume. `-d && ! -L` refused it on BOTH guards, so the walk was never called,
#     `git status --porcelain` said nothing, and `git merge --ff-only` unlinked the live
#     link to write the incoming blob;
#   * a CASE VARIANT of this spelling. `-d` folds on this filesystem, so `agents.d` was
#     refused only by accident, through a check that had answered about `Agents.d` and then
#     printed a path that, as printed, is not there.
# Plus `unknown` -- an entry that is there and could not be enumerated -- which is walked
# so that ff_collision says so, rather than skipped as if the path were free
# (ISSUE(security-audit-2026-09-18-daily-2026-09-18-13)).
# ff_collision then decides; this only says "look". Sets shell options through ff_dirent,
# so callers run it in a subshell.
ff_walk_worthy() {  # $1 root, $2 rel
  case "$(ff_disk_form "$1" "$2")" in
    dir|link|variant|unknown) return 0 ;;
    *) return 1 ;;
  esac
}

# Walks <rel> component by component against what is on disk in <root>, appending one
# NUL-separated record per thing in the way to <hits>. Returns 0 when it appended
# something, 1 when the path is free. Run in a subshell by its one caller, so the shell
# options it sets stay there.
ff_collision() {  # $1 root, $2 rel, $3 hits
  local root="$1" rel="$2" hits="$3"
  local rest="$rel" part="" acc="" disk_acc="" parent="$root"
  local ent="" kind="" real="" tracked="" parts=()
  while [[ -n "$rest" ]]; do
    part="${rest%%/*}"
    if [[ "$part" == "$rest" ]]; then rest=""; else rest="${rest#*/}"; fi
    if [[ -n "$part" ]]; then parts+=("$part"); fi
  done
  if [[ "${#parts[@]}" -eq 0 ]]; then
    return 1
  fi
  for part in "${parts[@]}"; do
    acc="${acc:+${acc}/}${part}"
    ent="$(ff_dirent "$parent" "$part")"
    if [[ -z "$ent" ]]; then
      # nothing on disk under this name in any spelling, so nothing below it either
      return 1
    fi
    if [[ "$ent" == "?" ]]; then
      ff_emit "$hits" "${acc} (what is on disk under this name could not be listed)"
      return 0
    fi
    kind="${ent:0:1}"
    if [[ "$kind" == "=" ]]; then
      # the entry is spelled exactly as the incoming path spells it; command substitution
      # eats a trailing newline, so take the spelling we already have
      real="$part"
    else
      real="${ent:1}"
    fi
    disk_acc="${disk_acc:+${disk_acc}/}${real}"

    if [[ "$kind" == "~" ]]; then
      # A CASE VARIANT. git's only in ONE shape: a tracked FILE, at the final component,
      # which is a case-only rename and is exactly what git fast-forwards correctly. The
      # walk used to refuse that -- and its refusal told the operator to move a TRACKED
      # file aside, which trips is_tracked_dirty and wedges every later landing, the same
      # wedge the `notes` -> `notes/` arm above exists to undo. Everything else is a
      # collision, named with BOTH spellings: the incoming one, and the one the filesystem
      # actually holds, because a refusal that prints only the spelling that is NOT there
      # sends the operator hunting.
      tracked="$(git -C "$root" -c core.quotepath=false ls-files -- ":(literal)${disk_acc}" 2>/dev/null || true)"
      if [[ "$acc" == "$rel" && "$tracked" == "$disk_acc" &&
            -f "${root}/${disk_acc}" && ! -L "${root}/${disk_acc}" ]]; then
        return 1
      fi
      ff_under "$root" "$disk_acc" "$hits" \
        "${acc} (this filesystem folds case: what is on disk is spelled ${disk_acc})" "yes" || true
      return 0
    fi

    if [[ "$acc" != "$rel" ]]; then
      # An INTERMEDIATE component. git tracking exactly this path as a FILE means the
      # incoming range turns that file into a directory -- git's to replace, not ours to
      # refuse: a commit that turns the tracked file `notes` into the directory `notes/`
      # arrives as D `notes` + A `notes/one.md` and fast-forwards correctly. The walk
      # used to flag `notes` anyway, under a sentence ("none of which is tracked there")
      # that was false of the very path it printed, and whose own instruction (move it
      # aside) then tripped is_tracked_dirty, so nothing landed until somebody
      # fast-forwarded BASE by hand.
      # `:(literal)` so a `*` in a name cannot match some other tracked file; quotepath off
      # so a non-ASCII name comes back as itself and can be compared to the path we asked
      # about. A failure to ask is an empty answer, which is the fail-closed direction.
      tracked="$(git -C "$root" -c core.quotepath=false ls-files -- ":(literal)${acc}" 2>/dev/null || true)"
      if [[ "$tracked" == "$acc" ]]; then
        parent="${parent}/${real}"
        continue
      fi
      # A real DIRECTORY is never in the way of a file INSIDE it; anything else here is,
      # a SYMLINK to a directory included -- `-d` follows links, so a `keys` symlink into
      # the node's key store used to satisfy "is a directory" and be waved through, and
      # git then replaced the link with a real directory wherever the ignore pattern let
      # it (measured in the daily-2026-09-17 review: one character in .gitignore apart).
      if [[ -d "${root}/${acc}" && ! -L "${root}/${acc}" ]]; then
        parent="${parent}/${real}"
        continue
      fi
      ff_emit "$hits" "$acc"
      return 0
    fi

    # The FINAL component, at the spelling the filesystem really holds.
    if [[ -d "${root}/${acc}" && ! -L "${root}/${acc}" ]]; then
      if ff_under "$root" "$acc" "$hits" "$acc" "no"; then
        return 0
      fi
      # ... and "every file in it is tracked" is what an EMPTY enumeration says, which is
      # also what git says about a tracked GITLINK: it will not list inside one. Asked
      # directly, before that silence is read as consent.
      if ff_gitlink_live "$root" "$acc"; then
        ff_emit "$hits" "${acc} (a tracked gitlink: git lists nothing inside it, and the files under it are not git's)"
        return 0
      fi
      # every file in it is tracked: git's to replace
      return 1
    fi
    # a tracked FILE at exactly this path is git's to replace; an untracked or ignored
    # file, or a symlink, is not
    tracked="$(git -C "$root" -c core.quotepath=false ls-files -- ":(literal)${acc}" 2>/dev/null || true)"
    if [[ "$tracked" == "$acc" ]]; then
      return 1
    fi
    ff_emit "$hits" "$acc"
    return 0
  done
  return 1
}

# The whole check, as ONE function used at BOTH sinks -- the origin->BASE fast-forward
# and the branch->BASE merge. Two copies were how the first version of this guard came
# to cover one sink and not the other: `git merge` deletes an ignored file to make room
# for an incoming tracked blob wherever it runs, and a session branch that `git add -f`s
# `keys/agent-a.key` or `node.env` passes the generated-file check, the tests and the
# lint (whose secret-file rule matches `keys/*.key`, not `node.env` or `data/`).
#
# Prints the indented list of what is in the way in $1 (empty when nothing is), every
# name run through iso_safe_text. Returns 2, printing nothing, when the ENUMERATION
# itself could not run: the range goes to a temporary file so `git diff`'s exit status
# is observed, because a guard that cannot run its check must refuse the landing, never
# conclude from a failed check that there is nothing in the way. Read from a process
# substitution, a failing `git diff` left this list empty and the landing fell straight
# through to the merge -- the exact pre-guard behaviour, silently.
# Renames arrive as D + A, so --no-renames keeps the added half.
#
# The enumeration is NOT "what the range adds". It used to be (`--diff-filter=A` alone),
# and a TYPECHANGE -- git's `T`, the letter for "the same path, a different kind" -- is
# neither `A` nor `D`, so a range that turns a tracked gitlink into a regular blob printed
# nothing here and the walk below was never called at all
# (ISSUE(security-audit-2026-09-18-daily-2026-09-18-6)). So the range is read TWICE, and
# every path either read judges goes through the same walk and the same rules:
#   * `--diff-filter=A`  -- what the range CREATES, walked whatever is on disk, as before;
#   * `--diff-filter=CMRDT` -- the rest of `ACMRDT`, walked when its current on-disk form
#     can be holding a running node's live state (`ff_walk_worthy`, by the real directory
#     entry as the fold code does): a directory, a SYMLINK to one, a CASE VARIANT of the
#     spelling, or an entry that could not be listed.
# Two reads rather than one `--name-status`: the first read keeps the exact spelling a
# landing has always used, so the arm that proves this guard FAILS CLOSED when git cannot
# answer is exercised by the same command it was written against. An ordinary modification
# of a tracked file is a file on disk, so it costs one dirent read and is free, as it was.
# Returns 3 when a name could not be ESCAPED, which the caller refuses on for the same
# reason: a landing that cannot print a name safely does not print it at all.
#
# The names are escaped BEFORE they are split into lines, and the two never meet: a hit
# is one NUL-separated RECORD per thing in the way, read with `read -r -d ''`. Splitting a
# multi-line hit on newlines first let the one Cc byte that structures the output past the
# escaper -- a crafted name bought a fabricated, correctly indented entry in a list whose
# next sentence is "move those paths aside yourself"
# (ISSUE(security-audit-2026-09-18-daily-2026-09-18-5)).
ff_collisions() {  # $1 the checkout the range would be written into, $2 the range
  local root="$1" range="$2" list="" wide="" hits="" add="" rec="" esc="" acc="" rc=0
  list="$(finish_tmp)" || return 2
  if ! wide="$(finish_tmp)"; then
    rm -f "$list"
    return 2
  fi
  if ! hits="$(finish_tmp)"; then
    rm -f "$list" "$wide"
    return 2
  fi
  if ! git -C "$worktree" -c core.quotepath=false diff --name-only -z \
         --no-renames --diff-filter=A "$range" > "$list"; then
    rm -f "$list" "$wide" "$hits"
    return 2
  fi
  # the other letters of ACMRDT. A failure to ask is a check that did not run, exactly as
  # above: never an empty answer read as "nothing in the way".
  if ! git -C "$worktree" -c core.quotepath=false diff --name-only -z \
         --no-renames --diff-filter=CMRDT "$range" > "$wide"; then
    rm -f "$list" "$wide" "$hits"
    return 2
  fi
  while IFS= read -r -d '' add; do
    [[ -n "$add" ]] || continue
    # a subshell, so the shell options ff_dirent sets never leave the walk; anything other
    # than "in the way" (0) or "free" (1) is a check that did not run
    rc=0
    ( ff_collision "$root" "$add" "$hits" ) || rc=$?
    if [[ "$rc" != "0" && "$rc" != "1" ]]; then
      rm -f "$list" "$wide" "$hits"
      return 2
    fi
  done < "$list"
  while IFS= read -r -d '' add; do
    [[ -n "$add" ]] || continue
    # not an addition: only a path whose on-disk form can be sitting over live state is
    # walked -- a directory, a symlink to one, a case variant of the spelling, or an entry
    # that could not be listed -- and it is then judged by exactly the rules an addition
    # gets (ff_walk_worthy)
    ( ff_walk_worthy "$root" "$add" ) || continue
    rc=0
    ( ff_collision "$root" "$add" "$hits" ) || rc=$?
    if [[ "$rc" != "0" && "$rc" != "1" ]]; then
      rm -f "$list" "$wide" "$hits"
      return 2
    fi
  done < "$wide"
  while IFS= read -r -d '' rec; do
    [[ -n "$rec" ]] || continue
    if ! esc="$(iso_safe_text "$rec")"; then
      rm -f "$list" "$wide" "$hits"
      return 3
    fi
    acc="${acc}   ${esc}"$'\n'
  done < "$hits"
  rm -f "$list" "$wide" "$hits"
  printf '%s' "$acc"
  return 0
}

# --- the self-rebase of an UNPUBLISHED BASE --------------------------------------
# The S7 shape: this Mac landed, handed BASE off, and the publisher could not push it
# because the other Mac moved origin first ("not a fast-forward"). Nobody but this Mac
# has those commits, so rebasing them onto origin rewrites nothing anyone else holds --
# and it is exactly what the owner otherwise does by hand before anything lands again.
# Everything else that diverges stays a refusal: a person reconciles it.
#
# Prints, as one clause, why BASE may NOT be rebased here; prints nothing when it may.
# All of these must hold (ISOLATED_SESSION_FORCE is checked by the caller):
#   * origin/BASE was read by THIS landing (fetched, or from a current bundle) -- a
#     rebase onto an origin view nobody refreshed buys nothing and rewrites anyway;
#   * the `handoff` remote's BASE is exactly local BASE -- ahead of it, or elsewhere,
#     means what the hand-off holds may already be on its way to origin;
#   * the publisher's status (LANDING_PUBLISHER_STATUS, else <state>/status/<name>.txt)
#     says result=held, not a fast-forward -- it saw that tip and could not publish it.
# Commits origin already contains are never rewritten by construction: the rebase
# replays only ${remote_base}..${base}.
self_rebase_blocker() {
  local sb_base sb_handoff sb_status sb_name
  if [[ "$origin_read" != "yes" ]]; then
    echo "origin was not read by this landing (no fetch, no current bundle), so ${remote_base} is not known to be origin"
    return 0
  fi
  if ! git -C "$primary" remote get-url handoff >/dev/null 2>&1; then
    echo "there is no handoff remote, so nothing shows that the local commits are unpublished"
    return 0
  fi
  sb_base="$(git -C "$worktree" rev-parse "$base")"
  sb_handoff="$(credless git -C "$primary" ls-remote handoff "refs/heads/${base}" 2>/dev/null |
                awk -v want="refs/heads/${base}" '$2 == want { print $1; exit }')" || sb_handoff=""
  if [[ "$sb_handoff" != "$sb_base" ]]; then
    echo "the hand-off's ${base} (${sb_handoff:0:7}) is not local ${base} (${sb_base:0:7}), so what it holds may already be on its way to origin"
    return 0
  fi
  if [[ -n "${LANDING_PUBLISHER_STATUS:-}" ]]; then
    sb_status="$LANDING_PUBLISHER_STATUS"
  elif sb_name="$(iso_publisher_name "$primary")"; then
    sb_status="${ISO_PUBLISHER_STATE}/status/${sb_name}.txt"
  else
    echo "the hand-off remote names no publisher repository, so there is no publisher status to read"
    return 0
  fi
  if ! iso_publisher_held_not_ff "$sb_status"; then
    echo "the publisher status $(iso_safe_text "$sb_status") does not say it held ${base} as not a fast-forward of origin"
    return 0
  fi
  return 0
}

# A conflict the ledger cannot answer: abort, put BASE back at exactly $2, name the
# paths on the receipt line, refuse. $3 is the conflicted paths, one per line.
self_rebase_refuse() {  # $1 checkout, $2 BASE's sha before, $3 paths
  local rr_wt="$1" rr_sha="$2" rr_paths="$3" rr_one="" rr_esc="" rr_names=""
  git -C "$rr_wt" rebase --abort >/dev/null 2>&1 || true
  if [[ "$(git -C "$worktree" rev-parse "$base")" != "$rr_sha" ]]; then
    git -C "$rr_wt" reset --quiet --keep "$rr_sha" >/dev/null 2>&1 || true
  fi
  while IFS= read -r rr_one; do
    [[ -n "$rr_one" ]] || continue
    if rr_esc="$(iso_safe_text "$rr_one")"; then
      rr_names="${rr_names}${rr_names:+ }${rr_esc}"
    else
      rr_names="${rr_names}${rr_names:+ }(a path this landing could not print safely)"
    fi
  done <<< "$rr_paths"
  echo "BASE_REBASE=conflict ${rr_names:-(the rebase stopped without naming a path)}"
  {
    echo "refusing to land ${branch}: ${base} holds this Mac's unpublished landings and ${remote_base}"
    echo "moved under them; rebasing them onto ${remote_base} conflicts in: ${rr_names:-(no path named)}"
    if [[ "$(git -C "$worktree" rev-parse "$base")" == "$rr_sha" ]]; then
      echo "The rebase was aborted and ${base} is exactly where it was (${rr_sha:0:7}); the hand-off,"
      echo "${branch} and ${worktree} did not move. That conflict is a person's to resolve:"
    else
      echo "WARNING: the rebase was aborted but ${base} is NOT back at ${rr_sha:0:7}; check it by hand"
      echo "(git -C '${rr_wt}' reset --keep ${rr_sha}) before anything else lands. Then:"
    fi
    echo "  in ${rr_wt}: git rebase ${remote_base}, resolve, git rebase --continue, then run finish again."
  } >&2
  exit 1
}

# Rebases local BASE onto ${remote_base} in the checkout that has BASE (a temporary one
# when none does), under the same guards as the fast-forward: a clean checkout, and
# nothing the range brings may land on an untracked or ignored path. A conflict confined
# to the generated files is answered by rebuilding the ledger there; any other is
# self_rebase_refuse. Then the hand-off is given the rebased BASE -- the one force push a
# landing ever makes, leased on the old tip so it overwrites only what this check read --
# and a hand-off that will not take it puts BASE back and refuses.
self_rebase_base() {
  local sr_wt sr_from sr_onto sr_rc=0 sr_hits="" sr_conf="" sr_one="" sr_only="" sr_gd="" sr_err="" sr_n=""
  sr_from="$(git -C "$worktree" rev-parse "$base")"
  sr_onto="$(git -C "$worktree" rev-parse "$remote_base")"
  sr_wt="$(worktree_for_branch "$base" || true)"
  if [[ -n "$sr_wt" ]]; then
    if is_tracked_dirty "$sr_wt"; then
      echo "base ${base} is checked out at ${sr_wt} and has uncommitted changes; cannot rebase" >&2
      echo "  ${base} holds unpublished landings that have to be rebased onto ${remote_base} first." >&2
      git -C "$sr_wt" status -sb >&2
      say_gitlink_state "$sr_wt"
      exit 1
    fi
  else
    mkdir -p "${primary}/.worktrees"
    if [[ -e "${primary}/.worktrees/.rebase-${base}" ]]; then
      echo "refusing to land ${branch}: temp rebase worktree already exists: ${primary}/.worktrees/.rebase-${base}" >&2
      exit 1
    fi
    tmp_rebase="${primary}/.worktrees/.rebase-${base}"
    if ! git -C "$primary" worktree add --quiet "$tmp_rebase" "$base" >/dev/null; then
      echo "refusing to land ${branch}: could not open ${base} in a temporary worktree to rebase it" >&2
      exit 1
    fi
    sr_wt="$tmp_rebase"
  fi
  sr_hits="$(ff_collisions "$sr_wt" "${sr_from}..${sr_onto}")" || sr_rc=$?
  if [[ "$sr_rc" != "0" ]]; then
    echo "refusing to land ${branch}: could not list (or could not safely print) the paths rebasing ${base} onto ${remote_base} would create in ${sr_wt}, so the on-disk check never ran; nothing moved." >&2
    exit 1
  fi
  if [[ -n "$sr_hits" ]]; then
    {
      echo "refusing to land ${branch}: rebasing ${base} onto ${remote_base} would have overwritten"
      echo "path(s) already on disk in ${sr_wt} that git does not track there:"
      printf '%s\n' "$sr_hits"
      echo "Move those paths aside yourself, then run finish again; nothing moved."
    } >&2
    exit 1
  fi
  # updateRefs off: a rebase of BASE moves BASE and nothing else, never the session branch
  if ! GIT_EDITOR=true git -C "$sr_wt" -c rebase.updateRefs=false -c rebase.autoStash=false \
         -c rebase.autoSquash=false rebase --quiet "$sr_onto" >/dev/null 2>&1; then
    while :; do
      sr_conf="$(git -C "$sr_wt" -c core.quotepath=false diff --name-only --diff-filter=U)"
      [[ -n "$sr_conf" ]] || break
      sr_only="yes"
      while IFS= read -r sr_one; do
        [[ -n "$sr_one" ]] || continue
        case " $generated " in
          *" $sr_one "*) ;;
          *) sr_only="no" ;;
        esac
      done <<< "$sr_conf"
      if [[ "$sr_only" != "yes" || ! -f "$gate_ledger" ]]; then
        self_rebase_refuse "$sr_wt" "$sr_from" "$sr_conf"
      fi
      # the generated files have one right answer: the ledger (BASE's), rebuilt on this tree
      if ! landing_python "$gate_ledger" --into "$sr_wt" build >/dev/null 2>&1; then
        self_rebase_refuse "$sr_wt" "$sr_from" "$sr_conf"
      fi
      for sr_one in $generated; do
        if [[ -e "$sr_wt/$sr_one" ]] ||
           git -C "$sr_wt" ls-files --error-unmatch -- "$sr_one" >/dev/null 2>&1; then
          git -C "$sr_wt" add -A -- "$sr_one"
        fi
      done
      if [[ -n "$(git -C "$sr_wt" diff --name-only --diff-filter=U)" ]]; then
        self_rebase_refuse "$sr_wt" "$sr_from" "$sr_conf"
      fi
      if ! GIT_EDITOR=true git -C "$sr_wt" -c rebase.updateRefs=false rebase --continue >/dev/null 2>&1; then
        if [[ -z "$(git -C "$sr_wt" diff --name-only --diff-filter=U)" ]]; then
          # the rebuild made that commit empty: nothing of it is left to carry
          GIT_EDITOR=true git -C "$sr_wt" rebase --skip >/dev/null 2>&1 || true
        fi
      fi
      sr_gd="$(git -C "$sr_wt" rev-parse --git-dir)"
      [[ -d "$sr_gd/rebase-merge" || -d "$sr_gd/rebase-apply" ]] || break
    done
    sr_gd="$(git -C "$sr_wt" rev-parse --git-dir)"
    if [[ -n "$(git -C "$sr_wt" diff --name-only --diff-filter=U)" ||
          -d "$sr_gd/rebase-merge" || -d "$sr_gd/rebase-apply" ]]; then
      self_rebase_refuse "$sr_wt" "$sr_from" "$(git -C "$sr_wt" -c core.quotepath=false diff --name-only --diff-filter=U)"
    fi
  fi
  if ! git -C "$worktree" merge-base --is-ancestor "$sr_onto" "$base"; then
    self_rebase_refuse "$sr_wt" "$sr_from" ""
  fi
  sr_err="$(finish_tmp)"
  if ! ISOLATED_SESSION_PUSH=1 git -C "$primary" push --quiet \
         --force-with-lease="refs/heads/${base}:${sr_from}" handoff "${base}:refs/heads/${base}" \
         >/dev/null 2>"$sr_err"; then
    git -C "$sr_wt" reset --quiet --keep "$sr_from" >/dev/null 2>&1 || true
    {
      echo "refusing to land ${branch}: ${base} was rebased onto ${remote_base}, but the hand-off would"
      echo "not take the rebased ${base}: $(iso_safe_text "$(tail -1 "$sr_err" 2>/dev/null || true)")"
      if [[ "$(git -C "$worktree" rev-parse "$base")" == "$sr_from" ]]; then
        echo "${base} was put back where it was (${sr_from:0:7}); nothing else moved."
      else
        echo "WARNING: ${base} could NOT be put back at ${sr_from:0:7}; check it by hand before anything lands."
      fi
    } >&2
    rm -f "$sr_err"
    exit 1
  fi
  rm -f "$sr_err"
  sr_n="$(git -C "$worktree" rev-list --count "${sr_onto}..${base}")"
  base_rebased="yes"
  base_rebase_from="$sr_from"
  base_rebase_line="${sr_n} commit(s) onto $(git -C "$worktree" rev-parse --short=7 "$sr_onto")"
  if [[ -n "$tmp_rebase" ]]; then
    git -C "$primary" worktree remove --force "$tmp_rebase" >/dev/null 2>&1 || true
    tmp_rebase=""
  fi
}

# --- what origin holds: lib.sh:iso_origin_view, and nothing else --------------------
# The owner's uid holds no GitHub credential (company/ops/publisher/README.md), so on this
# machine the fetch always fails, and for as long as it failed silently the landing judged
# BASE against whatever origin/BASE a person last brought down by hand -- hours old while
# the other Mac moved origin, which is how seven landings came to sit on a BASE origin had
# never seen (plan 2026-09-18-no-stops, S7). Then it read the publisher's bundle -- but
# with no bundle, or a stale one, it still went on "against the origin/BASE this
# repository already has", and the owner's rebase script kept a rule of its own that fell
# back to a five-day-old bundle
# (ISSUE(origin-view-has-two-rules-and-one-of-them-serves-a-stale-bundle)).
# Now there is ONE rule, iso_origin_view (lib.sh): the fetch, else the publisher's bundle
# cross-checked against its status, else a REFUSAL with nothing moved. It runs before the
# landing lock is taken, so a refusal leaves no lock behind.
# A repository with NO origin remote has no origin to be stale about and lands as it
# always did ("BASE_FF=none (no origin/BASE)"); that boundary is drawn HERE, by not
# calling the helper, so the refusal cannot creep into repositories that never had one.
origin_read="no"         # origin/BASE was read THIS landing (fetched, or from the bundle)
origin_source=""         # " from bundle" when it came from the bundle, for BASE_FF=
if git -C "$worktree" remote get-url origin >/dev/null 2>&1; then
  if ! iso_origin_view "$worktree" "$base"; then
    {
      echo "refusing to land ${branch}: origin/${base} has no current view (the reason is above), and a"
      echo "landing is never judged against an old one. Nothing moved (${base}, ${branch} and"
      echo "${worktree} are as they were); run finish again once the publisher has written a current bundle."
    } >&2
    exit 1
  fi
  origin_read="yes"
  if [[ "$ISO_ORIGIN_VIEW_SOURCE" == "bundle" ]]; then
    origin_source=" from bundle"
  fi
fi

# --- the landing lock: one landing at a time per primary ----------------------
# Where the lock is, asked ONCE and kept in a variable, so releasing it later is a bare
# `rm` with nothing in front of it. The release used to ask `iso_land_lock_release`,
# which finds the path through `$(git rev-parse --git-common-dir)` -- and a command
# substitution is a fork that inherits this shell's stdio buffer. After a write to a
# broken descriptor that buffer still HOLDS the refusal bash could not deliver, the
# child flushes it into the pipe, and the "path" that comes back is the refusal with the
# path glued to its end. `rm -f` then removes nothing and the landing lock stays owned by
# a live pid -- 2700s of refusal for every other landing. Nothing fallible goes in front
# of a release.
land_lock="$(iso_land_lock_path "$primary" 2>/dev/null || true)"
owner="$(iso_owner)"
land_wait="${ISOLATED_SESSION_LAND_WAIT:-2700}"
waited=0
holding_land="no"
while :; do
  case "$(iso_land_lock_state "$primary" "$owner")" in
    free)
      if iso_land_lock_take "$primary" "$owner" "$branch"; then holding_land="yes"; break; fi
      ;;
    mine)
      holding_land="yes"; break
      ;;
    dead)
      echo "note: a landing lock left by a session that is gone ($(iso_land_lock_describe "$primary")); taking it over" >&2
      iso_land_lock_release "$primary"
      ;;
    other)
      if (( waited >= land_wait )); then
        {
          echo "refusing to land ${branch}: another landing holds ${primary}"
          echo "  $(iso_land_lock_describe "$primary")"
          echo "Waited ${waited}s (ISOLATED_SESSION_LAND_WAIT). Run finish again when it is done."
        } >&2
        exit 1
      fi
      if (( waited % 30 == 0 )); then
        echo "waiting for the landing lock: $(iso_land_lock_describe "$primary")" >&2
      fi
      sleep 5
      waited=$(( waited + 5 ))
      ;;
  esac
done

tmp_merge=""
tmp_rebase=""
tmp_publish=""           # the detached checkout a not-a-fast-forward round rebases in
# the generated files: a conflict confined to them is answered by the ledger, both in the
# self-rebase of BASE and in the rebase of the branch below
generated="PLAN.md docs/IMPLEMENTATION_BACKLOG.md docs/SPECIFICATION.md"
base_rebased="no"        # the self-rebase below rewrote local BASE (and handed it off)
base_rebase_line=""      # BASE_REBASE= on the receipt, when it did
base_rebase_from=""
# The fast-forward of BASE below runs BEFORE the rebase, the tests, the scan and the
# merge, so every refusal AFTER it exits with refs/heads/BASE already advanced and the
# tracked files of the checkout sitting on BASE already rewritten from origin. The
# receipt line is owed on those exits too, and one sentence has to say the primary
# moved even though the landing did not happen -- "the worktree is untouched" is true
# of the session worktree and false of the checkout the operator is looking at. A
# refusal BEFORE the ff (diverged, an on-disk collision, a dirty base) says neither,
# because nothing moved.
#
# ... and the OTHER thing an exit has to know is whether the branch->BASE merge below
# has run. `merged` is set the moment it has, and from then on BASE carries the branch
# permanently: a step that fails after it (the worktree would not come out, the branch
# would not delete) leaves a landing that is neither undone nor finished, and the
# sentence "the landing did not happen" is then simply false. Three states, three
# sentences: (i) ff ran, merge did not; (ii) merge ran, a later step failed; (iii)
# nothing moved -- nothing printed.
base_ff_line="none (no origin/BASE)"
base_ff_moved="no"
base_ff_reported="no"
base_ff_where=""
merged="no"
base_tip=""
remote_base="origin/${base}"
# Landing lease (ISSUE(two-machines-land-without-talking), now a Durable Object: see
# ../worker/): held after the local lock, released on every path that took it --
# success, red tests, a failed publish, the rest -- with the epoch it was granted, so a
# release can never free a lease that has since passed to another machine.
lease_held="no"
lease_did_hold="no"
lease_as=""
lease_repo=""
lease_room=""
lease_epoch=""
cleanup() {
  # The lease first, while this landing still holds the local lock, then the lock
  # by name: one `rm` on a path this shell already had, before anything that forks
  # to *find* the lock (see land_lock above for what a fork costs after a failed
  # write). Only then the temp merge worktree, which needs git and may fail.
  # Always 0: a cleanup that held nothing is not an error.
  if [[ "$lease_held" == "yes" ]]; then
    lease_held="no"
    if [[ -n "${LANDING_LEASE_CLI:-}" ]]; then
      "$LANDING_LEASE_CLI" release --as "$lease_as" --repo "$lease_repo" --room "$lease_room" ${lease_epoch:+--epoch "$lease_epoch"} >/dev/null 2>&1 || true
    else
      DISPATCH_SKILL_REPO="$primary" bash "$here/landing-lease.sh" release --as "$lease_as" --repo "$lease_repo" \
        ${lease_epoch:+--epoch "$lease_epoch"} >/dev/null 2>&1 || true
    fi
  fi
  if [[ "$holding_land" == "yes" ]]; then
    holding_land="no"
    [[ -n "$land_lock" ]] && rm -f "$land_lock" 2>/dev/null
  fi
  if [[ -n "$tmp_merge" ]]; then
    git -C "$primary" worktree remove --force "$tmp_merge" >/dev/null 2>&1 || true
    tmp_merge=""
  fi
  if [[ -n "$tmp_rebase" ]]; then
    git -C "$primary" worktree remove --force "$tmp_rebase" >/dev/null 2>&1 || true
    tmp_rebase=""
  fi
  if [[ -n "$tmp_publish" ]]; then
    git -C "$tmp_publish" rebase --abort >/dev/null 2>&1 || true
    git -C "$primary" worktree remove --force "$tmp_publish" >/dev/null 2>&1 || true
    tmp_publish=""
  fi
  return 0
}
on_exit() {
  local rc=$? moved_note=""
  # `cleanup` FIRST, and every print after it non-fatal. Under `set -euo pipefail` the
  # trap's echoes ran BEFORE the cleanup they wrapped, so one failed write -- a closed
  # stdout, SIGPIPE, a full disk -- aborted the trap: the landing lock stayed owned by a
  # LIVE pid, every other landing then waited 2700s and refused, and an in-flight
  # tmp_merge worktree was left for the next landing to trip over. Releasing before
  # speaking costs nothing and cannot be talked out of.
  # (`cleanup` ends in an `if` that is false when nothing is held, so it can return 1
  # with nothing wrong; `|| true` keeps that out of the way.)
  cleanup || true
  [[ "$rc" != "0" ]] || return 0
  if [[ "$base_ff_moved" == "yes" && "$base_ff_reported" == "no" ]]; then
    base_ff_reported="yes"
    echo "BASE_FF=${base_ff_line}" || true
  fi
  # A self-rebase is not undone by a later refusal: local BASE and the hand-off both
  # already hold the rebased history, which is the state the publisher can push. Said,
  # so the operator does not go looking for the commits under their old names.
  if [[ "$base_rebased" == "yes" ]]; then
    echo "BASE_REBASE=${base_rebase_line}" || true
    echo "note: local ${base} was rebased onto ${remote_base} before this exit (${base_rebase_from:0:7}..$(git -C "$primary" rev-parse --short=7 "$base" 2>/dev/null || true), ${base_rebase_line}) and the hand-off was given it; that stays.$([[ "$merged" == "yes" ]] || printf ' The landing did not happen.')" >&2 || true
  fi
  # The ff sentence and the merge sentence are NOT alternatives: a landing can have
  # fast-forwarded BASE from origin AND merged the branch AND then failed, and the
  # operator is owed both facts -- that the checkout they are sitting in had its tracked
  # files rewritten from origin, and that BASE now carries the branch for good. As an
  # if/elif the ff half was simply dropped whenever the merge had run.
  if [[ "$base_ff_moved" == "yes" ]]; then
    # Which half moved matters: the update-ref arm moves a REF and not one working tree,
    # and telling an operator their files were rewritten when nothing touched them is its
    # own small lie.
    if [[ -n "$base_ff_where" ]]; then
      moved_note="local ${base} was moved to ${remote_base} before this exit (its checkout ${base_ff_where} came along), so that ref and the files under it are no longer where they were."
    else
      moved_note="local ${base} was moved to ${remote_base} before this exit; no working tree had ${base} checked out, so the ref moved and no files moved with it."
    fi
    # "the landing did not happen" is true only while the merge has not run: in state
    # (ii) it HAS, and saying so there is the claim the merge sentence exists to correct.
    [[ "$merged" == "yes" ]] || moved_note="${moved_note} The landing did not happen."
    echo "note: ${moved_note}" >&2 || true
  fi
  if [[ "$merged" == "yes" ]]; then
    # (ii) BASE carries the branch and will keep carrying it; only a later step failed.
    # Three facts are owed: what BASE now has, that the landing did not finish, and that
    # finish is not to be re-run as it stands (it would find the branch already merged
    # and print a receipt for a landing that never cleaned up).
    echo "note: ${base} now carries ${branch} (${base_tip}); the landing did not complete -- what remains is the session worktree ${worktree} and the branch ${branch}. No receipt was printed, so do not re-run finish as it stands: remove that worktree and delete the branch by hand." >&2 || true
    # ... and the two the receipt would have carried and cannot: whether what BASE now
    # holds was scanned as needs-eyes (nobody spawned a reviewer -- that section runs
    # after the receipt) and that the hand-off never got this tip, so the publisher has
    # not seen it and will not push it.
    if [[ "${sec_verdict:-none}" == "needs-eyes" ]]; then
      echo "note: that landing was needs-eyes, and its reviewer is spawned only after the receipt -- so no review ran and one is owed: run the security-audit skill over ${base_before}..${base_tip} by hand." >&2 || true
    fi
    echo "note: the hand-off was not pushed, so the publisher has not seen ${base_tip} and will not publish it until a later landing hands it over." >&2 || true
  fi
}
trap on_exit EXIT

# --- Landing lease: after the local lock, before origin fetch/ff/rebase ------------
# Two Macs publish to one origin. This machine must hold the landing lease for this
# repository before it moves git state, and release it on every path after a
# successful take (cleanup, including red tests). A live foreign hold refuses and
# leaves BASE, origin and the worktree unmoved. The take is ONE process and ONE POST
# (landing-lease.sh); its exit code says which failure it was: 2 this machine's
# configuration, 3 the lease service unreachable, 4 held by another, 5 refused by the
# service (its reason verbatim). None of them is ever reported as another.
# LANDING_LEASE=off or APPL_LEASE=off is the break-glass for a lease-service outage:
# either one disables the lease ENTIRELY, even where it is configured -- no take, no
# release, no request -- and the receipt says `LEASE=off (break-glass)` so the landing
# is visibly unleased (owner ruling, 20260922T150818Z). Otherwise the room file still
# says whether this machine is configured to land under a lease at all. Throwaway
# harnesses that never set DISPATCH_DIR and have no dispatch directory take none.
#
# A present room file that does NOT resolve is a refusal, before anything moves, and the
# refusal prints the one command that configures the machine (dispatch-init.sh), with a
# placeholder only where the value is unknown. It never suggests LANDING_LEASE=off: that
# override is an operator's decision, and a refusal that offers it is how every real
# landing came to run without a lease (plan 2026-09-19-multi-mac-appl, M1).
#
# The lease is then held past the hand-off push, until the publisher says it published
# what this landing handed over (see "held until published" below).
publish_wait_s="${LANDING_PUBLISH_WAIT_S:-300}"
case "$publish_wait_s" in
  ''|*[!0-9]*)
    echo "refusing to land ${branch}: LANDING_PUBLISH_WAIT_S=$(iso_safe_text "$publish_wait_s") is not a whole number of seconds; nothing moved." >&2
    exit 1
    ;;
esac
landing_lease_read_kv() {
  local f="$1" key="$2" line
  [[ -f "$f" && ! -L "$f" ]] || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
      "${key}="*) printf '%s\n' "${line#${key}=}"; return 0 ;;
    esac
  done < "$f"
  return 1
}

landing_lease_repo_from_repos() {
  local repos="$1" want="$2" n pth abs
  [[ -f "$repos" && ! -L "$repos" ]] || return 1
  abs="$(cd "$want" && pwd)" || return 1
  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in
      ''|\#*) continue ;;
    esac
    [[ "$line" == *=* ]] || continue
    n="${line%%=*}"
    pth="${line#*=}"
    case "$pth" in
      "~/"*) pth="${HOME}/${pth#~/}" ;;
    esac
    if [[ -d "$pth" ]] && [[ "$(cd "$pth" && pwd)" == "$abs" ]]; then
      printf '%s\n' "$n"
      return 0
    fi
  done < "$repos"
  return 1
}

dispatch_dir="${DISPATCH_DIR:-${HOME}/.muretai/dispatch}"
room_file="${dispatch_dir}/room"
if [[ "${LANDING_LEASE:-}" == "off" || "${APPL_LEASE:-}" == "off" ]]; then
  echo "LEASE=off (break-glass)"
elif [[ ! -f "$room_file" || -L "$room_file" ]]; then
  if [[ -n "${DISPATCH_DIR:-}" || -d "$dispatch_dir" ]]; then
    {
      echo "refusing to land ${branch}: no Room file at ${room_file}"
      echo "  write did=<the Room's did> to that file (the Room this machine takes the landing"
      echo "  lease through), then run finish again; nothing moved."
    } >&2
    exit 1
  fi
else
  lease_as="${LANDING_LEASE_AS:-}"
  if [[ -z "$lease_as" ]]; then
    lease_as="$(landing_lease_read_kv "${dispatch_dir}/agent" name || true)"
  fi
  lease_repo="${LANDING_LEASE_REPO:-}"
  if [[ -z "$lease_repo" ]]; then
    lease_repo="$(landing_lease_repo_from_repos "${dispatch_dir}/repos" "$primary" || true)"
  fi
  lease_room="$(landing_lease_read_kv "$room_file" did || true)"
  if [[ -z "$lease_as" || -z "$lease_repo" || -z "$lease_room" ]]; then
    if [[ -z "$lease_room" ]]; then
      {
        echo "refusing to land ${branch}: the Room file ${room_file} has no did= line"
        echo "  write did=<the Room's did> to it, then run finish again; nothing moved."
      } >&2
      exit 1
    else
      # the command, with each value this landing knows filled in: the agent from the
      # agent file (or LANDING_LEASE_AS), the name from the repos line that maps this
      # primary (or LANDING_LEASE_REPO), and this primary's path, which is always known
      li_path="$(printf '%q' "$primary")"
      {
        echo "refusing to land ${branch}: the Room file ${room_file} is set, but this machine"
        if [[ -z "$lease_as" ]]; then
          echo "  does not say which agent it lands as (no name= in ${dispatch_dir}/agent)"
        fi
        if [[ -z "$lease_repo" ]]; then
          echo "  maps no repository to this checkout (no line in ${dispatch_dir}/repos names ${primary})"
        fi
        echo "Configure it once, then run finish again; nothing moved:"
        echo "  bash $(printf '%q' "$hint_init") --as ${lease_as:-<agent>} --repo ${lease_repo:-<name>}=${li_path}"
        if [[ -z "$lease_repo" ]]; then
          echo "  (<name> is the repository's name in the Room lease: the same on every machine that lands it)"
        fi
      } >&2
      exit 1
    fi
  else
    # The node the lease runs through (M1 defect: the lease ran this checkout's
    # operator_cli, which has no connection to the Room). A missing or untrusted
    # node line refuses here, before anything moves, with the dispatch-init.sh call.
    lease_node="$(landing_lease_read_kv "${dispatch_dir}/node" node || true)"
    lease_node_err=""
    if [[ -z "$lease_node" ]]; then
      lease_node_err="no node= line in ${dispatch_dir}/node: this machine has not said which node the lease runs through"
    else
      set +e
      # DISPATCH_SKILL_REPO: `here` is BASE's copy in a private directory outside any
      # checkout, so the client cannot find this repository from its own location
      lease_node_err="$(DISPATCH_SKILL_REPO="$primary" python3 -I "$here/landing-lease.py" check-node "$lease_node" --as-prefix node 2>&1 >/dev/null)"
      lease_node_rc=$?
      set -e
      if [[ "$lease_node_rc" == "0" ]]; then
        lease_node_err=""
      fi
    fi
    if [[ -n "$lease_node_err" ]]; then
      {
        echo "refusing to land ${branch}: ${lease_node_err}"
        echo "Configure it once, then run finish again; nothing moved:"
        echo "  bash $(printf '%q' "$hint_init") --as ${lease_as} --repo ${lease_repo}=$(printf '%q' "$primary") --node <absolute path of this machine's node>"
      } >&2
      exit 1
    fi
    lease_out="$(finish_tmp)"
    lease_err="$(finish_tmp)"
    set +e
    if [[ -n "${LANDING_LEASE_CLI:-}" ]]; then
      "$LANDING_LEASE_CLI" take --as "$lease_as" --repo "$lease_repo" --room "$lease_room" >"$lease_out" 2>"$lease_err"
    else
      DISPATCH_SKILL_REPO="$primary" bash "$here/landing-lease.sh" take --as "$lease_as" --repo "$lease_repo" \
        >"$lease_out" 2>"$lease_err"
    fi
    lease_rc=$?
    set -e
    cat "$lease_err" >&2 || true
    lease_held_by=""
    lease_until=""
    lease_expired_by=""
    while IFS= read -r line || [[ -n "$line" ]]; do
      case "$line" in
        held-by=*) lease_held_by="${line#held-by=}" ;;
        until=*) lease_until="${line#until=}" ;;
        epoch=*) lease_epoch="${line#epoch=}" ;;
        expired-lease-by=*) lease_expired_by="${line#expired-lease-by=}" ;;
      esac
    done < "$lease_out"
    case "$lease_epoch" in
      *[!0-9]*) lease_epoch="" ;;
    esac
    # what the lease tool printed is the backend's words: every value that reaches the
    # receipt goes through iso_safe_text, like every other outside string in this file
    lease_held_by="$(iso_safe_text "$lease_held_by")"
    lease_until="$(iso_safe_text "$lease_until")"
    lease_expired_by="$(iso_safe_text "$lease_expired_by")"
    if [[ "$lease_rc" == "4" ]]; then
      echo "LEASE=refused held-by ${lease_held_by} until ${lease_until}"
      {
        echo "refusing to land ${branch}: the landing lease is held by ${lease_held_by} until ${lease_until}"
        cat "$lease_out"
      } >&2
      rm -f "$lease_out" "$lease_err"
      exit 1
    fi
    if [[ "$lease_rc" != "0" ]]; then
      # the client's own one-line reason, without its "landing-lease: " prefix: a refusal
      # names the service's reason verbatim, and unreachable says so -- never each other
      lease_why=""
      while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -n "$line" ]] && lease_why="${line#landing-lease: }"
      done < "$lease_err"
      case "$lease_rc" in
        3) lease_what="the lease service is unreachable" ;;
        5) lease_what="the lease service refused the take" ;;
        2) lease_what="this machine's lease configuration is incomplete" ;;
        *) lease_what="the landing lease take failed (exit ${lease_rc})" ;;
      esac
      {
        echo "refusing to land ${branch}: ${lease_what}: $(iso_safe_text "${lease_why:-no reason given}")"
        cat "$lease_out"
        echo "  nothing moved."
      } >&2
      rm -f "$lease_out" "$lease_err"
      exit 1
    fi
    lease_held="yes"
    lease_did_hold="yes"
    if [[ -n "$lease_expired_by" ]]; then
      echo "LEASE=held (expired lease by ${lease_expired_by} superseded) expired-lease-by=${lease_expired_by}"
    else
      echo "LEASE=held ${lease_held_by} until ${lease_until}"
    fi
    rm -f "$lease_out" "$lease_err"
  fi
fi

# --- origin is the serialization point: BASE comes down before the rebase ---------
# Two primaries (two Macs) now publish to ONE origin through their own publishers
# (company/ops/publisher/README.md). A landing that rebases onto LOCAL BASE alone
# lands a tip origin has never seen the parent of: this Mac's publisher holds the
# hand-off ("not a fast-forward of origin"), and the next ensure-worktree.sh here
# refuses to start, local BASE and origin/BASE having diverged. So the landed tip
# must DESCEND from origin/BASE, and the cheapest way to get there is to fast-forward
# local BASE first and rebase the branch onto the result.
#
# The fetch above already left origin/BASE current; it tolerates failure, because an
# offline landing is a supported case -- the ff is then judged against whatever
# origin/BASE this repository already has. Nothing here goes TO origin: this moves a
# LOCAL ref to a ref that came FROM origin.
#
# The ref moves, so the checkout that HAS BASE checked out is brought along the same
# way the merge below does it (and is refused, unchanged, when it holds uncommitted
# tracked changes). A diverged BASE is a stop, not a warning: reconciling two
# histories is a person's decision, and the session doing it says so with
# ISOLATED_SESSION_FORCE=1, which lands onto local BASE as before.
if git -C "$worktree" remote get-url origin >/dev/null 2>&1 &&
   git -C "$worktree" rev-parse --verify --quiet "$remote_base" >/dev/null; then
  ff_from="$(git -C "$worktree" rev-parse "$base")"
  ff_to="$(git -C "$worktree" rev-parse "$remote_base")"
  if git -C "$worktree" merge-base --is-ancestor "$remote_base" "$base"; then
    base_ff_line="no-op${origin_source}"
  elif git -C "$worktree" merge-base --is-ancestor "$base" "$remote_base"; then
    ff_wt="$(worktree_for_branch "$base" || true)"
    if [[ -n "$ff_wt" ]]; then
      if is_tracked_dirty "$ff_wt"; then
        echo "base ${base} is checked out at ${ff_wt} and has uncommitted changes; cannot merge" >&2
        echo "  ${base} is behind ${remote_base} and the landing has to bring it down first." >&2
        # `|| true`: `git status` itself FAILS on some of the shapes that bring us here --
        # a symlink where a gitlink is tracked is "expected submodule path 'x' not to be a
        # symbolic link", non-zero -- and under `set -e` that killed the script in the
        # middle of its own refusal, so the operator got a half-written sentence and exit
        # 128, which is a crash wearing a refusal's words. The refusal is this script's to
        # finish; git's own words are a courtesy inside it
        # (ISSUE(security-audit-2026-09-18-daily-2026-09-18-13)).
        git -C "$ff_wt" status -sb >&2 || true
        say_gitlink_state "$ff_wt"
        exit 1
      fi
      # ... and nothing the incoming commits CREATE may land on top of something that is
      # already on disk there. Ours, by name, before anything moves -- for ignored and
      # un-ignored untracked paths alike (see ff_collision above for what git does with
      # the ignored ones).
      ff_rc=0
      ff_collides="$(ff_collisions "$ff_wt" "${ff_from}..${ff_to}")" || ff_rc=$?
      if [[ "$ff_rc" == "3" ]]; then
        {
          echo "refusing to land ${branch}: the fast-forward of ${base} to ${remote_base}"
          echo "found path(s) already on disk in ${ff_wt} and could not print them -- python3"
          echo "is on PATH and iso_safe_text could not run it, so a name the range chose would"
          echo "reach your terminal unescaped. A landing that cannot print a name safely does"
          echo "not print it at all; nothing moved (${base}, ${branch} and ${worktree} are as"
          echo "they were)."
        } >&2
        exit 1
      fi
      if [[ "$ff_rc" != "0" ]]; then
        {
          echo "refusing to land ${branch}: could not list the paths the fast-forward of"
          echo "${base} to ${remote_base} would create (git diff --diff-filter=A over"
          echo "${ff_from}..${ff_to} failed, its words above), so the on-disk check never ran."
          echo "A guard that cannot run its own check refuses the landing rather than"
          echo "conclude that nothing is in the way; nothing moved (${base}, ${branch} and"
          echo "${worktree} are as they were)."
        } >&2
        exit 1
      fi
      if [[ -n "$ff_collides" ]]; then
        {
          echo "refusing to land ${branch}: the fast-forward of ${base} to ${remote_base}"
          echo "would have overwritten path(s) already on disk in ${ff_wt} that git does not"
          echo "track there -- an untracked or ignored file, or a directory holding one, which"
          echo "is listed with what is under it:"
          printf '%s\n' "$ff_collides"
          echo "git deletes an IGNORED file to make room for an incoming tracked blob, so a"
          echo "running node's live state (keys/, data/, agents.d/, node.env) goes with it."
          echo "Move those paths aside yourself, then run finish again; nothing moved"
          echo "(${base}, ${branch} and ${worktree} are as they were)."
        } >&2
        exit 1
      fi
      # git's stderr is NOT discarded: when it refuses for a reason the check above could
      # not anticipate (a stale index.lock, a permission), its words are the only ones
      # that say why, and ours follow them.
      if ! git -C "$ff_wt" -c advice.diverging=false merge --ff-only --no-verify "$remote_base" >/dev/null; then
        echo "refusing to land ${branch}: could not fast-forward ${base} to ${remote_base} in ${ff_wt}" >&2
        exit 1
      fi
      base_ff_where="$ff_wt"
    else
      # nothing has BASE checked out: move the ref alone, and only from where we looked
      git -C "$worktree" update-ref "refs/heads/${base}" "$ff_to" "$ff_from"
    fi
    # from here on BASE is not where the operator left it: every later exit says so
    base_ff_moved="yes"
    base_ff_line="$(git -C "$worktree" rev-list --count "${ff_from}..${ff_to}") commit(s) from ${remote_base} ($(git -C "$worktree" rev-parse --short=7 "$ff_from")..$(git -C "$worktree" rev-parse --short=7 "$ff_to"))${origin_source}"
  else
    ff_ahead="$(git -C "$worktree" rev-list --count "${remote_base}..${base}")"
    ff_behind="$(git -C "$worktree" rev-list --count "${base}..${remote_base}")"
    if [[ "${ISOLATED_SESSION_FORCE:-0}" == "1" ]]; then
      echo "warning: ${base} and ${remote_base} have diverged; forced landing onto local ${base}" >&2
      base_ff_line="forced (diverged: ${ff_ahead} ahead, ${ff_behind} behind)${origin_source}"
    else
      # Diverged. Rebased here only when the local-only commits are provably this Mac's
      # own UNPUBLISHED landings; anything else is a person's reconcile, as before.
      rb_why="$(self_rebase_blocker)" || rb_why="the conditions for it could not be checked"
      if [[ -z "$rb_why" ]]; then
        self_rebase_base
        base_ff_line="rebased onto ${remote_base} (diverged: ${ff_ahead} ahead, ${ff_behind} behind)${origin_source}"
      else
        {
          echo "refusing to land ${branch}: ${base} and ${remote_base} have diverged"
          echo "  ${base} is ${ff_ahead} commit(s) ahead of and ${ff_behind} behind ${remote_base}"
          echo "Origin is the serialization point for the primaries that share it, so a landing"
          echo "onto a ${base} that origin has never seen is not a landing. Reconcile the two"
          echo "first; nothing moved (${base}, ${branch} and ${worktree} are as they were)."
          echo "Not rebased here: ${rb_why}."
          echo "Override with ISOLATED_SESSION_FORCE=1 (the session doing the reconcile), which"
          echo "lands onto local ${base} as before."
        } >&2
        exit 1
      fi
    fi
  fi
fi

# --- bring the branch onto the current base -----------------------------------
# A local session branch is rebased, so the tree the tests see is byte-identical to
# the fast-forwarded BASE and BASE stays linear. A branch that is already on origin
# (a second laptop's) is merged, never rewritten. A conflict confined to the generated
# files is resolved by taking BASE's copy -- the ledger is rebuilt below anyway; any
# other conflict stops the landing with the steps to resolve it.
rebased="no-op"
if ! git -C "$worktree" merge-base --is-ancestor "$base" "$branch"; then
  on_origin=0
  if git -C "$worktree" remote get-url origin >/dev/null 2>&1 &&
     git -C "$worktree" ls-remote --exit-code origin "refs/heads/${branch}" >/dev/null 2>&1; then
    on_origin=1
  fi
  if [[ "$on_origin" == "1" || "${ISOLATED_SESSION_LAND_MERGE:-0}" == "1" ]]; then
    if ! git -C "$worktree" merge --no-edit "$base" >/dev/null 2>&1; then
      git -C "$worktree" merge --abort >/dev/null 2>&1 || true
      {
        echo "refusing to land ${branch}: merging ${base} into it conflicts."
        echo "In ${worktree}: git merge ${base}, resolve, commit, then run finish again."
      } >&2
      exit 1
    fi
    rebased="merge"
  else
    if ! git -C "$worktree" rebase "$base" >/dev/null 2>&1; then
      while :; do
        conflicted="$(git -C "$worktree" diff --name-only --diff-filter=U)"
        [[ -n "$conflicted" ]] || break
        only_generated=1
        for f in $conflicted; do
          case " $generated " in
            *" $f "*) ;;
            *) only_generated=0 ;;
          esac
        done
        if [[ "$only_generated" != "1" ]]; then
          git -C "$worktree" rebase --abort >/dev/null 2>&1 || true
          {
            echo "refusing to land ${branch}: rebasing onto ${base} conflicts in:"
            # names the diff chose, on a line an operator reads: spelled out, never raw
            for f in $conflicted; do printf '   %s\n' "$(iso_safe_text "$f")"; done
            echo "In ${worktree}: git rebase ${base}, resolve, git rebase --continue, then run"
            echo "finish again (ISOLATED_SESSION_LAND_MERGE=1 merges instead of rebasing)."
          } >&2
          exit 1
        fi
        for f in $conflicted; do
          git -C "$worktree" checkout --ours -- "$f" 2>/dev/null || true
          git -C "$worktree" add -- "$f"
        done
        if ! GIT_EDITOR=true git -C "$worktree" rebase --continue >/dev/null 2>&1; then
          if [[ -z "$(git -C "$worktree" diff --name-only --diff-filter=U)" ]]; then
            # the session's regeneration was all that commit carried: taking BASE's
            # copy emptied it, and an empty commit has nothing to land
            GIT_EDITOR=true git -C "$worktree" rebase --skip >/dev/null 2>&1 || true
          fi
        fi
        gd="$(git -C "$worktree" rev-parse --git-dir)"
        [[ -d "$gd/rebase-merge" || -d "$gd/rebase-apply" ]] || break
      done
      if [[ -n "$(git -C "$worktree" diff --name-only --diff-filter=U)" ]] ||
         [[ -d "$(git -C "$worktree" rev-parse --git-dir)/rebase-merge" ]] ||
         [[ -d "$(git -C "$worktree" rev-parse --git-dir)/rebase-apply" ]]; then
        git -C "$worktree" rebase --abort >/dev/null 2>&1 || true
        echo "refusing to land ${branch}: the rebase onto ${base} did not complete; resolve it in ${worktree}" >&2
        exit 1
      fi
    fi
    rebased="yes"
  fi
fi
# after a rebase the branch ref moved; make sure HEAD is still the branch
"$here/assert-head.sh" "$branch" "$worktree" >/dev/null

# --- a session never lands a generated file ------------------------------------
# BASE's ledger, from the gate directory: a branch that brings or rewrites
# tools/ledger.py is judged by the one BASE had, and by none when BASE had none.
ledger_tool="$gate_ledger"
if [[ -f "$ledger_tool" ]]; then
  ledger_err="$(finish_tmp)"
  if ! landing_python "$ledger_tool" --into "$worktree" check --diff "$base" --diff-only 2>"$ledger_err"; then
    # A check that died with a Traceback judged nothing: BASE's gate is broken (a module
    # its copy lacks, a bug in the ledger), and the branch is not to blame. Calling that a
    # generated-file edit sent sessions hunting for an edit they never made
    # (ISSUE(gate-copy-lacks-the-ledgers-import)). A refusal without one keeps its wording.
    if grep -q 'Traceback (most recent call last)' "$ledger_err"; then
      {
        echo "refusing to land ${branch}: the landing gate is broken -- ${base}'s tools/ledger.py"
        echo "check crashed before it could judge the branch (this is not a generated-file edit):"
        cat "$ledger_err"
        echo "Fix the ledger on ${base} (or the module it failed to import), then run finish again."
      } >&2
      rm -f "$ledger_err"
      exit 1
    fi
    {
      echo "refusing to land ${branch}: the branch edited a generated file."
      cat "$ledger_err"
      echo "Drop those commits' changes to the generated files (the landing regenerates them):"
      echo "  git -C '${worktree}' checkout ${base} -- ${generated}   # then commit"
    } >&2
    rm -f "$ledger_err"
    exit 1
  fi
  rm -f "$ledger_err"
fi

# --- the tests the diff owes -----------------------------------------------------
# BASE's runner, from the gate directory, pointed at the branch's tree with --root: the
# branch's TESTS run, its runner never does (a runner that reports every file green is
# how a red branch merged).
runner="$gate_runner"
tests_line="none (no tools/run_tests.py in this repository)"
tests_secs=""
tests_files=""
if [[ -f "$runner" ]]; then
  if [[ "${ISOLATED_SESSION_LAND_TESTS:-1}" == "0" ]]; then
    tests_line="skipped-by-operator (ISOLATED_SESSION_LAND_TESTS=0)"
    echo "NOTE: ISOLATED_SESSION_LAND_TESTS=0 -- landing ${branch} without running its tests" >&2
  else
    # --- the children's wall, and the one thing it costs -------------------------------
    # Where the CHILDREN would look for the operator's own packages. Asked ONCE, of an
    # isolated python, so nothing this process reads comes from a PYTHON* variable -- and
    # `-I` does not stop `site.getusersitepackages()` from honouring PYTHONUSERBASE, which
    # it reads from os.environ at call time, so the answer is the directory the children
    # would really have used. A python that cannot answer leaves the path empty, and the
    # children then run walled and without it: closed, and slow, never open.
    tests_usersite="$(credless python3 -I -c 'import site; print(site.getusersitepackages() or "")' 2>/dev/null || true)"
    branch_tests_backend_path=""
    if [[ -n "$tests_usersite" && -d "$tests_usersite" ]]; then
      branch_tests_backend_path="${tests_usersite}"
    fi

    tests_err="$(finish_tmp)"
    tests_tail="$(finish_tmp)"
    # A receipt the launcher already took, and only one that lives in the spawn's walls
    # directory: any other path, including one a worker set, runs the tests. The variables
    # are cleared before anything this landing starts, so a test cannot hand them on.
    tests_from_wall=no
    rec_path="${ISO_FINISH_TESTS_RECEIPT:-}"
    walls_path="${ISO_FINISH_WALLS_DIR:-}"
    unset ISO_FINISH_TESTS_RECEIPT ISO_FINISH_WALLS_DIR
    if [[ -n "$rec_path" && -n "$walls_path" ]]; then
      rec_rc="$(python3 -I - "$rec_path" "$walls_path" <<'PY'
import json, os, sys
rec, walls = sys.argv[1], sys.argv[2]

def real(p):
    return os.path.realpath(p)

try:
    if os.path.islink(rec) or os.path.islink(walls):
        raise OSError("link")
    rec_r, walls_r = real(rec), real(walls)
    if not os.path.isdir(walls_r) or not os.path.isfile(rec_r) or os.path.dirname(rec_r) != walls_r:
        raise OSError("place")
    rc_path = os.path.join(walls, "tests.json")
    if os.path.islink(rc_path):
        raise OSError("link")
    rc_r = real(rc_path)
    if os.path.dirname(rc_r) != walls_r or not os.path.isfile(rc_r):
        raise OSError("rc")
    rc = json.load(open(rc_r)).get("rc")
    if type(rc) is not int:
        raise OSError("rc")
    sys.stdout.write(rec_r + "\n" + str(rc) + "\n")
except OSError:
    sys.stdout.write("no\n")
PY
)"
      if [[ "$rec_rc" != "no" && "$rec_rc" != $'no\n' ]]; then
        report="${rec_rc%%$'\n'*}"
        rc="${rec_rc#*$'\n'}"
        rc="${rc%%$'\n'*}"
        tests_from_wall=yes
        : > "$tests_err"
      fi
    fi
    if [[ "$tests_from_wall" != "yes" ]]; then
      report="$(finish_tmp)"
      # the branch's tests, with no push credential in reach (credless, above), the harness
      # isolated, and the CHILDREN walled but still able to reach the operator's optional
      # backend through PYTHONPATH (branch_tests_python)
      set +e
      ( cd "$worktree" && branch_tests_python "$runner" --root "$worktree" --affected "${base}..HEAD" --gate --json -j "${ISOLATED_SESSION_LAND_JOBS:-4}" ) > "$report" 2>"$tests_err"
      rc=$?
      set -e
    fi
    # The tail of a failing file is the BRANCH's own output, so it is a name-the-diff-chose
    # sink like any other: it goes to a file as NUL-separated records and is escaped here,
    # rather than being printed raw from inside the summary
    # (ISSUE(security-audit-2026-09-18-daily-2026-09-18-4)).
    summary="$(landing_python - "$report" "$rc" "$tests_tail" <<'PY'
import json, sys
path, rc, tail_path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
try:
    d = json.load(open(path))
except Exception:
    print("BROKEN\t\t\t")
    sys.exit(0)
files = d.get("files", [])
counts = {}
for r in files:
    counts[r["status"]] = counts.get(r["status"], 0) + 1
# could-not-run is the verdict of the runner for a file behind a wall: counted on its
# own, never among the files that ran, and it refuses the landing like a red
line = ", ".join(f"{counts.get(k, 0)} {k}" for k in ("ok", "skip", "fail", "timeout", "could-not-run")
                 if counts.get(k))
failed = " ".join(d.get("failed", []))
unrun = " ".join(d.get("could_not_run", []))
names = " ".join(r["file"] for r in files)
# unit separator, not a tab: bash `read` folds runs of IFS whitespace, so an empty
# `failed` column would shift the columns after it
print("\x1f".join([f"{line or '0 files'} (of {len(files)}; {d.get('selection', '')})",
                   str(d.get("wall_s", "")), failed, unrun, names]))
with open(tail_path, "w", encoding="utf-8") as fh:
    for r in files:
        if r["status"] in ("fail", "timeout", "could-not-run"):
            fh.write(f"--- {r['file']}: {r['status']} {r.get('reason', '')}\0")
            for ln in r.get("tail", "").splitlines()[-15:]:
                fh.write("   | " + ln + "\0")
PY
)"
    IFS=$'\x1f' read -r tests_line tests_secs tests_failed tests_unrun tests_files <<< "$summary"
    while IFS= read -r -d '' tail_rec; do
      [[ -n "$tail_rec" ]] || continue
      if ! tail_esc="$(iso_safe_text "$tail_rec")"; then
        echo "refusing to land ${branch}: a test's own output could not be printed safely -- python3 is on PATH and iso_safe_text could not run it." >&2
        rm -f "$report" "$tests_err" "$tests_tail"
        exit 1
      fi
      printf '%s\n' "$tail_esc" >&2
    done < "$tests_tail"
    rm -f "$tests_tail"
    if [[ "$tests_line" == "BROKEN" ]]; then
      { echo "refusing to land ${branch}: tools/run_tests.py gave no report:"; cat "$tests_err"; } >&2
      rm -f "$report" "$tests_err"
      exit 1
    fi
    if [[ "$rc" != "0" ]]; then
      {
        echo "refusing to land ${branch}: ${tests_line}"
        [[ -z "$tests_failed" ]] || echo "red: $(iso_safe_text "$tests_failed")"
        if [[ -n "$tests_unrun" ]]; then
          # behind a wall: not a red, and not a pass -- the gate never got to judge these
          echo "could not run (this landing is behind a wall, so these are no verdict on the diff): $(iso_safe_text "$tests_unrun")"
          echo "The landing's gate belongs outside the wall: from a herd worker, the launcher runs it there."
        fi
        if [[ "$tests_from_wall" == "yes" ]]; then
          echo "The repair agent is asked before a person lands."
        else
          echo "The worktree is untouched (already rebased onto ${base}); fix, commit, run finish again."
        fi
      } >&2
      # A refusal is a receipt too: the counted verdict goes on STDOUT with the rest of
      # the receipt's spelling, so a reader (a herd coordinator, a test) sees what the
      # landing actually measured instead of an empty stdout it has to interpret. MERGED=no
      # is what tells it apart from a landing; the exit status is still the contract.
      echo "MERGED=no"
      echo "TESTS=${tests_line}"
      if [[ -n "$tests_failed" ]]; then
        echo "TESTS_RED=$(iso_safe_text "$tests_failed")"
      fi
      if [[ -n "$tests_unrun" ]]; then
        echo "TESTS_COULD_NOT_RUN=$(iso_safe_text "$tests_unrun")"
      fi
      # The refusal's class. `environment`: every suite that did not pass is one the room
      # refused (the runner measured a wall AND the suite carried the room's words), so
      # nothing here is a verdict on the diff. `red`: at least one ordinary failure or
      # timeout -- the diff's own, whatever else the room refused beside it. TESTS_RED= and
      # TESTS_COULD_NOT_RUN= never name the same file.
      if [[ -n "$tests_unrun" && -z "$tests_failed" ]]; then
        echo "TESTS_REFUSAL=environment"
      else
        echo "TESTS_REFUSAL=red"
      fi
      rm -f "$report" "$tests_err"
      exit 1
    fi
    rm -f "$report" "$tests_err"
    if [[ -n "$(git -C "$worktree" status --porcelain)" ]]; then
      {
        echo "refusing to land ${branch}: the tests left the tree dirty -- a test wrote into the checkout:"
        git -C "$worktree" status --porcelain
      } >&2
      exit 1
    fi
  fi
fi

# --- the deterministic security scan of the diff ----------------------------------
# tools/sec_lint.py reads the added lines and the touched paths and answers with one
# word. `refused` (a key, a token, a guard override) stops the landing exactly as a red
# test does; `needs-eyes` (the audited surface or a guard file changed) lands and owes
# a human review, which is spawned after the merge below; `clean` owes nothing.
#
# The lint that runs is BASE's, not the branch's: `git show BASE:tools/sec_lint.py`
# (and its audit_scope.py plus the generator siblings the rebuild runs) into an
# untracked scratch directory INSIDE the worktree -- the tool takes its
# repository from git rev-parse --show-toplevel of cwd, so from there `--diff`
# sees the branch -- and the directory is gone before anything asks `git status`.
# A branch that replaces the lint with one that answers `clean` is still scanned
# by the copy main had, and its replacement is a gate file (below), so it is
# needs-eyes on top. A BASE without the tool says SEC=none; the branch's copy is
# never the fallback. The rebuild runs THESE copies against the revision's data,
# never the revision's tools/ (ISSUE(scanner-executes-scanned-revision)).
#
# EVERY COMMIT of the range is judged, one lint run per commit (`c^..c`, the first parent
# for a merge), exactly as the publisher judges them (muretai-publish.py `evaluate`). The
# scan used to run ONCE over the net diff `BASE..HEAD`, so a commit that added a refused
# line and a later commit of the same branch that rewrote it landed `clean` -- f6b03cee
# went onto main that way, and only the publisher, asking the per-commit question, refused
# it and then held trunk (ISSUE(landing-and-publisher-asked-different-questions)). A
# refusal in any commit refuses the landing and names that commit's short sha; a later
# commit never excuses it -- the branch is rebased or amended instead. The verdict is the
# worst of the commits' verdicts, the review list the union of theirs, and the SCANNED
# list the union of every path any commit touched, printed on the receipt
# (SEC_SCANNED= / SEC_SCANNED_FILES=) so it is read, not inferred. The gate list is taken
# from that same union, so a gate file edited in one commit and restored in the next is
# still a gate change. A range that touches no path says `nothing-to-scan`, never `clean`.
#
# $1 the checkout to run in, $2 the lint, $3 the range's base; writes the aggregate JSON
# (the lint's own shape plus `scanned_files`, `commits`, `broken`) to $4 and the scanned
# paths, NUL-separated and as git spelled them, to $5. Non-zero only when it could not run.
sec_scan_commits() {  # $1 cwd, $2 lint, $3 base rev, $4 json out, $5 paths out
  ( cd "$1" && landing_python - "$2" "$3" "$4" "$5" <<'PY'
import json, subprocess, sys
lint, base, out_json, out_paths = sys.argv[1:5]
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
GIT = ["git", "-c", "core.quotepath=false"]

def git_out(*args):
    return subprocess.run(GIT + list(args), capture_output=True, check=True).stdout

commits = git_out("rev-list", "--reverse", "--topo-order", base + "..HEAD").decode().split()
scanned, review, findings, seen, broken, refused_in = {}, set(), [], set(), [], []
verdicts = set()
for c in commits:
    has_parent = subprocess.run(GIT + ["rev-parse", "--verify", "--quiet", c + "^"],
                                capture_output=True).returncode == 0
    parent = c + "^" if has_parent else EMPTY_TREE
    touched = [p for p in git_out("diff", "--name-only", "-z", "--no-renames", "--diff-filter=ACMRDT",
                                  parent, c).split(b"\0") if p]
    if not touched:
        continue                     # an empty commit: nothing of it to judge
    for p in touched:
        scanned.setdefault(p, None)
    r = subprocess.run([sys.executable, "-I", lint, "--diff", parent + ".." + c, "--json"],
                       capture_output=True, text=True)
    try:
        d = json.loads(r.stdout)
        verdict = str(d["verdict"])
    except (ValueError, KeyError, TypeError):
        broken.append("%s: %s" % (c[:7], (r.stderr.strip() or "no JSON from the lint")[-300:]))
        continue
    if r.returncode == 2 and verdict != "refused":
        verdict = "refused"          # the exit code is the contract; the word must agree
    if verdict not in ("clean", "needs-eyes", "refused"):
        broken.append("%s: the lint said %r" % (c[:7], verdict))
        continue
    verdicts.add(verdict)
    if verdict == "refused":
        refused_in.append(c[:7])
    review.update(str(f) for f in (d.get("review_files") or d.get("audited_files", [])))
    for f in d.get("findings", []):
        key = (f.get("file"), f.get("line"), f.get("rule"), f.get("level"), f.get("text"))
        if key in seen:
            continue                 # the same finding again in a later commit: named once, first commit
        seen.add(key)
        f = dict(f)
        f["commit"] = c[:7]
        findings.append(f)
if broken:
    verdict = "broken"
elif "refused" in verdicts:
    verdict = "refused"
elif "needs-eyes" in verdicts:
    verdict = "needs-eyes"
elif scanned:
    verdict = "clean"
else:
    verdict = "nothing-to-scan"
findings.sort(key=lambda f: (0 if f.get("level") == "refuse" else 1, str(f.get("file")), f.get("line") or 0))
names = sorted(p.decode("utf-8", "replace") for p in scanned)
with open(out_json, "w", encoding="utf-8") as fh:
    json.dump({"verdict": verdict, "review_files": sorted(review), "findings": findings,
               "scanned_files": names, "commits": len(commits), "refused_in": refused_in,
               "broken": broken}, fh)
with open(out_paths, "wb") as fh:
    for p in sorted(scanned):
        fh.write(p + b"\0")
PY
  )
}

sec_line="none (base has no tools/sec_lint.py)"
sec_verdict="none"
sec_scanned_line=""
sec_files=""
sec_gate=""
gate_files=""
# a branch that removes the scan or the receipt tool would turn this gate off for every
# later landing (SEC=none): refused here, before BASE's lint even runs
# (ISSUE(security-audit-2026-09-12-the-reviewer-opens-in-a-c-2))
for keep in tools/sec_lint.py tools/audit_scope.py; do
  if git -C "$worktree" cat-file -e "${base}:${keep}" 2>/dev/null &&
     ! git -C "$worktree" cat-file -e "HEAD:${keep}" 2>/dev/null; then
    echo "error: refusing to land ${branch}: it removes ${keep}, which every later landing's security gate runs" >&2
    exit 1
  fi
done
if git -C "$worktree" cat-file -e "${base}:tools/sec_lint.py" 2>/dev/null; then
  sec_base="$(mktemp -d "${worktree}/.sec-base-XXXXXX")"
  mkdir -p "$sec_base/tools" "$sec_base/company/ops"
  git -C "$worktree" show "${base}:tools/sec_lint.py" > "$sec_base/tools/sec_lint.py"
  for extra in tools/audit_scope.py tools/ledger.py tools/backlog_build.py \
               tools/spec_build.py company/ops/backlog_to_core.py; do
    if git -C "$worktree" cat-file -e "${base}:${extra}" 2>/dev/null; then
      mkdir -p "$sec_base/$(dirname "$extra")"
      git -C "$worktree" show "${base}:${extra}" > "$sec_base/${extra}"
    fi
  done
  sec_report="$(finish_tmp)"
  sec_err="$(finish_tmp)"
  sec_find_file="$(finish_tmp)"
  sec_paths="$(finish_tmp)"
  set +e
  sec_scan_commits "$worktree" "$sec_base/tools/sec_lint.py" "$base" "$sec_report" "$sec_paths" 2>"$sec_err"
  sec_rc=$?
  set -e
  # the gate list, from BASE's table, over the SAME union the scan judged (every path
  # any commit touched). NUL-separated and never quoted: with git's default quotepath a
  # non-ASCII name arrives octal-quoted and matches no entry (the LONG S case);
  # deletions, renames (as D + A) and type changes included
  if [[ "$sec_rc" == "0" ]]; then
    while IFS= read -r -d '' f; do
      [[ -n "$f" ]] || continue
      gate_files="${gate_files}${gate_files:+ }${f}"
    done < <(landing_python "$sec_base/tools/sec_lint.py" --gate-files < "$sec_paths" 2>/dev/null || true)
  fi
  rm -f "$sec_paths"
  rm -rf "$sec_base"
  # The findings go to a file as NUL-separated records, not down the same stream as the
  # summary: a finding's `file` and `text` come straight out of the lint, which reads paths
  # as raw bytes, and `bad_path_reason` refuses bytes below 0x20 and 0x7F but not U+009B,
  # U+202E or U+2028. Split on newlines first, those fields could both repaint the line and
  # fabricate another (ISSUE(security-audit-2026-09-18-daily-2026-09-18-4)).
  sec_summary="$(landing_python - "$sec_report" "$sec_rc" "$sec_find_file" <<'PY'
import json, sys
path, rc, findings_path = sys.argv[1], int(sys.argv[2]), sys.argv[3]
try:
    if rc != 0:
        raise ValueError("the per-commit scan did not run")
    d = json.load(open(path))
    verdict = str(d["verdict"])
    if verdict == "broken":
        raise ValueError("a commit got no verdict")
except Exception:
    print("BROKEN\x1f0\x1f\x1f0\x1f\x1f")
    sys.exit(0)
# review_files (the audited surface + guard files + files with an eyes-level line), the
# union over the commits, is what the reviewer opens
files = [str(f) for f in d.get("review_files", [])]
scanned = [str(f) for f in d.get("scanned_files", [])]
# unit separator (see the tests summary above)
print("\x1f".join([verdict, str(len(files)), " ".join(files), str(len(scanned)), " ".join(scanned),
                   " ".join(d.get("refused_in", []))]))
with open(findings_path, "w", encoding="utf-8") as fh:
    for f in d.get("findings", []):
        where = f.get("file", "?") if not f.get("line") else f"{f.get('file', '?')}:{f.get('line')}"
        fh.write(f"   {where}: [{f.get('level', '?')}] {f.get('rule', '')}: {f.get('text', '')}"
                 f" (commit {f.get('commit', '?')})\0")
PY
)"
  sec_head="${sec_summary%%$'\n'*}"
  sec_findings=""
  while IFS= read -r -d '' sec_rec; do
    [[ -n "$sec_rec" ]] || continue
    if ! sec_esc="$(iso_safe_text "$sec_rec")"; then
      echo "refusing to land ${branch}: a lint finding could not be printed safely -- python3 is on PATH and iso_safe_text could not run it." >&2
      rm -f "$sec_report" "$sec_err" "$sec_find_file"
      exit 1
    fi
    sec_findings="${sec_findings}${sec_esc}"$'\n'
  done < "$sec_find_file"
  rm -f "$sec_find_file"
  IFS=$'\x1f' read -r sec_verdict sec_count sec_files sec_scanned_n sec_scanned_files sec_refused_in <<< "$sec_head"
  # what was scanned, on the receipt whatever the verdict: every path any commit touched
  sec_scanned_line="SEC_SCANNED=${sec_scanned_n:-0}"$'\n'"SEC_SCANNED_FILES=$(iso_safe_text "${sec_scanned_files:-}")"
  # a gate file changed: needs-eyes whatever the lint said (a refusal stays a refusal),
  # and the reviewer opens those files too
  if [[ -n "$gate_files" ]]; then
    case "$sec_verdict" in
      clean|needs-eyes)
        sec_verdict="needs-eyes"
        for f in $gate_files; do
          case " $sec_files " in
            *" $f "*) ;;
            *) sec_files="${sec_files}${sec_files:+ }${f}" ;;
          esac
        done
        sec_count=0
        for f in $sec_files; do sec_count=$(( sec_count + 1 )); done
        sec_gate="; gate files changed"
        ;;
    esac
  fi
  case "$sec_verdict" in
    clean)
      sec_line="clean"
      ;;
    nothing-to-scan)
      # no commit of the range touched a path: nothing was judged, which is not "clean"
      sec_line="nothing-to-scan"
      ;;
    needs-eyes)
      # sec_files stays as git spelled it -- the brief and the reviewer's checkout need
      # the real names -- and only the RECEIPT LINE is spelled out
      sec_line="needs-eyes (${sec_count} file(s) to review: $(iso_safe_text "$sec_files")${sec_gate})"
      if [[ -n "$sec_findings" ]]; then
        # already escaped, one record per line, with its own trailing newline
        { echo "note: tools/sec_lint.py wants eyes on:"; printf '%s' "$sec_findings"; } >&2
      fi
      if [[ -n "$gate_files" ]]; then
        echo "note: the diff changes gate file(s), so it is needs-eyes whatever the lint said: $(iso_safe_text "$gate_files")" >&2
      fi
      ;;
    refused)
      {
        echo "refusing to land ${branch}: tools/sec_lint.py refused the diff, in commit(s) $(iso_safe_text "${sec_refused_in:-?}") of the range:"
        [[ -n "$sec_findings" ]] && printf '%s' "$sec_findings"
        echo "Every commit is judged on its own, as the publisher judges it: a later commit that"
        echo "removes the line does not excuse the one that added it, because that commit would"
        echo "still be in ${base}'s history. Rebase or amend the branch so no commit carries it"
        echo "(git rebase -i ${base}), then run finish again. The worktree is untouched (already"
        echo "rebased onto ${base}); nothing moved."
      } >&2
      # a refusal is a receipt too (as a red test's is): what the landing measured, on stdout
      echo "MERGED=no"
      echo "SEC=refused (in commit(s) $(iso_safe_text "${sec_refused_in:-?}"))"
      printf '%s\n' "$sec_scanned_line"
      rm -f "$sec_report" "$sec_err"
      exit 1
      ;;
    *)
      { echo "refusing to land ${branch}: tools/sec_lint.py gave no verdict for a commit of the range:"
        landing_python - "$sec_report" <<'PY' 2>/dev/null || true
import json, sys
try:
    for b in json.load(open(sys.argv[1])).get("broken", []):
        print("   " + str(b))
except Exception:
    pass
PY
        cat "$sec_err"; } >&2
      echo "MERGED=no"
      echo "SEC=no-verdict"
      rm -f "$sec_report" "$sec_err"
      exit 1
      ;;
  esac
  rm -f "$sec_report" "$sec_err"
else
  # no lint, so no table -- but a diff that brings the scan tools themselves is said,
  # because those two names are the one thing this script knows about the gate
  for keep in tools/sec_lint.py tools/audit_scope.py; do
    if [[ -n "$(git -C "$worktree" diff --name-only --no-renames --diff-filter=ACMRDT "${base}..HEAD" -- "$keep")" ]]; then
      gate_files="${gate_files}${gate_files:+ }${keep}"
    fi
  done
  if [[ -n "$gate_files" ]]; then
    echo "note: ${base} has no tools/sec_lint.py, so the diff was not scanned; it changes gate file(s): $(iso_safe_text "$gate_files")" >&2
  fi
fi

# --- the invariant gate, beside the lint ------------------------------------------
# BASE's tools/invariants.py, with BASE's sec_lint.py beside it (the table lives there,
# not in the tree being judged). A BASE without the tool is INV=none and is not a
# refusal, the same shape as SEC=none. refused stops the landing before the merge.
inv_line="none"
if git -C "$worktree" cat-file -e "${base}:tools/invariants.py" 2>/dev/null; then
  inv_base="$(mktemp -d "${worktree}/.inv-base-XXXXXX")"
  mkdir -p "$inv_base/tools"
  git -C "$worktree" show "${base}:tools/invariants.py" > "$inv_base/tools/invariants.py"
  if git -C "$worktree" cat-file -e "${base}:tools/sec_lint.py" 2>/dev/null; then
    git -C "$worktree" show "${base}:tools/sec_lint.py" > "$inv_base/tools/sec_lint.py"
  fi
  inv_out="$(finish_tmp)"
  inv_err="$(finish_tmp)"
  set +e
  ( cd "$worktree" && landing_python "$inv_base/tools/invariants.py" --diff "${base}..HEAD" --json >"$inv_out" 2>"$inv_err" )
  inv_rc=$?
  set -e
  inv_meta="$(landing_python - "$inv_out" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    sys.stdout.write("refused\x1f\x1fthe gate printed no verdict")
    raise SystemExit(0)
changed = d.get("changed") or []
why = [str(n) for n in (d.get("notes") or [])]
for guard, marks in sorted((d.get("results_by_guard") or {}).items()):
    why.extend("%s %s: %s" % (guard, k, v) for k, v in sorted(marks.items()) if v != "pass")
sys.stdout.write(str(d.get("verdict") or "refused") + "\x1f" + " ".join(str(p) for p in changed)
                 + "\x1f" + "; ".join(why))
PY
)"
  inv_verdict="${inv_meta%%$'\x1f'*}"
  inv_rest="${inv_meta#*$'\x1f'}"
  inv_changed="${inv_rest%%$'\x1f'*}"
  inv_why="${inv_rest#*$'\x1f'}"
  if [[ -z "$inv_why" && -s "$inv_err" ]]; then
    inv_why="$(tail -n 3 "$inv_err" | tr '\n' ' ')"
  fi
  rm -rf "$inv_base"
  rm -f "$inv_out" "$inv_err"
  case "$inv_verdict" in
    clean|needs-eyes) ;;
    *) inv_verdict="refused" ;;
  esac
  if [[ "$inv_rc" != "0" ]]; then
    inv_verdict="refused"
  fi
  if [[ "$inv_verdict" == "refused" ]]; then
    echo "refusing to land ${branch}: tools/invariants.py refused the diff. The worktree is untouched; nothing moved." >&2
    if [[ -n "$inv_why" ]] && inv_why_safe="$(iso_safe_text "$inv_why")"; then
      echo "  why: ${inv_why_safe}" >&2
    fi
    echo "MERGED=no"
    echo "INV=refused"
    exit 1
  fi
  if [[ "$inv_verdict" == "needs-eyes" && -n "$inv_changed" ]]; then
    if ! inv_changed_safe="$(iso_safe_text "$inv_changed")"; then
      echo "refusing to land ${branch}: an invariant path could not be printed safely." >&2
      echo "MERGED=no"
      echo "INV=refused"
      exit 1
    fi
    inv_line="needs-eyes (${inv_changed_safe})"
  else
    inv_line="$inv_verdict"
  fi
fi

# --- the ledgers, regenerated on the tip ------------------------------------------
ledger_line="none (no tools/ledger.py in this repository)"
if [[ -f "$ledger_tool" ]]; then
  build_out="$(landing_python "$ledger_tool" --into "$worktree" build 2>&1)" || {
    echo "refusing to land ${branch}: tools/ledger.py build failed:" >&2
    printf '%s\n' "$build_out" >&2
    exit 1
  }
  if [[ -n "$(git -C "$worktree" status --porcelain)" ]]; then
    git -C "$worktree" add -A -- $generated 2>/dev/null || git -C "$worktree" add -A
    git -C "$worktree" commit -q -m "ledger: regenerate on landing ${branch}"
    ledger_line="regenerated ($(git -C "$worktree" rev-parse --short HEAD))"
  else
    ledger_line="current"
  fi
fi

base_wt="$(worktree_for_branch "$base" || true)"
if [[ -n "$base_wt" ]]; then
  if is_tracked_dirty "$base_wt"; then
    echo "base ${base} is checked out at ${base_wt} and has uncommitted changes; cannot merge" >&2
    # `|| true`, for the reason the same call carries at the first sink
    git -C "$base_wt" status -sb >&2 || true
    say_gitlink_state "$base_wt"
    exit 1
  fi
  merge_cwd="$base_wt"
else
  mkdir -p "${primary}/.worktrees"
  tmp_merge="${primary}/.worktrees/.merge-${base}"
  if [[ -e "$tmp_merge" ]]; then
    echo "temp merge worktree already exists: ${tmp_merge}" >&2
    exit 1
  fi
  git -C "$primary" worktree add "$tmp_merge" "$base"
  merge_cwd="$tmp_merge"
fi

base_before="$(git -C "$merge_cwd" rev-parse "$base")"
if git -C "$merge_cwd" merge-base --is-ancestor "$branch" "$base"; then
  echo "BRANCH=${branch} already contained in ${base}"
  merge_kind="already"
  merged="yes"
else
  # The SECOND sink, guarded exactly like the first. `is_tracked_dirty` above sees only
  # TRACKED changes; what the branch would CREATE in this checkout is nobody's business
  # but this check's, and the file it lands on is a running node's live private state
  # (keys/, data/, agents.d/, node.env are ignored HERE, inside the very checkout the
  # merge writes into). The range is the branch's own: base_before..branch.
  merge_rc=0
  merge_collides="$(ff_collisions "$merge_cwd" "${base_before}..${branch}")" || merge_rc=$?
  if [[ "$merge_rc" == "3" ]]; then
    {
      echo "refusing to land ${branch}: merging it into ${base} would have overwritten"
      echo "path(s) already on disk in ${merge_cwd}, and this landing could not print them --"
      echo "python3 is on PATH and iso_safe_text could not run it, so a name the branch chose"
      echo "would reach your terminal unescaped. A landing that cannot print a name safely"
      echo "does not print it at all; ${base} was not merged and ${worktree} is as it was."
    } >&2
    exit 1
  fi
  if [[ "$merge_rc" != "0" ]]; then
    {
      echo "refusing to land ${branch}: could not list the paths merging it into ${base}"
      echo "would create (git diff --diff-filter=A over ${base_before}..${branch} failed,"
      echo "its words above), so the on-disk check never ran. A guard that cannot run its"
      echo "own check refuses the landing rather than conclude that nothing is in the way;"
      echo "${base} was not merged and ${worktree} is as it was."
    } >&2
    exit 1
  fi
  if [[ -n "$merge_collides" ]]; then
    {
      echo "refusing to land ${branch}: merging it into ${base} would have overwritten"
      echo "path(s) already on disk in ${merge_cwd} that git does not track there -- an"
      echo "untracked or ignored file, or a directory holding one, which is listed with"
      echo "what is under it:"
      printf '%s\n' "$merge_collides"
      echo "git deletes an IGNORED file to make room for an incoming tracked blob, so a"
      echo "running node's live state (keys/, data/, agents.d/, node.env) goes with it --"
      echo "and a branch reaches this sink with such a path because 'git add -f' puts it"
      echo "there past the ignore rule. Move those paths aside yourself, or drop them from"
      echo "the branch, then run finish again; ${base} was not merged and ${worktree} is"
      echo "as it was."
    } >&2
    exit 1
  fi
  if git -C "$merge_cwd" -c advice.diverging=false merge --ff-only --no-verify "$branch"; then
    merge_kind="fast-forward"
  else
    if ! git -C "$merge_cwd" merge --no-edit --no-verify "$branch"; then
      git -C "$merge_cwd" merge --abort >/dev/null 2>&1 || true
      echo "merge into ${base} failed; ${branch} was not merged" >&2
      exit 1
    fi
    merge_kind="commit"
  fi
  # from here on BASE carries the branch permanently: every later exit says so
  merged="yes"
fi
base_tip="$(git -C "$merge_cwd" rev-parse "$base")"

# This script never pushes BASE. Two reasons, both load-bearing:
#   1. CLAUDE.md step 4 -- "Pushing still requires an explicit ask."
#   2. No process of the owner's user may hold a GitHub credential, so publishing
#      is not this script's to do: BASE goes to the local hand-off remote below,
#      and the PUBLISHER -- another user, the only holder of a token -- scans the
#      range and pushes (company/ops/publisher/README.md).
# This is not in tension with the fast-forward above: that moves a LOCAL ref to a
# ref that came FROM origin, which is how a landing descends from what the other
# primary published. Landing BASE on the remote is still the trunk owner's
# deliberate act, not a side effect of finishing a session.
pushed="no"

cd "$primary"
if [[ "$worktree" == "$primary" ]]; then
  git switch "$base"
else
  git worktree remove "$worktree"
fi
if git merge-base --is-ancestor "$branch" "$base"; then
  git branch -D "$branch"
else
  echo "refusing to delete ${branch}: not merged into ${base}" >&2
  exit 1
fi
if git remote get-url origin >/dev/null 2>&1; then
  if git ls-remote --exit-code origin "refs/heads/${branch}" >/dev/null 2>&1; then
    # the landing's own cleanup of a session branch that reached origin: the one push a
    # landing makes, never of BASE, and the pre-push hook must let it through
    ISOLATED_SESSION_PUSH=1 git push origin --delete "$branch" || true
  fi
fi
# The session worktree is gone and the branch deleted: the landing is done. What is still
# held -- the Room lease and the local lock -- is held on purpose until the publisher has
# answered (below), so from here an exit releases them and says nothing else: the
# on_exit notes are about a landing that did not finish, and this one did.
if [[ -n "$tmp_merge" ]]; then
  git -C "$primary" worktree remove --force "$tmp_merge" >/dev/null 2>&1 || true
  tmp_merge=""
fi
trap 'cleanup || true' EXIT

echo "MERGED=yes"
echo "MERGE_KIND=${merge_kind}"
echo "BASE_FF=${base_ff_line}"
[[ -n "$base_rebase_line" ]] && echo "BASE_REBASE=${base_rebase_line}"
echo "REBASED=${rebased}"
echo "LANDING_LOCK=waited ${waited}s"
echo "TESTS=${tests_line}"
[[ -n "$tests_secs" ]] && echo "TESTS_SECS=${tests_secs}"
[[ -n "$tests_files" ]] && echo "TESTS_FILES=$(iso_safe_text "$tests_files")"
# names are tests/test_x.py: that is how the runner spells a file, and the receipt
# prints them with every invisible code point spelled out (iso_safe_text) -- a test file
# is a name the diff chose, and this line is read in a terminal
echo "SEC=${sec_line}"
echo "INV=${inv_line}"
[[ -n "$sec_scanned_line" ]] && printf '%s\n' "$sec_scanned_line"
echo "LEDGER=${ledger_line}"
echo "BASE=${base}"
echo "BRANCH=${branch}"
echo "PRIMARY=${primary}"
echo "PUSHED=${pushed}"
# The hand-off: when the primary has a `handoff` remote (setup-handoff.sh), BASE goes
# there -- a bare repository on this machine, no credential -- for the publisher, another
# user with the only GitHub token, to evaluate and push (company/ops/publisher/README.md).
# Never a failed landing: the line says what happened.
#
# --- held until published ------------------------------------------------------------
# The landing lease serializes two Macs' LANDINGS, but a landing that released it at the
# hand-off push left the gap it exists to close: the other Mac could take the lease, land
# and publish before this Mac's publisher ran, and this hand-off was then "not a
# fast-forward of origin" -- held until a person rebased it (plan 2026-09-19-multi-mac-appl,
# M1). So while a lease is held and the hand-off took the push, the lease (and the local
# lock, because a round below moves local BASE) is kept until the publisher's status file
# answers for THIS push:
#   * `when=` strictly newer than the second the push started -- a status left by an
#     earlier landing, or written in the same second, never counts -- AND, when the
#     status names a `handoff=`, that it is exactly the tip pushed (a clock cannot confuse
#     that one);
#   * result=published or result=up-to-date: released, PUBLISH=<that>;
#   * result=held because it is not a fast-forward: a ROUND -- origin is read again (the
#     fetch, else the publisher's bundle), local BASE's unpublished commits are rebased
#     onto it in a scratch checkout, the tests the rebased range owes run there, BASE's
#     lint refuses what it refuses, the ledger is rebuilt, and only then does local BASE
#     move and the hand-off take it (leased on the tip it had). At most two rounds after
#     the original push, three pushes in all; a third "not a fast-forward", a conflicting
#     rebase, red tests, or anything else a round cannot finish ends as HANDOFF=held with
#     the reason, local BASE left at the tip the hand-off holds, and exit 0 -- the landing
#     itself happened, and a person picks the hand-off up from the receipt;
#   * nothing of the above within LANDING_PUBLISH_WAIT_S (default 300) of a push:
#     PUBLISH=timeout, released. Any other status (held for a review, an error) is waited
#     out the same way: it is not this Mac's to fix by rebasing.
# No lease, or no hand-off push: no wait at all, as before.
publish_verdict() {  # $1 status file, $2 epoch the push started, $3 the tip pushed
  landing_python - "$1" "$2" "$3" <<'PY'
import sys
from datetime import datetime
path, since, tip = sys.argv[1], int(sys.argv[2]), sys.argv[3]
try:
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
except OSError:
    print("pending")
    sys.exit(0)
fields = {}
for line in text.splitlines():
    key, sep, value = line.partition("=")
    if sep and key not in fields:
        fields[key] = value.strip()
try:
    when = datetime.strptime(fields.get("when", ""), "%Y-%m-%dT%H:%M:%S%z").timestamp()
except ValueError:
    print("pending")          # a when= nobody can read does not count
    sys.exit(0)
if when <= since:
    print("pending")          # older than this push, or the same second: not about it
    sys.exit(0)
named = fields.get("handoff", "")
if named and named != tip:
    print("pending")          # about some other tip
    sys.exit(0)
result = fields.get("result", "")
if result in ("published", "up-to-date"):
    print(result)
elif result == "held" and "not a fast-forward" in fields.get("reason", ""):
    print("not-ff")
else:
    print("pending")
PY
}

# Polls until the status answers for the push, or LANDING_PUBLISH_WAIT_S has passed since
# it. Sets pw_result: published, up-to-date, not-ff or timeout.
publish_wait() {  # $1 epoch the push started, $2 epoch it finished, $3 the tip pushed
  local pwv="" pw_now=""
  while :; do
    pwv="$(publish_verdict "$pw_status" "$1" "$3" 2>/dev/null)" || pwv="pending"
    case "$pwv" in
      published|up-to-date|not-ff) pw_result="$pwv"; return 0 ;;
    esac
    pw_now="$(date +%s)"
    # strictly past: `date +%s` is whole seconds, so this holds for at least the full wait
    if (( pw_now > $2 + publish_wait_s )); then
      pw_result="timeout"
      return 0
    fi
    sleep 1
  done
}

# origin/BASE again, the way the landing read it: lib.sh:iso_origin_view, the one rule --
# which also takes only a fast-forward of what this repository already has. Its refusal
# (stale, mismatched, missing, older than what we have) is kept for pw_why.
pw_reread_why=""
publish_reread_origin() {
  local rr_err=""
  rr_err="$(finish_tmp)"
  if iso_origin_view "$primary" "$base" 2>"$rr_err"; then
    rm -f "$rr_err"
    return 0
  fi
  pw_reread_why="$(grep -i "refusing" "$rr_err" 2>/dev/null | head -1 | sed 's/^iso_origin_view: refusing: //')" ||
    pw_reread_why=""
  rm -f "$rr_err"
  return 1
}

# Puts local BASE back at $1 after a round moved it and the hand-off would not take it.
publish_put_back() {  # $1 sha, $2 the checkout that has BASE ("" for none)
  if [[ -n "$2" ]]; then
    git -C "$2" reset --quiet --keep "$1" >/dev/null 2>&1 || true
  else
    git -C "$primary" update-ref "refs/heads/${base}" "$1" >/dev/null 2>&1 || true
  fi
}

# One round. 0: the hand-off took the rebased BASE -- pw_tip, pw_since and pw_pushed are
# the new push. 1: pw_why says why not, and local BASE and the hand-off are where they
# were. Runs as the condition of an `if`, so `set -e` is off inside and every step is
# checked by hand. `worktree` is shadowed with the primary: the session worktree is gone,
# and worktree_for_branch and ff_collisions ask git from it.
publish_round() {
  local worktree="$primary"
  local pr_old="" pr_onto="" pr_wt="" pr_new="" pr_conf="" pr_one="" pr_only="" pr_gd=""
  local pr_names="" pr_rc=0 pr_base_wt="" pr_hits="" pr_sec="" pr_extra="" pr_err=""
  pr_old="$(git -C "$primary" rev-parse "$base")" || { pw_why="could not read ${base}"; return 1; }
  if [[ "$pr_old" != "$pw_tip" ]]; then
    pw_why="${base} moved during the wait (${pr_old:0:7}, the hand-off holds ${pw_tip:0:7})"
    return 1
  fi
  if ! publish_reread_origin; then
    pw_why="origin could not be read again ($(iso_safe_text "${pw_reread_why:-no reason given}" || printf 'a reason that could not be printed safely'))"
    return 1
  fi
  pr_onto="$(git -C "$primary" rev-parse --verify --quiet "$remote_base")" || {
    pw_why="there is no ${remote_base} to rebase onto"
    return 1
  }
  if git -C "$primary" merge-base --is-ancestor "$pr_onto" "$pr_old"; then
    pw_why="the publisher says not a fast-forward, but ${remote_base} as read again (${pr_onto:0:7}) is already in ${base}"
    return 1
  fi

  # the rebase, in a detached scratch checkout: local BASE does not move until the
  # rebased tree has passed everything below
  mkdir -p "${primary}/.worktrees"
  pr_wt="${primary}/.worktrees/.publish-${base}"
  if [[ -e "$pr_wt" ]]; then
    pw_why="a scratch checkout is already at ${pr_wt}"
    return 1
  fi
  if ! git -C "$primary" worktree add --quiet --detach "$pr_wt" "$pr_old" >/dev/null 2>&1; then
    pw_why="could not open ${base} in a scratch checkout to rebase it"
    return 1
  fi
  tmp_publish="$pr_wt"
  if ! GIT_EDITOR=true git -C "$pr_wt" -c rebase.updateRefs=false -c rebase.autoStash=false \
         -c rebase.autoSquash=false rebase --quiet "$pr_onto" >/dev/null 2>&1; then
    # a conflict confined to the generated files has one right answer, the ledger rebuilt
    # on this tree (as in self_rebase_base); any other stops the round
    while :; do
      pr_conf="$(git -C "$pr_wt" -c core.quotepath=false diff --name-only --diff-filter=U)"
      [[ -n "$pr_conf" ]] || break
      pr_only="yes"
      while IFS= read -r pr_one; do
        [[ -n "$pr_one" ]] || continue
        case " $generated " in
          *" $pr_one "*) ;;
          *) pr_only="no" ;;
        esac
      done <<< "$pr_conf"
      [[ "$pr_only" == "yes" && -f "$gate_ledger" ]] || break
      landing_python "$gate_ledger" --into "$pr_wt" build >/dev/null 2>&1 || break
      for pr_one in $generated; do
        if [[ -e "$pr_wt/$pr_one" ]] ||
           git -C "$pr_wt" ls-files --error-unmatch -- "$pr_one" >/dev/null 2>&1; then
          git -C "$pr_wt" add -A -- "$pr_one" >/dev/null 2>&1 || true
        fi
      done
      [[ -z "$(git -C "$pr_wt" diff --name-only --diff-filter=U)" ]] || break
      if ! GIT_EDITOR=true git -C "$pr_wt" -c rebase.updateRefs=false rebase --continue >/dev/null 2>&1; then
        if [[ -z "$(git -C "$pr_wt" diff --name-only --diff-filter=U)" ]]; then
          GIT_EDITOR=true git -C "$pr_wt" rebase --skip >/dev/null 2>&1 || true
        fi
      fi
      pr_gd="$(git -C "$pr_wt" rev-parse --git-dir)"
      [[ -d "$pr_gd/rebase-merge" || -d "$pr_gd/rebase-apply" ]] || break
    done
    pr_gd="$(git -C "$pr_wt" rev-parse --git-dir)"
    if [[ -n "$(git -C "$pr_wt" diff --name-only --diff-filter=U)" ||
          -d "$pr_gd/rebase-merge" || -d "$pr_gd/rebase-apply" ]]; then
      pr_conf="$(git -C "$pr_wt" -c core.quotepath=false diff --name-only --diff-filter=U)"
      while IFS= read -r pr_one; do
        [[ -n "$pr_one" ]] || continue
        pr_names="${pr_names}${pr_names:+ }$(iso_safe_text "$pr_one" 2>/dev/null || printf '(a path this landing could not print safely)')"
      done <<< "$pr_conf"
      pw_why="rebasing ${base} onto ${remote_base} (${pr_onto:0:7}) conflicts in: ${pr_names:-(no path named)}"
      cleanup_publish_wt
      return 1
    fi
  fi
  pr_new="$(git -C "$pr_wt" rev-parse HEAD)"
  if ! git -C "$primary" merge-base --is-ancestor "$pr_onto" "$pr_new"; then
    pw_why="the rebased ${base} does not descend from ${remote_base}"
    cleanup_publish_wt
    return 1
  fi

  # the tests the rebased range owes, on the rebased tree -- run by the gate's runner, not
  # the copy the merge just put on BASE
  if [[ -f "$gate_runner" && "${ISOLATED_SESSION_LAND_TESTS:-1}" != "0" ]]; then
    pr_rc=0
    ( cd "$pr_wt" && branch_tests_python "$gate_runner" --root "$pr_wt" --affected "${pr_onto}..HEAD" --gate --json \
        -j "${ISOLATED_SESSION_LAND_JOBS:-4}" ) >/dev/null 2>&1 || pr_rc=$?
    if [[ "$pr_rc" != "0" ]]; then
      pw_why="the tests went red on ${base} rebased onto ${remote_base} (${pr_onto:0:7}; tools/run_tests.py exit ${pr_rc})"
      cleanup_publish_wt
      return 1
    fi
    if [[ -n "$(git -C "$pr_wt" status --porcelain)" ]]; then
      pw_why="the tests left the rebased tree dirty"
      cleanup_publish_wt
      return 1
    fi
  fi

  # BASE's lint (as it was before this landing), over what the rebase rewrote; only a
  # refusal stops the round -- needs-eyes was this landing's, and is on its REVIEW= line
  if git -C "$primary" cat-file -e "${base_before}:tools/sec_lint.py" 2>/dev/null; then
    pr_sec="$(mktemp -d "${pr_wt}/.sec-base-XXXXXX")" || { pw_why="could not stage the lint"; cleanup_publish_wt; return 1; }
    mkdir -p "$pr_sec/tools" "$pr_sec/company/ops"
    for pr_extra in tools/sec_lint.py tools/audit_scope.py tools/ledger.py tools/backlog_build.py \
                    tools/spec_build.py company/ops/backlog_to_core.py; do
      if git -C "$primary" cat-file -e "${base_before}:${pr_extra}" 2>/dev/null; then
        mkdir -p "$pr_sec/$(dirname "$pr_extra")"
        git -C "$primary" show "${base_before}:${pr_extra}" > "$pr_sec/${pr_extra}" 2>/dev/null || true
      fi
    done
    # every commit of what the rebase rewrote, as the publisher will judge them
    # (sec_scan_commits), never the net diff
    pr_rc=0
    pr_json="$(finish_tmp)" || { pw_why="could not stage the lint"; rm -rf "$pr_sec"; cleanup_publish_wt; return 1; }
    pr_paths="$(finish_tmp)" || { pw_why="could not stage the lint"; rm -rf "$pr_sec" "$pr_json"; cleanup_publish_wt; return 1; }
    sec_scan_commits "$pr_wt" "$pr_sec/tools/sec_lint.py" "$pr_onto" "$pr_json" "$pr_paths" >/dev/null 2>&1 || pr_rc=$?
    if [[ "$pr_rc" == "0" ]] &&
       landing_python -c 'import json,sys; sys.exit(0 if json.load(open(sys.argv[1]))["verdict"] == "refused" else 1)' \
         "$pr_json" 2>/dev/null; then
      pr_rc=2
    fi
    rm -rf "$pr_sec" "$pr_json" "$pr_paths"
    if [[ "$pr_rc" == "2" ]]; then
      pw_why="tools/sec_lint.py refused a commit of ${base} rebased onto ${remote_base}"
      cleanup_publish_wt
      return 1
    fi
  fi

  # the ledgers, rebuilt on the rebased tip
  if [[ -f "$gate_ledger" ]]; then
    if ! landing_python "$gate_ledger" --into "$pr_wt" build >/dev/null 2>&1; then
      pw_why="tools/ledger.py build failed on the rebased tree"
      cleanup_publish_wt
      return 1
    fi
    if [[ -n "$(git -C "$pr_wt" status --porcelain)" ]]; then
      git -C "$pr_wt" add -A -- $generated >/dev/null 2>&1 || git -C "$pr_wt" add -A >/dev/null 2>&1
      if ! git -C "$pr_wt" commit -q -m "ledger: regenerate on landing ${branch} (rebased onto ${remote_base})" >/dev/null 2>&1; then
        pw_why="could not commit the rebuilt ledger on the rebased tree"
        cleanup_publish_wt
        return 1
      fi
      pr_new="$(git -C "$pr_wt" rev-parse HEAD)"
    fi
  fi
  cleanup_publish_wt

  # local BASE moves only now, under the guards every move of it has
  pr_base_wt="$(worktree_for_branch "$base" || true)"
  if [[ -n "$pr_base_wt" ]]; then
    if is_tracked_dirty "$pr_base_wt"; then
      pw_why="${base} is checked out at ${pr_base_wt} with uncommitted changes"
      return 1
    fi
    pr_rc=0
    pr_hits="$(ff_collisions "$pr_base_wt" "${pr_old}..${pr_new}")" || pr_rc=$?
    if [[ "$pr_rc" != "0" ]]; then
      pw_why="could not list (or could not safely print) what the rebased ${base} would write into ${pr_base_wt}"
      return 1
    fi
    if [[ -n "$pr_hits" ]]; then
      { echo "note: the rebased ${base} would overwrite path(s) on disk in ${pr_base_wt} that git does not track there:"; printf '%s\n' "$pr_hits"; } >&2
      pw_why="the rebased ${base} would overwrite untracked or ignored path(s) in ${pr_base_wt} (listed above)"
      return 1
    fi
    if ! git -C "$pr_base_wt" reset --quiet --keep "$pr_new" >/dev/null 2>&1; then
      publish_put_back "$pr_old" "$pr_base_wt"
      pw_why="could not move ${base} to the rebased tip in ${pr_base_wt}"
      return 1
    fi
  elif ! git -C "$primary" update-ref "refs/heads/${base}" "$pr_new" "$pr_old" >/dev/null 2>&1; then
    pw_why="could not move ${base} to the rebased tip"
    return 1
  fi

  # the hand-off takes it, leased on the tip it holds: it overwrites only what we pushed
  pr_err="$(finish_tmp)"
  pw_since="$(date +%s)"
  if ! ISOLATED_SESSION_PUSH=1 git -C "$primary" push --quiet \
         --force-with-lease="refs/heads/${base}:${pr_old}" handoff "${base}:refs/heads/${base}" \
         >/dev/null 2>"$pr_err"; then
    publish_put_back "$pr_old" "$pr_base_wt"
    pw_why="the hand-off would not take the rebased ${base}: $(iso_safe_text "$(tail -1 "$pr_err" 2>/dev/null || true)" 2>/dev/null || true)"
    rm -f "$pr_err"
    return 1
  fi
  rm -f "$pr_err"
  pw_pushed="$(date +%s)"
  pw_tip="$pr_new"
  return 0
}

cleanup_publish_wt() {
  if [[ -n "$tmp_publish" ]]; then
    git -C "$tmp_publish" rebase --abort >/dev/null 2>&1 || true
    git -C "$primary" worktree remove --force "$tmp_publish" >/dev/null 2>&1 || true
    tmp_publish=""
  fi
}

handoff_line="none (no handoff remote)"
publish_line=""
handoff_took="no"
if handoff_url="$(git -C "$primary" remote get-url handoff 2>/dev/null)"; then
  handoff_err="$(finish_tmp)"
  pw_since="$(date +%s)"
  if ISOLATED_SESSION_PUSH=1 git -C "$primary" push --quiet handoff "${base}:refs/heads/${base}" >/dev/null 2>"$handoff_err"; then
    handoff_line="pushed ${base_tip} to ${handoff_url}"
    handoff_took="yes"
  else
    handoff_line="failed: $(tail -1 "$handoff_err" 2>/dev/null | tr -d '\r' | cut -c1-200)"
  fi
  rm -f "$handoff_err"
fi
if [[ "$handoff_took" == "yes" && "$lease_held" == "yes" ]]; then
  pw_pushed="$(date +%s)"
  pw_status=""
  if [[ -n "${LANDING_PUBLISHER_STATUS:-}" ]]; then
    pw_status="$LANDING_PUBLISHER_STATUS"
  elif pw_name="$(iso_publisher_name "$primary")"; then
    pw_status="${ISO_PUBLISHER_STATE}/status/${pw_name}.txt"
  fi
  if [[ -z "$pw_status" ]]; then
    publish_line="not-waited (the hand-off remote names no publisher repository, so there is no status to read)"
  else
    pw_tip="$base_tip"
    pw_rounds=0
    pw_result=""
    pw_why=""
    echo "note: holding the landing lease until the publisher answers for ${pw_tip:0:12} (LANDING_PUBLISH_WAIT_S=${publish_wait_s})" >&2
    while :; do
      publish_wait "$pw_since" "$pw_pushed" "$pw_tip"
      case "$pw_result" in
        published|up-to-date|timeout)
          publish_line="$pw_result"
          break
          ;;
      esac
      # not a fast-forward of origin
      if (( pw_rounds >= 2 )); then
        handoff_line="held -- the publisher held ${pw_tip:0:12} as not a fast-forward of origin after ${pw_rounds} rebase round(s); ${base} is at that tip, which the hand-off holds"
        break
      fi
      pw_rounds=$(( pw_rounds + 1 ))
      echo "note: the publisher held ${pw_tip:0:12} as not a fast-forward of origin; rebasing onto ${remote_base} again (round ${pw_rounds} of 2)" >&2
      if publish_round; then
        handoff_line="pushed ${pw_tip} to ${handoff_url} (rebased onto ${remote_base}, round ${pw_rounds})"
        continue
      fi
      handoff_line="held -- round ${pw_rounds}: ${pw_why}; ${base} is at ${pw_tip:0:12}, which the hand-off holds"
      break
    done
  fi
fi
cleanup
trap - EXIT
echo "HANDOFF=${handoff_line}"
[[ -n "$publish_line" ]] && echo "PUBLISH=${publish_line}"
if [[ "$lease_did_hold" == "yes" ]]; then
  echo "LEASE=released"
fi
echo "WORKTREE_REMOVED=yes"

# --- the human half of the scan: a reviewer session -------------------------------
# The landing is done and its lock released; what follows can neither block nor fail
# it. A needs-eyes landing renders the per-landing reviewer brief and hands it to
# herd-spawn.sh; when herdr is absent or down (or the operator set
# ISOLATED_SESSION_LAND_REVIEW=0) the receipt carries the command to run by hand
# instead, because the review is owed either way.
#
# The template and the spawner come out of BASE's blobs at the sha it had BEFORE this
# landing (`git show base_before:path`), never from the primary's working tree: the
# fast-forward above moved that tree to the landed tip, so its copies are the branch's,
# and a branch that rewrote the brief or the spawner would otherwise be reviewed under
# its own brief, or not reviewed at all with a receipt that says it was.
review_line="none"
# The cadence: `.security/review-cadence` saying `daily` defers the review to
# tools/security_daily.sh, which reads the whole day's range once (the owner's choice,
# 2026-09-13: a reviewer per landing spent most of a week's subscription in a day);
# ISOLATED_SESSION_LAND_REVIEW, when set, still decides for this landing alone.
#
# Read out of BASE's blob at the sha it had BEFORE this landing, like every other gate
# input (the lint, the brief, the spawner), and never off the working tree: the merge
# above has just moved that tree to the landed tip, so a branch that ADDS `daily` made
# its OWN landing say REVIEW=deferred and spawn nothing -- and in a vendored copy with no
# daily LaunchAgent that is "no review at all". Absent in BASE means a reviewer per
# landing, as before.
review_cadence="$(git -C "$primary" show "${base_before}:.security/review-cadence" 2>/dev/null | tr -d '[:space:]')" || review_cadence=""
if [[ "$sec_verdict" == "needs-eyes" && "$base_before" != "$base_tip" && -z "${ISOLATED_SESSION_LAND_REVIEW+set}" && "$review_cadence" == "daily" ]]; then
  review_line="deferred -- daily cadence (${base}:.security/review-cadence at $(git -C "$primary" rev-parse --short=7 "$base_before")): tools/security_daily.sh reads the day's landings as one range, and the publisher waits for its receipt"
elif [[ "$sec_verdict" == "needs-eyes" && "$base_before" != "$base_tip" ]]; then
  # herdr names an agent with [a-z][a-z0-9_-]{0,31}: "secrev-" leaves 25 for the slug
  review_slug="$(printf '%s' "${branch#*/}" | tr 'A-Z' 'a-z' | tr -c 'a-z0-9-' '-' | tr -s '-')"
  # 20 characters of slug plus four of the landed tip: two branches that share a prefix
  # get two names, two checkouts and two briefs
  # (ISSUE(security-audit-2026-09-12-the-reviewer-opens-in-a-c-6))
  review_slug="${review_slug:0:20}"
  review_slug="${review_slug#-}"
  review_slug="${review_slug%-}"
  review_slug="${review_slug}-$(printf '%s' "$base_tip" | cut -c1-4)"
  review_name="secrev-${review_slug}"
  # empty when neither HERD_DIR nor HOME is set: said on the REVIEW= line below, never
  # a nounset error after the merge (ISSUE(security-audit-2026-09-12-the-cleanup-trusts-n-d474-4))
  herd_dir="$(iso_herd_dir || true)"
  # absolute, so the rules herd-spawn.sh writes from it name real paths
  [[ -z "$herd_dir" || "$herd_dir" == /* ]] || herd_dir="$(pwd)/${herd_dir}"
  review_brief="${herd_dir}/briefs/${review_name}.md"
  # The reviewer opens in a checkout of main as it was BEFORE this landing: its
  # SessionStart hook, its scripts and its settings are the ones main had, not the
  # branch's (a diff that edits session-guard.sh would otherwise run as the reviewer
  # spawns), and no .claude/settings.local.json lives there
  # (ISSUE(security-audit-2026-09-12-the-reviewer-sandbox-an-e-2), -3).
  # ... and OUTSIDE the primary: Claude Code reads CLAUDE.md from every parent directory,
  # and the primary's is the landed tip's (-4); under HERD_DIR it collides with no session
  # worktree either (-1)
  review_root="${herd_dir}/review"
  review_co="${review_root}/${review_name}"
  template_rel=".claude/skills/security-audit/references/landing-review-brief.md"
  spawner_rel=".cursor/skills/isolated-session/scripts/herd-spawn.sh"
  lib_rel=".cursor/skills/isolated-session/scripts/lib.sh"
  # The reviewer's checkout is ON A BRANCH of its own at the pre-landing BASE: the receipt
  # branch ensure-worktree.sh names for "Audit receipt for landing <slug>", held under the
  # reviewer's owner key (herd-spawn's default for a walled spawn: the worker's name). A
  # detached checkout recorded no branch, so the walled reviewer got no gate, and behind the
  # wall it could not open a worktree of its own to land from
  # (ISSUE(walled-reviewer-cannot-write-its-receipt)).
  receipt_task="Audit receipt for landing ${review_slug}"
  receipt_branch="feat/$(iso_task_slug "$receipt_task" 2>/dev/null || true)"
  run_hint="bash ${spawner_rel} ${review_name} ${review_brief} --profile reviewer --cwd ${review_co} --var MAIN=${primary} --env ISOLATED_SESSION_OWNER=${review_name}, in a checkout on ${receipt_branch} at ${base_before} (when it is not there: ISOLATED_SESSION_OWNER=${review_name} bash ${spawner_rel%/*}/ensure-worktree.sh --at ${base_before} --into ${review_co} '${receipt_task}'); the reviewer lands its receipt from that checkout with bash ${spawner_rel%/*}/finish-worktree.sh ${receipt_branch} ${review_co}"
  by_hand="run the security-audit skill over ${base_before}..${base_tip} by hand"
  # HERD_DIR is where a prompt for an autonomous session is written: ours, mode 700
  # when this creates it, refused when someone else owns it, and refused when a
  # directory above it is writable by others (a CLAUDE.md there would reach the
  # reviewer, whose cwd is under it). Nothing in this section may end the landing:
  # the merge is done, and a REVIEW= line is owed whatever stands at these paths
  # (ISSUE(security-audit-2026-09-12-the-review-checkout-lives-3), -4).
  if [[ -n "$herd_dir" && ! -e "$herd_dir" ]]; then
    mkdir -p "$herd_dir" 2>/dev/null && chmod 700 "$herd_dir" 2>/dev/null || true
  fi
  if [[ -z "$herd_dir" ]]; then
    review_line="needed -- neither HERD_DIR nor HOME is set, so there is no herd directory; ${by_hand}"
  elif [[ -L "$herd_dir" || ! -d "$herd_dir" || ! -O "$herd_dir" ]]; then
    review_line="needed -- ${herd_dir} is not a directory owned by $(id -un) (HERD_DIR); ${by_hand}"
  elif ! open_dir="$(iso_private_path "$herd_dir")"; then
    review_line="needed -- ${open_dir}, at or above ${herd_dir}, is writable by others (a CLAUDE.md there would reach the reviewer); set HERD_DIR under your home; ${by_hand}"
  elif ! git -C "$primary" cat-file -e "${base_before}:${template_rel}" 2>/dev/null; then
    review_line="needed -- no ${template_rel} in ${base} before this landing; ${by_hand}"
  elif [[ -L "${herd_dir}/briefs" || ( -e "${herd_dir}/briefs" && ! -d "${herd_dir}/briefs" ) || ( -d "${herd_dir}/briefs" && ! -O "${herd_dir}/briefs" ) ]]; then
    review_line="needed -- ${herd_dir}/briefs is a symlink, a file, or not ours; ${by_hand}"
  elif [[ ! -d "${herd_dir}/briefs" ]] && ! mkdir -m 700 "${herd_dir}/briefs" 2>/dev/null; then
    review_line="needed -- could not create ${herd_dir}/briefs; ${by_hand}"
  elif ! review_tpl="$(finish_tmp)" || ! git -C "$primary" show "${base_before}:${template_rel}" > "$review_tpl" 2>/dev/null; then
    review_line="needed -- could not read ${template_rel} from ${base_before}; ${by_hand}"
  else
    # One pass over the placeholders with a dict, never sequential replaces (a value
    # is never re-scanned for a later key). FILES and BRANCH are data the diff chose:
    # rendered as backticked paths with any backtick, brace pair or newline removed.
    if landing_python - "$review_tpl" "$review_brief" "NAME=${review_name}" "BASE=${base_before}" \
         "TIP=${base_tip}" "BRANCH=${branch}" "SLUG=${review_slug}" "FILES=${sec_files}" \
         "PRIMARY=${review_co}" "MAIN=${primary}" "BASE_FROM=the pre-landing base" <<'PY'
import os, re, sys
src, dst = sys.argv[1], sys.argv[2]
text = open(src, encoding="utf-8").read()
values = {}
for kv in sys.argv[3:]:
    key, _, value = kv.partition("=")
    values[key] = value


def as_data(s):
    # markdown-safe AND shell-safe: a branch name or a path reaches the brief as prose
    # only, never inside a command, but a reviewer may still paste it -- so nothing that
    # chains, substitutes, quotes or comments survives
    # (ISSUE(security-audit-2026-09-12-the-landing-judges-a-diff-4))
    s = s.replace("`", "").replace("\r", " ").replace("\n", " ")
    while "{{" in s or "}}" in s:
        s = s.replace("{{", "").replace("}}", "")
    s = "".join(ch if (ch.isalnum() or ch in "._/-+@:, ") else "-" for ch in s)
    return s


paths = [as_data(p) for p in values.get("FILES", "").split() if p]
values["FILES"] = ", ".join("`" + p + "`" for p in paths) or "(none)"
values["BRANCH"] = as_data(values.get("BRANCH", ""))
values["BASE_FROM"] = as_data(values.get("BASE_FROM", ""))


def fill(m):
    # a key the landing does not know ({{REPORT}}) is herd-spawn.sh's to fill; it stays
    return values.get(m.group(1), m.group(0))


# the exact path is unlinked (a planted symlink goes, its target stays) and the file is
# created O_EXCL, mode 600 -- the same write herd-spawn.sh does for its own copy
# (ISSUE(security-audit-2026-09-12-the-reviewer-sandbox-an-e-4))
out = re.sub(r"\{\{([A-Z][A-Z0-9_]*)\}\}", fill, text)
if os.path.lexists(dst):
    os.unlink(dst)
fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    f.write(out)
PY
    then
      rm -f "$review_tpl"
      if [[ "${ISOLATED_SESSION_LAND_REVIEW:-1}" == "0" ]]; then
        review_line="needed -- ISOLATED_SESSION_LAND_REVIEW=0; run: ${run_hint}"
      elif ! git -C "$primary" cat-file -e "${base_before}:${spawner_rel}" 2>/dev/null ||
           ! git -C "$primary" cat-file -e "${base_before}:${lib_rel}" 2>/dev/null; then
        review_line="needed -- no ${spawner_rel} in ${base} before this landing; run: ${run_hint}"
      elif ! spawn_dir="$(mktemp -d "${TMPDIR:-/tmp}/finish-spawner-XXXXXX" 2>/dev/null)"; then
        review_line="needed -- could not create a scratch directory for the spawner; run: ${run_hint}"
      elif ! git -C "$primary" show "${base_before}:${spawner_rel}" > "$spawn_dir/herd-spawn.sh" 2>/dev/null ||
           ! git -C "$primary" show "${base_before}:${lib_rel}" > "$spawn_dir/lib.sh" 2>/dev/null ||
           ! chmod +x "$spawn_dir/herd-spawn.sh" 2>/dev/null; then
        rm -rf "$spawn_dir"
        review_line="needed -- could not read ${spawner_rel} from ${base_before}; run: ${run_hint}"
      else
        # ... and BASE's worker wall beside it (scripts/walls/: the platform plug and its
        # template), so the reviewer is walled like any herd session. Without it the spawner
        # finds no plug and, HERD_WALL unset being require, starts no reviewer: the landing
        # says REVIEW=needed with the command to run. The spawner copies what it runs into
        # $HERD_DIR/walls/<name>/ at spawn, so this directory may go right after. Regular
        # blobs only.
        walls_rel="${spawner_rel%/*}/walls"
        if mkdir "$spawn_dir/walls" 2>/dev/null; then
          git -C "$primary" ls-tree "${base_before}" "${walls_rel}/" 2>/dev/null |
            while read -r w_mode w_type _w_sha w_path; do
              [[ "$w_type" == "blob" && ( "$w_mode" == "100644" || "$w_mode" == "100755" ) ]] || continue
              w_base="${w_path##*/}"
              case "$w_base" in *[!A-Za-z0-9._-]*|.*) continue ;; esac
              git -C "$primary" show "${base_before}:${w_path}" > "$spawn_dir/walls/${w_base}" 2>/dev/null || rm -f "$spawn_dir/walls/${w_base}"
            done || true
        fi
        # ... and BASE's claim-worktree.sh and assert-head.sh (each sources lib.sh, already
        # beside it): the spawner's claim probe runs them behind the wall, and with neither
        # beside it the claim is unproven and, under require, no reviewer starts. Same base
        # commit as the spawner; a BASE without them is left to the probe, which says so.
        # land.sh too: the reviewer is now spawned ON A BRANCH, so herd-spawn records a gate
        # for it and copies BASE's land.sh into its walls/ directory, which the launcher runs
        # when the reviewer's finish-worktree.sh asks for its landing (a walled spawn on a
        # branch with no land.sh beside the spawner is refused).
        for claim_name in claim-worktree.sh assert-head.sh land.sh; do
          git -C "$primary" show "${base_before}:${spawner_rel%/*}/${claim_name}" > "$spawn_dir/${claim_name}" 2>/dev/null ||
            rm -f "$spawn_dir/${claim_name}"
        done
        # The reviewer's checkout: at the sha main had before this landing, on its receipt
        # branch, under a review root that is a real directory of ours -- checked BEFORE the
        # cleanup walks it, so a review root swapped for a symlink to the session
        # worktrees is walked by nothing (-1). Only what THIS script created is ever
        # removed: an entry whose physical parent is the physical review root, that
        # git lists as a worktree, whose git dir carries the marker this script writes,
        # that is detached or on the receipt branch that marker names, that is a day old
        # or bears this landing's own name, and
        # that no live session holds. A bare `false` here once ended a completed
        # landing under set -e with no REVIEW= line: every branch of this chain sets
        # review_line and falls through.
        [[ -e "$review_root" ]] || mkdir -m 700 "$review_root" 2>/dev/null || true
        review_root_ok=no
        if [[ ! -L "$review_root" && -d "$review_root" && -O "$review_root" ]] &&
           review_root_real="$(cd "$review_root" 2>/dev/null && pwd -P)"; then
          review_root_ok=yes
        fi
        if [[ "$review_root_ok" == "yes" ]]; then
          for old_co in "${review_root}"/*; do
            [[ -d "$old_co" && ! -L "$old_co" ]] || continue
            old_real="$(cd "$old_co" 2>/dev/null && pwd -P)" || continue
            [[ "$(dirname "$old_real")" == "$review_root_real" ]] || continue
            git -C "$primary" worktree list --porcelain 2>/dev/null |
              grep -qFx -e "worktree ${old_co}" -e "worktree ${old_real}" || continue
            old_gd="$(git -C "$old_co" rev-parse --absolute-git-dir 2>/dev/null)" || continue
            [[ -f "${old_gd}/muretai-review-checkout" ]] || continue
            # detached (the older shape), or on exactly the receipt branch the marker names;
            # removing the checkout leaves that branch, and iso_open_at keeps any commit on
            # it as an archive/ tag before the name is used again
            if old_head="$(git -C "$old_co" symbolic-ref -q HEAD 2>/dev/null)"; then
              old_receipt="$(sed -n 's/^receipt_branch=//p' "${old_gd}/muretai-review-checkout" 2>/dev/null | head -1)"
              [[ -n "$old_receipt" && "$old_head" == "refs/heads/${old_receipt}" ]] || continue
            fi
            if [[ "$old_co" == "$review_co" ]] || [[ -n "$(find "$old_co" -maxdepth 0 -mtime +1 2>/dev/null)" ]]; then
              old_lock="$(iso_lock_path "$old_co" 2>/dev/null || true)"
              if [[ -n "$old_lock" && -f "$old_lock" ]] && iso_lock_alive "$old_lock"; then
                continue
              fi
              git -C "$primary" worktree remove --force "$old_co" >/dev/null 2>&1 || true
            fi
          done
          git -C "$primary" worktree prune >/dev/null 2>&1 || true
        fi
        review_err="$(finish_tmp)"
        opened=no
        # On the receipt branch at the pre-landing BASE, held under the reviewer's own key
        # (lib.sh, iso_open_at -- the open `ensure-worktree.sh --at` and the daily engine do).
        # The gate that lands it is BASE's land.sh; a BASE that predates it has none to land
        # through, and its reviewer opens detached, as before.
        [[ -f "$spawn_dir/land.sh" ]] || receipt_branch=""
        if [[ "$review_root_ok" == "yes" && -n "$receipt_branch" && "$receipt_branch" != "feat/" ]] &&
           iso_open_at "$primary" "$review_co" "$receipt_branch" "$base_before" "$review_name" "$receipt_task" >/dev/null 2>"$review_err" &&
           review_gd="$(git -C "$review_co" rev-parse --absolute-git-dir 2>/dev/null)" &&
           printf 'landing=%s\nbase=%s\ntip=%s\nreceipt_branch=%s\n' "$branch" "$base_before" "$base_tip" "$receipt_branch" > "${review_gd}/muretai-review-checkout" 2>/dev/null; then
          opened=yes
        elif [[ "$review_root_ok" == "yes" && -z "$receipt_branch" ]] &&
           git -C "$primary" worktree add --detach "$review_co" "$base_before" >/dev/null 2>"$review_err" &&
           review_gd="$(git -C "$review_co" rev-parse --absolute-git-dir 2>/dev/null)" &&
           printf 'landing=%s\nbase=%s\ntip=%s\n' "$branch" "$base_before" "$base_tip" > "${review_gd}/muretai-review-checkout" 2>/dev/null; then
          opened=yes
        elif [[ "$review_root_ok" != "yes" ]]; then
          printf '%s is not a directory owned by %s\n' "$review_root" "$(id -un)" > "$review_err"
        fi
        if [[ "$opened" != "yes" ]]; then
          echo "note: the reviewer was not spawned: could not open ${review_co} at ${base_before}: $(tail -1 "$review_err" 2>/dev/null || true)" >&2
          review_line="needed -- run: ${run_hint}"
        # ... through `credless`, like every other thing the landing runs on BASE's behalf.
        # The spawner runs pythons of its own -- the re-render of the brief the reviewer is
        # given, and the write of the reviewer's permission list -- and outside this wall
        # both took their answer from whatever `usercustomize.py` a branch's own test run
        # had planted in the user site directory
        # (ISSUE(security-audit-2026-09-18-daily-2026-09-18-7)).
        # The reviewer's own name is the key that holds its receipt branch (herd-spawn's
        # default for a walled spawn), said explicitly so an unwalled spawn carries it too.
        elif spawn_out="$(credless bash "$spawn_dir/herd-spawn.sh" "$review_name" "$review_brief" --cwd "$review_co" --profile reviewer --var "MAIN=${primary}" --env "ISOLATED_SESSION_OWNER=${review_name}" 2>"$review_err")"; then
          review_pane="$(printf '%s\n' "$spawn_out" | sed -n 's/.*pane=\([^ ]*\).*/\1/p' | head -1)"
          review_eyes="$(printf '%s\n' "$spawn_out" | sed -n 's/.*harness=\([^ ]*\) model=\([^ ]*\).*/\1\/\2/p' | head -1)"
          review_line="spawned ${review_name} (pane ${review_pane}${review_eyes:+, ${review_eyes}})"
          # a stubbed spawner is a test's business; the receipt must say so, never "spawned"
          # as if a reviewer were reading the diff (ISSUE(security-audit-2026-09-12-the-guard-override-rule-a-4))
          if [[ -n "${HERD_SPAWN_BIN:-}" ]]; then
            review_line="${review_line} via HERD_SPAWN_BIN=${HERD_SPAWN_BIN}"
          fi
        else
          echo "note: the reviewer was not spawned: $(tail -1 "$review_err" 2>/dev/null || true)" >&2
          review_line="needed -- run: ${run_hint}"
        fi
        rm -f "$review_err"
        rm -rf "$spawn_dir"
      fi
    else
      rm -f "$review_tpl"
      review_line="needed -- could not render ${template_rel}; ${by_hand}"
    fi
  fi
fi
echo "REVIEW=${review_line}"

if git -C "$primary" remote get-url origin >/dev/null 2>&1 &&
   git -C "$primary" rev-parse --verify --quiet "origin/${base}" >/dev/null; then
  ahead="$(git -C "$primary" rev-list --count "origin/${base}..${base}" 2>/dev/null || echo 0)"
  if [[ "$ahead" != "0" ]]; then
    echo "NOTE: local ${base} is ${ahead} commit(s) ahead of origin/${base}."
    echo "NOTE: pushing ${base} is the owner's call -- this script does not do it, and the pre-push hook"
    echo "NOTE: refuses every push without it: ISOLATED_SESSION_PUSH=1 git push origin ${base}"
  fi
fi

# Last, because `credless` is what runs the reviewer's spawner above and the wall it
# hands that spawner is this directory. It used to be removed right after
# WORKTREE_REMOVED=, which is before the brief render and before the spawn.
rm -rf "${ISO_GH_EMPTY:-/nonexistent/iso-gh}"
