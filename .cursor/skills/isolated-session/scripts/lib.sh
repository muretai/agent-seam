#!/usr/bin/env bash
# Shared by the isolated-session scripts and the hook. Source it; nothing here runs
# on its own.
#
# Two answers live here because four scripts and one hook must agree on them:
#   * who owns a session (iso_owner) -- a KEY. For most harnesses it is the nearest
#     agent process above us (one `claude` per chat), so two chats are two owners; for
#     a harness whose chats share one process (Cursor's Agent mode: every chat in a
#     window runs under one `agent-exec` helper) it is `cursor:<conversation_id>`,
#     which the hook reads off its payload and injects into the chat's shells, so the
#     chat's scripts and its hooks name the same owner;
#   * the per-worktree session lock (iso_lock_*) -- a file inside the worktree's own
#     git dir, so `git worktree remove` takes it with the tree and nothing ever
#     commits it.

# --- the herd directory -------------------------------------------------------

# Where briefs, reports and review checkouts live: HERD_DIR, else a directory under
# the home -- never /tmp. A reviewer's cwd is under it, Claude Code reads CLAUDE.md
# from every directory above a cwd, and /private/tmp is world-writable: any local uid
# could plant /private/tmp/CLAUDE.md and steer every reviewer
# (ISSUE(security-audit-2026-09-12-the-review-checkout-lives-4)).
# Prints nothing and returns 1 when neither HERD_DIR nor HOME is set: a caller under
# `set -u` after a merge must say so, not die
# (ISSUE(security-audit-2026-09-12-the-cleanup-trusts-n-d474-4)).
iso_herd_dir() {
  if [[ -n "${HERD_DIR:-}" ]]; then
    printf '%s\n' "$HERD_DIR"
  elif [[ -n "${HOME:-}" ]]; then
    printf '%s\n' "${HOME}/.cache/muretai-herd"
  else
    return 1
  fi
}

# 0 when every directory at or above $1 (symlinks resolved; a directory that does not
# exist yet is skipped) is owned by this user or root and writable by nobody else;
# else 1 with the first offending directory on stdout.
iso_private_path() {
  python3 -I - "$1" <<'PY'
import os, sys
p = os.path.realpath(sys.argv[1])
me = os.getuid()
while True:
    try:
        st = os.stat(p)
    except OSError:
        st = None
    if st is not None and (st.st_uid not in (me, 0) or (st.st_mode & 0o022)):
        print(p)
        sys.exit(1)
    parent = os.path.dirname(p)
    if parent == p:
        sys.exit(0)
    p = parent
PY
}

# --- the credential and interpreter wall ------------------------------------
#
# ONE definition, here, because three gates run code on the repository's behalf and all
# three need the same wall: the landing (finish-worktree.sh), the daily review engine
# (tools/security_daily.sh) and the weekly clock (tools/security_weekly.sh). It used to
# live in finish-worktree.sh alone, and the header there claimed "EVERY python the
# landing runs on BASE's behalf goes through here" -- which was false one call before the
# review it protects: the daily engine ran four bare `python3`s and the landing handed
# `herd-spawn.sh` to a bare `bash`, so the reviewer's own brief and its permission list
# were rendered by an interpreter nothing had walled
# (ISSUE(security-audit-2026-09-18-daily-2026-09-18-7)). Two copies of a wall are how one
# of them goes out of date; `tests/test_gate_pythons_are_isolated.py` now checks the claim
# mechanically, over every script a gate runs.
#
# What it clears: git's credential helpers, the terminal prompt, ssh, gh's config (the
# keychain token is reached through hosts.yml, which is not in an empty directory), and
# PYTHONNOUSERSITE -- a branch's own test run executes as the operator by accepted design,
# so it can write `usercustomize.py` into the USER SITE directory, which is outside the
# checkout: `git status --porcelain` after the tests stays green, the lint never sees it
# and no reviewer opens it, yet every later plain `python3` imports it at start-up.
# A python run through here is additionally given `-I` by its caller wherever `-I` does
# not break the call (`python3 -m agent.plugins` needs the caller's directory on sys.path).

# The empty gh config directory, made once per process under an UNPREDICTABLE name (never
# /tmp/<name>-$$: a symlink planted there would be followed as the operator). Callers arm
# it at top level so a `credless` inside a `$( )` does not make one of its own; a call that
# arrives unarmed still gets a wall, and a machine where mktemp fails gets a path that does
# not exist, which is the fail-closed direction for `gh`.
iso_credless_arm() {
  if [[ -n "${ISO_GH_EMPTY:-}" && -d "${ISO_GH_EMPTY:-/nonexistent}" ]]; then
    return 0
  fi
  ISO_GH_EMPTY="$(mktemp -d "${TMPDIR:-/tmp}/iso-gh-XXXXXX" 2>/dev/null)" ||
    ISO_GH_EMPTY="/nonexistent/iso-gh"
  return 0
}

credless() {
  iso_credless_arm
  env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=credential.helper GIT_CONFIG_VALUE_0= \
      GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/usr/bin/false GIT_SSH_COMMAND=/usr/bin/false \
      GH_CONFIG_DIR="$ISO_GH_EMPTY" GH_TOKEN= GITHUB_TOKEN= GH_ENTERPRISE_TOKEN= \
      PYTHONNOUSERSITE=1 "$@"
}

# --- text an operator reads -------------------------------------------------

# One value, safe to put on a line a person reads. Every code point in an INVISIBLE
# Unicode category -- Cc, Cf, Zl, Zp, Cs, Co, Cn -- becomes its `\xNN` / `\uNNNN` /
# `\UNNNNNNNN` spelling: a path carrying a carriage return and an erase-line escape
# otherwise REWRITES the sentence in front of it, and the sentence in front of a
# collision refusal is the one an operator reads immediately before deleting something
# by hand. The value stays identifiable; it is not deleted, only spelled out. The
# PREPUSH receipt line does the same to core.hooksPath (iso_prepush_line); this is that
# treatment, named.
#
# By CATEGORY, and not by a byte range, for the reason `agent/quarantine.py:_visible`
# already carries: `tr '\000-\037\177'` stops at 0x7F, so U+009B (the 8-bit CSI, "erase
# line" in a UTF-8 xterm or VTE), U+202E, U+2028 and the zero-width joiners reached the
# refusal untouched. A category is not an enumeration the next character is missing from.
#
# python3 is how a category is asked for, and it runs ISOLATED (`-I`): no user site
# directory, so a `usercustomize.py` that a branch's own test run wrote OUTSIDE the
# checkout -- invisible to the dirtiness guard, to the lint and to any reviewer -- is
# never imported, and no PYTHON* variable is read. This used to be the pipeline's only
# `python3 -c`, so a hook that failed for `-c` alone killed THIS helper and left every
# other python the landing runs working, dropping the whole pipeline back to the byte
# range this helper exists to replace
# (ISSUE(security-audit-2026-09-18-daily-2026-09-18-3)).
#
# The byte-level `tr` is kept for a machine with NO python3 at all -- worse, but never
# nothing, and the caller SAYS so on stderr, because a fallback weaker than the guard it
# stands in for may not be chosen in silence. A python3 that IS here and cannot run is not
# a fallback: this returns non-zero, printing nothing, and the caller refuses the landing
# (iso_safe_text_mode below is how the caller asks, once, before anything prints).
iso_safe_text() {
  local out
  if out="$(printf '%s' "${1:-}" | python3 -I -c '
import sys, unicodedata
BAD = frozenset(("Cc", "Cf", "Zl", "Zp", "Cs", "Co", "Cn"))
out = []
for ch in sys.stdin.buffer.read().decode("utf-8", "replace"):
    if unicodedata.category(ch) in BAD:
        cp = ord(ch)
        out.append("\\x%02x" % cp if cp < 0x100 else
                   "\\u%04x" % cp if cp < 0x10000 else "\\U%08x" % cp)
    else:
        out.append(ch)
sys.stdout.buffer.write("".join(out).encode("utf-8"))
' 2>/dev/null)"; then
    printf '%s' "$out"
    return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    return 1
  fi
  printf '%s' "${1:-}" | LC_ALL=C tr '\000-\037\177' '?'
  return 0
}

# Which escaper `iso_safe_text` will actually use on this machine. Asked ONCE, by the
# landing, before anything prints a name the diff chose:
#   python  the category table -- the only answer a landing may print names under
#   tr      no python3 at all: the byte-level fallback, which the caller announces
#   none    a python3 that IS here and cannot run: the caller refuses the landing
# The probe is the helper itself, over a value that tells the two weak answers apart --
# U+009B, the 8-bit CSI, spelled out in octal so this file stays ASCII (principle 6). `tr`
# stops at 0x7F and leaves it byte-identical; the category table spells it `\x9b`.
iso_safe_text_mode() {
  local probe out
  probe="$(printf 'a\302\233b')"
  if ! out="$(iso_safe_text "$probe")"; then
    printf 'none\n'
  elif [[ "$out" == 'a\x9bb' ]]; then
    printf 'python\n'
  else
    printf 'tr\n'
  fi
}

# --- checkout geometry ------------------------------------------------------

# The nearest existing directory at or above $1 (a file that is not written yet
# still has to resolve to a checkout).
iso_existing_dir() {
  local p="$1"
  [[ -d "$p" ]] || p="$(dirname "$p")"
  while [[ -n "$p" && "$p" != "/" && ! -d "$p" ]]; do p="$(dirname "$p")"; done
  printf '%s\n' "$p"
}

# The primary checkout root for any path inside a checkout, linked worktree or not.
iso_primary_of() {
  local dir common
  dir="$(iso_existing_dir "$1")"
  common="$(git -C "$dir" rev-parse --git-common-dir 2>/dev/null)" || return 1
  [[ "$common" == /* ]] || common="$(cd "$dir" && cd "$common" && pwd)"
  dirname "$common"
}

# The worktree root (git toplevel) for any path inside a checkout.
iso_worktree_of() {
  local dir
  dir="$(iso_existing_dir "$1")"
  git -C "$dir" rev-parse --show-toplevel 2>/dev/null
}

# 0 when $1 (a worktree root) is a linked worktree rather than the primary checkout.
iso_is_linked() {
  [[ -f "$1/.git" ]]
}

# --- what the publisher says about origin -------------------------------------
# The owner's uid holds no GitHub credential, so it can never fetch origin itself. The
# publisher -- another user, the only token holder -- leaves two world-readable files per
# repository under its state directory, and these helpers are how a landing (and, later,
# ensure-worktree.sh) reads them:
#   origin/<name>.bundle   refs/remotes/origin/<branch> of its clone, rewritten every run
#   status/<name>.txt      its last decision (result=, reason=, origin=, ...)
# (company/ops/publisher/muretai-publish.py). MURETAI_PUBLISHER_STATE moves the whole
# directory -- the same knob tools/appl-init.sh reads -- so a test, or a machine whose
# publisher keeps its state elsewhere, never needs a path of its own for either file.
ISO_PUBLISHER_STATE="${MURETAI_PUBLISHER_STATE:-/Users/Shared/muretai-publisher}"

# The publisher's name for the repository checkout $1 belongs to: the basename of the
# `handoff` remote's URL without `.git` (/Users/Shared/muretai-handoff/trunk.git ->
# trunk), which is how publisher.json names it. Not the checkout's directory name
# (muretai-trunk != trunk), and not publisher.json itself, which lives in the publisher's
# home. Returns 1, printing nothing, when there is no hand-off or the name is not a plain
# file name -- a name that could climb out of the state directory is no name.
iso_publisher_name() {  # $1 any path in the checkout
  local url name
  url="$(git -C "$1" remote get-url handoff 2>/dev/null)" || return 1
  url="${url%/}"
  name="${url##*/}"
  name="${name%.git}"
  case "$name" in
    ''|.*|*[!A-Za-z0-9._-]*) return 1 ;;
  esac
  printf '%s\n' "$name"
}

# 0 when the publisher status file $1 says it HELD the hand-off because it is not a
# fast-forward of origin -- the one state in which this Mac's own landings are known to
# be unpublished and blocked by origin having moved. Anything else (published, held for
# a review or a scan, an error, no file) is 1.
iso_publisher_held_not_ff() {  # $1 status file
  local result reason
  [[ -f "$1" ]] || return 1
  result="$(sed -n 's/^result=//p' "$1" 2>/dev/null | head -1)"
  reason="$(sed -n 's/^reason=//p' "$1" 2>/dev/null | head -1)"
  [[ "$result" == "held" && "$reason" == *"not a fast-forward"* ]]
}

# The modification time of $1 in epoch seconds: GNU stat first (Linux is the main
# target), BSD stat second. Prints nothing and returns 1 when neither answers.
iso_mtime() {  # $1 path
  local t
  t="$(stat -c %Y "$1" 2>/dev/null)" || t="$(stat -f %m "$1" 2>/dev/null)" || return 1
  case "$t" in
    ''|*[!0-9]*) return 1 ;;
  esac
  printf '%s\n' "$t"
}

# --- what origin holds: ONE answer, and it fails closed ------------------------
# "What does origin hold?" used to have two answers: the landing's (fetch, else the
# publisher bundle inside a window, else "the origin/BASE this repository already
# has") and the owner's rebase script's, which with no bundle fell back to a five-day-
# old one and only PRINTED that origin might be newer. Rebasing onto a stale view of
# origin rewrites or duplicates published commits
# (ISSUE(origin-view-has-two-rules-and-one-of-them-serves-a-stale-bundle)). This is
# the one answer; finish-worktree.sh and the owner's scripts all call it.
#
# iso_origin_view <repo> <base>:
#   1. `git fetch origin`. The owner's uid holds no GitHub credential, so here that
#      fails; git's prompt noise is replaced by ONE line saying so.
#   2. Else the publisher bundle <state>/origin/<name>.bundle (<name> from the `handoff`
#      remote, iso_publisher_name), and only when ALL of these hold:
#        * <state>/origin, <state>/status, the bundle and the status file are what they
#          claim -- directories and regular files, never symlinks (lstat, not stat);
#        * LANDING_ORIGIN_BUNDLE / LANDING_PUBLISHER_STATUS, if set, name exactly those
#          default paths -- a view read from anywhere else is not the publisher's;
#        * the bundle is younger than LANDING_ORIGIN_BUNDLE_MAX_AGE_S (default 1800);
#        * `git bundle verify` accepts it and it carries refs/remotes/origin/<base>;
#        * its tip equals `origin=` in <state>/status/<name>.txt -- the publisher's own
#          record of what it read, so a bundle left over from another run (ahead,
#          behind or unrelated) is caught;
#        * the tip is a fast-forward of the origin/<base> <repo> already has: an older
#          view never replaces a newer one.
#   3. Else it REFUSES: a line containing "refusing" on stderr, return 1, and no ref
#      moved. There is no "go on with what we have" -- that was the bug.
# On success refs/remotes/origin/<base> in <repo> is origin's tip and
# ISO_ORIGIN_VIEW_SOURCE is `fetch` or `bundle`. git's own bundle errors never reach
# the operator: each refusal says what was wrong in words of its own.
# A repository with NO origin remote has no origin to be stale about; the CALLER decides
# that (finish-worktree.sh does not call this there), so the refusal cannot creep into
# repositories that never had an origin.
ISO_ORIGIN_VIEW_SOURCE=""

_iso_ov_show() {  # a value for a refusal line; never fails
  iso_safe_text "$1" 2>/dev/null || printf '%s' "$1" | LC_ALL=C tr '\000-\037\177' '?'
}

_iso_ov_refuse() {  # $1.. lines; the first says "refusing"
  local line
  for line in "$@"; do
    printf '%s\n' "$line" >&2
  done
  return 1
}

iso_origin_view() {  # $1 repo, $2 base
  local repo="$1" base="$2"
  local ov_err="" ov_name="" ov_state="" ov_odir="" ov_sdir="" ov_bundle="" ov_status=""
  local ov_max="" ov_mtime="" ov_age="" ov_tip="" ov_claimed="" ov_got="" ov_have="" ov_show=""
  ISO_ORIGIN_VIEW_SOURCE=""
  ov_err="$(mktemp "${TMPDIR:-/tmp}/iso-origin-XXXXXX")" || {
    _iso_ov_refuse "iso_origin_view: refusing: could not make a scratch file; origin was not read"
    return 1
  }
  # never a terminal prompt: a landing that waits on a password nobody will type is a hang
  if GIT_TERMINAL_PROMPT=0 git -C "$repo" fetch origin --quiet 2>"$ov_err"; then
    rm -f "$ov_err"
    ISO_ORIGIN_VIEW_SOURCE="fetch"
    return 0
  fi
  if grep -qiE "could not read (username|password)|terminal prompts disabled|authentication failed|permission denied \(publickey" "$ov_err" 2>/dev/null; then
    echo "note: this user holds no GitHub credential, so origin cannot be fetched here; origin is read from the publisher bundle" >&2
  else
    ov_show="$(sed -n 's/^fatal: //p' "$ov_err" 2>/dev/null | head -1)"
    echo "note: origin could not be fetched ($(_iso_ov_show "${ov_show:-no reason given}")); reading the publisher bundle" >&2
  fi
  rm -f "$ov_err"

  if ! ov_name="$(iso_publisher_name "$repo")"; then
    _iso_ov_refuse "iso_origin_view: refusing: origin could not be fetched, and no \`handoff\` remote names a" \
      "publisher repository, so there is no publisher bundle to read origin from."
    return 1
  fi
  ov_state="$ISO_PUBLISHER_STATE"
  ov_odir="${ov_state}/origin"
  ov_sdir="${ov_state}/status"
  ov_bundle="${ov_odir}/${ov_name}.bundle"
  ov_status="${ov_sdir}/${ov_name}.txt"
  if [[ -n "${LANDING_ORIGIN_BUNDLE:-}" && "$LANDING_ORIGIN_BUNDLE" != "$ov_bundle" ]]; then
    _iso_ov_refuse "iso_origin_view: refusing: LANDING_ORIGIN_BUNDLE=$(_iso_ov_show "$LANDING_ORIGIN_BUNDLE") is not the publisher's" \
      "bundle $(_iso_ov_show "$ov_bundle"); origin is read from the publisher's state or not at all" \
      "(move the whole directory with MURETAI_PUBLISHER_STATE)."
    return 1
  fi
  if [[ -n "${LANDING_PUBLISHER_STATUS:-}" && "$LANDING_PUBLISHER_STATUS" != "$ov_status" ]]; then
    _iso_ov_refuse "iso_origin_view: refusing: LANDING_PUBLISHER_STATUS=$(_iso_ov_show "$LANDING_PUBLISHER_STATUS") is not the publisher's" \
      "status $(_iso_ov_show "$ov_status"); origin is read from the publisher's state or not at all" \
      "(move the whole directory with MURETAI_PUBLISHER_STATE)."
    return 1
  fi
  ov_max="${LANDING_ORIGIN_BUNDLE_MAX_AGE_S:-1800}"
  case "$ov_max" in
    ''|*[!0-9]*)
      _iso_ov_refuse "iso_origin_view: refusing: LANDING_ORIGIN_BUNDLE_MAX_AGE_S=$(_iso_ov_show "$ov_max") is not a whole number of seconds."
      return 1
      ;;
  esac

  # what the files ARE, before anything is read from them: a symlink is never followed
  if [[ -L "$ov_odir" || ! -d "$ov_odir" || -L "$ov_sdir" || ! -d "$ov_sdir" ]]; then
    _iso_ov_refuse "iso_origin_view: refusing: $(_iso_ov_show "$ov_odir") and $(_iso_ov_show "$ov_sdir") must both be real" \
      "directories of the publisher's state (a symlink is not followed); origin was not read."
    return 1
  fi
  if [[ -L "$ov_bundle" ]]; then
    _iso_ov_refuse "iso_origin_view: refusing: the publisher bundle $(_iso_ov_show "$ov_bundle") is a symlink; it is not followed."
    return 1
  fi
  if [[ ! -f "$ov_bundle" ]]; then
    _iso_ov_refuse "iso_origin_view: refusing: origin could not be fetched and there is no publisher bundle at" \
      "$(_iso_ov_show "$ov_bundle"); origin is not known, so nothing is judged against it."
    return 1
  fi
  if [[ -L "$ov_status" ]]; then
    _iso_ov_refuse "iso_origin_view: refusing: the publisher status $(_iso_ov_show "$ov_status") is a symlink; it is not followed."
    return 1
  fi
  if [[ ! -f "$ov_status" || ! -r "$ov_status" ]]; then
    _iso_ov_refuse "iso_origin_view: refusing: the publisher status $(_iso_ov_show "$ov_status") is missing or unreadable," \
      "so the bundle cannot be checked against what the publisher read; it is not trusted on its own."
    return 1
  fi
  if ! ov_mtime="$(iso_mtime "$ov_bundle")"; then
    _iso_ov_refuse "iso_origin_view: refusing: could not read the modification time of the publisher bundle $(_iso_ov_show "$ov_bundle")."
    return 1
  fi
  ov_age=$(( $(date +%s) - ov_mtime ))
  if (( ov_age > ov_max )); then
    _iso_ov_refuse "iso_origin_view: refusing: the publisher bundle $(_iso_ov_show "$ov_bundle") is stale" \
      "(${ov_age}s old, limit ${ov_max}s: LANDING_ORIGIN_BUNDLE_MAX_AGE_S); the publisher is late, and a late bundle is not origin."
    return 1
  fi
  if ! git -C "$repo" bundle verify --quiet "$ov_bundle" >/dev/null 2>&1; then
    _iso_ov_refuse "iso_origin_view: refusing: the publisher bundle $(_iso_ov_show "$ov_bundle") is not a readable git bundle" \
      "(git bundle verify rejected it: damaged, truncated or not a bundle at all)."
    return 1
  fi
  ov_tip="$(git -C "$repo" bundle list-heads "$ov_bundle" "refs/remotes/origin/${base}" 2>/dev/null |
            awk -v want="refs/remotes/origin/${base}" '$2 == want { print $1; exit }')" || ov_tip=""
  case "$ov_tip" in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
    *)
      _iso_ov_refuse "iso_origin_view: refusing: the publisher bundle $(_iso_ov_show "$ov_bundle") carries no refs/remotes/origin/${base}."
      return 1
      ;;
  esac
  ov_claimed="$(sed -n 's/^origin=//p' "$ov_status" 2>/dev/null | head -1 | tr -d '[:space:]')" || ov_claimed=""
  if [[ "$ov_claimed" != "$ov_tip" ]]; then
    _iso_ov_refuse "iso_origin_view: refusing: the publisher bundle's origin/${base} is ${ov_tip:0:7}, but its status" \
      "$(_iso_ov_show "$ov_status") says origin=$(_iso_ov_show "${ov_claimed:0:7}")$([[ -z "$ov_claimed" ]] && printf '(none)');" \
      "the two disagree, so neither is taken as origin."
    return 1
  fi
  # the objects: git's own text for a pack that will not unpack stays in the scratch file
  ov_err="$(mktemp "${TMPDIR:-/tmp}/iso-origin-XXXXXX")" || {
    _iso_ov_refuse "iso_origin_view: refusing: could not make a scratch file; origin was not read"
    return 1
  }
  if ! git -C "$repo" fetch --quiet --no-tags "$ov_bundle" "refs/remotes/origin/${base}" >/dev/null 2>"$ov_err" ||
     ! ov_got="$(git -C "$repo" rev-parse --verify --quiet "FETCH_HEAD^{commit}")" ||
     [[ "$ov_got" != "$ov_tip" ]]; then
    rm -f "$ov_err"
    _iso_ov_refuse "iso_origin_view: refusing: the publisher bundle $(_iso_ov_show "$ov_bundle") could not be unpacked" \
      "to ${ov_tip:0:7} (its pack is damaged or truncated); origin was not read."
    return 1
  fi
  rm -f "$ov_err"
  ov_have="$(git -C "$repo" rev-parse --verify --quiet "refs/remotes/origin/${base}" || true)"
  if [[ -n "$ov_have" && "$ov_have" != "$ov_tip" ]] &&
     ! git -C "$repo" merge-base --is-ancestor "$ov_have" "$ov_tip"; then
    _iso_ov_refuse "iso_origin_view: refusing: the publisher bundle's origin/${base} (${ov_tip:0:7}) is not a fast-forward" \
      "of the origin/${base} this repository already has (${ov_have:0:7}); an older view never replaces a newer one."
    return 1
  fi
  if [[ "$ov_have" != "$ov_tip" ]]; then
    if ! git -C "$repo" update-ref "refs/remotes/origin/${base}" "$ov_tip" ${ov_have:+"$ov_have"}; then
      _iso_ov_refuse "iso_origin_view: refusing: could not set origin/${base} to ${ov_tip:0:7}."
      return 1
    fi
  fi
  ISO_ORIGIN_VIEW_SOURCE="bundle"
  return 0
}

# --- who owns this session --------------------------------------------------

iso_is_pid() {
  case "${1:-}" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

# The process that stands for "this session" by the process tree alone: the nearest
# ancestor that is an agent host (Claude Code, Codex, Grok Build, Cursor, VS Code, Grok
# Bot), else the top-most ancestor below the init process (a terminal tab).
#
# The walk needs `ps`, and where `ps` cannot run there is NO answer: this REFUSES -- nothing
# on stdout (stdout is the answer; callers write `pid="$(iso_owner_pid)"`, so a message there
# would become an owner), one line on stderr, return 2. It used to print $$ instead, the pid
# of the one short-lived shell of that call: behind wall v1 (sandbox-exec) the setuid
# /bin/ps cannot be exec'd, so every lock a walled worker claimed named a process gone a
# second later, and the next session took the folder over
# (ISSUE(walled-worker-cannot-claim-a-worktree)). A walled worker is given a key by
# herd-spawn.sh and never needs the walk; a keyless one is refused, not guessed at.
# `ps` is asked about this shell first: it always exists, so a failure there is `ps`
# itself, never a process that went away mid-walk.
iso_owner_pid() {
  local pid=$$ last=$$ comm base
  if ! ps -o pid= -p "$$" >/dev/null 2>&1; then
    echo "iso_owner_pid: refusing: \`ps\` cannot run here (a wall denies it), so the process walk that names this session's owner cannot be made; set ISOLATED_SESSION_OWNER to a stable key" >&2
    return 2
  fi
  while [[ -n "$pid" && "$pid" -gt 1 ]]; do
    comm="$(ps -o comm= -p "$pid" 2>/dev/null || true)"
    base="${comm##*/}"
    case "$base" in
      claude|claude-code|codex|grok|xai-grok-pager|Cursor*|cursor*|Code*|code*|Electron|"Grok Bot"*|Grok*)
        printf '%s\n' "$pid"
        return 0
        ;;
    esac
    last="$pid"
    pid="$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ' || true)"
  done
  printf '%s\n' "$last"
}

# The owner key, in this order: ISOLATED_SESSION_OWNER (a harness or a sessionStart
# hook set it, or a test), then a harness key the caller read off a hook payload
# ($1, e.g. cursor:<conversation_id>), then the process walk.
iso_owner() {
  if [[ -n "${ISOLATED_SESSION_OWNER:-}" ]]; then
    printf '%s\n' "$ISOLATED_SESSION_OWNER"
    return 0
  fi
  if [[ -n "${1:-}" ]]; then
    printf '%s\n' "$1"
    return 0
  fi
  iso_owner_pid
}

# Harnesses whose payload id may become the owner key: only those that also carry
# that key into the chat's shells, otherwise the chat would refuse its own commits.
# Cursor does (the sessionStart response's `env`). Claude Code has one process per
# chat and needs no key. Extend here, one word per harness.
iso_harness_keys_shells() {
  case "$1" in
    cursor) return 0 ;;
    *) return 1 ;;
  esac
}

# The kind of owner: from the key's prefix, else from the process's executable.
iso_owner_kind() {  # $1 owner, [$2 pid]
  local owner="$1" pid="${2:-}" comm
  case "$owner" in
    *:*) printf '%s\n' "${owner%%:*}"; return 0 ;;
  esac
  [[ -n "$pid" ]] || pid="$owner"
  comm="$(iso_proc_comm "$pid")"
  case "$comm" in
    claude|claude-code) echo claude ;;
    codex) echo codex ;;
    grok|xai-grok-pager) echo grok ;;
    "Grok Bot"*|Grok*) echo grokbot ;;
    Cursor*|cursor*) echo cursor ;;
    Code*|code*|Electron) echo vscode ;;
    '') echo unknown ;;
    *) echo shell ;;
  esac
}

# The start time of process $1 as `ps` prints it; empty when the process is gone.
# Recorded into the lock so a pid the OS hands out again after the owner died does
# not look like a live owner.
iso_proc_start() {
  ps -o lstart= -p "$1" 2>/dev/null | sed 's/^ *//; s/ *$//'
}

iso_proc_comm() {
  ps -o comm= -p "$1" 2>/dev/null | sed 's#.*/##'
}

# 0 when pid $1 is alive AND (when $2 is given) still the process the lock recorded.
iso_owner_alive() {
  local pid="$1" recorded="${2:-}" now
  iso_is_pid "$pid" || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  [[ -z "$recorded" ]] && return 0
  now="$(iso_proc_start "$pid")"
  [[ -z "$now" || "$now" == "$recorded" ]]
}

# --- the session lock -------------------------------------------------------

# The lock file for worktree $1: inside that worktree's git dir.
iso_lock_path() {
  local gd
  gd="$(git -C "$1" rev-parse --git-dir 2>/dev/null)" || return 1
  [[ "$gd" == /* ]] || gd="$(cd "$1" && cd "$gd" && pwd)"
  printf '%s\n' "$gd/isolated-session.lock"
}

iso_lock_get() {  # $1 lock file, $2 key
  sed -n "s/^$2=//p" "$1" 2>/dev/null | head -1
}

# Rewrite one key of a lock (whole file, tmp + mv: sed -i differs between BSD and GNU).
iso_lock_set() {  # $1 lock file, $2 key, $3 value
  # The temporary file is this process's own: two writers sharing one `$1.tmp` (a
  # harness hook on every tool call, and a script in the same chat) truncated each
  # other's copy, and one of them renamed an empty instant over the lock -- which the
  # next writer then read as nothing, leaving a lock with `owner_seen` alone (2026-09-13,
  # two Cursor workers). A lock that reads empty while it exists is being replaced by
  # someone else: read it again rather than write that instant back.
  local tmp="$1.tmp.$$" tries=0
  while :; do
    { grep -v "^$2=" "$1" 2>/dev/null || true; echo "$2=$3"; } > "$tmp"
    if [[ -s "$1" ]] && [[ "$(grep -c . "$tmp")" -le 1 ]] && (( tries < 5 )); then
      tries=$((tries + 1)); sleep 0.1; continue
    fi
    mv "$tmp" "$1"
    return 0
  done
}

# A lock is alive when its process is, and -- for a key-owned lock, whose chat may end
# without a sessionEnd -- when it was seen within ISOLATED_SESSION_OWNER_TTL_HOURS
# (default 12). Every `mine` verdict touches it, so a chat in use never expires.
iso_lock_alive() {  # $1 lock file
  local owner pid seen ttl now
  owner="$(iso_lock_get "$1" owner)"
  if iso_is_pid "$owner"; then
    iso_owner_alive "$owner" "$(iso_lock_get "$1" owner_started)"
    return $?
  fi
  pid="$(iso_lock_get "$1" owner_pid)"
  if [[ -n "$pid" ]] && ! iso_owner_alive "$pid" "$(iso_lock_get "$1" owner_started)"; then
    return 1
  fi
  seen="$(iso_lock_get "$1" owner_seen)"
  [[ -n "$seen" ]] || seen="$(iso_lock_get "$1" started)"
  if [[ -z "$seen" ]]; then return 1; fi
  ttl="${ISOLATED_SESSION_OWNER_TTL_HOURS:-12}"
  now="$(date +%s)"
  if (( now - seen < ttl * 3600 )); then return 0; fi
  return 1
}

# alive | gone | expired -- why a lock is or is not live, for a sentence.
iso_lock_liveness() {  # $1 lock file
  local owner pid
  if iso_lock_alive "$1"; then echo alive; return 0; fi
  owner="$(iso_lock_get "$1" owner)"
  if iso_is_pid "$owner"; then echo gone; return 0; fi
  pid="$(iso_lock_get "$1" owner_pid)"
  if [[ -n "$pid" ]] && ! iso_owner_alive "$pid" "$(iso_lock_get "$1" owner_started)"; then
    echo gone
  else
    echo expired
  fi
}

# free | mine | dead | other -- the lock of worktree $1 as seen by owner $2.
#
# A lock that names a herd worker (`owner_worker=`, written by the pair hand-over below) is
# `mine` only for the session whose HERD_WORKER is that worker: a test author and its
# implementer carry the SAME owner key, so after the hand-over the key alone no longer
# says which of the two holds the folder, and the author is `other` (or `dead`) like any
# second chat.
iso_lock_state() {
  local lock owner worker
  lock="$(iso_lock_path "$1")" || { echo free; return 0; }
  [[ -f "$lock" ]] || { echo free; return 0; }
  owner="$(iso_lock_get "$lock" owner)"
  worker="$(iso_lock_get "$lock" owner_worker)"
  if [[ "$owner" == "$2" && ( -z "$worker" || "$worker" == "${HERD_WORKER:-}" ) ]]; then
    echo mine
  elif iso_lock_alive "$lock"; then
    echo other
  else
    echo dead
  fi
}

# The process a KEYED owner's lock records, when one can be seen: the walk, asked quietly.
# A key names its owner without the walk, so a walk that refuses (no `ps`: behind a wall) is
# not an error here -- the answer is empty and the lock is live by its seen-time TTL like
# any key-owned lock with no process. Never fatal: callers run under `set -e`, where a
# refusing `pid="$(iso_owner_pid)"` would abort a claim the key alone makes good.
iso_keyed_pid() {
  iso_owner_pid 2>/dev/null || true
}

# Write the lock: $1 worktree, $2 owner, $3 kind, $4 branch, $5 task.
iso_lock_write() {
  local lock pid started="" comm=""
  lock="$(iso_lock_path "$1")" || return 1
  if iso_is_pid "$2"; then pid="$2"; else pid="$(iso_keyed_pid)"; fi
  # `|| true`: under `set -e` and pipefail a `ps` the wall denies must not abort the write
  if [[ -n "$pid" ]]; then
    started="$(iso_proc_start "$pid")" || true
    comm="$(iso_proc_comm "$pid")" || true
  fi
  {
    echo "owner=$2"
    echo "owner_pid=$pid"
    echo "owner_started=$started"
    echo "owner_comm=$comm"
    echo "owner_kind=$(iso_owner_kind "$2" "$pid")"
    echo "owner_seen=$(date +%s)"
    echo "kind=$3"
    echo "branch=$4"
    echo "task=$(printf '%s' "$5" | tr '\n' ' ')"
    echo "started=$(date +%s)"
    echo "started_iso=$(date '+%Y-%m-%d %H:%M')"
    echo "host=$(hostname)"
  } > "$lock"
}

# Mark worktree $1's lock as seen now (called on every `mine` verdict, $2 the owner that
# verdict was for). A lock handed to this session's herd worker and not yet bound to a
# process is bound first (iso_lock_bind), so liveness follows this session from its
# first guarded command on.
iso_lock_touch() {
  local lock
  lock="$(iso_lock_path "$1")" || return 0
  [[ -f "$lock" ]] || return 0
  iso_lock_bind "$1" "${2:-$(iso_owner)}"
  iso_lock_set "$lock" owner_seen "$(date +%s)"
}

# --- the pair hand-over -------------------------------------------------------
# ISSUE(pair-worktree-lock-dies-with-the-test-author-session). A test author and its
# implementer share one worktree and one ISOLATED_SESSION_OWNER key, and the lock used to
# record the AUTHOR's process: the author's tab closing released it (SessionEnd drops every
# lock of its key) or left it `gone`, and the implementer -- forbidden to claim -- stopped.
#
# The hold now passes in two steps, because the spawn runs in the coordinator's process and
# cannot know the implementer's pid:
#   1. herd-spawn.sh, starting worker W with `--env ISOLATED_SESSION_OWNER=K`, rewrites
#      every lock of ITS repository whose owner is K: `owner_worker=W`, the process fields
#      emptied (iso_lock_handover). From that moment the key alone is not enough -- the
#      author, whose HERD_WORKER is not W, is refused (iso_lock_state) -- and the lock is
#      live by its seen-time TTL, like any key-owned lock with no process.
#   2. W's session, at its first guarded command (the hook, assert-head, claim, ensure),
#      finds a lock naming its key AND its HERD_WORKER with no process, and records its own
#      (iso_lock_bind). Liveness then follows W's process, exactly as it followed the
#      author's.
# Nothing is ever written through a symlink: both steps open the lock's directory and the
# lock itself with O_NOFOLLOW, refuse anything that is not a regular file, and replace the
# file by renaming a sibling over it (which replaces a directory ENTRY and never writes into
# what an entry points at). A symlinked lock or lock directory is left exactly as it is.
# The write is a compare-and-set: the precondition is re-read from the file just opened.
iso_lock_py() {
  python3 -I - "$@" <<'PY'
import os, stat, sys, time

NAME = "isolated-session.lock"
NOFOLLOW_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def read_lock(dfd):
    try:
        fd = os.open(NAME, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0), dir_fd=dfd)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        chunks = []
        while True:
            b = os.read(fd, 65536)
            if not b:
                break
            chunks.append(b)
    finally:
        os.close(fd)
    pairs = []
    for line in b"".join(chunks).decode("utf-8", "replace").splitlines():
        k, sep, v = line.partition("=")
        if sep:
            pairs.append([k, v])
    return pairs


def get(pairs, key):
    for k, v in pairs:
        if k == key:
            return v
    return ""


def put(pairs, key, value):
    value = value.replace("\n", " ").replace("\r", " ")
    for p in pairs:
        if p[0] == key:
            p[1] = value
            return
    pairs.append([key, value])


def write_lock(dfd, pairs):
    tmp = "%s.tmp.%d" % (NAME, os.getpid())
    try:
        os.unlink(tmp, dir_fd=dfd)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=dfd)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("".join("%s=%s\n" % (k, v) for k, v in pairs))
    os.rename(tmp, NAME, src_dir_fd=dfd, dst_dir_fd=dfd)


mode = sys.argv[1]
if mode == "handover":
    # argv: common git dir, key, worker. Prints each worktree whose hold passed.
    common, key, worker = sys.argv[2:5]
    try:
        top = os.open(os.path.join(common, "worktrees"), NOFOLLOW_DIR)
    except OSError:
        sys.exit(0)
    try:
        entries = sorted(os.listdir(top))
    except OSError:
        entries = []
    for entry in entries:
        try:
            dfd = os.open(entry, NOFOLLOW_DIR, dir_fd=top)
        except OSError:
            continue                      # a symlink, a file, gone: not ours to touch
        try:
            pairs = read_lock(dfd)
            if pairs is None or get(pairs, "owner") != key:
                continue
            put(pairs, "owner_worker", worker)
            for k in ("owner_pid", "owner_started", "owner_comm"):
                put(pairs, k, "")
            put(pairs, "owner_seen", str(int(time.time())))
            put(pairs, "handed_over", time.strftime("%Y-%m-%d %H:%M"))
            try:
                write_lock(dfd, pairs)
            except OSError:
                continue
            where = entry
            try:
                gfd = os.open("gitdir", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dfd)
                with os.fdopen(gfd, encoding="utf-8", errors="replace") as f:
                    where = os.path.dirname(f.readline().strip()) or entry
            except OSError:
                pass
            print(where)
        finally:
            os.close(dfd)
elif mode == "bind":
    # argv: lock dir, key, worker, pid, started, comm. Binds only a lock that names this
    # key AND this worker and carries no process yet.
    ldir, key, worker, pid, started, comm = sys.argv[2:8]
    try:
        dfd = os.open(ldir, NOFOLLOW_DIR)
    except OSError:
        sys.exit(0)
    try:
        pairs = read_lock(dfd)
        if (pairs is None or not worker or get(pairs, "owner") != key
                or get(pairs, "owner_worker") != worker or get(pairs, "owner_pid")):
            sys.exit(0)
        put(pairs, "owner_pid", pid)
        put(pairs, "owner_started", started)
        put(pairs, "owner_comm", comm)
        put(pairs, "owner_seen", str(int(time.time())))
        write_lock(dfd, pairs)
    finally:
        os.close(dfd)
PY
}

# Step 1, from herd-spawn.sh: pass every lock of the repository at $1 whose owner is key $2
# to herd worker $3. A key that is a bare pid is a chat's own process, never a pair's key,
# and is ignored. Prints each worktree whose hold passed.
iso_lock_handover() {  # $1 any path in the repository, $2 key, $3 worker
  local gd
  [[ -n "${2:-}" && -n "${3:-}" ]] || return 0
  iso_is_pid "$2" && return 0
  gd="$(git -C "$1" rev-parse --git-common-dir 2>/dev/null)" || return 0
  [[ "$gd" == /* ]] || gd="$(cd "$1" && cd "$gd" && pwd)"
  iso_lock_py handover "$gd" "$2" "$3"
}

# Step 2: bind worktree $1's lock to this session's process when it was handed to this
# session's herd worker under owner key $2 and nothing is bound yet.
iso_lock_bind() {  # $1 worktree, $2 owner
  local lock worker pid
  worker="${HERD_WORKER:-}"
  [[ -n "$worker" && -n "${2:-}" ]] || return 0
  lock="$(iso_lock_path "$1")" || return 0
  [[ "$(iso_lock_get "$lock" owner_worker)" == "$worker" ]] || return 0
  [[ -z "$(iso_lock_get "$lock" owner_pid)" ]] || return 0
  # no process to be seen (behind a wall): nothing to bind, the handed-over lock stays
  # live by its seen-time TTL
  pid="$(iso_keyed_pid)"
  [[ -n "$pid" ]] || return 0
  iso_lock_py bind "$(dirname "$lock")" "$2" "$worker" "$pid" "$(iso_proc_start "$pid")" \
    "$(iso_proc_comm "$pid")" >/dev/null 2>&1 || true
}

iso_lock_release() {
  local lock
  lock="$(iso_lock_path "$1")" || return 0
  rm -f "$lock"
}

# --- a session branch at a named commit ---------------------------------------
# The slug a task's branch carries: its first 32 ASCII characters plus a hash of the WHOLE
# task string, so two tasks that agree on a prefix cannot land on one branch, and the same
# task always gets the same branch back. ensure-worktree.sh's rule, stated once here so a
# spawn site can name a branch without the script (the daily engine's fixtures carry lib.sh
# and not ensure-worktree.sh).
iso_task_slug() {  # $1 task
  python3 -I - "$1" <<'PY'
import hashlib, re, sys
name = sys.argv[1].strip()
digest = hashlib.sha1(name.encode()).hexdigest()
ascii_part = re.sub(r"[^a-z0-9]+", "-", name.encode("ascii", "ignore").decode().lower()).strip("-")[:32].strip("-")
print(f"{ascii_part}-{digest[:4]}" if len(ascii_part) >= 2 else "task-" + digest[:6])
PY
}

# Open branch $3 AT COMMIT $4 in the new directory $2, from the repository at $1, and hold
# it as any session holds its worktree: the lock under owner key $5 (task $6) and the
# no-push hook. The reviewer spawn sites (tools/security_daily.sh, finish-worktree.sh's
# reviewer block, and `ensure-worktree.sh --at`) open a reviewer's receipt branch this way:
# ON A BRANCH, so herd-spawn.sh records it and a walled reviewer lands through the
# launcher's gate, but at BASE, so the reviewer runs BASE's hooks and scripts
# (ISSUE(walled-reviewer-cannot-write-its-receipt)). A branch of that name left with no
# worktree -- an earlier run that never landed -- is never deleted with work on it: a tip
# other than $4 is kept as the tag archive/<branch>-<sha7> first. A branch checked out
# anywhere, or anything already at $2, is a refusal. One line on stderr and non-zero on any
# failure; the PREPUSH receipt value on stdout on success.
iso_open_at() {  # $1 any path in the repository, $2 new dir, $3 branch, $4 commit, $5 owner key, $6 task
  local repo="$1" dir="$2" branch="$3" at="$4" owner="$5" task="${6:-}" sha old tag
  if [[ -z "$dir" || -z "$branch" || -z "$at" || -z "$owner" ]]; then
    echo "iso_open_at: a directory, a branch, a commit and an owner key are all required" >&2
    return 2
  fi
  if ! sha="$(git -C "$repo" rev-parse --verify --quiet "${at}^{commit}")"; then
    echo "iso_open_at: ${at} is not a commit in ${repo}" >&2
    return 1
  fi
  if [[ -e "$dir" || -L "$dir" ]]; then
    echo "iso_open_at: ${dir} is already in the way" >&2
    return 1
  fi
  if git -C "$repo" worktree list --porcelain 2>/dev/null | grep -qxF "branch refs/heads/${branch}"; then
    echo "iso_open_at: ${branch} is checked out in another worktree" >&2
    return 1
  fi
  if old="$(git -C "$repo" rev-parse --verify --quiet "refs/heads/${branch}^{commit}")"; then
    if [[ "$old" != "$sha" ]]; then
      tag="archive/${branch}-${old:0:7}"
      if ! git -C "$repo" tag "$tag" "$old" 2>/dev/null &&
         [[ "$(git -C "$repo" rev-parse --verify --quiet "refs/tags/${tag}^{commit}" 2>/dev/null)" != "$old" ]]; then
        echo "iso_open_at: ${branch} exists at ${old:0:12} and could not be kept as ${tag}" >&2
        return 1
      fi
      echo "note: ${branch} was left at ${old:0:12} by an earlier run; kept as ${tag}" >&2
    fi
    git -C "$repo" branch -D "$branch" >/dev/null 2>&1 || {
      echo "iso_open_at: could not reopen ${branch}" >&2
      return 1
    }
  fi
  mkdir -p "$(dirname "$dir")" 2>/dev/null || true
  if ! git -C "$repo" worktree add --quiet --no-track -b "$branch" "$dir" "$sha" >/dev/null 2>&1; then
    echo "iso_open_at: git could not open ${branch} at ${sha:0:12} in ${dir}" >&2
    return 1
  fi
  if ! iso_lock_write "$dir" "$owner" dev "$branch" "$task"; then
    echo "iso_open_at: ${dir} was opened on ${branch}, and its lock could not be written" >&2
    return 1
  fi
  iso_prepush_line "$dir"
}

# --- the landing lock -------------------------------------------------------
# One landing at a time per primary. The file lives in the COMMON git dir (shared by
# every worktree, so it survives `git worktree remove` and a crash) and is taken with
# noclobber, so two finishes racing for it get one winner. Same owner rules as the
# worktree lock: a live holder is waited for, a dead one taken over.

# ---- the no-push speed bump -------------------------------------------------------------
# Sessions never push; the owner pushes on purpose. Until 2026-09-12 that was a promise
# (allowlists, briefs); by the owner's decision A `<common git dir>/hooks/pre-push`
# refuses every push unless ISOLATED_SESSION_PUSH=1 is in the environment -- something
# a human types in a terminal, and something tools/sec_lint.py refuses inside any
# script. Installed by ensure-worktree.sh, claim-worktree.sh and the session guard, so a
# checkout that has hosted one session has it.
#
# What it is and is not (the ninth landing review, 2026-09-12): a client-side hook stops
# an honest session and a mistake; it cannot stop a same-uid process that sets the
# variable itself, passes `--no-verify`, or points `core.hooksPath` elsewhere. The wall
# against THAT is a push credential a process cannot use without the owner (an SSH key
# added with `ssh-add -c`, or none on the box) -- the owner's decision, recorded in
# ISSUE(push-credential-confirmation).
#
# The hook is verified by CONTENT, not by a comment: an existing hook that carries our
# marker but not our body is rewritten (`repaired`); one without the marker is someone
# else's and is left alone (`foreign`). Nothing here opens the hook path for writing: the
# file is written beside it and renamed over it, so a FIFO or a symlink planted there
# cannot block or redirect the installer (`replaced`).
ISO_PREPUSH_MARK="isolated-session pre-push v1"

iso_prepush_body() {
  cat <<'EOF'
#!/bin/sh
# isolated-session pre-push v1 -- installed by the isolated-session skill (lib.sh).
# Sessions never push. A push goes through only when ISOLATED_SESSION_PUSH=1 is in the
# environment: the owner types it, on purpose, from a terminal:
#   ISOLATED_SESSION_PUSH=1 git push origin main
# tools/sec_lint.py refuses that spelling inside any script, so no script carries it.
# The hand-off is the exception: a bare repository on this machine, credential-free,
# that the publisher (another user, the only GitHub token) reads and publishes from
# (company/ops/publisher/README.md). A landing pushes BASE there.
# (`*` in a case pattern crosses `/`, so the name after the root is checked to be one
# component: `muretai-handoff/../elsewhere/x.git` is not the hand-off)
case "${2:-}" in
  /Users/Shared/muretai-handoff/*.git|file:///Users/Shared/muretai-handoff/*.git)
    case "${2#*muretai-handoff/}" in
      */*) ;;
      *) exit 0 ;;
    esac ;;
esac
if [ "${ISOLATED_SESSION_PUSH:-}" = "1" ]; then
  exit 0
fi
echo "pre-push: refusing to push to $1 -- sessions never push. The owner pushes with: ISOLATED_SESSION_PUSH=1 git push ..." >&2
exit 1
EOF
}

iso_prepush_install() {  # $1 any path in the checkout -> installed|present|repaired|replaced|foreign|none
  local gd hook tmp state
  gd="$(git -C "$1" rev-parse --git-common-dir 2>/dev/null)" || { echo none; return 0; }
  [[ "$gd" == /* ]] || gd="$(cd "$1" && cd "$gd" && pwd)"
  hook="$gd/hooks/pre-push"
  state=installed
  if [[ -h "$hook" || ( -e "$hook" && ! -f "$hook" ) ]]; then
    state=replaced                       # a symlink, a FIFO, a directory: not a hook
  elif [[ -f "$hook" ]]; then
    if iso_prepush_body | cmp -s - "$hook" 2>/dev/null && [[ -x "$hook" ]]; then
      echo present
      return 0
    fi
    if grep -q "$ISO_PREPUSH_MARK" "$hook" 2>/dev/null; then
      state=repaired
    else
      echo foreign
      return 0
    fi
  fi
  mkdir -p "$gd/hooks" 2>/dev/null || { echo none; return 0; }
  tmp="$(mktemp "$gd/hooks/pre-push.XXXXXX" 2>/dev/null)" || { echo none; return 0; }
  iso_prepush_body > "$tmp"
  chmod 755 "$tmp" 2>/dev/null || true
  if [[ -d "$hook" ]]; then
    rm -rf "$hook" 2>/dev/null || { rm -f "$tmp"; echo none; return 0; }
  fi
  mv -f "$tmp" "$hook" 2>/dev/null || { rm -f "$tmp"; echo none; return 0; }
  echo "$state"
}

iso_prepush_line() {  # $1 any path in the checkout -> the receipt value, with the caveat
  local state hp
  state="$(iso_prepush_install "$1")"
  # the value is attacker-settable and goes onto an operator-read line: first line only,
  # control bytes out, bounded
  # The caveat fires when the KEY is set, not when its value survives sanitizing: an empty
  # value and a value that starts with a byte no locale accepts both sideline the hook
  # (ISSUE(security-audit-2026-09-12-the-wall-is-honest-about)). Asked from the path the
  # caller gave, so a worktree-scoped value (extensions.worktreeConfig) is seen when the
  # caller is a worktree (-2).
  # ... and from the primary as well: per-worktree config is not shared, so a value in
  # the PRIMARY's config.worktree sidelines a push from the primary while a worktree
  # sees nothing (ISSUE(security-audit-2026-09-12-the-scan-joins-continued-6)).
  local gd prim where
  gd="$(git -C "$1" rev-parse --git-common-dir 2>/dev/null)" || gd=""
  prim=""
  if [[ -n "$gd" ]]; then
    [[ "$gd" == /* ]] || gd="$(cd "$1" && cd "$gd" && pwd)"
    prim="$(dirname "$gd")"
  fi
  for where in "$1" "$prim"; do
    [[ -n "$where" && -d "$where" ]] || continue
    if hp="$(git -C "$where" config --get core.hooksPath 2>/dev/null)"; then
      hp="$(printf '%s' "$hp" | head -n 1 | LC_ALL=C tr -d '\000-\037\177' | cut -c1-200)"
      state="${state} (not consulted: core.hooksPath=${hp:-(empty)})"
      break
    fi
  done
  printf '%s\n' "$state"
}

iso_land_lock_path() {  # $1 primary (or any path in the checkout)
  local gd
  gd="$(git -C "$1" rev-parse --git-common-dir 2>/dev/null)" || return 1
  [[ "$gd" == /* ]] || gd="$(cd "$1" && cd "$gd" && pwd)"
  printf '%s/landing.lock\n' "$gd"
}

iso_land_lock_state() {  # $1 primary, $2 me -> free|mine|dead|other
  local lock owner
  lock="$(iso_land_lock_path "$1")" || { echo free; return 0; }
  [[ -f "$lock" ]] || { echo free; return 0; }
  owner="$(iso_lock_get "$lock" owner)"
  if [[ "$owner" == "$2" ]]; then
    echo mine
  elif iso_lock_alive "$lock"; then
    echo other
  else
    echo dead
  fi
}

iso_land_lock_take() {  # $1 primary, $2 owner, $3 branch -> 0 when this call created it
  local lock pid
  lock="$(iso_land_lock_path "$1")" || return 1
  if iso_is_pid "$2"; then pid="$2"; else pid="$(iso_keyed_pid)"; fi
  (
    set -o noclobber
    {
      echo "owner=$2"
      echo "owner_pid=$pid"
      echo "owner_started=$(iso_proc_start "$pid")"
      echo "owner_comm=$(iso_proc_comm "$pid")"
      echo "owner_kind=$(iso_owner_kind "$2" "$pid")"
      echo "owner_seen=$(date +%s)"
      echo "kind=landing"
      echo "branch=$3"
      echo "task=landing $3"
      echo "started=$(date +%s)"
      echo "started_iso=$(date '+%Y-%m-%d %H:%M')"
      echo "host=$(hostname)"
    } > "$lock"
  ) 2>/dev/null
}

iso_land_lock_release() {
  local lock
  lock="$(iso_land_lock_path "$1")" || return 0
  rm -f "$lock"
}

iso_land_lock_describe() {
  local lock owner
  lock="$(iso_land_lock_path "$1")" || return 0
  [[ -f "$lock" ]] || { echo "nobody"; return 0; }
  owner="$(iso_lock_get "$lock" owner)"
  printf 'landing of %s by owner %s (%s, %s, %s) since %s\n' \
    "$(iso_lock_get "$lock" branch)" "$owner" "$(iso_lock_get "$lock" owner_kind)" \
    "$(iso_lock_get "$lock" owner_comm)" "$(iso_lock_liveness "$lock")" "$(iso_lock_get "$lock" started_iso)"
}

iso_seen_ago() {  # $1 lock file -> "3m ago"
  local seen now d
  seen="$(iso_lock_get "$1" owner_seen)"
  [[ -n "$seen" ]] || seen="$(iso_lock_get "$1" started)"
  [[ -n "$seen" ]] || { echo "never"; return 0; }
  now="$(date +%s)"
  d=$(( now - seen ))
  if (( d < 120 )); then echo "${d}s ago"
  elif (( d < 7200 )); then echo "$(( d / 60 ))m ago"
  else echo "$(( d / 3600 ))h ago"; fi
}

# One line a person can read about who holds worktree $1.
iso_lock_describe() {
  local lock owner kind worker
  lock="$(iso_lock_path "$1")" || return 0
  [[ -f "$lock" ]] || { echo "nobody"; return 0; }
  owner="$(iso_lock_get "$lock" owner)"
  kind="$(iso_lock_get "$lock" owner_kind)"
  [[ -n "$kind" ]] || kind="$(iso_owner_kind "$owner")"
  worker="$(iso_lock_get "$lock" owner_worker)"
  [[ -z "$worker" ]] || owner="${owner} worker=${worker}"
  printf 'owner %s (%s, %s, %s, seen %s) since %s, task "%s"\n' \
    "$owner" "$kind" "$(iso_lock_get "$lock" owner_comm)" "$(iso_lock_liveness "$lock")" \
    "$(iso_seen_ago "$lock")" "$(iso_lock_get "$lock" started_iso)" "$(iso_lock_get "$lock" task)"
}

# The sentence that fixes the one honest mismatch: a shell without the harness key
# (a Cursor chat whose env did not arrive) meeting a lock its own hook took.
iso_lock_fix_hint() {  # $1 worktree, $2 me
  local lock owner
  lock="$(iso_lock_path "$1")" || return 0
  [[ -f "$lock" ]] || return 0
  owner="$(iso_lock_get "$lock" owner)"
  if ! iso_is_pid "$owner" && iso_is_pid "$2"; then
    echo "This shell carries no ISOLATED_SESSION_OWNER; if that lock is this chat's, run:"
    echo "  export ISOLATED_SESSION_OWNER=${owner}"
  fi
}

# The open-session inventory for primary $1, one worktree per line. Used by
# stale.sh and by the hook's SessionStart context.
iso_sessions_report() {
  local primary="$1" wt lock owner state kind branch okind worker
  local found=0
  while IFS= read -r wt; do
    lock="$(iso_lock_path "$wt" 2>/dev/null)" || continue
    [[ -f "$lock" ]] || continue
    found=1
    owner="$(iso_lock_get "$lock" owner)"
    case "$(iso_lock_liveness "$lock")" in
      alive) state="alive" ;;
      expired) state="EXPIRED" ;;
      *) state="GONE" ;;
    esac
    kind="$(iso_lock_get "$lock" kind)"
    branch="$(iso_lock_get "$lock" branch)"
    okind="$(iso_lock_get "$lock" owner_kind)"
    [[ -n "$okind" ]] || okind="$(iso_owner_kind "$owner")"
    worker="$(iso_lock_get "$lock" owner_worker)"
    [[ -z "$worker" ]] || owner="${owner} worker=${worker}"
    printf '   %-60s %-6s %-40s owner=%s (%s, %s, %s, seen %s) since %s\n' \
      "$wt" "$kind" "$branch" "$owner" "$okind" "$(iso_lock_get "$lock" owner_comm)" "$state" \
      "$(iso_seen_ago "$lock")" "$(iso_lock_get "$lock" started_iso)"
  done < <(git -C "$primary" worktree list --porcelain 2>/dev/null | awk '/^worktree /{print $2}')
  [[ "$found" == "1" ]] || echo "   (none)"
}

# --- design paths -----------------------------------------------------------

# A repository that separates design work from the rest lists the paths a design
# session owns, one per line, in .cursor/design-paths (directory prefixes end in
# "/"; anything else is an exact file). No file: the repository has no design
# sessions, and every session is a dev session.
iso_design_paths_file() {
  printf '%s\n' "$1/.cursor/design-paths"
}

iso_kind_of_branch() {
  case "$1" in
    design/*) echo design ;;
    *) echo dev ;;
  esac
}

# 0 when repo-relative path $2 is inside the design paths declared by primary $1.
iso_is_design_path() {
  local f p
  f="$(iso_design_paths_file "$1")"
  [[ -f "$f" ]] || return 1
  while IFS= read -r p || [[ -n "$p" ]]; do
    p="${p%%#*}"
    p="${p#"${p%%[![:space:]]*}"}"
    p="${p%"${p##*[![:space:]]}"}"
    [[ -z "$p" ]] && continue
    if [[ "$p" == */ ]]; then
      [[ "$2" == "$p"* ]] && return 0
    else
      [[ "$2" == "$p" ]] && return 0
    fi
  done < "$f"
  return 1
}
