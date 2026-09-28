#!/bin/bash
# The herd worker wall on macOS: Seatbelt, through /usr/bin/sandbox-exec.
#
#   darwin.sh available                      exit 0 when this machine can build the wall
#   darwin.sh exec <profile> -- <cmd...>     exec <cmd...> behind the wall <profile> describes
#   darwin.sh inside                         exit 0 when THIS process already runs behind a wall
#
# `exec` exports HERD_WALL_INSIDE=<worker name> (the name of the directory the profile sits
# in, $HERD_DIR/walls/<name>/profile) into the walled process. A spawn started from behind
# the wall finds `available` failing -- sandbox-exec refuses to nest -- and the marker set;
# it then asks `inside`, which asks the kernel (sandbox_check on its own pid) rather than
# the marker, so a marker set by hand outside any wall is not a wall.
#
# This file is a PLUG (AGENTS.md principle 12): herd-spawn.sh owns the mode, the probe, the
# bounds and the record, and picks the plug by `uname -s`, lowercased -- a Linux wall is
# one more file beside this one, answering the same two verbs. The profile is NEUTRAL: the
# lines herd-spawn.sh writes to $HERD_DIR/walls/<name>/profile, one verb and one absolute
# path per line --
#
#   egress open                  the only egress policy wall v1 has (see the template)
#   allow-write <dir>            the worker may write under <dir>
#   allow-write-prefix <path>    ... and any path that begins with <path> (~/.claude.json*)
#   deny-write <path>            but never under <path>, though an allow-write covers it
#   deny-read <dir>              and never read, list or stat anything under <dir>
#
# -- and this plug turns them into Seatbelt rules through darwin.sb.template, which sits
# in the same DIRECTORY. The directory is found from $0's dirname and never from this
# file's own name, so a copy of the plug under another name still finds its template.
#
# The profile is read here, OUTSIDE the wall, a moment before the exec; the walled
# process cannot write it (its directory is under $HERD_DIR/walls/, which is on no
# allow-write line). A path carrying a quote, a backslash or a control character is
# refused rather than escaped: it would be spliced into the rule language.
set -uo pipefail

SANDBOX=/usr/bin/sandbox-exec
walls="$(cd "$(dirname "$0")" && pwd)"
template="${walls}/darwin.sb.template"

die() { echo "walls/darwin: $*" >&2; exit 2; }

# a path fit to stand between double quotes in a rule: absolute, printable, no quote or
# backslash (bash 3.2: a bracket class, no regex engine needed)
safe_path() {
  case "$1" in
    /*) ;;
    *) return 1 ;;
  esac
  case "$1" in
    *[\"\\]*|*[[:cntrl:]]*) return 1 ;;
  esac
  return 0
}

rules_for() {
  # rules_for <verb> <profile>: the Seatbelt rules for every line of that verb
  local want="$1" profile="$2" verb path
  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in ''|'#'*) continue ;; esac
    verb="${line%% *}"
    path="${line#* }"
    [[ "$verb" == "$want" ]] || continue
    safe_path "$path" || die "profile line refused (not a plain absolute path): ${verb}"
    case "$verb" in
      allow-write)        printf '(allow file-write* (subpath "%s"))\n' "$path" ;;
      allow-write-prefix) printf '(allow file-write* (prefix "%s"))\n' "$path" ;;
      deny-write)         printf '(deny file-write* (subpath "%s"))\n' "$path" ;;
      deny-read)          printf '(deny file-read* (subpath "%s"))\n' "$path" ;;
    esac
  done < "$profile"
}

render() {
  local profile="$1" egress="" line verb
  while IFS= read -r line || [[ -n "$line" ]]; do
    case "$line" in ''|'#'*) continue ;; esac
    verb="${line%% *}"
    case "$verb" in
      egress) egress="${line#* }" ;;
      allow-write|allow-write-prefix|deny-write|deny-read) ;;
      *) die "profile line refused (unknown verb): ${verb}" ;;
    esac
  done < "$profile"
  # v1 has one egress policy. Anything else is a profile this plug cannot honour, and a
  # wall that silently ignored it would be the half-wall the v2 seam exists to prevent.
  [[ "$egress" == "open" ]] || die "profile egress '${egress}' is not built (wall v1 renders 'open' only)"
  [[ -f "$template" && ! -L "$template" ]] || die "no template at ${template}"
  # A marker line is `@@<NAME>@@` alone on its line; it is matched by shape and dispatched
  # by NAME, so the full marker spelling lives in the template and nowhere else. An
  # unknown marker is a template this plug cannot render: refused, never copied through.
  local tline marker tmp_dir cache_dir
  while IFS= read -r tline || [[ -n "$tline" ]]; do
    marker=""
    case "$tline" in
      @@*@@) marker="${tline#@@}"; marker="${marker%@@}" ;;
    esac
    if [[ -z "$marker" ]]; then
      printf '%s\n' "$tline"
      continue
    fi
    case "$marker" in
      ALLOW_WRITE)
        # the platform's own places every process writes: the devices (/dev/null, the
        # pane's tty) and this user's temporary and cache directories under /var/folders
        printf '(allow file-write* (subpath "/dev"))\n'
        tmp_dir="$(getconf DARWIN_USER_TEMP_DIR 2>/dev/null || true)"
        cache_dir="$(getconf DARWIN_USER_CACHE_DIR 2>/dev/null || true)"
        for d in "$tmp_dir" "$cache_dir"; do
          [[ -n "$d" && -d "$d" ]] || continue
          d="$(cd "$d" && pwd -P)"
          safe_path "$d" && printf '(allow file-write* (subpath "%s"))\n' "$d"
        done
        rules_for allow-write "$profile"
        rules_for allow-write-prefix "$profile"
        ;;
      DENY_WRITE) rules_for deny-write "$profile" ;;
      DENY_READ) rules_for deny-read "$profile" ;;
      # wall v2 renders its egress policy here; v1 has only `open` (checked above)
      EGRESS_POLICY) printf '; egress: open -- wall v1 does not restrict the network\n' ;;
      *) die "template marker not known to this plug: ${marker}" ;;
    esac
  done < "$template"
}

# The kernel's answer, not the environment's: sandbox_check(pid, NULL, 0) is 1 for a process
# some Seatbelt profile already holds. Anything else -- no python3, no symbol, an error -- is
# "not inside", so a spawn that asks stays a refusal.
behind_a_wall() {
  local py
  py="$(command -v python3 2>/dev/null || true)"
  [[ -n "$py" ]] || return 1
  "$py" -I - >/dev/null 2>&1 <<'PY'
import ctypes, os, sys
try:
    check = ctypes.CDLL("/usr/lib/libSystem.B.dylib").sandbox_check
    check.restype = ctypes.c_int
    sys.exit(0 if check(ctypes.c_int(os.getpid()), None, ctypes.c_int(0)) == 1 else 1)
except Exception:  # noqa: BLE001
    sys.exit(1)
PY
}

case "${1:-}" in
  available)
    [[ -x "$SANDBOX" ]] || exit 1
    [[ -f "$template" && ! -L "$template" ]] || exit 1
    # A wall does not nest. Behind one, a trial of `(allow default)` can still pass while
    # the worker's real profile is refused (sandbox_apply: exit 71, measured 2026-09-25),
    # so a process already walled is told no here, before the probe, not after it.
    ! behind_a_wall || exit 1
    # a trial wall: sandbox-exec refuses inside some sandboxes, and a plug that says
    # "available" and then cannot exec is a spawn that fails after the probe
    "$SANDBOX" -p '(version 1)(allow default)' /usr/bin/true >/dev/null 2>&1 || exit 1
    exit 0
    ;;
  inside)
    behind_a_wall || exit 1
    exit 0
    ;;
  exec)
    shift
    profile="${1:-}"
    [[ $# -ge 1 ]] && shift
    [[ "${1:-}" == "--" ]] && shift
    [[ -n "$profile" && -f "$profile" && ! -L "$profile" ]] || die "no profile at ${profile:-(none)}"
    [[ $# -ge 1 ]] || die "exec: no command"
    [[ "$1" == /* ]] || die "exec: the command must be an absolute path"
    sbpl="$(render "$profile")" || exit 2
    # the marker a spawn started from behind this wall reads (see the header); a directory
    # name that is not a worker name marks nothing
    inside_name="$(basename "$(dirname "$profile")")"
    case "$inside_name" in
      *[!a-z0-9_-]*|[!a-z]*) unset HERD_WALL_INSIDE ;;
      *) export HERD_WALL_INSIDE="$inside_name" ;;
    esac
    exec "$SANDBOX" -p "$sbpl" "$@"
    ;;
esac
echo "usage: darwin.sh available | inside | exec <profile> -- <cmd...>" >&2
exit 2
