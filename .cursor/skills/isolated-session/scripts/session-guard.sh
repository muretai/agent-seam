#!/usr/bin/env bash
# The hook behind the isolated-session rule: what a chat did not read, this refuses.
#
# Claude Code (.claude/settings.json), Cursor (.cursor/hooks.json) and Grok Build (which
# reads both of those files) run it on session start, before a file-editing tool, and on
# session end, with the event as JSON on stdin. It reads either spelling of the payload
# (Claude Code's snake_case, Cursor's and Grok Build's camelCase) and answers in the
# dialect that asked:
#   * an edit inside the primary checkout is refused -- the primary is read-only for
#     sessions, worktrees are where work happens;
#   * an edit inside a worktree another live session holds is refused, naming it;
#   * an edit inside a worktree nobody holds is refused -- claim it first;
#   * session start takes the worktree this chat opened directly (when nobody live
#     holds it) and puts the open-session inventory in front of the chat; for Cursor it
#     also hands the chat its owner key through the response's `env`, so the chat's
#     later shell commands name the same owner its hooks do; session end releases every
#     folder this session held.
# Fail open on anything unexpected: a hook crash must never wedge the editor, and a
# refusal is always a sentence a person can act on. ISOLATED_SESSION_GUARD=off in the
# editor's environment disables it; ISOLATED_SESSION_GUARD_TRACE=1 appends one line per
# event to <primary>/.git/isolated-session-guard.log -- how a new harness's dialect is
# verified on its first live chat.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/lib.sh"

raw="$(cat 2>/dev/null || true)"
fields="$(printf '%s' "$raw" | python3 -c '
import json, os, sys
try:
    ev = json.load(sys.stdin)
except Exception:
    ev = {}
if not isinstance(ev, dict):
    ev = {}
def first(*keys):
    for k in keys:
        v = ev.get(k)
        if isinstance(v, str) and v:
            return v
    return ""
ti = ev.get("tool_input")
if not isinstance(ti, dict):
    ti = ev.get("toolInput")
if not isinstance(ti, dict):
    ti = {}
path = ""
for k in ("file_path", "filePath", "notebook_path", "notebookPath", "path", "target_notebook",
          "target_file", "targetFile"):
    v = ti.get(k)
    if isinstance(v, str) and v:
        path = v
        break
cwd = first("cwd", "workspaceRoot", "workspace_root")
roots = ev.get("workspace_roots") or ev.get("workspaceRoots")
if not cwd and isinstance(roots, list) and roots and isinstance(roots[0], str):
    cwd = roots[0]
if not cwd:
    cwd = os.environ.get("GROK_WORKSPACE_ROOT") or os.environ.get("CLAUDE_PROJECT_DIR") or ""
event = first("hook_event_name", "hookEventName") or os.environ.get("GROK_HOOK_EVENT", "")
tool = first("tool_name", "toolName")
sid = first("session_id", "sessionId", "conversation_id", "conversationId") or os.environ.get("GROK_SESSION_ID", "")
camel = any(k in ev for k in ("sessionId", "toolName", "toolInput", "workspaceRoot", "hookEventName"))
cells = (event, tool, path, cwd, sid, "camel" if camel else "snake")
# unit separator, not a tab: bash `read` folds runs of IFS whitespace, so an empty
# tool or path column would shift every column after it
print("\x1f".join(str(c).replace("\x1f", " ").replace("\n", " ") for c in cells))
' 2>/dev/null)" || fields=""
IFS=$'\x1f' read -r event tool path cwd session shape <<< "$fields"
event="${event:-}"; tool="${tool:-}"; path="${path:-}"; cwd="${cwd:-}"; session="${session:-}"; shape="${shape:-snake}"
event_lc="$(printf '%s' "$event" | tr '[:upper:]' '[:lower:]')"

# Which harness asked, and so which dialect answers:
#   grok   -- Grok Build: GROK_HOOK_EVENT in the environment, or a camelCase envelope
#             with no Cursor-style event name; deny = {"decision":"deny","reason"}
#   cursor -- camelCase event names (preToolUse ...); deny = {"permission":"deny",...}
#   claude -- Claude Code (PascalCase); deny = exit 2 with the reason on stderr
if [[ -n "${GROK_HOOK_EVENT:-}" ]]; then
  harness="grok"
else
  case "$event" in
    preToolUse|sessionStart|sessionEnd|beforeShellExecution|afterFileEdit|stop) harness="cursor" ;;
    *) if [[ "$shape" == "camel" ]]; then harness="grok"; else harness="claude"; fi ;;
  esac
fi

json_str() { python3 -c 'import json, sys; print(json.dumps(sys.argv[1]))' "$1"; }

trace() {  # $1 verdict
  [[ "${ISOLATED_SESSION_GUARD_TRACE:-0}" == "1" ]] || return 0
  local primary
  primary="$(iso_primary_of "${cwd:-.}" 2>/dev/null)" || return 0
  printf '%s %s %s owner=%s session=%s %s %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$harness" \
    "$event" "${owner:-?}" "${session:-}" "$1" "${path:-}" >> "$primary/.git/isolated-session-guard.log" 2>/dev/null || true
}

allow() {
  trace allow
  if [[ "$harness" == "cursor" ]]; then
    if [[ "$event_lc" == "pretooluse" ]]; then printf '{"permission":"allow"}\n'; else printf '{}\n'; fi
  fi
  exit 0
}
deny() {
  trace deny
  case "$harness" in
    cursor)
      printf '{"permission":"deny","userMessage":%s,"agentMessage":%s}\n' "$(json_str "$1")" "$(json_str "$1")"
      exit 0 ;;
    grok)
      printf '{"decision":"deny","reason":%s}\n' "$(json_str "$1")"
      exit 0 ;;
  esac
  printf '%s\n' "$1" >&2
  exit 2
}
context() {  # $1 text, [$2 env key=value to hand the chat]
  trace context
  case "$harness" in
    cursor)
      if [[ -n "${2:-}" ]]; then
        printf '{"additional_context":%s,"env":{"ISOLATED_SESSION_OWNER":%s}}\n' "$(json_str "$1")" "$(json_str "$2")"
      else
        printf '{"additional_context":%s}\n' "$(json_str "$1")"
      fi ;;
    *) printf '%s\n' "$1" ;;
  esac
  exit 0
}

[[ "${ISOLATED_SESSION_GUARD:-on}" == "off" ]] && allow
[[ -z "$cwd" ]] && cwd="$(pwd)"

# The owner key. A Cursor chat is `cursor:<conversation_id>` -- every chat in a window
# shares one process, so the process cannot be the key -- and that key is handed to the
# chat's shells from sessionStart. Anyone else is their process (one per chat).
harness_key=""
key_from_payload="no"
if [[ -z "${ISOLATED_SESSION_OWNER:-}" && -n "$session" ]] && iso_harness_keys_shells "$harness"; then
  harness_key="${harness}:${session}"
  key_from_payload="yes"
fi
owner="$(iso_owner "$harness_key")"

case "$event_lc" in
  pretooluse)
    tool_lc="$(printf '%s' "$tool" | tr '[:upper:]' '[:lower:]')"
    case "$tool_lc" in
      *edit*|*write*|*notebook*|*create*|*delete*|*replace*|*patch*) ;;
      *) allow ;;
    esac
    [[ -z "$path" ]] && allow
    [[ "$path" == /* ]] || path="${cwd%/}/${path}"
    primary="$(iso_primary_of "$path")" || allow
    wt="$(iso_worktree_of "$path")" || allow
    rel="${path#"$primary"/}"
    if ! iso_is_linked "$wt"; then
      deny "isolated-session: refusing to edit ${rel} in the primary checkout ${primary}. The primary is read-only for sessions. Run: bash .cursor/skills/isolated-session/scripts/ensure-worktree.sh \"<task>\" and edit inside the WORKTREE it prints."
    fi
    case "$(iso_lock_state "$wt" "$owner")" in
      mine) iso_lock_touch "$wt" "$owner"; allow ;;
      free) deny "isolated-session: no session holds ${wt}. Run: bash .cursor/skills/isolated-session/scripts/claim-worktree.sh \"${wt}\" (or ensure-worktree.sh with this task) before editing there." ;;
      dead) deny "isolated-session: ${wt} is held by a session that is gone ($(iso_lock_describe "$wt")). Run: bash .cursor/skills/isolated-session/scripts/claim-worktree.sh \"${wt}\" to take it over." ;;
      other) deny "isolated-session: ${wt} is open in another live session -- $(iso_lock_describe "$wt"). Two chats must not share a folder. Open your own: bash .cursor/skills/isolated-session/scripts/ensure-worktree.sh \"<task>\". $(iso_lock_fix_hint "$wt" "$owner" | tr '\n' ' ')" ;;
    esac
    allow
    ;;
  sessionstart)
    primary="$(iso_primary_of "$cwd")" || allow
    wt="$(iso_worktree_of "$cwd")" || allow
    # the no-push wall goes up the moment a chat opens a checkout, before any edit
    iso_prepush_install "${wt:-$primary}" >/dev/null 2>&1 || true
    key_line=""
    if [[ "$key_from_payload" == "yes" ]]; then
      key_line=" This chat's owner key is ${owner}; its shells carry it as ISOLATED_SESSION_OWNER (if a script says otherwise: export ISOLATED_SESSION_OWNER=${owner})."
    fi
    if iso_is_linked "$wt"; then
      branch="$(git -C "$wt" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
      case "$(iso_lock_state "$wt" "$owner")" in
        mine)
          iso_lock_touch "$wt" "$owner"
          msg="isolated-session: this chat holds ${wt} (${branch}).${key_line}"
          ;;
        free|dead)
          iso_lock_write "$wt" "$owner" "$(iso_kind_of_branch "$branch")" "$branch" "(opened directly)"
          msg="isolated-session: this chat now holds ${wt} (${branch}). Edit only here; finish with finish-worktree.sh.${key_line}"
          ;;
        other)
          msg="isolated-session: STOP -- ${wt} is open in another live session: $(iso_lock_describe "$wt"). Every edit here will be refused. Tell the user, and open a worktree of your own with ensure-worktree.sh.${key_line}"
          ;;
      esac
    else
      msg="isolated-session: this chat opened the primary checkout ${primary}, which is read-only for sessions. Before any edit: bash .cursor/skills/isolated-session/scripts/stale.sh && bash .cursor/skills/isolated-session/scripts/ensure-worktree.sh \"<task>\" -- then edit only inside the WORKTREE it prints.${key_line}"
    fi
    inventory="$(iso_sessions_report "$primary")"
    if [[ "$key_from_payload" == "yes" ]]; then
      context "${msg}
== open sessions ==
${inventory}" "$owner"
    fi
    context "${msg}
== open sessions ==
${inventory}"
    ;;
  sessionend)
    primary="$(iso_primary_of "$cwd")" || allow
    while IFS= read -r wt; do
      [[ "$(iso_lock_state "$wt" "$owner")" == "mine" ]] && iso_lock_release "$wt"
    done < <(git -C "$primary" worktree list --porcelain 2>/dev/null | awk '/^worktree /{print $2}')
    allow
    ;;
  *)
    allow
    ;;
esac
