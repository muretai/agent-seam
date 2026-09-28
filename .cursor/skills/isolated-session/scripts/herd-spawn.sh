#!/usr/bin/env bash
# Start one worker session through herdr: a tab in a checkout, an interactive agent
# in it (its own process, so the session guard sees it as its own session), and a
# brief as its first prompt.
#
#   herd-spawn.sh <name> <brief-file> [--cwd DIR] [--profile worker|reviewer|coordinator]
#                 [--env K=V ...] [--var KEY=VALUE ...] [--allow 'Bash(...)' ...]
#                 [--muretai-agent NAME] [--role solo]
#
#   name        the worker: its herdr tab label and agent name, its own directory
#               $HERD_DIR/<name>/ (the one directory added to the session) and its
#               report there, $HERD_DIR/<name>/report.md. HERD_DIR defaults to
#               ~/.cache/muretai-herd (never /tmp: see iso_herd_dir), and it, the
#               cwd and everything above them must be writable by nobody else;
#               ~/.cache/muretai-herd; it is created mode 700 when absent and refused (exit 2)
#               when it exists and someone else owns it: a brief is a prompt for an
#               autonomous session, and a report is what the owner reads.
#   brief-file  the brief. {{KEY}} placeholders are filled from --var KEY=VALUE;
#               {{NAME}}, {{PRIMARY}} (the cwd) and {{REPORT}} are filled for you,
#               in one pass (a value is never re-scanned for a later key), and a
#               placeholder the template carries that nobody filled stops the spawn
#               (exit 2) rather than reaching a worker as literal braces. The filled
#               brief is written to $HERD_DIR/<name>/brief.md, mode 600, BEFORE herdr
#               is asked to create a tab, start an agent or type anything, and to the
#               operator's copy $HERD_DIR/briefs/<name>.md. A REGULAR brief.md already
#               there (a previous spawn of the same name, or a plant) is REWRITTEN with
#               this render: the exact path is unlinked, then created O_EXCL, the way
#               permissions.json is -- a re-used name gets its new brief, never the old
#               one and never none. A symlink or a directory at that path is still
#               exit 2, judged before anything is written; so is a symlinked worker
#               directory or briefs/. (This reverses the earlier "exit 2, never
#               overwritten or rotated" rule: ISSUE(herd-spawn-writes-the-brief-outside-
#               the-worker-directory).) The worker is TOLD one
#               short line: `Read <brief.md> and follow it. Your report goes to
#               <report.md>.` A pty drops typed input past about 1 KB and a stalled
#               prompt is re-typed, so a brief typed into the pane arrived cut short
#               (ISSUE(herd-spawn-stall-recovery-truncates-brief)); the body never
#               travels on any herdr argv.
#               A spawn that fails after writing brief.md exits non-zero, prints no
#               worker= line, and says on ONE stderr line which steps completed (the
#               tab and pane, whether the agent started) and that the brief was not
#               delivered. It removes brief.md only when nothing was typed into the
#               pane (a tab, start or wait failure, a first-run prompt); when `agent
#               prompt` itself failed -- a stall past the deadline, a timeout, a
#               refusal -- the line may already be in the pane, so brief.md is KEPT and
#               the message says so: a worker that did get the line finds its brief.
#   --cwd DIR   where the tab opens; default: the primary checkout of the repository
#               this script lives in. A worker opens its own worktree from there.
#               A WALLED worker's landing gate binds to the branch this directory has
#               checked out at spawn, so on the primary (the base branch) it records no
#               gate and says `gate=none (cwd is the primary on <base>)` on stderr and in
#               wall.log; an IMPLEMENTER brief (implementer.md, by its first line) walled
#               there is exit 2 before a tab -- pass --cwd <WORKTREE>. A Dispatch ticket
#               (dispatch-ticket.md) there still starts, with gate=none: dispatch-take.sh
#               now spawns it in the ticket's worktree, and this is the fallback for an
#               older dispatch-take (or a by-hand spawn) that did not.
#               REQUIRED in practice for HERD_SPAWN_HARNESS=codex: a codex session's
#               writable sandbox root IS this directory, and no session guard runs on
#               that harness, so a primary checkout here is exit 2 before herdr is asked
#               anything -- name the worktree instead.
#   --profile   which allowlist the session gets (below). `worker` (default) may run
#               the test runner and the test files; `reviewer` may not -- a reviewer
#               runs no tests, its brief says so, and what it reads is a diff an
#               attacker may have authored in full, so it gets no exec it does not need.
#               `coordinator` is the Dispatch coordinator's pane: it spawns through
#               this script, drives panes with the herdr agent/tab verbs (never `agent
#               start`: that is denied), reads the node inbox, sends dms, reads the
#               coordinator directory and edits only its intake/ and briefs/. The seat is
#               not a harness name: the spawn must write this pane's allow and deny into
#               a file that harness loads alone, and register appl-hook.sh on that pane
#               alone. Claude can. Cursor and codex cannot, and each is exit 2 naming
#               what is missing, before herdr is asked.
#               Its settings file alone also carries the harness: a UserPromptSubmit and
#               a SessionStart hook through appl-hook.sh, the appl-*.sh scripts by exact
#               path, and the Agent tool for the three appl-* subagents.
#   --allow 'Bash(...)'
#               one more allow rule for this session (repeatable): the brief's author
#               widening the list for a task-specific command, so the worker does not
#               stop on it. Bash rules only. A rule a deny entry would beat anyway (it
#               would still stop), or one naming a reader, an interpreter or a network
#               command, is exit 2 with one line and no worker. An accepted rule goes
#               into the settings file verbatim and nowhere else (no argv, no stdout).
#   --env K=V   extra environment for the tab (repeatable). A key the SPAWN sets itself is
#               refused here, by name: CODEX_HOME, CURSOR_CONFIG_DIR, PYTHONNOUSERSITE,
#               CLAUDE_CODE_DISABLE_AUTO_MEMORY, HERD_WORKER, HERD_BRIEF, HERD_REPORT,
#               ISOLATED_SESSION_GUARD_TRACE, MURETAI_HERDR_AGENT (which has a flag of
#               its own, --muretai-agent, with a name rule this door would skip), and
#               HERD_WALL_INSIDE (the wall's own marker: the plug sets it, a caller never). The
#               caller's entries are appended AFTER the spawn's on `herdr tab create`, so a
#               duplicate key leaves it to herdr's dedup order which value the tab gets --
#               neither pinned here nor testable, and the two it would decide are the
#               interpreter wall and the config home. MURETAI_BINDING_FILE and
#               ISOLATED_SESSION_OWNER are deliberately NOT on the list: the spawn never
#               sets the first, and sets the second only when the caller did not (a walled
#               worker's default key is its own name -- THE OWNER KEY, in the wall block --
#               and a caller's entry is then the only one on the tab). The first names a
#               binding a node child reads, and the second is
#               how a test-author / implementer pair hands its worktree lock over: every
#               lock of the cwd's repository owned by that key passes to THIS worker by
#               name (stderr says which), and the worker's session binds its own process
#               at its first guarded command -- see the pair hand-over in lib.sh.
#               The wall's knobs are the exception the other way: `--env HERD_WALL=off`
#               (and HERD_WALL_EGRESS, _CPU_SECS, _MEM_MB, _PROCS) set THIS spawn's wall,
#               exactly as the same variable in the spawn's environment would, and are
#               never put on the tab.
#               A coordinator-profile tab always carries DISABLE_AUTOUPDATER=1 (an
#               in-pane update must not end the long-lived coordinator mid-loop); a
#               caller's DISABLE_AUTOUPDATER on that profile is exit 2.
#   --muretai-agent NAME
#               mark the pane as that Muretai agent's wake target: tab env
#               MURETAI_HERDR_AGENT=NAME, then herdr pane report-metadata with
#               token muretai_agent=NAME (never a DID). Without this flag the
#               spawn is unchanged.
#   --role solo DECLARE the worker a solo one: spawned alone, with no test-author /
#               implementer pair, whose report appl-verify.sh checks as a landing with an
#               empty pin (ISSUE(single-worker-report-is-ignored)). Any other value, or no
#               value, is exit 2 before herdr is asked anything. The role is never inferred
#               from a name or a brief. The spawn writes it TWICE, each file mode 400,
#               created exclusively (the exact path unlinked first): the marker
#               $HERD_DIR/<name>/role, beside permissions.json, and the spawn's own record
#               $HERD_DIR/.roles/<name>, in a herd-level directory that is no worker's
#               --add-dir (a worker name starts with a letter, so `.roles` is never one) and
#               is Edit-denied to every session. appl-role-of.sh says `solo` only when BOTH
#               are there: the marker alone is in the worker's own directory, where it could
#               write one and skip its pin check. Since 2026-09-26 (Option B) a worker-profile
#               spawn WITHOUT --role writes the same two files: an operator's own spawn is
#               solo, and a pair worker stays its template's role because appl-role-of.sh
#               lets a template brief win over any record. A reviewer or coordinator spawn
#               removes both, so a record left by an earlier spawn never promotes it.
#               Every spawn, whatever its role, also records the repository its worker's
#               report is judged in: $HERD_DIR/.repos/<name>, `iso_primary_of <cwd>` and a
#               newline, mode 600 in a herd-level directory of mode 700, Edit-denied like
#               .roles/, written before the tab exists and removed with the brief when the
#               spawn fails. appl-hook.sh reads it as `appl-verify.sh --repo`; a cwd with no
#               repository is refused before herdr is asked anything.
#
# Exit 3, one line on stderr, when herdr is not on PATH or its server is not running
# (HERD_SPAWN_BIN names the binary explicitly; the tests point it at a stub). Exit 2
# on a usage error. On success the one stdout line is
#   worker=<name> pane=<id> tab=<id> report=<path> harness=<h> model=<m> wall=walled|unwalled|inherited egress=open
# (`inherited`: this spawn itself runs behind a wall that cannot nest -- see THE WALL.)
#
# HERD_WALL (require|prefer|off), HERD_WALL_EGRESS (open; deny is refused until wall v2),
# HERD_WALL_CPU_SECS (7200), HERD_WALL_MEM_MB (8192) and HERD_WALL_PROCS (512): the wall
# the worker runs behind, its probe, and the bounds it runs under -- see "the wall and the
# bounds" below; the record is $HERD_DIR/walls/<name>/wall.log.
#
# HERD_SPAWN_READY_SECS (default 30) is how long `agent start` is retried while the
# pane's shell prints its prompt. HERD_SPAWN_AGENT_READY_SECS (default 120) is how
# long, after start succeeds, to wait for the agent's input line (`herdr agent wait
# --until idle`) and is the caller --timeout on `agent prompt`. The two waits are
# not folded: start succeeding means the process is in the pane, not that a brief
# will be read. A spawn either hands the brief to an agent that took it, or fails.
#
# The agent runs on `opus` (HERD_SPAWN_MODEL overrides it: an alias or a model id) and
# in `auto` permission mode (HERD_SPAWN_PERMISSION_MODE overrides it,
# and only with `auto`, `acceptEdits`, `manual` or `plan`: anything else -- a
# `bypassPermissions`, a `dontAsk`, an empty string -- is exit 2 before herdr is asked
# anything, and the value is not handed down: a worker's own landing spawns the next
# reviewer from the default again unless that worker's environment says otherwise; on the
# codex harness the knob does not apply at all, and a SET value is exit 2 rather than a
# validated word nobody uses -- see the codex block below):
# the classifier answers the routine prompts and stops on the risky ones, which is what
# lets a worker run unattended -- in acceptEdits the first real reviewer stopped on
# every read-only `git config` and `ls` outside the allowlist. The project's PreToolUse
# session guard still refuses the primary and other sessions' worktrees whatever the mode --
# but only on the three harnesses that read it, which are claude, cursor and grok, and NOT on
# codex, which reads neither `.claude/settings.json` nor `.cursor/hooks.json`. The
# allowlist below covers what the briefs ask for and no more: a Bash rule matches the
# command's PREFIX, so `python3` alone would have allowed `python3 -c` anything, and a
# directory prefix (`python3 tools/`) would have run a `tools/evil.py` the reviewed diff
# itself landed -- for a REVIEWER the rules name each script by its exact path, in the
# bare AND the isolated (`python3 -I ...`) spelling the briefs instruct, plus
# `-m agent.plugins`. A WORKER runs the code of its own worktree anyway, so it also has
# `python3 tools/*`, `python3 tests/*` and `env -u * python3 tests/*` (the no-stops plan's
# S2: a worker stopped on every task script), and `test_*.py` in the isolated spelling.
# Both profiles have the glue a worker chains
# after a real command -- echo, printf, pwd, true, test, mkdir -p -- and three read-only
# git verbs (S1: a `cmd && echo "$X"` line stopped at the classifier because `echo` was on
# no list). `cat` is not on it (Read is the tool for a
# file). `git push` is refused outright -- by the session's own rule, which is a promise
# the session keeps, not a guard on the remote. A worker is an interactive session,
# billed like one.
#
# The rules reach the session as a settings file the spawn writes EXCLUSIVELY
# ($HERD_DIR/<name>/permissions.json: the exact path is removed first, then created
# O_EXCL mode 600, so a planted symlink is unlinked and never followed and a racer's
# file is a refusal, not a merge), in a per-worker directory that must be a real
# directory the caller owns (created mode 700; a symlink or another uid's directory is
# exit 2). The session loads the project and local settings only (`--setting-sources
# project,local`): the owner's user-global allow rules never reach a worker, so the file
# is the rules, not a patch over an inherited allow. The deny list names the shell
# readers and interpreters that would read around `--add-dir` (sed, awk, od, perl, a
# versioned python3, `git diff --no-index`, ...). A deny list is not containment: it
# removes the commands the classifier might wave through, and nothing else -- see
# ISSUE(reviewer-sandbox-is-a-denylist).
#
# THE CODEX HARNESS IS DIFFERENT IN KIND (HERD_SPAWN_HARNESS=codex), and the difference is
# not a detail to smooth over. Codex has NO per-command allow/deny list: Claude Code's
# `Bash(cmd:*)` and Cursor's `Shell(cmd:args*)` have no spelling there, so the canonical
# lists above are NOT enforced on it. Its wall is the SANDBOX (`-s workspace-write`) plus
# the approval policy (`-a on-request`), and nothing else -- `git push`, `curl`, a read of
# `keys/` are stopped by the sandbox and by whatever a person answers at an approval
# prompt, never by a rule. `danger-full-access` and
# `--dangerously-bypass-approvals-and-sandbox` are never passed. Rather than pretend the
# lists hold, the spawn writes them to `$HERD_DIR/<name>/rules.unenforced.json` with a note
# saying they are not enforced, and prints one line on stdout saying the same, where the
# person spawning the worker reads it. It writes no permissions.json: a rules file the
# harness ignores would read as a wall that is not there. For the same reason a codex
# session REVIEWS NOTHING (a reviewer reads a diff an attacker may have authored in full,
# and the deny list it would need does not exist here) and COORDINATES NOTHING: `worker`
# is the only profile, and the other two are exit 2 before herdr is asked anything.
# And nothing stands beside that wall either: NO session guard runs on a codex worker --
# the isolated-session PreToolUse hook is registered in `.claude/settings.json` and
# `.cursor/hooks.json`, `scripts/session-guard.sh` dispatches claude, cursor and grok only,
# codex-cli reads neither file, and the `config.toml` this spawn writes registers no hook of
# its own (ISSUE(session-guard-has-no-codex-dialect)). So the directory a codex session
# opens in is the whole of its blast radius, and a codex worker is ALWAYS given
# `--cwd <worktree>`: with `-s workspace-write` that directory IS the writable sandbox root
# and `-a on-request` escalates only for writes OUTSIDE it, so every write inside runs with
# no approval at all. A cwd that is a PRIMARY checkout -- which is the default when no
# `--cwd` is passed -- is exit 2 before herdr is asked anything, the way the cursor branch
# refuses the primary for its own narrower reason.
# Codex reads its own `AGENTS.md` and `config.toml` from CODEX_HOME (default `~/.codex`),
# and the user's copies there are writable by any session of this user -- the same hazard
# that keeps a cursor session from reviewing. So the tab is handed a config home the SPAWN
# owns, `CODEX_HOME=$HERD_DIR/<name>/codex-home` (mode 700, refused when it is a symlink or
# another uid's), holding one `config.toml` the spawn wrote exclusively: the model, the
# sandbox mode, the approval policy, nothing else. That home must hold NOTHING the spawn did
# not just write: a non-empty one is exit 2 listing what is in the way, because a planted
# `AGENTS.md` there would BE the worker's instructions, living in no checkout and in no diff.
# It is refused, never emptied, and a spawn that fails later removes the two files it made,
# so the retry is not refused by this spawn's own leftover.
# Only the login crosses over, and as a
# SYMLINK to the user's own `auth.json`: the path is handled, the content never read,
# printed or copied, and a user with no login is told to log in rather than handed a
# session that starts and cannot talk. That path is judged before it is linked -- a REGULAR
# file (`-L` first, then `-f`) owned by the caller (`-O`), under a home that passes
# `iso_private_path` -- because `-e` follows a symlink and accepts a directory or a fifo, and
# what is linked in is what the session is billed to. CODEX_HOME itself is read ONCE, for
# that login, and then `unset` like HERD_SPAWN_HARNESS and HERD_SPAWN_MODEL, so a spawn a
# worker starts does not inherit a home it never chose; a caller `--env CODEX_HOME=` is
# refused where --env is parsed. HERD_SPAWN_PERMISSION_MODE is refused there too: it is a
# claude knob, the codex approval policy is fixed at `-a on-request`, and a validated value
# this branch then discards is the one place this script would read a wall into something
# that is not one. HERD_SPAWN_MODEL is passed as `-m`; unset means the
# account default (measured 2026-09-20 on codex-cli 0.155.1: `gpt-5.1-codex-max` is
# refused for a ChatGPT account, so there is no id to pin here).
#
# Every `python3` below is `-I` (isolated: no user site directory, no PYTHON* variable
# read). Two of them decide what the reviewer is TOLD and what it may RUN -- the render of
# its brief and the write of that permission list -- and a caller used to reach this script
# outside the landing's wall, so a `usercustomize.py` a branch's own test run had planted
# in the operator-writable user site directory rewrote both, from outside any checkout a
# guard here looks at (ISSUE(security-audit-2026-09-18-daily-2026-09-18-7)). The callers
# now run this script through `credless` as well; `-I` is the half that does not depend on
# the caller remembering. `tests/test_gate_pythons_are_isolated.py` checks it mechanically.
# The TAB the spawn creates is a third thing again: see tab_env below.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/lib.sh"

usage() {
  echo "usage: herd-spawn.sh <name> <brief-file> [--cwd DIR] [--profile worker|reviewer|coordinator] [--env K=V ...] [--var KEY=VALUE ...] [--allow 'Bash(...)' ...] [--muretai-agent NAME] [--role solo]" >&2
  echo "       HERD_SPAWN_HARNESS=codex requires --cwd <worktree>: a codex session's writable sandbox root IS the directory it opens in, and no session guard runs on that harness" >&2
  exit 2
}

name="${1:-}"
brief="${2:-}"
[[ -n "$name" && -n "$brief" ]] || usage
shift 2
# herdr's own rule for an agent name (checked here so the reason is one line, not a JSON
# error after the tab exists): a lowercase letter, then [a-z0-9_-], 32 characters at most
case "$name" in
  *[!a-z0-9_-]*|[!a-z]*)
    echo "herd-spawn: a worker name is [a-z][a-z0-9_-]* (herdr's agent-name rule; it also names a tab and a file): ${name}" >&2
    exit 2
    ;;
esac
if [[ ${#name} -gt 32 ]]; then
  echo "herd-spawn: a worker name is at most 32 characters (herdr's agent-name rule): ${name} (${#name})" >&2
  exit 2
fi
if [[ ! -f "$brief" ]]; then
  echo "herd-spawn: no brief at ${brief}" >&2
  exit 2
fi

cwd=""
profile="worker"
envs=()
vars=()
extra_allow=()
muretai_agent=""
role=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cwd) [[ $# -ge 2 ]] || usage; cwd="$2"; shift 2 ;;
    --profile) [[ $# -ge 2 ]] || usage; profile="$2"; shift 2 ;;
    # A key the SPAWN sets on the tab itself is refused here, before herdr is asked
    # anything and before a single directory is made. `tab_env` is assembled spawn-first
    # and the caller's entries are appended AFTER it, so two `CODEX_HOME=` entries leave
    # it to herdr's dedup order which one the tab gets -- an order this repository neither
    # pins nor tests, deciding the interpreter wall (PYTHONNOUSERSITE), the memory switch
    # and the codex config home. The refusal is where --env is PARSED, so it holds for
    # every harness and not only for the one that added the newest key. The printed key is
    # the literal this case matched, never the caller's bytes.
    --env)
      [[ $# -ge 2 ]] || usage
      case "${2%%=*}" in
        CODEX_HOME|CURSOR_CONFIG_DIR|PYTHONNOUSERSITE|CLAUDE_CODE_DISABLE_AUTO_MEMORY|HERD_WORKER|HERD_BRIEF|HERD_REPORT|ISOLATED_SESSION_GUARD_TRACE|MURETAI_HERDR_AGENT|HERD_WALL_INSIDE)
          echo "herd-spawn: --env ${2%%=*}=... is refused: the spawn sets that key on the tab itself and the caller's entries are appended after its own, so which value the tab got would be herdr's dedup order to decide; the worker ${name} was not started" >&2
          exit 2
          ;;
        # The wall and the bounds ride on the tab's PATH: its first entry is the launcher
        # directory under $HERD_DIR/walls/<name>/bin (see the wall block below). A caller
        # PATH would decide, by herdr's dedup order, whether the agent starts behind them.
        PATH)
          echo "herd-spawn: --env PATH=... is refused: the tab's PATH carries the launcher that starts the agent behind the wall and under the bounds, so a caller PATH could start it outside them; the worker ${name} was not started" >&2
          exit 2
          ;;
        # The wall's knobs are read by THIS spawn, not by the tab: `--env HERD_WALL=off` is
        # how a coordinator (whose rules allow this script's argv, not an env prefix) spells
        # them. Set here, validated below like the environment's own, never put on the tab --
        # where it would only have unwalled the spawns the worker itself starts.
        HERD_WALL|HERD_WALL_EGRESS|HERD_WALL_CPU_SECS|HERD_WALL_MEM_MB|HERD_WALL_PROCS)
          export "$2"; shift 2; continue ;;
      esac
      envs+=("$2"); shift 2 ;;
    --var) [[ $# -ge 2 ]] || usage; vars+=("$2"); shift 2 ;;
    --allow) [[ $# -ge 2 ]] || usage; extra_allow+=("$2"); shift 2 ;;
    --muretai-agent) [[ $# -ge 2 ]] || usage; muretai_agent="$2"; shift 2 ;;
    --role)
      [[ $# -ge 2 ]] || usage
      if [[ "$2" != "solo" ]]; then
        echo "herd-spawn: --role is solo or absent (got a value that is neither); the worker ${name} was not started" >&2
        exit 2
      fi
      role="$2"; shift 2 ;;
    *) echo "herd-spawn: unknown argument: $1" >&2; usage ;;
  esac
done
if [[ -n "$muretai_agent" ]]; then
  case "$muretai_agent" in
    *[!a-z0-9_-]*|[!a-z]*)
      echo "herd-spawn: --muretai-agent is [a-z][a-z0-9_-]* (herdr's agent-name rule): ${muretai_agent}" >&2
      exit 2
      ;;
  esac
  if [[ ${#muretai_agent} -gt 32 ]]; then
    echo "herd-spawn: --muretai-agent is at most 32 characters (herdr's agent-name rule): ${muretai_agent} (${#muretai_agent})" >&2
    exit 2
  fi
fi
case "$profile" in
  worker|reviewer|coordinator) ;;
  *) echo "herd-spawn: --profile is worker, reviewer or coordinator (got '${profile}'); the worker ${name} was not started" >&2; exit 2 ;;
esac
# A coordinator pane carries DISABLE_AUTOUPDATER=1 (set on the tab below), so a caller's
# `--env DISABLE_AUTOUPDATER=...` is refused for that profile rather than left to herdr's
# dedup order: a silent override would hide the mistake. Judged after the loop because
# --profile may follow --env on the line.
if [[ "$profile" == "coordinator" ]]; then
  for kv in ${envs[@]+"${envs[@]}"}; do
    if [[ "${kv%%=*}" == "DISABLE_AUTOUPDATER" ]]; then
      echo "herd-spawn: --env DISABLE_AUTOUPDATER=... is refused for the coordinator profile: the spawn sets DISABLE_AUTOUPDATER=1 on that tab itself, so an in-pane update cannot end the coordinator mid-loop; the worker ${name} was not started" >&2
      exit 2
    fi
  done
fi
# a solo worker lands its own work, which is what the worker profile is for; a reviewer or
# a coordinator declared solo would be verified as a landing it never makes
if [[ -n "$role" && "$profile" != "worker" ]]; then
  echo "herd-spawn: --role solo goes with the worker profile only (got '${profile}'); the worker ${name} was not started" >&2
  exit 2
fi

# --- the permission mode: one of four words, checked before herdr is asked anything ----
# Unset means `auto`; set means exactly one of the accepted values (an empty string is
# not "unset", it is a value nobody meant). The validated literal goes on the command
# line and the variable is dropped from this process, so a spawn started by a worker
# (its landing spawns the next reviewer) does not inherit a mode it never chose.
# Whether the caller SET it at all, remembered before the unset below: on codex the knob
# does not apply and any value -- `auto` included -- is a refusal, which is a different
# question from whether the value is one of the four words.
permission_mode_set=""
[[ -z "${HERD_SPAWN_PERMISSION_MODE+set}" ]] || permission_mode_set=yes
permission_mode="${HERD_SPAWN_PERMISSION_MODE-auto}"
case "$permission_mode" in
  auto|acceptEdits|manual|plan) ;;
  *)
    echo "herd-spawn: HERD_SPAWN_PERMISSION_MODE must be one of auto, acceptEdits, manual, plan (got '${permission_mode}'); the worker ${name} was not started" >&2
    exit 2
    ;;
esac
unset HERD_SPAWN_PERMISSION_MODE
# The model: `opus` unless HERD_SPAWN_MODEL says otherwise (a model alias or id, one
# token of letters, digits, dots and dashes). A reviewer reads a diff for twenty to
# forty minutes; on the owner's subscription that is the cost that matters, and the
# top-tier model is not what the reading needs. Dropped from this process like the
# mode, so a worker's own spawns start from the default again.
# The harness: `claude` (Claude Code), `cursor` (Cursor's CLI agent, `cursor-agent`) or
# `codex` (codex-cli), HERD_SPAWN_HARNESS. herdr drives any of them in a pane; the brief,
# the report directory and the receipt tools are the same. Cursor reads its rules from
# `<cwd>/.cursor/cli.json` (written below from the same allow/deny lists) and runs in its
# classifier mode (`--auto-review`); the isolated-session hook speaks its dialect already.
# Another model's eyes on a diff see other things; the cost lands on the other plan.
#
# Codex is different in kind and the top-of-file header says how: no per-command rules,
# so the sandbox and the approval policy are the whole wall, `worker` is the only profile,
# and the config home is the spawn's.
harness="${HERD_SPAWN_HARNESS-claude}"
case "$harness" in
  claude|cursor|codex) ;;
  *)
    echo "herd-spawn: HERD_SPAWN_HARNESS must be claude, cursor or codex (got '${harness}'); the worker ${name} was not started" >&2
    exit 2
    ;;
esac
unset HERD_SPAWN_HARNESS
# ... and now that the harness is known: HERD_SPAWN_PERMISSION_MODE is a CLAUDE knob.
# `permission_mode` is consumed by the claude branch alone; the codex argv is fixed at
# `-a on-request`, so a value accepted above and then dropped would let a caller who
# tightened a risky task believe a wall is on that is off. This landing went to real
# trouble not to do that anywhere else -- it writes `rules.unenforced.json` and prints a
# line on stdout precisely so nobody reads a wall into what is not one -- so the knob is
# refused rather than swallowed. Unset stays the normal path.
if [[ "$harness" == "codex" && -n "$permission_mode_set" ]]; then
  echo "herd-spawn: HERD_SPAWN_PERMISSION_MODE does not apply to the codex harness: its approval policy is fixed at -a on-request and this script passes no other, so a mode set here would be validated and then dropped; unset it, or start the worker on claude; the worker ${name} was not started" >&2
  exit 2
fi
# A Cursor session reads the user's own instruction files -- ~/.cursor/rules/*.mdc,
# ~/.agents/skills/ -- and cursor-agent has no switch to leave them out (measured
# 2026-09-12: a rule planted under ~/.cursor/rules steered a herd session at once).
# Every one of those is the owner's user's to write, so a session of that user could
# dictate a reviewer's receipt through them. Until Cursor honours an instruction home
# the spawn owns, a Cursor session reviews nothing
# (ISSUE(security-audit-2026-09-12-a-herd-session-can-r-b1b5)); and its rules file
# lives in the cwd, shared by every Cursor session there, so the cwd is never the
# primary (-2).
if [[ "$harness" == "cursor" && "$profile" == "reviewer" ]]; then
  echo "herd-spawn: the cursor harness reviews nothing yet: cursor-agent reads the user's own rules and skills, which any session of this user may write; the worker ${name} was not started" >&2
  exit 2
fi
# A codex session reviews nothing for a reason of its own: the deny list a reviewer is held
# to has no spelling on this harness at all (its wall is the sandbox and the approval
# policy), and a reviewer reads a diff an attacker may have authored in full. It is the
# PROFILE that is refused here, not the harness -- a codex worker is accepted.
if [[ "$harness" == "codex" && "$profile" == "reviewer" ]]; then
  echo "herd-spawn: the codex harness reviews nothing: it has no per-command deny list (its wall is the sandbox and the approval policy), and a reviewer reads a diff an attacker may have authored in full; the worker ${name} was not started" >&2
  exit 2
fi
# The model: for claude `opus` unless HERD_SPAWN_MODEL says otherwise; for cursor the
# account's default unless it does. One token: letters, digits, dots, dashes, and the
# bracketed overrides Cursor's names carry (`x[context=1m,effort=high]`). Set but empty,
# or anything else, is exit 2 before herdr is asked; dropped from this process like the
# mode, so a worker's own spawns start from the default again.
model=""
if [[ -n "${HERD_SPAWN_MODEL+set}" ]]; then
  model="$HERD_SPAWN_MODEL"
  if ! [[ "$model" =~ ^[a-z][]a-z0-9.=,[-]{0,79}$ ]]; then
    echo "herd-spawn: HERD_SPAWN_MODEL must be a model alias or id (letters, digits, dots, dashes, bracketed overrides; got '${model}'); the worker ${name} was not started" >&2
    exit 2
  fi
  # The brackets in that pattern are Cursor's (`gpt-5[effort=high]`), and they are what
  # makes it accept `x[bad` as well. A codex model id carries no brackets, so the codex
  # path refuses any token that has one: the shared pattern stays as it is for cursor, and
  # a typo that would reach codex-cli as a model name stops here instead. One pattern now
  # means two things depending on the harness -- ISSUE(model-pattern-differs-by-harness).
  if [[ "$harness" == "codex" && "$model" == *[][]* ]]; then
    echo "herd-spawn: HERD_SPAWN_MODEL carries a bracket, which is Cursor's override spelling and not part of any codex model id (got '${model}'); the worker ${name} was not started" >&2
    exit 2
  fi
fi
[[ -n "$model" || "$harness" != "claude" ]] || model="opus"
unset HERD_SPAWN_MODEL
# The coordinator seat is two inputs this spawn can write for THIS pane alone: the allow
# and deny, into a file the harness loads and the worker cannot rewrite, and appl-hook.sh
# on UserPromptSubmit and SessionStart. Claude's --settings file is both, and
# --setting-sources project keeps the user's own allow out of it. A harness that has
# neither input does not sit, and the refusal names the gap rather than a product.
# Translating Read(//) into Read(/) would not make a wall: cursor still has no per-pane
# hook, still reads instruction files the spawn does not own, and writes its rules into
# the cwd, which a coordinator shares with every other session because its cwd is the
# primary. Codex has no per-command deny and no hook at all. Neither writes
# rules.unenforced.json here: that file records a worker's lists, and a coordinator that
# cannot sit is not started.
if [[ "$harness" == "cursor" && "$profile" == "coordinator" ]]; then
  echo "herd-spawn: the cursor harness does not take the coordinator profile: appl-hook.sh has no per-pane slot on it (the hook is written only into the claude --settings file), and cursor-agent reads the user's own rules and skills, which any session of this user may write; its rules file is <cwd>/.cursor/cli.json, shared by every Cursor session in that directory, and a coordinator's cwd is the primary; the worker ${name} was not started" >&2
  exit 2
fi
if [[ "$harness" == "codex" && "$profile" == "coordinator" ]]; then
  echo "herd-spawn: the codex harness does not take the coordinator profile: it has no per-command deny list and no session-guard hook, so the spawn cannot write this pane's allow and deny or register appl-hook.sh on it alone; the worker ${name} was not started" >&2
  exit 2
fi

# --- the wall's mode, its egress, and the bounds: checked before herdr is asked anything --
# (P1 ISSUE(workers-have-no-resource-limit-and-no-egress-control); the wall block below
# says what each one does.) HERD_WALL is require, prefer or off. Unset is require,
# including where this machine has no wall: a missing plug does not pick a mode that
# tolerates the missing plug. Set to anything else -- an empty string included -- is
# exit 2: a typo must not become "no wall". The caller's bytes are
# not echoed back (the line must stay one line).
wall_mode=""
if [[ -n "${HERD_WALL+set}" ]]; then
  case "$HERD_WALL" in
    require|prefer|off) wall_mode="$HERD_WALL" ;;
    *)
      echo "herd-spawn: HERD_WALL must be require, prefer or off (unset is require, including where this machine has no wall); the worker ${name} was not started" >&2
      exit 2
      ;;
  esac
fi
# Wall v1 leaves the network OPEN, and says so (egress=open on the success line and in
# wall.log). Denying egress needs a loopback proxy holding a host allowlist -- a real
# worker needs its API, the Dispatch finish verbs need the relay -- which is wall v2 and
# not built. So `deny` is refused in every mode, rather than accepted and ignored: a
# worker that ran with the network open under a `deny` would be a half-wall.
if [[ -n "${HERD_WALL_EGRESS+set}" ]]; then
  case "$HERD_WALL_EGRESS" in
    open) ;;
    deny)
      echo "herd-spawn: HERD_WALL_EGRESS=deny is refused: wall v1 leaves the network open, and denying egress needs the loopback proxy of wall v2, which does not exist yet; the worker ${name} was not started" >&2
      exit 2
      ;;
    *)
      echo "herd-spawn: HERD_WALL_EGRESS must be open (wall v1; deny waits for the wall v2 proxy); the worker ${name} was not started" >&2
      exit 2
      ;;
  esac
fi
# The bounds: positive whole numbers, nine digits at most, or the default. There is no
# spelling of "unbounded": 0, -1, `unlimited`, an empty string, a fraction and a number
# too long to be meant are each exit 2, on one line naming the variable.
#   cpu   seconds of CPU time PER PROCESS (an rlimit: SIGXCPU). A session idles on its API
#         most of its life, so two hours is far past a long session and still ends a
#         test spinning in a loop.
#   mem   megabytes of memory (physical footprint) of the worker's whole process tree.
#   procs processes in the worker's tree -- its own, not the uid's.
wall_bound() {
  local var="$1" def="$2" out="$3"
  if [[ -n "${!var+set}" ]]; then
    if ! [[ "${!var}" =~ ^[1-9][0-9]{0,8}$ ]]; then
      echo "herd-spawn: ${var} must be a positive whole number of at most nine digits (there is no unbounded value); the worker ${name} was not started" >&2
      exit 2
    fi
    printf -v "$out" '%s' "${!var}"
  else
    printf -v "$out" '%s' "$def"
  fi
}
wall_bound HERD_WALL_CPU_SECS 7200 wall_cpu
wall_bound HERD_WALL_MEM_MB 8192 wall_mem
wall_bound HERD_WALL_PROCS 512 wall_procs
# dropped from this process like the other knobs, so a spawn a worker starts decides its
# own wall from the defaults again
unset HERD_WALL HERD_WALL_EGRESS HERD_WALL_CPU_SECS HERD_WALL_MEM_MB HERD_WALL_PROCS

# --- the deny list ------------------------------------------------------------------------
# What the shell may NOT do even when an allow rule would allow it: a deny rule is
# evaluated before any allow rule and before the auto-mode classifier. A deny list is
# NOT containment. `--add-dir` scopes the Read/Edit tools, not Bash; Bash reads whatever
# the uid reads, and the reviewer's cwd is the primary, where `keys/` lives. What the
# list does is remove the commands the classifier might wave through: the readers
# (`cat`, `sed`, `awk`, `od`, `xxd`, `strings`, `dd`, `tr`, `nl`, `rev`, `cut`, `fold`,
# `tee`, `less`, `more`, `head`, `tail`, `grep`, `wc`), the interpreters (`perl`, `ruby`,
# `node`, `php`, `python`, `python3 -c`, `python3 -` for a heredoc, a shell with a dash
# option: `bash -c`, `sh -lc`, ...), `git diff` outside the checkout (prints any file
# as `+` lines: `--no-index`, and git turns it on by itself when an operand is
# `/dev/null` or a path outside the repository, in EITHER position -- so `/dev/null`,
# an absolute, a `../` or a `~` operand and `--output` are denied wherever they stand,
# and `git diff` stays allowed for the range under review), and the network.
# Whatever is not listed goes to the classifier, and `bash <file the session wrote>`
# is not listed. The real wall is a credential no process can use alone and keys no
# session can read: ISSUE(reviewer-sandbox-is-a-denylist).
#
# Spelling (Claude Code's documented rule syntax): `Bash(x:*)` is `Bash(x *)` -- the
# prefix AND a space, so `Bash(ls:*)` does not match `lsof`, and `Bash(python:*)` does
# not reach the allowed `python3 tools/...`. A versioned interpreter (`python3.12`) has
# no space after `python3.`, so that one is the no-space wildcard `Bash(python3.*)`,
# and a shell's dash options (`-c`, `-lc`, `-ic`) are `Bash(bash -*)`. A `*` stands
# anywhere in a rule and matches any text, spaces included, so `Bash(git diff */dev/null*)`
# is `/dev/null` in any position after `git diff ` (measured on 2026-09-13; a deny beats
# any allow whatever the order of the operands: ISSUE(security-audit-2026-09-13-daily-2026-09-13)).
# Defined here, before herdr is asked anything, because --allow is judged against it.
deny=(
  "Bash(git push:*)" "Bash(git -C:*)" "Bash(git -c:*)" "Bash(python3 -c:*)"
  "Bash(git diff --no-index:*)" "Bash(git diff /dev/null:*)" "Bash(git diff --output:*)" "Bash(git diff --output=*)"
  "Bash(git diff *--no-index*)" "Bash(git diff */dev/null*)" "Bash(git diff *--output*)"
  "Bash(git diff /*)" "Bash(git diff * /*)" "Bash(git diff *../*)" "Bash(git diff ~*)" "Bash(git diff * ~*)" "Bash(git diff *\$*)"
  "Bash(git grep -O:*)" "Bash(git grep -O*)" "Bash(git grep --open-files-in-pager:*)" "Bash(git grep --open-files-in-pager=*)"
  "Bash(git grep *-O*)" "Bash(git grep *--open-files-in-pager*)"
  "Bash(git blame --contents:*)" "Bash(git blame --contents=*)"
  "Bash(git blame *--contents*)"
  "Bash(python -c:*)" "Bash(python:*)" "Bash(python3 -:*)" "Bash(python3.*)"
  "Bash(/usr/bin/python3:*)" "Bash(/opt/homebrew/bin/python3:*)" "Bash(/usr/local/bin/python3:*)"
  # ARBITRARY-CODE PYTHON IS DENIED BY SHAPE, NOT BY SPELLING. The four rules above are
  # the BARE dialect only -- `Bash(python3 -c:*)` is the prefix `python3 -c` plus a SPACE
  # and `Bash(python3 -:*)` is `python3 -` plus a space -- so the day `python3 -I` became
  # the house form in all six briefs, `python3 -I -c`, `python3 -Ic`, `python3 -I -` and
  # `python3 -I -m http.server` matched NO rule at all, neither deny nor allow, and fell
  # through to the auto-mode classifier: exactly the wave-through this list exists to stop
  # (ISSUE(security-audit-2026-09-18-daily-2026-09-18-16)). The shape is what matters: any
  # `-c`, any `-m`, any bare `-` argument, whatever flags stand between. `-c` and `-m`
  # consume the rest of a cluster, so a cluster carrying one ENDS in `c` or `m` (`-Ic`,
  # `-IBm`) -- that is what the `-*c` / `-*m` rules read. `python3 -I <path>`, the form the
  # briefs instruct, carries no `c `/`m ` and none of these touch it (pinned both ways by
  # test_herd_spawn.test_deny_by_shape). `Bash(python:*)` already covers every `python `.
  "Bash(python3 -m:*)"
  "Bash(python3 * -c)" "Bash(python3 * -c *)"
  "Bash(python3 * -m)" "Bash(python3 * -m *)"
  "Bash(python3 * -)" "Bash(python3 * - *)"
  "Bash(python3 -*c)" "Bash(python3 -*c *)"
  "Bash(python3 -*m)" "Bash(python3 -*m *)"
  "Bash(perl:*)" "Bash(ruby:*)" "Bash(node:*)" "Bash(php:*)"
  "Bash(bash -*)" "Bash(sh -*)" "Bash(zsh -*)"
  "Bash(cat:*)" "Bash(head:*)" "Bash(tail:*)" "Bash(grep:*)" "Bash(wc:*)"
  "Bash(sed:*)" "Bash(awk:*)" "Bash(od:*)" "Bash(xxd:*)" "Bash(strings:*)" "Bash(dd:*)"
  "Bash(tr:*)" "Bash(nl:*)" "Bash(rev:*)" "Bash(cut:*)" "Bash(fold:*)" "Bash(tee:*)"
  "Bash(less:*)" "Bash(more:*)"
  "Bash(curl:*)" "Bash(wget:*)" "Bash(ssh:*)" "Bash(scp:*)"
)
# The coordinator starts panes only through this script (which writes their rules), so
# the raw verb that would start an agent with any flags it likes is denied to it.
if [[ "$profile" == "coordinator" ]]; then
  deny+=("Bash(herdr agent start:*)")
fi

# --- --allow: judged before herdr is asked anything -------------------------------------
# A rule is refused when allowing it would not stop the stall or would open a door:
#   * it is not `Bash(<body>)` (the one form the brief's author may add);
#   * a deny entry overlaps it -- the literal head of one (the text before its first `*`,
#     `x:*` read as `x *`) is a prefix of the other's, in either direction: a deny that
#     covers it would still stop the worker, and a rule wider than a deny (`git:*` over
#     `git push:*`, `python3:*` over `python3 -c:*`, `*`) allows the rest of that family;
#   * a word of it names a reader, a network command or an interpreter (`env cat:*`
#     runs `cat` wherever the word stands, so every word is checked, whole words only:
#     `make concat` is not `cat`); python3 and the shells count as interpreters when
#     they stand alone or take a dash option, not when they run a named script.
# One line on stderr, exit 2, nothing started or written.
if [[ ${#extra_allow[@]} -gt 0 ]]; then
  python3 -I - "$name" "${#deny[@]}" "${deny[@]}" "${extra_allow[@]}" <<'PY' || exit 2
import re, sys
name, n = sys.argv[1], int(sys.argv[2])
deny, rules = sys.argv[3:3 + n], sys.argv[3 + n:]
NAMED = {
    # readers
    "cat", "head", "tail", "grep", "egrep", "fgrep", "rg", "wc", "sed", "awk", "gawk", "od",
    "xxd", "hexdump", "strings", "dd", "tr", "nl", "rev", "cut", "fold", "tee", "less",
    "more", "base64", "openssl", "sqlite3",
    # interpreters that run code whatever follows
    "perl", "ruby", "node", "php", "python", "python2", "lua", "osascript", "eval", "exec",
    "xargs",
    # network
    "curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ssh", "scp", "sftp", "ftp",
    "rsync",
}
SHELLS = {"python3", "bash", "sh", "zsh", "dash", "ksh"}


def head(body):
    if body.endswith(":*"):
        body = body[:-2] + " *"
    return body.split("*", 1)[0]


def why(rule):
    m = re.fullmatch(r"Bash\(([^()\x00-\x1f\x7f]*)\)", rule)
    if not m or not m.group(1).strip():
        return "only a Bash(<command>) rule may be added"
    body = m.group(1)
    h = head(body)
    for d in deny:
        dm = re.fullmatch(r"Bash\((.*)\)", d)
        if not dm:
            continue
        dh = head(dm.group(1))
        if h.startswith(dh) or dh.startswith(h):
            return "the deny rule " + d + " overlaps it, so the session would still stop"
    words = [w.strip("*'\"") for w in re.split(r"\s+", body[:-2] if body.endswith(":*") else body)]
    words = [w.rsplit("/", 1)[-1] for w in words if w]
    for i, w in enumerate(words):
        if w in NAMED:
            return "it names `" + w + "`, a reader, interpreter or network command"
        if w in SHELLS and (i + 1 == len(words) or words[i + 1].startswith("-")):
            return "it names `" + w + "` bare or with a dash option, an interpreter"
    return ""


for rule in rules:
    reason = why(rule)
    if reason:
        shown = rule if rule.isprintable() else ascii(rule)
        print("herd-spawn: --allow %s is refused: %s; the worker %s was not started"
              % (shown or "''", reason, name), file=sys.stderr)
        sys.exit(2)
PY
fi

# --- where the tab opens ---------------------------------------------------------------
# Resolved BEFORE herdr is asked anything, because for codex the answer is itself a
# refusal (below) and a refused spawn must leave nothing anywhere -- not a tab, not a
# recorded call, not a directory.
if [[ -z "$cwd" ]]; then
  cwd="$(iso_primary_of "$here")" || {
    echo "herd-spawn: this script is not inside a git checkout; pass --cwd DIR" >&2
    exit 2
  }
fi
if [[ ! -d "$cwd" ]]; then
  echo "herd-spawn: cwd not found: ${cwd}" >&2
  exit 2
fi
cwd="$(cd "$cwd" && pwd)"
# A codex session requires a linked worktree: a .git file and a resolving Git common
# directory. `-C "$cwd" -s workspace-write` makes cwd the writable sandbox root,
# and `-a on-request` escalates only for writes OUTSIDE
# it, so every write inside runs with no approval at all -- and no session guard runs on this
# harness to refuse the primary, another live session's worktree or `keys/`: the hook is
# registered in `.claude/settings.json` and `.cursor/hooks.json`, `session-guard.sh`
# dispatches claude, cursor and grok only, codex-cli reads neither, and the `config.toml`
# this spawn writes registers none. A prompt-injected worker would be one write away from
# `<primary>/.claude/settings.json`, whose `hooks` entries are shell command lines, and none
# of it would appear in a diff. The cursor branch refuses the primary for a narrower reason
# (its rules file is shared by every Cursor session there); this one is the wall itself, so
# it is checked here rather than beside its harness block.
if [[ "$harness" == "codex" ]] && { [[ ! -f "$cwd/.git" ]] || ! iso_primary_of "$cwd" >/dev/null 2>&1; }; then
  echo "herd-spawn: a codex session requires a linked worktree, not a primary checkout or plain directory (${cwd}): its writable sandbox root IS the directory it opens in (-s workspace-write; -a on-request stops only for writes outside that root), and no session guard runs on this harness; pass --cwd <worktree>; the worker ${name} was not started" >&2
  exit 2
fi
# The repository the worker's report will be judged in: the spawn's own answer, recorded
# below as $HERD_DIR/.repos/<name> and passed by the hook as `appl-verify.sh --repo`, so
# the report is never asked where it landed. A cwd in no repository means a worker that
# could never be verified, so it is not started -- before herdr is asked anything
# (coordinator ruling 2026-09-24). After the codex rule, whose refusal is the sharper one.
spawn_repo="$(iso_primary_of "$cwd" 2>/dev/null)" && [[ "$spawn_repo" == /* ]] || {
  echo "herd-spawn: ${cwd} is not inside a git repository, so there is no repository to verify the worker's report in; the worker ${name} was not started" >&2
  exit 2
}

# --- herdr: on PATH (or HERD_SPAWN_BIN) and its server up, else exit 3 ---------------
herdr="${HERD_SPAWN_BIN:-}"
if [[ -n "$herdr" ]]; then
  if [[ ! -x "$herdr" ]]; then
    echo "herd-spawn: no herdr binary at HERD_SPAWN_BIN=${herdr}; the worker ${name} was not started" >&2
    exit 3
  fi
else
  herdr="$(command -v herdr 2>/dev/null || true)"
  if [[ -z "$herdr" ]]; then
    echo "herd-spawn: herdr is not on PATH (https://herdr.dev); the worker ${name} was not started" >&2
    exit 3
  fi
fi
if ! "$herdr" status >/dev/null 2>&1; then
  echo "herd-spawn: 'herdr status' failed -- the herdr server is not running; the worker ${name} was not started" >&2
  exit 3
fi

# --- HERD_DIR: ours, or nothing is written there ----------------------------------------
# Created mode 700 when absent. An existing directory someone else owns (a shared host's
# /tmp, a directory planted before us) is refused: whoever owns it could swap a brief
# or rewrite a report.
herd_dir="$(iso_herd_dir)" || {
  echo "herd-spawn: neither HERD_DIR nor HOME is set, so there is no herd directory; the worker ${name} was not started" >&2
  exit 2
}
# absolute, so the Edit rules and the excludes below name real paths
[[ "$herd_dir" == /* ]] || herd_dir="$(pwd)/${herd_dir}"
if [[ ! -d "$herd_dir" ]]; then
  mkdir -p "$herd_dir"
  chmod 700 "$herd_dir" 2>/dev/null || true
fi
if [[ ! -O "$herd_dir" ]]; then
  echo "herd-spawn: ${herd_dir} is not owned by $(id -un) (HERD_DIR); refusing to write a brief or a report there; the worker ${name} was not started" >&2
  exit 2
fi
# ... and nothing above it, or above the worker's cwd, is writable by others: Claude
# Code reads CLAUDE.md from the cwd and every directory above it, so a
# /private/tmp/CLAUDE.md planted by any local uid would reach a worker started there
# (ISSUE(security-audit-2026-09-12-the-review-checkout-lives-4))
if ! open_dir="$(iso_private_path "$herd_dir")"; then
  echo "herd-spawn: ${open_dir}, at or above ${herd_dir}, is writable by others; a CLAUDE.md there would reach the worker; set HERD_DIR under your home; the worker ${name} was not started" >&2
  exit 2
fi
if ! open_dir="$(iso_private_path "$cwd")"; then
  echo "herd-spawn: ${open_dir}, at or above the cwd ${cwd}, is writable by others; a CLAUDE.md there would reach the worker; the worker ${name} was not started" >&2
  exit 2
fi
# A directory under it is ours or nothing is written into it: a real directory (a
# symlink planted at $HERD_DIR/<name> by an earlier, prompt-injected session would carry
# the next reviewer's rules file wherever it points), created mode 700 when absent and
# owned by the caller when present. -L before -d: -d follows a symlink to a directory.
own_dir() {
  if [[ -L "$1" ]]; then
    echo "herd-spawn: $1 is a symlink, not a directory; refusing to write there; the worker ${name} was not started" >&2
    exit 2
  fi
  if [[ ! -d "$1" ]]; then
    mkdir -m 700 "$1" 2>/dev/null || {
      echo "herd-spawn: cannot create $1 (something else is in the way); the worker ${name} was not started" >&2
      exit 2
    }
  elif [[ ! -O "$1" ]]; then
    echo "herd-spawn: $1 is not owned by $(id -un); refusing to write there; the worker ${name} was not started" >&2
    exit 2
  fi
}
own_dir "$herd_dir/briefs"
own_dir "$herd_dir/.roles"
own_dir "$herd_dir/.repos"
own_dir "$herd_dir/${name}"
role_marker="$herd_dir/${name}/role"
role_record="$herd_dir/.roles/${name}"
repo_record="$herd_dir/.repos/${name}"
report="$herd_dir/${name}/report.md"
rendered="$herd_dir/briefs/${name}.md"
perms="$herd_dir/${name}/permissions.json"
bfile="$herd_dir/${name}/brief.md"
# Something at brief.md that is NOT a regular file -- a symlink (dangling or not; -L
# first, since -e and -f follow one) or a directory -- is a refusal, judged before the
# brief is even rendered, so nothing under HERD_DIR changes: it is never followed,
# replaced or prompted. A REGULAR brief.md (a previous spawn of this name, or a plant) is
# rewritten by the render below. (The render re-checks, for one that appears in between.)
if [[ -L "$bfile" ]] || { [[ -e "$bfile" ]] && [[ ! -f "$bfile" ]]; }; then
  echo "herd-spawn: ${bfile} is a symlink or not a regular file; brief.md is never written through or over one -- remove it if the name is yours to re-spawn; the worker ${name} was not started" >&2
  exit 2
fi
brief_abs="$(cd "$(dirname "$brief")" && pwd)/$(basename "$brief")"

# --- the command herdr will type, bounded -----------------------------------------------
# herdr TYPES the command into the pane, and a pty takes about 1 KB of typed input
# before it drops the rest: the argv form of the rules was cut off at
# `--disallowedTools ... 'Bash(tail:*` once the deny list existed (2026-09-12), and
# claude never started. The rules travel as a settings file to keep the line short, and
# HERD_DIR -- inherited from the environment, on the line twice -- could push it back
# over the limit: a line truncated at the `--settings` token would still be a valid
# `claude --add-dir <dir>`, with no rules at all. So the line is measured here and a long
# one is a refusal before herdr is asked anything, never a session with fewer rules.
#
# --setting-sources project: the owner's user-global settings are not loaded, so a
# worker never inherits an allow rule from ~/.claude/settings.json, and neither is the
# machine-local .claude/settings.local.json, where interactive "don't ask again" grants
# accumulate (ISSUE(security-audit-2026-09-12-the-reviewer-sandbox-an-e-3)); the project's
# own settings (the session-guard hook) and the --settings file (this spawn's rules) are.
# A claude too old for the flag refuses to start ("unknown option"), which the retry
# loop reports as exit 1: closed, not open.
# --strict-mcp-config: no MCP server from ~/.claude.json or a project file reaches a
# herd session (none is passed, so none is loaded)
if [[ "$harness" == "cursor" ]]; then
  # --trust: no workspace prompt in a pane nobody answers; --workspace pins the checkout
  # the tab opened in. NOT --auto-review: under the classifier mode Cursor's CLI ran
  # `git push`, `cat` and `curl` past their deny rules (measured 2026-09-12); in the
  # account's allowlist mode a denied command is "blocked by permissions
  # configuration", an allowed one runs, and an unlisted one waits for a person -- the
  # session shows as `blocked` in herdr, which is the safe failure.
  # The user's own config is unioned into every Cursor session (the CLI has no
  # project-only setting source), so it must be allowlist mode AND carry no allow of its
  # own -- an "always allow" click persists there and would arm every later herd session
  # (ISSUE(security-audit-2026-09-12-cursor-s-project-rul-e6f4-3)). The agent resolves
  # its config dir as CURSOR_CONFIG_DIR, else XDG_CONFIG_HOME/cursor, else ~/.cursor; the
  # tab is handed CURSOR_CONFIG_DIR explicitly so the file checked is the file obeyed (-4).
  cursor_home="${HOME:-}/.cursor"
  cursor_cfg="${cursor_home}/cli-config.json"
  if ! why="$(python3 -I - "$cursor_cfg" <<'PY'
import json, sys
try:
    cfg = json.load(open(sys.argv[1]))
except Exception as e:                                 # noqa: BLE001
    print("unreadable: " + type(e).__name__); sys.exit(1)
if cfg.get("approvalMode") != "allowlist":
    print("approvalMode is %r, not allowlist" % cfg.get("approvalMode")); sys.exit(1)
allowed = (cfg.get("permissions") or {}).get("allow") or []
if allowed:
    print("permissions.allow is not empty (%s): it would be unioned into the session" % ", ".join(allowed[:5])); sys.exit(1)
sys.exit(0)
PY
)"; then
    echo "herd-spawn: ${cursor_cfg}: ${why}; the worker ${name} was not started" >&2
    exit 2
  fi
  if [[ "$(iso_primary_of "$cwd" 2>/dev/null || true)" == "$cwd" ]]; then
    echo "herd-spawn: a cursor session does not start in the primary checkout: its rules file (<cwd>/.cursor/cli.json) is shared by every Cursor session there; pass --cwd <worktree>; the worker ${name} was not started" >&2
    exit 2
  fi
  agent_args=(--trust --workspace "$cwd" --add-dir "$herd_dir/${name}")
  [[ -z "$model" ]] || agent_args+=(--model "$model")
  typed="cursor-agent ${agent_args[*]}"
elif [[ "$harness" == "codex" ]]; then
  # The config home is the SPAWN's. Codex resolves CODEX_HOME (default ~/.codex) and loads
  # AGENTS.md and config.toml from it; the user's copies there are writable by any session
  # of this user, so a worker that read them could be told to ignore its brief by something
  # that appears in no diff. The tab is handed a home under the worker's own directory
  # instead, made the way that directory is (mode 700; a symlink or another uid's is exit 2
  # BEFORE a tab exists, so nothing is ever written through a plant).
  #
  # The login stays the user's, as a SYMLINK: we handle the PATH and never the content --
  # auth.json is not read, printed or copied anywhere. A user who has not logged in is told
  # to, here, rather than getting a pane whose agent cannot talk.
  #
  # CODEX_HOME is read ONCE, here, and then dropped from this process the way
  # HERD_SPAWN_PERMISSION_MODE, HERD_SPAWN_HARNESS and HERD_SPAWN_MODEL are: it was the one
  # knob that survived into a spawn a worker started, and the tab is handed the SPAWN's home
  # below, never this one. The other end of the same door -- a caller `--env CODEX_HOME=`,
  # which herdr's dedup order would have decided -- is refused where --env is parsed.
  user_codex_home="${CODEX_HOME:-${HOME:-}/.codex}"
  unset CODEX_HOME
  user_auth="${user_codex_home}/auth.json"
  # Nothing at or above that home may be writable by others: whoever can write there swaps
  # the login this spawn is about to link in, and the session is then billed to, and visible
  # in, an account that is not the owner's.
  if ! open_dir="$(iso_private_path "$user_codex_home")"; then
    echo "herd-spawn: ${open_dir}, at or above the codex home ${user_codex_home}, is writable by others; whoever can write there can swap the login the worker is handed; the worker ${name} was not started" >&2
    exit 2
  fi
  # ... and the login is a REGULAR file of the caller's, or it is not a login. `-e` was not
  # enough on its own: it FOLLOWS a symlink and it accepts a directory and a fifo, so a
  # CODEX_HOME holding a link to somebody else's auth.json was linked in as the worker's,
  # and a fifo there hangs the pane. -L first, the way own_dir tests -L before -d, so the
  # path is judged and never followed.
  if [[ -L "$user_auth" ]]; then
    echo "herd-spawn: the codex login ${user_auth} is a symlink, not a regular file; this path is linked into the worker's config home as its login, so it is judged and never followed; the worker ${name} was not started" >&2
    exit 2
  fi
  if [[ ! -e "$user_auth" ]]; then
    echo "herd-spawn: no codex login at ${user_auth} -- run 'codex login' first; the worker ${name} was not started" >&2
    exit 2
  fi
  if [[ ! -f "$user_auth" || ! -O "$user_auth" ]]; then
    echo "herd-spawn: the codex login ${user_auth} is not a regular file owned by $(id -un) -- a directory, a fifo or another user's file is refused, since it is what the worker is handed to talk with; the worker ${name} was not started" >&2
    exit 2
  fi
  codex_home="$herd_dir/${name}/codex-home"
  own_dir "$codex_home"
  # own_dir answers -L, -d and -O and no more, and codex loads `AGENTS.md` and `config.toml`
  # from this directory: a file planted here under a predictable worker name -- with no
  # brief.md, so the re-spawn refusal never fires -- would BE the worker's instructions,
  # living in no checkout and in no diff, which `tools/sec_lint.py` never scans and no
  # reviewer opens. So the home must hold NOTHING this spawn just wrote. It is REFUSED and
  # never emptied, the way brief.md is: what is in the way is listed and left where it is,
  # a symlink among it neither followed nor unlinked. The same refusal covers a leftover
  # from a spawn of this name that failed, which is the same state reached with no
  # foresight at all -- and drop_brief below removes what THIS spawn wrote, so a failed
  # spawn never refuses its own retry.
  #
  # The names go through iso_safe_text: the sentence an operator reads immediately before
  # deleting something by hand may not be repainted by the thing it names.
  shopt -s nullglob dotglob
  codex_entries=("$codex_home"/*)
  shopt -u nullglob dotglob
  if [[ ${#codex_entries[@]} -gt 0 ]]; then
    in_the_way=""
    for entry in "${codex_entries[@]}"; do
      in_the_way="${in_the_way}${in_the_way:+, }${entry##*/}"
    done
    in_the_way="$(iso_safe_text "$in_the_way")" ||
      in_the_way="(names withheld: this machine has a python3 that cannot run, so they cannot be spelled safely)"
    echo "herd-spawn: ${codex_home} is not empty -- it holds ${in_the_way}; a codex worker reads its instructions and its config from that directory, so it is refused rather than emptied: remove what is in the way if it is yours to re-spawn; the worker ${name} was not started" >&2
    exit 2
  fi
  # The wall, and the whole of it: the sandbox plus the approval policy. No
  # danger-full-access, no --dangerously-bypass-approvals-and-sandbox, ever.
  agent_args=(-C "$cwd" --add-dir "$herd_dir/${name}")
  [[ -z "$model" ]] || agent_args+=(-m "$model")
  agent_args+=(-s workspace-write -a on-request)
  typed="codex ${agent_args[*]}"
else
  agent_args=(--permission-mode "$permission_mode" --model "$model" --add-dir "$herd_dir/${name}"
              --settings "$perms" --setting-sources project --strict-mcp-config)
  typed="claude ${agent_args[*]}"
fi
if [[ ${#typed} -gt 900 ]]; then
  echo "herd-spawn: the command herdr would type is ${#typed} characters (bound 900; a pty drops typed input past about 1 KB) -- shorten HERD_DIR (${herd_dir}); the worker ${name} was not started" >&2
  exit 2
fi
# ... and the one line the worker is told, under the same bound for the same reason (with
# the default HERD_DIR and a 32-character name it is under 200 characters)
prompt_line="Read ${bfile} and follow it. Your report goes to ${report}."
if [[ ${#prompt_line} -gt 900 ]]; then
  echo "herd-spawn: the prompt herdr would type is ${#prompt_line} characters (bound 900) -- shorten HERD_DIR (${herd_dir}); the worker ${name} was not started" >&2
  exit 2
fi

# --- the wall and the bounds ------------------------------------------------------------
# P1 ISSUE(workers-have-no-resource-limit-and-no-egress-control). Until this block, every
# timeout here bounded the spawn HANDSHAKE and nothing bounded a worker once it ran, and
# the only thing between a worker and `keys/` was a deny list, which is not containment.
# The publisher, one directory away, already scans under sandbox-exec and PROBES that its
# wall stands before it trusts it; this is that, ported, and the probe is the half that
# matters.
#
# THE WALL (claude `worker` and `reviewer` sessions). A plug per platform,
# scripts/walls/<uname -s, lowercased>.sh, answers `available` and
# `exec <profile> -- <cmd...>` (walls/darwin.sh: Seatbelt). This script owns the rest: the
# mode, the profile, the probe, the bounds and the record. The profile is NEUTRAL (one verb
# and one path per line) and is written to $HERD_DIR/walls/<name>/profile; wall v1 denies
# READS of the primary checkout's keys/ and of ~/.muretai/bindings, and WRITES anywhere but
# the worker's own places -- its cwd, its $HERD_DIR/<name>/ (never its brief.md or its
# permissions.json), git's common directory (never its hooks/ or config), the temporary
# directories, and ~/.claude -- and the two places its JOB writes: ~/.cache/muretai-tests
# (the fixture root the test files hard-code) and $HERD_DIR/coordinator/intake (where
# tools/appl-add.sh files an intake). Those two exactly, never HERD_DIR or ~/.cache whole;
# the spawn creates them mode 700 before rendering, since the worker cannot. ~/.muretai
# stays readable and unwritable. The network stays OPEN in v1 (`egress=open` on the success
# line and in wall.log, so nobody reads "walled" as "offline"); HERD_WALL_EGRESS=deny is
# refused above until the v2 proxy exists.
#   Deliberate holes, for v2 to revisit: the walled agent may write ~/.claude (the harness
#   keeps its session state there and does not start without it -- and a write there can
#   plant instructions for a LATER session), and the `coordinator` profile is never walled
#   (its whole job is dms and inbox reads through the node: the network and the bindings).
#   The cursor and codex harnesses are not walled in v1 either (codex brings a sandbox of
#   its own, and sandbox-exec does not nest under one); wall.log says why, per spawn.
# THE PROBE runs before herdr is asked for a tab, through the SAME plug with the SAME
# profile the agent later gets, from a scratch directory inside HERD_DIR that is removed
# afterwards. It tries to list the two directories; either one it can see into is a leak.
# It also trials a write into each of the job's two places; one it cannot write means the
# wall stands but the worker could not do its job.
# HERD_WALL=require (the default, including where there is no plug): a leak, a plug that
# cannot build the wall, a probe that did not finish, or a job the wall denies is exit 2
# on one line naming what leaked or what the worker could not do,
# with no tab, no agent and no brief. prefer, only when set explicitly: the same
# findings are ONE warning line and the worker runs unwalled, recorded. off: unwalled,
# recorded. No variable skips the probe.
# INHERITED: a spawn that itself runs behind a wall (a walled worker's test that spawns)
# cannot build another -- sandbox-exec does not nest. When the plug says so, the plug's
# `exec` marker HERD_WALL_INSIDE is set, AND the plug's `inside` verb confirms a wall
# around this process, the worker starts `wall=inherited why=inside:<name>`, with the
# bounds and no new profile; run.py asks `inside` again before it starts the agent. A
# missing plug is still a refusal, marker or not, and so is a marker `inside` denies.
# THE BOUNDS hold in every mode, for every profile but the coordinator (which lives for
# days): cpu seconds per process, memory of the worker's tree, processes in the worker's
# tree (above). A launcher enforces them from OUTSIDE the wall: the tab's PATH starts with
# $HERD_DIR/walls/<name>/bin, whose one file is named for the harness binary and execs
# run.py; run.py sets RLIMIT_CPU on its child, starts the agent through the plug (or
# directly, unwalled), watches the tree -- kqueue fork events and libproc on macOS, /proc
# elsewhere -- and on a breach stops and kills the whole tree and appends a `killed` line
# naming the bound to wall.log. Measured on macOS 26: RLIMIT_AS/DATA/RSS are refused and
# RLIMIT_NPROC counts every process of the uid, so memory and the process cap cannot be
# rlimits there; only the CPU bound is.
# THE GATE. A walled worker cannot run the landing's gate (a suite that builds a wall,
# walks the process tree or writes beside its HERD_DIR entry dies of the wall, and the
# fast-forward writes the primary), so the same launcher serves the worker's LANDING from
# outside the wall: finish-worktree.sh, walled, writes a request into $HERD_DIR/<name>/, and
# run.py runs the PRIMARY's finish-worktree.sh unwalled on the branch and worktree recorded
# here at spawn (run.json `gate`), then hands the receipt back with a GATE= line saying so.
# The request is judged, never obeyed; see run.py's Gate. The worker stays walled.
# Everything the launcher runs is COPIED into $HERD_DIR/walls/<name>/ at spawn -- the
# plug, its templates and run.py -- where the walled worker cannot write (walls/ is on no
# allow-write line). The script this block lives in may run from a worktree the worker can
# edit, or from the landing's temporary copy that is deleted after the spawn.
#
# THE OWNER KEY (ISSUE(walled-worker-cannot-claim-a-worktree)). Behind wall v1 `ps` cannot
# run (/bin/ps is setuid, and a Seatbelt-walled process cannot exec it), so the process walk
# that names a keyless session's owner has no answer there, and iso_owner_pid refuses. A
# walled (or inherited-wall) worker is therefore ALWAYS given a stable key on its tab:
# the caller's `--env ISOLATED_SESSION_OWNER=<k>` when there is one -- and then that entry
# alone, never a second beside it, which would leave the value to herdr's dedup order --
# else the worker's own name. Every lock of the repository that key already owns is handed
# over below, exactly as the pair hand-over does. And the probe proves the claim works:
# behind the same wall, before any tab exists, claim-worktree.sh and assert-head.sh run
# under that key against a THROWAWAY repository in the worker's own directory (removed
# afterwards); a wall under which they fail is a finding like a leak.
owner_key=""
owner_key_from_caller=no
for kv in ${envs[@]+"${envs[@]}"}; do
  if [[ "${kv%%=*}" == "ISOLATED_SESSION_OWNER" ]]; then
    owner_key="${kv#*=}"
    owner_key_from_caller=yes
  fi
done
[[ "$owner_key_from_caller" == "yes" ]] || owner_key="$name"
wall_scope=walled
bounded=yes
if [[ "$profile" == "coordinator" ]]; then
  wall_scope=coordinator
  bounded=no
elif [[ "$harness" != "claude" ]]; then
  wall_scope="harness-${harness}"
fi
case "$harness" in
  cursor) agent_cmd="cursor-agent" ;;
  *) agent_cmd="$harness" ;;
esac
wall_os="$(uname -s | tr '[:upper:]' '[:lower:]')"
walls_dir="$herd_dir/walls"
wall_dir="$walls_dir/${name}"
own_dir "$walls_dir"
own_dir "$wall_dir"
own_dir "$wall_dir/bin"
wall_py="$(command -v python3 2>/dev/null || true)"
wall_primary="$(iso_primary_of "$cwd" 2>/dev/null || true)"
[[ -n "$wall_primary" ]] || wall_primary="$cwd"
wall_common="$(cd "$cwd" && git rev-parse --path-format=absolute --git-common-dir 2>/dev/null || true)"
# run.py: the launcher (`run`) and the probe (`probe`), one stdlib file. It is here rather
# than beside this script because the landing runs this script from a temporary copy of
# herd-spawn.sh and lib.sh alone.
IFS= read -r -d '' wall_run_src <<'PY' || true
"""run.py -- written by herd-spawn.sh into $HERD_DIR/walls/<name>/. Two modes:

  run.py probe <word> <dir> [<word> <dir> ...]
      Run BEHIND the wall, before the worker exists. Prints each <word> whose <dir> it
      could see into (a leak), then `done`. A directory that is not there has nothing to
      leak; one it cannot stat or list is held. A <word> spelled `write:<job>` is the other
      half, the worker's JOB: it makes a directory in <dir>, writes a file there, reads it
      back and removes both; any step that fails prints `cannot-<job>`.
  run.py run <run.json> -- <agent args...>
      The launcher the tab's PATH finds first. Starts the harness binary (the next one on
      PATH after its own directory) through the plug, or directly when the spawn ran
      unwalled; puts RLIMIT_CPU on it; watches its process tree from OUTSIDE the wall; on a
      breach of the memory bound or the process cap stops and kills the whole tree, and
      writes `killed` and the bound to wall.log. A child that dies of SIGXCPU is the cpu
      bound, recorded the same way.
      A WALLED run also serves the worker's landing from outside the wall -- see Gate.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import json
import os
import resource
import select
import signal
import stat
import subprocess
import sys
import threading
import time

LOG = ""


def log(line: str) -> None:
    try:
        fd = os.open(LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(fd, (time.strftime("%Y-%m-%dT%H:%M:%S%z") + " " + line + "\n").encode())
        finally:
            os.close(fd)
    except OSError:
        pass


def probe(args: list) -> int:
    for word, path in zip(args[0::2], args[1::2]):
        if word.startswith("write:"):
            d = os.path.join(path, ".herd-wall-probe-%d" % os.getpid())
            try:
                os.mkdir(d, 0o700)
                p = os.path.join(d, "probe")
                fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                try:
                    os.write(fd, b"x")
                finally:
                    os.close(fd)
                with open(p, "rb") as f:
                    if f.read() != b"x":
                        raise OSError("read back")
                os.unlink(p)
                os.rmdir(d)
            except OSError:
                print("cannot-" + word[len("write:"):])
            continue
        try:
            st = os.stat(path)
        except OSError:
            continue                      # absent: nothing to leak; EPERM/EACCES: held
        try:
            if stat.S_ISDIR(st.st_mode):
                os.listdir(path)
            else:
                with open(path, "rb") as f:
                    f.read(1)
        except OSError:
            continue
        print(word)
    print("done")
    return 0


class RUsage(ctypes.Structure):
    _fields_ = [("uuid", ctypes.c_uint8 * 16)] + [(n, ctypes.c_uint64) for n in (
        "user_time", "system_time", "pkg_idle_wkups", "interrupt_wkups", "pageins",
        "wired_size", "resident_size", "phys_footprint", "proc_start_abstime", "proc_exit_abstime")]


class Table:
    """The worker's process tree and its memory: libproc on macOS, /proc on Linux, ps
    anywhere else."""

    def __init__(self) -> None:
        self.lib = None
        if sys.platform == "darwin":
            try:
                self.lib = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib")
                self.lib.proc_listpids.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int]
                self.lib.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
            except (OSError, AttributeError):
                self.lib = None
        self.proc = os.path.isdir("/proc/self/task")
        self.buf = (ctypes.c_int * 8192)()

    def _listpids(self, kind: int, arg: int) -> list:
        n = self.lib.proc_listpids(kind, arg, self.buf, ctypes.sizeof(self.buf))
        return [self.buf[i] for i in range(max(n, 0) // 4) if self.buf[i] > 0]

    def _ppid_map(self) -> dict:
        out = {}
        if self.proc:
            for d in os.listdir("/proc"):
                if d.isdigit():
                    try:
                        with open("/proc/%s/stat" % d) as f:
                            out[int(d)] = int(f.read().rsplit(")", 1)[1].split()[1])
                    except (OSError, ValueError, IndexError):
                        pass
            return out
        r = subprocess.run(["ps", "-A", "-o", "pid=", "-o", "ppid="], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                out[int(parts[0])] = int(parts[1])
        return out

    def tree(self, root: int) -> set:
        seen, todo = set(), [root]
        kids = None
        if self.lib is None:
            ppids = self._ppid_map()
            kids = {}
            for p, pp in ppids.items():
                kids.setdefault(pp, []).append(p)
        while todo:
            p = todo.pop()
            if p in seen:
                continue
            seen.add(p)
            todo.extend(self._listpids(6, p) if self.lib is not None else kids.get(p, []))  # 6: PROC_PPID_ONLY
        # a process group we lead (a pane's job) also holds what was orphaned out of the tree
        if self.lib is not None and os.getpgrp() == os.getpid():
            seen.update(self._listpids(2, os.getpid()))                                    # 2: PROC_PGRP_ONLY
        seen.discard(os.getpid())
        return seen

    def footprint(self, pids: set) -> int:
        total = 0
        for p in pids:
            if self.lib is not None:
                ru = RUsage()
                if self.lib.proc_pid_rusage(p, 0, ctypes.byref(ru)) == 0:           # 0: RUSAGE_INFO_V0
                    total += ru.phys_footprint
            elif self.proc:
                try:
                    with open("/proc/%d/statm" % p) as f:
                        total += int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
                except (OSError, ValueError, IndexError):
                    pass
            else:
                r = subprocess.run(["ps", "-o", "rss=", "-p", str(p)], capture_output=True, text=True)
                if r.stdout.strip().isdigit():
                    total += int(r.stdout.strip()) * 1024
        return total


def stop_and_kill(table: Table, root: int, also: set) -> None:
    """SIGSTOP first, the whole tree, until no new member appears -- a stopped parent
    cannot fork and its children stay its children, so the tree is still there to read --
    then SIGKILL every member."""
    seen = set()
    for _ in range(64):
        cur = table.tree(root) | {p for p in also if p != os.getpid()}
        new = cur - seen
        if not new:
            break
        for p in new:
            try:
                os.kill(p, signal.SIGSTOP)
            except OSError:
                pass
        seen |= new
    for p in seen:
        try:
            os.kill(p, signal.SIGKILL)
        except OSError:
            pass


NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
FINISH_REL = os.path.join(".cursor", "skills", "isolated-session", "scripts", "finish-worktree.sh")


class Gate:
    """The landing a walled worker ASKS for, run from OUTSIDE its wall (coordinator
    rulings, 2026-09-24).

    Why: the landing's gate is not the worker's work. Behind the wall a suite that builds a
    wall, walks the process tree or writes beside the worker's HERD_DIR entry dies of the
    wall, and the fast-forward writes the primary, which the wall denies -- so a worker
    that had finished its work was refused, and an operator landed it by hand. This does
    what that operator did, and nothing else.

    The worker may ASK; it may not say WHAT. Its finish-worktree.sh writes `gate.request`
    into the one place both sides reach, the worker's own $HERD_DIR/<name>/ (walls/<name>/
    is unwritable to it). The request is read once, removed, and JUDGED, never obeyed: it
    must name exactly the branch and worktree this launcher was started on (run.json,
    written at spawn where the worker cannot write), and what runs is decided here --
    `land.sh` from this walls/<name>/ directory, never a path the request names. land.sh
    reads the spawn record, runs the branch's tests in its own process -- a child of THIS
    launcher, outside every profile, as an operator's landing runs them -- and only then
    runs BASE's finish-worktree.sh out of the recorded base commit. (It used to run them
    back through the plug and the worker's profile, where a nested sandbox-exec is refused,
    so every suite that builds a wall was booked FAIL: ISSUE(launcher-landing-still-runs-
    inside-the-wall).) wall.log names the pid that ran the landing. A landing that fails
    asks this worker once to fix the branch; a person is named only after that attempt.
    The receipt comes back as `gate.result`, written through
    a directory descriptor, O_EXCL and O_NOFOLLOW, then renamed into place: a link the
    worker planted there is replaced, never followed. Its stdout ends with a GATE= line
    saying the gate ran outside the worker's wall -- the escalation is on the receipt.

    One landing at a time. The landing runs in a session of its own, so its tests are not
    the worker's tree and never count against the worker's bounds; the worker itself stays
    behind its wall the whole time."""

    REQUEST, RESULT = "gate.request", "gate.result"

    def __init__(self, gate: dict, shim_dir: str, worker: str, runjson: str) -> None:
        self.channel = gate["channel"]
        self.primary = gate["primary"]
        self.worktree = gate["worktree"]
        self.branch = gate["branch"]
        self.lander = gate.get("lander") if isinstance(gate.get("lander"), str) else ""
        self.runjson = runjson
        self.shim = os.path.realpath(shim_dir)
        self.worker = worker
        self.thread = None
        self.closed = False

    def env_for_agent(self) -> dict:
        return {"HERD_GATE_CHANNEL": self.channel, "HERD_GATE_BRANCH": self.branch,
                "HERD_GATE_WORKTREE": self.worktree}

    def _dirfd(self) -> int:
        return os.open(self.channel, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | NOFOLLOW)

    def _take(self):
        """The request's bytes, "" when it is not a small regular file, None when absent."""
        try:
            dfd = self._dirfd()
        except OSError:
            return None
        try:
            try:
                fd = os.open(self.REQUEST, os.O_RDONLY | os.O_NONBLOCK | NOFOLLOW, dir_fd=dfd)
            except OSError as e:
                if e.errno == errno.ENOENT:
                    return None
                data = ""                           # a link, or something we may not open
            else:
                try:
                    st = os.fstat(fd)
                    data = os.read(fd, 4097) if stat.S_ISREG(st.st_mode) else ""
                finally:
                    os.close(fd)
            try:
                os.unlink(self.REQUEST, dir_fd=dfd)
            except OSError:
                # a name we cannot remove would be answered on every tick: stop serving
                self.closed = True
                log("gate: closed: %s/%s could not be removed" % (self.channel, self.REQUEST))
            return data
        finally:
            os.close(dfd)

    def _judge(self, data) -> tuple:
        """("", script) to land, or (why, "") to refuse."""
        if not isinstance(data, bytes) or not data or len(data) > 4096:
            return "the request was not a small regular file", ""
        try:
            req = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return "the request was not JSON", ""
        if not isinstance(req, dict) or not isinstance(req.get("branch"), str) \
                or not isinstance(req.get("worktree"), str):
            return "the request named no branch and worktree", ""
        if req["branch"] != self.branch or os.path.realpath(req["worktree"]) != self.worktree:
            return ("this launcher lands only %s in %s, the branch and worktree its worker was "
                    "started on" % (self.branch, self.worktree)), ""
        script = self.lander
        try:
            ok = bool(script) and stat.S_ISREG(os.lstat(script).st_mode) and not os.path.islink(script)
        except OSError:
            ok = False
        if not ok:
            return "the spawn record has no land.sh", ""
        return "", script

    def _answer(self, rc: int, out: str, err: str) -> None:
        body = json.dumps({"rc": rc, "stdout": out, "stderr": err}).encode("utf-8")
        tmp = self.RESULT + ".tmp"
        try:
            dfd = self._dirfd()
        except OSError as e:
            log("gate: could not open %s to answer: %s" % (self.channel, type(e).__name__))
            return
        try:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except FileNotFoundError:
                pass
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600, dir_fd=dfd)
            try:
                os.write(fd, body)
            finally:
                os.close(fd)
            os.rename(tmp, self.RESULT, src_dir_fd=dfd, dst_dir_fd=dfd)
        except OSError as e:
            log("gate: could not write the receipt into %s: %s" % (self.channel, type(e).__name__))
        finally:
            os.close(dfd)

    def _repair(self, reason: str) -> None:
        if not self.lander or not self.runjson:
            return
        try:
            subprocess.run(["/bin/bash", self.lander, "--repair", self.runjson, reason],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            log("gate: the repair agent was not prompted")

    def _land(self, script: str) -> None:
        env = {k: v for k, v in os.environ.items() if not k.startswith("HERD_GATE_")}
        # never this worker's launcher again: a reviewer the landing spawns finds the real harness
        env["PATH"] = os.pathsep.join(d for d in env.get("PATH", "").split(os.pathsep)
                                      if d and os.path.realpath(d) != self.shim)
        log("gate: landing %s from the spawn record outside the wall" % self.branch)
        try:
            p = subprocess.Popen(["/bin/bash", script, self.runjson], cwd=self.primary, env=env,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, errors="replace", start_new_session=True)
            log("gate: the landing of %s runs as pid=%d, a child of the launcher pid=%d, not of the worker"
                % (self.branch, p.pid, os.getpid()))
            out, err = p.communicate()
            rc = p.returncode
        except OSError as e:
            rc, out, err = 126, "MERGED=no\n", "herd gate: could not start the landing: %s\n" % type(e).__name__
        if out and not out.endswith("\n"):
            out += "\n"
        out += ("GATE=ran outside the worker's wall: the herd launcher for %s ran land.sh "
                "from the spawn record\n" % self.worker)
        log("gate: landing of %s exited %d" % (self.branch, rc))
        self._answer(rc, out, err)

    def poll(self) -> None:
        if self.closed or (self.thread is not None and self.thread.is_alive()):
            return
        data = self._take()
        if data is None:
            return
        why, script = self._judge(data)
        if why:
            log("gate: refused a landing request: " + why)
            self._repair(why)
            self._answer(1, "MERGED=no\n", "herd gate: refusing to land: %s; nothing moved.\n" % why)
            return
        self.thread = threading.Thread(target=self._land, args=(script,), daemon=False)
        self.thread.start()

    def join(self) -> None:
        if self.thread is not None:
            self.thread.join()


def resolve(cmd: str, skip_dir: str) -> str:
    skip = os.path.realpath(skip_dir)
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not d or os.path.realpath(d) == skip:
            continue
        p = os.path.join(d, cmd)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return os.path.abspath(p)
    return ""


def run(cfg_path: str, args: list) -> int:
    global LOG
    fd = os.open(cfg_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd) as f:
        cfg = json.load(f)
    LOG = cfg["log"]
    cpu, mem_mb, procs = int(cfg["cpu"]), int(cfg["mem_mb"]), int(cfg["procs"])
    agent = resolve(cfg["command"], cfg["shim_dir"])
    if not agent:
        sys.stderr.write("herd wall: no %s on PATH after the launcher's own directory\n" % cfg["command"])
        log("refused: no %s on PATH after the launcher" % cfg["command"])
        return 127
    gate = None
    child_env = dict(os.environ)
    if cfg["walled"]:
        argv = [cfg["bash"], cfg["plug"], "exec", cfg["profile"], "--", agent] + args
        # only a walled worker needs its landing served from outside; unwalled, it lands itself
        if isinstance(cfg.get("gate"), dict):
            gate = Gate(cfg["gate"], cfg["shim_dir"], cfg["worker"], cfg_path)
            child_env.update(gate.env_for_agent())
    else:
        argv = [agent] + args
        # an INHERITED wall is the one this launcher itself must be inside: the spawn saw
        # one around itself, but the tab may have been started by a herdr server that is
        # not behind it. The plug's `inside` is asked here, where the agent runs.
        if cfg.get("inherited"):
            inside = subprocess.run([cfg["bash"], cfg["plug"], "inside"], stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL).returncode == 0
            if not inside:
                sys.stderr.write("herd wall: the spawn inherited a wall, but this launcher runs behind none; "
                                 "the agent was not started\n")
                log("refused: wall=inherited, but the launcher runs behind no wall")
                return 2
    pid = os.fork()
    if pid == 0:
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_CPU)
            top = cpu + 5 if hard == resource.RLIM_INFINITY else min(hard, cpu + 5)
            resource.setrlimit(resource.RLIMIT_CPU, (min(cpu, top), top))
            os.execve(argv[0], argv, child_env)
        except BaseException as e:                                  # noqa: BLE001
            os.write(2, ("herd wall: could not start %s: %s\n" % (cfg["command"], type(e).__name__)).encode())
        os._exit(127)
    for s in (signal.SIGINT, signal.SIGQUIT, signal.SIGTSTP):
        signal.signal(s, signal.SIG_IGN)

    def forward(sig, _frame):
        try:
            os.kill(pid, sig)
        except OSError:
            pass
    for s in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(s, forward)
    said = "walled" if cfg["walled"] else ("inherited" if cfg.get("inherited") else "unwalled")
    log("started pid=%d wall=%s cpu=%ds mem=%dMB procs=%d" % (pid, said,
                                                              cpu, mem_mb, procs))
    table = Table()
    kq = select.kqueue() if hasattr(select, "kqueue") else None
    watched: set = set()
    killed = ""
    last = {pid}
    status, ru = 0, None
    while True:
        try:
            wpid, status, ru = os.wait4(pid, os.WNOHANG)
        except ChildProcessError:
            break
        if wpid == pid:
            break
        if gate is not None and not killed:
            gate.poll()
        if not killed:
            tree = table.tree(pid)
            if tree:
                last = tree
            if len(tree) > procs:
                killed = "process"
                log("killed: the process cap (procs=%d) was hit: %d in the worker's tree" % (procs, len(tree)))
                stop_and_kill(table, pid, tree)
            else:
                used = table.footprint(tree)
                if used > mem_mb * 1024 * 1024:
                    killed = "memory"
                    log("killed: the memory bound (mem=%dMB) was hit: %dMB in the worker's tree"
                        % (mem_mb, used // (1024 * 1024)))
                    stop_and_kill(table, pid, tree)
            if kq is not None and not killed:
                for p in tree - watched:
                    try:
                        kq.control([select.kevent(p, select.KQ_FILTER_PROC, select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                                                  select.KQ_NOTE_FORK | select.KQ_NOTE_EXIT)], 0, 0)
                    except OSError:
                        pass
                watched = (watched | tree) & tree
        try:
            if kq is not None:
                kq.control(None, 64, 0.2)
            else:
                time.sleep(0.1)
        except InterruptedError:
            pass
    rc = 0
    if os.WIFSIGNALED(status):
        sig = os.WTERMSIG(status)
        spent = (ru.ru_utime + ru.ru_stime) if ru is not None else 0.0
        if not killed and (sig == signal.SIGXCPU or (sig == signal.SIGKILL and spent >= cpu)):
            killed = "cpu"
            log("killed: the cpu bound (cpu=%ds) was hit by the agent after %.1fs of cpu time" % (cpu, spent))
            stop_and_kill(table, pid, last)
        rc = 128 + sig
    elif os.WIFEXITED(status):
        rc = os.WEXITSTATUS(status)
    log("exited status=%d" % rc)
    if gate is not None:
        # a landing half-done is worse than a launcher that outlives its worker by minutes
        gate.join()
    return rc


def main(argv: list) -> int:
    if argv[1:2] == ["probe"]:
        return probe(argv[2:])
    if argv[1:2] == ["run"] and len(argv) >= 3:
        rest = argv[3:]
        if rest[:1] == ["--"]:
            rest = rest[1:]
        return run(argv[2], rest)
    sys.stderr.write("usage: run.py probe <word> <dir> ... | run <run.json> -- <args...>\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
PY
# Step 1: judge every path this block writes (a symlink or a non-file there is exit 2,
# never followed or replaced -- even with HERD_WALL=off), then write the profile and the
# copies the launcher will run. Each file is unlinked by its exact path and created O_EXCL.
# The branch and its git dir are read NOW, before the worker exists, and the profile allows
# only that branch's ref -- never the whole common directory.
wall_branch="$(git -C "$cwd" symbolic-ref --quiet --short HEAD 2>/dev/null || true)"
wall_gitdir="$(git -C "$cwd" rev-parse --path-format=absolute --git-dir 2>/dev/null || true)"
HS_WALL_DIR="$wall_dir" HS_WALLS="$walls_dir" HS_CWD="$cwd" HS_HERD="$herd_dir" HS_NAME="$name" \
  HS_PRIMARY="$wall_primary" HS_COMMON="$wall_common" HS_PLUG="$here/walls/${wall_os}.sh" \
  HS_AGENT_CMD="$agent_cmd" HS_RUN_SRC="$wall_run_src" \
  HS_BRANCH="$wall_branch" HS_GITDIR="$wall_gitdir" \
  python3 -I - <<'PY' || exit 2
import os, shutil, stat, sys
wd, walls, cwd, herd, name = (os.environ[k] for k in ("HS_WALL_DIR", "HS_WALLS", "HS_CWD", "HS_HERD", "HS_NAME"))
primary, common, plug = os.environ["HS_PRIMARY"], os.environ["HS_COMMON"], os.environ["HS_PLUG"]
home, tmp = os.environ.get("HOME", ""), os.environ.get("TMPDIR", "")
targets = ["profile", "wall.log", "run.json", "run.py", "plug.sh", os.path.join("bin", os.environ["HS_AGENT_CMD"])]
tpl_dir = os.path.dirname(plug)
templates = sorted(n for n in (os.listdir(tpl_dir) if os.path.isdir(tpl_dir) else [])
                   if n.endswith(".template"))
for t in targets + templates:
    p = os.path.join(wd, t)
    if os.path.lexists(p) and not stat.S_ISREG(os.lstat(p).st_mode):
        print("herd-spawn: %s is a symlink or not a regular file; the wall's files are never written "
              "through or over one -- remove it if the name is yours to re-spawn; the worker %s was not started"
              % (p, name), file=sys.stderr)
        sys.exit(2)


def write(rel, text, mode=0o600):
    p = os.path.join(wd, rel)
    if os.path.lexists(p):
        os.unlink(p)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def real(p):
    return os.path.realpath(p)


def job_dir(anchor, parts):
    """Create anchor/parts... mode 700 where absent, OUTSIDE the wall: the worker may write
    into the last one but not beside it, so it could never create the chain itself. Each
    component made here must be a real directory -- a symlink or a file is exit 2, never
    followed into an allow-write line."""
    p = anchor
    for part in parts:
        p = os.path.join(p, part)
        if os.path.lexists(p):
            if not stat.S_ISDIR(os.lstat(p).st_mode):
                print("herd-spawn: %s is a symlink or not a directory; a walled worker's job directory is never "
                      "followed through one -- remove it; the worker %s was not started" % (p, name), file=sys.stderr)
                sys.exit(2)
        else:
            os.mkdir(p, 0o700)
    return p


# The worker's JOB, the two places outside its own that it must write (coordinator ruling,
# 2026-09-24): the test fixture root 54 test files hard-code, and the intake directory
# tools/appl-add.sh files into. Those two and nothing wider -- never HERD_DIR, which holds
# every other worker's brief and permissions.json.
intake = job_dir(herd, ["coordinator", "intake"])
fixtures = ""
if home:
    os.makedirs(os.path.join(home, ".cache"), exist_ok=True)
    fixtures = job_dir(os.path.join(home, ".cache"), ["muretai-tests"])
keys = real(os.path.join(primary, "keys"))
bindings = real(os.path.join(home, ".muretai", "bindings")) if home else ""
lines = ["# herd wall profile v1, written by herd-spawn.sh for the worker " + name,
         "# read by scripts/walls/<os>.sh; one verb and one absolute path per line",
         "egress open",
         "allow-write " + real(cwd),
         "allow-write " + real(os.path.join(herd, name)),
         "allow-write " + real(intake)]
if fixtures:
    lines.append("allow-write " + real(fixtures))
# The common directory is not a trust anchor: a worker who can write every ref can point
# main at their own commit. Allow the object store, this worktree's git dir, and this
# branch's ref (the lock file is <ref>.lock, so the ref path is a prefix). Deny main,
# master and packed-refs after that allow; a later Seatbelt rule wins.
branch = os.environ.get("HS_BRANCH", "")
gitdir = os.environ.get("HS_GITDIR", "")
if common and branch:
    lines.append("allow-write " + real(os.path.join(common, "objects")))
    if gitdir:
        gd, cm = real(gitdir), real(common)
        if gd != cm and (gd + "/").startswith(cm + "/worktrees/"):
            lines.append("allow-write " + gd)
    ref = real(os.path.join(common, "refs", "heads", branch))
    lines.append("allow-write-prefix " + ref)
    lines.append("allow-write-prefix " + real(os.path.join(common, "logs", "refs", "heads", branch)))
    for denied in ("refs/heads/main", "refs/heads/master",
                   "logs/refs/heads/main", "logs/refs/heads/master", "packed-refs"):
        lines.append("deny-write " + real(os.path.join(common, denied)))
for t in (tmp, "/tmp"):
    if t and os.path.isdir(t):
        lines.append("allow-write " + real(t))
if home:
    lines.append("allow-write " + real(os.path.join(home, ".claude")))
    lines.append("allow-write-prefix " + real(os.path.join(home, ".claude.json")))
if common:
    lines += ["deny-write " + real(os.path.join(common, "hooks")), "deny-write " + real(os.path.join(common, "config"))]
lines += ["deny-write " + real(os.path.join(herd, name, "brief.md")),
          "deny-write " + real(os.path.join(herd, name, "permissions.json")),
          "deny-write " + real(walls), "deny-write " + keys, "deny-read " + keys]
if bindings:
    lines += ["deny-write " + bindings, "deny-read " + bindings]
write("profile", "\n".join(lines) + "\n")
write("run.py", os.environ["HS_RUN_SRC"])
if os.path.isfile(plug) and not os.path.islink(plug):
    write("plug.sh", open(plug, encoding="utf-8").read(), 0o700)
    for t in templates:
        src = os.path.join(tpl_dir, t)
        if os.path.isfile(src) and not os.path.islink(src):
            write(t, open(src, encoding="utf-8").read())
else:
    for t in ["plug.sh"] + templates:
        if os.path.lexists(os.path.join(wd, t)):
            os.unlink(os.path.join(wd, t))
PY
# The claim probe (THE OWNER KEY above). Runs through the plug, under the worker's profile,
# the scripts a worker runs to hold its folder -- claim-worktree.sh, then assert-head.sh from
# another shell, as each Bash call of a session is -- with the key the tab will carry, in a
# throwaway repository and linked worktree made behind the wall inside $HERD_DIR/<name>/
# (the one place under HERD_DIR the profile lets the worker write, never TMPDIR and never
# the worker's repository), removed whatever the outcome. The scripts are this script's own
# siblings, the version that just wrote the profile: the landing's reviewer spawn and
# tools/security_daily.sh extract both from BASE beside their temporary copy of this script.
# Failing that, the cwd checkout's copy -- the one the worker itself will run -- is used.
# No copy of either is a finding, not a skip.
# Silent and 0 when the claim holds; else one clause on stdout and 1. No variable skips it.
wall_claim_probe() {
  local sd="" cand wt_root cdir crc cout step
  wt_root="$(iso_worktree_of "$cwd" 2>/dev/null || true)"
  for cand in "$here" "${wt_root:-/nonexistent}/.cursor/skills/isolated-session/scripts"; do
    if [[ -f "$cand/claim-worktree.sh" && -f "$cand/assert-head.sh" && -f "$cand/lib.sh" ]]; then
      sd="$cand"
      break
    fi
  done
  if [[ -z "$sd" ]]; then
    echo "no claim-worktree.sh and assert-head.sh were found to prove the worktree claim behind the wall, so the worker's lock is unproven"
    return 1
  fi
  if ! cdir="$(mktemp -d "$herd_dir/${name}/.claim-probe.XXXXXX" 2>/dev/null)"; then
    echo "could not create the claim probe's throwaway directory in ${herd_dir}/${name}, so the worker's lock is unproven"
    return 1
  fi
  crc=0
  cout="$( cd "$cdir" && /bin/bash "$wall_dir/plug.sh" exec "$wall_dir/profile" -- /bin/bash -c '
    d="$1"; sd="$2"
    unset HERD_WORKER ISOLATED_SESSION_TAKEOVER ISOLATED_SESSION_FORCE ISOLATED_SESSION_RESUME ISOLATED_SESSION_CROSS
    export ISOLATED_SESSION_OWNER="$3" GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
    export GIT_AUTHOR_NAME=herd-probe GIT_AUTHOR_EMAIL=herd-probe@example.invalid
    export GIT_COMMITTER_NAME=herd-probe GIT_COMMITTER_EMAIL=herd-probe@example.invalid
    git init -q "$d/repo" >/dev/null 2>&1 &&
      git -C "$d/repo" commit -q --allow-empty -m probe >/dev/null 2>&1 &&
      git -C "$d/repo" worktree add -q -b herd/claim-probe "$d/wt" >/dev/null 2>&1 || { echo step=setup; exit 1; }
    /bin/bash "$sd/claim-worktree.sh" "$d/wt" >/dev/null 2>&1 || { echo step=claim; exit 1; }
    /bin/bash "$sd/assert-head.sh" herd/claim-probe "$d/wt" >/dev/null 2>&1 || { echo step=assert-head; exit 1; }
    echo step=done
  ' herd-claim-probe "$cdir" "$sd" "$owner_key" 2>/dev/null )" || crc=$?
  rm -rf "$cdir"
  step="$(printf '%s\n' "$cout" | sed -n 's/^step=//p' | tail -1)"
  if [[ "$crc" == "0" && "$step" == "done" ]]; then
    return 0
  fi
  case "$step" in
    claim|assert-head)
      echo "behind the wall the worktree claim does not hold (${step}.sh failed in a throwaway repository under the worker's key), so the worker could not keep its lock" ;;
    setup)
      echo "behind the wall the claim probe could not even make its throwaway repository (git failed), so the worker's worktree claim and lock are unproven" ;;
    *)
      echo "the claim probe did not run to the end behind the wall (exit ${crc}), so the worker's worktree claim and lock are unproven" ;;
  esac
  return 1
}
wall_state=unwalled
wall_why=""
if [[ "$wall_scope" != "walled" ]]; then
  wall_why="scope=${wall_scope}"
  [[ -n "$wall_mode" ]] || wall_mode="n/a"
else
  plug_ok=no
  if [[ -f "$wall_dir/plug.sh" ]] && /bin/bash "$wall_dir/plug.sh" available >/dev/null 2>&1; then
    plug_ok=yes
  fi
  mode_said="HERD_WALL=${wall_mode}"
  if [[ -z "$wall_mode" ]]; then
    wall_mode=require
    mode_said="HERD_WALL=require, the default"
  fi
  # A spawn that already runs BEHIND a wall inherits it (coordinator ruling 2026-09-25):
  # sandbox-exec does not nest, so the plug says it cannot build one, and a walled worker
  # that runs a test which spawns would otherwise be refused. The marker is what the plug's
  # `exec` put into the walled process; it is a CLAIM, and the plug's `inside` verb (the
  # kernel's answer) must confirm it. A missing plug is a broken install, not a nested
  # wall: no marker turns it into a start. The launcher asks `inside` again where the agent
  # really runs (run.py), since a real herdr starts the tab from its server, not from here.
  inherited_from=""
  marker_said=""
  if [[ "$wall_mode" != "off" && "$plug_ok" != "yes" && -f "$wall_dir/plug.sh" ]]; then
    case "${HERD_WALL_INSIDE:-}" in
      ''|*[!a-z0-9_-]*|[!a-z]*) ;;
      *)
        if [[ ${#HERD_WALL_INSIDE} -le 32 ]] && /bin/bash "$wall_dir/plug.sh" inside >/dev/null 2>&1; then
          inherited_from="$HERD_WALL_INSIDE"
        else
          marker_said="; HERD_WALL_INSIDE is set, but the plug finds no wall around this spawn, so the marker is not a wall"
        fi
        ;;
    esac
  fi
  if [[ "$wall_mode" == "off" ]]; then
    wall_why="why=off"
  elif [[ -n "$inherited_from" ]]; then
    wall_state=inherited
    wall_why="why=inside:${inherited_from}"
  elif [[ "$plug_ok" != "yes" ]]; then
    if [[ "$wall_mode" == "require" ]]; then
      echo "herd-spawn: there is no wall on this machine (scripts/walls/${wall_os}.sh is missing or says it cannot build one) and ${mode_said}${marker_said}; the worker ${name} was not started" >&2
      exit 2
    fi
    echo "herd-spawn: warning: no wall on this machine (scripts/walls/${wall_os}.sh is missing or says it cannot build one)${marker_said}, so the worker ${name} runs unwalled (${mode_said}); the bounds still hold" >&2
    wall_why="why=no-wall"
  else
    # the probe: through the plug, under the agent's own profile, from a scratch
    # directory inside HERD_DIR (never TMPDIR), removed whatever the outcome
    probe_dir="$(mktemp -d "$herd_dir/.wall-probe.XXXXXX")" || {
      echo "herd-spawn: could not create the wall probe's scratch directory under ${herd_dir}; the worker ${name} was not started" >&2
      exit 2
    }
    # ... and the JOB: the same run trials a write into each place the worker must write
    # outside its own (the fixture root, the intake dir). A wall that holds the secrets but
    # denies the job would start a worker only to have it die at its first test run.
    probe_args=(keys "$wall_primary/keys" bindings "${HOME:-/nonexistent}/.muretai/bindings"
                write:intake "$herd_dir/coordinator/intake")
    [[ -z "${HOME:-}" ]] || probe_args+=(write:suite "$HOME/.cache/muretai-tests")
    probe_rc=0
    ( cd "$probe_dir" && /bin/bash "$wall_dir/plug.sh" exec "$wall_dir/profile" -- \
        "$wall_py" -I "$wall_dir/run.py" probe "${probe_args[@]}" \
    ) >"$probe_dir/out" 2>/dev/null || probe_rc=$?
    leaks=""
    jobs_denied=""
    probe_done=no
    # a path is named with a literal ~ for HOME: the line is read on a screen, not pasted
    home_said() {
      if [[ -n "${HOME:-}" && ( "$1" == "$HOME" || "$1" == "$HOME"/* ) ]]; then
        printf '%s%s' '~' "${1#"$HOME"}"
      else
        printf '%s' "$1"
      fi
    }
    while IFS= read -r pl; do
      case "$pl" in
        keys|bindings) leaks="${leaks}${leaks:+, }${pl}" ;;
        cannot-suite)
          jobs_denied="${jobs_denied}${jobs_denied:+, nor }write $(home_said "$HOME/.cache/muretai-tests") (so it could not run the test suite)" ;;
        cannot-intake)
          jobs_denied="${jobs_denied}${jobs_denied:+, nor }write $(home_said "$herd_dir/coordinator/intake") (so it could not file an intake)" ;;
        done) probe_done=yes ;;
      esac
    done < "$probe_dir/out"
    rm -rf "$probe_dir"
    if [[ -n "$leaks" ]]; then
      finding="the wall probe could still read ${leaks} behind the wall, so the wall does not hold"
    elif [[ "$probe_done" != "yes" || "$probe_rc" != "0" ]]; then
      finding="the wall probe did not run to the end (exit ${probe_rc}), so the wall is unproven"
    elif [[ -n "$jobs_denied" ]]; then
      finding="the wall stands, but behind it the worker could not ${jobs_denied}"
    elif ! finding="$(wall_claim_probe)"; then
      :
    else
      finding=""
      wall_state=walled
    fi
    if [[ -n "$finding" ]]; then
      if [[ "$wall_mode" == "require" ]]; then
        echo "herd-spawn: ${finding}; the worker ${name} was not started (${mode_said})" >&2
        exit 2
      fi
      echo "herd-spawn: warning: ${finding}; the worker ${name} runs unwalled (${mode_said}); the bounds still hold" >&2
      wall_why="why=probe"
    fi
  fi
fi
# A walled worker whose cwd is the PRIMARY gets NO gate. The launcher's gate is the branch
# the cwd has checked out at spawn, and finish-worktree.sh hands a landing to it only when
# the branch and worktree it lands ARE the gate's -- a gate on the base branch in the
# primary matches no landing a worker ever makes (it opens its own worktree from there), so
# it would only look like a gate. "The primary" is judged the way the landing judges it:
# the recorded branch is the base ref, which a subdirectory of the primary is too. Said on
# stderr and in wall.log, so a spawn that can never land through the gate is visible.
wall_base="main"
if [[ -n "$wall_common" ]] &&
   ! git --git-dir "$wall_common" rev-parse --verify --quiet refs/heads/main >/dev/null 2>&1 &&
   git --git-dir "$wall_common" rev-parse --verify --quiet refs/heads/master >/dev/null 2>&1; then
  wall_base="master"
fi
gate_none=""
if [[ "$wall_state" == "walled" && -n "$wall_common" && "$wall_branch" == "$wall_base" ]]; then
  gate_none="gate=none (cwd is the primary on ${wall_base})"
  # ... and an IMPLEMENTER there is not started at all: it is the worker that lands, and
  # its landing could never be handed to the launcher, so it would fall to the lease step
  # inside the wall and wait for a person. Judged by the brief's first line, the way
  # appl-role-of.sh reads a role. The IMPLEMENTER template only: dispatch-take.sh now opens
  # the ticket's worktree and spawns there, but a Dispatch ticket spawned on the primary (an
  # older dispatch-take, a by-hand spawn) still starts here with gate=none (coordinator
  # ruling 20260927T014613Z; test_gate_cwd.py c4).
  # A test author on the primary opens its own worktree and never lands, so it starts.
  brief_first=""
  IFS= read -r brief_first < "$brief" || true
  case "$brief_first" in
    "You are a Muretai implementer session"*)
      echo "herd-spawn: a walled implementer on the primary checkout could never land: its landing gate binds to the branch its cwd has checked out at spawn (${wall_base} here), and finish-worktree.sh hands the launcher only that branch in that worktree; pass --cwd <WORKTREE> (the pair's worktree, from the test author's report); the worker ${name} was not started" >&2
      exit 2
      ;;
  esac
  echo "herd-spawn: ${gate_none}: the worker ${name} has no landing gate; a landing it makes runs where it runs" >&2
fi
# Step 2: the record, and the launcher. wall.log is this spawn's own (rewritten, like the
# profile); run.py appends to it -- the start, and any kill -- from outside the wall.
if [[ "$bounded" == "yes" ]]; then
  bounds_said="cpu=${wall_cpu}s mem=${wall_mem}MB procs=${wall_procs}"
else
  bounds_said="bounds=none"
fi
# The landing the launcher may serve for a walled worker (run.py's Gate): the branch the
# worker's cwd has checked out NOW, at spawn, in the file the worker cannot write -- never
# what the worker's worktree says later, and never what its request says. wall_branch and
# wall_gitdir were read before the profile, so the record and the wall name the same ref.
HS_WALL_DIR="$wall_dir" HS_NAME="$name" HS_AGENT_CMD="$agent_cmd" HS_PY="$wall_py" \
  HS_HERD="$herd_dir" HS_CWD="$cwd" HS_PRIMARY="$wall_primary" HS_BRANCH="$wall_branch" \
  HS_COMMON="$wall_common" HS_GITDIR="$wall_gitdir" HS_LAND="$here/land.sh" \
  HS_RECORD="spawn worker=${name} profile=${profile} harness=${harness} mode=${wall_mode} wall=${wall_state} egress=open ${bounds_said}${wall_why:+ ${wall_why}}" \
  HS_WALLED="$wall_state" HS_BOUNDED="$bounded" HS_CPU="$wall_cpu" HS_MEM="$wall_mem" HS_PROCS="$wall_procs" \
  HS_GATE_NONE="$gate_none" HS_PROFILE="$profile" \
  python3 -I - <<'PY' || exit 2
import json, os, shlex, subprocess, time
wd = os.environ["HS_WALL_DIR"]


def write(rel, text, mode=0o600):
    p = os.path.join(wd, rel)
    if os.path.lexists(p):
        os.unlink(p)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
logged = stamp + " " + os.environ["HS_RECORD"] + "\n"
if os.environ.get("HS_GATE_NONE"):
    logged += stamp + " " + os.environ["HS_GATE_NONE"] + "\n"
write("wall.log", logged)
shim = os.path.join("bin", os.environ["HS_AGENT_CMD"])
if os.environ["HS_BOUNDED"] != "yes":
    for rel in ("run.json", shim):
        if os.path.lexists(os.path.join(wd, rel)):
            os.unlink(os.path.join(wd, rel))
else:
    common = os.environ.get("HS_COMMON", "")
    branch = os.environ.get("HS_BRANCH", "")
    gitdir = os.environ.get("HS_GITDIR", "")

    def has_ref(ref):
        if not common:
            return False
        return subprocess.run(["git", "--git-dir", common, "rev-parse", "--verify", "--quiet", ref],
                              capture_output=True).returncode == 0

    base_ref = "main"
    if common and not has_ref("refs/heads/main") and has_ref("refs/heads/master"):
        base_ref = "master"
    base_sha = ""
    if common and has_ref("refs/heads/" + base_ref):
        base_sha = subprocess.run(
            ["git", "--git-dir", common, "rev-parse", "--verify", "--quiet",
             "refs/heads/" + base_ref + "^{commit}"],
            capture_output=True, text=True).stdout.strip()
    # A REVIEWER's checkout is opened at the BASE it reviews from, on a receipt branch of its
    # own, while main already carries the landings it reads (both spawn sites). Its base is
    # that checkout's HEAD now, at spawn: land.sh runs BASE's gate out of it and tests the
    # receipt range from it, and the landed tip would name commits the reviewer never branched
    # from. A worker's base stays main at spawn.
    if os.environ.get("HS_PROFILE") == "reviewer" and branch and gitdir:
        base_sha = subprocess.run(
            ["git", "--git-dir", gitdir, "rev-parse", "--verify", "--quiet", "HEAD^{commit}"],
            capture_output=True, text=True).stdout.strip()
    record = None
    if branch and common:
        record = {"common_dir": os.path.realpath(common),
                  "worktree_gitdir": os.path.realpath(gitdir) if gitdir else "",
                  "base_ref": base_ref, "base_sha": base_sha, "branch": branch,
                  "branch_ref": "refs/heads/" + branch,
                  "worktree": os.path.realpath(os.environ["HS_CWD"]),
                  "primary": os.path.realpath(os.environ["HS_PRIMARY"])}
    src = os.environ.get("HS_LAND", "")
    if src and os.path.isfile(src) and not os.path.islink(src):
        write("land.sh", open(src, encoding="utf-8").read(), 0o700)
    gate = None
    # no gate on the base branch: a cwd in the primary (see gate_none in the shell above)
    if os.environ["HS_WALLED"] == "walled" and branch and record and branch != base_ref:
        gate = {"channel": os.path.join(os.environ["HS_HERD"], os.environ["HS_NAME"]),
                "primary": record["primary"], "worktree": record["worktree"], "branch": branch,
                "lander": os.path.join(wd, "land.sh")}
        gate.update(record)
    write("run.json", json.dumps({
        "worker": os.environ["HS_NAME"], "log": os.path.join(wd, "wall.log"),
        "cpu": int(os.environ["HS_CPU"]), "mem_mb": int(os.environ["HS_MEM"]), "procs": int(os.environ["HS_PROCS"]),
        "walled": os.environ["HS_WALLED"] == "walled", "inherited": os.environ["HS_WALLED"] == "inherited",
        "plug": os.path.join(wd, "plug.sh"),
        "profile": os.path.join(wd, "profile"), "command": os.environ["HS_AGENT_CMD"],
        "shim_dir": os.path.join(wd, "bin"), "bash": "/bin/bash",
        "record": record, "gate": gate}, indent=1) + "\n")
    write(shim, "#!/bin/bash\n"
          "# herd-spawn.sh wrote this launcher for the worker " + os.environ["HS_NAME"] + ": the tab's PATH\n"
          "# finds it first, and it starts the agent under the bounds (and behind the wall, when\n"
          "# the spawn was walled) -- see run.py and run.json beside it.\n"
          "exec " + " ".join(shlex.quote(a) for a in (os.environ["HS_PY"], "-I", os.path.join(wd, "run.py"), "run",
                                                       os.path.join(wd, "run.json"), "--")) + ' "$@"\n', 0o700)
PY
# Only a spawn that GETS a landing needs land.sh: the same test run.json's `gate` uses (walled,
# on a branch, in a repository). A spawn in a detached checkout has no branch to land, so
# nothing would ever run the lander; refusing it for a missing one refused the daily review.
# Both reviewer spawn sites now open the reviewer ON its receipt branch, so a walled reviewer
# gets the gate, and needs land.sh, like a worker.
if [[ "$wall_state" == "walled" && -n "$wall_branch" && -n "$wall_common" && ! -f "$wall_dir/land.sh" ]]; then
  echo "herd-spawn: no land.sh beside this script; a walled worker has no landing to run; the worker ${name} was not started" >&2
  exit 2
fi

# --- the brief, filled ----------------------------------------------------------------
# Built-ins first, --var after, so a caller can override NAME/PRIMARY/REPORT on purpose.
# One pass with a dict: a value is substituted, never re-scanned, so a value carrying
# `{{NAME}}` stays literal. A placeholder the TEMPLATE carries and nobody filled stops
# the spawn. The text is rendered once and written twice: the worker's brief.md, and the
# operator's copy under briefs/ (the brief may already BE that path -- a landing renders
# there, then calls this script on it -- so it is read once, before either write).
# Both files are written the way the rules file is: the exact path unlinked, then created
# O_EXCL mode 600. For the operator's copy a symlink goes and its target stays. For
# brief.md only a REGULAR file is unlinked (the re-spawn of a name gets its new brief);
# a symlink or a directory there is exit 2 BEFORE the operator's copy is touched, and a
# path that exists again between the unlink and the create is a refusal, never a merge.
python3 -I - "$brief_abs" "$rendered" "$bfile" "NAME=${name}" "PRIMARY=${cwd}" "REPORT=${report}" \
  ${vars[@]+"${vars[@]}"} <<'PY' || exit $?
import os, re, stat, sys
src, dst, bfile = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(src, encoding="utf-8").read()
values = {}
for kv in sys.argv[4:]:
    key, _, value = kv.partition("=")
    values[key] = value
missing = []


def fill(m):
    key = m.group(1)
    if key in values:
        return values[key]
    missing.append(key)
    return m.group(0)


out = re.sub(r"\{\{([A-Z][A-Z0-9_]*)\}\}", fill, text)
if missing:
    print("herd-spawn: the brief still carries unfilled placeholders: " + " ".join(sorted(set(missing)))
          + " -- pass --var KEY=VALUE for each", file=sys.stderr)
    sys.exit(2)
out = out.rstrip("\n") + "\n"


worker = os.path.basename(os.path.dirname(bfile))


def refuse(why):
    print("herd-spawn: " + bfile + " " + why + "; brief.md is never written through or over one -- "
          "remove it if the name is yours to re-spawn; the worker " + worker + " was not started",
          file=sys.stderr)
    sys.exit(2)


def not_regular(p):
    st = os.lstat(p)
    return not stat.S_ISREG(st.st_mode)


if os.path.lexists(bfile) and not_regular(bfile):
    refuse("is a symlink or not a regular file")
if os.path.lexists(dst):
    os.unlink(dst)
fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    f.write(out)
# a re-spawn of the name: the previous brief.md (a regular file, checked above) is
# replaced by this render -- unlinked by its exact path, then created O_EXCL
if os.path.lexists(bfile):
    if not_regular(bfile):
        refuse("became a symlink or a non-regular file while the brief was rendered")
    os.unlink(bfile)
try:
    fd = os.open(bfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except OSError as e:
    refuse("could not be created exclusively (" + (e.strerror or type(e).__name__) + ")")
with os.fdopen(fd, "w", encoding="utf-8") as f:
    f.write(out)
PY
# brief.md is this spawn's own from here: a failure below where nothing was typed into the
# pane removes it (a refusal above never reaches this line, and leaves the file that was
# there alone). A failure of `agent prompt` itself keeps it: see half_fail.
brief_ours=yes
# What a failure below has already done, for the one line it prints: the coordinator
# must never read a half-spawn as a success, and "which half" is what it acts on.
done_steps="brief.md written (${bfile})"
# half_fail RC WHAT [keep]: one stderr line naming the failure, the steps that
# completed, and that the brief was NOT delivered; no worker= line. `keep` is for a
# failure of `agent prompt` itself (a stall past the deadline, a timeout, a refusal),
# where the line may already be in the pane: the ISSUE this exists for was a worker that
# received the line after a stall and found brief.md removed by the spawn's own cleanup.
half_fail() {
  local rc="$1" what="$2" keep="${3:-}" tail delivered="the brief was not delivered"
  if [[ "$keep" == "keep" ]]; then
    brief_ours=no
    delivered="the brief was not delivered as far as herdr reports"
    tail="brief.md is KEPT at ${bfile}: the line may already have been typed into the pane, so a worker that got it finds its brief -- check the pane before re-spawning ${name}"
  else
    tail="nothing was typed into a pane, so brief.md is removed"
  fi
  echo "herd-spawn: ${what}; ${delivered} to ${name} -- done: ${done_steps}; ${tail}" >&2
  exit "$rc"
}
drop_brief() {
  if [[ "${brief_ours:-no}" == "yes" ]]; then
    rm -f "$bfile"
    # a solo role belongs to a worker that was started; a failed spawn declares nothing,
    # and records no repository for a report that will never come
    rm -f "$role_marker" "$role_record" "$repo_record"
    # ... and the codex config home this spawn wrote into. Left standing, the config.toml
    # and the login symlink ARE the non-empty home the check above refuses, so a spawn that
    # failed after them would refuse its own retry; and a link to the owner's auth.json in a
    # home nobody will ever open is a link nobody meant to leave. The EXACT paths are removed
    # (a symlink goes, its target stays), then the directory itself when nothing else is in
    # it -- a plant beside them is not this spawn's to delete.
    if [[ -n "${codex_home:-}" && ! -L "$codex_home" && -d "$codex_home" ]]; then
      rm -f "$codex_home/config.toml" "$codex_home/auth.json"
      rmdir "$codex_home" 2>/dev/null || true
    fi
  fi
}
trap drop_brief EXIT

# --- the role, declared ------------------------------------------------------------------
# Only after brief.md was created exclusively: the name is this spawn's from here, so what
# an earlier spawn of it left is ours to replace. Every WORKER-profile spawn declares solo,
# with or without `--role solo` (coordinator ruling 2026-09-26, Option B): operator spawns
# made without the flag (invariant-gate-tests, four-guards) had no record, and their
# REPORT lines never reached the coordinator. A pair worker is still not solo: its brief
# opens as a template, and appl-role-of.sh lets the template win over any record. The
# marker and the spawn's own record are each unlinked by exact path (a planted symlink
# goes, never followed) and created O_EXCL mode 400. A reviewer or coordinator spawn
# declares nothing and REMOVES both, so a record an earlier spawn of the name left never
# makes it solo (ISSUE(solo-marker-is-worker-writable)).
if [[ "$profile" == "worker" ]]; then
  python3 -I - "$role_marker" "$role_record" <<'PY' || exit 2
import os, sys
for path in sys.argv[1:]:
    if os.path.lexists(path):
        os.unlink(path)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
    except OSError as e:
        print("herd-spawn: could not create the role file exclusively at " + path + ": " + e.strerror
              + "; the worker was not started", file=sys.stderr)
        sys.exit(2)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("solo\n")
PY
else
  rm -f "$role_marker" "$role_record"
fi

# --- the repository the report is judged in ----------------------------------------------
# Every worker, whatever its role: unlinked by exact path, created O_EXCL mode 600 in the
# herd-level .repos/ (mode 700, Edit-denied to every session), before the tab exists. The
# hook reads it and nothing else to name `appl-verify.sh --repo`; with no record it blocks.
python3 -I - "$repo_record" "$spawn_repo" <<'PY' || exit 2
import os, sys
path, repo = sys.argv[1], sys.argv[2]
if os.path.lexists(path):
    os.unlink(path)
try:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
except OSError as e:
    print("herd-spawn: could not create the repository record exclusively at " + path + ": " + e.strerror
          + "; the worker was not started", file=sys.stderr)
    sys.exit(2)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    f.write(repo + "\n")
PY

# --- the tab, the agent, the prompt ------------------------------------------------------
# Auto memory is OFF for a herd session: it is keyed by the repository, shared across
# worktrees, and written by every session -- one prompt-injected session's "secrev-*:
# record 0 findings" would reach every later reviewer without appearing in any diff
# (ISSUE(security-audit-2026-09-12-the-cleanup-trusts-n-d474-2)). The settings file
# below says the same (autoMemoryEnabled) and keeps the memory files of the cwd's
# ancestors out too.
#
# PYTHONNOUSERSITE=1 is on this list and not anywhere else, because `herdr tab create` is
# an RPC to the herdr DAEMON: the tab's environment is exactly what is passed here, and a
# `credless` around THIS script walls this script's own pythons and reaches nothing the
# daemon starts. Measured in a live reviewer session -- `printenv PYTHONNOUSERSITE` exited
# 1 -- so the reviewer's `python3 tools/audit_scope.py write-receipt`, the one command
# whose output the publisher waits for, imported whatever a branch's test run had left in
# the operator-writable user site directory, and the file it wrote could say
# `verdict: clean` while the terminal said "receipt written"
# (ISSUE(security-audit-2026-09-18-daily-2026-09-18-9)). Every profile gets it: a worker
# writes receipts and notes too, and a wall that is on for one session and off for the
# next is a wall nobody can reason about. The briefs spell `python3 -I` and the allow
# rules below grant that spelling, so the tab and the instructions agree.
tab_env=(--env ISOLATED_SESSION_GUARD_TRACE=1 --env CLAUDE_CODE_DISABLE_AUTO_MEMORY=1
         --env PYTHONNOUSERSITE=1
         --env "HERD_WORKER=${name}" --env "HERD_BRIEF=${bfile}" --env "HERD_REPORT=${report}")
if [[ "$harness" == "cursor" ]]; then
  tab_env+=(--env "CURSOR_CONFIG_DIR=${cursor_home}")
fi
# The coordinator is the one pane that runs for days. Claude Code's in-pane auto-update
# ended it mid-loop twice (2026-09-24, 2026-09-26: `Update installed - Restart to update`
# beside `Not logged in`), after which it swallowed every intake until the owner found it.
# With the updater off, the update happens when the owner restarts the pane on purpose
# (restart-coordinator-pane.sh). A caller override was refused above.
if [[ "$profile" == "coordinator" ]]; then
  tab_env+=(--env DISABLE_AUTOUPDATER=1)
fi
if [[ "$harness" == "codex" ]]; then
  # the config home the spawn owns, so the file we wrote is the file codex obeys; no path
  # under the user's own ~/.codex is handed to the tab at all
  tab_env+=(--env "CODEX_HOME=${codex_home}")
fi
# the launcher first on the tab's PATH, so the harness binary herdr starts is the wall's
# and the bounds' (a caller --env PATH= is refused where --env is parsed)
if [[ "$bounded" == "yes" ]]; then
  tab_env+=(--env "PATH=${wall_dir}/bin:${PATH}")
fi
for kv in ${envs[@]+"${envs[@]}"}; do
  tab_env+=(--env "$kv")
done
# A walled worker's stable owner key (THE OWNER KEY, in the wall block): the caller's entry
# went on above and is the only one; without it, the worker's name. An unwalled worker keeps
# the process walk, which works where `ps` does.
if [[ "$wall_state" == "walled" || "$wall_state" == "inherited" ]] && [[ "$owner_key_from_caller" != "yes" ]]; then
  tab_env+=(--env "ISOLATED_SESSION_OWNER=${owner_key}")
fi
# Wake-target mark: the pane env is what a node child / L0 hook can see. The
# token is the first non-DID mark herdrwake._select recognises. Never a DID.
if [[ -n "$muretai_agent" ]]; then
  tab_env+=(--env "MURETAI_HERDR_AGENT=${muretai_agent}")
fi
tab_json="$("$herdr" tab create --cwd "$cwd" --label "$name" --no-focus "${tab_env[@]}")" ||
  half_fail 1 "'herdr tab create' failed for ${name}, so no tab and no pane exist"
ids="$(printf '%s\n' "$tab_json" | python3 -I -c '
import json, sys
d = json.load(sys.stdin)
r = d.get("result", d)
print(r["root_pane"]["pane_id"], r["tab"]["tab_id"])
')" || half_fail 1 "could not read pane/tab ids from 'herdr tab create' output for ${name} (a tab may be open under the label ${name})"
pane="${ids%% *}"
tab_id="${ids#* }"
done_steps="${done_steps}, tab created (pane ${pane}, tab ${tab_id}; left open)"
if [[ -n "$muretai_agent" ]]; then
  # Pane id is known only after tab create. Token only -- never muretai_did
  # (a spawn must not write a DID onto argv or into the brief).
  "$herdr" pane report-metadata "$pane" --source muretai \
      --token "muretai_agent=${muretai_agent}" >/dev/null ||
    half_fail 1 "'herdr pane report-metadata' failed for ${name} (pane ${pane}); the agent was not started"
fi

if [[ "$profile" == "coordinator" ]]; then
  # Exactly this list, nothing shared with the others: spawn (both spellings, the second
  # through the primary of the repository this script lives in), drive panes, read the
  # node inbox, dm, read the coordinator directory, write only its intake/ and briefs/.
  # No git, no echo, no tools/tests: a coordinator that needs more briefs a worker.
  spawner_rel=".cursor/skills/isolated-session/scripts/herd-spawn.sh"
  coord_dir="${herd_dir%/}/coordinator"
  allow=("Bash(bash ${spawner_rel}:*)")
  if spawner_primary="$(iso_primary_of "$here")"; then
    allow+=("Bash(bash ${spawner_primary}/${spawner_rel}:*)")
  fi
  allow+=(
    "Bash(herdr agent prompt:*)" "Bash(herdr agent read:*)" "Bash(herdr agent wait:*)"
    "Bash(herdr agent list:*)" "Bash(herdr agent send-keys:*)"
    "Bash(herdr tab list:*)" "Bash(herdr tab close:*)"
    "Bash(python3 operator_cli.py --as * inbox*)" "Bash(python3 operator_cli.py --as * dm *)"
    "Read(//${coord_dir#/}/**)"
    "Edit(//${coord_dir#/}/intake/**)" "Edit(//${coord_dir#/}/briefs/**)"
  )
  # The coordinator harness (plan 2026-09-19): the pane's deterministic steps, each script
  # by its exact path (both spellings, like the spawner: never a directory or an `appl-*`
  # glob, which would run whatever a diff drops beside them), and the Agent tool for its
  # three small-model subagents only. appl-hook.sh is not here: the hook runs it, the
  # model never needs to.
  for s in appl-verify.sh appl-status.sh appl-hydrate.sh appl-role-of.sh appl-close.sh; do
    allow+=("Bash(bash .cursor/skills/isolated-session/scripts/${s}:*)")
    if [[ -n "${spawner_primary:-}" ]]; then
      allow+=("Bash(bash ${spawner_primary}/.cursor/skills/isolated-session/scripts/${s}:*)")
    fi
  done
  allow+=("Agent(appl-brief-writer)" "Agent(appl-report-reader)" "Agent(appl-prompt-triage)")
else
allow=(
  "Bash(python3 tools/audit_scope.py:*)"
  "Bash(python3 tools/ledger.py:*)"
  "Bash(python3 tools/sec_lint.py:*)"
  "Bash(python3 tools/affected_tests.py:*)"
  "Bash(python3 tools/spec_build.py:*)"
  # SHADOWED since the deny list refuses `-m` by shape (see the deny block below): a deny
  # beats any allow, so this rule grants nothing any more and a session that needs
  # `agent.plugins check` asks a person for it. It is left standing, and named here, so
  # the next reader learns the rule was withdrawn rather than never written -- the plugin
  # check a session actually reads is the one tools/security_weekly.sh already ran.
  "Bash(python3 -m agent.plugins:*)"
)
if [[ "$profile" == "worker" ]]; then
  allow+=("Bash(python3 tools/run_tests.py:*)" "Bash(python3 tests/test_:*)")
  # the no-stops plan's S2: the task scripts and tests of the worker's own worktree, also
  # behind `env -u X` (no-space `*`: `tools/*` is any path under tools/). The env form
  # starts `env -u `: a bare `env *python3 tests/*` also matched
  # `env python3 -c '<code>' python3 tests/x`, which no deny prefix reaches
  allow+=("Bash(python3 tools/*)" "Bash(python3 tests/*)" "Bash(env -u * python3 tests/*)")
  # the test files in the isolated spelling. This one is the NO-SPACE wildcard and not a
  # `:*` prefix: `Bash(x:*)` is the prefix AND a space, and the argument here ends in a
  # NAME prefix (`tests/test_`) that the file name continues without one -- the same
  # reason cursor_rule() re-spells a trailing `_` as `<prefix>*`
  allow+=("Bash(python3 -I tools/run_tests.py:*)" "Bash(python3 -I tests/test_*)")
  # Dispatch finish verbs the ticket brief names: coord deliver, a Room dm
  # (deliverable, /remember, or failed), and stance full via dispatch-capacity.
  # A bare operator_cli.py prefix would let a ticket drive wake set/test.
  allow+=("Bash(python3 operator_cli.py --as * coord * deliver *)")
  allow+=("Bash(python3 operator_cli.py --as * dm *)")
  allow+=("Bash(python3 -I operator_cli.py --as * coord * deliver *)")
  allow+=("Bash(python3 -I operator_cli.py --as * dm *)")
  allow+=("Bash(bash .cursor/skills/isolated-session/scripts/dispatch-capacity.sh:*)")
fi
# The SAME commands in the isolated spelling. The tab above carries PYTHONNOUSERSITE=1 and
# every brief instructs `python3 -I`, so a list that granted only the bare spelling would
# stop the worker at a permission prompt on its own instructions -- and a session that has
# to ask a person for each of its own commands is a session that runs nothing unattended.
# `-I` is per-process and grants nothing: it REMOVES the user site directory and the
# PYTHON* variables from that one interpreter. The deny list beats every one of these, and
# since the shape rules below it does so in the ISOLATED dialect too: `python3 -I -c`,
# `python3 -Ic`, `python3 -I -` and `python3 -I -m ...` are refused, while `python3 -I
# <path>` -- what each rule here names -- is not.
allow+=(
  "Bash(python3 -I tools/audit_scope.py:*)"
  "Bash(python3 -I tools/ledger.py:*)"
  "Bash(python3 -I tools/sec_lint.py:*)"
  "Bash(python3 -I tools/affected_tests.py:*)"
  "Bash(python3 -I tools/spec_build.py:*)"
  # `-m agent.plugins` is deliberately NOT here: `-I` takes the caller's directory off
  # sys.path and the module would not be found, so the isolated spelling of that one is a
  # broken command, and a rule granting it would teach it. The tab's PYTHONNOUSERSITE=1
  # walls it either way.
)
allow+=(
  "Bash(bash .cursor/skills/isolated-session/scripts/stale.sh:*)"
  "Bash(bash .cursor/skills/isolated-session/scripts/ensure-worktree.sh:*)"
  "Bash(bash .cursor/skills/isolated-session/scripts/assert-head.sh:*)"
  "Bash(bash .cursor/skills/isolated-session/scripts/claim-worktree.sh:*)"
  "Bash(bash .cursor/skills/isolated-session/scripts/finish-worktree.sh:*)"
  "Bash(cd:*)"
  "Bash(git status:*)" "Bash(git add:*)" "Bash(git commit:*)"
  "Bash(git diff:*)" "Bash(git log:*)" "Bash(git show:*)"
  "Bash(git rev-parse:*)" "Bash(git worktree list:*)"
  "Bash(git ls-files:*)"
  "Bash(ls:*)"
  # the no-stops plan's S1: the glue chained after a real command, and read-only git
  # (`git branch` only in its reading forms: `git branch -f/-D main` would move or
  # delete the shared trunk ref from a worktree)
  "Bash(echo:*)" "Bash(printf:*)" "Bash(pwd)" "Bash(true)" "Bash(test:*)" "Bash(mkdir -p:*)"
  "Bash(git branch --list:*)" "Bash(git branch --show-current)"
  "Bash(git merge-base:*)" "Bash(git rev-list:*)"
)
fi
# the brief's own --allow rules (judged above), after the profile's
allow+=(${extra_allow[@]+"${extra_allow[@]}"})
# `git ls-files` reads tracked content only (never keys/, which is not tracked).
# `git grep -O` / `--open-files-in-pager` runs a program, and `git blame --contents`
# reads any file the uid can read, so those two are not on the allowlist: a session
# navigates with its own search and Read tools, and a `git grep` stops at a prompt
# (the coordinator answers -- that is the intended cost). Measured 2026-09-13: a
# Cursor session in allowlist mode stops at "Waiting for approval" on an unlisted
# git subcommand, and "add to allowlist" writes the USER config, which the spawner
# then refuses for every later spawn.
# (The deny list is defined above, before herdr is asked anything: --allow is judged
# against it.)
# The rules travel as a settings file, not as argv (the typed-line bound above). The
# file is the worker's own, under its report directory, and it is written exclusively:
# `rm -f` the exact path (a planted symlink is removed, never followed; the file a
# previous spawn of the same name left is removed too), then O_CREAT|O_EXCL mode 600 --
# a path that exists again by then is a refusal, and claude is never started on a file
# this spawn did not create.
#
# On codex the SAME lists are written, to rules.unenforced.json and with a note, because
# nothing there enforces them (see the header). That file is not a settings file: no codex
# argv names it, and no permissions.json is written, so nobody reads a wall into a file the
# harness ignores.
rules_out="$perms"
if [[ "$harness" == "codex" ]]; then
  rules_out="$herd_dir/${name}/rules.unenforced.json"
fi
rm -f "$rules_out"
HS_CWD="$cwd" HS_HERD="$herd_dir" HS_HARNESS="$harness" HS_NAME="$name" HS_PRIMARY="$(iso_primary_of "$cwd" 2>/dev/null || true)" \
  HS_CODEX_HOME="${codex_home:-}" HS_CODEX_AUTH="${user_auth:-}" HS_MODEL="$model" HS_PROFILE="$profile" \
  python3 -I - "$rules_out" "${#allow[@]}" "${allow[@]}" "${deny[@]}" <<'PY' || half_fail 2 "the rules file for ${name} could not be written; the agent was not started"
import json, os, shlex, sys
path, n = sys.argv[1], int(sys.argv[2])
rest = sys.argv[3:]
cwd, herd, home = os.environ["HS_CWD"], os.environ["HS_HERD"], os.environ.get("HOME", "")
name_of_worker = os.environ.get("HS_NAME", "")


def ancestors(p):
    """the STRICT ancestors of p, nearest first"""
    out = []
    p = os.path.dirname(p)
    while True:
        out.append(p)
        parent = os.path.dirname(p)
        if parent == p:
            return out
        p = parent


def abs_rule(p):
    # Claude Code's absolute path form in a rule: a double slash, then the path
    return "Edit(//" + p.lstrip("/") + ")"


# The worker obeys the instruction files of its checkout and below, none above: Claude
# Code loads CLAUDE.md, CLAUDE.local.md, .claude/CLAUDE.md and .claude/rules/ from every
# directory above the cwd, and those directories are the owner's (the herd, ~/.cache,
# ~), where any same-uid session may write. Each such file is excluded from memory AND
# denied to Edit/Write (an Edit rule covers Write), so a worker can neither read one
# as instructions nor plant one for the next worker. The review checkouts, the briefs
# and ~/.claude (auto memory, user settings) are denied to Edit/Write as well
# (ISSUE(security-audit-2026-09-12-the-cleanup-trusts-n-d474-2)).
anc = []
for base in (cwd, os.path.realpath(cwd)):
    for a in ancestors(base):
        if a not in anc:
            anc.append(a)
excludes = ["/tmp/**", "/private/tmp/**", "/var/tmp/**", "/private/var/tmp/**"]
extra_deny = []
for a in anc:
    for f in ("CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md", ".claude/rules/**"):
        excludes.append(os.path.join(a, f))
        extra_deny.append(abs_rule(os.path.join(a, f)))
# .repos/ holds the repository each worker's report is judged in: a worker that could
# rewrite its own record would choose where its claim is checked again
for d in ("review/**", "briefs/**", ".roles/**", ".repos/**", "CLAUDE.md", "CLAUDE.local.md", ".claude/**"):
    extra_deny.append(abs_rule(os.path.join(herd, d)))
if home:
    extra_deny.append(abs_rule(os.path.join(home, ".claude/**")))
    # ... and Cursor's, whose user config every Cursor session inherits and where an
    # "always allow" would be persisted (ISSUE(security-audit-2026-09-12-cursor-s-project-rul-e6f4-3))
    extra_deny.append(abs_rule(os.path.join(home, ".cursor/**")))
UNENFORCED_NOTE = (
    "These lists are not enforced. They are the allow and deny rules a claude worker of "
    "this profile would be held to; the codex harness has no per-command rule of any kind, "
    "so nothing here is applied. The wall is the sandbox (workspace-write) and the approval "
    "policy (on-request). They are written down so what the worker was meant to be held to "
    "is on the record -- not so anyone can point at a file and call it a wall."
)
try:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except OSError as e:
    print("herd-spawn: could not create the rules file exclusively at " + path + ": " + e.strerror
          + "; the worker was not started", file=sys.stderr)
    sys.exit(2)
settings = {"permissions": {"allow": rest[:n], "deny": rest[n:] + extra_deny},
            "autoMemoryEnabled": False,
            "claudeMdExcludes": excludes}
if os.environ.get("HS_PROFILE") == "coordinator":
    # The coordinator harness (plan 2026-09-19, B): the pane's prompts go through
    # appl-hook.sh first, which blocks the mechanical ones and hands the rest over with
    # the verdict. In THIS file only, so no worker or reviewer ever carries it. The tab is
    # not handed HERD_DIR, so the command carries this spawn's own; the script is found
    # from whichever checkout the pane runs in ($CLAUDE_PROJECT_DIR, else the cwd), never
    # by the primary's absolute path. A REPORT runs the named tests, hence the long
    # timeout. No model is named here: HERD_SPAWN_MODEL alone picks the pane's.
    hook = ('HERD_DIR=' + shlex.quote(herd) + ' bash "${CLAUDE_PROJECT_DIR:-.}"'
            '/.cursor/skills/isolated-session/scripts/appl-hook.sh ')
    settings["hooks"] = {
        "UserPromptSubmit": [{"hooks": [{"type": "command", "command": hook + "UserPromptSubmit",
                                         "timeout": 3600}]}],
        "SessionStart": [{"matcher": "startup|resume|compact|clear",
                          "hooks": [{"type": "command", "command": hook + "SessionStart", "timeout": 60}]}],
    }
with os.fdopen(fd, "w", encoding="utf-8") as f:
    if os.environ.get("HS_HARNESS") == "codex":
        json.dump({"note": UNENFORCED_NOTE,
                   "allow": rest[:n], "deny": rest[n:] + extra_deny},
                  f, indent=1)
    else:
        # claudeMdExcludes: a second layer under the ancestor check for the shared
        # temporary directories, and the only layer for the owner's own directories above;
        # `settings` also carries the coordinator's hooks when HS_PROFILE is coordinator.
        json.dump(settings, f, indent=1)
    f.write("\n")


if os.environ.get("HS_HARNESS") == "codex":
    # The config home the tab is handed: one flat config.toml carrying the model, the
    # sandbox mode and the approval policy, and nothing else -- written the way the rules
    # file is (the EXACT path unlinked first, so a planted symlink goes and its target is
    # never written through, then O_EXCL mode 600). No section, no bypass spelling, and
    # nothing of the user's own config.toml or AGENTS.md, which are not loaded at all.
    codex_home = os.environ["HS_CODEX_HOME"]
    cfg = os.path.join(codex_home, "config.toml")
    lines = []
    if os.environ.get("HS_MODEL"):
        lines.append('model = "' + os.environ["HS_MODEL"] + '"')
    lines.append('sandbox_mode = "workspace-write"')
    lines.append('approval_policy = "on-request"')
    if os.path.lexists(cfg):
        os.unlink(cfg)
    fd = os.open(cfg, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    # The login is the user's and stays there: a symlink by PATH. The file is never
    # opened, so no token reaches this process, an argv, a log line or a copy on disk.
    auth = os.path.join(codex_home, "auth.json")
    if os.path.lexists(auth):
        os.unlink(auth)
    os.symlink(os.environ["HS_CODEX_AUTH"], auth)


def cursor_rule(rule):
    """Claude Code's spelling to Cursor's: `Bash(x y:*)` (the prefix and a space) is
    `Shell(x:y*)` (the command base, then its arguments); `Bash(x*)` is `Shell(x*)`;
    `Edit(//abs)` is `Write(/abs)`. Deny beats allow in both."""
    if rule.startswith("Bash(") and rule.endswith(")"):
        body = rule[5:-1]
        if body.endswith(":*"):
            first, _, args = body[:-2].partition(" ")
            if not args:
                return ["Shell(%s:*)" % first]
            if args.endswith("_"):
                # a NAME prefix (`python3 tests/test_:*` is every test file
                # under tests/): the wildcard follows the prefix with no space,
                # or `python3 tests/test_x.py` never matches and a Cursor
                # session stops at "Waiting for approval" on each test run
                # (measured 2026-09-13)
                return ["Shell(%s:%s*)" % (first, args)]
            # the boundary Claude's rule carries (the prefix, then a space): the exact
            # arguments, or the arguments followed by more -- never `tools/x.py_evil.py`
            # (ISSUE(security-audit-2026-09-12-cursor-s-project-rul-e6f4-2))
            return ["Shell(%s:%s)" % (first, args), "Shell(%s:%s *)" % (first, args)]
        first, _, args = body.partition(" ")          # `bash -*`: the base, then its arguments
        return ["Shell(%s:%s)" % (first, args) if args else "Shell(" + body + ")"]
    if rule.startswith("Edit(//") and rule.endswith(")"):
        return ["Write(/" + rule[7:-1] + ")"]
    return [rule]


def cursor_rules(rules):
    out = []
    for r in rules:
        out.extend(cursor_rule(r))
    return out


if os.environ.get("HS_HARNESS") == "cursor":
    # the same lists, in Cursor's spelling, at the one place its CLI reads them: the
    # workspace's own .cursor/cli.json (exclusive, like the file above; the path is
    # gitignored in this tree so a worker's primary stays clean). In allowlist mode a
    # write outside an allowed path waits for a person, so the worker's report
    # directory and the primary's session worktrees are allowed: the isolated-session
    # hook -- which Cursor's CLI does run, measured -- still refuses another session's
    # worktree inside that allowance.
    primary = os.environ.get("HS_PRIMARY", "")
    cursor_allow = cursor_rules(rest[:n])
    cursor_allow += ["Read(" + os.path.join(herd, name_of_worker) + "/**)",
                     "Write(" + os.path.join(herd, name_of_worker) + "/**)"]
    cursor_deny = cursor_rules(rest[n:] + extra_deny)
    if primary:
        # the session worktrees may be written (the guard still holds each to its
        # session); the primary is never granted for reading -- its keys/ holds the
        # resident agents' seeds, and the diff is read through git, not the tree
        # (ISSUE(security-audit-2026-09-12-cursor-s-project-rul-e6f4))
        cursor_allow += ["Write(" + os.path.join(primary, ".worktrees") + "/**)"]
        cursor_deny += ["Read(" + os.path.join(primary, "keys") + "/**)"]
    cli = os.path.join(cwd, ".cursor", "cli.json")
    os.makedirs(os.path.dirname(cli), exist_ok=True)
    if os.path.lexists(cli):
        os.unlink(cli)
    fd = os.open(cli, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        # the project file's schema admits `permissions` alone: `version` and
        # `approvalMode` belong to the user's own config, and their presence here made
        # cursor-agent refuse the whole file at its first real spawn (2026-09-12)
        json.dump({"permissions": {"allow": cursor_allow, "deny": cursor_deny}}, f, indent=1)
        f.write("\n")
PY
# A new tab's shell needs a moment to print its prompt, and `herdr agent start` refuses
# a pane that is not at one: called 143 ms after `tab create` it failed (2026-09-12).
# So try again, two seconds apart, for HERD_SPAWN_READY_SECS (default 30). Only a FAST
# failure is retried: an attempt that ran into herdr's own readiness timeout has
# already typed the command, and the deadline has long passed by then.
# HERD_SPAWN_AGENT_READY_SECS (below) is a different wait: after start succeeds.
# A failed start is not always a slow shell: a harness stuck on one of Claude Code's
# FIRST-RUN prompts (the renderer choice, the auto-mode setup, folder trust, "Not logged
# in") is already registered, so a retry only earns herdr's agent_name_taken (Mac B,
# 2026-09-17). After a failure that is not the slow shell, the pane is read once and matched on keywords; a match
# is NAMED from the fixed vocabulary below -- the pane's bytes never reach stderr, they
# are data another checkout may have written -- and the spawn stops without a second
# start. The tab stays open: the owner answers the prompt in it. The keywords are guesses
# at the real screens (ISSUE(first-run-prompt-texts-are-guesses)).
first_run_prompt() {
  local screen
  screen="$("$herdr" agent read "$name" --source recent-unwrapped --lines 80 2>/dev/null \
            || "$herdr" agent read "$name" 2>/dev/null || true)"
  [[ -n "$screen" ]] || return 1
  printf '%s' "$screen" | python3 -I -c '
import re, sys
text = sys.stdin.buffer.read().decode("utf-8", "replace")
# drop OSC strings (a title) whole, then CSI/other escapes, then the remaining controls
text = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?", "", text)
text = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b.", "", text)
text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", text).lower()
for word, pat in (("login", r"not logged in|please run /login"),
                  ("trust", r"\btrust\b[^\n]*\b(folder|files|workspace|directory|project)\b"),
                  ("auto-mode", r"\bauto[- ]mode\b"),
                  ("renderer", r"\brenderer\b")):
    if re.search(pat, text):
        print(word)
        sys.exit(0)
sys.exit(1)
'
}
start_err="$(mktemp "${TMPDIR:-/tmp}/herd-spawn-start.XXXXXX")"
started=no
stuck_on=""
deadline=$(( $(date +%s) + ${HERD_SPAWN_READY_SECS:-30} ))
while :; do
  if "$herdr" agent start "$name" --kind "$harness" --pane "$pane" --timeout 120000 -- \
       "${agent_args[@]}" >/dev/null 2>"$start_err"; then
    started=yes
    break
  fi
  # a pane not yet at a shell prompt never had the harness typed into it, so it cannot
  # show a first-run prompt: that is the old slow-shell case, retried without a read
  if ! grep -q 'not at an interactive shell prompt' "$start_err" 2>/dev/null \
       && stuck_on="$(first_run_prompt)"; then
    break
  fi
  stuck_on=""
  [[ $(date +%s) -lt $deadline ]] || break
  sleep 2
done
if [[ -n "$stuck_on" ]]; then
  rm -f "$start_err"
  case "$stuck_on" in
    login)     what="\"Not logged in\"; run 'claude auth login' (once per machine)" ;;
    trust)     what="the folder-trust question; answer it in the pane" ;;
    auto-mode) what="the auto-mode setup prompt; answer it in the pane" ;;
    *)         what="the renderer choice; answer it in the pane" ;;
  esac
  half_fail 1 "${name} is stuck on Claude Code's first-run prompt: ${what}. The tab is left open (pane ${pane}, tab ${tab_id}); close it afterwards and spawn ${name} again. Not retried: the agent is already registered, and it did not start"
fi
if [[ "$started" != "yes" ]]; then
  start_reason="$(tail -1 "$start_err" 2>/dev/null || true)"
  rm -f "$start_err"
  half_fail 1 "'herdr agent start' failed for ${name} (pane ${pane}, tab ${tab_id}): ${start_reason}; the agent did not start"
fi
rm -f "$start_err"
done_steps="${done_steps}, agent started in pane ${pane}"

# Start succeeding means the harness process is in the pane, not that its input
# line takes text (daily-2026-09-16 typed into a banner; shop-door-hardening-tests
# at 23:50 sat unsent). One wait for idle, then prompt with --wait until working
# or blocked so the spawn returns when the brief is taken, not when the turn ends.
agent_ready_secs="${HERD_SPAWN_AGENT_READY_SECS:-120}"
ready_ms=$(( agent_ready_secs * 1000 ))
wait_err="$(mktemp "${TMPDIR:-/tmp}/herd-spawn-wait.XXXXXX")"
if ! "$herdr" agent wait "$name" --until idle --timeout "$ready_ms" >/dev/null 2>"$wait_err"; then
  wait_reason="$(tail -1 "$wait_err" 2>/dev/null || true)"
  rm -f "$wait_err"
  half_fail 1 "'herdr agent wait' failed for ${name} (pane ${pane}, tab ${tab_id}): ${wait_reason}; the agent started but never reached its input line, and no prompt was typed"
fi
rm -f "$wait_err"

# The pair hand-over (ISSUE(pair-worktree-lock-dies-with-the-test-author-session)): a worker
# started with `--env ISOLATED_SESSION_OWNER=<key>` takes over every worktree lock of THIS
# repository (the cwd's) whose owner is that key -- the test author's -- recorded as handed
# to this worker by name; the worker's session binds its own process at its first guarded
# command (lib.sh, iso_lock_handover / iso_lock_bind). Here, after the agent is up and
# before it is told anything, so it never meets the author's lock, and a spawn that failed
# earlier hands nothing to a worker that does not exist. A spawn without the key, or with a
# key no lock carries, changes nothing. A walled worker always has a key -- the caller's, or
# its own name (THE OWNER KEY) -- so the hold on a folder that key already owns passes to it
# the same way.
pair_key=""
if [[ "$owner_key_from_caller" == "yes" ]] ||
   [[ "$wall_state" == "walled" || "$wall_state" == "inherited" ]]; then
  pair_key="$owner_key"
fi
if [[ -n "$pair_key" ]]; then
  while IFS= read -r handed; do
    [[ -n "$handed" ]] || continue
    echo "herd-spawn: the hold on $(iso_safe_text "$handed" || echo '(a worktree)') passes to ${name} (owner key $(iso_safe_text "$pair_key" || echo '?'))" >&2
  done < <(iso_lock_handover "$cwd" "$pair_key" "$name" 2>/dev/null || true)
fi

# Flags after TEXT (herdr: agent prompt <TARGET> <TEXT> [OPTIONS]). Only
# agent_prompt_stalled is retried, two seconds apart, until AGENT_READY_SECS
# from the first attempt. Any other failure (agent_blocked, timeout, ...) is not.
prompt_err="$(mktemp "${TMPDIR:-/tmp}/herd-spawn-prompt.XXXXXX")"
prompted=no
prompt_deadline=$(( $(date +%s) + agent_ready_secs ))
while :; do
  if "$herdr" agent prompt "$name" "$prompt_line" \
       --wait --until working --until blocked --timeout "$ready_ms" \
       >/dev/null 2>"$prompt_err"; then
    prompted=yes
    break
  fi
  prompt_reason="$(tail -1 "$prompt_err" 2>/dev/null)"
  if [[ "$prompt_reason" != "agent_prompt_stalled" ]]; then
    rm -f "$prompt_err"
    half_fail 1 "'herdr agent prompt' failed for ${name} (pane ${pane}, tab ${tab_id}): ${prompt_reason}; the agent had started" keep
  fi
  [[ $(date +%s) -lt $prompt_deadline ]] || break
  sleep 2
done
if [[ "$prompted" != "yes" ]]; then
  prompt_reason="$(tail -1 "$prompt_err" 2>/dev/null || true)"
  rm -f "$prompt_err"
  half_fail 1 "'herdr agent prompt' kept stalling for ${name} (pane ${pane}, tab ${tab_id}) past ${agent_ready_secs}s: ${prompt_reason}; the agent had started" keep
fi
rm -f "$prompt_err"
brief_ours=no          # the worker has been told to read it: it stays
# The honest half, said out loud where the person spawning the worker reads it: on codex
# the allow/deny lists this script computed are recorded, not applied. A file nobody opens
# would let the claude wall be assumed for a session that does not have it. The second line
# is the OTHER half of the same truth, and it was missing while the header claimed the
# opposite: no session guard runs here either, so the worktree named by --cwd is the whole
# of this session's blast radius.
if [[ "$harness" == "codex" ]]; then
  echo "codex: the allow/deny lists are not enforced on this harness; the wall is the sandbox (workspace-write) and approval (on-request)"
  echo "codex: and no session guard runs on it -- the isolated-session hook is registered for claude, cursor and grok only, and codex-cli reads neither .claude/settings.json nor .cursor/hooks.json; the worktree this worker opened in is the whole of its blast radius"
fi
# the harness and the model are on the line, so a landing's REVIEW= and its note can say
# which eyes read the diff; and whether the worker is walled, with the network said
# plainly (wall v1 leaves it open), so nobody reads "walled" as "offline"
echo "worker=${name} pane=${pane} tab=${tab_id} report=${report} harness=${harness} model=${model:-default} wall=${wall_state} egress=open"
