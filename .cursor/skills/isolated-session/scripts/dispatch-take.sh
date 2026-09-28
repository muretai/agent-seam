#!/usr/bin/env bash
# Take an accepted Dispatch ticket on this desk and spawn a worker.
#
#   dispatch-take.sh --as <agent> --context <contextId> [--capacity-file <path>]
#                    [--primary <repo checkout>] [--room <did>]
#
# Reads the accepted coord thread from the node (operator_cli JSON: the node's own
# <node>/operator_cli.py, named by `node=` in $DISPATCH_DIR/node), checks the
# thread is accepted by this DID (or, when this desk's own `coord accept` is held
# in the action quarantine and a line of the standing accept policy
# $DISPATCH_DIR/accept -- `did=<did> repo=<name> kind=sketch|land`, mode 0600 --
# matches the verified propose exactly, releases it with the same
# `quarantine approve <id>` a person runs; stdout says ACCEPT=policy or
# ACCEPT=person), checks the local stance is open, checks the
# Room /mem carries no taken-by line for that contextId, writes the /remember
# line, and spawns a worker through herd-spawn.sh (worker profile) IN the ticket's
# worktree of the resolved repo, which it opens first with ensure-worktree.sh under
# the owner key `dispatch:<worker>` and hands to the worker. Ticket fields reach the brief as fenced DATA through --var;
# they are never a shell argument to anything else. This script never calls
# `herdr agent prompt`.
#
# Exit 0 spawned; 2 not accepted / not mine / missing key / unknown repo;
# 3 herdr down (prints the by-hand command); 4 stance full or already taken
# (prints who).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/lib.sh"

usage() {
  echo "usage: dispatch-take.sh --as <agent> --context <contextId> [--capacity-file PATH] [--primary DIR] [--room DID]" >&2
  exit 2
}

as_name=""
context=""
capacity_file=""
primary=""
room=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --as) [[ $# -ge 2 ]] || usage; as_name="$2"; shift 2 ;;
    --context) [[ $# -ge 2 ]] || usage; context="$2"; shift 2 ;;
    --capacity-file) [[ $# -ge 2 ]] || usage; capacity_file="$2"; shift 2 ;;
    --primary) [[ $# -ge 2 ]] || usage; primary="$2"; shift 2 ;;
    --room) [[ $# -ge 2 ]] || usage; room="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "dispatch-take: unknown argument: $1" >&2; usage ;;
  esac
done
[[ -n "$as_name" && -n "$context" ]] || usage

skill_repo="$(iso_primary_of "$here")" || {
  echo "dispatch-take: this script is not inside a git checkout" >&2
  exit 2
}

export DISPATCH_AS="$as_name"
export DISPATCH_CONTEXT="$context"
export DISPATCH_CAPACITY_FILE="$capacity_file"
export DISPATCH_PRIMARY="${primary}"
export DISPATCH_ROOM="$room"
export DISPATCH_HERE="$here"
export DISPATCH_SKILL_REPO="$skill_repo"

python3 - <<'PY'
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

as_name = os.environ["DISPATCH_AS"]
context = os.environ["DISPATCH_CONTEXT"]
capacity_file = os.environ.get("DISPATCH_CAPACITY_FILE") or ""
primary_arg = os.environ.get("DISPATCH_PRIMARY") or ""
room_arg = os.environ.get("DISPATCH_ROOM") or ""
here = Path(os.environ["DISPATCH_HERE"])
skill_repo = Path(os.environ["DISPATCH_SKILL_REPO"])
spawn_sh = here / "herd-spawn.sh"
brief_tpl = here.parent / "briefs" / "dispatch-ticket.md"
py = sys.executable


def die(code: int, msg: str) -> None:
    sys.stderr.write("dispatch-take: " + msg.rstrip() + "\n")
    sys.exit(code)


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


if capacity_file:
    cap_path = Path(capacity_file)
    dispatch_dir = cap_path.parent
else:
    dispatch_dir = Path(os.environ.get("DISPATCH_DIR")
                        or (Path.home() / ".muretai" / "dispatch"))
    cap_path = dispatch_dir / "capacity"


# -- the node, and --as on a missing key refuses (never mint) --------------------
# The same rules as the landing lease (landing-lease.py): operator_cli is
# <node>/operator_cli.py (or DISPATCH_CLI) run with MURETAI_STATE_DIR=<node>, the key
# must be in <node>/keys, and a missing or untrusted node line refuses. Never this
# checkout's operator_cli, never the cwd's.
import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location("_landing_lease", str(here / "landing-lease.py"))
lease_lib = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lease_lib)
try:
    node = lease_lib.resolve_node(dispatch_dir)
    lease_lib.require_identity(node, as_name)
except lease_lib.Refusal as _r:
    die(_r.code, _r.msg)


# -- capacity: open or full, never a remaining-% --------------------------------

stance, cap_reason = "open", ""
if cap_path.is_file() and not cap_path.is_symlink():
    fields = {}
    for line in cap_path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, _, v = line.partition("=")
            fields[k.strip()] = v
    stance = (fields.get("stance") or "open").strip().lower()
    cap_reason = (fields.get("reason") or "").strip()
if stance == "full":
    who = cap_reason or "stance=full"
    sys.stdout.write("full %s\n" % who)
    die(4, "stance is full (%s)" % who)


# -- operator_cli JSON (stdout is one object; banner is on stderr) ---------------
def op(*args: str, timeout: float = 30.0) -> subprocess.CompletedProcess:
    return lease_lib.run_cli(node, as_name, *args, timeout=timeout)


def op_json(*args: str, timeout: float = 30.0) -> dict:
    r = op(*args, timeout=timeout)
    if r.returncode != 0:
        die(2, "operator_cli %s failed (%s): %s"
            % (" ".join(args[:3]), r.returncode, (r.stderr or r.stdout).strip()[-400:]))
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    if not lines:
        die(2, "operator_cli %s printed no JSON" % " ".join(args[:3]))
    try:
        return json.loads(lines[-1])
    except json.JSONDecodeError:
        die(2, "operator_cli %s was not JSON: %s" % (" ".join(args[:3]), r.stdout[-200:]))


inbox = op_json("inbox", "--json")
me = inbox.get("did") or ""
if not me:
    die(2, "inbox --json did not name this DID")

rows = inbox.get("messages") or []


def latest_id() -> int:
    return int(op_json("inbox", "--json").get("latest_id") or 0)


def wait_in(after: int, timeout: float = 12.0) -> list:
    r = op("wait", "--after", str(after), "--timeout", str(timeout), "--json",
           timeout=timeout + 5)
    if r.returncode != 0:
        return []
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    if not lines:
        return []
    try:
        d = json.loads(lines[-1])
    except json.JSONDecodeError:
        return []
    return list(d.get("messages") or [])


# Room: --room, else a group overlay on any inbox row, else dispatch/room.
# Consulted BEFORE "is this mine" so a third desk that can see /mem exits 4
# (already taken) instead of 2 (not mine). The 1:1 ticket is not on Carol's
# inbox; the board record is.
def room_did() -> str:
    if room_arg:
        return room_arg
    for m in rows:
        g = m.get("group") or {}
        if isinstance(g, dict):
            rid = g.get("room_id") or g.get("host")
            if isinstance(rid, str) and rid.startswith("did:"):
                return rid
    room_file = dispatch_dir / "room"
    if room_file.is_file() and not room_file.is_symlink():
        for line in room_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("did="):
                return line.split("=", 1)[1].strip()
    return ""


def mem_text(room_id: str) -> str:
    after = latest_id()
    r = op("dm", room_id, "/mem")
    if r.returncode != 0:
        die(2, "could not send /mem to the Room: %s" % (r.stderr or r.stdout)[-300:])
    deadline = time.time() + 12
    chunks: list[str] = []
    while time.time() < deadline:
        msgs = wait_in(after, timeout=min(4.0, max(1.0, deadline - time.time())))
        for m in msgs:
            if m.get("peer_did") == room_id and m.get("direction") == "in":
                t = m.get("text") or ""
                if "MEMORY" in t or "taken-by=" in t or "(no entries" in t:
                    chunks.append(t)
        if chunks:
            return "\n".join(chunks)
        after = latest_id()
    die(2, "no /mem reply from the Room within 12s")


def taken_who(doc: str) -> str:
    for line in doc.splitlines():
        if context in line and "taken-by=" in line:
            m = re.search(r"taken-by=(\S+)", line)
            return m.group(1) if m else line.strip()
    return ""


room = room_did()
if room:
    taken = taken_who(mem_text(room))
    if taken:
        sys.stdout.write("taken-by=%s\n" % taken)
        die(4, "already taken by %s" % taken)


thread = [m for m in rows if m.get("context_id") == context]
if not thread:
    die(2, "no coord thread %s in this agent's inbox (not mine)" % context)

propose = None
accept_out = False
for m in thread:
    coord = m.get("coord") or {}
    if not isinstance(coord, dict):
        continue
    if coord.get("type") == "propose" and propose is None:
        propose = m
    if coord.get("type") == "accept" and m.get("direction") == "out":
        accept_out = True

if propose is None:
    die(2, "thread %s has no propose (not a Dispatch ticket)" % context)
peer = propose.get("peer_did") or ""
if propose.get("direction") != "in":
    die(2, "thread %s was not proposed TO this DID (not mine)" % context)


# -- ticket fields ride in the existing coord payload text ----------------------
# `kind` (sketch|land) is one more payload key next to `repo`; only the standing
# accept policy reads it, and a ticket without one always goes to a person.
def parse_ticket(text: str) -> dict:
    out = {"title": "", "task": "", "repo": "", "branchHint": "", "kind": ""}
    raw = (text or "").strip()
    if not raw:
        return out
    if raw.startswith("{"):
        try:
            d = json.loads(raw)
        except json.JSONDecodeError:
            d = None
        if isinstance(d, dict):
            for k in out:
                v = d.get(k)
                if isinstance(v, str):
                    out[k] = v
            return out
    for line in raw.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
        elif "=" in line:
            k, _, v = line.partition("=")
        else:
            continue
        k = k.strip()
        if k in out:
            out[k] = v.strip()
    return out


ticket = parse_ticket(propose.get("text") or "")
repo_name = ticket.get("repo") or ""


def looks_like_path(name: str) -> bool:
    if not name:
        return False
    if "/" in name or name.startswith(".") or name.startswith("~"):
        return True
    if re.fullmatch(r"[0-9a-fA-F]{40}", name):
        return True
    return False


# -- the standing accept policy (plan P5) ----------------------------------------
# Core never holds a teammate's propose; what a person releases today is THIS
# desk's own outbound `coord accept`, held in the action quarantine. The policy's
# one act is the same `quarantine approve <id>` a person types, and only for a
# verified propose whose wire sender, repo and kind match one grant line exactly.
# It never sends, introduces, trusts, or writes to the Room.
GRANT_KINDS = ("sketch", "land")


def accept_grants(ddir: Path) -> list[tuple[str, str, str]]:
    """(did, repo, kind) lines from <dispatch dir>/accept. A missing file is no
    grants. A symlink, a file owned by another uid, or one any group/other bit is
    set on is ignored WHOLE with one stderr line (a grant file others can write
    is a grant file others author). A malformed line is skipped with one stderr
    line naming the file and line number -- never widened into a wildcard."""
    path = ddir / "accept"
    try:
        stt = os.lstat(path)
    except FileNotFoundError:
        return []
    except OSError as e:
        sys.stderr.write("dispatch-take: ignoring %s: %s\n" % (path, e))
        return []
    import stat as _stat
    why = ""
    if _stat.S_ISLNK(stt.st_mode):
        why = "it is a symlink"
    elif not _stat.S_ISREG(stt.st_mode):
        why = "it is not a regular file"
    elif stt.st_uid != os.getuid():
        why = "it is owned by uid %d, not this user" % stt.st_uid
    elif stt.st_mode & 0o077:
        why = "mode %04o is wider than 0600" % (stt.st_mode & 0o777)
    if why:
        sys.stderr.write("dispatch-take: ignoring the accept policy %s: %s\n" % (path, why))
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        sys.stderr.write("dispatch-take: ignoring %s: %s\n" % (path, e))
        return []
    grants: list[tuple[str, str, str]] = []
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        fields: dict = {}
        bad = "*" in s
        for tok in s.split():
            k, eq, v = tok.partition("=")
            if not eq or k not in ("did", "repo", "kind") or k in fields or not v:
                bad = True
                break
            fields[k] = v
        if not bad and len(fields) == 3:
            did, repo, kind = fields["did"], fields["repo"], fields["kind"]
            if did.startswith("did:") and kind in GRANT_KINDS and not looks_like_path(repo):
                grants.append((did, repo, kind))
                continue
        sys.stderr.write("dispatch-take: %s line %d is not `did=<did> repo=<name> "
                         "kind=sketch|land`; skipped\n" % (path, n))
    return grants


def held_accept_for_thread(peer_did: str) -> str:
    """The id of the held CLI-surface `coord <peer> accept ... --thread <context>`,
    or "". MCP-surface holds and every other action stay with a person."""
    r = op("quarantine", "list", "--json")
    if r.returncode != 0:
        return ""
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    if not lines:
        return ""
    try:
        doc = json.loads(lines[-1])
    except json.JSONDecodeError:
        return ""
    held = doc.get("held") if isinstance(doc, dict) else None
    if not isinstance(held, list):
        return ""
    for h in held:
        if not isinstance(h, dict):
            continue
        if h.get("surface") != "cli" or h.get("action") != "coord accept":
            continue
        argv = (h.get("detail") or {}).get("argv") or []
        if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
            continue
        names_peer = any(argv[i] == "coord" and argv[i + 1] == peer_did
                         and argv[i + 2] == "accept" for i in range(len(argv) - 2))
        on_thread = any(argv[i] == "--thread" and argv[i + 1] == context
                        for i in range(len(argv) - 1)) or ("--thread=" + context) in argv
        hid = h.get("id")
        if names_peer and on_thread and isinstance(hid, str) and hid:
            return hid
    return ""


def policy_accept() -> bool:
    """Release the held accept under a matching grant. True only when the
    approve itself succeeded."""
    grants = accept_grants(dispatch_dir)
    if propose.get("verified") is not True:
        return False
    kind = ticket.get("kind") or ""
    if kind not in GRANT_KINDS or not repo_name or looks_like_path(repo_name):
        return False
    if (peer, repo_name, kind) not in grants:
        return False
    hid = held_accept_for_thread(peer)
    if not hid:
        return False
    r = op("quarantine", "approve", hid, "--json")
    if r.returncode != 0:
        sys.stderr.write("dispatch-take: quarantine approve %s failed (%s); a person accepts\n"
                         % (hid, r.returncode))
        return False
    sys.stdout.write("ACCEPT=policy %s %s %s\n" % (peer, repo_name, kind))
    sys.stdout.flush()
    return True


def accepted_out() -> bool:
    for m in op_json("inbox", "--json").get("messages") or []:
        coord = m.get("coord") or {}
        if (m.get("context_id") == context and isinstance(coord, dict)
                and coord.get("type") == "accept" and m.get("direction") == "out"):
            return True
    return False


if not accept_out and policy_accept():
    accept_out = accepted_out()
    if not accept_out:
        die(2, "thread %s: the held accept was released but no outbound accept "
            "is on the thread yet" % context)
else:
    sys.stdout.write("ACCEPT=person\n")
    sys.stdout.flush()
if not accept_out:
    die(2, "thread %s is not accepted by this DID" % context)

st = op_json("coord-state", peer, "--thread", context, "--json")
status = (st.get("status") or "").lower()
if status not in ("agreed", "confirmed", "delivered", "completed"):
    die(2, "thread %s status is %r, not accepted" % (context, st.get("status")))


if looks_like_path(repo_name):
    die(2, "repo is a name the receiver resolves locally, never a path or a git sha: %r"
        % repo_name)

repos_path = dispatch_dir / "repos"
resolved = ""
if repos_path.is_file() and not repos_path.is_symlink() and repo_name:
    for line in repos_path.read_text(encoding="utf-8").splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        n, _, pth = line.partition("=")
        if n.strip() == repo_name:
            resolved = os.path.expanduser(pth.strip())
            break
if not resolved and primary_arg:
    resolved = os.path.abspath(os.path.expanduser(primary_arg))
if not resolved:
    die(2, "unknown repo %r: add %s=<path> to %s (or pass --primary)"
        % (repo_name or "(empty)", repo_name or "NAME", repos_path))
if not os.path.isdir(resolved):
    die(2, "resolved repo path is not a directory: %s" % resolved)

if not room:
    die(2, "no Room to consult: pass --room <did> or set did= in %s/room"
        % dispatch_dir)


# -- the ticket's worktree, opened HERE, before any spawn -------------------------
# The worker is spawned IN its worktree, never on the primary: herd-spawn binds a
# walled worker's landing gate to the branch its cwd has checked out at spawn, so a
# worker spawned on the primary (gate=none) could never land through the launcher
# (ISSUE(dispatch-take-spawns-on-the-primary-so-a-ticket-worker-cannot-land-through-the-gate)).
# ensure-worktree.sh derives the branch from the ticket title (feat/<iso_task_slug>),
# exactly as the worker running it would have. It runs under ONE owner key per ticket,
# derived from the contextId and never a pid, so a re-take after a stopped one (herdr
# down) finds its own lock `mine` and resumes the same worktree; the spawn hands the key
# to the worker (--env), and herd-spawn's pair hand-over passes the hold to it by name.
# Opened after every refusal that is not herdr's (not mine, taken, unknown repo), so a
# refused take opens nothing.
worker = "dt-" + re.sub(r"[^a-z0-9]", "", context.lower())[:20]
if not re.match(r"^[a-z]", worker):
    worker = "d" + worker[1:]
owner_key = "dispatch:" + worker
title = ticket.get("title") or context


def open_worktree() -> tuple[str, str]:
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("ISOLATED_SESSION_") and k != "HERD_WORKER"}
    env["ISOLATED_SESSION_OWNER"] = owner_key
    r = subprocess.run(["bash", str(here / "ensure-worktree.sh"), title], cwd=resolved,
                       env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL)
    if r.returncode != 0:
        die(2, "could not open the ticket's worktree in %s (ensure-worktree exit %s): %s"
            % (resolved, r.returncode, (r.stderr or r.stdout).strip()[-400:]))
    got = {}
    for line in r.stdout.splitlines():
        k, eq, v = line.partition("=")
        if eq and k in ("WORKTREE", "BRANCH") and k not in got:
            got[k] = v.strip()
    if not got.get("WORKTREE") or not got.get("BRANCH") or not os.path.isdir(got["WORKTREE"]):
        die(2, "ensure-worktree named no usable WORKTREE/BRANCH: %s" % r.stdout.strip()[-300:])
    return got["WORKTREE"], got["BRANCH"]


worktree, branch = open_worktree()


# -- herdr preflight (exit 3, print the by-hand command, do not take) ------------
brief_rel = ".cursor/skills/isolated-session/briefs/dispatch-ticket.md"
vars_kv = [
    ("TITLE", title),
    ("TASK", ticket.get("task") or ""),
    ("REPO", repo_name),
    ("BRANCH_HINT", ticket.get("branchHint") or ""),
    ("CONTEXT", context),
    ("AS", as_name),
    ("DID", me),
    ("ROOM", room),
    ("PEER", peer),
    ("WORKTREE", worktree),
    ("BRANCH", branch),
    ("REPO_PRIMARY", resolved),
]


def spawn_argv() -> list[str]:
    cmd = ["bash", str(spawn_sh), worker, str(brief_tpl),
           "--cwd", worktree, "--profile", "worker",
           "--env", "ISOLATED_SESSION_OWNER=" + owner_key]
    for k, v in vars_kv:
        cmd.extend(["--var", "%s=%s" % (k, v)])
    return cmd


def by_hand() -> str:
    cmd = ["bash", ".cursor/skills/isolated-session/scripts/herd-spawn.sh",
           worker, brief_rel, "--cwd", worktree, "--profile", "worker",
           "--env", "ISOLATED_SESSION_OWNER=" + owner_key]
    for k, v in vars_kv:
        cmd.extend(["--var", "%s=%s" % (k, v)])
    return " ".join(shlex_quote(p) for p in cmd)


def shlex_quote(s: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_./:=+-]+", s):
        return s
    return "'" + s.replace("'", "'\"'\"'") + "'"


def herdr_ok() -> bool:
    named = os.environ.get("HERD_SPAWN_BIN") or ""
    if named:
        return os.path.isfile(named) and os.access(named, os.X_OK) and \
            subprocess.run([named, "status"], capture_output=True).returncode == 0
    herdr = shutil.which("herdr")
    if not herdr:
        return False
    return subprocess.run([herdr, "status"], capture_output=True).returncode == 0


hand = by_hand()
if not herdr_ok():
    sys.stdout.write("needed -- run: %s\n" % hand)
    die(3, "herdr is not running; needed -- run: %s" % hand)


# -- /remember once, then spawn -------------------------------------------------
# title is the contextId so a third desk's /mem can match it; type stays `note`
# (room mem has no `task` type). Body is the taken-by line the board reads.
remember = "/remember note [task] %s | taken-by=%s lane=working at=%s" % (
    context, me, iso_now())
after = latest_id()
r = op("dm", room, remember)
if r.returncode != 0:
    die(2, "could not /remember the take: %s" % (r.stderr or r.stdout)[-300:])
# wait for the room to accept the write so a second take sees it
deadline = time.time() + 12
acked = False
while time.time() < deadline:
    msgs = wait_in(after, timeout=min(4.0, max(1.0, deadline - time.time())))
    for m in msgs:
        t = m.get("text") or ""
        if m.get("peer_did") == room and "remembered" in t.lower():
            acked = True
            break
    if acked:
        break
    after = latest_id()
if not acked:
    die(2, "Room did not ack /remember within 12s")

spawn = subprocess.run(spawn_argv(), capture_output=True, text=True)
sys.stdout.write(spawn.stdout)
sys.stderr.write(spawn.stderr)
if spawn.returncode == 3:
    sys.stdout.write("needed -- run: %s\n" % hand)
    die(3, "herdr is not running; needed -- run: %s" % hand)
if spawn.returncode != 0:
    die(2, "herd-spawn failed (%s): %s" % (spawn.returncode, (spawn.stderr or "").strip()[-300:]))
sys.exit(0)
PY
