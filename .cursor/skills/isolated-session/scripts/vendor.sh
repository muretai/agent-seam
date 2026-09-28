#!/usr/bin/env bash
# Carry this skill into another repository, pinned -- or prove a copy is still its pin.
#
#   vendor.sh pull    copy SKILL.md, scripts/ and tests/test_isolated_session.py
#                     from the home (${MURETAI_CORE:-$HOME/muretai-trunk}) into
#                     THIS repository and write VENDOR.json with the home commit
#                     and every digest. The contract test is taken from
#                     tests/test_isolated_session.py and written at the same
#                     relative path (creating tests/ in the consumer). A stale
#                     root copy in the consumer is removed.
#   vendor.sh check   hold the copies to VENDOR.json's digests; needs no home checkout
#
# What is copied is the explicit FILES list below -- the reviewed contract. The CLOSURE
# is its guard: every sibling a listed script reaches (`$here/<name>`, a `source` of
# `$(dirname ...)/<name>`, Python's `HERE / "<name>"`), transitively, must be listed too.
# `pull` refuses a home whose closure the list does not cover, and `check` refuses a copy
# whose closure VENDOR.json does not cover. The bug this exists for: finish-worktree.sh
# runs landing-lease.sh / landing-lease.py and names dispatch-init.sh, none of which was
# listed, so every vendored landing failed with "can't open file .../landing-lease.py".
#
# `pull` validates everything before it writes anything: a FILES entry must be a plain
# relative path under the skill (or the contract test), and a source must be a regular
# file, never a symlink -- a symlink in the home would copy whatever it points at.
#
# The home is the one repository without a VENDOR.json. It never pulls into itself.
# Nothing here writes into the home, and nothing in the home writes here.
set -euo pipefail
# `pull` overwrites this very file while bash is still reading it (bash reads a script
# as it goes), which ended the first pull into muretai-site with a syntax error after
# the copy loop (2026-09-12). So the script runs from a temporary copy of itself and
# remembers where it came from.
if [[ -z "${VENDOR_SH_HERE:-}" ]]; then
  VENDOR_SH_HERE="$(cd "$(dirname "$0")" && pwd)"
  _vendor_copy="$(mktemp "${TMPDIR:-/tmp}/vendor-sh.XXXXXX")"
  cp "$0" "$_vendor_copy"
  VENDOR_SH_HERE="$VENDOR_SH_HERE" exec bash "$_vendor_copy" "$@"
fi
trap 'rm -f "$0"' EXIT
here="$VENDOR_SH_HERE"
skill_dir="$(cd "$here/.." && pwd)"
repo="$(cd "$skill_dir/../../.." && pwd)"
home_repo="${MURETAI_CORE:-$HOME/muretai-trunk}"
mode="${1:-}"
[[ "$mode" == "pull" || "$mode" == "check" ]] || { echo "usage: vendor.sh pull|check" >&2; exit 2; }

VENDOR_MODE="$mode" VENDOR_REPO="$repo" VENDOR_HOME="$home_repo" python3 - <<'PY'
import hashlib, json, os, pathlib, posixpath, re, subprocess, sys, datetime

mode = os.environ["VENDOR_MODE"]
repo = pathlib.Path(os.environ["VENDOR_REPO"]).resolve()
home = pathlib.Path(os.path.expanduser(os.environ["VENDOR_HOME"]))
skill = ".cursor/skills/isolated-session"
FILES = [
    f"{skill}/SKILL.md",
    f"{skill}/scripts/lib.sh",
    f"{skill}/scripts/ensure-worktree.sh",
    f"{skill}/scripts/assert-head.sh",
    f"{skill}/scripts/claim-worktree.sh",
    f"{skill}/scripts/finish-worktree.sh",
    f"{skill}/scripts/landing-lease.sh",
    f"{skill}/scripts/landing-lease.py",
    f"{skill}/scripts/lease_core.py",
    f"{skill}/scripts/dispatch-init.sh",
    f"{skill}/scripts/stale.sh",
    f"{skill}/scripts/session-guard.sh",
    f"{skill}/scripts/vendor.sh",
    f"{skill}/scripts/herd-spawn.sh",
    # the landing the spawner copies beside the wall (herd-spawn.sh reaches it as `$here/land.sh`)
    f"{skill}/scripts/land.sh",
    # the worker wall's platform plug and its one profile template (herd-spawn.sh reaches
    # them as `$here/walls/<os>.sh`; a Linux plug joins this list when it exists)
    f"{skill}/scripts/walls/darwin.sh",
    f"{skill}/scripts/walls/darwin.sb.template",
    f"{skill}/scripts/dispatch-take.sh",
    f"{skill}/scripts/dispatch-capacity.sh",
    f"{skill}/scripts/herd-watch.sh",
    f"{skill}/briefs/worker.md",
    f"{skill}/briefs/dispatch-ticket.md",
]

CONTRACT = "tests/test_isolated_session.py"
pin = repo / skill / "VENDOR.json"

def sha(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()

def fail(head, lines, tail=None):
    print("vendor: " + head, file=sys.stderr)
    for b in lines:
        print("   " + b, file=sys.stderr)
    if tail:
        print(tail, file=sys.stderr)
    sys.exit(1)

def not_plain(rel: str):
    """Why `rel` may not be vendored, or None: a plain relative path under the skill."""
    if rel.startswith("/") or os.path.isabs(rel):
        return "an absolute path"
    if any(part in ("", ".", "..") for part in rel.split("/")):
        return "not a plain relative path (`..`, `.` or an empty segment)"
    if rel != CONTRACT and not rel.startswith(skill + "/"):
        return "outside " + skill
    return None

# --- the closure -----------------------------------------------------------------------
# The forms a skill script uses to reach a sibling: `$here/<name>` (also `"$here")/<name>`,
# the spelling a refusal prints through printf %q), `source`/`.` of `$(dirname ...)/<name>`,
# and Python's `HERE / "<name>"`. Each is resolved against the script's own directory; a
# reference that lands outside the skill is never a vendoring requirement (and is never
# followed), and one naming a directory is not a file to carry.
_NAME = r"((?:\.\./)*[A-Za-z0-9_][A-Za-z0-9_./-]*)"
REF_PATTERNS = [
    re.compile(r"\$\{?here\}?[\"')]*/" + _NAME),
    re.compile(r"(?:^|[\s;&|(])(?:source|\.)\s+[\"']?\$\(\s*dirname\s+[^)]*\)[\"']?/" + _NAME),
    re.compile(r"\bHERE\s*/\s*[\"']" + _NAME + r"[\"']"),
]

def refs_of(root: pathlib.Path, rel: str) -> set:
    """Skill-relative paths `rel` (skill-relative) references, inside the skill."""
    path = root / rel
    if path.suffix not in (".sh", ".py") or path.is_symlink() or not path.is_file():
        return set()
    text = path.read_text(errors="replace")
    out = set()
    for pat in REF_PATTERNS:
        for m in pat.finditer(text):
            name = m.group(1).rstrip("./")
            if not name:
                continue
            target = posixpath.normpath(posixpath.join(posixpath.dirname(rel), name))
            if target == ".." or target.startswith("../") or target == rel:
                continue
            if (root / target).is_dir():
                continue
            out.add(target)
    return out

def closure(root: pathlib.Path, start) -> dict:
    """Every skill-relative path reachable from `start`, with the files that reference it."""
    need, todo, done = {}, sorted(start), set()
    while todo:
        cur = todo.pop()
        if cur in done:
            continue
        done.add(cur)
        for ref in refs_of(root, cur):
            need.setdefault(ref, set()).add(cur)
            if ref not in done:
                todo.append(ref)
    return need

def in_skill(rels) -> set:
    return {r[len(skill) + 1:] for r in rels if r.startswith(skill + "/")}

def uncovered(root: pathlib.Path, listed) -> list:
    """The closure of `listed` that `listed` does not cover, as refusal lines."""
    have = in_skill(listed)
    need = closure(root, have)
    return ["%s/%s: referenced by %s but not listed" % (skill, n, ", ".join(sorted(need[n])))
            for n in sorted(set(need) - have)]

def primary_of(p: pathlib.Path) -> pathlib.Path:
    """The primary checkout behind a path -- a worktree of the home is still the home."""
    try:
        common = subprocess.run(["git", "-C", str(p), "rev-parse", "--git-common-dir"],
                                capture_output=True, text=True, check=True).stdout.strip()
    except (subprocess.CalledProcessError, OSError):
        return p.resolve()
    common_path = pathlib.Path(common) if pathlib.Path(common).is_absolute() else p / common
    return common_path.resolve().parent

is_home = home.exists() and primary_of(home) == primary_of(repo)
if mode == "check":
    if not pin.exists():
        if is_home:
            print(f"vendor: {repo} is the home of the skill; nothing to check")
            sys.exit(0)
        print(f"vendor: {pin} is missing -- this copy is unpinned; run vendor.sh pull", file=sys.stderr)
        sys.exit(1)
    data = json.loads(pin.read_text())
    bad = []
    for rel, meta in data["files"].items():
        why = not_plain(rel)
        p = repo / rel
        if why:
            bad.append(f"{rel}: {why}")
        elif p.is_symlink():
            bad.append(f"{rel}: a symlink, not the pinned file")
        elif not p.is_file():
            bad.append(f"{rel}: missing")
        elif sha(p) != meta["sha256"]:
            bad.append(f"{rel}: digest differs from the pin")
    # the reviewed list and the pin agree ...
    for rel in FILES + [CONTRACT]:
        if rel not in data["files"]:
            bad.append(f"{rel}: listed in vendor.sh FILES but not in VENDOR.json")
    # ... and the pin covers everything its own scripts reach, present or not
    bad += [b.replace("but not listed", "but not in VENDOR.json")
            for b in uncovered(repo / skill, data["files"])]
    if bad:
        fail("the copy has drifted from VENDOR.json:", bad,
             "Edit the skill in its home and pull again; never patch the copy.")
    print(f"vendor: {len(data['files'])} files match the pin ({data['from']} @ {data['commit'][:12]}, {data['date']})")
    sys.exit(0)

# pull -- every refusal below happens before the first write
if is_home:
    print("vendor: refusing to pull into the home of the skill", file=sys.stderr)
    sys.exit(1)
bad = [f"{rel}: {why}" for rel in FILES for why in [not_plain(rel)] if why]
if bad:
    fail("refusing to pull: a FILES entry is not a plain path under the skill:", bad)
if not (home / skill / "SKILL.md").exists():
    print(f"vendor: no skill at {home / skill} -- set MURETAI_CORE to the home checkout", file=sys.stderr)
    sys.exit(1)
def git(*a):
    return subprocess.run(["git", "-C", str(home)] + list(a), capture_output=True, text=True, check=True).stdout.strip()
commit = git("rev-parse", "HEAD")
dirty = git("status", "--porcelain", "--", skill, CONTRACT)
if dirty:
    print("vendor: refusing to pull uncommitted skill files from the home:", file=sys.stderr)
    print(dirty, file=sys.stderr)
    sys.exit(1)
if not (home / CONTRACT).is_file():
    print(f"vendor: no {CONTRACT} at {home} -- the contract test lives under tests/", file=sys.stderr)
    sys.exit(1)
home_real, repo_real = home.resolve(), repo
for rel in FILES + [CONTRACT]:
    src, dst = home / rel, repo / rel
    if src.is_symlink():
        bad.append(f"{rel}: a symlink in the home -- refusing to copy what it points at")
    elif not src.is_file():
        bad.append(f"{rel}: not a regular file in the home")
    elif src.resolve() != home_real / rel:
        bad.append(f"{rel}: resolves outside the home ({src.resolve()})")
    if dst.is_symlink() or (dst.exists() and not dst.is_file()):
        bad.append(f"{rel}: the consumer's copy is a symlink or not a file")
    elif os.path.realpath(str(dst.parent)) != str(repo_real / posixpath.dirname(rel)) and dst.parent.exists():
        bad.append(f"{rel}: the consumer's directory resolves elsewhere")
if bad:
    fail("refusing to pull:", bad)
bad = uncovered(home / skill, FILES)
if bad:
    fail("refusing to pull: FILES does not cover what its scripts reach:", bad,
         "Add each to FILES in the home's scripts/vendor.sh, commit, and pull again.")
files = {}
for rel in FILES + [CONTRACT]:
    src, dst = home / rel, repo / rel
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(src.read_bytes())
    dst.chmod(src.stat().st_mode & 0o777)
    files[rel] = {"sha256": sha(dst)}
stale = repo / "test_isolated_session.py"
if stale.is_file():
    stale.unlink()
pin.write_text(json.dumps({
    "_": "Written by .cursor/skills/isolated-session/scripts/vendor.sh pull; never edit the copies by "
         "hand. `vendor.sh check` holds them to these digests, and to the closure of what the "
         "scripts reference, with no home checkout present. The skill's home is the core trunk; "
         "edit it there and pull again.",
    "from": "muretai-trunk",
    "repository": "private",
    "commit": commit,
    "date": datetime.date.today().isoformat(),
    "files": files,
}, indent=2) + "\n")
print(f"vendor: pulled {len(files)} files from {home} @ {commit[:12]}")
PY
