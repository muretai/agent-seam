#!/bin/bash
# land.sh -- the launcher's landing. herd-spawn.sh copies this file into
# $HERD_DIR/walls/<name>/, which the worker cannot write.
#
# The worker may ask for a landing. It does not choose this program, the branch,
# the worktree, or the commit the tests run against. Those come from the spawn's
# run.json, written where the worker cannot write.
#
#   land.sh <run.json>                 do the landing
#   land.sh --repair <run.json> <why>  ask the worker once to fix the branch
#
# A landing that fails asks that worker once, then stops. A person lands only
# after that attempt. This program never tells anyone to run finish-worktree.sh.
#
# The branch's tests run HERE, in this process's own environment -- the launcher's,
# outside every Seatbelt profile -- exactly as an operator's landing runs them
# (ISSUE(launcher-landing-still-runs-inside-the-wall)). They used to go back through
# `plug.sh exec profile`, i.e. behind the worker's own wall, where the OS refuses a
# nested sandbox-exec: every suite that builds a wall was booked FAIL for the room. The
# pid that ran them, and whether a nested sandbox-exec worked from it, go to wall.log.
set -euo pipefail
exec python3 -I - "$@" <<'PY'
import json, os, shutil, site, subprocess, sys, time

SKILL = os.path.join(".cursor", "skills", "isolated-session", "scripts")
SANDBOX_EXEC = "/usr/bin/sandbox-exec"


def say(text):
    sys.stderr.write(text if text.endswith("\n") else text + "\n")


def runjson_of(argv):
    if len(argv) < 2 or not argv[1]:
        say("land: no spawn record")
        return ""
    return argv[1]


def wall_of(runjson):
    return os.path.dirname(os.path.realpath(runjson))


def repair(runjson, reason):
    """One attempt by the worker that owns this landing. A second failure names a person."""
    reason = " ".join(str(reason).split())[:400] or "the landing failed"
    wall = wall_of(runjson)
    marker = os.path.join(wall, "repair-tried")
    if os.path.lexists(marker):
        say("landing exception: the repair agent already tried once. A person may land this branch.")
        return 0
    try:
        cfg = json.load(open(runjson, encoding="utf-8"))
    except (OSError, ValueError):
        say("landing exception: the repair agent could not be prompted. A person may land this branch.")
        return 0
    worker = cfg.get("worker") if isinstance(cfg, dict) else ""
    if not isinstance(worker, str):
        worker = ""
    try:
        with open(os.path.join(wall, "landing-exception.json"), "w", encoding="utf-8") as fh:
            json.dump({"worker": worker, "reason": reason}, fh, indent=1)
            fh.write("\n")
        fd = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
    except OSError:
        say("landing exception: the repair agent could not be prompted. A person may land this branch.")
        return 0
    brief = ("Landing failed: %s. Fix the branch in the recorded worktree and ask for the "
             "landing again. You are the first attempt; a person lands only if you cannot."
             % reason)
    herdr = shutil.which("herdr")
    if not herdr or not worker:
        say("landing exception: the repair agent could not be prompted. A person may land this branch.")
        return 0
    try:
        r = subprocess.run([herdr, "agent", "prompt", worker, brief],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        r = None
    if r is None or r.returncode != 0:
        say("landing exception: the repair agent could not be prompted. A person may land this branch.")
    return 0


def tests_lines(wall):
    """The runner's JSON, in the same TESTS=/TESTS_RED= shape finish-worktree.sh prints."""
    try:
        data = json.load(open(os.path.join(wall, "tests-runner.json"), encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    if not isinstance(data, dict):
        return ""
    files = data.get("files") if isinstance(data.get("files"), list) else []
    counts = {}
    for row in files:
        if isinstance(row, dict):
            counts[row.get("status")] = counts.get(row.get("status"), 0) + 1
    order = ("ok", "skip", "fail", "timeout", "could-not-run")
    line = ", ".join("%d %s" % (counts[k], k) for k in order if counts.get(k))
    text = "TESTS=%s (of %d; %s)\n" % (line or "0 files", len(files), data.get("selection") or "")
    failed = " ".join(x for x in (data.get("failed") or []) if isinstance(x, str))
    unrun = " ".join(x for x in (data.get("could_not_run") or []) if isinstance(x, str))
    if failed:
        text += "TESTS_RED=%s\n" % failed
    if unrun:
        text += "TESTS_COULD_NOT_RUN=%s\n" % unrun
    # the refusal's class, as finish-worktree.sh spells it: `environment` only when every
    # suite that did not pass is one the room could not run; any ordinary red makes it `red`
    text += "TESTS_REFUSAL=%s\n" % ("environment" if unrun and not failed else "red")
    return text


def log(wall, line):
    """One line in the spawn's wall.log, appended the way run.py appends: never through a link."""
    try:
        fd = os.open(os.path.join(wall, "wall.log"),
                     os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(fd, (time.strftime("%Y-%m-%dT%H:%M:%S%z") + " " + line + "\n").encode())
        finally:
            os.close(fd)
    except OSError:
        pass


def nest_probe():
    """The requirement's probe, from THIS process: `sandbox-exec -p '(version 1)(allow
    default)' true`. "ok" outside every profile; the refusal's words inside one; "n/a"
    where there is no Seatbelt."""
    if sys.platform != "darwin" or not os.path.exists(SANDBOX_EXEC):
        return "n/a"
    try:
        r = subprocess.run([SANDBOX_EXEC, "-p", "(version 1)(allow default)", "/usr/bin/true"],
                           stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as e:
        return "refused (%s)" % type(e).__name__
    if r.returncode == 0:
        return "ok"
    said = (r.stderr.strip().splitlines() or [""])[-1][:120]
    return "refused (exit %d: %s)" % (r.returncode, said)


def tests_env(env):
    """What finish-worktree.sh's branch_tests_python gives the branch's tests: no push
    credential in reach, the user site directory walled, the operator's optional backend
    lent through MURETAI_TEST_BACKEND_PATH (never PYTHONPATH)."""
    out = dict(env)
    out.update({"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "credential.helper",
                "GIT_CONFIG_VALUE_0": "", "GIT_TERMINAL_PROMPT": "0",
                "GIT_ASKPASS": "/usr/bin/false", "GIT_SSH_COMMAND": "/usr/bin/false",
                "GH_CONFIG_DIR": "/nonexistent/iso-gh", "GH_TOKEN": "", "GITHUB_TOKEN": "",
                "GH_ENTERPRISE_TOKEN": "", "PYTHONNOUSERSITE": "1"})
    out.pop("PYTHONPATH", None)
    try:
        usersite = site.getusersitepackages() or ""
    except Exception:  # noqa: BLE001
        usersite = ""
    out["MURETAI_TEST_BACKEND_PATH"] = usersite if usersite and os.path.isdir(usersite) else ""
    return out


def fail(runjson, reason, extra=""):
    if extra:
        sys.stdout.write(extra if extra.endswith("\n") else extra + "\n")
    sys.stdout.write("MERGED=no\n")
    say("land: " + " ".join(str(reason).split()))
    repair(runjson, reason)
    return 1


def git(gitdir, *args):
    return subprocess.run(["git", "--git-dir", gitdir, *args],
                          capture_output=True, text=True)


def gitdir_of(worktree):
    """The git dir the worktree's .git names now. A symlink is not a worktree we will trust."""
    p = os.path.join(worktree, ".git")
    if os.path.islink(p):
        return ""
    if os.path.isfile(p):
        try:
            text = open(p, encoding="utf-8", errors="replace").read().strip()
        except OSError:
            return ""
        if not text.startswith("gitdir:"):
            return ""
        gd = text.split(":", 1)[1].strip()
        if not gd:
            return ""
        if not os.path.isabs(gd):
            gd = os.path.join(worktree, gd)
        return os.path.realpath(gd)
    if os.path.isdir(p):
        return os.path.realpath(p)
    return ""


def listed(common, worktree):
    r = git(common, "worktree", "list", "--porcelain")
    if r.returncode != 0:
        return False
    want = os.path.realpath(worktree)
    for line in r.stdout.splitlines():
        if line.startswith("worktree "):
            try:
                if os.path.realpath(line.split(" ", 1)[1]) == want:
                    return True
            except OSError:
                continue
    return False


def record_of(cfg):
    gate = cfg.get("gate") if isinstance(cfg.get("gate"), dict) else {}
    rec = cfg.get("record") if isinstance(cfg.get("record"), dict) else {}
    out = dict(rec)
    out.update({k: v for k, v in gate.items() if v})
    return out


SAFE_NAME = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-")

# The programs the gate runs out of its copy of BASE. Their imports are walked at BASE
# (closure() below) to find which repository modules outside tools/ the copy must carry.
GATE_ENTRIES = ("tools/ledger.py", "tools/sec_lint.py", "tools/invariants.py",
                "tools/run_tests.py", "tools/audit_scope.py", "tools/backlog_build.py",
                "tools/spec_build.py", "tools/affected_tests.py")
# The modules outside tools/ that a gate program may reach through its own sys.path
# insert (tools/ledger.py puts company/ops/ first). Where the insert points cannot be
# read statically, so the list is pinned. It must name exactly the paths outside tools/ in
# finish-worktree.sh's `gate_tools` -- tests/test_gate_closure_lists.py holds the two
# to each other (ISSUE(gate-copy-lacks-the-ledgers-import)).
GATE_CLOSURE = ("company/ops/backlog_to_core.py",)


def imported_names(path):
    """The top-level names a Python file imports absolutely, anywhere in it. A file that does
    not parse imports nothing here: the gate program that runs it will crash, and
    finish-worktree.sh calls that crash a broken gate."""
    import ast
    try:
        tree = ast.parse(open(path, "rb").read(), path)
    except (OSError, SyntaxError, ValueError):
        return set()
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
            names.add(node.module.split(".")[0])
    return names


def closure(dest):
    """The GATE_CLOSURE paths BASE's gate actually imports: a walk from GATE_ENTRIES through
    every tools/ module they import, and through each closure module already written into
    `dest` (extract() calls this until it names nothing new). A closure path nothing
    imports is not demanded, so a BASE without a ledger needs no company/ops/."""
    by_name = {os.path.splitext(os.path.basename(p))[0]: p for p in GATE_CLOSURE}

    def there(rel):
        return os.path.isfile(os.path.join(dest, *rel.split("/")))

    queue = [p for p in GATE_ENTRIES if there(p)]
    seen, needed = set(queue), []
    while queue:
        rel = queue.pop(0)
        for name in sorted(imported_names(os.path.join(dest, *rel.split("/")))):
            if name in by_name:
                nxt = by_name[name]
                if nxt not in needed:
                    needed.append(nxt)
            else:
                nxt = "tools/" + name + ".py"
            if nxt not in seen and there(nxt):
                seen.add(nxt)
                queue.append(nxt)
    return needed


def extract(common, base_sha, wall):
    """BASE's scripts and tools, from the commit the spawn recorded, into walls/<name>/base.
    The worker cannot write that directory, so it cannot swap the runner.

    Returns (dest, "") or ("", why). Read blob by blob -- `ls-tree -r -z`, then `git show`
    per entry -- the way finish-worktree.sh extracts BASE's walls/, never `git archive`:
    the archive honours `.gitattributes` export-ignore, and the real tree marks `.cursor/`
    so, which left the gate copy with tools/ and no skill at all
    (ISSUE(land-extract-honours-export-ignore)). `--worktree-attributes` is no cure, since
    it reads the worker-writable worktree. Only regular blobs (100644/100755, the exec bit
    kept) are written; a symlink, a gitlink or anything else under these paths is refused
    by name -- neither followed nor silently skipped. Each name below the prefix obeys the
    walls/ basename rule, and a name that breaks it is refused the same way."""
    dest = os.path.join(wall, "base")
    if os.path.lexists(dest):
        if os.path.islink(dest):
            return "", "the gate copy's directory is a link"
        shutil.rmtree(dest)
    os.mkdir(dest, 0o700)

    def bail(why):
        shutil.rmtree(dest, ignore_errors=True)
        return "", why

    def put(path, mode):
        """One regular blob of BASE into dest, exec bit kept; never through a link."""
        target = os.path.join(dest, *path.split("/"))
        os.makedirs(os.path.dirname(target), 0o700, exist_ok=True)
        blob = subprocess.run(["git", "--git-dir", common, "show", "%s:%s" % (base_sha, path)],
                              capture_output=True)
        if blob.returncode != 0:
            return False
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                     0o755 if mode == "100755" else 0o644)
        try:
            os.write(fd, blob.stdout)
        finally:
            os.close(fd)
        return True

    roots = (SKILL.replace(os.sep, "/"), "tools")
    tree = subprocess.run(["git", "--git-dir", common, "ls-tree", "-r", "-z", "--full-tree",
                           base_sha, "--"] + [r + "/" for r in roots], capture_output=True)
    if tree.returncode != 0 or not tree.stdout:
        return bail("BASE's runner is not in the recorded commit")
    for raw in tree.stdout.split(b"\0"):
        if not raw:
            continue
        head, _, rawpath = raw.partition(b"\t")
        path = rawpath.decode("utf-8", "replace")
        fields = head.split()
        if len(fields) != 3:
            return bail("BASE's tree lists an entry land.sh cannot read")
        mode, kind = fields[0].decode(), fields[1].decode()
        if kind != "blob" or mode not in ("100644", "100755"):
            return bail("BASE's %s is not a regular file" % path)
        root = next((r for r in roots if path.startswith(r + "/")), "")
        parts = path[len(root) + 1:].split("/") if root else []
        if not parts or any(not p or p.startswith(".") or not set(p) <= SAFE_NAME for p in parts):
            return bail("BASE's %s is not a name land.sh extracts" % path)
        if not put(path, mode):
            return bail("BASE's %s could not be read" % path)
    # ... and BASE's closure for the gate: every GATE_CLOSURE path its gate programs import,
    # by blob like the rest. Demanded and missing at BASE is refused here, by name, before a
    # test runs -- the ledger would otherwise die of ModuleNotFoundError inside finish, after
    # the tests (ISSUE(gate-copy-lacks-the-ledgers-import)). Never the worktree's copy: the
    # branch cannot supply a module BASE's gate lacks.
    done = set()
    while True:
        todo = [p for p in closure(dest) if p not in done]
        if not todo:
            break
        for path in todo:
            done.add(path)
            rec = subprocess.run(["git", "--git-dir", common, "ls-tree", "-z", "--full-tree",
                                  base_sha, "--", path], capture_output=True)
            head, _, rawpath = rec.stdout.rstrip(b"\0").partition(b"\t")
            if rec.returncode != 0 or rawpath.decode("utf-8", "replace") != path:
                return bail("BASE's gate imports %s, and the recorded commit does not carry it"
                            % path)
            fields = head.split()
            if (len(fields) != 3 or fields[1] != b"blob"
                    or fields[0].decode() not in ("100644", "100755")):
                return bail("BASE's %s is not a regular file" % path)
            if not put(path, fields[0].decode()):
                return bail("BASE's %s could not be read" % path)
    return dest, ""


def write_json(path, obj):
    tmp = path + ".tmp"
    if os.path.lexists(tmp):
        os.unlink(tmp)
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)
        fh.write("\n")
    os.replace(tmp, path)


def main(argv):
    if argv[1:2] == ["--repair"]:
        if len(argv) < 4:
            say("land: a repair needs the spawn record and a reason")
            return 1
        return repair(argv[2], argv[3])
    runjson = runjson_of(argv)
    if not runjson or os.path.islink(runjson) or not os.path.isfile(runjson):
        say("land: the spawn record is not a regular file")
        return 1
    try:
        cfg = json.load(open(runjson, encoding="utf-8"))
    except (OSError, ValueError):
        return fail(runjson, "the spawn record is not JSON")
    if not isinstance(cfg, dict):
        return fail(runjson, "the spawn record is not a record")
    rec = record_of(cfg)
    wall = wall_of(runjson)
    common = rec.get("common_dir") or ""
    gitdir = rec.get("worktree_gitdir") or ""
    worktree = rec.get("worktree") or ""
    branch = rec.get("branch") or ""
    branch_ref = rec.get("branch_ref") or ""
    base_sha = rec.get("base_sha") or ""
    base_ref = rec.get("base_ref") or "main"
    primary = rec.get("primary") or ""
    for label, value in (("common dir", common), ("worktree", worktree), ("git dir", gitdir),
                         ("branch", branch), ("base", base_sha)):
        if not isinstance(value, str) or not value:
            return fail(runjson, "the spawn record has no " + label)
    if os.path.realpath(worktree) != worktree or gitdir_of(worktree) != os.path.realpath(gitdir):
        return fail(runjson, "the worktree does not point at the git dir recorded at spawn")
    if not listed(common, worktree):
        return fail(runjson, "the worktree is not in the recorded repository")
    tip = git(common, "rev-parse", "--verify", "--quiet", branch_ref + "^{commit}").stdout.strip()
    if not tip:
        return fail(runjson, "the recorded branch has no commit")
    if git(common, "merge-base", "--is-ancestor", base_sha, tip).returncode != 0:
        return fail(runjson, "the recorded base is not an ancestor of the branch")
    dest, why = extract(common, base_sha, wall)
    if why:
        return fail(runjson, why)
    runner = os.path.join(dest, "tools", "run_tests.py") if dest else ""
    if not (dest and os.path.isfile(runner) and not os.path.islink(runner)):
        return fail(runjson, "BASE's runner is not in the recorded commit")
    env = {k: v for k, v in os.environ.items() if not k.startswith("HERD_GATE_")}
    env.pop("ISO_FINISH_TESTS_RECEIPT", None)
    env.pop("ISO_FINISH_WALLS_DIR", None)
    # Outside the wall, as the operator's landing: no plug, no profile. `--gate` keeps the
    # runner honest if this launcher was itself started behind a wall: then a suite the
    # room refused is could-not-run, never a red on the diff and never a pass.
    probe = nest_probe()
    where = ("outside every wall" if probe in ("ok", "n/a")
             else "INSIDE a wall this launcher was started in, so the room's refusals are could-not-run")
    log(wall, "land: the landing of %s runs its tests in pid=%d (parent pid=%d, the launcher), "
              "%s; nested sandbox-exec from here: %s"
        % (branch, os.getpid(), os.getppid(), where, probe))
    proc = subprocess.run(
        [sys.executable, "-I", runner, "--root", worktree, "--affected", base_sha + ".." + tip,
         "--gate", "--json", "-j", env.get("ISOLATED_SESSION_LAND_JOBS") or "4"],
        cwd=worktree, env=tests_env(env), stdin=subprocess.DEVNULL, capture_output=True, text=True,
        errors="replace")
    runner_path = os.path.join(wall, "tests-runner.json")
    with open(runner_path, "w", encoding="utf-8") as fh:
        fh.write(proc.stdout)
    write_json(os.path.join(wall, "tests.json"), {"rc": proc.returncode})
    if proc.returncode != 0:
        return fail(runjson, "the landing tests exited %d" % proc.returncode, tests_lines(wall))
    scripts = os.path.realpath(os.path.join(dest, SKILL))
    finish = os.path.join(scripts, "finish-worktree.sh")
    if not os.path.isfile(finish) or os.path.islink(finish) or not primary:
        return fail(runjson, "BASE's finish-worktree.sh is not in the recorded commit")
    fenv = dict(env)
    fenv["ISO_FINISH_GATE_DIR"] = dest
    fenv["ISO_FINISH_GATE_SELF"] = scripts
    fenv["ISO_FINISH_TESTS_RECEIPT"] = runner_path
    fenv["ISO_FINISH_WALLS_DIR"] = wall
    landed = subprocess.run(
        ["/bin/bash", finish, branch, worktree], cwd=primary, env=fenv,
        stdin=subprocess.DEVNULL, capture_output=True, text=True, errors="replace")
    sys.stdout.write(landed.stdout)
    if landed.stderr:
        sys.stderr.write(landed.stderr)
    merged, review = "no", ""
    for line in landed.stdout.splitlines():
        if line.startswith("MERGED="):
            merged = line.split("=", 1)[1].strip()
        elif line.startswith("REVIEW="):
            review = line.split("=", 1)[1].strip().split(" ", 1)[0]
    on_base = git(common, "merge-base", "--is-ancestor", tip,
                  "refs/heads/" + base_ref).returncode == 0
    receipt = {"base_sha": base_sha, "tip": tip, "review": review or "none", "merged": "yes"}
    if not on_base and landed.returncode == 0 and merged == "yes":
        # finish-worktree.sh REBASES a branch whose base moved before it fast-forwards, so the
        # commits that landed are copies of the recorded ones and the recorded tip is on no
        # base. A reviewer's receipt branch always starts at the BASE it reviewed, behind the
        # tip main already holds, so its landing always takes this path. The landing counts
        # when every recorded commit's patch is on the base now (`git cherry` lists none as
        # missing); the receipt then names the base's tip, and the recorded one as branch_tip.
        head = git(common, "rev-parse", "--verify", "--quiet",
                   "refs/heads/" + base_ref + "^{commit}").stdout.strip()
        cherry = git(common, "cherry", "refs/heads/" + base_ref, tip, base_sha)
        if head and cherry.returncode == 0 and not any(
                line.startswith("+") for line in cherry.stdout.splitlines()):
            on_base = True
            receipt.update({"tip": head, "branch_tip": tip})
    if landed.returncode != 0 or merged != "yes" or not on_base:
        return fail(runjson, "the landing did not fast-forward the recorded base")
    write_json(os.path.join(wall, "landing-receipt.json"), receipt)
    return 0


sys.exit(main(sys.argv))
PY
