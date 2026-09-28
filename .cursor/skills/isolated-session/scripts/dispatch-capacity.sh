#!/usr/bin/env bash
# Set this desk's Dispatch stance. A desk is `open` or `full`, nothing finer.
#
#   dispatch-capacity.sh open|full [reason]
#
# Writes ~/.muretai/dispatch/capacity (stance=, since=<iso>, reason=). The App's
# loopback writes the same file; Beatless sets it to full when a local worker
# ends on a provider-limit signature. DISPATCH_DIR relocates the directory
# (tests); DISPATCH_CAPACITY names the file itself (matches dispatch-take.sh
# --capacity-file).
set -euo pipefail

usage() {
  echo "usage: dispatch-capacity.sh open|full [reason]" >&2
  exit 2
}

stance="${1:-}"
case "$stance" in
  open|full) ;;
  *) usage ;;
esac
shift
reason="$*"

if [[ -n "${DISPATCH_CAPACITY:-}" ]]; then
  path="$DISPATCH_CAPACITY"
else
  dir="${DISPATCH_DIR:-${HOME:?}/.muretai/dispatch}"
  path="${dir}/capacity"
fi
dir="$(dirname "$path")"
mkdir -p "$dir"
since="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
# O_EXCL after unlink so a planted symlink is not followed (same write as herd-spawn).
python3 - "$path" "$stance" "$since" "$reason" <<'PY'
import os, sys
path, stance, since, reason = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
if os.path.lexists(path):
    os.unlink(path)
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    f.write("stance=" + stance + "\n")
    f.write("since=" + since + "\n")
    f.write("reason=" + reason.replace("\n", " ") + "\n")
PY
echo "stance=${stance} since=${since} file=${path}"
