#!/usr/bin/env bash
# Take, renew or release this repository's landing lease.
#
#   landing-lease.sh take    --as <agent> --repo <name>
#   landing-lease.sh renew   --as <agent> --repo <name> --epoch <n>
#   landing-lease.sh release --as <agent> --repo <name> --epoch <n>
#
# ONE process: bash execs landing-lease.py, which makes one signed HTTPS POST to the
# lease service configured for this machine (see landing-lease.py for where the node,
# the lease identity and the endpoint come from). Nothing here forks.
# Exit 0 held / renewed / released; 2 a client-side configuration error (nothing was
# sent); 3 the lease service is unreachable; 4 held by another (prints held-by= and
# until=); 5 any other refusal, its reason printed verbatim.
set -euo pipefail
here="${BASH_SOURCE[0]%/*}"
[[ "$here" != "${BASH_SOURCE[0]}" ]] || here="."
# -I: no user site, no PYTHON* variables, no cwd on sys.path -- a branch's test run cannot
# plant a module this process imports (landing-lease.py adds its own directory itself)
exec python3 -I "$here/landing-lease.py" "$@"
