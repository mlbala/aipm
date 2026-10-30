#!/bin/sh
# Install aipm (https://github.com/mlbala/aipm) as a uv tool.
#
#   sh install.sh [-y] [-t TAG]
#
#   -y      install uv without asking, if it is missing
#   -t TAG  the aipm release to install (default below)
#
# It prints what it will do first. If uv is missing, it asks before installing it with uv's
# official installer; it never pipes a download into a shell. Then it runs
#   uv tool install git+https://github.com/mlbala/aipm@TAG
set -eu

TAG="v0.2.0"
REPO="https://github.com/mlbala/aipm"
UV_INSTALLER="https://astral.sh/uv/install.sh"
YES=0

fail() { echo "install.sh: $1" >&2; exit "${2:-1}"; }

while getopts "yt:h" opt; do
  case "$opt" in
    y) YES=1 ;;
    t) TAG="$OPTARG" ;;
    *) fail "usage: sh install.sh [-y] [-t TAG]" 2 ;;
  esac
done

if ! printf '%s\n' "$TAG" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'; then
  fail "the tag must look like v1.2.3, not '$TAG'" 2
fi

UV=$(command -v uv 2>/dev/null || true)
echo "This will:"
if [ -n "$UV" ]; then
  echo "  1. use uv at $UV"
else
  echo "  1. install uv with its official installer ($UV_INSTALLER), after asking"
fi
echo "  2. run: uv tool install git+$REPO@$TAG"

if [ -z "$UV" ]; then
  if [ "$YES" -ne 1 ]; then
    printf 'uv is not installed. Install it now? [y/N] '
    answer=""
    { read -r answer </dev/tty; } 2>/dev/null || answer=""
    case "$answer" in
      y | Y | yes | YES) ;;
      *) fail "not installing uv; install it yourself (https://docs.astral.sh/uv/), then run this again" ;;
    esac
  fi
  command -v curl >/dev/null 2>&1 || fail "curl is needed to download the uv installer"
  installer=$(mktemp)
  trap 'rm -f "$installer"' EXIT
  curl --proto '=https' --tlsv1.2 -fsSL "$UV_INSTALLER" -o "$installer"
  sh "$installer"
  PATH="$HOME/.local/bin:$PATH"
  export PATH
  UV=$(command -v uv 2>/dev/null || true)
  [ -n "$UV" ] || fail "uv was installed but is not on PATH; open a new shell and run this again"
fi

"$UV" tool install "git+$REPO@$TAG"
echo "Done. Run: aipm --help"
