#!/bin/sh
# Install aipm (https://github.com/mlbala/aipm) as a uv tool.
#
#   sh install.sh [-y] [-t TAG]
#
#   -y      install uv without asking, if it is missing
#   -t TAG  the aipm release to install (default below)
#
# It prints what it will do first. If uv is missing, it asks before installing it with uv's
# official installer for one pinned uv version; it never pipes a download into a shell. A uv
# from a relative PATH entry or the active virtualenv is refused. Then it runs
#   uv tool install git+https://github.com/mlbala/aipm@TAG
set -eu

TAG="v0.4.0"
REPO="https://github.com/mlbala/aipm"
UV_INSTALLER="https://github.com/astral-sh/uv/releases/download/0.13.6/uv-installer.sh"
YES=0

fail() { echo "install.sh: $1" >&2; exit "${2:-1}"; }

# The first uv on PATH. An active virtualenv, or a relative or empty PATH entry, can hold a
# cloned repository's own commands, so both are refused before anything runs (RT04-18).
find_uv() {
  [ -z "${VIRTUAL_ENV:-}" ] || fail "a virtualenv is active ($VIRTUAL_ENV); deactivate it first" 2
  case "$PATH" in :* | *: | *::*) fail "refusing the relative (empty) entry in PATH" 2 ;; esac
  UV=""; IFS=:; set -f
  for d in $PATH; do
    case "$d" in /*) ;; *) fail "refusing the relative PATH entry '$d'; remove it from PATH" 2 ;; esac
    if [ -z "$UV" ] && [ -f "$d/uv" ] && [ -x "$d/uv" ]; then UV="$d/uv"; fi
  done
  unset IFS; set +f
}

while getopts "yt:h" opt; do
  case "$opt" in
    y) YES=1 ;;
    t) TAG="$OPTARG" ;;
    *) fail "usage: sh install.sh [-y] [-t TAG]" 2 ;;
  esac
done

find_uv
if ! printf '%s\n' "$TAG" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'; then
  fail "the tag must look like v1.2.3, not '$TAG'" 2
fi
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
  trap 'exit 130' INT TERM HUP
  curl --proto '=https' --tlsv1.2 -fsSL "$UV_INSTALLER" -o "$installer"
  sh "$installer"
  PATH="$HOME/.local/bin:$PATH"
  export PATH
  find_uv
  [ -n "$UV" ] || fail "uv was installed but is not on PATH; open a new shell and run this again"
fi

"$UV" tool install "git+$REPO@$TAG"
echo "Done. Run: aipm --help"
