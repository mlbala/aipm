#!/bin/sh
# Install aipm (https://github.com/mlbala/aipm) as a uv tool, from a release's attested wheel.
#   sh install.sh [-y] [-t TAG]   -y: install uv without asking; -t: a release, v0.4.0 or later
# It prints what it will do first. A missing uv is installed only after asking, with uv's
# official installer for one pinned version, checked against a pinned SHA-256; it never pipes
# a download into a shell. A uv from a relative PATH entry or the active virtualenv is refused.
# Then it downloads the release's wheel and SHA256SUMS, checks the wheel's SHA-256 and, when gh
# is installed, its provenance (gh attestation verify), and runs uv tool install <the wheel>.
set -eu

TAG="v0.4.0"
REPO="https://github.com/mlbala/aipm"
UV_INSTALLER="https://github.com/astral-sh/uv/releases/download/0.13.6/uv-installer.sh"
UV_INSTALLER_SHA256="f7a56e7afaec49a3bcbc3ac3cdbe917e7c6ce30e0d815308a12e531aa5ef23b7"
YES=0

fail() { printf 'install.sh: %s\n' "$1" >&2; exit "${2:-1}"; }

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

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d ' ' -f 1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d ' ' -f 1
  else fail "sha256sum or shasum is needed to check the downloads"; fi
}

get() { curl --proto '=https' --tlsv1.2 --max-filesize 104857600 -fsSL "$1" -o "$2"; }

while getopts "yt:h" opt; do
  case "$opt" in
    y) YES=1 ;;
    t) TAG="$OPTARG" ;;
    *) fail "usage: sh install.sh [-y] [-t TAG]" 2 ;;
  esac
done

find_uv
case "$TAG" in "" | *[!0-9A-Za-z.-]*) fail "the tag must look like v1.2.3" 2 ;; esac # before grep's per-line match
printf '%s\n' "$TAG" | grep -Eq '^v[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}(-[0-9A-Za-z.]{1,40})?$' ||
  fail "the tag must look like v1.2.3, not '$TAG'" 2
# Releases before v0.4.0 publish no attested wheel; such a tag can only be built from source.
core=${TAG#v}; core=${core%%-*}; major=${core%%.*}; rest=${core#*.}; minor=${rest%%.*}
old=0
if [ "$major" -eq 0 ] && [ "$minor" -lt 4 ]; then old=1; fi
if [ "$core" = 0.4.0 ] && [ "$TAG" != v0.4.0 ]; then old=1; fi # a v0.4.0 pre-release
if [ "$old" -eq 1 ]; then
  fail "$TAG is older than v0.4.0 and has no attested wheel. To build it from source, run:
  uv tool install git+$REPO@$TAG" 2
fi
GH=$(command -v gh 2>/dev/null || true)
echo "This will:"
if [ -n "$UV" ]; then
  echo "  1. use uv at $UV"
else
  echo "  1. install uv with its official installer ($UV_INSTALLER), after asking"
fi
echo "  2. download the wheel and SHA256SUMS of $TAG from $REPO/releases/download/$TAG/"
if [ -n "$GH" ]; then
  echo "  3. check the wheel's SHA-256, and its provenance with gh attestation verify"
else
  echo "  3. check the wheel's SHA-256 (gh is not installed, so not its provenance)"
fi
echo "  4. run: uv tool install <the wheel>"

if [ -z "$UV" ] && [ "$YES" -ne 1 ]; then
  printf 'uv is not installed. Install it now? [y/N] '
  answer=""
  { read -r answer </dev/tty; } 2>/dev/null || answer=""
  case "$answer" in
    y | Y | yes | YES) ;;
    *) fail "not installing uv; install it yourself (https://docs.astral.sh/uv/), then run this again" ;;
  esac
fi
command -v curl >/dev/null 2>&1 || fail "curl is needed to download the release"
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
trap 'exit 130' INT TERM HUP

if [ -z "$UV" ]; then
  get "$UV_INSTALLER" "$dir/uv-installer.sh"
  [ "$(sha256 "$dir/uv-installer.sh")" = "$UV_INSTALLER_SHA256" ] ||
    fail "uv's installer does not match its pinned SHA-256; not running it"
  sh "$dir/uv-installer.sh"
  export PATH="$HOME/.local/bin:$PATH"
  find_uv
  [ -n "$UV" ] || fail "uv was installed but is not on PATH; open a new shell and run this again"
fi

get "$REPO/releases/download/$TAG/SHA256SUMS" "$dir/SHA256SUMS"
line=$(grep -aE '^[0-9a-f]{64}  aipm-[0-9A-Za-z.+]+-py3-none-any\.whl$' "$dir/SHA256SUMS" || true)
case "$line" in "" | *"
"*) fail "SHA256SUMS of $TAG does not list exactly one aipm wheel; nothing installed" ;; esac
wheel=${line#*  }
get "$REPO/releases/download/$TAG/$wheel" "$dir/$wheel"
[ "$(sha256 "$dir/$wheel")" = "${line%%  *}" ] ||
  fail "the SHA-256 of $wheel does not match SHA256SUMS; nothing installed"
if [ -n "$GH" ]; then
  "$GH" auth status --hostname github.com >/dev/null 2>&1 ||
    fail "gh is not logged in, so the wheel's provenance cannot be checked: run gh auth login and retry"
  "$GH" attestation verify "$dir/$wheel" --repo mlbala/aipm \
    --cert-identity "https://github.com/mlbala/aipm/.github/workflows/release.yml@refs/tags/$TAG" \
    --source-ref "refs/tags/$TAG" --deny-self-hosted-runners ||
    fail "verification failed: $wheel has no valid attestation from aipm's release workflow for $TAG; nothing installed"
else
  echo "gh is not installed: only the SHA-256 was checked, not the provenance (README, \"Verifying a release\")"
fi

"$UV" tool install "$dir/$wheel"
echo "Done. Run: aipm --help"
