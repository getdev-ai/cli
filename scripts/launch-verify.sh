#!/usr/bin/env sh
# launch-verify.sh — post-release verification harness for getdev.
#
# Given a released version (e.g. v0.1.0), confirms the *automatable* launch
# outcomes and prints a PASS/FAIL table. Exits non-zero if ANY check FAILs.
#
# It is READ-ONLY and touches no secrets: it makes only GET requests to public
# endpoints (GitHub Releases, npm, crates.io, getdev.ai, the scoop bucket) and
# verifies the KEYED cosign signature offline with a PUBLIC key. It never signs,
# never publishes, never provisions credentials.
#
# The cosign check reuses the exact keyed/detached recipe the embedded
# self-update verifier reads (crates/getdev-cli/src/update/signature.rs +
# testdata/update/signature/README.md): a base64 ASN.1-DER ECDSA-P256 signature
# over sha256(SHA256SUMS), verified with cosign 2.4.x and the transparency log
# ignored (--insecure-ignore-tlog=true) — NOT the sigstore/bundle keyless flow.
#
# POSIX sh. No bashisms. No `set -e` — check flow is controlled by hand so one
# FAIL never aborts the remaining checks (the whole table always prints).
set -u

PROG="launch-verify.sh"
REPO="getdev-ai/cli"
# The release's KEYED cosign public key (the public half of EMBEDDED_COSIGN_PUBKEY).
# Default: the cosign.pub asset published alongside SHA256SUMS.sig on the release.
# Override with --pubkey <path> to verify against a locally-held key.
PUBKEY=""
OFFLINE=0
SKIP_DOWNLOAD=0
VERSION=""

# ---- getdev.ai frozen install URLs (never change without a coordinated move) --
INSTALL_SH_URL="https://getdev.ai/install.sh"
INSTALL_PS1_URL="https://getdev.ai/install.ps1"

usage() {
  cat <<EOF
$PROG — verify a published getdev release, fail-closed.

USAGE
  $PROG <version> [options]
  $PROG --offline           # dry-print the checks without any network access

ARGUMENTS
  <version>                  release to verify, e.g. v0.1.0 (the leading v is optional)

OPTIONS
  --repo <owner/name>        GitHub repo to query        (default: $REPO)
  --pubkey <path>            keyed cosign public key      (default: the release's cosign.pub asset)
  --offline                  print the checks and exit 0 without touching the network
  --skip-download            skip per-archive checksum re-download (still checks assets + signature)
  -h, --help                 show this help and exit

CHECKS (all must PASS; any FAIL exits non-zero)
  1. release-exists     the GitHub Release for the tag exists
  2. required-assets    SHA256SUMS, SHA256SUMS.sig, and the SBOM (*.sbom.spdx.json) are attached
  3. checksums-match    every archive in SHA256SUMS downloads and its sha256 matches the manifest
  4. cosign-verify      SHA256SUMS.sig verifies over SHA256SUMS with the keyed public key
                        (cosign 2.4.x, --insecure-ignore-tlog=true — the self-update recipe)
  5. channel-npm        npm view getdev version == the released version
  6. channel-crates     crates.io reports the released version for the getdev crate
  7. channel-brew       the Homebrew formula (getdev-ai/tap/getdev) reports the released version
  8. channel-scoop      the scoop-bucket getdev manifest reports the released version
  9. channel-install    $INSTALL_SH_URL and $INSTALL_PS1_URL serve a real installer
                        script for this tag (not an HTML landing page)

NOTES
  Read-only. No secrets are read or required. Network destinations are exhaustively
  GitHub, npm, crates.io, getdev.ai, and the scoop bucket — matching getdev's own
  privacy contract. A non-existent version FAILs closed (never a false PASS).
EOF
}

# ---- arg parsing --------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --offline) OFFLINE=1; shift ;;
    --skip-download) SKIP_DOWNLOAD=1; shift ;;
    --repo) REPO="${2:-}"; [ -n "$REPO" ] || { echo "$PROG: --repo needs a value" >&2; exit 2; }; shift 2 ;;
    --pubkey) PUBKEY="${2:-}"; [ -n "$PUBKEY" ] || { echo "$PROG: --pubkey needs a value" >&2; exit 2; }; shift 2 ;;
    -*) echo "$PROG: unknown option '$1' (try --help)" >&2; exit 2 ;;
    *) if [ -z "$VERSION" ]; then VERSION="$1"; shift; else echo "$PROG: unexpected argument '$1'" >&2; exit 2; fi ;;
  esac
done

# ---- offline dry-print --------------------------------------------------------
if [ "$OFFLINE" -eq 1 ]; then
  echo "$PROG: --offline — dry run, no network access. Checks that WOULD run:"
  echo "  repo:    $REPO"
  echo "  version: ${VERSION:-<required at real run>}"
  echo
  usage | sed -n '/^CHECKS/,/^NOTES/p' | sed '$d'
  exit 0
fi

# ---- a version is required for a real run -------------------------------------
if [ -z "$VERSION" ]; then
  echo "$PROG: a version is required (e.g. $PROG v0.1.0). See --help." >&2
  exit 2
fi

# Normalise: TAG has the leading v, SEMVER does not.
case "$VERSION" in
  v*) TAG="$VERSION"; SEMVER="${VERSION#v}" ;;
  *)  TAG="v$VERSION"; SEMVER="$VERSION" ;;
esac

# ---- prerequisites ------------------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1; }
if ! need curl; then echo "$PROG: curl is required" >&2; exit 2; fi
SHA_TOOL=""
if need sha256sum; then SHA_TOOL="sha256sum"; elif need shasum; then SHA_TOOL="shasum -a 256"; fi

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/getdev-launch-verify.XXXXXX")" || {
  echo "$PROG: could not create a temp dir" >&2; exit 2; }
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT INT TERM

# ---- result table -------------------------------------------------------------
FAILS=0
FAIL_NAMES=""
RESULTS=""

record() { # name  status(PASS|FAIL|SKIP)  detail
  RESULTS="${RESULTS}${1}	${2}	${3}
"
  if [ "$2" = "FAIL" ]; then
    FAILS=$((FAILS + 1))
    FAIL_NAMES="${FAIL_NAMES} $1"
  fi
}

# Bounded, read-only GET helpers (timeouts so a stalled host never hangs the run).
# crates.io (and some CDNs) hard-reject requests without a User-Agent (403).
CURL="curl -fsSL -A getdev-launch-verify --connect-timeout 10 --max-time 120"
# GET a URL to a file; echoes the HTTP status. Read-only, follows redirects.
http_get() { # url  outfile
  $CURL -o "$2" -w '%{http_code}' "$1" 2>/dev/null
}
http_status() { # url  (echoes status only)
  $CURL -o /dev/null -w '%{http_code}' "$1" 2>/dev/null
}

API="https://api.github.com/repos/${REPO}/releases/tags/${TAG}"
REL_JSON="$WORKDIR/release.json"

# ---- 1. release-exists --------------------------------------------------------
# No -f here: on a 404 we want the real status code, not a curl failure exit.
REL_STATUS="$(curl -sSL --connect-timeout 10 --max-time 120 -o "$REL_JSON" \
  -w '%{http_code}' -H 'Accept: application/vnd.github+json' "$API" 2>/dev/null || echo 000)"
if [ "$REL_STATUS" = "200" ] && [ -s "$REL_JSON" ]; then
  record "release-exists" "PASS" "$REPO $TAG found"
  REL_OK=1
else
  record "release-exists" "FAIL" "no release for $TAG (HTTP $REL_STATUS)"
  REL_OK=0
fi

# Extract "name": "url" pairs from the release assets (portable, no jq).
asset_url() { # asset-name-or-suffix  ->  browser_download_url
  # matches the browser_download_url whose tail matches the argument
  grep -o '"browser_download_url": *"[^"]*"' "$REL_JSON" 2>/dev/null \
    | sed 's/.*"browser_download_url": *"//; s/"$//' \
    | grep -E "$1" | head -n1
}

SUMS_URL=""; SIG_URL=""; SBOM_URL=""
if [ "$REL_OK" -eq 1 ]; then
  SUMS_URL="$(asset_url '/SHA256SUMS$')"
  SIG_URL="$(asset_url '/SHA256SUMS\.sig$')"
  SBOM_URL="$(asset_url '\.sbom\.spdx\.json$')"
fi

# ---- 2. required-assets -------------------------------------------------------
if [ "$REL_OK" -eq 1 ]; then
  MISSING=""
  [ -n "$SUMS_URL" ] || MISSING="$MISSING SHA256SUMS"
  [ -n "$SIG_URL" ]  || MISSING="$MISSING SHA256SUMS.sig"
  [ -n "$SBOM_URL" ] || MISSING="$MISSING SBOM(*.sbom.spdx.json)"
  if [ -z "$MISSING" ]; then
    record "required-assets" "PASS" "SHA256SUMS + .sig + SBOM attached"
  else
    record "required-assets" "FAIL" "missing:$MISSING"
  fi
else
  record "required-assets" "FAIL" "release missing — cannot check assets"
fi

# Fetch the manifest + signature once for the checksum and cosign checks.
SUMS_FILE="$WORKDIR/SHA256SUMS"
SIG_FILE="$WORKDIR/SHA256SUMS.sig"
HAVE_SUMS=0
if [ -n "$SUMS_URL" ]; then
  s="$(http_get "$SUMS_URL" "$SUMS_FILE")"; [ "$s" = "200" ] && [ -s "$SUMS_FILE" ] && HAVE_SUMS=1
fi
HAVE_SIG=0
if [ -n "$SIG_URL" ]; then
  s="$(http_get "$SIG_URL" "$SIG_FILE")"; [ "$s" = "200" ] && [ -s "$SIG_FILE" ] && HAVE_SIG=1
fi

# ---- 3. checksums-match -------------------------------------------------------
if [ "$SKIP_DOWNLOAD" -eq 1 ]; then
  record "checksums-match" "SKIP" "--skip-download requested"
elif [ "$HAVE_SUMS" -ne 1 ]; then
  record "checksums-match" "FAIL" "SHA256SUMS not retrievable"
elif [ -z "$SHA_TOOL" ]; then
  record "checksums-match" "FAIL" "no sha256sum/shasum tool available"
else
  BAD=""; N=0
  # SHA256SUMS lines: "<hex>  <asset-basename>"
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    want="$(printf '%s\n' "$line" | awk '{print $1}')"
    name="$(printf '%s\n' "$line" | awk '{print $NF}')"
    [ -n "$want" ] && [ -n "$name" ] || continue
    N=$((N + 1))
    aurl="$(asset_url "/$(printf '%s' "$name" | sed 's/[.[\*^$/]/\\&/g')\$")"
    if [ -z "$aurl" ]; then BAD="$BAD $name(no-asset)"; continue; fi
    af="$WORKDIR/asset_$N"
    s="$(http_get "$aurl" "$af")"
    if [ "$s" != "200" ] || [ ! -s "$af" ]; then BAD="$BAD $name(dl-$s)"; continue; fi
    got="$($SHA_TOOL "$af" | awk '{print $1}')"
    [ "$got" = "$want" ] || BAD="$BAD $name(mismatch)"
    rm -f "$af"
  done < "$SUMS_FILE"
  if [ "$N" -eq 0 ]; then
    record "checksums-match" "FAIL" "SHA256SUMS had no entries"
  elif [ -z "$BAD" ]; then
    record "checksums-match" "PASS" "$N archive(s) match SHA256SUMS"
  else
    record "checksums-match" "FAIL" "bad:$BAD"
  fi
fi

# ---- 4. cosign-verify (keyed, offline, tlog ignored) --------------------------
if ! need cosign; then
  record "cosign-verify" "FAIL" "cosign not installed (need 2.4.x)"
elif [ "$HAVE_SUMS" -ne 1 ] || [ "$HAVE_SIG" -ne 1 ]; then
  record "cosign-verify" "FAIL" "SHA256SUMS / .sig not retrievable"
else
  KEYFILE=""
  if [ -n "$PUBKEY" ]; then
    if [ -f "$PUBKEY" ]; then KEYFILE="$PUBKEY"; else
      record "cosign-verify" "FAIL" "--pubkey '$PUBKEY' not found"; fi
  else
    PUB_URL="$(asset_url '/cosign\.pub$')"
    if [ -n "$PUB_URL" ]; then
      KEYFILE="$WORKDIR/cosign.pub"
      s="$(http_get "$PUB_URL" "$KEYFILE")"
      [ "$s" = "200" ] && [ -s "$KEYFILE" ] || { KEYFILE=""; \
        record "cosign-verify" "FAIL" "cosign.pub asset not retrievable (HTTP $s)"; }
    else
      record "cosign-verify" "FAIL" "no public key: pass --pubkey or publish cosign.pub"
    fi
  fi
  if [ -n "$KEYFILE" ]; then
    # Keyed detached verify — the exact recipe verify_detached() mirrors.
    if cosign verify-blob --key "$KEYFILE" --signature "$SIG_FILE" \
         --insecure-ignore-tlog=true "$SUMS_FILE" >/dev/null 2>&1; then
      record "cosign-verify" "PASS" "keyed signature verifies over SHA256SUMS"
    else
      record "cosign-verify" "FAIL" "signature did NOT verify (fail closed)"
    fi
  fi
fi

# ---- 5. channel-npm -----------------------------------------------------------
if need npm; then
  got="$(npm view getdev version 2>/dev/null | tr -d '[:space:]')"
  if [ "$got" = "$SEMVER" ]; then
    record "channel-npm" "PASS" "npm getdev@$got"
  else
    record "channel-npm" "FAIL" "npm getdev=${got:-<none>} (want $SEMVER)"
  fi
else
  # No npm CLI — fall back to the public registry JSON.
  nf="$WORKDIR/npm.json"
  s="$(http_get "https://registry.npmjs.org/getdev/$SEMVER" "$nf")"
  if [ "$s" = "200" ]; then
    record "channel-npm" "PASS" "registry.npmjs.org getdev@$SEMVER"
  else
    record "channel-npm" "FAIL" "npm getdev@$SEMVER not found (HTTP $s)"
  fi
fi

# ---- 6. channel-crates --------------------------------------------------------
cf="$WORKDIR/crates.json"
s="$(http_get "https://crates.io/api/v1/crates/getdev/$SEMVER" "$cf")"
if [ "$s" = "200" ] && grep -q "\"num\":\"$SEMVER\"" "$cf" 2>/dev/null; then
  record "channel-crates" "PASS" "crates.io getdev@$SEMVER"
elif [ "$s" = "200" ]; then
  record "channel-crates" "PASS" "crates.io getdev $SEMVER (200)"
else
  record "channel-crates" "FAIL" "crates.io getdev@$SEMVER not found (HTTP $s)"
fi

# ---- 7. channel-brew ----------------------------------------------------------
# The tap repo file is the source of truth; a local `brew info` only works once
# the machine has tapped getdev-ai/tap, so it is a bonus signal, not the check.
bf="$WORKDIR/getdev.rb"
s="$(http_get "https://raw.githubusercontent.com/getdev-ai/homebrew-tap/HEAD/Formula/getdev.rb" "$bf")"
if [ "$s" = "200" ] && grep -q "$SEMVER" "$bf" 2>/dev/null; then
  record "channel-brew" "PASS" "tap formula file reports $SEMVER"
elif need brew && brew info --json=v2 getdev-ai/tap/getdev 2>/dev/null | grep -q "\"$SEMVER\""; then
  record "channel-brew" "PASS" "tap formula reports $SEMVER (local brew)"
else
  record "channel-brew" "FAIL" "tap formula@$SEMVER not found (HTTP $s)"
fi

# ---- 8. channel-scoop ---------------------------------------------------------
sf="$WORKDIR/getdev.scoop.json"
s="$(http_get "https://raw.githubusercontent.com/getdev-ai/scoop-bucket/HEAD/bucket/getdev.json" "$sf")"
if [ "$s" = "200" ] && grep -q "\"version\": *\"$SEMVER\"" "$sf" 2>/dev/null; then
  record "channel-scoop" "PASS" "scoop manifest @ $SEMVER"
else
  record "channel-scoop" "FAIL" "scoop manifest@$SEMVER not found (HTTP $s)"
fi

# ---- 9. channel-install (frozen getdev.ai URLs) -------------------------------
# A 200 alone is NOT sufficient: an SPA landing page returns 200 (text/html) for
# every path, which would silently pass while `curl … | sh` actually pipes HTML
# into a shell. Fetch each body and prove it is a real installer script that
# resolves THIS version's release artifacts, and that it is not an HTML page.
shf="$WORKDIR/install.sh"; psf="$WORKDIR/install.ps1"
sh_s="$(http_get "$INSTALL_SH_URL" "$shf")"
ps_s="$(http_get "$INSTALL_PS1_URL" "$psf")"
# looks like a real POSIX installer: shebang + points at this tag's release download
sh_ok=0
if [ "$sh_s" = "200" ] && [ -s "$shf" ] \
   && head -1 "$shf" | grep -q '^#!' \
   && ! grep -qi '<!DOCTYPE html\|<html' "$shf" \
   && grep -q "releases/download/$TAG" "$shf"; then
  sh_ok=1
fi
# looks like a real PowerShell installer: not HTML + references this tag's release
ps_ok=0
if [ "$ps_s" = "200" ] && [ -s "$psf" ] \
   && ! grep -qi '<!DOCTYPE html\|<html' "$psf" \
   && grep -q "releases/download/$TAG" "$psf"; then
  ps_ok=1
fi
if [ "$sh_ok" = 1 ] && [ "$ps_ok" = 1 ]; then
  record "channel-install" "PASS" "install.sh + install.ps1 serve a $TAG installer script"
else
  det="install.sh=$sh_s"; [ "$sh_ok" = 1 ] || det="$det(not-a-$TAG-script)"
  det="$det install.ps1=$ps_s"; [ "$ps_ok" = 1 ] || det="$det(not-a-$TAG-script)"
  record "channel-install" "FAIL" "$det — getdev.ai must serve the real installer, not an HTML page"
fi

# ---- print the table ----------------------------------------------------------
echo
echo "getdev launch verification — $REPO $TAG"
echo "---------------------------------------------------------------"
printf '%s' "$RESULTS" | while IFS='	' read -r name status detail; do
  [ -n "$name" ] || continue
  printf '  %-6s  %-16s  %s\n' "$status" "$name" "$detail"
done
echo "---------------------------------------------------------------"

if [ "$FAILS" -eq 0 ]; then
  echo "RESULT: PASS — all checks green for $TAG"
  exit 0
else
  echo "RESULT: FAIL — $FAILS check(s) failed:${FAIL_NAMES}"
  exit 1
fi
