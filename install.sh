#!/usr/bin/env bash
#
# truemap installer: install the toolchain, build, install the binary, grant the
# capability --l4 needs, and verify the result.
#
#   ./install.sh                      # build + install to /usr/local/bin
#   ./install.sh --prefix ~/.local    # install somewhere else
#   ./install.sh --no-setcap          # skip the CAP_NET_RAW grant (no --l4)
#   ./install.sh --build-only         # build and test, install nothing
#
set -euo pipefail

PREFIX="/usr/local"
DO_SETCAP=1
DO_INSTALL=1
RUN_TESTS=1
ASSUME_YES=0

RED=''; GRN=''; YLW=''; DIM=''; OFF=''
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; DIM=$'\033[2m'; OFF=$'\033[0m'
fi
say()  { printf '%s==>%s %s\n' "$GRN" "$OFF" "$*"; }
warn() { printf '%s warn%s %s\n' "$YLW" "$OFF" "$*" >&2; }
die()  { printf '%serror%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }
note() { printf '%s      %s%s\n' "$DIM" "$*" "$OFF"; }

usage() {
    sed -n '3,9p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

Options:
  --prefix <DIR>   install into <DIR>/bin        [/usr/local]
  --no-setcap      do not grant CAP_NET_RAW; --l4 will be unavailable
  --build-only     build and test, then stop
  --skip-tests     do not run the unit tests
  -y, --yes        do not prompt before installing system packages
  -h, --help       this message
EOF
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)     PREFIX="${2:?--prefix needs a directory}"; shift 2 ;;
        --prefix=*)   PREFIX="${1#*=}"; shift ;;
        --no-setcap)  DO_SETCAP=0; shift ;;
        --build-only) DO_INSTALL=0; DO_SETCAP=0; shift ;;
        --skip-tests) RUN_TESTS=0; shift ;;
        -y|--yes)     ASSUME_YES=1; shift ;;
        -h|--help)    usage ;;
        *)            die "unknown option: $1 (try --help)" ;;
    esac
done

cd "$(dirname "$(readlink -f "$0")")"
[ -f Cargo.toml ] || die "run this from the truemap checkout (no Cargo.toml here)"

# ---------------------------------------------------------------------------
# 1. Platform. truemap is Linux-only and this is not a style preference:
#    src/sweep.rs hardcodes RLIMIT_NOFILE = 7, which is the Linux value (macOS
#    and the BSDs use 8), and the --l4 path needs AF_INET/SOCK_RAW plus
#    file capabilities. Building elsewhere yields a binary that misreads its
#    own fd limit, so refuse rather than hand over something subtly wrong.
# ---------------------------------------------------------------------------
[ "$(uname -s)" = "Linux" ] || die "truemap is Linux-only (got $(uname -s)); see the note in install.sh"

# ---------------------------------------------------------------------------
# 2. Privilege: how do we run a command that needs root?
# ---------------------------------------------------------------------------
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        warn "not root and no sudo; system packages and setcap will be skipped"
    fi
fi

# Is some path writable without root? A prefix that does not exist yet is the
# normal case (--prefix ~/.local on a fresh machine), so walk up to the nearest
# ancestor that DOES exist and test that. Testing -w on the missing directory
# itself always fails, which would send a perfectly user-writable install down
# the sudo path and leave root-owned directories in someone's home.
writable_without_root() {
    local d="$1"
    while [ ! -e "$d" ]; do
        local parent; parent="$(dirname "$d")"
        [ "$parent" = "$d" ] && break
        d="$parent"
    done
    [ -w "$d" ]
}

pkg_mgr() {
    for m in apt-get dnf yum pacman zypper apk; do
        command -v "$m" >/dev/null 2>&1 && { echo "$m"; return; }
    done
}

confirm() {
    [ "$ASSUME_YES" -eq 1 ] && return 0
    [ -t 0 ] || return 1
    printf '      install %s with %s? [y/N] ' "$1" "$2"
    read -r a; [ "$a" = y ] || [ "$a" = Y ]
}

install_pkgs() {
    local what="$1"; shift
    local mgr; mgr="$(pkg_mgr)"
    [ -n "$mgr" ] || { warn "no known package manager; install $what yourself"; return 1; }
    [ -n "$SUDO" ] || [ "$(id -u)" -eq 0 ] || { warn "cannot install $what without root"; return 1; }
    confirm "$what" "$mgr" || { warn "declined; install $what yourself"; return 1; }
    case "$mgr" in
        apt-get) $SUDO apt-get update -qq && $SUDO apt-get install -y "$@" ;;
        dnf|yum) $SUDO "$mgr" install -y "$@" ;;
        pacman)  $SUDO pacman -Sy --noconfirm "$@" ;;
        zypper)  $SUDO zypper -n install "$@" ;;
        apk)     $SUDO apk add --no-cache "$@" ;;
    esac
}

# ---------------------------------------------------------------------------
# 3. A C toolchain. Every dependency is pure Rust, but rustc still shells out
#    to cc to link the final binary.
# ---------------------------------------------------------------------------
say "checking for a linker"
if command -v cc >/dev/null 2>&1; then
    note "cc: $(command -v cc)"
else
    warn "no cc found; rustc cannot link without one"
    case "$(pkg_mgr)" in
        apt-get) install_pkgs "build-essential" build-essential ;;
        dnf|yum) install_pkgs "gcc" gcc ;;
        pacman)  install_pkgs "base-devel" base-devel ;;
        zypper)  install_pkgs "gcc" gcc ;;
        apk)     install_pkgs "build-base" build-base ;;
    esac
    command -v cc >/dev/null 2>&1 || die "still no cc; install a C toolchain and re-run"
fi

# ---------------------------------------------------------------------------
# 4. Rust. Prefer whatever is already on PATH; otherwise source an existing
#    rustup env, and only then offer to install rustup.
# ---------------------------------------------------------------------------
say "checking for cargo"
if ! command -v cargo >/dev/null 2>&1; then
    # shellcheck disable=SC1091
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
fi
if ! command -v cargo >/dev/null 2>&1; then
    warn "cargo not found"
    if [ "$ASSUME_YES" -eq 1 ] || { [ -t 0 ] && { printf '      install the Rust toolchain via rustup.rs? [y/N] '; read -r a; [ "$a" = y ] || [ "$a" = Y ]; }; }; then
        command -v curl >/dev/null 2>&1 || install_pkgs "curl" curl || die "need curl to fetch rustup"
        say "installing rustup (this does not need root)"
        # -k skips certificate verification, at the operator's instruction, so the
        # bootstrap still works where the TLS chain cannot be validated locally -- an
        # intercepting proxy, or a trust store that lacks the issuing CA. Understand the
        # trade: what this URL returns is piped into sh and runs as you, so verification
        # is what distinguishes rustup from whatever an on-path attacker substitutes.
        # --proto '=https' --tlsv1.2 are kept: they still refuse a plaintext redirect and
        # old TLS. If you need the check back, drop -k; if you are behind a known proxy,
        # --cacert <its-ca.pem> is the narrower fix.
        curl -k --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --no-modify-path
        # shellcheck disable=SC1091
        . "$HOME/.cargo/env"
    else
        die "cargo is required; see https://rustup.rs"
    fi
fi
note "cargo: $(cargo --version)"
note "rustc: $(rustc --version)"

# ---------------------------------------------------------------------------
# 5. Build and test.
# ---------------------------------------------------------------------------
say "building (release)"
cargo build --release

if [ "$RUN_TESTS" -eq 1 ]; then
    say "running the unit tests"
    cargo test --release --quiet
else
    note "tests skipped (--skip-tests)"
fi

BIN="$PWD/target/release/truemap"
[ -x "$BIN" ] || die "build reported success but $BIN is missing"

if [ "$DO_INSTALL" -eq 0 ]; then
    say "built: $BIN"
    note "not installed (--build-only)."
    note "NOTE: --l4 needs CAP_NET_RAW on the binary you actually run:"
    note "  sudo setcap cap_net_raw+ep $BIN"
    exit 0
fi

# ---------------------------------------------------------------------------
# 6. Install. Fall back to a user-writable prefix rather than failing when
#    there is no way to write to /usr/local.
# ---------------------------------------------------------------------------
DEST="$PREFIX/bin"
if ! writable_without_root "$DEST" && [ -z "$SUDO" ] && [ "$(id -u)" -ne 0 ]; then
    warn "$DEST needs root and there is no sudo; falling back to ~/.local/bin"
    DEST="$HOME/.local/bin"
fi

say "installing to $DEST"
if writable_without_root "$DEST"; then
    mkdir -p "$DEST"; install -m0755 "$BIN" "$DEST/truemap"
else
    $SUDO mkdir -p "$DEST"; $SUDO install -m0755 "$BIN" "$DEST/truemap"
fi
TARGET="$DEST/truemap"

# ---------------------------------------------------------------------------
# 7. CAP_NET_RAW for --l4.
#
#    File capabilities are stored against the INODE, so `cargo build` replaces
#    the binary and silently drops them. That is why this grants the capability
#    to the INSTALLED copy and warns about the build-tree copy separately: a
#    rebuild leaves the installed binary alone, but anything invoking
#    target/release/truemap directly loses --l4 without saying so.
# ---------------------------------------------------------------------------
if [ "$DO_SETCAP" -eq 1 ]; then
    say "granting CAP_NET_RAW (for --l4)"
    if ! command -v setcap >/dev/null 2>&1; then
        case "$(pkg_mgr)" in
            apt-get) install_pkgs "libcap2-bin" libcap2-bin || true ;;
            dnf|yum) install_pkgs "libcap" libcap || true ;;
            pacman)  install_pkgs "libcap" libcap || true ;;
            zypper)  install_pkgs "libcap-progs" libcap-progs || true ;;
            apk)     install_pkgs "libcap" libcap || true ;;
        esac
    fi
    if command -v setcap >/dev/null 2>&1; then
        if $SUDO setcap cap_net_raw+ep "$TARGET" 2>/dev/null; then
            note "granted on $TARGET"
        else
            warn "setcap failed (filesystem may be mounted nosuid, or no root)"
            warn "truemap still works; --l4 will report that raw sockets are unavailable"
        fi
    else
        warn "setcap unavailable; --l4 will be disabled"
    fi
else
    note "setcap skipped (--no-setcap); --l4 will be unavailable"
fi

# ---------------------------------------------------------------------------
# 8. Verify. Report what is true rather than announcing success.
# ---------------------------------------------------------------------------
say "verifying"
"$TARGET" --version >/dev/null 2>&1 || die "$TARGET will not run"
note "version: $("$TARGET" --version)"
note "path:    $TARGET"

# Test --l4 by RUNNING it, not by asking getcap. File capabilities are stored on
# the inode but ignored by the kernel when the filesystem is mounted nosuid --
# common for /tmp, and for some container and home-directory mounts. There,
# setcap succeeds and getcap reports cap_net_raw=ep while the raw socket still
# fails, so trusting getcap would claim a capability that does not work. One
# connection to 127.0.0.1:1 settles it.
# Capture first, then match. Piping straight into grep would be wrong under
# `set -o pipefail`: truemap exits 1 when it proves no service -- which is the
# normal result for this one-port loopback probe -- and that non-zero status
# would mask grep's verdict and always take the "enabled" branch.
L4_PROBE="$("$TARGET" 127.0.0.1 -p 1 --l4 -t 50 --tries 1 --controls 0 --accessible 2>&1 || true)"
if printf '%s' "$L4_PROBE" | grep -q 'raw sockets unavailable'; then
    note "--l4:    unavailable -- the application-layer engine is unaffected"
    if command -v getcap >/dev/null 2>&1 && [ -n "$(getcap "$TARGET" 2>/dev/null)" ]; then
        warn "CAP_NET_RAW is set on $TARGET but the kernel is ignoring it."
        MNT="$(findmnt -no TARGET,OPTIONS --target "$TARGET" 2>/dev/null || true)"
        case "$MNT" in
            *nosuid*)
                warn "its filesystem is mounted nosuid, which makes file capabilities inert:"
                warn "  $MNT"
                warn "re-install to a prefix on a normal mount (e.g. --prefix /usr/local) for --l4" ;;
            *)  warn "mount: ${MNT:-unknown}" ;;
        esac
    fi
else
    note "--l4:    enabled"
fi

case ":$PATH:" in
    *":$DEST:"*) ;;
    *) warn "$DEST is not on your PATH; add it:"
       warn "  echo 'export PATH=\"$DEST:\$PATH\"' >> ~/.profile" ;;
esac

say "done -- try: truemap scanme.nmap.org"
