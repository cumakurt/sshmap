#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="sshmap"
DEFAULT_PREFIX="${HOME}/.local"
PREFIX="${SSHMAP_INSTALL_PREFIX:-$DEFAULT_PREFIX}"
ASSUME_YES=0
DRY_RUN=0
SKIP_RUST=0
SKIP_BUILD=0

log() {
  printf '%s\n' "$*"
}

warn() {
  printf 'warning: %s\n' "$*" >&2
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage: ./install.sh [options]

Options:
  -y, --yes          Run package manager commands without prompting when supported.
  --dry-run          Print detected actions without installing or building anything.
  --skip-rust        Do not install Rust through rustup if cargo is missing.
  --skip-build       Install system dependencies only; do not build or install sshmap.
  --prefix PATH      Install sshmap into PATH/bin. Defaults to ~/.local.
  -h, --help         Show this help message.

Environment:
  SSHMAP_INSTALL_PREFIX  Default install prefix when --prefix is not provided.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes)
      ASSUME_YES=1
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --skip-rust)
      SKIP_RUST=1
      shift
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --prefix)
      [[ $# -ge 2 ]] || fail "--prefix requires a path"
      PREFIX="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
done

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '[dry-run] %q' "$1"
    shift || true
    for arg in "$@"; do
      printf ' %q' "$arg"
    done
    printf '\n'
    return 0
  fi

  "$@"
}

has_command() {
  command -v "$1" >/dev/null 2>&1
}

need_sudo() {
  [[ "$(id -u)" -ne 0 ]]
}

sudo_cmd() {
  if need_sudo; then
    if has_command sudo; then
      printf 'sudo'
    elif has_command doas; then
      printf 'doas'
    else
      fail "root privileges are required, but sudo/doas was not found"
    fi
  fi
}

detect_os() {
  OS_NAME="$(uname -s | tr '[:upper:]' '[:lower:]')"
  OS_ID=""
  OS_LIKE=""

  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-}"
    OS_LIKE="${ID_LIKE:-}"
  fi
}

detect_package_manager() {
  if has_command apt-get; then
    PACKAGE_MANAGER="apt"
  elif has_command dnf; then
    PACKAGE_MANAGER="dnf"
  elif has_command yum; then
    PACKAGE_MANAGER="yum"
  elif has_command pacman; then
    PACKAGE_MANAGER="pacman"
  elif has_command zypper; then
    PACKAGE_MANAGER="zypper"
  elif has_command apk; then
    PACKAGE_MANAGER="apk"
  elif has_command brew; then
    PACKAGE_MANAGER="brew"
  else
    PACKAGE_MANAGER=""
  fi
}

install_packages() {
  case "$PACKAGE_MANAGER" in
    apt)
      install_apt
      ;;
    dnf)
      install_dnf
      ;;
    yum)
      install_yum
      ;;
    pacman)
      install_pacman
      ;;
    zypper)
      install_zypper
      ;;
    apk)
      install_apk
      ;;
    brew)
      install_brew
      ;;
    "")
      warn "no supported package manager was detected; install OpenSSH client, curl, CA certificates, sqlite3, and build tools manually"
      ;;
    *)
      fail "unsupported package manager: $PACKAGE_MANAGER"
      ;;
  esac
}

install_apt() {
  local yes_flag=()
  [[ "$ASSUME_YES" -eq 1 ]] && yes_flag=(-y)
  local sudo_prefix
  sudo_prefix="$(sudo_cmd)"

  run ${sudo_prefix:+"$sudo_prefix"} apt-get update
  run ${sudo_prefix:+"$sudo_prefix"} apt-get install "${yes_flag[@]}" \
    ca-certificates curl build-essential pkg-config openssh-client sqlite3
}

install_dnf() {
  local yes_flag=()
  [[ "$ASSUME_YES" -eq 1 ]] && yes_flag=(-y)
  local sudo_prefix
  sudo_prefix="$(sudo_cmd)"

  run ${sudo_prefix:+"$sudo_prefix"} dnf install "${yes_flag[@]}" \
    ca-certificates curl gcc gcc-c++ make pkgconf-pkg-config openssh-clients sqlite
}

install_yum() {
  local yes_flag=()
  [[ "$ASSUME_YES" -eq 1 ]] && yes_flag=(-y)
  local sudo_prefix
  sudo_prefix="$(sudo_cmd)"

  run ${sudo_prefix:+"$sudo_prefix"} yum install "${yes_flag[@]}" \
    ca-certificates curl gcc gcc-c++ make pkgconfig openssh-clients sqlite
}

install_pacman() {
  local yes_flag=(--needed)
  [[ "$ASSUME_YES" -eq 1 ]] && yes_flag+=(--noconfirm)
  local sudo_prefix
  sudo_prefix="$(sudo_cmd)"

  run ${sudo_prefix:+"$sudo_prefix"} pacman -Syu "${yes_flag[@]}" \
    ca-certificates curl base-devel pkgconf openssh sqlite
}

install_zypper() {
  local yes_flag=()
  [[ "$ASSUME_YES" -eq 1 ]] && yes_flag=(-y)
  local sudo_prefix
  sudo_prefix="$(sudo_cmd)"

  run ${sudo_prefix:+"$sudo_prefix"} zypper install "${yes_flag[@]}" \
    ca-certificates curl gcc gcc-c++ make pkg-config openssh-clients sqlite3
}

install_apk() {
  local sudo_prefix
  sudo_prefix="$(sudo_cmd)"

  run ${sudo_prefix:+"$sudo_prefix"} apk add --no-cache \
    ca-certificates curl build-base pkgconf openssh-client sqlite
}

install_brew() {
  run brew install curl openssh sqlite pkg-config
}

install_rust_if_missing() {
  if has_command cargo; then
    log "cargo: $(cargo --version)"
    return 0
  fi

  if [[ "$SKIP_RUST" -eq 1 ]]; then
    warn "cargo was not found and Rust installation was skipped"
    return 0
  fi

  has_command curl || fail "curl is required to install Rust through rustup"

  log "Installing Rust through rustup."
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
    return 0
  fi

  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  # shellcheck disable=SC1091
  . "${HOME}/.cargo/env"
}

verify_requirements() {
  local missing=()
  has_command cargo || missing+=("cargo")
  has_command ssh || missing+=("ssh")
  has_command ssh-keygen || missing+=("ssh-keygen")

  if [[ "${#missing[@]}" -gt 0 ]]; then
    fail "missing required commands after installation: ${missing[*]}"
  fi
}

build_and_install() {
  if [[ "$SKIP_BUILD" -eq 1 ]]; then
    log "Skipping build and binary installation."
    return 0
  fi

  run cargo build --release
  run mkdir -p "$PREFIX/bin"
  run cp "target/release/$PROJECT_NAME" "$PREFIX/bin/$PROJECT_NAME"

  log "Installed $PROJECT_NAME to $PREFIX/bin/$PROJECT_NAME"

  case ":$PATH:" in
    *":$PREFIX/bin:"*) ;;
    *)
      warn "$PREFIX/bin is not in PATH"
      warn "Add this line to your shell profile: export PATH=\"$PREFIX/bin:\$PATH\""
      ;;
  esac
}

main() {
  detect_os
  detect_package_manager

  log "Detected OS: ${OS_ID:-$OS_NAME}${OS_LIKE:+ ($OS_LIKE)}"
  log "Detected package manager: ${PACKAGE_MANAGER:-none}"
  log "Install prefix: $PREFIX"

  install_packages
  install_rust_if_missing
  verify_requirements
  build_and_install

  log "Installation completed."
}

main "$@"
