#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="sshmap"
DEFAULT_PREFIX="${HOME}/.local"
PREFIX="${SSHMAP_INSTALL_PREFIX:-$DEFAULT_PREFIX}"
ASSUME_YES=0
DRY_RUN=0
SKIP_RUST=0
SKIP_BUILD=0
NO_PATH_SETUP=0

TOTAL_STEPS=7
STEP_NUM=0

# ── Terminal styling ────────────────────────────────────────────────────────────

setup_colors() {
  if [[ -t 1 ]] && [[ "${TERM:-dumb}" != "dumb" ]]; then
    BOLD=$'\033[1m'
    DIM=$'\033[2m'
    RESET=$'\033[0m'
    RED=$'\033[31m'
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    BLUE=$'\033[34m'
    CYAN=$'\033[36m'
    MAGENTA=$'\033[35m'
  else
    BOLD="" DIM="" RESET="" RED="" GREEN="" YELLOW="" BLUE="" CYAN="" MAGENTA=""
  fi
}

print_banner() {
  printf '\n'
  printf '%b' "${CYAN}${BOLD}"
  cat <<'BANNER'
   ███████╗███████╗██╗  ██╗███╗   ███╗ █████╗ ██████╗
   ██╔════╝██╔════╝██║  ██║████╗ ████║██╔══██╗██╔══██╗
   ███████╗███████╗███████║██╔████╔██║███████║██████╔╝
   ╚════██║╚════██║██╔══██║██║╚██╔╝██║██╔══██║██╔═══╝
   ███████║███████║██║  ██║██║ ╚═╝ ██║██║  ██║██║
   ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝
BANNER
  printf '%b\n' "${RESET}${DIM}   Agentless SSH exposure management — installer${RESET}"
  printf '\n'
}

step() {
  STEP_NUM=$((STEP_NUM + 1))
  printf '\n'
  printf '%b\n' "${BOLD}${BLUE}┌─ Step ${STEP_NUM}/${TOTAL_STEPS}: $*${RESET}"
  printf '%b\n' "${DIM}└──────────────────────────────────────────────────${RESET}"
}

status_ok() {
  printf '  %b✓%b %s\n' "$GREEN" "$RESET" "$1"
}

status_skip() {
  printf '  %b○%b %s %b(already satisfied)%b\n' "$CYAN" "$RESET" "$1" "$DIM" "$RESET"
}

status_run() {
  printf '  %b→%b %s\n' "$YELLOW" "$RESET" "$1"
}

status_fail() {
  printf '  %b✗%b %s\n' "$RED" "$RESET" "$1"
}

warn() {
  printf '%bwarning:%b %s\n' "$YELLOW" "$RESET" "$*" >&2
}

fail() {
  printf '%berror:%b %s\n' "$RED" "$RESET" "$*" >&2
  exit 1
}

usage() {
  cat <<'USAGE'
Usage: ./install.sh [options]

Options:
  -y, --yes            Run package manager commands without prompting when supported.
  --dry-run            Print detected actions without installing or building anything.
  --skip-rust          Do not install Rust through rustup if cargo is missing.
  --skip-build         Install system dependencies only; do not build or install sshmap.
  --no-path-setup      Do not update shell profile PATH entries.
  --prefix PATH        Install sshmap into PATH/bin. Defaults to ~/.local.
  -h, --help           Show this help message.

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
    --no-path-setup)
      NO_PATH_SETUP=1
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
    printf '  %b[dry-run]%b ' "$DIM" "$RESET"
    printf '%q' "$1"
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

has_compiler() {
  has_command cc || has_command gcc || has_command clang
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

dedupe_array() {
  local -n _arr=$1
  local -A seen=()
  local -a unique=()
  local item
  for item in "${_arr[@]}"; do
    [[ -n "$item" ]] || continue
    if [[ -z "${seen[$item]+x}" ]]; then
      seen[$item]=1
      unique+=("$item")
    fi
  done
  _arr=("${unique[@]}")
}

detect_os() {
  OS_NAME="$(uname -s | tr '[:upper:]' '[:lower:]')"
  OS_ID=""
  OS_VERSION=""
  OS_PRETTY=""
  OS_LIKE=""

  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    OS_ID="${ID:-}"
    OS_VERSION="${VERSION_ID:-}"
    OS_PRETTY="${PRETTY_NAME:-}"
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

package_installed() {
  local package="$1"
  case "$PACKAGE_MANAGER" in
    apt)
      dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"
      ;;
    dnf|yum|zypper)
      rpm -q "$package" >/dev/null 2>&1
      ;;
    pacman)
      pacman -Q "$package" >/dev/null 2>&1
      ;;
    apk)
      apk info -e "$package" >/dev/null 2>&1
      ;;
    brew)
      brew list "$package" >/dev/null 2>&1
      ;;
    *)
      return 1
      ;;
  esac
}

# Returns package names still required for this OS.
packages_needed_for_os() {
  local -a needed=()

  case "$PACKAGE_MANAGER" in
    apt)
      has_command curl || needed+=(ca-certificates curl)
      has_command ssh || needed+=(openssh-client)
      has_command ssh-keygen || needed+=(openssh-client)
      has_compiler || needed+=(build-essential)
      has_command pkg-config || needed+=(pkg-config)
      has_command sqlite3 || needed+=(sqlite3)
      ;;
    dnf)
      has_command curl || needed+=(ca-certificates curl)
      has_command ssh || needed+=(openssh-clients)
      has_command ssh-keygen || needed+=(openssh-clients)
      has_compiler || needed+=(gcc gcc-c++ make)
      has_command pkg-config || needed+=(pkgconf-pkg-config)
      has_command sqlite3 || needed+=(sqlite)
      ;;
    yum)
      has_command curl || needed+=(ca-certificates curl)
      has_command ssh || needed+=(openssh-clients)
      has_command ssh-keygen || needed+=(openssh-clients)
      has_compiler || needed+=(gcc gcc-c++ make)
      has_command pkg-config || needed+=(pkgconfig)
      has_command sqlite3 || needed+=(sqlite)
      ;;
    pacman)
      has_command curl || needed+=(ca-certificates curl)
      has_command ssh || needed+=(openssh)
      has_command ssh-keygen || needed+=(openssh)
      has_compiler || needed+=(base-devel)
      has_command pkg-config || needed+=(pkgconf)
      has_command sqlite3 || needed+=(sqlite)
      ;;
    zypper)
      has_command curl || needed+=(ca-certificates curl)
      has_command ssh || needed+=(openssh-clients)
      has_command ssh-keygen || needed+=(openssh-clients)
      has_compiler || needed+=(gcc gcc-c++ make)
      has_command pkg-config || needed+=(pkg-config)
      has_command sqlite3 || needed+=(sqlite3)
      ;;
    apk)
      has_command curl || needed+=(ca-certificates curl)
      has_command ssh || needed+=(openssh-client)
      has_command ssh-keygen || needed+=(openssh-client)
      has_compiler || needed+=(build-base)
      has_command pkg-config || needed+=(pkgconf)
      has_command sqlite3 || needed+=(sqlite)
      ;;
    brew)
      has_command curl || needed+=(curl)
      has_command ssh || needed+=(openssh)
      has_command ssh-keygen || needed+=(openssh)
      has_command pkg-config || needed+=(pkg-config)
      has_command sqlite3 || needed+=(sqlite)
      ;;
  esac

  dedupe_array needed

  local package
  local -a missing=()
  for package in "${needed[@]}"; do
    if package_installed "$package"; then
      status_skip "package $package"
    else
      missing+=("$package")
    fi
  done

  if [[ "${#needed[@]}" -gt 0 && "${#missing[@]}" -eq 0 ]]; then
    warn "required commands are still missing, but packages appear installed — check PATH or reinstall manually"
  fi

  PACKAGES_TO_INSTALL=("${missing[@]}")
}

check_runtime_dependencies() {
  local -a checks=(
    "curl:HTTP client"
    "ssh:OpenSSH client"
    "ssh-keygen:SSH key utilities"
    "pkg-config:Native library build helper"
    "sqlite3:SQLite CLI"
  )
  local entry tool label
  local all_ok=1

  for entry in "${checks[@]}"; do
    tool="${entry%%:*}"
    label="${entry#*:}"
    if has_command "$tool"; then
      status_ok "$label ($tool)"
    else
      status_fail "$label ($tool) — missing"
      all_ok=0
    fi
  done

  if has_compiler; then
    if has_command cc; then
      status_ok "C compiler (cc)"
    elif has_command gcc; then
      status_ok "C compiler (gcc)"
    else
      status_ok "C compiler (clang)"
    fi
  else
    status_fail "C compiler (cc/gcc/clang) — missing"
    all_ok=0
  fi

  if has_command cargo; then
    status_ok "Rust toolchain (cargo $(cargo --version 2>/dev/null | cut -d' ' -f2))"
  elif [[ "$SKIP_RUST" -eq 1 ]]; then
    status_fail "Rust toolchain (cargo) — missing (installation skipped)"
    all_ok=0
  else
    status_run "Rust toolchain (cargo) — will be installed via rustup"
  fi

  DEPENDENCIES_OK=$all_ok
}

install_packages() {
  if [[ -z "$PACKAGE_MANAGER" ]]; then
    warn "no supported package manager detected; install dependencies manually if checks fail"
    return 0
  fi

  packages_needed_for_os

  if [[ "${#PACKAGES_TO_INSTALL[@]}" -eq 0 ]]; then
    status_ok "all required system packages are already installed"
    return 0
  fi

  status_run "installing packages: ${PACKAGES_TO_INSTALL[*]}"

  case "$PACKAGE_MANAGER" in
    apt)
      install_apt "${PACKAGES_TO_INSTALL[@]}"
      ;;
    dnf)
      install_dnf "${PACKAGES_TO_INSTALL[@]}"
      ;;
    yum)
      install_yum "${PACKAGES_TO_INSTALL[@]}"
      ;;
    pacman)
      install_pacman "${PACKAGES_TO_INSTALL[@]}"
      ;;
    zypper)
      install_zypper "${PACKAGES_TO_INSTALL[@]}"
      ;;
    apk)
      install_apk "${PACKAGES_TO_INSTALL[@]}"
      ;;
    brew)
      install_brew "${PACKAGES_TO_INSTALL[@]}"
      ;;
  esac
}

install_apt() {
  local yes_flag=()
  [[ "$ASSUME_YES" -eq 1 ]] && yes_flag=(-y)
  local sudo_prefix
  sudo_prefix="$(sudo_cmd)"

  run ${sudo_prefix:+"$sudo_prefix"} apt-get update
  run ${sudo_prefix:+"$sudo_prefix"} apt-get install "${yes_flag[@]}" "$@"
}

install_dnf() {
  local yes_flag=()
  [[ "$ASSUME_YES" -eq 1 ]] && yes_flag=(-y)
  local sudo_prefix
  sudo_prefix="$(sudo_cmd)"

  run ${sudo_prefix:+"$sudo_prefix"} dnf install "${yes_flag[@]}" "$@"
}

install_yum() {
  local yes_flag=()
  [[ "$ASSUME_YES" -eq 1 ]] && yes_flag=(-y)
  local sudo_prefix
  sudo_prefix="$(sudo_cmd)"

  run ${sudo_prefix:+"$sudo_prefix"} yum install "${yes_flag[@]}" "$@"
}

install_pacman() {
  local yes_flag=(--needed)
  [[ "$ASSUME_YES" -eq 1 ]] && yes_flag+=(--noconfirm)
  local sudo_prefix
  sudo_prefix="$(sudo_cmd)"

  run ${sudo_prefix:+"$sudo_prefix"} pacman -S "${yes_flag[@]}" "$@"
}

install_zypper() {
  local yes_flag=()
  [[ "$ASSUME_YES" -eq 1 ]] && yes_flag=(-y)
  local sudo_prefix
  sudo_prefix="$(sudo_cmd)"

  run ${sudo_prefix:+"$sudo_prefix"} zypper install "${yes_flag[@]}" "$@"
}

install_apk() {
  local sudo_prefix
  sudo_prefix="$(sudo_cmd)"

  run ${sudo_prefix:+"$sudo_prefix"} apk add --no-cache "$@"
}

install_brew() {
  run brew install "$@"
}

ensure_cargo_env() {
  if [[ -f "${HOME}/.cargo/env" ]]; then
    # shellcheck disable=SC1091
    . "${HOME}/.cargo/env"
  fi
}

install_rust_if_missing() {
  ensure_cargo_env

  if has_command cargo; then
    status_ok "cargo $(cargo --version)"
    return 0
  fi

  if [[ "$SKIP_RUST" -eq 1 ]]; then
    warn "cargo was not found and Rust installation was skipped"
    return 0
  fi

  has_command curl || fail "curl is required to install Rust through rustup"

  status_run "installing Rust through rustup"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '  %b[dry-run]%b curl --proto '"'"'=https'"'"' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y\n' "$DIM" "$RESET"
    return 0
  fi

  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  ensure_cargo_env
  status_ok "Rust installed ($(cargo --version 2>/dev/null || echo rustup))"
}

verify_requirements() {
  local missing=()
  has_command cargo || missing+=("cargo")
  has_command ssh || missing+=("ssh")
  has_command ssh-keygen || missing+=("ssh-keygen")
  has_compiler || missing+=("cc/gcc")

  if [[ "${#missing[@]}" -gt 0 ]]; then
    fail "missing required commands after installation: ${missing[*]}"
  fi
  status_ok "runtime requirements satisfied"
}

build_and_install() {
  if [[ "$SKIP_BUILD" -eq 1 ]]; then
    status_skip "build and binary installation"
    return 0
  fi

  ensure_cargo_env
  status_run "building release binary (this may take a few minutes)"
  run cargo build --release
  run mkdir -p "$PREFIX/bin"
  run cp "target/release/$PROJECT_NAME" "$PREFIX/bin/$PROJECT_NAME"
  run chmod +x "$PREFIX/bin/$PROJECT_NAME"
  status_ok "installed $PREFIX/bin/$PROJECT_NAME"
}

setup_path_for_session() {
  export PATH="$PREFIX/bin:$PATH"
  ensure_cargo_env
  status_ok "current shell PATH updated"
}

profile_marker_begin="# >>> sshmap installer >>>"
profile_marker_end="# <<< sshmap installer <<<"

setup_shell_profile() {
  if [[ "$NO_PATH_SETUP" -eq 1 ]]; then
    status_skip "shell profile update (--no-path-setup)"
    return 0
  fi

  local profile=""
  case "${SHELL##*/}" in
    zsh) profile="${HOME}/.zshrc" ;;
    bash) profile="${HOME}/.bashrc" ;;
    *)
      warn "unsupported shell for automatic profile setup: ${SHELL:-unknown}"
      warn "add manually: export PATH=\"$PREFIX/bin:\$PATH\""
      return 0
      ;;
  esac

  if [[ -f "$profile" ]] && grep -qF "$profile_marker_begin" "$profile"; then
    status_skip "shell profile already configured ($profile)"
    return 0
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    status_run "would append PATH block to $profile"
    return 0
  fi

  {
    printf '\n%s\n' "$profile_marker_begin"
    printf 'export PATH="%s/bin:$PATH"\n' "$PREFIX"
    if [[ -f "${HOME}/.cargo/env" ]]; then
      printf '[[ -f "$HOME/.cargo/env" ]] && . "$HOME/.cargo/env"\n'
    fi
    printf '%s\n' "$profile_marker_end"
  } >>"$profile"

  status_ok "shell profile updated ($profile)"
}

verify_installation() {
  if [[ "$SKIP_BUILD" -eq 1 ]]; then
    status_skip "post-install verification (build skipped)"
    return 0
  fi

  local binary="$PREFIX/bin/$PROJECT_NAME"
  [[ -x "$binary" ]] || fail "binary not found at $binary"

  status_run "running post-install checks"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    status_run "would run: $binary --version"
    status_run "would run: $binary doctor"
    return 0
  fi

  local version
  version="$("$binary" --version 2>/dev/null || true)"
  status_ok "version: ${version:-unknown}"

  if "$binary" doctor >/dev/null 2>&1; then
    status_ok "sshmap doctor passed"
  else
    warn "sshmap doctor reported issues — run '$binary doctor' for details"
  fi
}

print_success() {
  printf '\n'
  printf '%b\n' "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
  printf '%b\n' "${GREEN}${BOLD}║  Installation complete — SSHMap is ready to use          ║${RESET}"
  printf '%b\n' "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"
  printf '\n'

  if [[ "$SKIP_BUILD" -eq 0 ]]; then
    printf '  %bBinary:%b    %s/bin/%s\n' "$BOLD" "$RESET" "$PREFIX" "$PROJECT_NAME"
    printf '  %bVersion:%b   %s\n' "$BOLD" "$RESET" "$("$PREFIX/bin/$PROJECT_NAME" --version 2>/dev/null || echo n/a)"
    printf '\n'
    printf '  %bQuick start:%b\n' "$BOLD" "$RESET"
    printf '    sshmap doctor\n'
    printf '    sshmap init --db sshmap.db\n'
    printf '    sshmap --help\n'
    printf '\n'
    if [[ "$NO_PATH_SETUP" -eq 0 ]]; then
      case "${SHELL##*/}" in
        zsh|bash)
          printf '  %bNote:%b Open a new terminal or run:\n' "$DIM" "$RESET"
          printf '    source ~/.%src\n' "${SHELL##*/}"
          printf '\n'
          ;;
      esac
    else
      printf '  %bNote:%b This shell already has PATH set. For new terminals:\n' "$DIM" "$RESET"
      printf '    export PATH="%s/bin:$PATH"\n' "$PREFIX"
      printf '\n'
    fi
  else
    printf '  Dependencies are installed. Build manually with:\n'
    printf '    cargo build --release\n'
    printf '\n'
  fi
}

show_system_info() {
  local label="${OS_PRETTY:-$OS_NAME}"
  [[ -n "$OS_ID" ]] && label="$label (${OS_ID}${OS_VERSION:+ $OS_VERSION})"
  status_ok "operating system: $label"
  if [[ -n "$PACKAGE_MANAGER" ]]; then
    status_ok "package manager: $PACKAGE_MANAGER"
  else
    status_fail "package manager: none detected"
  fi
  status_ok "install prefix: $PREFIX"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    status_run "dry-run mode enabled — no changes will be made"
  fi
}

main() {
  setup_colors
  print_banner

  step "Detect system"
  detect_os
  detect_package_manager
  show_system_info

  step "Check dependencies"
  check_runtime_dependencies

  step "Install system packages"
  install_packages

  step "Check dependencies after package install"
  check_runtime_dependencies

  step "Install Rust toolchain"
  install_rust_if_missing
  verify_requirements

  step "Build and install SSHMap"
  build_and_install
  setup_path_for_session
  setup_shell_profile

  step "Verify installation"
  verify_installation

  print_success
}

main "$@"
