#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="${NORR_REPOSITORY:-Theok09/norr}"
PREFIX="${PREFIX:-/usr/local}"
MODE=release
LOCAL_BINARY=""
MIRROR=""

usage() {
  cat <<EOF
USAGE
  install.sh [flags]

FLAGS
  --from-source        build norrd on this machine
  --local=<file>       install a norrd binary you copied here yourself
  --mirror=<url>       download the release archive from this base URL instead of GitHub
EOF
}

while (( $# )); do
  case "$1" in
    --from-source) MODE=source; shift ;;
    --local) LOCAL_BINARY=$2; MODE=local; shift 2 ;;
    --local=*) LOCAL_BINARY=${1#*=}; MODE=local; shift ;;
    --mirror) MIRROR=$2; shift 2 ;;
    --mirror=*) MIRROR=${1#*=}; shift ;;
    -h | --help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  R=$'\e[0m' B=$'\e[1m' ACCENT=$'\e[38;5;67m' OK=$'\e[38;5;71m' ERR=$'\e[38;5;167m' MUTED=$'\e[38;5;244m'
else
  R="" B="" ACCENT="" OK="" ERR="" MUTED=""
fi
step() { printf '    %s›%s %s\n' "$ACCENT" "$R" "$*"; }
good() { printf '    %s✓%s %s\n' "$OK" "$R" "$*"; }
die()  { printf '    %s✗%s %s\n' "$ERR" "$R" "$*" >&2; exit 1; }
quiet() { "$@" >/tmp/norr-install.log 2>&1 || { tail -20 /tmp/norr-install.log >&2; die "Failed: $*"; }; }

[[ "$(uname -s)" == Linux ]] || die "Norr runs on Linux"
[[ $(id -u) -eq 0 ]] || die "Run as root"

case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) ARCH=""; [[ $MODE == release ]] && MODE=source ;;
esac

SOURCE_DIR=""
if [[ -f "$(dirname "${BASH_SOURCE[0]}")/CMakeLists.txt" ]]; then
  SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

packages() {
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    quiet apt-get update -qq
    quiet apt-get install -y -qq "$@"
  elif command -v dnf >/dev/null 2>&1; then
    quiet dnf install -y -q "$@"
  elif command -v apk >/dev/null 2>&1; then
    quiet apk add --no-cache "$@"
  else
    die "Unsupported package manager; install: $*"
  fi
}

runtime_packages() {
  local missing=()
  command -v ip >/dev/null 2>&1 || missing+=(iproute2)
  command -v iptables >/dev/null 2>&1 || missing+=(iptables)
  command -v curl >/dev/null 2>&1 || missing+=(curl)
  command -v ping >/dev/null 2>&1 || missing+=(iputils-ping)
  command -v tcpdump >/dev/null 2>&1 || missing+=(tcpdump)
  command -v python3 >/dev/null 2>&1 || missing+=(python3)
  (( ${#missing[@]} == 0 )) && return
  if command -v dnf >/dev/null 2>&1; then
    missing=("${missing[@]/iproute2/iproute}")
    missing=("${missing[@]/iputils-ping/iputils}")
  fi
  packages "${missing[@]}"
}

install_support() {
  local from=$1
  install -m 0755 "$from/norr" "$PREFIX/bin/norr"
  install -D -m 0755 "$from/norr-quick" "$PREFIX/lib/norr/norr-quick"
  install -m 0644 "$from/norr@.service" /etc/systemd/system/norr@.service
  [[ -f "$from/norr-doctor" ]] && install -m 0755 "$from/norr-doctor" "$PREFIX/bin/norr-doctor"
  [[ -f "$from/norr-failover" ]] && install -m 0755 "$from/norr-failover" "$PREFIX/bin/norr-failover"
  [[ -f "$from/norr-failover.service" ]] && install -m 0644 "$from/norr-failover.service" /etc/systemd/system/
  [[ -f "$from/norr-failover.timer" ]] && install -m 0644 "$from/norr-failover.timer" /etc/systemd/system/
  return 0
}

stage_source_support() {
  local source=$1 stage=$2
  cp "$source/scripts/norr" "$source/scripts/norr-quick" "$source/deployment/systemd/norr@.service" "$stage/"
  cp "$source/deployment/tools/norr-doctor" "$stage/"
  cp "$source/deployment/failover/norr-failover" "$source/deployment/failover/norr-failover.service" \
    "$source/deployment/failover/norr-failover.timer" "$stage/"
}

fetch_source() {
  if [[ -n "$SOURCE_DIR" ]]; then printf '%s' "$SOURCE_DIR"; return; fi
  local source; source=$(mktemp -d)
  curl -fsSL "https://codeload.github.com/$REPOSITORY/tar.gz/refs/heads/main" \
    | tar -xz --strip-components=1 -C "$source" || die "could not download the source"
  printf '%s' "$source"
}

install_release() {
  local work; work=$(mktemp -d)
  local base="${MIRROR:-https://github.com/$REPOSITORY/releases/latest/download}/norr-linux-$ARCH.tar.gz"
  curl -fsSL --retry 3 "$base" -o "$work/norr.tar.gz" || { rm -rf "${work:?}"; return 1; }
  if curl -fsSL "$base.sha256" -o "$work/norr.tar.gz.sha256" 2>/dev/null; then
    (cd "$work" && awk '{print $1"  norr.tar.gz"}' norr.tar.gz.sha256 | sha256sum -c --quiet -) \
      || die "Checksum mismatch; download refused"
  fi
  tar -xzf "$work/norr.tar.gz" -C "$work"
  local root="$work/norr-linux-$ARCH"
  install -m 0755 "$root/norrd" "$PREFIX/bin/norrd"
  install_support "$root"
  rm -rf "${work:?}"
}

install_local() {
  [[ -f "$LOCAL_BINARY" ]] || die "$LOCAL_BINARY does not exist"
  "$LOCAL_BINARY" version >/dev/null 2>&1 || die "$LOCAL_BINARY does not run on this machine"
  install -m 0755 "$LOCAL_BINARY" "$PREFIX/bin/norrd"
  local source stage; source=$(fetch_source); stage=$(mktemp -d)
  stage_source_support "$source" "$stage"
  install_support "$stage"
  rm -rf "${stage:?}"
}

install_source() {
  local source build compiler stage
  source=$(fetch_source)
  step "Installing build dependencies"
  if command -v apt-get >/dev/null 2>&1; then
    packages g++ cmake ninja-build pkg-config libsodium-dev libgnutls28-dev
  elif command -v dnf >/dev/null 2>&1; then
    packages gcc-c++ cmake ninja-build pkgconf-pkg-config libsodium-devel gnutls-devel
  else
    packages g++ cmake ninja pkgconf linux-headers libsodium-dev gnutls-dev
  fi
  compiler=$(command -v g++-14 || command -v g++-13 || command -v clang++ || command -v g++)
  step "Building from source with $(basename "$compiler")"
  build="$source/build-release"
  quiet env CXX="$compiler" cmake -S "$source" -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DNORR_BUILD_TESTS=OFF -DNORR_USE_NGTCP2=OFF
  quiet cmake --build "$build" --target norrd --parallel
  install -m 0755 "$build/norrd" "$PREFIX/bin/norrd"
  stage=$(mktemp -d)
  stage_source_support "$source" "$stage"
  install_support "$stage"
  rm -rf "${stage:?}"
}

printf '\n    %sInstalling Norr%s\n\n' "$B" "$R"

step "Checking system tools"
runtime_packages

case "$MODE" in
  local) step "Installing $LOCAL_BINARY"; install_local ;;
  source) install_source ;;
  release)
    step "Downloading Norr for linux-$ARCH${MIRROR:+ from $MIRROR}"
    install_release || { step "No release archive reachable; building instead"; install_source; }
    ;;
esac

step "Registering the services"
install -d -m 0700 /etc/norr
sed -i -e "s#/usr/local/bin#$PREFIX/bin#g" -e "s#/usr/local/lib#$PREFIX/lib#g" /etc/systemd/system/norr@.service
[[ -f /etc/systemd/system/norr-failover.service ]] && \
  sed -i "s#/usr/local/bin#$PREFIX/bin#g" /etc/systemd/system/norr-failover.service
systemctl daemon-reload

step "Tuning the network stack"
cat >/etc/sysctl.d/99-norr.conf <<SYSCTL
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.ip_forward = 1
SYSCTL
modprobe tcp_bbr >/dev/null 2>&1 || true
sysctl -q --system >/dev/null 2>&1 || true

good "Norr $("$PREFIX/bin/norrd" version | awk '{print $2}') is installed"
printf '\n    %sNext steps%s\n\n' "$B" "$R"
printf '      %sMenu%s     norr\n' "$MUTED" "$R"
printf '      %sServer%s   norr server --transport udp --forward 443\n' "$MUTED" "$R"
printf '      %sClient%s   norr client <code>\n\n' "$MUTED" "$R"

if [[ -t 0 && -t 1 ]]; then
  read -r -p "    Open the menu now? [Y/n] " answer
  case "${answer:-y}" in
    y | Y | "") exec "$PREFIX/bin/norr" ;;
  esac
fi
