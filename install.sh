#!/usr/bin/env bash
set -euo pipefail

REPOSITORY="${NORR_REPOSITORY:-Theok09/norr}"
PREFIX="${PREFIX:-/usr/local}"
FROM_SOURCE=no
[[ "${1:-}" == "--from-source" ]] && FROM_SOURCE=yes

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
  *) ARCH=""; FROM_SOURCE=yes ;;
esac

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
  (( ${#missing[@]} == 0 )) && return
  if command -v dnf >/dev/null 2>&1; then
    missing=("${missing[@]/iproute2/iproute}")
    missing=("${missing[@]/iputils-ping/iputils}")
  fi
  packages "${missing[@]}"
}

install_binary() {
  local work; work=$(mktemp -d)
  local base="https://github.com/$REPOSITORY/releases/latest/download/norr-linux-$ARCH.tar.gz"
  curl -fsSL "$base" -o "$work/norr.tar.gz" || return 1
  curl -fsSL "$base.sha256" -o "$work/norr.tar.gz.sha256" || return 1
  (cd "$work" && sed "s/norr-linux-$ARCH.tar.gz/norr.tar.gz/" norr.tar.gz.sha256 | sha256sum -c --quiet -) \
    || die "Checksum mismatch; download refused"
  tar -xzf "$work/norr.tar.gz" -C "$work"
  install -m 0755 "$work/norr-linux-$ARCH/norrd" "$PREFIX/bin/norrd"
  install -m 0755 "$work/norr-linux-$ARCH/norr" "$PREFIX/bin/norr"
  install -D -m 0755 "$work/norr-linux-$ARCH/norr-quick" "$PREFIX/lib/norr/norr-quick"
  install -m 0644 "$work/norr-linux-$ARCH/norr@.service" /etc/systemd/system/norr@.service
  rm -rf "$work"
}

install_source() {
  local source build
  if [[ -f "$(dirname "${BASH_SOURCE[0]}")/CMakeLists.txt" ]]; then
    source="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  else
    source=$(mktemp -d)
    curl -fsSL "https://codeload.github.com/$REPOSITORY/tar.gz/refs/heads/main" | tar -xz --strip-components=1 -C "$source"
  fi
  step "Installing build dependencies"
  if command -v apt-get >/dev/null 2>&1; then
    packages g++ cmake ninja-build pkg-config libsodium-dev libssl-dev libgnutls28-dev
  elif command -v dnf >/dev/null 2>&1; then
    packages gcc-c++ cmake ninja-build pkgconf-pkg-config libsodium-devel openssl-devel gnutls-devel
  else
    packages g++ cmake ninja pkgconf linux-headers libsodium-dev openssl-dev gnutls-dev
  fi
  step "Building from source"
  build="$source/build-release"
  quiet cmake -S "$source" -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DNORR_BUILD_TESTS=OFF
  quiet cmake --build "$build" --target norrd --parallel
  install -m 0755 "$build/norrd" "$PREFIX/bin/norrd"
  install -m 0755 "$source/scripts/norr" "$PREFIX/bin/norr"
  install -D -m 0755 "$source/scripts/norr-quick" "$PREFIX/lib/norr/norr-quick"
  install -m 0644 "$source/deployment/systemd/norr@.service" /etc/systemd/system/norr@.service
}

printf '\n    %sInstalling Norr%s\n\n' "$B" "$R"

step "Checking system tools"
runtime_packages

if [[ $FROM_SOURCE == no ]]; then
  step "Downloading Norr for linux-$ARCH"
  install_binary || { step "No release binary available; building instead"; install_source; }
else
  install_source
fi

step "Registering the service"
install -d -m 0700 /etc/norr
sed -i -e "s#/usr/local/bin#$PREFIX/bin#g" -e "s#/usr/local/lib#$PREFIX/lib#g" /etc/systemd/system/norr@.service
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
printf '      %sServer%s   norr server --forward 443\n' "$MUTED" "$R"
printf '      %sClient%s   norr client <code>\n\n' "$MUTED" "$R"
