#!/bin/sh
# Build and install Norr, create its service account, and lay out /etc/norr.
#
# Deliberately does not start the service or write a configuration: a tunnel
# with no peers and no keys has nothing to start, and generating a key without
# being asked would leave a secret on disk the operator did not expect.
set -eu

PREFIX="${PREFIX:-/usr}"
BUILD_DIR="${BUILD_DIR:-build}"

say()  { printf '%s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = "Linux" ] || die "Norr's datapath is Linux-only"

if [ "$(id -u)" -ne 0 ]; then
  die "run as root, or with sudo"
fi

if command -v apt-get >/dev/null 2>&1; then
  say "installing build dependencies"
  apt-get update -qq
  apt-get install -y -qq cmake ninja-build pkg-config \
    libsodium-dev libgnutls28-dev libngtcp2-dev libngtcp2-crypto-gnutls-dev
elif command -v dnf >/dev/null 2>&1; then
  say "installing build dependencies"
  dnf install -y -q cmake ninja-build pkgconf-pkg-config \
    libsodium-devel gnutls-devel libngtcp2-devel
else
  say "unknown package manager; assuming the toolchain and libraries are present"
fi

command -v cmake >/dev/null 2>&1 || die "cmake not found"

say "building"
cmake -S . -B "$BUILD_DIR" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" >/dev/null
cmake --build "$BUILD_DIR" --parallel >/dev/null

say "running the test suite"
ctest --test-dir "$BUILD_DIR" --output-on-failure >/dev/null \
  || die "tests failed; refusing to install"

say "installing to $PREFIX"
cmake --install "$BUILD_DIR" >/dev/null

# The unit runs as this user. It owns nothing but its own state directory;
# CAP_NET_ADMIN is granted ambiently for the TUN device and dropped after.
if ! getent passwd norr >/dev/null 2>&1; then
  say "creating the norr service account"
  useradd --system --no-create-home --shell /usr/sbin/nologin norr
fi

mkdir -p /etc/norr
chown root:norr /etc/norr
chmod 0750 /etc/norr

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi

cat <<EOF

Installed. Next:

  1. Generate a key
       sudo sh -c 'norr keygen > /etc/norr/private.key'
       sudo chown root:norr /etc/norr/private.key
       sudo chmod 0640 /etc/norr/private.key

  2. Write a configuration
       sudo cp $PREFIX/share/doc/norr/norr.toml.example /etc/norr/norr.toml
       sudo norr check /etc/norr/norr.toml

  3. Start it
       sudo systemctl enable --now norr

Norr does not configure the interface address or routes; see the README.
EOF
