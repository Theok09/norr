#!/bin/sh
set -eu

VERSION="${VERSION:-0.2.0}"
GNUTLS_VERSION=3.8.9
NGTCP2_VERSION=1.12.0
SOURCE=/src
OUT=/out
DEPS=/opt/static

apk add --no-cache build-base cmake ninja pkgconf linux-headers curl xz \
  libsodium-dev libsodium-static openssl-dev openssl-libs-static \
  nettle-dev nettle-static gmp-dev gmp-static >/dev/null

mkdir -p /build && cd /build

curl -fsSL "https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-$GNUTLS_VERSION.tar.xz" | tar -xJ
cd "gnutls-$GNUTLS_VERSION"
./configure --prefix="$DEPS" --enable-static --disable-shared --with-included-libtasn1 \
  --with-included-unistring --without-p11-kit --without-idn --without-brotli --without-zstd \
  --without-zlib --without-tpm --without-tpm2 --disable-doc --disable-tests --disable-tools \
  --disable-cxx --disable-nls --disable-guile >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null
cd /build

curl -fsSL "https://github.com/ngtcp2/ngtcp2/releases/download/v$NGTCP2_VERSION/ngtcp2-$NGTCP2_VERSION.tar.xz" | tar -xJ
cmake -S "ngtcp2-$NGTCP2_VERSION" -B ngtcp2-build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="$DEPS" -DCMAKE_PREFIX_PATH="$DEPS" -DENABLE_GNUTLS=ON \
  -DENABLE_OPENSSL=OFF -DENABLE_STATIC_LIB=ON -DENABLE_SHARED_LIB=OFF -DBUILD_TESTING=OFF \
  -DENABLE_LIB_ONLY=ON >/dev/null
cmake --build ngtcp2-build >/dev/null
cmake --install ngtcp2-build >/dev/null

export PKG_CONFIG_PATH="$DEPS/lib/pkgconfig:$DEPS/lib64/pkgconfig"
cmake -S "$SOURCE" -B norr-build -G Ninja -DCMAKE_BUILD_TYPE=Release -DNORR_STATIC=ON \
  -DNORR_BUILD_TESTS=OFF -DCMAKE_EXE_LINKER_FLAGS="-static" >/dev/null
cmake --build norr-build --target norrd >/dev/null
strip norr-build/norrd

case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64) arch=arm64 ;;
  *) arch=$(uname -m) ;;
esac
name="norr-linux-$arch"
mkdir -p "$OUT/$name"
cp norr-build/norrd "$OUT/$name/norrd"
cp "$SOURCE/scripts/norr" "$SOURCE/scripts/norr-quick" "$OUT/$name/"
cp "$SOURCE/deployment/systemd/norr@.service" "$OUT/$name/"
cp "$SOURCE/LICENSE" "$OUT/$name/"
tar -C "$OUT" -czf "$OUT/$name.tar.gz" "$name"
(cd "$OUT" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
rm -rf "$OUT/${name:?}"
norr-build/norrd features
