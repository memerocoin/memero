# Maintainer: wowario <wowario[at]protonmail[dot]com>

pkgname=lolnero-git
pkgver=0.8.0.0
pkgrel=1
pkgdesc="Lolnero: a fairly launched privacy-centric meme coin with no premine and a finite supply"
license=('BSD')
arch=('x86_64')
url="https://lolnero.org/"
depends=('boost-libs' 'libunwind' 'openssl' 'readline' 'zeromq' 'pcsclite' 'hidapi' 'protobuf')
makedepends=('git' 'cmake' 'boost')
source=(
    "${pkgname}"::"git+https://github.com/lolnero/lolnero#tag=v${pkgver}"
    "git+https://github.com/monero-project/unbound.git"
    "git+https://github.com/monero-project/miniupnp.git"
    "git+https://github.com/Tencent/rapidjson.git"
    "git+https://github.com/trezor/trezor-common.git"
    "git+https://github.com/lolnero/RandomWOW.git"
    "lolnero.sysusers"
    "lolnero.tmpfiles")
sha512sums=('SKIP'
            'SKIP'
            'SKIP'
            'SKIP'
            'SKIP'
            'SKIP'
            'SKIP'
            'SKIP')

prepare() {
  cd "${pkgname}"
  git submodule init
  git config submodule.external/unbound.url "$srcdir/unbound"
  git config submodule.external/miniupnp.url "$srcdir/miniupnp"
  git config submodule.external/rapidjson.url "$srcdir/rapidjson"
  git config submodule.external/RandomWOW.url "$srcdir/RandomWOW"
  git submodule update
}

build() {
  cd "${pkgname}"
  mkdir -p build && cd build
  cmake -D BUILD_TESTS=OFF -D CMAKE_BUILD_TYPE=release -D ARCH=default ../
  make
}

package() {
  backup=('etc/lolnerod.conf')

  cd "${pkgname}"
  install -Dm644 "LICENSE" -t "${pkgdir}/usr/share/licenses/${pkgname}"

  install -Dm644 "utils/conf/lolnerod.conf" "${pkgdir}/etc/lolnerod.conf"
  install -Dm644 "utils/systemd/lolnerod.service" "${pkgdir}/usr/lib/systemd/system/lolnerod.service"
  install -Dm644 "../lolnero.sysusers" "${pkgdir}/usr/lib/sysusers.d/lolnero.conf"
  install -Dm644 "../lolnero.tmpfiles" "${pkgdir}/usr/lib/tmpfiles.d/lolnero.conf"

  install -Dm755 "build/bin/lolnero-wallet-cli" \
                 "build/bin/lolnero-wallet-rpc" \
                 "build/bin/lolnerod" \
                 -t "${pkgdir}/usr/bin"
}

# vim: ts=2 sw=2 et:
