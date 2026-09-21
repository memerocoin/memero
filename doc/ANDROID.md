# Android Wallet — build the Memero ARM64 native backend

This documents how to cross-compile the non-custodial `memero-wallet-rpc`
backend for Android ARM64 (AArch64), the required native piece for the
Android wallet APK.

## Status

**Verified working.** On an Ubuntu 24.04 box (2 GB RAM) we produced a genuine
Android ARM64 ELF (`memero-wallet-rpc`, AArch64, `/system/bin/linker64`)
using NDK r26c + clang 17.

The heavyweight dependency cross-compile (Boost + libsodium) is the slow
part; on a machine with more RAM it goes faster but it works on 2 GB too.

## 1. Prerequisites

- `curl`, `unzip`, `cmake`, `g++-13`
- `libssl-dev`, `rapidjson-dev`, `nlohmann-json3-dev` (header-only, used by host)

## 2. Download Android NDK r26c

```sh
mkdir -p /tmp/ndk26
cd /tmp
curl -sL -o ndk26.zip https://dl.google.com/android/repository/android-ndk-r26c-linux.zip
unzip -q ndk26.zip -d /tmp/ndk26
# => /tmp/ndk26/android-ndk-r26c
```

## 3. Cross-compile libsodium (ARM64)

```sh
export NDK=/tmp/ndk26/android-ndk-r26c
export TOOLCHAIN=$NDK/toolchains/llvm/prebuilt/linux-x86_64
mkdir -p /opt/memero-android && cd /opt/memero-android
curl -sL -o libsodium.tar.gz https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz
tar xzf libsodium.tar.gz && cd libsodium-1.0.18
./configure --host=aarch64-linux-android --prefix=/opt/memero-android/out \
  CC=$TOOLCHAIN/bin/aarch64-linux-android21-clang \
  CXX=$TOOLCHAIN/bin/aarch64-linux-android21-clang++ \
  AR=$TOOLCHAIN/bin/llvm-ar RANLIB=$TOOLCHAIN/bin/llvm-ranlib
make -j2 && make install
```

## 4. Cross-compile Boost 1.83 (ARM64)

```sh
cd /opt/memero-android
curl -sL -o boost.tar.gz https://archives.boost.io/release/1.83.0/source/boost_1_83_0.tar.gz
tar xzf boost.tar.gz && cd boost_1_83_0

# bootstrap b2 with -fcommon (GCC 10+ fix)
./bootstrap.sh --with-toolset=gcc --with-libraries=system,serialization,program_options,filesystem
cd tools/build/src/engine && g++ -fcommon -DNDEBUG \
  builtins.cpp class.cpp command.cpp compile.cpp constants.cpp cwd.cpp debug.cpp \
  debugger.cpp execcmd.cpp execnt.cpp execunix.cpp filesys.cpp filent.cpp fileunix.cpp \
  frames.cpp function.cpp glob.cpp hash.cpp hcache.cpp hdrmacro.cpp headers.cpp \
  jam_strings.cpp jam.cpp jamgram.cpp lists.cpp make.cpp make1.cpp md5.cpp mem.cpp \
  modules.cpp native.cpp object.cpp option.cpp output.cpp parse.cpp pathnt.cpp \
  pathsys.cpp pathunix.cpp regexp.cpp rules.cpp scan.cpp search.cpp startup.cpp \
  subst.cpp sysinfo.cpp timestamp.cpp variable.cpp w32_getreg.cpp \
  modules/order.cpp modules/path.cpp modules/property-set.cpp modules/regex.cpp \
  modules/sequence.cpp modules/set.cpp -o b2
cp b2 ../../
cd /opt/memero-android/boost_1_83_0

# user-config for Android clang
cat > ~/user-config.jam <<EOF
using clang : android : $TOOLCHAIN/bin/aarch64-linux-android21-clang++ ;
EOF

./b2 --user-config=$HOME/user-config.jam toolset=clang-android target-os=android \
  architecture=arm address-model=64 link=static variant=release threading=multi \
  --with-system --with-serialization --with-program_options --with-filesystem \
  --prefix=/opt/memero-android/out install
```

## 5. Copy header-only deps into the android prefix

```sh
cp -r /usr/include/nlohmann /opt/memero-android/out/include/
cp -r /usr/include/rapidjson /opt/memero-android/out/include/
```

## 6. Cross-compile memero-wallet-rpc

```sh
cd /path/to/memero-src
mkdir build-android && cd build-android
cmake -DCMAKE_TOOLCHAIN_FILE=/opt/memero-android/toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release -DUSE_TBB=OFF ..
make -j2 memero-wallet-rpc
```

`toolchain.cmake` (see `doc/android-toolchain.cmake` in this repo):

```cmake
set(CMAKE_SYSTEM_NAME Android)
set(CMAKE_SYSTEM_VERSION 21)
set(CMAKE_ANDROID_ARCH_ABI arm64-v8a)
set(CMAKE_ANDROID_NDK /tmp/ndk26/android-ndk-r26c)
set(CMAKE_ANDROID_STL_TYPE c++_static)
set(CMAKE_ANDROID_NDK_TOOLCHAIN_VERSION clang)
set(CMAKE_PREFIX_PATH /opt/memero-android/out)
set(CMAKE_INCLUDE_PATH /opt/memero-android/out/include)
set(CMAKE_LIBRARY_PATH /opt/memero-android/out/lib)
set(Boost_NO_SYSTEM_PATHS ON)
set(Boost_NO_BOOST_CMAKE ON)
set(BOOST_ROOT /opt/memero-android/out)
set(Boost_INCLUDE_DIR /opt/memero-android/out/include)
set(Boost_LIBRARY_DIR /opt/memero-android/out/lib)
set(Boost_USE_STATIC_LIBS ON)
set(SODIUM_LIBRARY /opt/memero-android/out/lib/libsodium.a)
set(SODIUM_INCLUDE_DIR /opt/memero-android/out/include)
set(nlohmann_json_DIR /usr/share/cmake/nlohmann_json)
```

The result is `build-android/bin/memero-wallet-rpc`, an ARM64 ELF that runs on
Android and talks to the Memero daemon.

## 7. Bundle into an APK (next step)

The Flutter Android app (`lolnero-wallet`, to be rebranded) places this binary
into `android/app/src/main/jniLibs/arm64-v8a/` and loads it at runtime. Build
the APK with `flutter build apk` on a machine with the Flutter SDK + Android
SDK.

## Notes

- `USE_TBB=OFF` and the `std::execution::seq` change are already committed;
  the wallet does not need TBB.
- libsodium and Boost are static-linked; nlohmann-json and rapidjson are
  header-only.
