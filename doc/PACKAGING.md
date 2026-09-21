# Packaging Memero wallets

This documents how to produce installable wallet artifacts. The native
backend (`memero-wallet-rpc`) and the UI are already built; this is the
"turn source into files users can download and run" step.

> Most packaging requires the relevant OS/toolchain (Android SDK, Flutter,
> or the target desktop OS). The hard C++ cross-compile is already done and
> documented in [ANDROID.md](ANDROID.md).

## Where the pieces live

| Piece | Repo / path |
|---|---|
| Node/daemon + wallet C++ | `memerocoin/memero` (`src/`, build via `BUILD.md`) |
| Wallet backend (`memero-wallet-rpc`) | built from `memerocoin/memero` |
| Desktop wallet (Electron) | `memerocoin/memero/desktop/` |
| Android wallet (Flutter) | `memerocoin/memero-wallet` |
| Seed generator (Flutter) | `memerocoin/memero-seed` |

---

## 1. Desktop wallet (Electron)

Produces `.AppImage`/`.deb` (Linux), `.exe` (Windows), `.dmg` (macOS).

### Prerequisites
- Node.js 18+ and npm
- A compiled `memero-wallet-rpc` binary placed in `desktop/bin/`
  (see `BUILD.md` for how to compile it; the Electron app bundles this
  directory verbatim).

### Build packages

```sh
cd memero/desktop
npm install            # installs Electron + electron-builder
npm run dist           # builds packages for the *current* OS
```

`electron-builder` config is already in `desktop/package.json` (targets:
AppImage + deb on Linux, nsis on Windows, dmg on macOS).

### Important per-OS notes
- **Windows `.exe`** must be built **on Windows** (or a Windows cross
  toolchain), and you need a Windows `memero-wallet-rpc.exe` in `desktop/bin/`.
- **macOS `.dmg`** must be built **on macOS** with Xcode, and you need a
  `memero-wallet-rpc` macOS binary.
- The C++ wallet cross-compile for each OS is the same kind of NDK/GCC work
  as the Android path (see `ANDROID.md`) — do it on the target OS.

---

## 2. Android APK (Flutter)

### Prerequisites (on a machine with Flutter + Android SDK)
- Flutter SDK (stable channel)
- Android SDK + build-tools 30+
- The ARM64 `memero-wallet-rpc` binary (see `ANDROID.md` — **already built**)

### Steps

```sh
# 1. Place the native backend where Flutter bundles it
mkdir -p memero-wallet/android/app/src/main/jniLibs/arm64-v8a
cp /path/to/build-android/bin/memero-wallet-rpc \
   memero-wallet/android/app/src/main/jniLibs/arm64-v8a/libmemero-rpc.so

# 2. Build the APK
cd memero-wallet
flutter pub get
flutter build apk --release
```

Output: `build/app/outputs/flutter-apk/app-release.apk`.

Sign it (for Play Store) with a keystore, otherwise it uses a debug key.

---

## 3. iOS (later)

iOS requires macOS + Xcode, and a `memero-wallet-rpc` binary cross-compiled
for `arm64-apple-ios`. Not buildable on Linux. Defer until a Mac is available.
