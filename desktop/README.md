# Memero Desktop Wallet (non-custodial)

An Electron desktop wallet for Memero (MEM). **Non-custodial:** private keys
are generated and stored on *your* machine; only the daemon RPC is used for
network access.

## Architecture

```
Electron (main.js + wallet.html)
   └─ spawns memero-wallet-rpc (localhost:18082)
        └─ talks to memerod (default 127.0.0.1:50709, or MEMERO_DAEMON env)
```

The wallet private keys never leave your computer. `memero-wallet-rpc` links
the `wallet2` C++ wallet directly and signs transactions locally.

## Build

1. Build the `memero-wallet-rpc` binary (see top-level `README.md`), and place
   it in `desktop/bin/` (next to `main.js`) or on your `PATH`.

2. Install Electron:

   ```sh
   cd desktop
   npm install
   ```

3. Run:

   ```sh
   npm start
   ```

   Optionally point at a remote daemon:

   ```sh
   MEMERO_DAEMON=107.172.243.15:50709 npm start
   ```

## Package (distributable)

```sh
npm run dist
```

Produces an AppImage/deb (Linux), nsis installer (Windows), or dmg (macOS).
The `memero-wallet-rpc` binary in `desktop/bin/` is bundled automatically.

## Non-custodial caveats

- The wallet file + keys live on your machine (the path you provide).
- Back up your 25-word seed — it is the only way to recover funds.
- The bundled wallet backend is a single-wallet process; open one wallet at a
  time.
