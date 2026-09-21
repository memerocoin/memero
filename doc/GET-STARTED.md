# Get started with Memero (MEM)

Memero is a private, ASIC-friendly cryptocurrency with a fair,
Monero-style emission curve and a hard cap of 18.4 million MEM. This
guide gets you from zero to running a node and mining.

**No premine. No dev tax. No tail emission.**

---

## Quick facts

| | |
|---|---|
| Ticker | MEM |
| Max supply | 18,400,000 MEM |
| Block reward | `(18.4M − emitted) >> 19` (decays) |
| Block time | 5 minutes |
| PoW | SHA-3-256 (CPU/ASIC) |
| Privacy | CLSAG ring sigs, Bulletproofs, ring size 32 |
| Seed node | `107.172.243.15:50708` |
| Website / Explorer | https://memero.lol · https://explorer.memero.lol |
| Public RPC | https://node.memero.lol |

---

## 1. Build from source

```sh
# Ubuntu/Debian
sudo apt install -y cmake g++-13 git \
  libboost-system-dev libboost-serialization-dev libboost-program-options-dev \
  libsodium-dev nlohmann-json3-dev libtbb-dev rapidjson-dev

git clone https://github.com/memerocoin/memero.git
cd memero
mkdir build && cd build
CC=gcc-13 CXX=g++-13 cmake ..
make -j$(nproc)
```

Binaries land in `build/bin/`:
- `memerod` — daemon CLI
- `memerod-rpc` — RPC/P2P node
- `memero` — wallet CLI
- `memero-wallet-rpc` — non-custodial wallet JSON-RPC (for desktop/Android)

---

## 2. Run a node

```sh
./build/bin/memerod-rpc --data-dir ~/.memero
```

Connect to the seed node to sync:

```sh
./build/bin/memerod-rpc --data-dir ~/.memero --add-peer 107.172.243.15:50708
```

Your node is now part of the network. P2P is on port `50708`, RPC on `50709`.

---

## 3. Mine

Mining is SHA-3-256, CPU-friendly. Create a wallet to receive rewards:

```sh
./build/bin/memero --new ~/myminer-wallet --password "your-password"
# write down the 25-word seed, then note the printed address
```

Mine:

```sh
./build/bin/memerod-rpc \
  --data-dir ~/.memero-miner \
  --add-peer 107.172.243.15 \
  --mining-address <YOUR_WALLET_ADDRESS>
```

During the bootstrap phase difficulty is low enough to solo-mine on a
laptop. See [MINING.md](MINING.md) for WSL2-specific steps.

---

## 4. Use a wallet

Pick your flavor:

- **CLI** — `./build/bin/memero --open ~/mywallet` (create, send, receive).
- **Web wallet** — https://wallet.memero.lol (hosted/custodial).
- **Desktop** — the Electron app in `desktop/` (non-custodial; see
  [PACKAGING.md](PACKAGING.md)).
- **Android** — the Flutter app in `memerocoin/memero-wallet`
  (non-custodial; see [ANDROID.md](ANDROID.md)).

For self-custody, use CLI/desktop/Android — keys stay on your device.

---

## 5. Explore the chain

- **Block explorer:** https://explorer.memero.lol
- **Read-only RPC:** https://node.memero.lol

Example RPC call:

```sh
curl -s https://node.memero.lol/json_rpc \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":"0","method":"get_info"}'
```

---

## 6. Get involved

- Source: https://github.com/memerocoin/memero
- Run a node, mine, report issues, or build a service on the RPC.
