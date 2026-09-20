# Memero (MEM)

A private, ASIC-friendly cryptocurrency with a fair, Monero-style emission
curve and a hard supply cap.

There is **no premine** and **no dev tax**.

Memero is a revived fork of [Lolnero](https://gitlab.com/lolnero/lolnero)
(which itself forked from Wownero, which forked from Monero). The original
Lolnero project was abandoned in 2022; this project restarts it as an
independent experiment under a new name, new network identity, and a fairer
emission schedule.

## Status

**Building and runnable.** The daemon (`memerod`), RPC daemon
(`memerod-rpc`), and wallet (`memero`) compile and run. A fresh chain
bootstraps from a deterministic genesis block. See [`STATUS.md`](STATUS.md).

## Specifications

| Parameter | Value |
|---|---|
| Proof of Work | [SHA-3-256](https://en.wikipedia.org/wiki/SHA-3) (ASIC-friendly) |
| Max supply | **18,400,000 MEM** (hard cap) |
| Block reward | `(18,400,000 - emitted) >> 19` (Monero-style decay) |
| ~90% emitted in | ~11.5 years |
| Block time | 5 minutes |
| Difficulty algorithm | LWMA-1 |
| Block size limit | `max(128 kB, height)` bytes, linearly increasing |
| Range proof | [Bulletproofs](https://eprint.iacr.org/2017/1066.pdf) |
| Ring signature | [CLSAG](https://eprint.iacr.org/2019/654.pdf), ring size 32 |
| Coinbase unlock | 60 blocks |

## Build

Dependencies (Ubuntu/Debian): `cmake`, `g++-13`, `libboost1.83-dev`
(`system`, `serialization`, `program_options`), `libsodium-dev`,
`nlohmann-json3-dev`, `libtbb-dev`, `rapidjson-dev`.

```sh
sudo apt install -y cmake g++-13 \
  libboost-system-dev libboost-serialization-dev libboost-program-options-dev \
  libsodium-dev nlohmann-json3-dev libtbb-dev rapidjson-dev

mkdir build && cd build
CC=gcc-13 CXX=g++-13 cmake ..
make -j$(nproc)
```

Binaries are produced in `build/bin/`:
- `memerod` — interactive daemon CLI
- `memerod-rpc` — RPC/P2P daemon (the actual node)
- `memero` — wallet CLI

Alternatively, build with the project's [Nix](https://nixos.org) flake
(`nix build .`).

## Network

| | mainnet | testnet |
|---|---|---|
| address prefix | `0x5d4a` | `0x5d4c` |
| subaddress prefix | `0x1a8b3` | `0x1a8b5` |
| P2P port | 50708 | 51708 |
| RPC port | 50709 | 51709 |
| wallet RPC port | 45680 | 45680 |

## Run a node

```sh
./build/bin/memerod-rpc --data-dir ~/.memero
```

To add a peer:

```sh
./build/bin/memerod-rpc --add-peer <SEED_NODE_IP>
```

### Seed node

The primary Memero seed node runs at:

```
107.172.243.15:50708
```

Connect to it with:

```sh
./build/bin/memerod-rpc --add-peer 107.172.243.15
```

## Run the wallet

```sh
./build/bin/memero --daemon-address localhost:50709
```

## Mining

See [doc/MINING.md](doc/MINING.md) for how to solo-mine the bootstrap phase.

## License

Memero retains the upstream copyright headers of Monero / Wownero / Lolnero.
Lolnero was authored by fuwa. This fork is an independent experiment and is
not affiliated with the original project.
