# Mining Memero

Memero uses SHA-3-256 proof-of-work. During the bootstrap phase (the
first ~147 blocks), difficulty is fixed low at `2^20` so a single hobbyist
miner can solo-mine; after that, LWMA-1 difficulty takes over.

## Solo-mining on a Windows laptop (WSL2)

This is the recommended way to mine the bootstrap phase.

### 1. Install WSL2 + Ubuntu

- Enable WSL2 (PowerShell as admin): `wsl --install -d Ubuntu-24.04`
- Open the Ubuntu terminal.

### 2. Install build dependencies

```sh
sudo apt update
sudo apt install -y build-essential cmake g++-13 git \
  libboost-system-dev libboost-serialization-dev \
  libboost-program-options-dev libsodium-dev nlohmann-json3-dev \
  libtbb-dev rapidjson-dev
```

### 3. Clone and build

```sh
git clone https://github.com/memerocoin/memero.git
cd memero
mkdir build && cd build
CC=gcc-13 CXX=g++-13 cmake ..
make -j$(nproc)
```

### 4. Create a wallet (to receive mining rewards)

```sh
./build/bin/memero --new /path/to/wallet --password "your-password"
```

Write down the 25-word seed. The wallet will print the mining address.

### 5. Mine

```sh
./build/bin/memerod-rpc \
  --add-peer 107.172.243.15 \
  --mining-address <YOUR_WALLET_ADDRESS> \
  --data-dir ~/.memero
```

The daemon will connect to the seed node, sync, and mine blocks into your
wallet address. Keep the terminal open (or run it in `tmux`/`screen`).

### Notes

- **Don't let the laptop sleep** while mining, or it'll stop hashing.
- **Windows Defender** may flag the miner binary; add an exclusion for the
  `build/` folder if needed.
- The seed node is relay-only (it does not mine). Mining is intended to run
  on your own hardware, not the seed node.
- Once more miners join, difficulty rises and solo mining becomes
  competitive; consider pointing additional hardware at the chain.
