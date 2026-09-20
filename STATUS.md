# Memero — fork of Lolnero

A revived, rebranded fork of Lolnero (Lolnero → fork of Wownero → fork of
Monero). This is an experiment to see how hard it is to fork and restart a
dead CryptoNote coin.

## Status: BUILDING & RUNNING

- Fork baseline: Lolnero `v0.9.10.75` (last tag where the `lolnerod`
  daemon still worked, pre-mid-2022 rewrite).
- Branch: `memero`
- Build: works on Ubuntu 24.04 + GCC 13 + Boost 1.83 (see `doc/BUILD.md`).
- Binaries: `memerod` (daemon), `memerod-rpc` (RPC daemon), `memero` (wallet).

## Changes from Lolnero

### Rebrand (commit `fae408bf2`)
- Name: Memero, ticker MEM
- mainnet address prefix `0x5d4a` / subaddress `0x1a8b3`
- testnet address prefix `0x5d4c` / subaddress `0x1a8b5`
- mainnet P2P/RPC ports 50708/50709, testnet 51708/51709
- new 16-byte network UUIDs
- signing domain separator `Memero_Tx_Output_Signatures_V1_`
- binary names: `lolnerod -> memerod`, `lolnerod-rpc -> memerod-rpc`,
  `lolnero -> memero`

### Consensus / emission (commit `abf42bb65`)
- Replaced flat 300/block reward with Monero-style exponential decay:
  `reward = (18,400,000 - emitted) >> 19`
- Hard cap: 18,400,000 MEM (no tail emission)
- ~90% emitted in ~11.5 years (5-min blocks)
- Kept: SHA-3-256 PoW, 5-min blocks, LWMA-1 difficulty, ring size 32,
  CLSAG, Bulletproofs, 60-block coinbase unlock.

### Build fixes (commit `455c67874`)
- GCC 13 requires explicit includes (the codebase targeted GCC 11).
- Added RapidJSON + TBB linkage for non-Nix (apt) builds.

## Known follow-ups (TODO)

1. **Regenerate genesis block (optional, cosmetic).** The current genesis
   blob is Lolnero's original; its coinbase is a standard Monero-family
   sentinel placeholder (`2^40 - 1` atomic units) paid to an unspendable
   output. It is *not* consensus-critical (height 0 bypasses reward
   validation) and does not block launching. The genesis hash is
   deterministic (`a2be2680...`). For aesthetic completeness one could
   regenerate a fresh coinbase tx + nonce, but it is not required.

2. **Checkpoints: none.** There are no hardcoded checkpoint or
   difficulty-check maps in this codebase (the old Monero checkpoint
   system was already removed upstream). Nothing to wipe.

3. **Mobile wallet / seed app.** The separate `fuwa/lolnero-wallet` and
   `fuwa/lolnero-seed` repos (Flutter Android) need rebrand + re-pointing
   to `memerod-rpc` if you want them.

4. **Bootstrap the network.** All Lolnero seed nodes (incl. 89.58.35.252)
   are offline. A revival means launching a fresh chain and providing your
   own seed nodes.

## Chain identity (summary)

| | mainnet | testnet |
|---|---|---|
| address prefix | 0x5d4a | 0x5d4c |
| subaddress prefix | 0x1a8b3 | 0x1a8b5 |
| P2P port | 50708 | 51708 |
| RPC port | 50709 | 51709 |

## License / attribution

Memero retains the upstream copyright headers of Monero/Wownero/Lolnero.
Lolnero was authored by fuwa (fuwa25519@protonmail.com). This fork is an
independent experiment and is not affiliated with the original project.
