Memero is a private and ASIC friendly cryptocurrency.

There is no premine and no dev tax.


Why
===

Memero is a revived fork of Lolnero (which itself forked from Wownero,
which forked from Monero). The goal is to provide a private, ASIC
friendly chain with a fair, Monero-style emission curve and a hard
supply cap.


Specifications
==============

* Proof of Work: [SHA-3-256][4]
* Max supply: 18,400,000 MEM (hard cap)
* Block reward: `(18,400,000 - emitted) >> 19` (Monero-style decay)
* Block time: 5 minutes
* Block size limit: Block height bytes (linearly increasing)
* Range proof: [Bulletproofs][5]
* Ring signature: [CLSAG (Concise Linkable Spontaneous Anonymous
  Group)][6]
* Ring size: 32


# [How to build](doc/BUILD.md)

# How to connect to the network

```
memerod-rpc --add-peer SOME_SEED_NODE_IP
```

[4]: https://en.wikipedia.org/wiki/SHA-3
[5]: https://eprint.iacr.org/2017/1066.pdf
[6]: https://eprint.iacr.org/2019/654.pdf
