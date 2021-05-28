Lolnero is a fork of Wownero with a linear emission and a SHA-3 PoW.

There is no premine and no dev tax.


Why
===

The goal of Lolnero is to replace `C/C++` with a safer language, and to not hardfork.


Specifications
==============

* Proof of Work: SHA-3
* Max supply: ∞
* Block reward: 300
* Block time: 5 minutes
* Block size limit: max(128k, Block height) bytes
* Confidential transaction: Bulletproofs
* Ring signature: CLSAG
* Ring size: 32


# [How to build](https://lolnero.org/build.html)

# Seed nodes

Here are some nodes run by the community:

* `128.199.161.251` by fuwa

# How to connect to the network

```
lolnerod --seed-node SOME_SEED_NODE_IP
```

