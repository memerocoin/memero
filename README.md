Lolnero is a code fork of the cryptocurreny [Wownero][2], but with a
linear emission and an ASIC friendly proof of work.

There is no premine and no dev tax.


Why
===

The goal of Lolnero is to replace `C/C++` with a safer language, and
to not hardfork.


Specifications
==============

* Proof of Work: [SHA-3-256][4]
* Max supply: ∞
* Block reward: 300
* Block time: 5 minutes
* Block size limit: Block height bytes (linearly increasing)
* Range proof: [Bulletproofs][5]
* Ring signature: [CLSAG (Concise Linkable Spontaneous Anonymous
  Group)][6]
* Ring size: 32


# [How to build](doc/BUILD.md)

# [Seed nodes](https://gitlab.com/lolnero/lolnero/-/wikis/Seed-nodes)

# How to connect to the network

```
lolnerod-rpc-cpp --seed-node SOME_SEED_NODE_IP
```

[1]: https://en.wikipedia.org/wiki/Cryptocurrency
[2]: https://wownero.org/
[3]: https://en.wikipedia.org/wiki/Proof_of_work
[4]: https://en.wikipedia.org/wiki/SHA-3
[5]: https://eprint.iacr.org/2017/1066.pdf
[6]: https://eprint.iacr.org/2019/654.pdf
