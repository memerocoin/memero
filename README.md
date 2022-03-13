Lolnero is a private and ASIC friendly cryptocurrency with a linear emission.

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
lolnerod-rpc --add-peer SOME_SEED_NODE_IP
```

[4]: https://en.wikipedia.org/wiki/SHA-3
[5]: https://eprint.iacr.org/2017/1066.pdf
[6]: https://eprint.iacr.org/2019/654.pdf
