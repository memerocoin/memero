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
* Confidential transaction type: Bulletproofs
* Ring signature type: CLSAG
* Ring size: 32


How to build
============

Debian 10.0 buster
------------------

```
sudo apt install git

git clone https://gitlab.com/fuwa/lolnero.git

mkdir lolnero/build
cd lolnero/build

sudo apt install build-essential cmake -y

sudo apt install \
libboost-all-dev \
libssl-dev \
libsodium-dev \
libreadline6-dev \
rapidjson-dev \
-y

cmake .. && make
```

Generated binaries will be in `bin/`.

Tor
===

To use Tor for everything, start the daemon like this

```
lolnerod \
--proxy public,127.0.0.1:9063 \
--proxy tor,127.0.0.1:9063
```
