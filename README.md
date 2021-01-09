Lolnero is a fork of Wownero with a linear emission and a SHA-3 PoW.

There is no premine and no dev tax.

Note
====

This network isn't really going anywhere, it's probably better to shut it down to prevent more wasted energy and save the hosting cost of the seed node. The seed node will be taken off line once hash rate disappears.


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
sudo apt install git build-essential cmake -y

sudo apt install \
libboost-dev \
libboost-date-time-dev \
libboost-filesystem-dev \
libboost-program-options-dev \
libboost-serialization-dev \
libboost-system-dev \
-y

sudo apt install \
libreadline6-dev \
libsodium-dev \
libssl-dev \
rapidjson-dev \
-y

git clone https://gitlab.com/fuwa/lolnero.git

mkdir lolnero/build
cd lolnero/build

cmake .. && make
```

Generated binaries will be in `bin/`.

Tor
===

To use Tor for everything, start the daemon like this

```
lolnerod \
--proxy public,127.0.0.1:9050 \
--proxy tor,127.0.0.1:9050
```
