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
* Block size limit: 4 MB
* Confidential transaction: Bulletproofs
* Ring signature: CLSAG
* Ring size: 32


How to build
============

Debian testing (for gcc9)
-------------------------

```
sudo apt install git build-essential cmake -y

sudo apt install \
libboost-dev \
libboost-date-time-dev \
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
