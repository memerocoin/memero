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


How to build
============

Debian testing (for gcc10)
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

Android
=======

Node
----
<a href='https://play.google.com/store/apps/details?id=org.lolnero.node'><img alt='Get it on Google Play' src='https://play.google.com/intl/en_us/badges/images/generic/en_badge_web_generic.png' height='80'/></a>

Seed generator
--------------
<a href='https://play.google.com/store/apps/details?id=org.lolnero.lolnero_seed'><img alt='Get it on Google Play' src='https://play.google.com/intl/en_us/badges/images/generic/en_badge_web_generic.png' height='80'/></a>

Wallet
------
<a href='https://play.google.com/store/apps/details?id=org.lolnero.lolnero_wallet'><img alt='Get it on Google Play' src='https://play.google.com/intl/en_us/badges/images/generic/en_badge_web_generic.png' height='80'/></a>
