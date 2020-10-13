Lolnero is a fork of Wownero with a linear emission and a SHA-3 PoW.

There is no premine and no dev tax.


Why
===

The goal of Lolnero is to replace `C/C++` with a safer language, and to not hardfork.

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

cmake .. -DMANUAL_SUBMODULES=1
make
```

Generated binaries will be in `bin/`.
