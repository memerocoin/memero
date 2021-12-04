## Alpine

```
sudo apk add build-base cmake git
sudo apk add boost-dev libsodium-dev openssl-dev rapidjson-dev

git clone https://gitlab.com/lolnero/lolnero.git

mkdir lolnero/build
cd lolnero/build

cmake .. && make
```

Generated binaries will be in `./bin/`.


## Arch

```
sudo pacman -S base-devel cmake git
sudo pacman -S boost libsodium openssl rapidjson

git clone https://gitlab.com/lolnero/lolnero.git

mkdir lolnero/build
cd lolnero/build

cmake .. && make
```

Generated binaries will be in `./bin/`.


## Debian 11 "Bullseye"

```
sudo apt install build-essential cmake git

sudo apt install libboost-dev

sudo apt install \
libboost-program-options-dev \
libboost-serialization-dev \
libboost-system-dev

sudo apt install \
libsodium-dev \
libssl-dev \
rapidjson-dev

git clone https://gitlab.com/lolnero/lolnero.git

mkdir lolnero/build
cd lolnero/build

cmake .. && make
```

Generated binaries will be in `./bin/`.


## Gentoo

```
sudo emerge \
dev-util/cmake \
dev-vcs/git

sudo emerge \
dev-libs/boost \
dev-libs/libsodium \
dev-libs/openssl \
dev-libs/rapidjson

git clone https://gitlab.com/lolnero/lolnero.git

mkdir lolnero/build
cd lolnero/build

cmake .. && make
```

Generated binaries will be in `./bin/`.


## Build for the built-in OpenCL miner

1. Install [`opencl-headers`][1]
2. Install [`ocl-icd`][2]
3. For AMD GPUs, install [`rocm-opencl-runtime`][3]. For NVIDIA GPUs, install [`opencl-nvidia`][4].
4. In the last command that involves `cmake`, do 

        cmake -DUSE_OPENCL=ON .. && make


[1]: https://archlinux.org/packages/extra/any/opencl-headers/
[2]: https://archlinux.org/packages/extra/x86_64/ocl-icd/
[3]: https://aur.archlinux.org/packages/rocm-opencl-runtime/
[4]: https://archlinux.org/packages/extra/x86_64/opencl-nvidia/

### [Tutorial for Manjaro Linux][5]

[5]: https://bitcointalk.org/index.php?topic=5280570.msg58294497#msg58294497
