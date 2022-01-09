# Supported

## [Nix flakes](https://nixos.org/manual/nix/stable/command-ref/new-cli/nix3-flake.html)

### [Install nix flakes](https://nixos.wiki/wiki/Flakes#Installing_flakes)

### Build lolnero

```
nix build gitlab:lolnero/lolnero
```

Generated binaries will be in `./result/bin/`.

# Unsupported

## Build for the built-in OpenCL miner

1. Install [`opencl-headers`][1]
2. Install [`opencl-clhpp`][5]
2. Install [`ocl-icd`][2]
3. For AMD GPUs, install [`rocm-opencl-runtime`][3]. For NVIDIA GPUs, install [`opencl-nvidia`][4].
4. In the last command that involves `cmake`, do 

        cmake -DUSE_OPENCL=ON .. && make


### [Tutorial for Manjaro Linux][6]

[1]: https://archlinux.org/packages/extra/any/opencl-headers/
[2]: https://archlinux.org/packages/extra/x86_64/ocl-icd/
[3]: https://aur.archlinux.org/packages/rocm-opencl-runtime/
[4]: https://archlinux.org/packages/extra/x86_64/opencl-nvidia/
[5]: https://archlinux.org/packages/extra/any/opencl-clhpp/
[6]: https://bitcointalk.org/index.php?topic=5280570.msg58294497#msg58294497
