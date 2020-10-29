# https://nixos.wiki/wiki/Cross_Compiling

let pkgs = import <nixpkgs> {
  crossSystem = (import <nixpkgs/lib>).systems.examples.mingwW64;
};
in
  pkgs.callPackage (
    { mkShell, cmake
    , boost
    , libsodium
    # , openssl
    # , readline
    # , rapidjson
    , }:
    mkShell {
      nativeBuildInputs = [ cmake ]; # you build dependencies here
      buildInputs = [
        boost
        libsodium
        # openssl
        # readline
        # rapidjson
      ]; # your dependencies here
    }
  ) {}
