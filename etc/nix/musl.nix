# https://nixos.wiki/wiki/Cross_Compiling

let pkgs = (import <nixpkgs> {})
; in

pkgs.pkgsMusl.callPackage
(
  { mkShell
  , cmake
  , boost175
  , libsodium
  , openssl
  , readline
  , rapidjson
  , }:
  mkShell {
    nativeBuildInputs = [ cmake ];
    buildInputs = [
      boost175
      libsodium
      openssl
      readline
      rapidjson
    ];

    CMakeFlags_Lolnero = ''
      -DReadline_ROOT_DIR=${readline.dev}
    '';
  }
) {}
