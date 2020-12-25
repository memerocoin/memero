# https://stackoverflow.com/questions/50277775/how-do-i-select-gcc-version-in-nix-shell

with import <nixpkgs> {};
let
  CMakeFlags_Lolnero = ''
    -DReadline_ROOT_DIR=${readline.dev}
    -DUSE_CCACHE=ON
  '';
in
{
  qpidEnv = stdenvNoCC.mkDerivation {
    name = "lolnero-build-environment";
    buildInputs = [
      gcc10
      cmake git ccache
      boost174 openssl readline libsodium rapidjson
    ];

    inherit CMakeFlags_Lolnero;

    configure = "${cmake}/bin/cmake ${CMakeFlags_Lolnero}";
    build = "make -j";
  };
}
