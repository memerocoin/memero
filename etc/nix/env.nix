# https://stackoverflow.com/questions/50277775/how-do-i-select-gcc-version-in-nix-shell

with import <nixpkgs> {};
let
  CMakeFlags_Lolnero = ''
    -DReadline_ROOT_DIR=${readline.dev}
    -DUSE_CCACHE=ON
    -DBUILD_SHARED_LIBS=ON
    -DBUILD_TESTING=ON
  '';
in
{
  qpidEnv = stdenvNoCC.mkDerivation {
    name = "lolnero-build-environment";
    buildInputs = [
      gcc10
      cmake git ccache
      boost175 openssl readline libsodium rapidjson
      gmock
    ];

    inherit CMakeFlags_Lolnero;

    configure = "${cmake}/bin/cmake ${CMakeFlags_Lolnero}";
    build = "make -j6";
    test = "ctest -j6";
  };
}
