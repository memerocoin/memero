# https://stackoverflow.com/questions/50277775/how-do-i-select-gcc-version-in-nix-shell

with import <nixpkgs> {};
let
  CMakeFlags_Lolnero = ''
    -DReadline_ROOT_DIR=${readline.dev}
    -DBUILD_SHARED_LIBS=ON
    -DBUILD_TESTING=ON
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
    -DCMAKE_C_COMPILER_LAUNCHER=ccache
    -DCMAKE_BUILD_TYPE=Debug
  '';
in
{
  qpidEnv = stdenvNoCC.mkDerivation {
    name = "lolnero-build-environment";
    buildInputs = [
      gcc11
      cmake git ccache
      boost175 openssl readline libsodium rapidjson
      gmock
    ];

    inherit CMakeFlags_Lolnero;

    configure = "${cmake}/bin/cmake ${CMakeFlags_Lolnero}";
    build = "make";
    test = "ctest -j6";
  };
}
