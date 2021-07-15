# https://stackoverflow.com/questions/50277775/how-do-i-select-gcc-version-in-nix-shell

with import <nixpkgs> {};
let
  CMakeFlags_Lolnero = ''
    -DReadline_ROOT_DIR=${readline.dev}
  '';

  CMakeDevFlags = ''
    -DBUILD_SHARED_LIBS=ON
    -DCMAKE_BUILD_TYPE=Debug
  '';

  CMakeCCacheFlags = ''
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
    -DCMAKE_C_COMPILER_LAUNCHER=ccache
  '';

  CMakeClangFlags = ''
    -DCMAKE_CXX_COMPILER=clang++
    -DCMAKE_C_COMPILER=clang
  '';

  CMakeFlags_Lolnero_Test = CMakeFlags_Lolnero + ''
    -DBUILD_TESTING=ON
  '';
in
{
  qpidEnv = stdenvNoCC.mkDerivation {
    name = "lolnero-build-environment";
    buildInputs = [
      gcc11
      clang_12
      cmake git ccache
      boost175 openssl readline libsodium rapidjson
      gmock
    ];

    inherit CMakeFlags_Lolnero;
    inherit CMakeFlags_Lolnero_Test;
    inherit CMakeCCacheFlags;
    inherit CMakeClangFlags;

    configure = "cmake ${CMakeFlags_Lolnero} ${CMakeDevFlags} ${CMakeCCacheFlags}";
    configureRelease = "cmake ${CMakeFlags_Lolnero} ${CMakeCCacheFlags}";
    configureClang = "cmake ${CMakeFlags_Lolnero} ${CMakeDevFlags} ${CMakeClangFlags} ${CMakeCCacheFlags}";
    configureClangRelease = "cmake ${CMakeFlags_Lolnero} ${CMakeClangFlags} ${CMakeCCacheFlags}";
    configureTest = "cmake ${CMakeFlags_Lolnero_Test} ${CMakeDevFlags} ${CMakeCCacheFlags}";
    configureTestRelease = "cmake ${CMakeFlags_Lolnero_Test} ${CMakeCCacheFlags}";
    build = "make";
    ci = "make Continuous";
    testFilter = "ctest -R";
  };
}
