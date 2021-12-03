# https://stackoverflow.com/questions/50277775/how-do-i-select-gcc-version-in-nix-shell

with import <nixpkgs> {};
let
  CMakeFlags_Lolnero = ''
    -DUSE_OPENCL=ON
  '';

  CMakeDevFlags = ''
    -DBUILD_SHARED_LIBS=ON
    -DCMAKE_BUILD_TYPE=Debug
  '';

  CMakeCCacheFlags = "";

  CMakeCCacheFlags1 = ''
    -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
    -DCMAKE_C_COMPILER_LAUNCHER=ccache
  '';

  CMakeClangFlags = ''
    -DCMAKE_CXX_COMPILER=clang++
    -DCMAKE_C_COMPILER=clang
  '';

  CMakeTestFlags = ''
    -DBUILD_TESTING=ON
  '';

  configure = "cmake ${CMakeFlags_Lolnero} ${CMakeDevFlags} ${CMakeClangFlags} ${CMakeCCacheFlags}";
  configureRelease = "cmake ${CMakeFlags_Lolnero} ${CMakeClangFlags} ${CMakeCCacheFlags}";
in
{
  qpidEnv = stdenvNoCC.mkDerivation {
    name = "lolnero-build-environment";
    buildInputs = [
      gcc11
      llvmPackages_13.clang
      cmake git

      # ccache

      boost175 openssl libsodium rapidjson
      gmock

      opencl-headers
      opencl-icd
      rocm-opencl-runtime
    ];

    inherit CMakeFlags_Lolnero;
    inherit CMakeCCacheFlags;
    inherit CMakeClangFlags;

    inherit configure;
    inherit configureRelease;

    configureGCC = "cmake ${CMakeFlags_Lolnero} ${CMakeDevFlags} ${CMakeCCacheFlags}";
    configureGCCRelease = "cmake ${CMakeFlags_Lolnero} ${CMakeCCacheFlags}";
    configureTest = configure + " " + CMakeTestFlags;
    configureTestRelease = configureRelease + " " + CMakeTestFlags;
    build = "make";
    ci = "make Continuous";
    testFilter = "ctest -R";
  };
}
