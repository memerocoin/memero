{
  description = "A private ASIC friendly cryptocurrency";

  inputs.nixpkgs.url = "nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ]
      ; forAllSystems = f: nixpkgs.lib.genAttrs supportedSystems (system: f system)
      ; nixpkgsFor = forAllSystems (system: import nixpkgs { inherit system; overlays = [ self.overlay ]; })
      ; in
    {
      # A Nixpkgs overlay.
      overlay = final: prev:
        with final;
        let
          # stdenv = llvmPackages_12.stdenv
          stdenv = gcc11Stdenv
          ; doCheck = false
          ; version = builtins.substring 0 8 self.lastModifiedDate
          ; in
        {
          lolnero = stdenv.mkDerivation rec {
            pname = "lolnero";
            inherit version;
            src = ./.;

            nativeBuildInputs = [ cmake ];

            inherit doCheck;

            buildInputs = [
              boost175 openssl libsodium rapidjson
            ]
            ++ lib.optionals doCheck
              [
                gmock
                opencl-headers
                opencl-icd
              ]
            ;

            cmakeFlags = [
              "--no-warn-unused-cli"
              "-DVERSIONTAG=${version}"
            ]
            ++ lib.optionals doCheck ["-DBUILD_TESTING=ON"]
            ;
          };

          lolnero-opencl = stdenv.mkDerivation rec {
            pname = "lolnero-opencl";
            inherit version;
            src = ./.;

            nativeBuildInputs = [ cmake ];

            inherit doCheck;

            buildInputs = [
              boost175 openssl libsodium rapidjson
              opencl-headers
              opencl-icd
              rocm-opencl-runtime
            ]
            ++ lib.optionals doCheck
              [
                gmock
              ]
            ;

            cmakeFlags = [
              "--no-warn-unused-cli"
              "-DVERSIONTAG=${version}"
              "-DUSE_OPENCL=ON"
            ]
            ++ lib.optionals doCheck ["-DBUILD_TESTING=ON"]
            ;
          };
        };

      packages = forAllSystems (system:
        {
          inherit (nixpkgsFor.${system}) lolnero;
          inherit (nixpkgsFor.${system}) lolnero-opencl;
        });

      defaultPackage = forAllSystems (system: self.packages.${system}.lolnero);

      devShell = forAllSystems
        (
          system:
          let
            pkgs = nixpkgs.legacyPackages.${system};

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
            with pkgs;
            stdenvNoCC.mkDerivation {
              name = "lolnero-dev-shell";
              buildInputs = [
                gcc11
                llvmPackages_13.clang
                cmake git

                boost175 openssl libsodium rapidjson
                gmock

                opencl-headers
                opencl-icd
                rocm-opencl-runtime

                gnumake
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
            }
        );
    };
}
