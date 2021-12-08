{
  description = "A private ASIC friendly cryptocurrency";

  inputs.nixpkgs.url = "nixpkgs/nixos-unstable-small";

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ]
      ; forAllSystems = f: nixpkgs.lib.genAttrs supportedSystems (system: f system)
      ; nixpkgsFor = forAllSystems
        (system: import nixpkgs { inherit system; overlays = [ self.overlay ]; })
      ; in
    {
      # A Nixpkgs overlay.
      overlay = final: prev:
        with final;
        let
          # stdenv = llvmPackages_12.stdenv
          stdenv = gcc11Stdenv
          ; version = builtins.substring 0 8 self.lastModifiedDate
          ; in
        {
          lolnero = stdenv.mkDerivation {
            pname = "lolnero";
            inherit version;
            src = ./.;

            nativeBuildInputs = [ cmake ];

            buildInputs = [
              boost175 openssl libsodium rapidjson
            ]
            ;

            cmakeFlags = [
              "--no-warn-unused-cli"
              "-DVERSIONTAG=${version}"
            ]
            ;
          };

          lolnero-opencl = stdenv.mkDerivation {
            pname = "lolnero-opencl";
            inherit version;
            src = ./.;

            nativeBuildInputs = [ cmake ];

            buildInputs = [
              boost175 openssl libsodium rapidjson
              opencl-headers
              opencl-icd
              opencl-clhpp
            ]
            ;

            cmakeFlags = [
              "--no-warn-unused-cli"
              "-DVERSIONTAG=${version}"
              "-DUSE_OPENCL=ON"
            ]
            ;
          };

          lolnero-with-tests = stdenv.mkDerivation {
            pname = "lolnero-with-tests";
            inherit version;
            src = ./.;

            nativeBuildInputs = [ cmake ];

            buildInputs = [
              boost175 openssl libsodium rapidjson
              opencl-headers
              opencl-icd
              opencl-clhpp
              gmock
            ]
            ;

            doCheck = true;

            checkPhase = ''
              ${cmake}/bin/ctest
            '';

            cmakeFlags = [
              "--no-warn-unused-cli"
              "-DVERSIONTAG=${version}"
              "-DUSE_OPENCL=ON"
              "-DBUILD_TESTING=ON"
            ]
            ;
          };
        };

      nixosModules.lolnero =
        { pkgs, ... }:
        {
          nixpkgs.overlays = [ self.overlay ];
        };

      checks = forAllSystems (system:
        {
          inherit (nixpkgsFor.${system}) lolnero-with-tests;
        });

      packages = forAllSystems (system:
        {
          inherit (nixpkgsFor.${system}) lolnero;
          inherit (nixpkgsFor.${system}) lolnero-opencl;
        });

      defaultPackage = forAllSystems (system: self.packages.${system}.lolnero);

      apps = forAllSystems
        (
          system:
          {
            lolnerod =
              {
                type = "app";
                program = "${self.defaultPackage.${system}}/bin/lolnerod";
              };

            lolnero =
              {
                type = "app";
                program = "${self.defaultPackage.${system}}/bin/lolnero";
              };

            lolnero-rpc =
              {
                type = "app";
                program = "${self.defaultPackage.${system}}/bin/lolnero-rpc";
              };
          }
        );

      devShell = forAllSystems
        (
          system:
          let
            pkgs = nixpkgs.legacyPackages.${system};
            gcc = pkgs.gcc11;
            clang = pkgs.llvmPackages_13.clang;

            CMakeFlags_Lolnero = ''
              -DUSE_OPENCL=ON
            '';

            CMakeDevFlags = ''
              -DBUILD_SHARED_LIBS=ON
              -DCMAKE_BUILD_TYPE=Debug
            '';

            # CMakeCCacheFlags = "";

            CMakeCCacheFlags = ''
              -DCMAKE_CXX_COMPILER_LAUNCHER=${pkgs.ccache}/bin/ccache
              -DCMAKE_C_COMPILER_LAUNCHER=${pkgs.ccache}/bin/ccache
            '';

            CMakeClangFlags = ''
              -DCMAKE_CXX_COMPILER=${clang}/bin/clang++
              -DCMAKE_C_COMPILER=${clang}/bin/clang
            '';

            CMakeGCCFlags = ''
              -DCMAKE_CXX_COMPILER=${gcc}/bin/g++
              -DCMAKE_C_COMPILER=${gcc}/bin/gcc
            '';

            CMakeTestFlags = ''
              -DBUILD_TESTING=ON
            '';

            configureReleaseCommon = ''
              ${pkgs.cmake}/bin/cmake ${CMakeFlags_Lolnero} ${CMakeCCacheFlags}
            '';

            configureCommon = configureReleaseCommon + CMakeDevFlags;

            configureGCC = configureCommon + CMakeGCCFlags;
            configureGCCRelease = configureReleaseCommon + CMakeGCCFlags;

            configureClang = configureCommon + CMakeClangFlags;
            configureClangRelease = configureReleaseCommon + CMakeClangFlags;

            configure = configureClang;
            configureRelease = configureClangRelease;

          in
            pkgs.stdenvNoCC.mkDerivation {
              name = "lolnero-dev-shell";
              buildInputs =
                [gcc clang] ++
                (
                  with pkgs; [
                    cmake git

                    boost175 openssl libsodium rapidjson
                    gmock
                    ccache

                    opencl-headers
                    opencl-icd
                    opencl-clhpp
                  ]
                );

              inherit CMakeFlags_Lolnero;
              inherit CMakeCCacheFlags;
              inherit CMakeClangFlags;

              inherit configureGCC;
              inherit configureGCCRelease;
              inherit configureClang;
              inherit configureClangRelease;
              inherit configure;
              inherit configureRelease;

              configureTest = configure + CMakeTestFlags;
              configureTestRelease = configureRelease + CMakeTestFlags;
            }
        );
    };
}
