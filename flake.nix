{
  description = "A private ASIC friendly cryptocurrency"

  ; inputs.nixpkgs.url = "nixpkgs/nixos-unstable-small"

  ; outputs = { self, nixpkgs }:
      let
        supportedSystems = [ "x86_64-linux" "aarch64-linux" ]
        ; forAllSystems = f: nixpkgs.lib.genAttrs supportedSystems (system: f system)
        ; nixpkgsFor = forAllSystems
          (system: import nixpkgs { inherit system; overlays = [ self.overlay ]; })
        ;
      in
        {
          # A Nixpkgs overlay.
          overlay = final: prev:
            with final
            ;

            let
              stdenvLatest = gcc11Stdenv
              ; clangStdenvLatest = llvmPackages_14.stdenv
              ; version = builtins.substring 0 8 self.lastModifiedDate

              ; memero-template =
                  {
                    stdenv
                  , opencl ? false
                  , name ? "memero"
                  }: stdenv.mkDerivation {
                    pname = name
                    ; inherit version
                    ; src = ./.

                    ; nativeBuildInputs = [ cmake ]

                    ; buildInputs = [
                        boost17x libsodium rapidjson
                      ]
                      ++
                      (
                        nixpkgs.lib.optionals opencl
                          [
                            
                            opencl-headers
                            ocl-icd
                            opencl-clhpp
                          ]
                      )

                    ; cmakeFlags = [
                        "--no-warn-unused-cli"
                        "-DVERSIONTAG=${version}"
                      ]
                      ++
                      (
                        nixpkgs.lib.optionals opencl
                          [
                            "-DUSE_OPENCL=ON"
                          ]
                      )
                    ;
                  }
              ; in
              {
                memero = memero-template { stdenv = stdenvLatest; }

                ; memero-opencl = memero-template
                  {
                    name = "memero-opencl"
                    ; stdenv = stdenvLatest
                    ; opencl = true
                    ;
                  }

                ; memero-clang = memero-template
                  {
                    name = "memero-clang"
                    ; stdenv = clangStdenvLatest
                    ;
                  }

                ; memero-clang-opencl = memero-template
                  {
                    name = "memero-clang-opencl"
                    ; stdenv = clangStdenvLatest
                    ; opencl = true
                    ;
                  }

                ; memero-lib = stdenvLatest.mkDerivation {
                    pname = "memero-lib"
                    ; inherit version
                    ; src = ./.

                    ; nativeBuildInputs = [ cmake ]

                    ; buildInputs = [
                        boost17x libsodium rapidjson
                      ]

                    ; cmakeFlags = [
                        "--no-warn-unused-cli"
                        "-DVERSIONTAG=${version}"
                        "-DONLY_LIB=ON"
                        "-DBUILD_SHARED_LIBS=ON"
                      ]
                    ;
                  }

                ; memero-with-tests = stdenvLatest.mkDerivation {
                    pname = "memero-with-tests"
                    ; inherit version
                    ; src = ./.

                    ; nativeBuildInputs = [ cmake ]

                    ; buildInputs = [
                        boost17x libsodium rapidjson
                        opencl-headers
                        ocl-icd
                        opencl-clhpp
                        gmock
                      ]

                    ; doCheck = true

                    ; checkPhase =
                        ''
                            ${cmake}/bin/ctest
                        ''
                          
                    ; cmakeFlags = [
                        "--no-warn-unused-cli"
                        "-DVERSIONTAG=${version}"
                        "-DUSE_OPENCL=ON"
                        "-DBUILD_TESTING=ON"
                      ]
                    ;
                  }
                ;
              }
                
          ; nixosModules.memero =
              { pkgs, ... }:
              {
                nixpkgs.overlays = [ self.overlay ]
                ;
              }
                
          ; checks = forAllSystems (system:
              {
                inherit (nixpkgsFor.${system}) memero-with-tests
                ;
              })
            
          ; packages = forAllSystems (system:
              {
                inherit (nixpkgsFor.${system}) memero
                ; inherit (nixpkgsFor.${system}) memero-opencl
                ; inherit (nixpkgsFor.${system}) memero-clang
                ; inherit (nixpkgsFor.${system}) memero-clang-opencl
                ; inherit (nixpkgsFor.${system}) memero-lib
                ;
              })
            
          ; defaultPackage = forAllSystems (system: self.packages.${system}.memero)
            
          ; apps = forAllSystems
            (
              system:
              {
                memerod-rpc =
                  {
                    type = "app"
                    ; program = "${self.defaultPackage.${system}}/bin/memerod-rpc"
                    ;
                  }

                ; memerod =
                  {
                    type = "app"
                    ; program = "${self.defaultPackage.${system}}/bin/memerod"
                    ;
                  }
                    
                ; memero =
                    {
                      type = "app"
                      ; program = "${self.defaultPackage.${system}}/bin/memero"
                      ;
                    }
                ;
                
              }
            )
            
          ; devShell = forAllSystems
            (
              system:
              let
                pkgs = nixpkgs.legacyPackages.${system}
                ; gccLatest = pkgs.gcc11
                ; clangLatest = pkgs.llvmPackages_14.clang

                ; CMakeFlags_Memero =
                    ''
                    ''

                ; CMakeFlags_Memero_OpenCL =
                    ''
                        -DUSE_OPENCL=ON
                    ''

                ; CMakeDevFlags =
                    ''
                        -DBUILD_SHARED_LIBS=ON
                        -DCMAKE_BUILD_TYPE=Debug
                    ''

                # CMakeCCacheFlags = "";

                ; CMakeCCacheFlags =
                    ''
                        -DCMAKE_CXX_COMPILER_LAUNCHER=${pkgs.ccache}/bin/ccache
                        -DCMAKE_C_COMPILER_LAUNCHER=${pkgs.ccache}/bin/ccache
                    ''

                ; CMakeClangFlags =
                    ''
                        -DCMAKE_CXX_COMPILER=${clangLatest}/bin/clang++
                        -DCMAKE_C_COMPILER=${clangLatest}/bin/clang
                    ''

                ; CMakeGCCFlags =
                    ''
                        -DCMAKE_CXX_COMPILER=${gccLatest}/bin/g++
                        -DCMAKE_C_COMPILER=${gccLatest}/bin/gcc
                    ''

                ; CMakeTestFlags =
                    ''
                        -DBUILD_TESTING=ON
                    ''

                ; configureReleaseCommon =
                    ''
                        ${pkgs.cmake}/bin/cmake ${CMakeFlags_Memero} ${CMakeCCacheFlags}
                    ''

                ; configureCommon = configureReleaseCommon + CMakeDevFlags

                ; configureGCC = configureCommon + CMakeGCCFlags
                ; configureGCCRelease = configureReleaseCommon + CMakeGCCFlags

                ; configureClang = configureCommon + CMakeClangFlags
                ; configureClangRelease = configureReleaseCommon + CMakeClangFlags

                ; configure = configureClang
                ; configureRelease = configureClangRelease

                ;
              in
                pkgs.stdenvNoCC.mkDerivation {
                  name = "memero-dev-shell"
                  ; buildInputs =
                      [gccLatest clangLatest] ++
                      (
                        with pkgs
                        ;
                        [
                          cmake git

                          boost17x libsodium rapidjson
                          gmock
                          ccache

                          opencl-headers
                          ocl-icd
                          opencl-clhpp
                        ]
                      )

                  ; inherit CMakeFlags_Memero
                  ; inherit CMakeCCacheFlags
                  ; inherit CMakeClangFlags
                  ; inherit CMakeGCCFlags
                  ; inherit CMakeTestFlags

                  ; inherit configureGCC
                  ; inherit configureGCCRelease
                  ; inherit configureClang
                  ; inherit configureClangRelease
                  ; inherit configure
                  ; inherit configureRelease

                  ; configureTest = configure + CMakeTestFlags
                  ; configureTestRelease = configureRelease + CMakeTestFlags
                  ;
                }
            )
          ;
        }
  ;
}
