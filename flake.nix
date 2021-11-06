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
              boost175 openssl readline libsodium rapidjson
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
              "-DReadline_ROOT_DIR=${readline.dev}"
              "-DVERSIONTAG=${version}"
            ]
            ++ lib.optionals doCheck ["-DBUILD_TESTING=ON"]
            ;
          };
        };

      packages = forAllSystems (system:
        {
          inherit (nixpkgsFor.${system}) lolnero;
        });

      defaultPackage = forAllSystems (system: self.packages.${system}.lolnero);
    };
}
