{
  description = "A private ASIC friendly cryptocurrency";

  inputs.nixpkgs.url = "nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    with import nixpkgs { system = "x86_64-linux"; };
    let
      stdenv = llvmPackages_12.stdenv
    ; lolnero-rev = "v0.9.8.14"
    ; doCheck = false
    ; in
    {
      defaultPackage.x86_64-linux =
        stdenv.mkDerivation {
          pname = "lolnero";
          version = lolnero-rev;
          src = self;

          nativeBuildInputs = [ cmake ];

          inherit doCheck;

          buildInputs = [
            boost175 openssl readline libsodium rapidjson
          ]
          ++ lib.optionals doCheck [gmock]
          ;

          cmakeFlags = [
            "--no-warn-unused-cli"
            "-DReadline_ROOT_DIR=${readline.dev}"
            "-DVERSIONTAG=${lolnero-rev}"
          ]
          ++ lib.optionals doCheck ["-DBUILD_TESTING=ON"]
          ;
        };
    };
}
