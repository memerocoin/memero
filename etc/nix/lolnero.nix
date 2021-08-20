{ gcc11Stdenv
, cmake, git, fetchgit
, boost175, openssl, readline, libsodium, rapidjson
, lib, gmock, llvmPackages_12
}:

let

  stdenv = llvmPackages_12.stdenv
; lolnero-rev = "v0.9.8.14"
; lolnero-sha256 = "149cskvn5zq4ab17pfs2qpk7p3wjvwyl6hm3nn8h2cc9cc0vb89n"
; doCheck = false

; in

stdenv.mkDerivation rec {
  pname = "lolnero";
  version = lolnero-rev;
  src = fetchgit {
    url = "https://gitlab.com/lolnero/lolnero.git";
    rev = lolnero-rev;
    sha256 = lolnero-sha256;
    fetchSubmodules = false;
  };

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

  meta = with lib; {
    description = "A private ASIC friendly cryptocurrency";
    homepage    = https://lolnero.org/;
    license     = licenses.bsd3;
    platforms   = platforms.linux;
  };
}

