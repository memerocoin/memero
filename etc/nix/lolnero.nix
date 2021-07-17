{ gcc11Stdenv
, cmake, git, fetchgit
, boost175, openssl, readline, libsodium, rapidjson
, lib, gmock
}:

let

  stdenv = gcc11Stdenv
; lolnero-rev = "v0.9.7.51"
; lolnero-sha256 = "1mkmgfgc5m1fcd3z7pc63fz0cpd1l60dyw341c4yr5sy9ciqkrgj"
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

