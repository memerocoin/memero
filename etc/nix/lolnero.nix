{ gcc10Stdenv
, cmake, git, fetchgit
, boost175, openssl, readline, libsodium, rapidjson
, lib, gmock
}:

let

  stdenv = gcc10Stdenv
; lolnero-rev = "v0.9.1.0"
; lolnero-sha256 = "1qahvswfqwfp6lpmxhrh8jhbp47nlfvnny6s3gdqhlrd8h4pxfrc"
; doCheck = true

; in

stdenv.mkDerivation rec {
  pname = "lolnero";
  version = "0.9.1.0";
  src = fetchgit {
    url = "https://gitlab.com/fuwa/lolnero.git";
    rev = lolnero-rev;
    sha256 = lolnero-sha256;
    fetchSubmodules = false;
  };

  nativeBuildInputs = [ cmake ];

  inherit doCheck;

  buildInputs = [
    boost175 openssl readline libsodium rapidjson gmock
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
    description = "A fork of Wownero with a linear emission and a SHA-3 PoW";
    homepage    = https://lolnero.org/;
    license     = licenses.bsd3;
    platforms   = platforms.linux;
  };
}

