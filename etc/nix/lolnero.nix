{ gcc11Stdenv
, cmake, git, fetchgit
, boost175, openssl, readline, libsodium, rapidjson
, lib, gmock
}:

let

  stdenv = gcc11Stdenv
; lolnero-rev = "v0.9.6.3"
; lolnero-sha256 = "09m3nbsdpk09pcv8kgl4n76i0q7zkd8cb06wmm8yx92yqw3nq24y"
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
    description = "A fork of Wownero with a linear emission and a SHA-3 PoW";
    homepage    = https://lolnero.org/;
    license     = licenses.bsd3;
    platforms   = platforms.linux;
  };
}

