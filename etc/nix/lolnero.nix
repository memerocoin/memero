{ gcc10Stdenv
, cmake, git, fetchgit
, boost175, openssl, readline, libsodium, rapidjson
, lib
}:

let

  stdenv = gcc10Stdenv
; lolnero-rev = "v0.9.0.1"
; lolnero-sha256 = "1r58753zcacjlaq0h86xx837rsnq5g0mhyvkg2p6nkbmpiacy0dk"

; in

stdenv.mkDerivation rec {
  pname = "lolnero";
  version = "0.9.0.1";
  src = fetchgit {
    url = "https://gitlab.com/fuwa/lolnero.git";
    rev = lolnero-rev;
    sha256 = lolnero-sha256;
    fetchSubmodules = false;
  };

  nativeBuildInputs = [ cmake ];

  buildInputs = [
    boost175 openssl readline libsodium rapidjson
  ];

  cmakeFlags = [
    "--no-warn-unused-cli"
    "-DReadline_ROOT_DIR=${readline.dev}"
    "-DVERSIONTAG=${lolnero-rev}"
  ];

  meta = with lib; {
    description = "A fork of Wownero with a linear emission and a SHA-3 PoW";
    homepage    = https://lolnero.org/;
    license     = licenses.bsd3;
    platforms   = platforms.linux;
  };
}

