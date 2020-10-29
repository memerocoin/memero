{ gcc10Stdenv
, cmake, git, fetchgit
, boost172, openssl, readline, libsodium, rapidjson
}:

let
  stdenv = gcc10Stdenv;
in
stdenv.mkDerivation rec {
  pname = "lolnero";
  version = "0.5";
  src = fetchgit {
    url = "https://gitlab.com/fuwa/lolnero.git";
    rev = "e9d9b9ff";
    sha256 = "0i6dgrdrgbds3ivynr7wgvxqcby5v83056h1scgcxk6g5047ldz0";
    fetchSubmodules = false;
  };

  nativeBuildInputs = [ cmake ];

  buildInputs = [
    boost172 openssl readline libsodium rapidjson
  ];

  cmakeFlags = [
    "-DReadline_ROOT_DIR=${readline.dev}"
    "-DMANUAL_SUBMODULES=ON"
  ];

  meta = with stdenv.lib; {
    description = "A fork of Wownero with a linear emission and a SHA-3 PoW";
    homepage    = https://lolnero.org/;
    license     = licenses.bsd3;
    platforms   = platforms.linux;
  };
}

