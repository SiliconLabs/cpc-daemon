{
  stdenv,
  lib,
  nix-gitignore,
  cmake,
  pkg-config,
  protobuf,
  mbedtls,
  unity-src ? null,
  libprotobuf-mutator-src ? null,
}:
let
  doCheck = (unity-src != null) && (libprotobuf-mutator-src != null);
in
stdenv.mkDerivation {
  pname = "cpc-daemon";
  version = "4.7.0";

  src = nix-gitignore.gitignoreSource [ ] ./.;

  inherit doCheck;
  separateDebugInfo = true;

  nativeBuildInputs = [
    cmake
    pkg-config
  ];
  nativeCheckInputs = [ protobuf ];
  buildInputs = [ mbedtls ];
  checkInputs = [ protobuf ];

  cmakeBuildType = "RelWithDebInfo";
  cmakeFlags =
    with lib.strings;
    [
      (cmakeBool "CMAKE_COMPILE_WARNING_AS_ERROR" doCheck)
    ]
    ++ lib.optionals doCheck [
      (cmakeOptionType "path" "UNITY_DIR" unity-src.outPath)
      (cmakeOptionType "path" "LIBPROTOBUF_MUTATOR_DIR" libprotobuf-mutator-src.outPath)
    ];

  outputs = [
    "bin"
    "lib"
    "dev"
    "out"
  ];

  meta = {
    description = "CPC daemon";
    homepage = "https://github.com/SiliconLabs/cpc-daemon";
    license = "MSLA";
    maintainers = [ "iemaghni" ];
    platform = lib.platforms.linux;
    mainProgram = "cpcd";
  };
}
