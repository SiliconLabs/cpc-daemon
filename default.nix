{
  stdenv,
  lib,
  nix-gitignore,
  cmake,
  pkg-config,
  protobuf,
  mbedtls,
  unitySrc ? null,
  libprotobufMutatorSrc ? null,
}:
stdenv.mkDerivation rec {
  pname = "cpc-daemon";
  version = "4.6.0";

  src = nix-gitignore.gitignoreSource [ ] ./.;
  doCheck = (unitySrc != null) && (libprotobufMutatorSrc != null);
  separateDebugInfo = doCheck;

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
      (cmakeBool "BUILD_TESTING" doCheck)
    ]
    ++ lib.optionals doCheck [
      (cmakeOptionType "path" "UNITY_DIR" unitySrc.outPath)
      (cmakeOptionType "path" "LIBPROTOBUF_MUTATOR_DIR" libprotobufMutatorSrc.outPath)
    ];

  meta = with lib; {
    description = "CPC daemon";
    homepage = "https://github.com/SiliconLabs/cpc-daemon";
    license = "MSLA";
    maintainers = [ "iemaghni" ];
    platform = platforms.linux;
    mainProgram = "cpcd";
  };
}
