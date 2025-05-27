{ rustPlatform, pkg-config, cpc-daemon }:
rustPlatform.buildRustPackage rec {
  pname = "libcpc-rust-blackbox";
  version = "0.1.0";

  src = ./.;

  cargoHash = "sha256-cQrcYoVTUPBR+ncHYRfPtU9T46z8B2xZR83aWmH5lPk=";

  nativeBuildInputs = [
    rustPlatform.bindgenHook
    pkg-config
  ];

  buildInputs = [
    cpc-daemon
  ];

  RUSTFLAGS = "-D warnings";

  cargoBuildFlags = [ "--all-targets" ];
  doCheck = false;
  installPhase = ''
    mkdir -p $out/bin
    rm target/*/*/deps/blackbox-*.d
    cp target/*/*/deps/blackbox-* $out/bin/blackbox
    cp target/*/*/examples/sample_app $out/bin/
  '';
}
