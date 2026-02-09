{
  description = "Waybar syshealth streaming daemon (eBPF)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = {
    self,
    nixpkgs,
  }: let
    systems = ["x86_64-linux" "aarch64-linux"];
    forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
  in {
    packages = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      probe = pkgs.stdenv.mkDerivation {
        pname = "rstat-probe";
        version = "0.1.0";
        src = ./src;
        sourceRoot = ".";
        nativeBuildInputs = [pkgs.llvmPackages.clang-unwrapped];
        buildInputs = [pkgs.libbpf];
        dontUnpack = true;
        buildPhase = ''
          ${pkgs.llvmPackages.clang-unwrapped}/bin/clang \
            -target bpf -O2 -g \
            -I${pkgs.libbpf}/include \
            -I$src \
            -c $src/probe.bpf.c -o probe.bpf.o
        '';
        installPhase = ''
          mkdir -p $out
          cp probe.bpf.o $out/
        '';
      };
      rstat = pkgs.rustPlatform.buildRustPackage {
        pname = "rstat";
        version = "0.1.0";
        src = ./.;
        cargoHash = "sha256-1O6RRWztQXukeM6WAc2KEbNRRhsAVxqr5MhtcTelFeo=";
        postInstall = ''
          cp ${probe}/probe.bpf.o $out/bin/
        '';
      };
    in {
      default = rstat;
      rstat = rstat;
    });
  };
}
