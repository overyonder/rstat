{
  description = "Low-overhead Linux system monitor daemon for Waybar";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";

    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = {
    self,
    nixpkgs,
    rust-overlay,
  }: let
    systems = ["x86_64-linux" "aarch64-linux"];
    forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);
    pkgsFor = system:
      import nixpkgs {
        inherit system;
        overlays = [(import rust-overlay)];
      };
  in {
    packages = forAllSystems (system: let
      pkgs = pkgsFor system;
      rstat = pkgs.rustPlatform.buildRustPackage {
        pname = "rstat";
        version = "2.0.0";
        src = ./.;
        cargoLock.lockFile = ./Cargo.lock;
        nativeBuildInputs = [pkgs.makeWrapper];
        # NVML is loaded at runtime from the NVIDIA driver, which NixOS installs under /run/opengl-driver;
        # iw reports Wi-Fi links.
        postFixup = ''
          wrapProgram $out/bin/rstat \
            --suffix LD_LIBRARY_PATH : /run/opengl-driver/lib \
            --suffix PATH : ${pkgs.iw}/bin
        '';
      };
    in {
      default = rstat;
      rstat = rstat;
    });

    devShells = forAllSystems (system: let
      pkgs = pkgsFor system;
      rustToolchain = pkgs.rust-bin.stable."1.96.0".default.override {
        extensions = ["clippy" "rust-analyzer" "rust-src" "rustfmt"];
      };
    in {
      default = pkgs.mkShell {
        packages = [rustToolchain pkgs.mold];
        RUSTFLAGS = "-C link-arg=-fuse-ld=mold";
        LD_LIBRARY_PATH = "/run/opengl-driver/lib";
      };
    });
  };
}
