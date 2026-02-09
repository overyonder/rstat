{
  description = "Waybar syshealth streaming daemon";

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
      rstat = pkgs.rustPlatform.buildRustPackage {
        pname = "rstat";
        version = "0.1.0";
        src = ./.;
        cargoHash = "sha256-wLRw3F8cH8fmeKPZ01+lJCwLPhccDjEwmcOvdlI2BCw=";
      };
    in {
      default = rstat;
      rstat = rstat;
    });
  };
}
