{
  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      packageFor = system: self.packages.${system}.vibemaxxer;
    in
    {
      packages = forAllSystems (pkgs: rec {
        default = vibemaxxer;
        vibemaxxer = pkgs.callPackage ./nix/package.nix { src = ./.; };
      });

      checks = forAllSystems (
        pkgs: import ./nix/checks.nix { package = packageFor pkgs.stdenv.hostPlatform.system; }
      );

      devShells = forAllSystems (pkgs: {
        default = import ./nix/shell.nix { inherit pkgs; };
      });

      formatter = forAllSystems (pkgs: import ./nix/formatter.nix { inherit pkgs; });
    };
}
