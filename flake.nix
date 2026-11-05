{
  inputs.nixpkgs.url = "https://channels.nixos.org/nixpkgs-unstable/nixexprs.tar.zst";

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
        pkgs:
        import ./nix/checks.nix {
          inherit pkgs;
          package = packageFor pkgs.stdenv.hostPlatform.system;
        }
      );

      devShells = forAllSystems (pkgs: {
        default = import ./nix/shell.nix { inherit pkgs; };
      });

      formatter = forAllSystems (pkgs: import ./nix/formatter.nix { inherit pkgs; });
    };
}
