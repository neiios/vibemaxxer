{
  description = "vibemaxxer — a small, access-controlled HTTP CONNECT proxy";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = self.packages.${system}.vibemaxxer;
          vibemaxxer = pkgs.buildGoModule {
            pname = "vibemaxxer";
            version = "0.1.0";
            src = pkgs.lib.cleanSource self;
            vendorHash = null;
            env.CGO_ENABLED = 0;
            ldflags = [
              "-s"
              "-w"
            ];
            doCheck = true;
            meta = {
              description = "Access-controlled HTTP CONNECT proxy for a trusted LAN";
              homepage = "https://github.com/neiios/vibemaxxer";
              mainProgram = "vibemaxxer";
              platforms = systems;
            };
          };
        }
      );

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.vibemaxxer}/bin/vibemaxxer";
          meta.description = "Run the vibemaxxer CONNECT proxy";
        };
      });

      checks = forAllSystems (system: {
        package = self.packages.${system}.vibemaxxer;
      });

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.go
              pkgs.gopls
              pkgs.nixfmt
            ];
          };
        }
      );

      formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixfmt-tree);
    };
}
