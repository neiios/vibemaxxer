{ pkgs }:
pkgs.mkShell {
  packages = [
    pkgs.go_1_27
    pkgs.gopls
    pkgs.nixfmt
  ];
}
