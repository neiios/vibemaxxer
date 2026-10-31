{ pkgs, package }:
{
  inherit package;
  e2e = pkgs.testers.runNixOSTest (import ./e2e.nix { inherit pkgs package; });
}
