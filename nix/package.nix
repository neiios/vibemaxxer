{
  lib,
  buildGo127Module,
  src,
}:
buildGo127Module {
  pname = "vibemaxxer";
  version = "0.3.0";
  src = lib.cleanSource src;
  vendorHash = null;
  env.CGO_ENABLED = 0;
  ldflags = [
    "-s"
    "-w"
  ];
  doCheck = true;
}
