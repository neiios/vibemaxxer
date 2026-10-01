{
  lib,
  buildGo127Module,
  stdenvNoCC,
  removeReferencesTo,
  tzdata,
  iana-etc,
  mailcap,
  src,
}:
(buildGo127Module.override { stdenv = stdenvNoCC; }) {
  pname = "vibemaxxer";
  version = "0.3.0";
  src = lib.fileset.toSource {
    root = src;
    fileset = lib.fileset.unions [
      (lib.fileset.fileFilter (file: file.hasExt "go") src)
      (src + "/go.mod")
    ];
  };
  vendorHash = null;
  env.CGO_ENABLED = 0;
  ldflags = [
    "-s"
    "-w"
  ];
  doCheck = true;
  checkPhase = ''
    runHook preCheck
    go test -p "$NIX_BUILD_CORES" ./...
    runHook postCheck
  '';
  nativeBuildInputs = [ removeReferencesTo ];
  postFixup = ''
    remove-references-to -t ${tzdata} -t ${iana-etc} -t ${mailcap} $out/bin/vibemaxxer
  '';
}
