{
  lib,
  buildGo127Module,
  stdenvNoCC,
  removeReferencesTo,
  shellcheck,
  tzdata,
  iana-etc,
  mailcap,
  src,
}:
(buildGo127Module.override { stdenv = stdenvNoCC; }) {
  pname = "vibemaxxer";
  version = "1.0.0";
  src = lib.fileset.toSource {
    root = src;
    fileset = lib.fileset.unions [
      (lib.fileset.fileFilter (file: file.hasExt "go") src)
      (src + "/go.mod")
      (src + "/scripts/vibemaxxer-run")
    ];
  };
  vendorHash = null;
  env.CGO_ENABLED = 0;
  ldflags = [
    "-s"
    "-w"
  ];
  checkPhase = ''
    runHook preCheck
    go test -p "$NIX_BUILD_CORES" ./...
    shellcheck scripts/vibemaxxer-run
    runHook postCheck
  '';
  nativeBuildInputs = [ removeReferencesTo ];
  nativeCheckInputs = [ shellcheck ];
  postInstall = ''
    install -Dm755 scripts/vibemaxxer-run $out/bin/vibemaxxer-run
  '';
  dontPatchShebangs = true;
  postFixup = ''
    remove-references-to -t ${tzdata} -t ${iana-etc} -t ${mailcap} $out/bin/vibemaxxer
  '';
}
