{
  description = "INK protocol reference implementation";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = {nixpkgs, ...}: let
    systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    forAllSystems = nixpkgs.lib.genAttrs systems;
  in {
    devShells = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      default = pkgs.mkShell {
        packages = [pkgs.nodejs_22 pkgs.git pkgs.gitleaks];
      };
    });

    packages = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      pkg = builtins.fromJSON (builtins.readFile ./package.json);
    in {
      default = pkgs.buildNpmPackage {
        pname = "ink";
        version = pkg.version;
        src = ./.;
        npmDepsHash = "sha256-S9a0OL9HkZ5ldfwVmRCK79hO5TM9YDmgjWJrB/3/oRo=";
        nodejs = pkgs.nodejs_22;
        dontNpmBuild = true;
        installPhase = ''
          runHook preInstall
          export HOME=$TMPDIR
          export npm_config_cache=$TMPDIR/npm-cache
          mkdir -p $out
          npm pack --pack-destination $out --ignore-scripts
          runHook postInstall
        '';
        meta = {
          description = "INK protocol reference implementation";
          homepage = "https://ink.tulpa.network";
          license = with pkgs.lib.licenses; [mit asl20];
        };
      };
    });
  };
}
