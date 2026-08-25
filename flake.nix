{
  description = "INK protocol library and specification";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = {self, nixpkgs, ...}: let
    systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    forAllSystems = nixpkgs.lib.genAttrs systems;
  in {
    devShells = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      default = pkgs.mkShell {
        packages = [
          pkgs.nodejs_24
          # Matches the `go 1.26` directive in go/go.mod, so the devshell
          # builds and tests the Go implementation without setup-go.
          pkgs.go_1_26
          pkgs.actionlint
          pkgs.git
          pkgs.gitleaks
          pkgs.zizmor
        ];
        shellHook = ''
          cat <<'BANNER'

              /\
             /  \
            |    |    ___ _   _ _  __
            | () |   |_ _| \ | | |/ /
            |    |    | ||  \| | ' /
             \  /     | || |\  | . \
              \/     |___|_| \_|_|\_\

            Inter-agent Networking Kernel
          BANNER
        '';
      };
    });

    packages = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      pkg = builtins.fromJSON (builtins.readFile ./package.json);
    in {
      # Publishable npm tarball. Used to verify the package builds and
      # ships the right files; not the runnable form.
      default = pkgs.buildNpmPackage {
        pname = "ink";
        version = pkg.version;
        src = ./.;
        npmDepsHash = "sha256-wiRASyu1hipiP5oiU+3dS7+bdP70N10o7VK4KiyiTb0=";
        nodejs = pkgs.nodejs_24;
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
          description = "INK protocol library and specification";
          homepage = "https://ink.tulpa.network";
          license = with pkgs.lib.licenses; [mit asl20];
        };
      };

      # Installed CLI: `nix run github:Ad-Astra-Computing/ink -- verify-inclusion ...`
      # Copies the package + node_modules into the store and writes a
      # $out/bin/ink wrapper. No npm install step required for end users.
      cli = pkgs.buildNpmPackage {
        pname = "ink-cli";
        version = pkg.version;
        src = ./.;
        npmDepsHash = "sha256-wiRASyu1hipiP5oiU+3dS7+bdP70N10o7VK4KiyiTb0=";
        nodejs = pkgs.nodejs_24;
        dontNpmBuild = true;
        installPhase = ''
          runHook preInstall
          mkdir -p $out/lib/node_modules/@adastracomputing/ink $out/bin
          cp -r bin src package.json \
            $out/lib/node_modules/@adastracomputing/ink/
          cp -r node_modules \
            $out/lib/node_modules/@adastracomputing/ink/
          cat > $out/bin/ink <<EOF
          #!${pkgs.bash}/bin/bash
          exec ${pkgs.nodejs_24}/bin/node \\
            $out/lib/node_modules/@adastracomputing/ink/bin/ink.mjs "\$@"
          EOF
          chmod +x $out/bin/ink
          runHook postInstall
        '';
        meta = {
          description = "INK protocol CLI";
          homepage = "https://ink.tulpa.network";
          license = with pkgs.lib.licenses; [mit asl20];
          mainProgram = "ink";
        };
      };
    });

    apps = forAllSystems (system: {
      default = {
        type = "app";
        program = "${self.packages.${system}.cli}/bin/ink";
      };
    });
  };
}
