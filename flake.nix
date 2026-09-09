{
  description = "INK protocol library and specification";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = {self, nixpkgs, ...}: let
    systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    forAllSystems = nixpkgs.lib.genAttrs systems;
    # A whole line at a time. An unanchored match over the file would also
    # match a commented-out declaration, and would prefer the last one.
    readVersion = file: let
      lines = builtins.filter builtins.isString (builtins.split "\n" (builtins.readFile file));
      matched = builtins.filter (m: m != null)
        (map (line: builtins.match ''const Version = "([0-9][^"]*)"'' line) lines);
    in builtins.elemAt (builtins.head matched) 0;
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
        npmDepsHash = "sha256-J9B3fqC/at9KaDm6EClyVu3EpKlRQOaXCZIhNJvZAO8=";
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
        npmDepsHash = "sha256-J9B3fqC/at9KaDm6EClyVu3EpKlRQOaXCZIhNJvZAO8=";
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

    checks = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      # `go test ./...` over the whole module. It runs here rather than from
      # go/flake.nix because the conformance tests read vector files from
      # conformance/v1/vectors, above the Go module's own directory.
      go-tests = pkgs.buildGoModule {
        pname = "ink-go-tests";
        version = readVersion ./go/internal/cli/cli.go;
        src = builtins.path {
          path = ./.;
          name = "ink-source";
        };
        modRoot = "go";
        vendorHash = "sha256-62TRxpLtAh7LyhI+B7/8sBsgpQ+klW43rKhhYtnLCWc=";
        # Named so a `go.sum` change invalidates the vendor derivation instead
        # of a warm store handing back the previous dependencies.
        goSum = ./go/go.sum;
        buildPhase = ''
          runHook preBuild
          go test ./...
          runHook postBuild
        '';
        installPhase = "touch $out";
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
