{
  description = "INK protocol Go implementation";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  # Only the module itself. The conformance tests read vector files from the
  # repository root, so `go test ./...` runs from the root flake's checks.
  outputs = {self, nixpkgs, ...}: let
    systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    forAllSystems = nixpkgs.lib.genAttrs systems;
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
        # Matches the `go 1.26` directive in go.mod.
        packages = [pkgs.go_1_26 pkgs.git];
      };
    });

    packages = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      # The directory is named `go`, which collides with GOPATH inside the
      # builder, so the source enters the store under a different name.
      src = builtins.path {
        path = ./.;
        name = "ink-go-source";
      };
      # Read rather than transcribed, so the flake cannot drift from the
      # version the CLI reports and the release-parity check enforces. Matched a
      # whole line at a time: an unanchored pattern over the file would also
      # match a commented-out declaration, and would prefer the last one.
      version = readVersion ./internal/cli/cli.go;
      meta = {
        description = "INK protocol Go implementation";
        homepage = "https://ink.tulpa.network";
        license = with pkgs.lib.licenses; [mit asl20];
      };
      build = {pname, subPackage, mainProgram}:
        pkgs.buildGoModule {
          inherit pname version src;
          vendorHash = "sha256-62TRxpLtAh7LyhI+B7/8sBsgpQ+klW43rKhhYtnLCWc=";
          # Named so a `go.sum` change invalidates the vendor derivation
          # instead of a warm store handing back the previous dependencies.
          goSum = ./go.sum;
          subPackages = [subPackage];
          meta = meta // {inherit mainProgram;};
        };
    in {
      default = build {
        pname = "ink-go";
        subPackage = "cmd/ink";
        mainProgram = "ink";
      };
      verify-server = build {
        pname = "ink-verify-server";
        subPackage = "cmd/ink-verify-server";
        mainProgram = "ink-verify-server";
      };
      witness-server = build {
        pname = "ink-witness-server";
        subPackage = "cmd/ink-witness-server";
        mainProgram = "ink-witness-server";
      };
    });

    apps = forAllSystems (system: {
      default = {
        type = "app";
        program = "${self.packages.${system}.default}/bin/ink";
      };
    });
  };
}
