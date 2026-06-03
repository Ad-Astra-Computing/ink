{
  description = "ink-interop — standalone INK protocol reference client (Python)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = {
    self,
    nixpkgs,
    ...
  }: let
    systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    forAllSystems = nixpkgs.lib.genAttrs systems;

    # The runnable CLI, built from this directory's pyproject (hatchling).
    # Runtime deps come from nixpkgs, so the closure is fully pinned by
    # flake.lock with no network fetch at build time. The package's own
    # test suite runs during the build via pytestCheckHook; the vector
    # tests that read the repo-root test-vectors/ dir skip cleanly when
    # the example is built on its own (they are exercised from the repo).
    inkInterop = pkgs:
      pkgs.python3Packages.buildPythonApplication {
        pname = "ink-interop";
        version = "0.1.0";
        pyproject = true;
        src = ./.;

        build-system = [pkgs.python3Packages.hatchling];

        dependencies = with pkgs.python3Packages; [
          cryptography
          httpx
          typer
        ];

        nativeCheckInputs = with pkgs.python3Packages; [
          pytestCheckHook
          pytest-httpx
        ];

        pythonImportsCheck = ["ink_interop"];

        meta = {
          description = "Standalone INK protocol reference client: Ed25519 keys, hand-built envelopes, JCS signing, independent of any single implementation";
          homepage = "https://ink.tulpa.network";
          license = with pkgs.lib.licenses; [mit asl20];
          mainProgram = "ink-interop";
        };
      };
  in {
    packages = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      default = inkInterop pkgs;
      ink-interop = inkInterop pkgs;
    });

    # `nix run .#` -> the CLI.
    apps = forAllSystems (system: {
      default = {
        type = "app";
        program = "${self.packages.${system}.default}/bin/ink-interop";
      };
    });

    # `nix develop` -> an editable environment with the runtime + dev tools.
    devShells = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      default = pkgs.mkShell {
        packages = [
          (pkgs.python3.withPackages (ps:
            with ps; [
              cryptography
              httpx
              typer
              pytest
              pytest-httpx
              mypy
            ]))
          pkgs.ruff
        ];
        shellHook = ''
          echo "ink-interop dev shell. Run: pytest -q | ruff check src tests | mypy src"
        '';
      };
    });

    # `nix flake check` -> build + test the package and lint the source.
    checks = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in {
      package = self.packages.${system}.default;
      # Runs the project's configured ruff lint rules (from pyproject).
      # Source is copied into a writable tree so ruff can use its cache;
      # the store path is read-only. Format-style is left to the project,
      # so only `ruff check` runs here, not `ruff format --check`.
      lint = pkgs.runCommandLocal "ink-interop-lint" {nativeBuildInputs = [pkgs.ruff];} ''
        mkdir -p work && cd work
        cp -r ${./.}/src ${./.}/tests ${./.}/pyproject.toml .
        ruff check src tests
        touch $out
      '';
    });

    formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.nixfmt);
  };
}
