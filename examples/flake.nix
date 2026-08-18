{
  description = "INK examples, dev shells for the runnable reference implementations";

  # Seeded from the repo-root lock so the examples start on the same Node the
  # library is tested against. It is its own input from here on, so an example
  # can move ahead of the library when it needs to.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = {
    self,
    nixpkgs,
    ...
  }: let
    systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    forAllSystems = nixpkgs.lib.genAttrs systems;
    inherit (nixpkgs) lib;

    # One entry per npm example. Each example pins its own dependencies in
    # its own package-lock.json, so nix supplies the runtime and the tools
    # npm cannot (a container client), never the libraries. `commands` is
    # what the shell banner prints.
    #
    # examples/interop-cli is absent on purpose: it is Python with no
    # lockfile of its own, so its dependency closure has to come from nix,
    # and it keeps the flake it already has.
    npmExamples = {
      docker-receiver = {
        summary = "reference receiver bundled with esbuild, run under plain Node in a container";
        commands = ["npm ci" "npm run build" "npm test" "npm start" "docker compose up --build"];
        extraPackages = pkgs: [pkgs.docker-client pkgs.docker-compose];
      };
      foreign-sender-receiver = {
        summary = "receive-side patterns from the Accepting Foreign Senders guide";
        commands = ["npm ci" "npm test" "npm run typecheck"];
        extraPackages = _: [];
      };
      reference-receiver = {
        summary = "publicly addressable INK receiver on Cloudflare Workers";
        commands = ["npm ci" "npm test" "npm run typecheck" "npx wrangler dev" "npm run deploy"];
        extraPackages = _: [];
      };
      reference-rp = {
        summary = "relying-party half of the Sign in with INK flow";
        commands = ["npm ci" "npm test" "npm run typecheck" "npm run demo"];
        extraPackages = _: [];
      };
      reference-sender = {
        summary = "signs an envelope, discovers the inbox and POSTs it";
        commands = ["npm ci" "npm test" "npm run typecheck" "npm run send"];
        extraPackages = _: [];
      };
    };

    # The runnable npm examples on disk: any subdirectory carrying a
    # package.json. Derived, so it cannot drift from the tree.
    npmExamplesOnDisk =
      lib.sort (a: b: a < b)
      (lib.filter
        (name: builtins.pathExists (./. + "/${name}/package.json"))
        (lib.attrNames (lib.filterAttrs (_: type: type == "directory") (builtins.readDir ./.))));

    # The heredoc terminator has to survive `nix fmt` reindenting the
    # shellHook, so the banner body is built as its own string and the
    # wrapper keeps `cat`, the body and `BANNER` at one indentation level.
    banner = text: ''
      cat <<'BANNER'
      ${text}
      BANNER
    '';

    exampleShell = pkgs: name: spec:
      pkgs.mkShell {
        packages = [pkgs.nodejs_24 pkgs.git] ++ spec.extraPackages pkgs;
        shellHook = banner ''

            INK example: ${name}
            ${spec.summary}

            From examples/${name}:
          ${lib.concatMapStringsSep "\n" (c: "      ${c}") spec.commands}
        '';
      };
  in {
    devShells = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in
      (lib.mapAttrs (exampleShell pkgs) npmExamples)
      // {
        # Runs every npm example. Enter it from examples/ when you want one
        # shell for all of them; enter a named one (`nix develop .#reference-sender`)
        # when you want that example's commands in front of you.
        default = pkgs.mkShell {
          packages = [pkgs.nodejs_24 pkgs.git];
          shellHook = banner ''

              INK examples

              Node and git for every npm example below. Each example pins its
              own dependencies, so `npm ci` in its directory is all that is
              left to do. Named shells carry that example's commands:

            ${lib.concatMapStringsSep "\n" (n: "      nix develop .#${n}") (lib.attrNames npmExamples)}

              interop-cli is Python and has its own flake: cd interop-cli && nix develop
          '';
        };
      });

    checks = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
    in
      # Every shell must evaluate and build.
      self.devShells.${system}
      // {
        # Gate the hand-written table against the tree. A new runnable
        # example with no entry above, or an entry naming a directory that
        # has been removed or renamed, fails here rather than shipping a
        # flake that silently does not cover it.
        examples-covered =
          pkgs.runCommandLocal "ink-examples-covered" {
            onDisk = lib.concatStringsSep "\n" npmExamplesOnDisk;
            declared = lib.concatStringsSep "\n" (lib.sort (a: b: a < b) (lib.attrNames npmExamples));
          } ''
            printf '%s\n' "$onDisk" > on-disk
            printf '%s\n' "$declared" > declared
            if ! diff -u on-disk declared; then
              echo
              echo "examples/flake.nix npmExamples does not match the runnable"
              echo "examples on disk (- on disk, + declared). Add or remove an"
              echo "entry so every example with a package.json has a dev shell."
              exit 1
            fi
            touch $out
          '';
      });

    formatter = forAllSystems (system: nixpkgs.legacyPackages.${system}.alejandra);
  };
}
