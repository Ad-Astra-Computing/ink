// Command ink is the INK protocol verifier: a single static binary that
// validates Agent Cards and verifies Merkle inclusion and consistency proofs
// using the reference Go library, without Node or npm. It is the second
// implementation alongside the TypeScript reference.
package main

import (
	"os"

	"github.com/Ad-Astra-Computing/ink/go/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
