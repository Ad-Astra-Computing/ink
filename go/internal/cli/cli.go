// Package cli is the command layer for the `ink` binary. It parses arguments,
// reads the artifact JSON from a file or stdin, dispatches to the transport-
// neutral verifiers in internal/verify, formats the result, and maps it to a
// process exit code. The verification logic itself lives in internal/verify so
// a later server can reuse it.
//
// Exit-code contract:
//
//	0  the artifact is valid (verified / accepted)
//	1  the artifact is well-formed but rejected (verification failed)
//	2  bad input or usage (malformed JSON, missing file, unknown command)
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Ad-Astra-Computing/ink/go/internal/verify"
)

// Version is the binary's reported version. It tracks the protocol/library
// version the verifiers are built against.
const Version = "0.9.0"

// maxInputBytes caps how much a single invocation reads from a file or stdin.
// An Agent Card or a Merkle proof is kilobytes; the cap is generous but bounds
// memory so a hostile pipe or oversized file cannot exhaust it before the
// library's own length checks run.
const maxInputBytes = 4 << 20 // 4 MiB

const usage = `ink - INK protocol verifier

Usage:
  ink <command> [--file PATH] [--pretty]

Commands:
  verify-card            Validate an Agent Card document
  verify-signature       Verify a detached Ed25519 signature over a signed request
  verify-receipt         Verify a witness inclusion receipt
  verify-audit-response  Verify a witness audit-query response
  verify-inclusion       Verify a Merkle inclusion proof
  verify-consistency     Verify a Merkle consistency proof
  version                Print the verifier version
  help                   Print this help

Input is read from --file PATH, or from stdin when --file is omitted.
Output is a JSON result object; pass --pretty for human-readable text.

Exit codes: 0 verified, 1 rejected, 2 bad input or usage.`

type verifier func([]byte) (verify.Result, error)

// Run executes one invocation and returns the process exit code. It never
// calls os.Exit, so it is directly testable; main wraps it.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "help", "-h", "--help":
		fmt.Fprintln(stdout, usage)
		return 0
	case "version", "--version":
		for _, a := range rest {
			if a != "--pretty" {
				return badInput(stderr, fmt.Sprintf("unexpected argument %q", a))
			}
		}
		enc(stdout, map[string]string{"version": Version}, hasFlag(rest, "--pretty"))
		return 0
	}

	verifiers := map[string]verifier{
		"verify-card":           verify.Card,
		"verify-signature":      verify.Signature,
		"verify-receipt":        verify.Receipt,
		"verify-audit-response": verify.AuditResponse,
		"verify-inclusion":      verify.Inclusion,
		"verify-consistency":    verify.Consistency,
	}
	v, ok := verifiers[cmd]
	if !ok {
		return badInput(stderr, fmt.Sprintf("unknown command %q", cmd))
	}

	file, pretty, err := parseFlags(rest)
	if err != nil {
		return badInput(stderr, err.Error())
	}

	data, err := readInput(file, stdin)
	if err != nil {
		return badInput(stderr, err.Error())
	}

	res, err := v(data)
	if err != nil {
		return badInput(stderr, err.Error())
	}

	enc(stdout, res, pretty)
	if res.OK {
		return 0
	}
	return 1
}

func parseFlags(args []string) (file string, pretty bool, err error) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--pretty":
			pretty = true
		case "--file":
			if i+1 >= len(args) {
				return "", false, fmt.Errorf("--file requires a path")
			}
			i++
			file = args[i]
		default:
			return "", false, fmt.Errorf("unexpected argument %q", args[i])
		}
	}
	return file, pretty, nil
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func readInput(file string, stdin io.Reader) ([]byte, error) {
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, fmt.Errorf("cannot read %s: %w", file, err)
		}
		defer f.Close()
		data, err := readCapped(f)
		if err != nil {
			return nil, fmt.Errorf("cannot read %s: %w", file, err)
		}
		return data, nil
	}
	data, err := readCapped(stdin)
	if err != nil {
		return nil, fmt.Errorf("cannot read stdin: %w", err)
	}
	return data, nil
}

// readCapped reads at most maxInputBytes and errors if the source has more, so
// the verifier never buffers an unbounded artifact.
func readCapped(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxInputBytes {
		return nil, fmt.Errorf("input exceeds %d bytes", maxInputBytes)
	}
	return data, nil
}

func badInput(stderr io.Writer, message string) int {
	enc(stderr, map[string]any{"ok": false, "error": "bad_input", "message": message}, false)
	return 2
}

// enc writes v as JSON. When pretty, it indents; the JSON form is the default
// so the output stays machine-readable for scripting and CI.
func enc(w io.Writer, v any, pretty bool) {
	e := json.NewEncoder(w)
	if pretty {
		e.SetIndent("", "  ")
	}
	_ = e.Encode(v)
}
