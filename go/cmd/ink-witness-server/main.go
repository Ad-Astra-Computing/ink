// Command ink-witness-server runs a single INK witness log over HTTP.
// It holds an Ed25519 witness key, issues signed inclusion receipts for
// submitted audit events, answers audit queries with signed audit-query
// responses, and serves the current checkpoint and the inclusion and
// consistency proofs of its tree. By default it is in-memory, so a restart
// starts an empty log; pass -data-dir to keep a durable append-only record file
// that is replayed on startup to rebuild the tree. It is a development and
// interop witness, not a durable production log.
//
// The witness key is a hex-encoded 32-byte Ed25519 seed read from
// INK_WITNESS_SEED_HEX. Submit and audit-query are authenticated by default: set
// the bearer token in INK_WITNESS_SUBMIT_TOKEN, or pass -allow-unauthenticated to
// run an open server for local testing.
package main

import (
	"flag"
	"log"
	"os"

	"github.com/Ad-Astra-Computing/ink/go/internal/witnessserver"
)

func main() {
	addr := flag.String("addr", ":8081", "address to listen on")
	origin := flag.String("origin", "", "witness origin identity bound into every checkpoint")
	serviceDid := flag.String("service-did", "", "witness DID bound into an audit-query response, for example did:web:witness.example")
	maxLeaves := flag.Int("max-leaves", 0, "cap on the tree size (0 selects the default)")
	dataDir := flag.String("data-dir", "", "directory for the durable append-only record file; empty keeps the log in memory and a restart starts empty")
	allowUnauth := flag.Bool("allow-unauthenticated", false, "accept submit and audit-query without a bearer token (local testing only)")
	flag.Parse()

	if *origin == "" {
		log.Fatal("-origin is required")
	}
	if *serviceDid == "" {
		log.Fatal("-service-did is required")
	}
	seedHex := os.Getenv("INK_WITNESS_SEED_HEX")
	if seedHex == "" {
		log.Fatal("INK_WITNESS_SEED_HEX is required (hex-encoded 32-byte ed25519 seed)")
	}
	priv, err := witnessserver.PrivateKeyFromSeedHex(seedHex)
	if err != nil {
		log.Fatalf("witness key: %v", err)
	}

	cfg := witnessserver.Config{
		Origin:               *origin,
		PrivateKey:           priv,
		ServiceDid:           *serviceDid,
		SubmitToken:          os.Getenv("INK_WITNESS_SUBMIT_TOKEN"),
		AllowUnauthenticated: *allowUnauth,
		MaxLeaves:            *maxLeaves,
		DataDir:              *dataDir,
	}

	log.Printf("ink-witness-server listening on %s (origin %s)", *addr, *origin)
	if err := witnessserver.Serve(*addr, cfg); err != nil {
		log.Fatal(err)
	}
}
