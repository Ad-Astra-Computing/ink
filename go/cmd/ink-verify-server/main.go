// Command ink-verify-server runs the INK verification service: an HTTP front
// end over the same verifiers as the ink CLI. It is verify-only and stateless,
// holding no keys and issuing nothing, so it can serve as an interop and
// conformance endpoint for other implementations.
package main

import (
	"flag"
	"log"

	"github.com/Ad-Astra-Computing/ink/go/internal/server"
)

func main() {
	addr := flag.String("addr", ":8080", "address to listen on")
	flag.Parse()

	log.Printf("ink-verify-server listening on %s", *addr)
	if err := server.Serve(*addr); err != nil {
		log.Fatal(err)
	}
}
