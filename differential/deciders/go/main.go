// Command go-decide is the Go decider for the differential harness.
//
// It reads NDJSON cases on stdin, one {caseId, surface, input} per line, and
// writes one NDJSON decision per line. It is the mirror of ts-decide.mts: same
// surfaces, same field names, same fail-closed decoding rules, so the only thing
// that can differ between the two outputs is the library's decision.
//
// It imports only github.com/Ad-Astra-Computing/ink/go/ink, the package an
// adopter imports. It never calls an unexported helper, because a divergence
// found through a private path is a divergence no adopter can hit.
//
// Decoding rules marked MIRRORED must match ts-decide.mts exactly. They are
// input plumbing, never a security decision: an input that cannot be decoded
// fails closed to "reject" on both sides.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"

	"github.com/Ad-Astra-Computing/ink/go/ink"
)

type caseIn struct {
	CaseID  string                     `json:"caseId"`
	Surface string                     `json:"surface"`
	Input   map[string]json.RawMessage `json:"input"`
}

type decision struct {
	CaseID             string  `json:"caseId"`
	Result             string  `json:"result"`
	Reason             string  `json:"reason,omitempty"`
	CanonicalPrincipal *string `json:"canonicalPrincipal,omitempty"`
	CanonicalString    *string `json:"canonicalString,omitempty"`
	EpochMs            *int64  `json:"epochMs,omitempty"`
	Signature          *string `json:"signature,omitempty"`
	KeyID              *string `json:"keyId,omitempty"`
}

func reject() decision { return decision{Result: "reject"} }

func accept() decision { return decision{Result: "accept"} }

func str(in map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := in[key]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

func optStr(in map[string]json.RawMessage, key string) *string {
	raw, ok := in[key]
	if !ok {
		return nil
	}
	var s *string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil
	}
	return s
}

func strSlice(in map[string]json.RawMessage, key string) ([]string, bool) {
	raw, ok := in[key]
	if !ok {
		return nil, false
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, false
	}
	return out, true
}

// MIRRORED: a JSON number is usable as an index only when it is integral and
// lands exactly on a Go int. Both sides carry the same IEEE-754 double, so the
// conversion is the same conversion.
func asInt(in map[string]json.RawMessage, key string) (int, bool) {
	raw, ok := in[key]
	if !ok {
		return 0, false
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err != nil {
		return 0, false
	}
	if math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) {
		return 0, false
	}
	if f > math.MaxInt64/2 || f < math.MinInt64/2 {
		return 0, false
	}
	return int(f), true
}

// MIRRORED: hex to bytes, and an undecodable key is a reject, not a crash.
func keyBytes(in map[string]json.RawMessage, key string) ([]byte, bool) {
	s, ok := str(in, key)
	if !ok {
		return nil, false
	}
	if len(s)%2 != 0 {
		return nil, false
	}
	b, err := hex.DecodeString(strings.ToLower(s))
	if err != nil {
		return nil, false
	}
	return b, true
}

func decide(surface string, in map[string]json.RawMessage) decision {
	switch surface {
	case "signed-body-canonical":
		body, ok := str(in, "bodyRaw")
		if !ok {
			return reject()
		}
		parsed, err := ink.ParseSignedBody([]byte(body))
		if err != nil {
			return reject()
		}
		canonical, err := ink.JCSCanonicalize(parsed)
		if err != nil {
			return reject()
		}
		d := accept()
		d.CanonicalString = &canonical
		return d

	case "signed-body-utf8":
		h, ok := str(in, "bodyHex")
		if !ok {
			return reject()
		}
		raw, err := hex.DecodeString(h)
		if err != nil {
			return reject()
		}
		if _, err := ink.ParseSignedBody(raw); err != nil {
			return reject()
		}
		return accept()

	case "signature-base":
		pub, ok := keyBytes(in, "publicKeyHex")
		if !ok {
			return reject()
		}
		sig, ok := str(in, "signature")
		if !ok {
			return reject()
		}
		var si struct {
			Method       string      `json:"method"`
			Path         string      `json:"path"`
			RecipientDid string      `json:"recipientDid"`
			Body         interface{} `json:"body"`
			Timestamp    string      `json:"timestamp"`
		}
		if err := json.Unmarshal(in["signInput"], &si); err != nil {
			return reject()
		}
		if ink.VerifyInkSignature(ink.InkSignInput{
			Method:       si.Method,
			Path:         si.Path,
			RecipientDid: si.RecipientDid,
			Body:         si.Body,
			Timestamp:    si.Timestamp,
		}, sig, pub) {
			return accept()
		}
		return reject()

	case "principal-normalization":
		id, ok := str(in, "agentId")
		if !ok {
			return reject()
		}
		p, err := ink.CanonicalAgentPrincipal(id)
		if err != nil {
			return reject()
		}
		d := accept()
		d.CanonicalPrincipal = &p
		return d

	case "timestamp-validity":
		ts, ok := str(in, "timestamp")
		if !ok {
			return reject()
		}
		ms, valid := ink.ParseInkTimestampMs(ts)
		if !valid {
			return reject()
		}
		d := accept()
		d.EpochMs = &ms
		return d

	case "authorization-header":
		h, ok := str(in, "header")
		if !ok {
			return reject()
		}
		p := ink.ParseInkAuthHeader(h)
		if !p.OK {
			return decision{Result: "reject", Reason: p.Reason}
		}
		d := accept()
		sig := p.Signature
		d.Signature = &sig
		if p.KeyID != "" {
			kid := p.KeyID
			d.KeyID = &kid
		}
		return d

	case "agent-card":
		var card map[string]interface{}
		if err := json.Unmarshal(in["card"], &card); err != nil {
			return reject()
		}
		if ink.ValidateAgentCard(card) {
			return accept()
		}
		return reject()

	case "agent-card-fetch":
		status, ok := asInt(in, "status")
		if !ok {
			return reject()
		}
		bodyRaw, _ := str(in, "bodyRaw")
		reqID, _ := str(in, "requestedAgentId")
		if ink.EvaluateAgentCardFetch(status, optStr(in, "contentType"), optStr(in, "contentLength"), bodyRaw, reqID, optStr(in, "resolutionDid")) {
			return accept()
		}
		return reject()

	case "private-hostname":
		h, ok := str(in, "hostname")
		if !ok {
			return reject()
		}
		// accept means the destination is public, matching the conformance category.
		if ink.IsPrivateHostname(h) {
			return reject()
		}
		return accept()

	case "merkle-checkpoint":
		body, ok := str(in, "body")
		if !ok {
			return reject()
		}
		parsed, valid := ink.ParseCheckpoint(body)
		if !valid {
			return reject()
		}
		canonical := ink.FormatCheckpoint(parsed)
		d := accept()
		d.CanonicalString = &canonical
		return d

	case "merkle-inclusion":
		leafIndex, ok1 := asInt(in, "leafIndex")
		treeSize, ok2 := asInt(in, "treeSize")
		if !ok1 || !ok2 {
			return reject()
		}
		leafHash, _ := str(in, "leafHash")
		rootHash, _ := str(in, "rootHash")
		proof, _ := strSlice(in, "inclusionProof")
		if ink.VerifyInclusionProof(leafHash, proof, leafIndex, treeSize, rootHash) {
			return accept()
		}
		return reject()

	case "merkle-consistency":
		first, ok1 := asInt(in, "first")
		second, ok2 := asInt(in, "second")
		if !ok1 || !ok2 {
			return reject()
		}
		firstRoot, _ := str(in, "firstRoot")
		secondRoot, _ := str(in, "secondRoot")
		proof, _ := strSlice(in, "proof")
		if ink.VerifyConsistencyProof(first, firstRoot, second, secondRoot, proof) {
			return accept()
		}
		return reject()

	case "discovery-query-envelope":
		pub, ok := keyBytes(in, "publicKeyHex")
		if !ok {
			return reject()
		}
		envelopeRaw, ok := str(in, "envelopeRaw")
		if !ok {
			return reject()
		}
		now, _ := str(in, "now")
		// A directory names the spellings of itself it answers to. The case
		// carries one string or a list of them; both decode to the same set.
		var audience []string
		if single, isSingle := str(in, "audience"); isSingle {
			audience = []string{single}
		} else if list, isList := strSlice(in, "audience"); isList {
			audience = list
		} else {
			return reject()
		}
		var seen []ink.DiscoveryQueryKey
		if raw, present := in["seenNonces"]; present {
			var list []struct {
				From  string `json:"from"`
				Nonce string `json:"nonce"`
			}
			if err := json.Unmarshal(raw, &list); err == nil {
				for _, k := range list {
					seen = append(seen, ink.DiscoveryQueryKey{From: k.From, Nonce: k.Nonce})
				}
			}
		}
		ok2, reason := ink.VerifyDiscoveryQueryEnvelope([]byte(envelopeRaw), pub, ink.DiscoveryQueryContext{
			Audience:   audience,
			Now:        now,
			SeenNonces: seen,
		})
		if ok2 {
			return accept()
		}
		return decision{Result: "reject", Reason: string(reason)}

	default:
		return decision{Result: "reject", Reason: "__harness_error:unknown surface " + surface}
	}
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 1<<20), 64<<20)
	out := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer out.Flush()

	enc := json.NewEncoder(out)
	for in.Scan() {
		line := in.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var c caseIn
		if err := json.Unmarshal(line, &c); err != nil {
			fmt.Fprintf(os.Stderr, "go-decide: bad case line: %v\n", err)
			os.Exit(2)
		}
		d := run(c)
		d.CaseID = c.CaseID
		if err := enc.Encode(d); err != nil {
			fmt.Fprintf(os.Stderr, "go-decide: encode: %v\n", err)
			os.Exit(2)
		}
	}
	if err := in.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "go-decide: read: %v\n", err)
		os.Exit(2)
	}
}

// run isolates a panic to one case. A panic the surface did not model is
// reported, never swallowed: an unhandled crash on one side is itself a
// divergence worth seeing.
func run(c caseIn) (d decision) {
	defer func() {
		if r := recover(); r != nil {
			d = decision{Result: "reject", Reason: fmt.Sprintf("__harness_error:%v", r)}
		}
	}()
	return decide(c.Surface, c.Input)
}
