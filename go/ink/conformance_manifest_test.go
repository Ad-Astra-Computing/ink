package ink

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
)

// manifestPath is the machine-readable corpus index, relative to this package.
const manifestPath = "../../conformance/v1/manifest.json"

type manifestCategory struct {
	ID        string `json:"id"`
	Vector    string `json:"vector"`
	Profile   string `json:"profile"`
	Spec      string `json:"spec"`
	Summary   string `json:"summary"`
	CaseCount int    `json:"caseCount"`
	SHA256    string `json:"sha256"`
}

// goProfileCategories freezes the full conformance profile partition: every
// category mapped to the profile that requires it (see
// specs/ink-conformance-profile.md). It is the second-implementation half of
// the freeze in test/conformance-profile.test.ts; moving a category between
// profiles, or adding one without classifying it, must be a deliberate edit in
// both places, not a silent drift. The `base` set is the floor every conforming
// INK implementation MUST satisfy.
var goProfileCategories = map[string][]string{
	"base": {
		"agent-card",
		"agent-card-fetch",
		"connection-payload",
		"first-contact-transcript",
		"jcs-number",
		"jcs-string-safety",
		"key-rotation",
		"principal-normalization",
		"private-hostname",
		"replay-freshness",
		"signature-base",
		"signed-body-utf8",
		"timestamp-validity",
	},
	"encryption":  {"payload-encryption"},
	"audit":       {"audit-query-response", "inclusion-receipt", "merkle-leaf"},
	"witness":     {"merkle-checkpoint", "merkle-consistency", "merkle-inclusion"},
	"containment": {"handshake-message"},
	"discovery":   {"discovery-query-envelope"},
}

type conformanceManifest struct {
	Format     string             `json:"format"`
	Corpus     string             `json:"corpus"`
	Categories []manifestCategory `json:"categories"`
}

// goVerifiedCategories lists the conformance categories this Go implementation
// has a verifier and a TestXxx function for in conformance_test.go. It is the
// set the Go suite DECLARES it covers; adding a manifest category requires
// adding both its verifier test there and an entry here, or the parity test
// below fails. It is a drift tripwire, not proof that a verifier runs (that is
// what the per-category tests in conformance_test.go provide).
var goVerifiedCategories = []string{
	"agent-card",
	"agent-card-fetch",
	"audit-query-response",
	"connection-payload",
	"discovery-query-envelope",
	"first-contact-transcript",
	"handshake-message",
	"inclusion-receipt",
	"jcs-number",
	"jcs-string-safety",
	"key-rotation",
	"merkle-checkpoint",
	"merkle-consistency",
	"merkle-inclusion",
	"merkle-leaf",
	"payload-encryption",
	"principal-normalization",
	"private-hostname",
	"replay-freshness",
	"signature-base",
	"signed-body-utf8",
	"timestamp-validity",
}

func loadManifest(t *testing.T) conformanceManifest {
	t.Helper()
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if dup, path := firstDuplicateKey(t, raw); dup {
		t.Fatalf("manifest has a duplicate object key at %s; a duplicate key parses ambiguously across implementations", path)
	}
	var m conformanceManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	return m
}

func TestManifestFormat(t *testing.T) {
	m := loadManifest(t)
	if m.Format != "ink.conformance.manifest.v1" {
		t.Errorf("format = %q, want ink.conformance.manifest.v1", m.Format)
	}
	if m.Corpus != "ink.conformance.v1" {
		t.Errorf("corpus = %q, want ink.conformance.v1", m.Corpus)
	}
}

func TestManifestVectorsLoadAndMatch(t *testing.T) {
	m := loadManifest(t)
	dir := filepath.Dir(manifestPath)
	for _, cat := range m.Categories {
		path := filepath.Join(dir, cat.Vector)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s: read vector: %v", cat.ID, err)
			continue
		}
		// A duplicate object key in a vector parses ambiguously (last-key-wins
		// here, first-key-wins or reject elsewhere), so two implementations
		// could read the same bytes as different cases. Reject it outright; the
		// generator never emits one.
		if dup, where := firstDuplicateKey(t, raw); dup {
			t.Errorf("%s: vector has a duplicate object key at %s", cat.ID, where)
		}
		h := sha256.Sum256(raw)
		if got := hex.EncodeToString(h[:]); got != cat.SHA256 {
			t.Errorf("%s: sha256 = %s, want %s", cat.ID, got, cat.SHA256)
		}
		var vf vectorFile
		if err := json.Unmarshal(raw, &vf); err != nil {
			t.Errorf("%s: parse vector: %v", cat.ID, err)
			continue
		}
		if vf.Format != "ink.conformance.v1" {
			t.Errorf("%s: vector format = %q", cat.ID, vf.Format)
		}
		if vf.Category != cat.ID {
			t.Errorf("%s: vector category = %q", cat.ID, vf.Category)
		}
		if len(vf.Cases) != cat.CaseCount {
			t.Errorf("%s: caseCount = %d, want %d", cat.ID, len(vf.Cases), cat.CaseCount)
		}
	}
}

func TestDuplicateKeyDetector(t *testing.T) {
	cases := []struct {
		json string
		want string
	}{
		{`{"a":1,"b":{"c":2,"c":3}}`, "$.b.c"},
		{`{"items":[{"id":1},{"id":1,"id":2}]}`, "$.items[1].id"},
		{`{"a":1,"b":[1,2,{"x":true}],"c":"d"}`, ""},
		{`{"format":"ink.conformance.manifest.v1","categories":[]}`, ""},
		// Keys are compared by decoded member name, so an escape-encoded
		// duplicate is caught the same way the TS detector catches it.
		{`{"a":1,"a":2}`, "$.a"},
		{`{"/":1,"\/":2}`, "$./"},
	}
	for _, c := range cases {
		dec := json.NewDecoder(bytes.NewReader([]byte(c.json)))
		dup, where := scanDuplicateKey(dec, "$")
		if c.want == "" {
			if dup {
				t.Errorf("%s: unexpected duplicate at %s", c.json, where)
			}
			continue
		}
		if !dup || where != c.want {
			t.Errorf("%s: got (%v,%q), want (true,%q)", c.json, dup, where, c.want)
		}
	}
}

func TestManifestMatchesGoCategories(t *testing.T) {
	m := loadManifest(t)
	manifestIDs := make([]string, len(m.Categories))
	for i, c := range m.Categories {
		manifestIDs[i] = c.ID
	}
	sort.Strings(manifestIDs)
	verified := append([]string(nil), goVerifiedCategories...)
	sort.Strings(verified)

	if len(manifestIDs) != len(verified) {
		t.Fatalf("category count: manifest %d, go %d", len(manifestIDs), len(verified))
	}
	for i := range manifestIDs {
		if manifestIDs[i] != verified[i] {
			t.Errorf("category mismatch at %d: manifest %q, go %q", i, manifestIDs[i], verified[i])
		}
	}
}

func TestManifestProfilesFrozen(t *testing.T) {
	m := loadManifest(t)
	got := map[string][]string{}
	for _, c := range m.Categories {
		if _, ok := goProfileCategories[c.Profile]; !ok {
			t.Errorf("%s: unknown profile %q", c.ID, c.Profile)
			continue
		}
		got[c.Profile] = append(got[c.Profile], c.ID)
	}
	for profile, wantIDs := range goProfileCategories {
		want := append([]string(nil), wantIDs...)
		sort.Strings(want)
		have := append([]string(nil), got[profile]...)
		sort.Strings(have)
		if len(have) != len(want) {
			t.Errorf("%s profile count: manifest %d, frozen %d", profile, len(have), len(want))
			continue
		}
		for i := range want {
			if have[i] != want[i] {
				t.Errorf("%s profile mismatch at %d: manifest %q, frozen %q", profile, i, have[i], want[i])
			}
		}
	}
}

// firstDuplicateKey reports whether any JSON object in data declares the same
// member name twice, and a dotted path to the first one found. Both encoding/json
// and the JS JSON.parse silently keep the last duplicate, so a drift gate that
// only unmarshals would accept a corpus that a stricter or first-key-wins
// implementation reads differently.
func firstDuplicateKey(t *testing.T, data []byte) (bool, string) {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dup, path := scanDuplicateKey(dec, "$")
	return dup, path
}

func scanDuplicateKey(dec *json.Decoder, path string) (bool, string) {
	tok, err := dec.Token()
	if err != nil {
		return false, ""
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return false, ""
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return false, ""
			}
			key, _ := keyTok.(string)
			child := path + "." + key
			if seen[key] {
				return true, child
			}
			seen[key] = true
			if dup, where := scanDuplicateKey(dec, child); dup {
				return true, where
			}
		}
		_, _ = dec.Token() // closing }
	case '[':
		i := 0
		for dec.More() {
			if dup, where := scanDuplicateKey(dec, path+"["+strconv.Itoa(i)+"]"); dup {
				return true, where
			}
			i++
		}
		_, _ = dec.Token() // closing ]
	}
	return false, ""
}
