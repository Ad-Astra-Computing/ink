package ink

import (
	"bytes"
	"testing"
)

func TestBase58LeadingZeros(t *testing.T) {
	cases := []struct {
		s    string
		want []byte
	}{
		{"1", []byte{0x00}},
		{"11", []byte{0x00, 0x00}},
		{"", []byte{}},
	}
	for _, c := range cases {
		got, err := decodeBase58(c.s)
		if err != nil {
			t.Fatalf("decodeBase58(%q): %v", c.s, err)
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("decodeBase58(%q) = %v, want %v", c.s, got, c.want)
		}
		if enc := encodeBase58(c.want); enc != c.s {
			t.Errorf("encodeBase58(%v) = %q, want %q", c.want, enc, c.s)
		}
	}
}

func TestMultibaseRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	mb, err := EncodePublicKeyMultibase(key)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	back, err := DecodePublicKeyMultibase(mb)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(back, key) {
		t.Errorf("round trip changed the key")
	}
}

func TestDecodeRejectsBadInput(t *testing.T) {
	cases := []string{
		"",                                     // empty
		"xabc",                                 // wrong multibase prefix
		"z111",                                 // decodes to zero bytes, wrong multicodec
		"z" + encodeBase58([]byte{0xed, 0x01}), // multicodec but no key
	}
	for _, c := range cases {
		if _, err := DecodePublicKeyMultibase(c); err == nil {
			t.Errorf("DecodePublicKeyMultibase(%q): expected error", c)
		}
	}
}

func TestUTF16Len(t *testing.T) {
	// BMP char (你) is one UTF-16 unit; an astral char (emoji) is a surrogate pair.
	if got := utf16Len("你你"); got != 2 {
		t.Errorf("utf16Len(BMP x2) = %d, want 2", got)
	}
	if got := utf16Len("\U0001F600"); got != 2 {
		t.Errorf("utf16Len(astral) = %d, want 2", got)
	}
}
