package ink

import (
	"regexp"
	"strconv"
	"strings"
)

// Host-safety classifier: a faithful port of the TypeScript isPrivateHostname
// (src/discovery/agent-card.ts). The two implementations must make the same
// accept (public) / reject (private, special, or malformed IP-shaped) decision
// on every hostname, which is what the `private-hostname` conformance category
// pins. See specs/ink-private-hostname.md.

var (
	v4MappedDottedRe = regexp.MustCompile(`^::ffff:(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$`)
	dottedV4Re       = regexp.MustCompile(`^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$`)
	allDigitsRe      = regexp.MustCompile(`^\d+$`)
	hexGroupRe       = regexp.MustCompile(`^[0-9a-f]{1,4}$`)
)

// IsPrivateHostname reports whether a hostname is loopback, private,
// link-local, or an IANA special-use address, and so unsafe to fetch as a
// public discovery target.
func IsPrivateHostname(hostname string) bool {
	h := strings.ToLower(hostname)
	for strings.HasSuffix(h, ".") {
		h = h[:len(h)-1]
	}
	if h == "" {
		return true
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	bare := h
	if strings.HasPrefix(bare, "[") && strings.HasSuffix(bare, "]") {
		bare = bare[1 : len(bare)-1]
	}
	// IPv4-mapped IPv6 in dotted form (::ffff:1.2.3.4), checked before general
	// IPv6 so the v4 octet rules apply.
	if m := v4MappedDottedRe.FindStringSubmatch(bare); m != nil {
		return dottedV4Unsafe(smallInt(m[1]), smallInt(m[2]), smallInt(m[3]), smallInt(m[4]))
	}
	// General IPv6 literal: expand and apply special-use ranges. Unparseable
	// v6 fails closed.
	if strings.Contains(bare, ":") {
		groups := expandIPv6(bare)
		if groups == nil {
			return true
		}
		// IPv4-mapped (::ffff:HHHH:HHHH): extract embedded v4 and use v4 rules.
		if groups[0] == 0 && groups[1] == 0 && groups[2] == 0 && groups[3] == 0 &&
			groups[4] == 0 && groups[5] == 0xffff {
			hi, lo := groups[6], groups[7]
			return dottedV4Unsafe((hi>>8)&0xff, hi&0xff, (lo>>8)&0xff, lo&0xff)
		}
		return isPrivateIPv6Groups(groups)
	}
	// Dotted-quad IPv4 (decimal only).
	if m := dottedV4Re.FindStringSubmatch(bare); m != nil {
		return dottedV4Unsafe(smallInt(m[1]), smallInt(m[2]), smallInt(m[3]), smallInt(m[4]))
	}
	// Single-segment numeric forms (e.g. 2130706433) are suspicious.
	if allDigitsRe.MatchString(bare) {
		return true
	}
	return false
}

// smallInt parses a 1-3 digit regex capture (0..999).
func smallInt(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// dottedV4Unsafe matches the TypeScript: a dotted IPv4 is unsafe if any octet
// is out of range (a malformed IP-shaped name, fail closed) or it is in a
// private/special-use block.
func dottedV4Unsafe(a, b, c, d int) bool {
	if a > 255 || b > 255 || c > 255 || d > 255 {
		return true
	}
	return isPrivateIPv4(a, b, c, d)
}

// isPrivateIPv4 covers the IANA Special-Purpose IPv4 Address Registry, matching
// the TypeScript classifier rule-for-rule.
func isPrivateIPv4(a, b, c, _ int) bool {
	switch {
	case a == 0:
		return true // 0.0.0.0/8
	case a == 10:
		return true // 10/8 private
	case a == 100 && b >= 64 && b <= 127:
		return true // 100.64/10 CGNAT
	case a == 127:
		return true // 127/8 loopback
	case a == 169 && b == 254:
		return true // 169.254/16 link-local + metadata
	case a == 172 && b >= 16 && b <= 31:
		return true // 172.16/12 private
	case a == 192 && b == 0 && c == 0:
		return true // 192.0.0/24
	case a == 192 && b == 0 && c == 2:
		return true // 192.0.2/24 TEST-NET-1
	case a == 192 && b == 31 && c == 196:
		return true // 192.31.196/24
	case a == 192 && b == 52 && c == 193:
		return true // 192.52.193/24
	case a == 192 && b == 88 && c == 99:
		return true // 192.88.99/24 6to4 relay
	case a == 192 && b == 168:
		return true // 192.168/16 private
	case a == 192 && b == 175 && c == 48:
		return true // 192.175.48/24 AS112
	case a == 198 && (b == 18 || b == 19):
		return true // 198.18/15 benchmarking
	case a == 198 && b == 51 && c == 100:
		return true // 198.51.100/24 TEST-NET-2
	case a == 203 && b == 0 && c == 113:
		return true // 203.0.113/24 TEST-NET-3
	case a >= 224:
		return true // 224/4 multicast + reserved + broadcast
	}
	return false
}

// isPrivateIPv6Groups classifies an 8-group IPv6 address against the IANA v6
// special-use registry, matching the TypeScript classifier rule-for-rule.
func isPrivateIPv6Groups(g []int) bool {
	if len(g) != 8 {
		return true
	}
	if g[0] == 0 && g[1] == 0 && g[2] == 0 && g[3] == 0 &&
		g[4] == 0 && g[5] == 0 && g[6] == 0 && (g[7] == 0 || g[7] == 1) {
		return true // ::/128 + ::1/128
	}
	high := g[0]
	if high&0xffc0 == 0xfe80 {
		return true // fe80::/10 link-local
	}
	if high&0xfe00 == 0xfc00 {
		return true // fc00::/7 ULA
	}
	if high&0xff00 == 0xff00 {
		return true // ff00::/8 multicast
	}
	if high == 0x2001 {
		if g[1] == 0x0000 {
			return true // 2001::/32 Teredo
		}
		if g[1] == 0x0002 && g[2] == 0 {
			return true // 2001:2::/48 BMWG
		}
		if g[1]&0xfff0 == 0x0010 {
			return true // 2001:10::/28 ORCHID
		}
		if g[1]&0xfff0 == 0x0020 {
			return true // 2001:20::/28 ORCHIDv2
		}
		if g[1] == 0x0db8 {
			return true // 2001:db8::/32 documentation
		}
	}
	if high == 0x2002 {
		a := (g[1] >> 8) & 0xff
		b := g[1] & 0xff
		c := (g[2] >> 8) & 0xff
		d := g[2] & 0xff
		if isPrivateIPv4(a, b, c, d) {
			return true // 2002::/16 6to4 with private embedded v4
		}
	}
	if high == 0x0064 && g[1] == 0xff9b && g[2] == 0 && g[3] == 0 && g[4] == 0 && g[5] == 0 {
		return true // 64:ff9b::/96 NAT64
	}
	if high == 0x0064 && g[1] == 0xff9b && g[2] == 0x0001 {
		return true // 64:ff9b:1::/48
	}
	if high == 0x0100 && g[1] == 0 && g[2] == 0 && g[3] == 0 {
		return true // 100::/64 discard
	}
	if high == 0x0100 && g[1] == 0 && g[2] == 0 && g[3] == 0x0001 {
		return true // 100:0:0:1::/64
	}
	if high&0xfff0 == 0x3ff0 {
		return true // 3fff::/20 BMWG v6
	}
	if high == 0x5f00 {
		return true // 5f00::/16 SRv6
	}
	return false
}

// expandIPv6 expands an IPv6 address with optional `::` into 8 16-bit groups,
// returning nil on malformed input or any zone/scope id. Matches the
// TypeScript expandIPv6 (string-level, no net.ParseIP, so the accept/reject
// decision is identical across runtimes).
func expandIPv6(addr string) []int {
	if strings.Contains(addr, "%") {
		return nil
	}
	dcIdx := strings.Index(addr, "::")
	var leftStr, rightStr string
	if dcIdx == -1 {
		leftStr = addr
		rightStr = ""
	} else {
		leftStr = addr[:dcIdx]
		rightStr = addr[dcIdx+2:]
		if strings.Contains(leftStr, "::") || strings.Contains(rightStr, "::") {
			return nil
		}
	}
	var leftParts, rightParts []string
	if leftStr != "" {
		leftParts = strings.Split(leftStr, ":")
	}
	if rightStr != "" {
		rightParts = strings.Split(rightStr, ":")
	}
	fill := 8 - (len(leftParts) + len(rightParts))
	if fill < 0 {
		return nil
	}
	if dcIdx == -1 && fill != 0 {
		return nil
	}
	parts := make([]string, 0, 8)
	parts = append(parts, leftParts...)
	for i := 0; i < fill; i++ {
		parts = append(parts, "0")
	}
	parts = append(parts, rightParts...)
	if len(parts) != 8 {
		return nil
	}
	out := make([]int, 0, 8)
	for _, p := range parts {
		if !hexGroupRe.MatchString(p) {
			return nil
		}
		v, _ := strconv.ParseInt(p, 16, 32)
		out = append(out, int(v))
	}
	return out
}
