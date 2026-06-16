package ink

// Connection handshake payload validation (INK connection_request /
// connection_response). Unlike the challenge/rejection/resolution messages,
// these schemas are .strict(): an unknown key is rejected, not stripped. The
// payloads embed a profile snapshot, which embeds an availability config; both
// are also .strict(). The Go validators mirror the reference Zod schemas
// (ConnectionRequestPayloadSchema / ConnectionResponsePayloadSchema in
// src/models/intent.ts, ProfileSnapshotSchema / AvailabilityConfigSchema in
// src/models/profile.ts).

// onlyKeys reports whether m has no key outside allowed, modeling Zod .strict().
func onlyKeys(m map[string]interface{}, allowed ...string) bool {
	for k := range m {
		found := false
		for _, a := range allowed {
			if k == a {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// reqStrArray validates a required array of strings: present, at most maxLen
// entries, each at most maxUTF16 code units. A missing or non-array value fails.
func reqStrArray(m map[string]interface{}, key string, maxLen, maxUTF16 int) bool {
	v, present := m[key]
	if !present {
		return false
	}
	arr, ok := v.([]interface{})
	if !ok || len(arr) > maxLen {
		return false
	}
	for _, e := range arr {
		s, ok := e.(string)
		if !ok || utf16Len(s) > maxUTF16 {
			return false
		}
	}
	return true
}

func validateAvailabilityConfig(m map[string]interface{}) bool {
	if !onlyKeys(m, "timezone", "meetingHours", "responseSla") {
		return false
	}
	return reqStr(m, "timezone", 64) &&
		optStr(m, "meetingHours", 200) &&
		optStr(m, "responseSla", 200)
}

func validateProfileSnapshot(m map[string]interface{}) bool {
	if !onlyKeys(m, "headline", "skills", "interests", "availability", "openTo") {
		return false
	}
	if !reqStr(m, "headline", 500) {
		return false
	}
	if !reqStrArray(m, "skills", 50, 100) ||
		!reqStrArray(m, "interests", 50, 100) ||
		!reqStrArray(m, "openTo", 20, 100) {
		return false
	}
	if v, present := m["availability"]; present {
		ac, ok := v.(map[string]interface{})
		if !ok || !validateAvailabilityConfig(ac) {
			return false
		}
	}
	return true
}

// ValidateConnectionRequest validates an INK connection_request payload.
func ValidateConnectionRequest(m map[string]interface{}) bool {
	if !onlyKeys(m, "method", "introducedBy", "context", "profileSnapshot") {
		return false
	}
	method, ok := hsString(m, "method")
	if !ok || !inEnum(method, "qr", "intro", "discovery", "import") {
		return false
	}
	if !optStr(m, "introducedBy", 512) {
		return false
	}
	if !reqStr(m, "context", 2000) {
		return false
	}
	ps, ok := m["profileSnapshot"].(map[string]interface{})
	return ok && validateProfileSnapshot(ps)
}

// ValidateConnectionResponse validates an INK connection_response payload.
func ValidateConnectionResponse(m map[string]interface{}) bool {
	if !onlyKeys(m, "status", "profileSnapshot", "note") {
		return false
	}
	status, ok := hsString(m, "status")
	if !ok || !inEnum(status, "accepted", "declined", "pending") {
		return false
	}
	if !optStr(m, "note", 1000) {
		return false
	}
	if v, present := m["profileSnapshot"]; present {
		ps, ok := v.(map[string]interface{})
		if !ok || !validateProfileSnapshot(ps) {
			return false
		}
	}
	return true
}

// ValidateConnectionPayload dispatches on the kind ("connection_request" or
// "connection_response"); any other kind is rejected.
func ValidateConnectionPayload(kind string, m map[string]interface{}) bool {
	switch kind {
	case "connection_request":
		return ValidateConnectionRequest(m)
	case "connection_response":
		return ValidateConnectionResponse(m)
	default:
		return false
	}
}
