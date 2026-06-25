package ink

// dualWireType reports whether a message `type` is either the legacy
// network.tulpa.<suffix> or the vendor-neutral network.ink.<suffix> spelling.
// Receivers dual-accept both; senders keep emitting the legacy form by default.
// The actual type is always bound into the signature/AAD, never normalized, so a
// relabelled message fails verification. See specs/ink-compatibility-policy.md §1.3.
func dualWireType(actual, suffix string) bool {
	return actual == "network.tulpa."+suffix || actual == "network.ink."+suffix
}
