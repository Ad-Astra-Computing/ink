import { describe, it, expect } from "vitest";
import {
  didWebToDocUrl,
  extractDidWebHost,
  isIpLiteralHost,
  isPrivateHost,
} from "../src/did-web-resolver.js";
import { validateOutboundDeliveryUrl } from "../src/outbound-delivery.js";

describe("didWebToDocUrl", () => {
  it("returns well-known URL for bare host", () => {
    expect(didWebToDocUrl("did:web:example.com")).toBe(
      "https://example.com/.well-known/did.json",
    );
  });

  it("returns path-style URL for nested DID", () => {
    expect(didWebToDocUrl("did:web:example.com:user:alice")).toBe(
      "https://example.com/user/alice/did.json",
    );
  });

  it("rejects dot segments in the path form", () => {
    expect(didWebToDocUrl("did:web:example.com:..")).toBeNull();
    expect(didWebToDocUrl("did:web:example.com:.")).toBeNull();
    expect(didWebToDocUrl("did:web:example.com:user:..:admin")).toBeNull();
  });

  it("rejects malformed hosts", () => {
    expect(didWebToDocUrl("did:web:")).toBeNull();
    expect(didWebToDocUrl("did:web:not_valid_host_with_underscore")).toBeNull();
  });

  it("rejects private and loopback hosts", () => {
    expect(didWebToDocUrl("did:web:127.0.0.1")).toBeNull();
    expect(didWebToDocUrl("did:web:10.0.0.5")).toBeNull();
    expect(didWebToDocUrl("did:web:localhost")).toBeNull();
  });
});

// A `%3A` in the host part of a did:web identifier is a port. Dropping it and
// resolving at the default port silently retargets a different origin, so the
// rule is: carry the port, or reject the identifier. Never drop it.
describe("didWebToDocUrl carries the %3A port", () => {
  it("carries the port into the document URL", () => {
    expect(didWebToDocUrl("did:web:example.com%3A8443")).toBe(
      "https://example.com:8443/.well-known/did.json",
    );
  });

  it("carries the port on path-form identifiers", () => {
    expect(didWebToDocUrl("did:web:example.com%3A8443:user:alice")).toBe(
      "https://example.com:8443/user/alice/did.json",
    );
  });

  it("rejects rather than drops a malformed port", () => {
    expect(didWebToDocUrl("did:web:example.com%3A")).toBeNull();
    expect(didWebToDocUrl("did:web:example.com%3Aabc")).toBeNull();
    expect(didWebToDocUrl("did:web:example.com%3A0")).toBeNull();
    expect(didWebToDocUrl("did:web:example.com%3A08443")).toBeNull();
    expect(didWebToDocUrl("did:web:example.com%3A65536")).toBeNull();
    expect(didWebToDocUrl("did:web:example.com%3A8443%3A9")).toBeNull();
    expect(didWebToDocUrl("did:web:example.com%3a8443")).toBeNull();
  });

  // The W3C did:web method allows an optional percent-encoded port and bans no
  // value, so `%3A443` is a legal identifier and refusing it is an interop bug.
  // It names the default https origin, which is exactly where it resolves. The
  // sign-in profile's extra ban on an explicit 443 is profile-local
  // (`deriveRpOrigin`) and does not reach this path.
  it("accepts an explicit 443 and resolves it at the default origin", () => {
    expect(didWebToDocUrl("did:web:example.com%3A443")).toBe(
      "https://example.com/.well-known/did.json",
    );
    expect(extractDidWebHost("did:web:example.com%3A443")).toBe("example.com");
  });

  it("still rejects a private host that carries a port", () => {
    expect(didWebToDocUrl("did:web:localhost%3A8443")).toBeNull();
    expect(didWebToDocUrl("did:web:127.0.0.1%3A8443")).toBeNull();
  });
});

describe("extractDidWebHost", () => {
  it("returns the resolved host", () => {
    expect(extractDidWebHost("did:web:partner.example")).toBe("partner.example");
  });
  it("returns null for malformed DIDs", () => {
    expect(extractDidWebHost("did:web:10.0.0.1")).toBeNull();
  });
  it("returns the authority including the carried port", () => {
    // The identity binding compares this against the delivery URL's authority,
    // so a DID that names a port must not bind to the default-port origin.
    expect(extractDidWebHost("did:web:partner.example%3A8443")).toBe("partner.example:8443");
  });
});

describe("outbound identity binding includes the port", () => {
  const bind = (did: string, url: string) => {
    const host = extractDidWebHost(did);
    return validateOutboundDeliveryUrl(url, { requiredDidWebHost: host ?? undefined });
  };

  it("binds a ported DID to the same ported origin", () => {
    const r = bind("did:web:partner.example%3A8443", "https://partner.example:8443/ink/v1/inbound");
    expect(r.ok).toBe(true);
  });

  it("refuses to deliver a ported DID to the default-port origin", () => {
    const r = bind("did:web:partner.example%3A8443", "https://partner.example/ink/v1/inbound");
    expect(r).toEqual({ ok: false, reason: "host_mismatch" });
  });

  it("refuses to deliver a portless DID to a ported origin", () => {
    const r = bind("did:web:partner.example", "https://partner.example:8443/ink/v1/inbound");
    expect(r).toEqual({ ok: false, reason: "host_mismatch" });
  });

  it("still accepts the portless case and a trailing-dot host", () => {
    expect(bind("did:web:partner.example", "https://partner.example/ink/v1/inbound").ok).toBe(true);
    expect(bind("did:web:partner.example", "https://partner.example./ink/v1/inbound").ok).toBe(true);
  });
});

describe("isIpLiteralHost", () => {
  it("matches IPv4 dotted-quad", () => {
    expect(isIpLiteralHost("127.0.0.1")).toBe(true);
    expect(isIpLiteralHost("192.168.1.1")).toBe(true);
  });
  it("matches bracketed IPv6", () => {
    expect(isIpLiteralHost("::1")).toBe(true);
    expect(isIpLiteralHost("::ffff:127.0.0.1")).toBe(true);
    expect(isIpLiteralHost("fe80::1")).toBe(true);
  });
  it("matches decimal IPv4 form", () => {
    expect(isIpLiteralHost("2130706433")).toBe(true);
  });
  it("returns false for hostnames", () => {
    expect(isIpLiteralHost("partner.example")).toBe(false);
  });
});

describe("isPrivateHost", () => {
  it("rejects all the obvious private ranges", () => {
    expect(isPrivateHost("127.0.0.1")).toBe(true);
    expect(isPrivateHost("10.0.0.5")).toBe(true);
    expect(isPrivateHost("172.16.0.1")).toBe(true);
    expect(isPrivateHost("192.168.1.1")).toBe(true);
    expect(isPrivateHost("169.254.169.254")).toBe(true);
    expect(isPrivateHost("localhost")).toBe(true);
  });
});
