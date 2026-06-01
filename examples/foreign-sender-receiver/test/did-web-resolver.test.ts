import { describe, it, expect } from "vitest";
import {
  didWebToDocUrl,
  extractDidWebHost,
  isIpLiteralHost,
  isPrivateHost,
} from "../src/did-web-resolver.js";

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

describe("extractDidWebHost", () => {
  it("returns the resolved host", () => {
    expect(extractDidWebHost("did:web:partner.example")).toBe("partner.example");
  });
  it("returns null for malformed DIDs", () => {
    expect(extractDidWebHost("did:web:10.0.0.1")).toBeNull();
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
