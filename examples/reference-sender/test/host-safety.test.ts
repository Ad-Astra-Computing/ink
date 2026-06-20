import { describe, it, expect } from "vitest";
import { isIpLiteralHost, isPrivateHost } from "../src/host-safety.ts";

describe("isIpLiteralHost", () => {
  it("flags IPv4 dotted-quad and decimal forms", () => {
    expect(isIpLiteralHost("203.0.113.1")).toBe(true);
    expect(isIpLiteralHost("3221225985")).toBe(true);
  });
  it("flags IPv6 literals including mapped and bracketed forms", () => {
    expect(isIpLiteralHost("::1")).toBe(true);
    expect(isIpLiteralHost("::ffff:127.0.0.1")).toBe(true);
    expect(isIpLiteralHost("[2001:db8::1]")).toBe(true);
  });
  it("does not flag a hostname", () => {
    expect(isIpLiteralHost("ink-echo.tulpa.network")).toBe(false);
  });
});

describe("isPrivateHost", () => {
  it("flags loopback and localhost", () => {
    expect(isPrivateHost("localhost")).toBe(true);
    expect(isPrivateHost("api.localhost")).toBe(true);
    expect(isPrivateHost("127.0.0.1")).toBe(true);
    expect(isPrivateHost("::1")).toBe(true);
  });
  it("flags RFC 1918 and link-local incl. cloud metadata", () => {
    expect(isPrivateHost("10.1.2.3")).toBe(true);
    expect(isPrivateHost("172.16.0.1")).toBe(true);
    expect(isPrivateHost("192.168.1.1")).toBe(true);
    expect(isPrivateHost("169.254.169.254")).toBe(true);
  });
  it("flags ULA and link-local IPv6", () => {
    expect(isPrivateHost("fd00::1")).toBe(true);
    expect(isPrivateHost("fe80::1")).toBe(true);
  });
  it("does not flag a public hostname or public IP", () => {
    expect(isPrivateHost("ink-echo.tulpa.network")).toBe(false);
    expect(isPrivateHost("8.8.8.8")).toBe(false);
  });
});
