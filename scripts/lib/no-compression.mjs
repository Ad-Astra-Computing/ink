// CVE-2026-111497: fetch() decodes Brotli lazily, on the first body read, and
// a compromised or malicious endpoint picks Content-Encoding on its own
// regardless of what the request asked for. Shared by every script here that
// reads a response body from a host it does not operate.

/** Fetch, then refuse the response outright if its Content-Encoding is
 * anything other than identity or absent, before any body read. Takes the
 * same arguments as fetch(). */
export async function fetchUncompressed(url, init = {}) {
  const res = await fetch(url, {
    ...init,
    headers: { ...init.headers, "accept-encoding": "identity" },
  });
  const enc = res.headers.get("content-encoding");
  if (enc !== null && enc.toLowerCase() !== "identity") {
    try {
      await res.body?.cancel();
    } catch {
      /* ignore */
    }
    throw new Error(`refusing a response compressed as '${enc}' from ${url}`);
  }
  return res;
}
