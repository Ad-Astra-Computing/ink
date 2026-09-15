/**
 * What this deployment is running.
 *
 * The receiver is built only on the published `@adastracomputing/ink` package
 * and deployed by hand, so a deployment can sit a release behind the library
 * without anything observable saying so. An interop check against a stale
 * receiver reports a pass for a build that was never the one under test. This
 * module is the fact that makes that visible.
 *
 * Deliberately NOT on the agent card. The card is a signed protocol document
 * and a pure function of configuration and key material; which library build
 * serves it is an operational fact about one deployment, not something a peer
 * must know to talk to it. It rides a response header instead, so it is
 * attached to the exact response that judged an envelope rather than to a
 * separate request that a gradual rollout could route to a different build.
 */
import inkPkg from "@adastracomputing/ink/package.json" with { type: "json" };

/** Custom, because Cloudflare overwrites the standard `Server` header. */
export const BUILD_INFO_HEADER = "Ink-Receiver-Build";

/** Cloudflare's version metadata binding, when one is configured. */
export interface VersionMetadata {
  id: string;
  tag: string;
}

export interface BuildInfoEnv {
  CF_VERSION_METADATA?: VersionMetadata;
}

export interface BuildInfo {
  /** The `@adastracomputing/ink` version in this bundle. */
  ink: string;
  /** Cloudflare's id for the deployed worker version, or `unknown`. */
  deployment: string;
}

/** Anything that cannot appear in a header value, plus the separators this
 *  format uses. Replaced rather than dropped so a mangled value is obvious
 *  instead of quietly reading as a different one. */
function headerSafe(value: string): string {
  return value.replace(/[^\x20-\x7e]|[;=]/g, "_");
}

export function buildInfo(env: BuildInfoEnv): BuildInfo {
  // `unknown` rather than an empty string: a freshness check comparing an
  // empty string against a real id would read the blank as an answer.
  const id = env.CF_VERSION_METADATA?.id;
  return { ink: inkPkg.version, deployment: id ? headerSafe(id) : "unknown" };
}

export function buildInfoHeader(env: BuildInfoEnv): string {
  const info = buildInfo(env);
  return `ink=${headerSafe(info.ink)}; deployment=${info.deployment}`;
}
