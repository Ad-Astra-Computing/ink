/**
 * Command-line entry point.
 *
 * Parses a small set of flags, mints or loads a sender identity, builds
 * the chosen intent payload, then runs the full send flow. The argument
 * parsing and orchestration are kept in an exported `runCli` so they can
 * be unit-tested without spawning a process.
 *
 * Usage:
 *   node bin/ink-send.mjs --to <did> [--intent ping|connection_request]
 *                         [--endpoint https://host/ink/v1/inbound]
 *                         [--note "..."] [--context "..."] [--headline "..."]
 *                         [--allow-private]
 *   node bin/ink-send.mjs --keygen
 *
 * Identity:
 *   With no identity env set, a fresh ephemeral did:key is minted and its
 *   DID is printed. Set INK_SENDER_SIGNING_SEED + INK_SENDER_PUBLIC_KEY_MULTIBASE
 *   (see --keygen) to send from a stable DID a receiver can allow-list.
 */

import {
  generateSenderIdentity,
  loadSenderIdentity,
  describeIdentitySeed,
  selfCheckIdentity,
  type SenderIdentity,
} from "./identity.ts";
import { connectionRequestPayload, pingPayload } from "./envelope.ts";
import { sendIntent } from "./index.ts";

export interface CliEnv {
  INK_SENDER_SIGNING_SEED?: string;
  INK_SENDER_PUBLIC_KEY_MULTIBASE?: string;
}

export interface ParsedArgs {
  to?: string;
  intent: string;
  endpoint?: string;
  note?: string;
  context?: string;
  headline?: string;
  allowPrivate: boolean;
  keygen: boolean;
  help: boolean;
}

const FLAGS_WITH_VALUE = new Set(["--to", "--intent", "--endpoint", "--note", "--context", "--headline"]);

export function parseArgs(argv: string[]): ParsedArgs {
  const out: ParsedArgs = { intent: "ping", allowPrivate: false, keygen: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--help" || arg === "-h") {
      out.help = true;
      continue;
    }
    if (arg === "--keygen") {
      out.keygen = true;
      continue;
    }
    if (arg === "--allow-private") {
      out.allowPrivate = true;
      continue;
    }
    if (FLAGS_WITH_VALUE.has(arg)) {
      const value = argv[i + 1];
      if (value === undefined) throw new Error(`missing value for ${arg}`);
      i++;
      switch (arg) {
        case "--to":
          out.to = value;
          break;
        case "--intent":
          out.intent = value;
          break;
        case "--endpoint":
          out.endpoint = value;
          break;
        case "--note":
          out.note = value;
          break;
        case "--context":
          out.context = value;
          break;
        case "--headline":
          out.headline = value;
          break;
      }
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }
  return out;
}

const HELP = `ink-send: minimal INK sender built on @adastracomputing/ink.

Usage:
  node bin/ink-send.mjs --to <did> [options]
  node bin/ink-send.mjs --keygen

Options:
  --to <did>            Recipient DID (did:key:... or did:web:...). Required to send.
  --intent <name>       ping (default) or connection_request.
  --endpoint <url>      Inbox URL. Required for did:key recipients; for did:web
                        it overrides Agent Card discovery.
  --note <text>         Note for a ping payload.
  --context <text>      Context line for a connection_request.
  --headline <text>     Profile headline for a connection_request.
  --allow-private       Permit private/loopback hosts (local dev only).
  --keygen              Mint a stable identity and print its seed + public key.
  -h, --help            Show this help.

Identity:
  Without INK_SENDER_SIGNING_SEED set, a fresh ephemeral did:key is minted.
`;

function buildPayload(args: ParsedArgs): { intent: string; payload: Record<string, unknown> } {
  if (args.intent === "ping") {
    return { intent: "ping", payload: pingPayload(args.note) };
  }
  if (args.intent === "connection_request") {
    return {
      intent: "connection_request",
      payload: connectionRequestPayload({
        context: args.context ?? "Hello from the INK reference sender.",
        headline: args.headline ?? "INK reference sender",
      }),
    };
  }
  throw new Error(`unsupported --intent ${args.intent}; use ping or connection_request`);
}

export interface CliDeps {
  env?: CliEnv;
  fetchImpl?: typeof fetch;
  log?: (line: string) => void;
}

/**
 * Run the CLI. Returns a process exit code. Pure with respect to its
 * injected deps (env, fetch, logger) so a test can drive it end-to-end.
 */
export async function runCli(argv: string[], deps: CliDeps = {}): Promise<number> {
  const log = deps.log ?? ((line: string) => console.log(line));
  let args: ParsedArgs;
  try {
    args = parseArgs(argv);
  } catch (err) {
    log(`error: ${(err as Error).message}`);
    log(HELP);
    return 2;
  }

  if (args.help) {
    log(HELP);
    return 0;
  }

  const env = deps.env ?? (process.env as CliEnv);

  if (args.keygen) {
    const id = await generateSenderIdentity();
    const seed = describeIdentitySeed(id);
    log(`did: ${id.did}`);
    log(`INK_SENDER_SIGNING_SEED=${seed.INK_SENDER_SIGNING_SEED}`);
    log(`INK_SENDER_PUBLIC_KEY_MULTIBASE=${seed.INK_SENDER_PUBLIC_KEY_MULTIBASE}`);
    return 0;
  }

  let identity: SenderIdentity;
  if (env.INK_SENDER_SIGNING_SEED) {
    identity = loadSenderIdentity(env);
    await selfCheckIdentity(identity);
  } else {
    identity = await generateSenderIdentity();
    log(`minted ephemeral sender did: ${identity.did}`);
  }

  if (!args.to) {
    log("error: --to <did> is required (or use --keygen)");
    log(HELP);
    return 2;
  }

  const { intent, payload } = buildPayload(args);

  const result = await sendIntent({
    identity,
    recipientDid: args.to,
    intent,
    payload,
    endpoint: args.endpoint,
    fetchImpl: deps.fetchImpl,
    allowPrivateHosts: args.allowPrivate,
  });

  if (result.stage === "discovery") {
    log(`discovery failed: ${result.reason}`);
    return 1;
  }
  if (!result.ok) {
    log(`delivery failed: ${result.reason}${result.status ? ` (status ${result.status})` : ""}`);
    return 1;
  }
  log(`delivered: status ${result.status}`);
  log(result.bodyPreview);
  return 0;
}
