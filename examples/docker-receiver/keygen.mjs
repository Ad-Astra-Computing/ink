/**
 * Mint a receiver identity and print the three environment variables the
 * server needs. The seed is the secret half; the multibase is published in
 * the agent card. Pipe into an env file or paste into compose/`docker run -e`.
 *
 *   node keygen.mjs
 *   INK_RECEIVER_SIGNING_SEED=...
 *   INK_RECEIVER_PUBLIC_KEY_MULTIBASE=z6Mk...
 *   INK_RECEIVER_HOST=ink-receiver.example
 */

import { generateKeypair, encodePublicKeyMultibase, base64urlEncode } from "@adastracomputing/ink";

const host = process.argv[2] ?? "ink-receiver.example";
const kp = await generateKeypair();
console.log(`INK_RECEIVER_SIGNING_SEED=${base64urlEncode(kp.privateKey)}`);
console.log(`INK_RECEIVER_PUBLIC_KEY_MULTIBASE=${encodePublicKeyMultibase(kp.publicKey)}`);
console.log(`INK_RECEIVER_HOST=${host}`);
