/**
 * Mint the receiver identity for one container run and print it as shell
 * assignments. The entrypoint sources the output, so the seed lives only in the
 * container's process environment: the lab commits no key material and never
 * writes any to an image layer.
 */

import { generateKeypair, encodePublicKeyMultibase, base64urlEncode } from "@adastracomputing/ink";

const host = process.env.INK_RECEIVER_HOST ?? "ts-receiver.example";
const kp = await generateKeypair();

process.stdout.write(
  [
    `INK_RECEIVER_SIGNING_SEED=${base64urlEncode(kp.privateKey)}`,
    `INK_RECEIVER_PUBLIC_KEY_MULTIBASE=${encodePublicKeyMultibase(kp.publicKey)}`,
    `INK_RECEIVER_HOST=${host}`,
    "",
  ].join("\n"),
);
