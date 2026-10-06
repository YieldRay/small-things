#!/usr/bin/env -S node --experimental-strip-types --disable-warning=ExperimentalWarning
import { parseArgs, styleText } from "node:util";
import process from "node:process";
import pkg from "../../package.json" with { type: "json" };
import { ZeroPw, generateKeyPair, type KeyPair } from "./index.ts";

// https://nodejs.org/api/util.html#utilparseargsconfig
const { values, positionals } = parseArgs({
  options: {
    help: {
      type: "boolean",
      multiple: false,
      short: "h",
      default: false,
    },
    url: {
      type: "string",
    },
    seed: {
      type: "string",
    },
  },
  strict: true,
  allowPositionals: true,
});

const command = positionals[0];

if (values.help || command === "help") help(0);
if (command === undefined) help(1);

try {
  switch (command) {
    case "keygen": {
      const seed = values.seed !== undefined ? fromHex(values.seed, 32, "seed") : undefined;
      const keyPair = generateKeyPair(seed);
      process.stdout.write(`publicKey: ${toHex(keyPair.publicKey)}\nsecretKey: ${toHex(keyPair.secretKey)}\n`);
      break;
    }
    case "set": {
      const zeroPw = new ZeroPw({ url: values.url, keyPair: keyPairFromHex(positionals[1]) });
      const message =
        positionals[2] !== undefined ? new TextEncoder().encode(positionals[2]) : await readStdin();
      await zeroPw.store(message);
      process.stderr.write(`stored ${message.byteLength} bytes for ${toHex(zeroPw.keyPair.publicKey)}\n`);
      break;
    }
    case "get": {
      if (positionals[1] === undefined) help(1);
      const publicKey = fromHex(positionals[1], 32, "publicKey");
      const entry = await new ZeroPw({ url: values.url }).retrieve(publicKey);
      if (entry === null) {
        process.stderr.write("not found\n");
        process.exit(1);
      }
      process.stderr.write(`timestamp: ${new Date(entry.timestamp * 1000).toISOString()}\n`);
      if (entry.message !== null) {
        process.stdout.write(entry.message);
      }
      break;
    }
    case "del": {
      const zeroPw = new ZeroPw({ url: values.url, keyPair: keyPairFromHex(positionals[1]) });
      await zeroPw.store(null);
      process.stderr.write(`deleted ${toHex(zeroPw.keyPair.publicKey)}\n`);
      break;
    }
    default:
      process.stderr.write(`Unknown command ${command}\n`);
      help(1);
  }
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
}

/** Build a KeyPair from a 64-byte secret key or a 32-byte seed, hex-encoded. */
function keyPairFromHex(hex: string | undefined): KeyPair {
  if (hex === undefined) help(1);
  const bytes = fromHex(hex, undefined, "secretKey");
  if (bytes.length === 64) {
    return { publicKey: bytes.slice(32), secretKey: bytes };
  }
  if (bytes.length === 32) {
    return generateKeyPair(bytes);
  }
  process.stderr.write(`secretKey must be 64 or 32 bytes, got ${bytes.length}\n`);
  return help(1);
}

/** Read all of stdin; refuses to block on a terminal. */
async function readStdin(): Promise<Uint8Array> {
  if (process.stdin.isTTY) {
    process.stderr.write("pass the message as an argument or pipe it on stdin\n");
    help(1);
  }
  const chunks: Uint8Array[] = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  const bytes = new Uint8Array(chunks.reduce((n, c) => n + c.byteLength, 0));
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex: string, length: number | undefined, name: string): Uint8Array {
  if (!/^(?:[0-9a-fA-F]{2})+$/.test(hex)) {
    process.stderr.write(`${name} must be hex-encoded\n`);
    help(1);
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  if (length !== undefined && bytes.length !== length) {
    process.stderr.write(`${name} must be ${length} bytes, got ${bytes.length}\n`);
    help(1);
  }
  return bytes;
}

function help(code: number): never {
  const out = code === 0 ? process.stdout : process.stderr;
  out.write(`${styleText("green", "0pw")} v${pkg.version}

  Client for 0pw.me — signed, public, last-write-wins storage (64 KiB max per key)

  ${styleText("bold", "Usage:")}

  0pw keygen [--seed <hex>]           Generate a key pair, optionally from a 32-byte seed
  0pw set <secretKey> [message]       Store the message, or stdin when omitted
  0pw get <publicKey>                 Write the stored message to stdout
  0pw del <secretKey>                 Delete the stored value

  ${styleText("bold", "Options:")}

  --url <url>                         Service endpoint (default https://0pw.me/)
  -h, --help                          Show this help

  Keys are hex-encoded: secretKey 64 bytes (or a 32-byte seed), publicKey 32 bytes.
`);
  process.exit(code);
}
