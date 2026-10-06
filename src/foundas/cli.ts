#!/usr/bin/env -S node --experimental-strip-types --disable-warning=ExperimentalWarning
import { parseArgs, styleText } from "node:util";
import { readFile } from "node:fs/promises";
import process from "node:process";
import pkg from "../../package.json" with { type: "json" };
import {
  FoundAs,
  PageType,
  generateKeyPair,
  deriveKeyPair,
  base64UrlEncode,
  base64UrlDecode,
  type KeyPair,
  type PageState,
  type PublicBundle,
} from "./index.ts";

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
    password: {
      type: "string",
    },
    redir: {
      type: "string",
    },
    state: {
      type: "string",
    },
    bundle: {
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
      showKeyPair(generateKeyPair(), positionals[1]);
      break;
    }
    case "derive": {
      const slug = need(positionals[1], "slug");
      if (values.password === undefined) {
        process.stderr.write("derive needs --password\n");
        help(1);
      }
      showKeyPair(await deriveKeyPair(slug, values.password), slug);
      break;
    }
    case "publish": {
      const foundAs = new FoundAs({ url: values.url, keyPair: keyFromArg(positionals[1]) });
      const slug = need(positionals[2], "slug");
      const { state, bundle } = await readContent();
      await foundAs.publish(slug, state, bundle);
      process.stderr.write(`published https://found.as/${slug}\n`);
      break;
    }
    case "load": {
      const foundAs = new FoundAs({ url: values.url, keyPair: keyFromArg(positionals[1]) });
      const state = await foundAs.load(need(positionals[2], "slug"));
      if (state === null) {
        process.stderr.write("not found\n");
        process.exit(1);
      }
      process.stdout.write(`${JSON.stringify(state, null, 2)}\n`);
      break;
    }
    case "domains": {
      const foundAs = new FoundAs({ url: values.url, keyPair: keyFromArg(positionals[1]) });
      const domains = await foundAs.listDomains(need(positionals[2], "slug"));
      process.stdout.write(domains.length ? `${domains.join("\n")}\n` : "");
      break;
    }
    case "map-domain":
    case "unmap-domain":
    case "domain-status": {
      const foundAs = new FoundAs({ url: values.url, keyPair: keyFromArg(positionals[1]) });
      const slug = need(positionals[2], "slug");
      const domain = need(positionals[3], "domain");
      if (command === "map-domain") {
        await foundAs.mapDomain(slug, domain);
        process.stderr.write(`mapped ${domain}\n`);
      } else if (command === "unmap-domain") {
        await foundAs.unmapDomain(slug, domain);
        process.stderr.write(`unmapped ${domain}\n`);
      } else {
        process.stdout.write(`${JSON.stringify(await foundAs.domainStatus(slug, domain), null, 2)}\n`);
      }
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

/** Print a key pair and, when a slug is known, its editor link. */
function showKeyPair(keyPair: KeyPair, slug: string | undefined): void {
  const seed = base64UrlEncode(keyPair.secretKey.subarray(0, 32));
  process.stdout.write(`seed: ${seed}\nsecretKey: ${base64UrlEncode(keyPair.secretKey)}\n`);
  if (slug) {
    process.stdout.write(`editor: https://be.found.as/${slug}#${seed}\n`);
  }
}

/** Decode a base64url secret key (64 bytes) or seed (32 bytes). */
function keyFromArg(text: string | undefined): KeyPair {
  if (text === undefined) help(1);
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(text);
  } catch {
    process.stderr.write("secretKey must be base64url-encoded\n");
    return help(1);
  }
  if (bytes.length === 64) {
    return { publicKey: bytes.slice(32), secretKey: bytes };
  }
  if (bytes.length === 32) {
    return generateKeyPair(bytes);
  }
  process.stderr.write(`secretKey must be 64 or 32 bytes, got ${bytes.length}\n`);
  return help(1);
}

/** Build state/bundle from --redir, or read them as JSON from --state/--bundle files. */
async function readContent(): Promise<{ state: PageState; bundle: PublicBundle }> {
  if (values.redir !== undefined) {
    if (values.state !== undefined || values.bundle !== undefined) {
      process.stderr.write("--redir cannot be combined with --state/--bundle\n");
      help(1);
    }
    const redir = values.redir.replace(/\s+/g, "");
    const target = redir.includes("://") ? redir : `https://${redir}`;
    return {
      state: { type: PageType.Redirect, md: "", html: "", redir: target },
      bundle: { redir: target },
    };
  }
  if (values.state === undefined || values.bundle === undefined) {
    process.stderr.write("publish needs --redir <url> or both --state and --bundle JSON files\n");
    help(1);
  }
  const state = JSON.parse(await readFile(values.state!, "utf8")) as PageState;
  const bundle = JSON.parse(await readFile(values.bundle!, "utf8")) as PublicBundle;
  return { state, bundle };
}

function need(value: string | undefined, name: string): string {
  if (value === undefined) {
    process.stderr.write(`missing ${name}\n`);
    help(1);
  }
  return value;
}

function help(code: number): never {
  const out = code === 0 ? process.stdout : process.stderr;
  out.write(`${styleText("green", "foundas")} v${pkg.version}

  Client for the found.as editor API — contact pages and redirects, no account

  ${styleText("bold", "Usage:")}

  foundas keygen [slug]                        Generate a key pair and editor link
  foundas derive <slug> --password <pw>        Derive the key pair of a password-protected page
  foundas publish <secretKey> <slug> --redir <url>
  foundas publish <secretKey> <slug> --state <file> --bundle <file>
  foundas load <secretKey> <slug>              Print the stored editor state as JSON
  foundas domains <secretKey> <slug>           List custom domains
  foundas map-domain <secretKey> <slug> <domain>
  foundas unmap-domain <secretKey> <slug> <domain>
  foundas domain-status <secretKey> <slug> <domain>

  ${styleText("bold", "Options:")}

  --url <url>                                  API endpoint (default https://be.found.as/)
  -h, --help                                   Show this help

  Keys are base64url: secretKey 64 bytes (or a 32-byte seed), as shown by keygen/derive.
`);
  process.exit(code);
}
