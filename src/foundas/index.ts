/**
 * Client for the found.as editor API (be.found.as) — signed, server-stored
 * contact pages, redirects, and small files. No account: a page is controlled
 * by whoever holds its ed25519 (tweetnacl) key, carried as a base64url seed in
 * the editor link's URL hash or derived from slug + password via PBKDF2.
 *
 * Wire protocol (single endpoint, POST {url}/api, CBOR arrays):
 *   [op, publicKey, sign(CBOR([timestamp, ...payload]))]
 * with ops 1 publish, 2 load, 4 map domain, 5 unmap domain, 6 domain status,
 * 7 list domains, 10 indieauth authorization. Extracted from the be.found.as
 * frontend source.
 *
 * Runs in Node.js >= 22 and in browsers (uses fetch and WebCrypto).
 *
 * @example
 * ```ts
 * import { FoundAs } from "./index.ts";
 *
 * const foundAs = new FoundAs(); // fresh key pair in foundAs.keyPair; keep the seed safe
 * await foundAs.publish("you", { type: PageType.Redirect, redir: "https://example.com" },
 *   { redir: "https://example.com" });
 * const state = await foundAs.load("you");
 * ```
 */
import { keygen, sign as edSign, hashes } from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { encode, decode } from "cbor-x";

// Wire SHA-512 so the synchronous ed25519 API works (RFC 8032).
hashes.sha512 = sha512;

const DEFAULT_URL = "https://be.found.as/";
const PBKDF2_ITERATIONS = 100_000;

/** Page types understood by the editor, as stored in {@link PageState}. */
export const PageType = {
  HtmlPage: 0,
  MarkdownPage: 1,
  Redirect: 2,
  Bytes: 3,
  LinkTree: 4,
} as const;
export type PageType = (typeof PageType)[keyof typeof PageType];

/** ed25519 key pair, using the tweetnacl `nacl.sign.keyPair()` layout. */
export interface KeyPair {
  /** 32-byte public key. Identifies the page to the API. */
  publicKey: Uint8Array;
  /** 64-byte secret key: 32-byte seed followed by the public key. */
  secretKey: Uint8Array;
}

/**
 * Private editor state of a page. `linkTree` and friends are only loosely
 * typed: the editor owns their shape, and unknown fields round-trip as-is.
 */
export interface PageState {
  type: PageType;
  md?: string;
  html?: string;
  redir?: string;
  linkTree?: Record<string, unknown>;
  [field: string]: unknown;
}

/** Public content published for a page; the server renders or serves it. */
export interface PublicBundle {
  html?: string;
  redir?: string;
  bytes?: Uint8Array;
  mime?: string;
  [field: string]: unknown;
}

/** Result of a domain status query (op 6). */
export interface DomainStatus {
  conflict?: boolean;
  certPaused?: boolean;
  mapped?: boolean;
  cert?: boolean;
  bound?: boolean;
  reachable?: boolean;
  target?: string;
  label?: string;
  apex?: boolean;
  [field: string]: unknown;
}

/** Parameters of an indieauth authorization request (op 10). */
export interface IndieAuthParams {
  me: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  scope?: string;
}

/** Options for the FoundAs client. */
export interface FoundAsOptions {
  /** API endpoint. Defaults to https://be.found.as/ */
  url?: string | URL;
  /** fetch implementation. Defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
  /** Key pair signing requests. Defaults to a freshly generated one. */
  keyPair?: KeyPair;
}

export class FoundAs {
  readonly url: string | URL;
  readonly keyPair: KeyPair;
  readonly #fetch: typeof fetch;

  constructor(options: FoundAsOptions = {}) {
    this.url = options.url ?? DEFAULT_URL;
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.keyPair = options.keyPair ?? generateKeyPair();
  }

  /**
   * Publish a page: store the private editor state alongside the public
   * bundle. Last write wins.
   */
  async publish(slug: string, state: PageState, bundle: PublicBundle): Promise<void> {
    await this.#send("publish", [1, [Date.now() / 1000, slug, encode(state), encode(bundle)]]);
  }

  /**
   * Load the private editor state of a page.
   * Returns null when the page does not exist (HTTP 404).
   */
  async load(slug: string): Promise<PageState | null> {
    const response = await this.#request([2, [Date.now() / 1000, slug]]);
    if (response.status === 404) return null;
    await this.#checkOk("load", response);
    return decode(new Uint8Array(await response.arrayBuffer())) as PageState;
  }

  /** Connect a custom domain to a page (op 4). */
  async mapDomain(slug: string, domain: string): Promise<void> {
    await this.#send("mapDomain", [4, [Date.now() / 1000, slug, domain]]);
  }

  /** Disconnect a custom domain from a page (op 5). */
  async unmapDomain(slug: string, domain: string): Promise<void> {
    await this.#send("unmapDomain", [5, [Date.now() / 1000, slug, domain]]);
  }

  /** Query DNS/certificate status for a custom domain (op 6). */
  async domainStatus(slug: string, domain: string): Promise<DomainStatus> {
    const response = await this.#request([6, [Date.now() / 1000, slug, domain]]);
    await this.#checkOk("domainStatus", response);
    return decode(new Uint8Array(await response.arrayBuffer())) as DomainStatus;
  }

  /** List the custom domains connected to a page (op 7). */
  async listDomains(slug: string): Promise<string[]> {
    const response = await this.#request([7, [Date.now() / 1000, slug, ""]]);
    await this.#checkOk("listDomains", response);
    return (decode(new Uint8Array(await response.arrayBuffer())) as string[] | null) ?? [];
  }

  /**
   * Authorize an indieauth request as this page's identity (op 10).
   * Returns the authorization code to hand back to the client.
   */
  async indieAuth(params: IndieAuthParams): Promise<{ code: string }> {
    const { me, clientId, redirectUri, codeChallenge, codeChallengeMethod, scope } = params;
    const response = await this.#request([
      10,
      [Date.now() / 1000, me, clientId, redirectUri, codeChallenge, codeChallengeMethod, scope ?? null],
    ]);
    await this.#checkOk("indieAuth", response);
    return decode(new Uint8Array(await response.arrayBuffer())) as { code: string };
  }

  /** POST [op, publicKey, sign(CBOR(payload))] and return the raw response. */
  #request(message: [number, unknown[]]): Promise<Response> {
    const [op, payload] = message;
    const signed = sign(encode(payload), this.keyPair.secretKey);
    // Copy into a plain Uint8Array: cbor-x types encode() as Buffer, which the
    // DOM BodyInit type rejects, and browsers return Uint8Array anyway.
    const body = new Uint8Array(encode([op, this.keyPair.publicKey, signed]));
    return this.#fetch(new URL("api", this.url), {
      method: "POST",
      headers: { "content-type": "application/cbor" },
      body,
    });
  }

  /** POST and throw unless the status is 2xx. */
  async #send(op: string, message: [number, unknown[]]): Promise<void> {
    await this.#checkOk(op, await this.#request(message));
  }

  async #checkOk(op: string, response: Response): Promise<void> {
    if (!response.ok) {
      const text = (await response.text()).trim();
      throw new Error(`foundas ${op} failed: HTTP ${response.status}${text ? ` (${text})` : ""}`);
    }
  }
}

/**
 * Generate a key pair, optionally from a 32-byte seed for deterministic keys.
 * Keys are interchangeable with tweetnacl's `nacl.sign.keyPair()`; the editor
 * link carries the seed, base64url-encoded, in its URL hash.
 */
export function generateKeyPair(seed?: Uint8Array): KeyPair {
  const { secretKey: seed32, publicKey } = keygen(seed);
  const secretKey = new Uint8Array(64);
  secretKey.set(seed32);
  secretKey.set(publicKey, 32);
  return { publicKey, secretKey };
}

/**
 * Derive the key pair of a password-protected page: PBKDF2-SHA256 over the
 * password with salt `found.as/{slug}`, 100 000 iterations, 256-bit seed.
 */
export async function deriveKeyPair(slug: string, password: string): Promise<KeyPair> {
  const subtle = globalThis.crypto.subtle;
  const encoder = new TextEncoder();
  const baseKey = await subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, [
    "deriveBits",
  ]);
  const seed = await subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: encoder.encode(`found.as/${slug}`), iterations: PBKDF2_ITERATIONS },
    baseKey,
    256,
  );
  return generateKeyPair(new Uint8Array(seed));
}

/** Base64url-encode (no padding), the format used by editor links. */
export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode base64url, tolerating missing padding. */
export function base64UrlDecode(text: string): Uint8Array {
  const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** tweetnacl `nacl.sign`: the 64-byte signature followed by the message. */
function sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array {
  if (secretKey.length !== 64 && secretKey.length !== 32) {
    throw new RangeError(`secretKey must be 64 or 32 bytes, got ${secretKey.length}`);
  }
  const signature = edSign(message, secretKey.subarray(0, 32));
  const signed = new Uint8Array(64 + message.length);
  signed.set(signature);
  signed.set(message, 64);
  return signed;
}
