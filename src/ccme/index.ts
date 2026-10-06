/**
 * Clients for cc.me — the xmit dev team's toolbox: favicons, Google Fonts,
 * a distributed semaphore ("Library"), proof of work, screenshots, and
 * burnable secrets. APIs from https://cc.me/ docs pages.
 *
 * Not covered: the encrypted HTTP inbox (/i) and email aliases (/hi),
 * which need interactive flows.
 *
 * Runs in Node.js >= 22 and in browsers (uses fetch and WebCrypto).
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { xsalsa20poly1305 } from "@noble/ciphers/salsa.js";

const DEFAULT_URL = "https://cc.me/";

/** Options shared by all cc.me clients. */
export interface CcMeOptions {
  /** Service endpoint. Defaults to https://cc.me/ */
  url?: string | URL;
  /** fetch implementation. Defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
}

abstract class Client {
  readonly url: string | URL;
  protected readonly fetch: typeof fetch;

  constructor(options: CcMeOptions = {}) {
    this.url = options.url ?? DEFAULT_URL;
    this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /** Throw with the server's JSON {error} or text body when not ok. */
  protected async checkOk(op: string, response: Response): Promise<void> {
    if (response.ok) return;
    const body = await response.text();
    let detail = body.trim();
    try {
      const parsed = JSON.parse(body) as { error?: unknown };
      if (typeof parsed.error === "string") detail = parsed.error;
    } catch {}
    throw new Error(`ccme ${op} failed: HTTP ${response.status}${detail ? ` (${detail})` : ""}`);
  }
}

// ---------------------------------------------------------------------------
// Proof of work — https://cc.me/pow
//
// A token is b64u(doc) "." b64u(suffix). Its level is the number of trailing
// zero bits in SHA-256(SHA-256(doc) ‖ suffix) read as a big-endian integer.
// ---------------------------------------------------------------------------

/** Trailing zero bits of a big-endian byte string. */
function trailingZeroBits(bytes: Uint8Array): number {
  let bits = 0;
  for (let i = bytes.length - 1; i >= 0; i--) {
    const byte = bytes[i]!;
    if (byte === 0) {
      bits += 8;
      continue;
    }
    let value = byte;
    while ((value & 1) === 0) {
      bits++;
      value >>= 1;
    }
    break;
  }
  return bits;
}

/** Parse a token into its document and suffix, checking canonical base64url. */
function parseToken(token: string): { doc: Uint8Array; suffix: Uint8Array } {
  const [docPart, suffixPart, extra] = token.split(".");
  if (docPart === undefined || suffixPart === undefined || extra !== undefined) {
    throw new Error("pow token must be two base64url segments joined by a dot");
  }
  const doc = base64UrlDecode(docPart);
  const suffix = base64UrlDecode(suffixPart);
  if (base64UrlEncode(doc) !== docPart || base64UrlEncode(suffix) !== suffixPart) {
    throw new Error("pow token segments must be canonical unpadded base64url");
  }
  if (suffix.length > 32) {
    throw new Error(`pow suffix must be at most 32 bytes, got ${suffix.length}`);
  }
  return { doc, suffix };
}

/** The exact level a token proves: trailing zero bits of its check digest. */
export function powLevel(token: string): number {
  const { doc, suffix } = parseToken(token);
  return trailingZeroBits(checkDigest(doc, suffix));
}

/** Whether a token proves at least the given level. */
export function powVerify(token: string, level: number): boolean {
  return powLevel(token) >= level;
}

function checkDigest(doc: Uint8Array, suffix: Uint8Array): Uint8Array {
  const message = new Uint8Array(32 + suffix.length);
  message.set(sha256(doc));
  message.set(suffix, 32);
  return sha256(message);
}

/**
 * Solve a proof of work over doc: search an 8-byte big-endian counter suffix
 * until the token proves level. Expected cost is 2**level double hashes —
 * instant up to ~20, seconds in the low 20s, minutes from the high 20s.
 */
export function solvePow(doc: Uint8Array | string, level: number): string {
  const docBytes = typeof doc === "string" ? new TextEncoder().encode(doc) : doc;
  if (!Number.isInteger(level) || level < 0 || level > 256) {
    throw new RangeError(`level must be an integer in 0..256, got ${level}`);
  }
  const docHash = sha256(docBytes);
  const message = new Uint8Array(40); // 32-byte doc hash + 8-byte counter
  message.set(docHash);
  const view = new DataView(message.buffer, 32, 8);
  for (let counter = 0n; ; counter++) {
    view.setBigUint64(0, counter);
    const suffix = message.subarray(32);
    if (trailingZeroBits(sha256(message)) >= level) {
      return `${base64UrlEncode(docBytes)}.${base64UrlEncode(suffix)}`;
    }
  }
}

// ---------------------------------------------------------------------------
// Favicons — GET /icon?url=
// ---------------------------------------------------------------------------

export class Favicons extends Client {
  /** The embeddable URL of a site's favicon. */
  iconUrl(target: string | URL): URL {
    const url = new URL("icon", this.url);
    url.searchParams.set("url", String(target));
    return url;
  }

  /** The favicon image, or null when the origin has none (404). */
  async get(target: string | URL): Promise<{ bytes: Uint8Array; contentType: string } | null> {
    const response = await this.fetch(this.iconUrl(target));
    if (response.status === 404) return null;
    await this.checkOk("icon", response);
    return {
      bytes: new Uint8Array(await response.arrayBuffer()),
      contentType: response.headers.get("content-type") ?? "application/octet-stream",
    };
  }
}

// ---------------------------------------------------------------------------
// Fonts — GET /fonts, /fonts/<slug>, /fonts/<slug>/<filename>
// ---------------------------------------------------------------------------

export interface FontFile {
  filename: string;
  style: string;
  weight: number;
  path: string;
}

export interface FontAxis {
  tag: string;
  min: number;
  max: number;
}

export interface FontFamily {
  slug: string;
  name: string;
  license: string;
  category: string;
  designer: string;
  subsets: string[];
  variable: boolean;
  files: FontFile[];
  axes?: FontAxis[];
}

export interface FontSearch {
  total: number;
  count: number;
  offset: number;
  limit: number;
  families: FontFamily[];
}

export interface FontSearchParams {
  q?: string;
  category?: string;
  subset?: string;
  limit?: number;
  offset?: number;
}

export class Fonts extends Client {
  /** Search the catalog; all parameters optional, an empty query lists everything. */
  async search(params: FontSearchParams = {}): Promise<FontSearch> {
    const url = new URL("fonts", this.url);
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined) url.searchParams.set(key, String(value));
    }
    const response = await this.fetch(url);
    await this.checkOk("fonts search", response);
    return (await response.json()) as FontSearch;
  }

  /** One family, including variable-font axes. Throws on unknown slug (404). */
  async family(slug: string): Promise<FontFamily> {
    const response = await this.fetch(new URL(`fonts/${encodeURIComponent(slug)}`, this.url));
    await this.checkOk("fonts family", response);
    return (await response.json()) as FontFamily;
  }

  /** The download URL of one font file from the family's files list. */
  fileUrl(slug: string, filename: string): URL {
    return new URL(`fonts/${encodeURIComponent(slug)}/${encodeURIComponent(filename)}`, this.url);
  }

  /** Download a font file (TTF bytes). Throws on unknown file (404). */
  async download(slug: string, filename: string): Promise<Uint8Array> {
    const response = await this.fetch(this.fileUrl(slug, filename));
    await this.checkOk("fonts download", response);
    return new Uint8Array(await response.arrayBuffer());
  }
}

// ---------------------------------------------------------------------------
// Library — a distributed semaphore: PUT/GET/DELETE /l/<id>, /borrow, /return
// ---------------------------------------------------------------------------

export interface PoolState {
  id: string;
  count: number;
  in_use: number;
  available: number;
}

export interface Lease {
  /** Lease UUID; hold it to return early. */
  lease: string;
  /** Slot position in 0..count-1, always the lowest free one. */
  position: number;
  expires_at_unix: number;
  expires_in: number;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class Library extends Client {
  /** The pool UUID — the only credential; keep it secret. */
  readonly id: string;

  constructor(options: CcMeOptions & { id?: string } = {}) {
    super(options);
    this.id = options.id ?? crypto.randomUUID();
    if (!UUID_PATTERN.test(this.id)) {
      throw new RangeError(`pool id must be a UUID, got ${JSON.stringify(this.id)}`);
    }
  }

  /**
   * Register the pool with count slots (0..1000). Idempotent: calling again
   * on an existing pool updates count, growing or shrinking it.
   */
  async register(count: number): Promise<PoolState> {
    const response = await this.fetch(this.#poolUrl(), {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ count }),
    });
    await this.checkOk("lib register", response);
    return (await response.json()) as PoolState;
  }

  /** Current pool state. */
  async inspect(): Promise<PoolState> {
    const response = await this.fetch(this.#poolUrl());
    await this.checkOk("lib inspect", response);
    return (await response.json()) as PoolState;
  }

  /** Delete the pool and all its leases. Idempotent. */
  async delete(): Promise<void> {
    const response = await this.fetch(this.#poolUrl(), { method: "DELETE" });
    await this.checkOk("lib delete", response);
  }

  /**
   * Borrow one permit for up to ttl seconds, waiting up to wait seconds when
   * the pool is exhausted. Returns null when no permit frees up in time (409).
   */
  async borrow(options: { ttl?: number; wait?: number } = {}): Promise<Lease | null> {
    const response = await this.fetch(`${this.#poolUrl()}/borrow`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ttl: options.ttl ?? 60, wait: options.wait ?? 0 }),
    });
    if (response.status === 409) return null;
    await this.checkOk("lib borrow", response);
    return (await response.json()) as Lease;
  }

  /**
   * Return a lease early, waking any waiting borrower. Idempotent: false when
   * the lease was already returned, expired, or unknown.
   */
  async returnLease(lease: string): Promise<boolean> {
    const response = await this.fetch(`${this.#poolUrl()}/return`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ lease }),
    });
    await this.checkOk("lib return", response);
    return ((await response.json()) as { returned: boolean }).returned;
  }

  #poolUrl(): URL {
    return new URL(`l/${this.id}`, this.url);
  }
}

// ---------------------------------------------------------------------------
// Screenshots — GET /shot?token=, gated by proof of work
// ---------------------------------------------------------------------------

export interface ShotOptions {
  /** http(s) page to render; non-public addresses are refused. */
  url: string;
  /** Viewport width in CSS pixels, 1..2048. Defaults to 800. */
  width?: number;
  /** Viewport height in CSS pixels, 1..2048. Defaults to 600. */
  height?: number;
  /** Optional downscale factor in (0, 1]. */
  scale?: number;
  /** Optional prefers-color-scheme. */
  scheme?: "light" | "dark";
}

export class Screenshots extends Client {
  /** The proof-of-work level the service currently requires. */
  async requiredLevel(): Promise<number> {
    const response = await this.fetch(new URL("shot/config", this.url));
    await this.checkOk("shot config", response);
    return ((await response.json()) as { level: number }).level;
  }

  /**
   * Render a page to PNG. Solves the required proof of work locally, which
   * takes a few seconds. Identical requests hit an hour-long cache.
   */
  async capture(options: ShotOptions): Promise<{ bytes: Uint8Array; cached: boolean }> {
    const level = await this.requiredLevel();
    const doc: Record<string, unknown> = {
      url: options.url,
      width: options.width ?? 800,
      height: options.height ?? 600,
      ts: Math.floor(Date.now() / 1000),
    };
    if (options.scale !== undefined) doc.scale = options.scale;
    if (options.scheme !== undefined) doc.scheme = options.scheme;
    const token = solvePow(JSON.stringify(doc), level);

    const url = new URL("shot", this.url);
    url.searchParams.set("token", token);
    const response = await this.fetch(url);
    await this.checkOk("shot", response);
    return {
      bytes: new Uint8Array(await response.arrayBuffer()),
      cached: response.headers.get("x-cache") === "hit",
    };
  }
}

// ---------------------------------------------------------------------------
// Secrets — POST /p, GET /p/<id>/content, DELETE /p/<id>
//
// Notes are encrypted client-side with XSalsa20-Poly1305 (nacl.secretbox);
// the key travels in the URL fragment and never reaches the server.
// ---------------------------------------------------------------------------

export interface CreatedSecret {
  id: string;
  /** Full share link, https://cc.me/p/<id>#<key>. */
  url: string;
}

export class Secrets extends Client {
  /**
   * Encrypt and store a note. expiresHours defaults to 24; autoDestroy burns
   * the note on first read. The plaintext never leaves the client.
   */
  async create(
    plaintext: string | Uint8Array,
    options: { expiresHours?: number; autoDestroy?: boolean } = {},
  ): Promise<CreatedSecret> {
    const bytes = typeof plaintext === "string" ? new TextEncoder().encode(plaintext) : plaintext;
    const key = crypto.getRandomValues(new Uint8Array(32));
    const nonce = crypto.getRandomValues(new Uint8Array(24));
    const box = xsalsa20poly1305(key, nonce).encrypt(bytes);
    const payload = new Uint8Array(nonce.length + box.length);
    payload.set(nonce);
    payload.set(box, nonce.length);

    const response = await this.fetch(new URL("p", this.url), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        ciphertext: base64UrlEncode(payload),
        expires_hours: options.expiresHours ?? 24,
        auto_destroy: options.autoDestroy ?? false,
      }),
    });
    await this.checkOk("secret create", response);
    const { id } = (await response.json()) as { id: string };
    return { id, url: `${new URL(`p/${id}`, this.url)}#${base64UrlEncode(key)}` };
  }

  /**
   * Fetch and decrypt a shared secret from its URL (id plus fragment key).
   * Throws when the secret was burned, already read, or expired (410).
   */
  async open(url: string | URL): Promise<Uint8Array> {
    const link = new URL(String(url));
    const id = link.pathname.split("/").pop() ?? "";
    const key = base64UrlDecode(link.hash.slice(1));
    if (key.length !== 32) {
      throw new Error(`secret key must be 32 bytes, got ${key.length}`);
    }
    const response = await this.fetch(new URL(`p/${encodeURIComponent(id)}/content`, this.url));
    if (response.status === 410) {
      throw new Error("ccme secret open failed: HTTP 410 (already read, burned, or expired)");
    }
    await this.checkOk("secret open", response);
    const { ciphertext } = (await response.json()) as { ciphertext: string };
    const payload = base64UrlDecode(ciphertext);
    const nonce = payload.subarray(0, 24);
    const box = payload.subarray(24);
    try {
      return xsalsa20poly1305(key, nonce).decrypt(box);
    } catch {
      throw new Error("ccme secret open failed: decryption failed — the key may be incorrect");
    }
  }

  /** Burn a secret now. Throws when already gone (410). */
  async burn(id: string): Promise<void> {
    const response = await this.fetch(new URL(`p/${encodeURIComponent(id)}`, this.url), {
      method: "DELETE",
    });
    if (response.status === 410) {
      throw new Error("ccme secret burn failed: HTTP 410 (already burned or expired)");
    }
    await this.checkOk("secret burn", response);
  }
}

// ---------------------------------------------------------------------------
// Base64url (RFC 4648 §5, unpadded)
// ---------------------------------------------------------------------------

/** Base64url-encode without padding. */
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
