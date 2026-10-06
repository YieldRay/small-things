/**
 * Client for 0pw.me — signed, public, last-write-wins storage.
 *
 * Stores up to 64 KiB of arbitrary bytes per ed25519 (tweetnacl) key.
 * There is no versioning: last write wins, and storing `null` deletes.
 * Data is signed, not encrypted — anyone with the public key can read it.
 *
 * Wire protocol (both directions are POSTed CBOR):
 *   store:    POST / CBOR([publicKey, sign(CBOR([timestamp, message]))])
 *   retrieve: POST / CBOR([publicKey]) → sign(CBOR([timestamp, message]))
 *
 * Runs in Node.js >= 22 and in browsers (uses fetch).
 *
 * @example
 * ```ts
 * import { ZeroPw } from "./index.ts";
 *
 * const zeroPw = new ZeroPw(); // generates a key pair; keep zeroPw.keyPair.secretKey safe
 * await zeroPw.store(new TextEncoder().encode("hello"));
 * const entry = await zeroPw.retrieve();
 * ```
 */
import { keygen, sign as edSign, verify as edVerify, hashes } from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { encode, decode } from "cbor-x";

// Wire SHA-512 so the synchronous ed25519 API works (RFC 8032).
hashes.sha512 = sha512;

const DEFAULT_URL = "https://0pw.me/";
const MAX_MESSAGE_SIZE = 64 * 1024;

/** ed25519 key pair, using the tweetnacl `nacl.sign.keyPair()` layout. */
export interface KeyPair {
  /** 32-byte public key. Safe to share; identifies the stored value. */
  publicKey: Uint8Array;
  /** 64-byte secret key: 32-byte seed followed by the public key. */
  secretKey: Uint8Array;
}

/** A stored value: writer-supplied Unix timestamp (seconds) and payload. */
export interface Entry {
  timestamp: number;
  message: Uint8Array | null;
}

/** Options for the ZeroPw client. */
export interface ZeroPwOptions {
  /** Service endpoint. Defaults to https://0pw.me/ */
  url?: string | URL;
  /** fetch implementation. Defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
  /** Key pair to sign and identify stored data. Defaults to a freshly generated one. */
  keyPair?: KeyPair;
}

export class ZeroPw {
  readonly url: string | URL;
  readonly keyPair: KeyPair;
  readonly #fetch: typeof fetch;

  constructor(options: ZeroPwOptions = {}) {
    this.url = options.url ?? DEFAULT_URL;
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.keyPair = options.keyPair ?? generateKeyPair();
  }

  /**
   * Store message under this client's key, replacing any previous value.
   * Pass null to delete. Resolves on HTTP 200, throws on 4xx/5xx.
   */
  async store(message: Uint8Array | null): Promise<void> {
    if (message !== null && message.byteLength > MAX_MESSAGE_SIZE) {
      throw new RangeError(`message is ${message.byteLength} bytes, max is ${MAX_MESSAGE_SIZE}`);
    }
    const signed = sign(encode([Date.now() / 1000, message]), this.keyPair.secretKey);
    // Copy into a plain Uint8Array: cbor-x types encode() as Buffer, which the
    // DOM BodyInit type rejects, and browsers return Uint8Array anyway.
    const body = new Uint8Array(encode([this.keyPair.publicKey, signed]));
    const response = await this.#fetch(this.url, {
      method: "POST",
      headers: { "content-type": "application/cbor" },
      body,
    });
    if (!response.ok) {
      throw new Error(`0pw store failed: HTTP ${response.status}`);
    }
  }

  /**
   * Retrieve a stored value; defaults to the value under this client's key.
   * Returns null on HTTP 404. Throws on server errors or an invalid signature.
   */
  async retrieve(publicKey: Uint8Array = this.keyPair.publicKey): Promise<Entry | null> {
    const body = new Uint8Array(encode([publicKey]));
    const response = await this.#fetch(this.url, {
      method: "POST",
      headers: { "content-type": "application/cbor" },
      body,
    });
    if (response.status === 404) return null;
    if (!response.ok) {
      throw new Error(`0pw retrieve failed: HTTP ${response.status}`);
    }
    const payload = open(new Uint8Array(await response.arrayBuffer()), publicKey);
    if (payload === null) {
      throw new Error("0pw retrieve failed: response has an invalid signature");
    }
    const [timestamp, message] = decode(payload) as [number, Uint8Array | null];
    return { timestamp, message };
  }
}

/**
 * Generate a key pair, optionally from a 32-byte seed for deterministic keys.
 * Keys are interchangeable with tweetnacl's `nacl.sign.keyPair()`.
 */
export function generateKeyPair(seed?: Uint8Array): KeyPair {
  const { secretKey: seed32, publicKey } = keygen(seed);
  const secretKey = new Uint8Array(64);
  secretKey.set(seed32);
  secretKey.set(publicKey, 32);
  return { publicKey, secretKey };
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

/** tweetnacl `nacl.sign.open`: the verified message, or null on a bad signature. */
function open(signed: Uint8Array, publicKey: Uint8Array): Uint8Array | null {
  if (signed.length < 64) return null;
  const message = signed.subarray(64);
  const valid = edVerify(signed.subarray(0, 64), message, publicKey);
  return valid ? message : null;
}
