/**
 * Client for libk.org (Let It Be Known) — a free dynamic-DNS-style service
 * from the xmit dev team. Claim any subdomain, protect it with a password,
 * and point it at one or more IP addresses (A/AAAA records).
 *
 * Wire protocol (https://libk.org, HTTP Basic auth as `subdomain:password`):
 *   GET /     → 200 JSON string[] of IPs (or null), 401 invalid password
 *   POST /    → update; optional `To: ip,ip` header (defaults to the caller's
 *               IP; use https://6.libk.org or https://4.libk.org to force the
 *               family) and `NewPassword: pw` header; 200 JSON string[]
 *   DELETE /  → delete the record; 200, 401
 *
 * Runs in Node.js >= 22 and in browsers (uses fetch).
 *
 * @example
 * ```ts
 * import { Libk } from "./index.ts";
 *
 * const libk = new Libk({ subdomain: "you", password: "s3cret" });
 * await libk.update();                       // point at the caller's current IP
 * const ips = await libk.get();              // ["203.0.113.7"]
 * await libk.update({ newPassword: "n3w" }); // rotate the password
 * await libk.delete();
 * ```
 */

const DEFAULT_URL = "https://libk.org/";
const SUBDOMAIN_PATTERN = /^[a-z0-9-]+$/;

/** Options for the Libk client. */
export interface LibkOptions {
  /** Service endpoint. Defaults to https://libk.org/ (6.libk.org forces IPv4, 4.libk.org IPv6). */
  url?: string | URL;
  /** fetch implementation. Defaults to `globalThis.fetch`. */
  fetch?: typeof fetch;
  /** The subdomain to manage, lowercase letters/numbers/hyphens. */
  subdomain: string;
  /** Its password. */
  password: string;
}

/** Options for {@link Libk.update}. */
export interface UpdateOptions {
  /** IPs to point at. Defaults to the caller's current IP (also when empty). */
  ips?: string[];
  /** Rotate the password; the instance uses the new one from then on. */
  newPassword?: string;
}

export class Libk {
  readonly url: string | URL;
  readonly subdomain: string;
  #password: string;
  readonly #fetch: typeof fetch;

  constructor(options: LibkOptions) {
    if (!SUBDOMAIN_PATTERN.test(options.subdomain)) {
      throw new RangeError(
        `invalid subdomain ${JSON.stringify(options.subdomain)}: use lowercase letters, numbers, and hyphens only`,
      );
    }
    this.url = options.url ?? DEFAULT_URL;
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.subdomain = options.subdomain;
    this.#password = options.password;
  }

  /** The current IPs of the record, or null when the subdomain has none. */
  async get(): Promise<string[] | null> {
    const response = await this.#fetch(this.url, {
      method: "GET",
      headers: { authorization: this.#authorization() },
    });
    await this.#checkOk("get", response);
    const ips = (await response.json()) as string[] | null;
    return ips !== null && ips.length > 0 ? ips : null;
  }

  /**
   * Create or update the record. Returns the resulting IPs.
   * With no ips, points at the caller's current IP (pick the 6.libk.org or
   * 4.libk.org endpoint to force IPv4/IPv6). With newPassword, rotates the
   * password and this instance adopts it.
   */
  async update(options: UpdateOptions = {}): Promise<string[]> {
    const headers: Record<string, string> = { authorization: this.#authorization() };
    if (options.ips !== undefined && options.ips.length > 0) {
      headers.to = options.ips.join(",");
    }
    if (options.newPassword !== undefined && options.newPassword !== "") {
      headers.newpassword = options.newPassword;
    }
    const response = await this.#fetch(this.url, { method: "POST", headers });
    await this.#checkOk("update", response);
    if (headers.newpassword !== undefined) {
      this.#password = options.newPassword!;
    }
    return (await response.json()) as string[];
  }

  /** Delete the record. */
  async delete(): Promise<void> {
    const response = await this.#fetch(this.url, {
      method: "DELETE",
      headers: { authorization: this.#authorization() },
    });
    await this.#checkOk("delete", response);
  }

  /** HTTP Basic credentials for `subdomain:password`, UTF-8 safe. */
  #authorization(): string {
    const bytes = new TextEncoder().encode(`${this.subdomain}:${this.#password}`);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return `Basic ${btoa(binary)}`;
  }

  async #checkOk(op: string, response: Response): Promise<void> {
    if (!response.ok) {
      const text = (await response.text()).trim();
      throw new Error(`libk ${op} failed: HTTP ${response.status}${text ? ` (${text})` : ""}`);
    }
  }
}
