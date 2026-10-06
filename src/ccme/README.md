# ccme

Clients for [cc.me](https://cc.me/) — the xmit dev team's toolbox: favicons,
Google Fonts, a distributed semaphore ("Library"), proof of work, screenshots,
and burnable secrets. APIs from the site's docs pages.

Not covered: the encrypted HTTP inbox (`/i`) and email aliases (`/hi`), which
need interactive flows.

## Usage

```ts
import { Favicons, Fonts, Library, Screenshots, Secrets, solvePow } from "./ccme/index.ts";

// favicons — GET /icon?url=, null when the origin has none
const icon = await new Favicons().get("https://github.com"); // { bytes, contentType } | null

// fonts — search the Google Fonts catalog, download TTFs
const { families } = await new Fonts().search({ q: "roboto", limit: 2 });
const ttf = await new Fonts().download("roboto", families[0].files[0].filename);

// library — a distributed semaphore; the pool UUID is the only credential
const lib = new Library();              // fresh random pool UUID in lib.id
await lib.register(4);                  // idempotent; also grows/shrinks the pool
const lease = await lib.borrow({ ttl: 30, wait: 25 }); // null when none frees up
await lib.returnLease(lease.lease);     // or let the ttl expire

// proof of work — pure functions (https://cc.me/pow)
const token = solvePow("hello world", 20); // ~2**20 double SHA-256

// screenshots — PNG of any public page, gated by proof of work
const shot = await new Screenshots().capture({ url: "https://example.com" });

// secrets — encrypted client-side (XSalsa20-Poly1305), key in the URL fragment
const secrets = new Secrets();
const created = await secrets.create("burn after reading", { autoDestroy: true });
const plaintext = await secrets.open(created.url);
await secrets.burn(created.id);
```

Every class constructor accepts `url` (default `https://cc.me/`) and `fetch`.
Exports: the five classes above, `solvePow` / `powLevel` / `powVerify`,
`base64UrlEncode` / `base64UrlDecode`, and the options/result types.

## CLI

```sh
ccme icon <url> [-o file]                    Fetch a site's favicon
ccme fonts [query] [--category C] [--limit N]  Search the font catalog
ccme font <slug> [filename] [-o file]        Family details, or download a font
ccme pow solve <level> [doc]                 Solve a proof of work (doc or stdin)
ccme pow level <token>                       Print the level a token proves
ccme shot <url> [-o file] [--width --height --scale --scheme]
ccme lib register <count> [--id uuid]        Register a semaphore pool
ccme lib inspect|borrow|return|delete ...
ccme secret create [text] [--hours N] [--burn]
ccme secret open <url>
ccme secret burn <id>
ccme ... --url <url>                         Service endpoint (default https://cc.me/)
```

Run directly as `./src/ccme/cli.ts` or via the `ccme` bin.

## Notes

- Proof of work: a token is `b64u(doc) "." b64u(suffix)`; its level is the
  number of trailing zero bits in `SHA-256(SHA-256(doc) ‖ suffix)`. Solving
  costs ~2^level hashes (instant to ~20, seconds in the low 20s).
- Secrets are encrypted before upload with XSalsa20-Poly1305
  ([@noble/ciphers](https://www.npmjs.com/package/@noble/ciphers),
  wire-compatible with the site's `nacl.secretbox`): nonce (24 B) ‖ box,
  base64url. The server never sees plaintext; 410 means read, burned, or expired.
- Library slots are dense and stable: borrow hands out the lowest free position
  in `0..count-1`; leases expire on their ttl or return early.

Works in Node.js ≥ 22 and browsers.
