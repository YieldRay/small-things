# foundas

Client for the [found.as](https://found.as/) editor API (`be.found.as`) — free
contact pages and redirects, no account. A page is controlled by whoever holds
its ed25519 key: a random seed carried base64url in the editor link's URL hash
(`be.found.as/{slug}#{seed}`), or a key derived from slug + password via
PBKDF2-SHA256.

## Usage

```ts
import { FoundAs, PageType } from "./foundas/index.ts";

const foundAs = new FoundAs(); // fresh key pair; the editor link seed is
                               // base64UrlEncode(keyPair.secretKey.subarray(0, 32))
await foundAs.publish(
  "you",
  { type: PageType.Redirect, md: "", html: "", redir: "https://example.com" },
  { redir: "https://example.com" },
);
const state = await foundAs.load("you");        // null when the page doesn't exist
await foundAs.mapDomain("you", "www.example.com");
const status = await foundAs.domainStatus("you", "www.example.com");
const domains = await foundAs.listDomains("you");
```

The constructor accepts `url` (default `https://be.found.as/`), `fetch`, and
`keyPair` (generated when omitted). Exports: `FoundAs`, `generateKeyPair(seed?)`,
`deriveKeyPair(slug, password)`, `base64UrlEncode` / `base64UrlDecode`,
`PageType`, and the `KeyPair` / `PageState` / `PublicBundle` / `DomainStatus` /
`IndieAuthParams` / `FoundAsOptions` types. Ops 3/8/9 exist in the frontend
bundle as dead code and are not implemented.

## CLI

```sh
foundas keygen [slug]                        Generate a key pair and editor link
foundas derive <slug> --password <pw>        Derive the key pair of a password-protected page
foundas publish <secretKey> <slug> --redir <url>
foundas publish <secretKey> <slug> --state <file> --bundle <file>
foundas load <secretKey> <slug>              Print the stored editor state as JSON
foundas domains <secretKey> <slug>           List custom domains
foundas map-domain <secretKey> <slug> <domain>
foundas unmap-domain <secretKey> <slug> <domain>
foundas domain-status <secretKey> <slug> <domain>
foundas ... --url <url>                      API endpoint (default https://be.found.as/)
```

Keys are base64url: the 64-byte secret key, or a 32-byte seed as found in
editor links. Run directly as `./src/foundas/cli.ts` or via the `foundas` bin.

## Protocol

Single endpoint `POST {url}/api` with CBOR arrays
`[op, publicKey, sign(CBOR([timestamp, ...payload]))]`, extracted from the
be.found.as frontend source:

| op | method | payload |
|----|--------|---------|
| 1  | `publish` | `slug, CBOR(state), CBOR(bundle)` |
| 2  | `load` | `slug` → CBOR state, 404 when absent |
| 4 / 5 | `mapDomain` / `unmapDomain` | `slug, domain` |
| 6 / 7 | `domainStatus` / `listDomains` | `slug, domain` / `slug, ""` |
| 10 | `indieAuth` | `me, clientId, redirectUri, codeChallenge, codeChallengeMethod, scope` → `{code}` |

Works in Node.js ≥ 22 and browsers.
