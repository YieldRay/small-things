# 0pw

Client for [0pw.me](https://0pw.me/) — signed, public, last-write-wins storage.

Stores up to 64 KiB of arbitrary bytes per ed25519 (tweetnacl) key. There is no
versioning: last write wins, and storing `null` deletes. Data is signed, not
encrypted — anyone with the public key can read it; encrypt end-to-end if you
need secrecy.

## Usage

```ts
import { ZeroPw } from "./0pw/index.ts";

const zeroPw = new ZeroPw(); // fresh key pair in zeroPw.keyPair; keep secretKey safe
await zeroPw.store(new TextEncoder().encode("hello"));
const entry = await zeroPw.retrieve();                    // { timestamp, message }
const other = await zeroPw.retrieve(somePublicKey);       // read anyone's data
await zeroPw.store(null);                                 // delete
```

The constructor accepts `url` (default `https://0pw.me/`), `fetch` (default
`globalThis.fetch`), and `keyPair` (generated when omitted). Exports: `ZeroPw`,
`generateKeyPair(seed?)`, and the `KeyPair` / `Entry` / `ZeroPwOptions` types.
Key pairs use the tweetnacl `nacl.sign.keyPair()` layout (64-byte secretKey =
32-byte seed ‖ public key), so keys interchange with tweetnacl tooling.

## CLI

```sh
0pw keygen [--seed <hex>]           Generate a key pair, optionally from a 32-byte seed
0pw set <secretKey> [message]       Store the message, or raw stdin bytes when omitted
0pw get <publicKey>                 Write the stored message to stdout (exit 1 when absent)
0pw del <secretKey>                 Delete the stored value
0pw ... --url <url>                 Service endpoint (default https://0pw.me/)
```

Keys are hex-encoded; `set`/`del` accept the full 64-byte secret key or a
32-byte seed. Run directly as `./src/0pw/cli.ts` or via the `0pw` bin.

## Protocol

Both directions POST CBOR to `/`:

- store: `CBOR([publicKey, sign(CBOR([Date.now()/1000, message]))])` → 200 / 4xx / 5xx
- retrieve: `CBOR([publicKey])` → signed bytes to open with the public key, or 404

Signatures are tweetnacl-style (64-byte signature followed by the message),
implemented with [@noble/ed25519](https://www.npmjs.com/package/@noble/ed25519);
CBOR with [cbor-x](https://www.npmjs.com/package/cbor-x). Works in Node.js ≥ 22
and browsers.
