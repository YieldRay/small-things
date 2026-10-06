# libk

Client for [libk.org](https://www.libk.org/) (Let It Be Known) — a free
dynamic-DNS-style service. Claim any `*.libk.org` subdomain, protect it with a
password, and point it at one or more IP addresses (A/AAAA records).

## Usage

```ts
import { Libk } from "./libk/index.ts";

const libk = new Libk({ subdomain: "you", password: "s3cret" });
await libk.update({ ips: ["127.0.0.1", "::1"] }); // explicit IPs
await libk.update();                              // or the caller's current IP
const ips = await libk.get();                     // string[] or null when no record
await libk.update({ newPassword: "n3w" });        // rotate; the instance adopts it
await libk.delete();
```

The constructor takes `subdomain` and `password` (both required) plus `url`
(default `https://libk.org/`; use `https://6.libk.org` or `https://4.libk.org`
to force the address family of a current-IP update) and `fetch`. Exports:
`Libk` and the `LibkOptions` / `UpdateOptions` types.

## CLI

```sh
libk get <subdomain> <password>              Print the record's IPs (exit 1 when none)
libk update <subdomain> <password> [ip...]   Point at the given IPs, or the current IP
libk delete <subdomain> <password>           Delete the record
libk update ... --new-password <pw>          Rotate the password during update
libk ... --url <url>                         Service endpoint (default https://libk.org/)
```

Run directly as `./src/libk/cli.ts` or via the `libk` bin.

## Protocol

Documented on the site's home page. HTTP Basic auth (`subdomain:password`,
UTF-8 safe here) against `/`:

- `GET /` → 200 JSON `string[]` of IPs (or `null`), 401 invalid password
- `POST /` → update; optional `To: ip,ip` header (caller's IP when omitted) and
  `NewPassword: pw` header; 200 JSON `string[]`
- `DELETE /` → delete the record; 200, 401

Works in Node.js ≥ 22 and browsers.
