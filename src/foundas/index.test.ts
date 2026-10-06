import { test } from "node:test";
import * as assert from "node:assert";
import { pbkdf2Sync } from "node:crypto";
import { verify, hashes } from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { encode, decode } from "cbor-x";
import {
  FoundAs,
  PageType,
  generateKeyPair,
  deriveKeyPair,
  base64UrlEncode,
  base64UrlDecode,
  type KeyPair,
} from "./index.ts";

hashes.sha512 = sha512;

type FetchHandler = (url: unknown, init: RequestInit) => Promise<Response>;

function client(handler: FetchHandler, keyPair?: KeyPair): FoundAs {
  return new FoundAs({ fetch: handler as typeof fetch, keyPair });
}

/** CBOR-encode a response body as a plain Uint8Array (cbor-x types encode() as Buffer). */
function cbor(value: unknown) {
  return new Uint8Array(encode(value));
}

/** Decode a request body into [op, publicKey, payload] with a verified signature. */
function decodeRequest(body: Uint8Array, keyPair: KeyPair): [number, Uint8Array, unknown[]] {
  const [op, publicKey, signed] = decode(body) as [number, Uint8Array, Uint8Array];
  assert.deepEqual(publicKey, keyPair.publicKey);
  const payload = signed.subarray(64);
  assert.ok(verify(signed.subarray(0, 64), payload, publicKey), "signature must verify");
  return [op, publicKey, decode(payload) as unknown[]];
}

test("constructor generates a key pair, or keeps a provided one", () => {
  const generated = new FoundAs();
  assert.equal(generated.keyPair.publicKey.length, 32);
  assert.equal(generated.keyPair.secretKey.length, 64);

  const keyPair = generateKeyPair();
  assert.equal(new FoundAs({ keyPair }).keyPair, keyPair);
});

test("generateKeyPair is deterministic from a seed", () => {
  const seed = new Uint8Array(32).fill(7);
  assert.deepEqual(generateKeyPair(seed), generateKeyPair(seed));
});

test("base64url roundtrips and matches the editor-link format", () => {
  const seed = new Uint8Array(32).fill(42);
  const encoded = base64UrlEncode(seed);
  assert.equal(encoded.length, 43); // 32 bytes, no padding
  assert.doesNotMatch(encoded, /[+/=]/);
  assert.deepEqual(base64UrlDecode(encoded), seed);
  assert.deepEqual(base64UrlDecode(`${encoded}=`), seed, "tolerates padding");

  const bytes = crypto.getRandomValues(new Uint8Array(64));
  const expected = Buffer.from(bytes).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  assert.equal(base64UrlEncode(bytes), expected);
});

test("deriveKeyPair matches PBKDF2-SHA256(found.as/{slug}, 100k, 256 bits)", async () => {
  const expectedSeed = new Uint8Array(pbkdf2Sync("s3cret", "found.as/you", 100_000, 32, "sha256"));
  const keyPair = await deriveKeyPair("you", "s3cret");
  assert.deepEqual(keyPair.secretKey.subarray(0, 32), expectedSeed);

  assert.notDeepEqual(
    (await deriveKeyPair("you", "other")).publicKey,
    keyPair.publicKey,
    "different password, different key",
  );
  assert.notDeepEqual(
    (await deriveKeyPair("me", "s3cret")).publicKey,
    keyPair.publicKey,
    "different slug, different key",
  );
});

test("publish posts [1, publicKey, sign([ts, slug, CBOR(state), CBOR(bundle)])] to {url}api", async () => {
  const keyPair = generateKeyPair();
  const state = { type: PageType.Redirect, redir: "https://example.com" };
  const bundle = { redir: "https://example.com" };
  const before = Date.now() / 1000;

  const foundAs = client(async (url, init) => {
    assert.equal(String(url), "https://be.found.as/api");
    assert.equal(init.method, "POST");
    const [op, , payload] = decodeRequest(init.body as Uint8Array, keyPair);
    assert.equal(op, 1);

    const [timestamp, slug, stateBytes, bundleBytes] = payload as [number, string, Uint8Array, Uint8Array];
    assert.ok(timestamp >= before && timestamp <= Date.now() / 1000);
    assert.equal(slug, "you");
    assert.deepEqual(decode(stateBytes), state);
    assert.deepEqual(decode(bundleBytes), bundle);
    return new Response(null, { status: 200 });
  }, keyPair);
  await foundAs.publish("you", state, bundle);
});

test("publish throws with the server error text", async () => {
  const foundAs = client(async () => new Response("  rate limited  ", { status: 429 }));
  await assert.rejects(
    () => foundAs.publish("you", { type: PageType.Redirect }, {}),
    new Error("foundas publish failed: HTTP 429 (rate limited)"),
  );
});

test("load returns the decoded state, null on 404, throws on 403", async () => {
  const keyPair = generateKeyPair();
  const state = { type: PageType.LinkTree, md: "", html: "", redir: "", linkTree: { displayName: "You" } };

  const foundAs = client(async (_url, init) => {
    const [op, , payload] = decodeRequest(init.body as Uint8Array, keyPair);
    assert.equal(op, 2);
    assert.equal(payload[1], "you");
    return new Response(cbor(state), { status: 200 });
  }, keyPair);
  assert.deepEqual(await foundAs.load("you"), state);

  const missing = client(async () => new Response(null, { status: 404 }), keyPair);
  assert.equal(await missing.load("you"), null);

  const forbidden = client(async () => new Response("Forbidden", { status: 403 }), keyPair);
  await assert.rejects(() => forbidden.load("you"), /HTTP 403 \(Forbidden\)/);
});

test("domain ops use ops 4/5/6/7 with [ts, slug, domain]", async () => {
  const keyPair = generateKeyPair();
  const calls: Array<[number, unknown[]]> = [];
  const status = { mapped: false, bound: true, reachable: true, target: "you.found.as", apex: false };

  const foundAs = client(async (_url, init) => {
    const [op, , payload] = decodeRequest(init.body as Uint8Array, keyPair);
    calls.push([op, payload]);
    if (op === 6) return new Response(cbor(status), { status: 200 });
    if (op === 7) return new Response(cbor(["example.com"]), { status: 200 });
    return new Response(null, { status: 200 });
  }, keyPair);

  await foundAs.mapDomain("you", "example.com");
  await foundAs.unmapDomain("you", "example.com");
  assert.deepEqual(await foundAs.domainStatus("you", "example.com"), status);
  assert.deepEqual(await foundAs.listDomains("you"), ["example.com"]);

  assert.deepEqual(
    calls.map(([op, payload]) => [op, payload[1], payload[2]]),
    [
      [4, "you", "example.com"],
      [5, "you", "example.com"],
      [6, "you", "example.com"],
      [7, "you", ""],
    ],
  );
});

test("listDomains returns [] when the server answers null", async () => {
  const foundAs = client(async () => new Response(cbor(null), { status: 200 }));
  assert.deepEqual(await foundAs.listDomains("you"), []);
});

test("indieAuth signs the authorization parameters and returns the code", async () => {
  const keyPair = generateKeyPair();
  const params = {
    me: "https://found.as/you",
    clientId: "https://app.example",
    redirectUri: "https://app.example/callback",
    codeChallenge: "challenge",
    codeChallengeMethod: "S256",
    scope: "profile",
  };
  const foundAs = client(async (_url, init) => {
    const [op, , payload] = decodeRequest(init.body as Uint8Array, keyPair);
    assert.equal(op, 10);
    assert.deepEqual(payload.slice(1), [
      params.me,
      params.clientId,
      params.redirectUri,
      params.codeChallenge,
      params.codeChallengeMethod,
      params.scope,
    ]);
    return new Response(cbor({ code: "auth-code" }), { status: 200 });
  }, keyPair);
  assert.deepEqual(await foundAs.indieAuth(params), { code: "auth-code" });
});
