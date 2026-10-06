import { test } from "node:test";
import * as assert from "node:assert";
import { verify, hashes } from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { encode, decode } from "cbor-x";
import { ZeroPw, generateKeyPair } from "./index.ts";

hashes.sha512 = sha512;

type FetchHandler = (url: unknown, init: RequestInit) => Promise<Response>;

function client(handler: FetchHandler, url?: string): ZeroPw {
  return new ZeroPw({ url, fetch: handler as typeof fetch });
}

test("constructor generates a key pair, or keeps a provided one", () => {
  const generated = new ZeroPw({ fetch: globalThis.fetch });
  assert.equal(generated.keyPair.publicKey.length, 32);
  assert.equal(generated.keyPair.secretKey.length, 64);

  const keyPair = generateKeyPair();
  assert.equal(new ZeroPw({ keyPair }).keyPair, keyPair);
});

test("generateKeyPair is deterministic from a seed", () => {
  const seed = new Uint8Array(32).fill(7);
  assert.deepEqual(generateKeyPair(seed), generateKeyPair(seed));
});

test("store posts [publicKey, sign(CBOR([timestamp, message]))] to the constructor url", async () => {
  const message = new TextEncoder().encode("arbitrary data");
  const before = Date.now() / 1000;
  const zeroPw = client(async (url, init) => {
    assert.equal(String(url), "https://1pw.me/");
    assert.equal(init.method, "POST");

    const [publicKey, signed] = decode(init.body as Uint8Array) as [Uint8Array, Uint8Array];
    assert.deepEqual(publicKey, zeroPw.keyPair.publicKey);

    const payload = signed.subarray(64);
    assert.ok(verify(signed.subarray(0, 64), payload, publicKey), "signature must verify");
    const [timestamp, stored] = decode(payload) as [number, Uint8Array];
    assert.ok(timestamp >= before && timestamp <= Date.now() / 1000);
    assert.deepEqual(stored, message);

    return new Response(null, { status: 200 });
  }, "https://1pw.me/");
  await zeroPw.store(message);
});

test("store and retrieve roundtrip through a fake server, null deletes", async () => {
  const storage = new Map<string, Uint8Array>();
  const server: FetchHandler = async (_url, init) => {
    const parts = decode(init.body as Uint8Array) as [Uint8Array, Uint8Array?];
    const id = String(parts[0]);
    if (parts.length === 2) {
      // store: keep the signed blob, drop it when the message is null
      const [, message] = decode(parts[1]!.subarray(64)) as [number, Uint8Array | null];
      if (message === null) storage.delete(id);
      else storage.set(id, parts[1]!);
      return new Response(null, { status: 200 });
    }
    const signed = storage.get(id);
    if (signed === undefined) return new Response(null, { status: 404 });
    return new Response(new Uint8Array(signed), { status: 200 });
  };

  const writer = client(server);
  const message = new TextEncoder().encode("stored bytes");
  await writer.store(message);

  const entry = await writer.retrieve();
  assert.equal(new TextDecoder().decode(entry!.message!), "stored bytes");
  assert.ok(entry!.timestamp > 0);

  // a different client can read the data with only the writer's public key
  const reader = client(server);
  assert.deepEqual((await reader.retrieve(writer.keyPair.publicKey))!.message, entry!.message);
  // its own key has nothing stored
  assert.equal(await reader.retrieve(), null);

  await writer.store(null);
  assert.equal(await writer.retrieve(), null);
});

test("store rejects messages over 64 KiB without fetching", async () => {
  let called = false;
  const zeroPw = client(async () => {
    called = true;
    return new Response(null, { status: 200 });
  });
  await assert.rejects(() => zeroPw.store(new Uint8Array(64 * 1024 + 1)), RangeError);
  assert.equal(called, false);
});

test("store throws on 4xx/5xx", async () => {
  for (const status of [400, 500]) {
    const zeroPw = client(async () => new Response(null, { status }));
    await assert.rejects(
      () => zeroPw.store(new Uint8Array([1])),
      new Error(`0pw store failed: HTTP ${status}`),
    );
  }
});

test("retrieve returns null on 404 and throws on 5xx", async () => {
  const zeroPw = client(async () => new Response(null, { status: 404 }));
  assert.equal(await zeroPw.retrieve(), null);

  const failing = client(async () => new Response(null, { status: 500 }));
  await assert.rejects(() => failing.retrieve(), /HTTP 500/);
});

test("retrieve throws on an invalid signature", async () => {
  const zeroPw = client(async () => new Response(new Uint8Array(100), { status: 200 }));
  await assert.rejects(() => zeroPw.retrieve(), /invalid signature/);
});
