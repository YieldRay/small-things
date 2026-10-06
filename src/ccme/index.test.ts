import { test } from "node:test";
import * as assert from "node:assert";
import {
  Favicons,
  Fonts,
  Library,
  Screenshots,
  Secrets,
  powLevel,
  powVerify,
  solvePow,
  base64UrlEncode,
  base64UrlDecode,
} from "./index.ts";

type FetchHandler = (url: unknown, init?: RequestInit) => Promise<Response>;

function mockFetch(handler: FetchHandler): typeof fetch {
  return handler as typeof fetch;
}

function json(value: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(value), { status, headers });
}

// ---- proof of work ---------------------------------------------------------

test("powLevel matches the documented hello world vector", () => {
  // from https://cc.me/pow: ends in 0x300000 → exactly 20 trailing zero bits
  assert.equal(powLevel("aGVsbG8gd29ybGQ.XBCKI7lQ3i4"), 20);
  assert.ok(powVerify("aGVsbG8gd29ybGQ.XBCKI7lQ3i4", 20));
  assert.ok(!powVerify("aGVsbG8gd29ybGQ.XBCKI7lQ3i4", 21));
});

test("solvePow produces verifiable tokens", () => {
  const token = solvePow("hello world", 12);
  assert.ok(powVerify(token, 12));
  const [docPart] = token.split(".");
  assert.equal(new TextDecoder().decode(base64UrlDecode(docPart!)), "hello world");
});

test("powLevel rejects malformed tokens", () => {
  assert.throws(() => powLevel("onlyone"), /two base64url segments/);
  assert.throws(() => powLevel("a.b.c"), /two base64url segments/);
  assert.throws(() => powLevel("aGVsbG8gd29ybGQ=.XBCKI7lQ3i4"), /canonical/);
  const longSuffix = base64UrlEncode(new Uint8Array(33));
  assert.throws(() => powLevel(`aGVsbG8gd29ybGQ.${longSuffix}`), /at most 32 bytes/);
});

test("base64url roundtrips", () => {
  const bytes = crypto.getRandomValues(new Uint8Array(64));
  const encoded = base64UrlEncode(bytes);
  assert.doesNotMatch(encoded, /[+/=]/);
  assert.deepEqual(base64UrlDecode(encoded), bytes);
  assert.deepEqual(base64UrlDecode(`${encoded}=`), bytes);
});

// ---- favicons ---------------------------------------------------------------

test("favicons: url building, get, 404 → null, errors carry server detail", async () => {
  const favicons = new Favicons({
    fetch: mockFetch(async (url) => {
      const parsed = new URL(String(url));
      assert.equal(parsed.pathname, "/icon");
      const target = parsed.searchParams.get("url")!;
      if (target === "https://example.com") {
        return new Response(new Uint8Array([1, 2, 3]), {
          status: 200,
          headers: { "content-type": "image/png" },
        });
      }
      if (target === "https://missing.example") return new Response("nope", { status: 404 });
      return json({ error: "cache lookup failed" }, 502);
    }),
  });

  assert.equal(
    favicons.iconUrl("https://example.com").toString(),
    "https://cc.me/icon?url=https%3A%2F%2Fexample.com",
  );
  const icon = await favicons.get("https://example.com");
  assert.deepEqual(icon, { bytes: new Uint8Array([1, 2, 3]), contentType: "image/png" });
  assert.equal(await favicons.get("https://missing.example"), null);
  await assert.rejects(() => favicons.get("https://down.example"), /HTTP 502 \(cache lookup failed\)/);
});

// ---- fonts -------------------------------------------------------------------

test("fonts: search encodes query params and decodes the result", async () => {
  const fonts = new Fonts({
    fetch: mockFetch(async (url) => {
      const parsed = new URL(String(url));
      assert.equal(parsed.pathname, "/fonts");
      assert.equal(parsed.searchParams.get("q"), "roboto");
      assert.equal(parsed.searchParams.get("category"), "SANS_SERIF");
      assert.equal(parsed.searchParams.get("limit"), "2");
      return json({ total: 18, count: 2, offset: 0, limit: 2, families: [] });
    }),
  });
  const result = await fonts.search({ q: "roboto", category: "SANS_SERIF", limit: 2 });
  assert.equal(result.total, 18);
});

test("fonts: family, fileUrl, download", async () => {
  const fonts = new Fonts({
    fetch: mockFetch(async (url) => {
      const parsed = new URL(String(url));
      if (parsed.pathname === "/fonts/roboto") {
        return json({ slug: "roboto", name: "Roboto", axes: [{ tag: "wght", min: 100, max: 900 }] });
      }
      if (parsed.pathname === "/fonts/roboto/Roboto%5Bwdth%2Cwght%5D.ttf") {
        return new Response(new Uint8Array([0, 1, 1]), { status: 200 });
      }
      return new Response("not found", { status: 404 });
    }),
  });
  const family = await fonts.family("roboto");
  assert.equal(family.axes![0]!.tag, "wght");
  assert.equal(
    fonts.fileUrl("roboto", "Roboto[wdth,wght].ttf").toString(),
    "https://cc.me/fonts/roboto/Roboto%5Bwdth%2Cwght%5D.ttf",
  );
  assert.deepEqual(await fonts.download("roboto", "Roboto[wdth,wght].ttf"), new Uint8Array([0, 1, 1]));
  await assert.rejects(() => fonts.family("unknown"), /HTTP 404/);
});

// ---- library -----------------------------------------------------------------

test("library: id defaults to a fresh UUID and is validated", () => {
  assert.match(new Library().id, /^[0-9a-f-]{36}$/);
  assert.throws(() => new Library({ id: "nope" }), RangeError);
});

test("library: full lifecycle over a fake pool", async () => {
  const id = "9f1c2e7a-5b3d-4c8e-a1f0-6d2b9c4e7a01";
  const leases = new Set<string>();
  let count = 0;

  const lib = new Library({
    id,
    fetch: mockFetch(async (url, init) => {
      const parsed = new URL(String(url));
      assert.ok(parsed.pathname.startsWith(`/l/${id}`));
      const action = parsed.pathname.slice(`/l/${id}`.length);
      if (init?.method === "PUT") {
        count = JSON.parse(String(init.body)).count;
        return json({ id, count, in_use: 0, available: count });
      }
      if (init?.method === "DELETE") return json({ deleted: true });
      if (action === "/borrow") {
        if (leases.size >= count) return json({ error: "no resource available" }, 409);
        const lease = crypto.randomUUID();
        leases.add(lease);
        return json({ lease, position: 0, expires_at_unix: 1781337630, expires_in: 30 });
      }
      if (action === "/return") {
        const gone = leases.delete(JSON.parse(String(init!.body)).lease);
        return json({ returned: gone });
      }
      return json({ id, count, in_use: leases.size, available: count - leases.size });
    }),
  });

  assert.deepEqual(await lib.register(1), { id, count: 1, in_use: 0, available: 1 });

  const lease = await lib.borrow({ ttl: 30, wait: 0 });
  assert.equal(lease!.position, 0);
  assert.equal(await lib.borrow(), null, "exhausted pool yields null");

  assert.deepEqual(await lib.inspect(), { id, count: 1, in_use: 1, available: 0 });
  assert.equal(await lib.returnLease(lease!.lease), true);
  assert.equal(await lib.returnLease(lease!.lease), false, "idempotent return");
  assert.equal((await lib.borrow())!.position, 0, "returned slot is handed out again");

  await lib.delete();
});

// ---- screenshots ---------------------------------------------------------------

test("screenshots: capture solves the required level over the request document", async () => {
  const shots = new Screenshots({
    fetch: mockFetch(async (url) => {
      const parsed = new URL(String(url));
      if (parsed.pathname === "/shot/config") return json({ level: 4 });
      assert.equal(parsed.pathname, "/shot");
      const token = parsed.searchParams.get("token")!;
      assert.ok(powVerify(token, 4), "token proves the required level");
      const doc = JSON.parse(new TextDecoder().decode(base64UrlDecode(token.split(".")[0]!)));
      assert.equal(doc.url, "https://example.com/");
      assert.equal(doc.width, 800);
      assert.equal(doc.height, 600);
      assert.equal(doc.scheme, "dark");
      assert.ok(Math.abs(doc.ts - Date.now() / 1000) < 5);
      assert.ok(!("scale" in doc));
      return new Response(new Uint8Array([0x89, 0x50, 0x4e, 0x47]), {
        status: 200,
        headers: { "x-cache": "hit" },
      });
    }),
  });
  const shot = await shots.capture({ url: "https://example.com/", scheme: "dark" });
  assert.deepEqual(shot.bytes, new Uint8Array([0x89, 0x50, 0x4e, 0x47]));
  assert.equal(shot.cached, true);
});

// ---- secrets -------------------------------------------------------------------

test("secrets: create encrypts client-side and open decrypts", async () => {
  let stored: { ciphertext: string; expires_hours: number; auto_destroy: boolean } | null = null;
  const secrets = new Secrets({
    fetch: mockFetch(async (url, init) => {
      const parsed = new URL(String(url));
      if (init?.method === "POST" && parsed.pathname === "/p") {
        stored = JSON.parse(String(init.body));
        return json({ id: "sec_123" });
      }
      if (parsed.pathname === "/p/sec_123/content") {
        return json({ ciphertext: stored!.ciphertext });
      }
      if (init?.method === "DELETE") return new Response(null, { status: 200 });
      return new Response("gone", { status: 410 });
    }),
  });

  const created = await secrets.create("burn after reading", { autoDestroy: true });
  assert.equal(created.id, "sec_123");
  assert.match(created.url, /^https:\/\/cc\.me\/p\/sec_123#/);
  assert.equal(stored!.auto_destroy, true);
  assert.equal(stored!.expires_hours, 24);
  assert.ok(!stored!.ciphertext.includes("burn"), "server never sees plaintext");

  const opened = await secrets.open(created.url);
  assert.equal(new TextDecoder().decode(opened), "burn after reading");

  await secrets.burn("sec_123");
});

test("secrets: open reports 410 and bad keys", async () => {
  const gone = new Secrets({ fetch: mockFetch(async () => new Response("gone", { status: 410 })) });
  await assert.rejects(
    () => gone.open("https://cc.me/p/sec_123#aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    /HTTP 410/,
  );

  let ciphertext = "";
  const secrets = new Secrets({
    fetch: mockFetch(async (url, init) => {
      if (init?.method === "POST") {
        ciphertext = JSON.parse(String(init.body)).ciphertext;
        return json({ id: "sec_123" });
      }
      return json({ ciphertext });
    }),
  });
  const created = await secrets.create("hello");
  const wrongKey = `${created.url.slice(0, -1)}A`; // corrupt the last key character
  await assert.rejects(() => secrets.open(wrongKey), /decryption failed/);
});
