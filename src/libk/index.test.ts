import { test } from "node:test";
import * as assert from "node:assert";
import { Libk } from "./index.ts";

type FetchHandler = (url: unknown, init: RequestInit) => Promise<Response>;

function client(handler: FetchHandler, password = "s3cret"): Libk {
  return new Libk({ subdomain: "you", password, fetch: handler as typeof fetch });
}

function basicAuth(subdomain: string, password: string): string {
  const bytes = new TextEncoder().encode(`${subdomain}:${password}`);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return `Basic ${btoa(binary)}`;
}

test("constructor validates the subdomain format", () => {
  for (const bad of ["You", "you_me", "you.me", ""]) {
    assert.throws(() => new Libk({ subdomain: bad, password: "x" }), RangeError);
  }
  assert.ok(new Libk({ subdomain: "you-2", password: "x" }));
});

test("get sends Basic auth and returns the IPs, null when empty", async () => {
  const seen: string[] = [];
  const libk = client(async (url, init) => {
    assert.equal(String(url), "https://libk.org/");
    assert.equal(init.method, "GET");
    seen.push(new Headers(init.headers).get("authorization")!);
    return new Response(JSON.stringify(["203.0.113.7", "2001:db8::1"]), { status: 200 });
  });
  assert.deepEqual(await libk.get(), ["203.0.113.7", "2001:db8::1"]);
  assert.equal(seen[0], basicAuth("you", "s3cret"));

  for (const body of ["null", "[]"]) {
    const empty = client(async () => new Response(body, { status: 200 }));
    assert.equal(await empty.get(), null);
  }
});

test("get throws on 401 and 5xx with the server text", async () => {
  const unauthorized = client(async () => new Response("Invalid password", { status: 401 }));
  await assert.rejects(() => unauthorized.get(), /HTTP 401 \(Invalid password\)/);

  const failing = client(async () => new Response("boom", { status: 500 }));
  await assert.rejects(() => failing.get(), /HTTP 500 \(boom\)/);
});

test("update defaults to the caller IP: no To header", async () => {
  const libk = client(async (_url, init) => {
    const headers = new Headers(init.headers);
    assert.equal(init.method, "POST");
    assert.equal(headers.get("to"), null);
    assert.equal(headers.get("newpassword"), null);
    return new Response(JSON.stringify(["198.51.100.3"]), { status: 200 });
  });
  assert.deepEqual(await libk.update(), ["198.51.100.3"]);
  assert.deepEqual(await libk.update({ ips: [] }), ["198.51.100.3"]);
});

test("update sends comma-separated To IPs", async () => {
  const libk = client(async (_url, init) => {
    assert.equal(new Headers(init.headers).get("to"), "127.0.0.1,::1");
    return new Response(JSON.stringify(["127.0.0.1", "::1"]), { status: 200 });
  });
  assert.deepEqual(await libk.update({ ips: ["127.0.0.1", "::1"] }), ["127.0.0.1", "::1"]);
});

test("update with newPassword rotates the instance password", async () => {
  const authorizations: Array<string | null> = [];
  const libk = client(async (_url, init) => {
    const headers = new Headers(init.headers);
    authorizations.push(headers.get("authorization"));
    if (authorizations.length === 1) {
      assert.equal(headers.get("newpassword"), "n3w");
    }
    return new Response(JSON.stringify(["198.51.100.3"]), { status: 200 });
  });
  await libk.update({ newPassword: "n3w" });
  await libk.get();
  assert.equal(authorizations[0], basicAuth("you", "s3cret"));
  assert.equal(authorizations[1], basicAuth("you", "n3w"));
});

test("update does not rotate the password when the request fails", async () => {
  const authorizations: Array<string | null> = [];
  const libk = client(async (_url, init) => {
    authorizations.push(new Headers(init.headers).get("authorization"));
    return new Response("nope", { status: 500 });
  });
  await assert.rejects(() => libk.update({ newPassword: "n3w" }), /HTTP 500/);
  await assert.rejects(() => libk.get(), /HTTP 500/);
  assert.equal(authorizations[1], basicAuth("you", "s3cret"), "still the old password");
});

test("update accepts UTF-8 passwords in Basic auth", async () => {
  const libk = client(async (_url, init) => {
    assert.equal(new Headers(init.headers).get("authorization"), basicAuth("you", "päss🔑"));
    return new Response(JSON.stringify([]), { status: 200 });
  }, "päss🔑");
  await libk.update();
});

test("delete issues DELETE with auth and throws on failure", async () => {
  const libk = client(async (_url, init) => {
    assert.equal(init.method, "DELETE");
    assert.equal(new Headers(init.headers).get("authorization"), basicAuth("you", "s3cret"));
    return new Response(null, { status: 200 });
  });
  await libk.delete();

  const failing = client(async () => new Response("Invalid password", { status: 401 }));
  await assert.rejects(() => failing.delete(), /HTTP 401/);
});
