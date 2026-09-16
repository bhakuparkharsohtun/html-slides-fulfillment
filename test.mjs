/* Real tests: generate an RSA key, mint tokens, run them through verifyJwt,
 * and drive the webhook handler with a mocked marketplace API. */

import { webcrypto } from "node:crypto";
import assert from "node:assert";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
}
if (!globalThis.atob) {
  globalThis.atob = (b64) => Buffer.from(b64, "base64").toString("binary");
}

const { verifyJwt, isWorkAccount, MSA_TENANT } = await import("./src/jwt.js");

/* ---------- key setup ---------- */
const pair = await webcrypto.subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true, ["sign", "verify"]
);
const pubJwk = await webcrypto.subtle.exportKey("jwk", pair.publicKey);
pubJwk.kid = "test-key-1";

function b64url(buf) {
  return Buffer.from(buf).toString("base64")
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function mint(payload, { kid = "test-key-1", alg = "RS256" } = {}) {
  const header = b64url(JSON.stringify({ alg, kid, typ: "JWT" }));
  const body = b64url(JSON.stringify(payload));
  const data = new TextEncoder().encode(header + "." + body);
  const sig = await webcrypto.subtle.sign("RSASSA-PKCS1-v1_5", pair.privateKey, data);
  return `${header}.${body}.${b64url(sig)}`;
}

/* ---------- fake JWKS endpoint ---------- */
const JWKS_URL = "https://jwks.test/keys";
let fetchLog = [];
globalThis.fetch = async (url, init = {}) => {
  const u = String(url);
  fetchLog.push({ url: u, method: init.method || "GET", init });

  if (u === JWKS_URL) {
    return new Response(JSON.stringify({ keys: [pubJwk] }), {
      headers: { "content-type": "application/json" }
    });
  }
  return mockMarketplace(u, init);
};

const now = () => Math.floor(Date.now() / 1000);
const base = (over = {}) => ({
  aud: "app-123", iss: "https://login.microsoftonline.com/tid-abc/v2.0",
  tid: "tid-abc", exp: now() + 3600, nbf: now() - 60,
  preferred_username: "bk@contoso.com", name: "Test User", ...over
});

const V = { audiences: ["app-123"], issuers: ["https://login.microsoftonline.com/"], jwksUri: JWKS_URL };

let pass = 0, fail = 0;
async function check(name, fn) {
  try { await fn(); console.log("  PASS", name); pass++; }
  catch (e) { console.log("  FAIL", name, "-", e.message); fail++; }
}
async function rejects(fn, match) {
  let threw = null;
  try { await fn(); } catch (e) { threw = e; }
  assert(threw, "expected a rejection");
  if (match) assert(threw.message.includes(match),
    `expected "${match}", got "${threw.message}"`);
}

console.log("\nJWT verification");

await check("valid token passes", async () => {
  const c = await verifyJwt(await mint(base()), V);
  assert.equal(c.tid, "tid-abc");
});

await check("expired token rejected", async () => {
  const t = await mint(base({ exp: now() - 1000 }));
  await rejects(() => verifyJwt(t, V), "expired");
});

await check("wrong audience rejected", async () => {
  const t = await mint(base({ aud: "someone-else" }));
  await rejects(() => verifyJwt(t, V), "audience");
});

await check("wrong issuer rejected", async () => {
  const t = await mint(base({ iss: "https://evil.example/" }));
  await rejects(() => verifyJwt(t, V), "issuer");
});

await check("unknown kid rejected", async () => {
  const t = await mint(base(), { kid: "not-a-real-key" });
  await rejects(() => verifyJwt(t, V), "signing key not found");
});

await check("alg none rejected", async () => {
  const header = b64url(JSON.stringify({ alg: "none", kid: "test-key-1" }));
  const body = b64url(JSON.stringify(base()));
  await rejects(() => verifyJwt(`${header}.${body}.`, V), "unexpected alg");
});

await check("tampered payload rejected", async () => {
  const t = await mint(base());
  const [h, , s] = t.split(".");
  const evil = b64url(JSON.stringify(base({ tid: "attacker-tenant" })));
  await rejects(() => verifyJwt(`${h}.${evil}.${s}`, V), "signature");
});

await check("malformed token rejected", async () =>
  rejects(() => verifyJwt("not.a.token.at.all", V)));

await check("jwks is cached, not refetched", async () => {
  fetchLog = [];
  await verifyJwt(await mint(base()), V);
  await verifyJwt(await mint(base()), V);
  const hits = fetchLog.filter(f => f.url === JWKS_URL).length;
  assert(hits <= 1, `expected at most 1 JWKS fetch, saw ${hits}`);
});

console.log("\nWork account gate");

await check("work account accepted", () => {
  const r = isWorkAccount({ tid: "tid-abc", preferred_username: "bk@contoso.com" });
  assert(r && r.tid === "tid-abc");
});

await check("personal MSA tenant refused", () => {
  assert.equal(isWorkAccount({ tid: MSA_TENANT, preferred_username: "a@outlook.com" }), false);
});

await check("live.com idp refused", () => {
  assert.equal(isWorkAccount({ tid: "tid-abc", idp: "live.com" }), false);
});

await check("missing tid refused", () => {
  assert.equal(isWorkAccount({ preferred_username: "x@y.com" }), false);
});

await check("null claims refused", () => {
  assert.equal(isWorkAccount(null), false);
});

/* ---------- webhook ---------- */

let mpCalls = [];
let operationResponse = { status: 200, body: { id: "op-1", status: "InProgress" } };

function mockMarketplace(u, init) {
  mpCalls.push({ url: u, method: init.method || "GET", body: init.body });

  if (u.includes("/oauth2/v2.0/token")) {
    return new Response(JSON.stringify({ access_token: "fake", expires_in: 3600 }),
      { headers: { "content-type": "application/json" } });
  }
  if (u.includes("/operations/")) {
    if ((init.method || "GET") === "PATCH") {
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    }
    return new Response(JSON.stringify(operationResponse.body),
      { status: operationResponse.status, headers: { "content-type": "application/json" } });
  }
  return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
}

/* in-memory KV */
function makeKV() {
  const m = new Map();
  return {
    _m: m,
    async get(k, type) { const v = m.get(k); return v == null ? null : (type === "json" ? JSON.parse(v) : v); },
    async put(k, v) { m.set(k, v); },
  };
}

const { handleWebhook } = await import("./src/webhook.js");

function makeEnv() {
  return {
    SUBSCRIPTIONS: makeKV(),
    WEBHOOK_AUDIENCE: "app-123",
    PUBLISHER_TENANT_ID: "pub-tid",
    PUBLISHER_CLIENT_ID: "pub-cid",
    PUBLISHER_CLIENT_SECRET: "pub-secret"
  };
}

const tasks = [];
const ctx = { waitUntil: (p) => tasks.push(p) };
const settle = async () => { await Promise.all(tasks); tasks.length = 0; };

async function post(env, payload, token) {
  return handleWebhook(new Request("https://w.test/webhook", {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json"
    },
    body: JSON.stringify(payload)
  }), env, ctx);
}

/* webhook validates against the "common" JWKS url; point it at our fake */
const origVerify = JWKS_URL;
const webhookToken = async (over) => mint(base({ aud: "app-123", ...over }));

console.log("\nWebhook handler");

/* patch jwt module's jwks url by intercepting fetch for the real MS url */
const REAL_JWKS = "https://login.microsoftonline.com/common/discovery/v2.0/keys";
const prevFetch = globalThis.fetch;
globalThis.fetch = async (url, init = {}) => {
  if (String(url) === REAL_JWKS) {
    return new Response(JSON.stringify({ keys: [pubJwk] }),
      { headers: { "content-type": "application/json" } });
  }
  return prevFetch(url, init);
};

await check("unauthenticated call rejected with 401", async () => {
  const env = makeEnv();
  const res = await handleWebhook(new Request("https://w.test/webhook", {
    method: "POST", body: "{}", headers: { "content-type": "application/json" }
  }), env, ctx);
  assert.equal(res.status, 401);
});

await check("bad token rejected with 401", async () => {
  const env = makeEnv();
  const res = await post(env, { action: "Subscribe", subscriptionId: "s1", id: "o1" }, "garbage");
  assert.equal(res.status, 401);
});

await check("GET rejected with 405", async () => {
  const env = makeEnv();
  const res = await handleWebhook(new Request("https://w.test/webhook"), env, ctx);
  assert.equal(res.status, 405);
});

await check("Subscribe returns 200 and stores as active", async () => {
  const env = makeEnv(); mpCalls = [];
  const res = await post(env, {
    action: "Subscribe", subscriptionId: "sub-1", id: "op-1",
    planId: "pro", quantity: 5, offerId: "html-slides"
  }, await webhookToken());
  assert.equal(res.status, 200);
  await settle();
  const sub = await env.SUBSCRIPTIONS.get("sub:sub-1", "json");
  assert.equal(sub.active, true);
  assert.equal(sub.planId, "pro");
  assert.equal(sub.quantity, 5);
});

await check("Subscribe does NOT patch the operation", async () => {
  const env = makeEnv(); mpCalls = [];
  await post(env, { action: "Subscribe", subscriptionId: "sub-x", id: "op-x", planId: "pro" },
    await webhookToken());
  await settle();
  const patches = mpCalls.filter(c => c.method === "PATCH");
  assert.equal(patches.length, 0, "notify-only events must not be acknowledged");
});

await check("ChangePlan patches Success", async () => {
  const env = makeEnv(); mpCalls = [];
  await post(env, {
    action: "ChangePlan", subscriptionId: "sub-2", id: "op-2", planId: "enterprise"
  }, await webhookToken());
  await settle();
  const patch = mpCalls.find(c => c.method === "PATCH");
  assert(patch, "expected a PATCH");
  assert(JSON.parse(patch.body).status === "Success");
  const sub = await env.SUBSCRIPTIONS.get("sub:sub-2", "json");
  assert.equal(sub.planId, "enterprise");
});

await check("ChangeQuantity patches Success and stores quantity", async () => {
  const env = makeEnv(); mpCalls = [];
  await post(env, {
    action: "ChangeQuantity", subscriptionId: "sub-3", id: "op-3", quantity: 25
  }, await webhookToken());
  await settle();
  const patch = mpCalls.find(c => c.method === "PATCH");
  assert.equal(JSON.parse(patch.body).status, "Success");
  const sub = await env.SUBSCRIPTIONS.get("sub:sub-3", "json");
  assert.equal(sub.quantity, 25);
});

await check("Suspend revokes access", async () => {
  const env = makeEnv();
  await post(env, { action: "Suspend", subscriptionId: "sub-4", id: "op-4" }, await webhookToken());
  await settle();
  const sub = await env.SUBSCRIPTIONS.get("sub:sub-4", "json");
  assert.equal(sub.active, false);
  assert.equal(sub.status, "Suspended");
});

await check("Reinstate restores access and acknowledges", async () => {
  const env = makeEnv(); mpCalls = [];
  await post(env, { action: "Reinstate", subscriptionId: "sub-5", id: "op-5" }, await webhookToken());
  await settle();
  const sub = await env.SUBSCRIPTIONS.get("sub:sub-5", "json");
  assert.equal(sub.active, true);
  assert(mpCalls.find(c => c.method === "PATCH"), "Reinstate requires an ack");
});

await check("Unsubscribe revokes access", async () => {
  const env = makeEnv();
  await post(env, { action: "Unsubscribe", subscriptionId: "sub-6", id: "op-6" }, await webhookToken());
  await settle();
  const sub = await env.SUBSCRIPTIONS.get("sub:sub-6", "json");
  assert.equal(sub.active, false);
  assert.equal(sub.status, "Unsubscribed");
});

await check("replayed event is ignored", async () => {
  const env = makeEnv(); mpCalls = [];
  const p = { action: "ChangeQuantity", subscriptionId: "sub-7", id: "op-dup", quantity: 10 };
  await post(env, p, await webhookToken()); await settle();
  const after1 = mpCalls.filter(c => c.method === "PATCH").length;
  await post(env, p, await webhookToken()); await settle();
  const after2 = mpCalls.filter(c => c.method === "PATCH").length;
  assert.equal(after1, after2, "duplicate delivery must not re-acknowledge");
});

await check("unverifiable operation patches Failure", async () => {
  const env = makeEnv(); mpCalls = [];
  operationResponse = { status: 500, body: null };
  await post(env, { action: "ChangePlan", subscriptionId: "sub-8", id: "op-8", planId: "x" },
    await webhookToken());
  await settle();
  const patch = mpCalls.find(c => c.method === "PATCH");
  assert.equal(JSON.parse(patch.body).status, "Failure");
  operationResponse = { status: 200, body: { id: "op-1", status: "InProgress" } };
});

await check("unknown future action does not crash or revoke", async () => {
  const env = makeEnv();
  const res = await post(env, { action: "SomeNewThing2027", subscriptionId: "sub-9", id: "op-9" },
    await webhookToken());
  assert.equal(res.status, 200);
  await settle();
  const sub = await env.SUBSCRIPTIONS.get("sub:sub-9", "json");
  assert.equal(sub.unknownAction, "SomeNewThing2027");
});

await check("extra unknown fields are tolerated", async () => {
  const env = makeEnv();
  const res = await post(env, {
    action: "Subscribe", subscriptionId: "sub-10", id: "op-10", planId: "pro",
    futureField: { nested: true }, anotherNew: [1, 2, 3]
  }, await webhookToken());
  assert.equal(res.status, 200);
  await settle();
  assert((await env.SUBSCRIPTIONS.get("sub:sub-10", "json")).active === true);
});

await check("missing subscriptionId rejected with 400", async () => {
  const env = makeEnv();
  const res = await post(env, { action: "Subscribe" }, await webhookToken());
  assert.equal(res.status, 400);
});

await check("200 returned before processing completes", async () => {
  const env = makeEnv();
  tasks.length = 0;
  const res = await post(env, { action: "Subscribe", subscriptionId: "sub-11", id: "op-11" },
    await webhookToken());
  assert.equal(res.status, 200);
  assert(tasks.length > 0, "work must be deferred to waitUntil");
  await settle();
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
