/* Real tests: generate an RSA key, mint tokens, run them through verifyJwt,
 * and drive the webhook and entitlement handlers with a mocked marketplace. */

import { webcrypto } from "node:crypto";
import assert from "node:assert";

if (!globalThis.crypto) {
  Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
}
if (!globalThis.atob) {
  globalThis.atob = (b64) => Buffer.from(b64, "base64").toString("binary");
}

const { verifyJwt, classifyAccount, isPersonalAccount, MSA_TENANT } =
  await import("./src/jwt.js");

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

const JWKS_URL = "https://jwks.test/keys";
const REAL_JWKS = "https://login.microsoftonline.com/common/discovery/v2.0/keys";

let mpCalls = [];
let operationResponse = { status: 200, body: { id: "op-1", status: "InProgress" } };
let fetchLog = [];

globalThis.fetch = async (url, init = {}) => {
  const u = String(url);
  fetchLog.push({ url: u });

  if (u === JWKS_URL || u === REAL_JWKS) {
    return new Response(JSON.stringify({ keys: [pubJwk] }),
      { headers: { "content-type": "application/json" } });
  }

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
};

const now = () => Math.floor(Date.now() / 1000);
const base = (over = {}) => ({
  aud: "app-123", iss: "https://login.microsoftonline.com/tid-abc/v2.0",
  tid: "tid-abc", oid: "user-oid-1", exp: now() + 3600, nbf: now() - 60,
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

console.log("\nAccount classification");

await check("work account keyed by tenant", () => {
  const a = classifyAccount({ tid: "tid-abc", oid: "o1", preferred_username: "a@contoso.com" });
  assert.equal(a.kind, "work");
  assert.equal(a.key, "tenant:tid-abc");
  assert.equal(a.seatModel, "tenant");
});

await check("personal account keyed by user, NOT tenant", () => {
  const a = classifyAccount({ tid: MSA_TENANT, oid: "msa-1", preferred_username: "x@outlook.com" });
  assert.equal(a.kind, "personal");
  assert.equal(a.key, "user:msa-1");
  assert.equal(a.seatModel, "user");
  assert(!a.key.includes(MSA_TENANT), "personal key must not be the shared MSA tenant");
});

await check("two personal accounts get DIFFERENT keys", () => {
  const a = classifyAccount({ tid: MSA_TENANT, oid: "msa-aaa" });
  const b = classifyAccount({ tid: MSA_TENANT, oid: "msa-bbb" });
  assert.notEqual(a.key, b.key, "consumer accounts must not share an entitlement key");
});

await check("live.com idp treated as personal", () => {
  const a = classifyAccount({ tid: "some-tid", idp: "live.com", oid: "o9" });
  assert.equal(a.kind, "personal");
  assert.equal(a.key, "user:o9");
});

await check("personal account without oid refused", () => {
  assert.equal(classifyAccount({ tid: MSA_TENANT }), null);
});

await check("missing tid and not personal refused", () => {
  assert.equal(classifyAccount({ preferred_username: "x@y.com" }), null);
});

await check("null claims refused", () => {
  assert.equal(classifyAccount(null), null);
});

await check("isPersonalAccount helper agrees", () => {
  assert.equal(isPersonalAccount({ tid: MSA_TENANT, oid: "m1" }), true);
  assert.equal(isPersonalAccount({ tid: "tid-abc", oid: "o1" }), false);
});

/* ---------- harness ---------- */

function makeKV() {
  const m = new Map();
  return {
    _m: m,
    async get(k, type) { const v = m.get(k); return v == null ? null : (type === "json" ? JSON.parse(v) : v); },
    async put(k, v) { m.set(k, v); },
  };
}

const { handleWebhook } = await import("./src/webhook.js");
const worker = (await import("./src/index.js")).default;

function makeEnv() {
  return {
    SUBSCRIPTIONS: makeKV(),
    WEBHOOK_AUDIENCE: "app-123",
    ADDIN_CLIENT_ID: "addin-app",
    PUBLISHER_TENANT_ID: "pub-tid",
    PUBLISHER_CLIENT_ID: "pub-cid",
    PUBLISHER_CLIENT_SECRET: "pub-secret",
    ALLOWED_ORIGINS: "https://site.test"
  };
}

const tasks = [];
const ctx = { waitUntil: (p) => tasks.push(p) };
const settle = async () => { await Promise.all(tasks); tasks.length = 0; };

const webhookToken = async (over) => mint(base({ aud: "app-123", ...over }));

async function post(env, payload, token) {
  return handleWebhook(new Request("https://w.test/webhook", {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(payload)
  }), env, ctx);
}

console.log("\nWebhook handler");

await check("unauthenticated call rejected with 401", async () => {
  const res = await handleWebhook(new Request("https://w.test/webhook", {
    method: "POST", body: "{}", headers: { "content-type": "application/json" }
  }), makeEnv(), ctx);
  assert.equal(res.status, 401);
});

await check("bad token rejected with 401", async () => {
  const res = await post(makeEnv(), { action: "Subscribe", subscriptionId: "s1", id: "o1" }, "garbage");
  assert.equal(res.status, 401);
});

await check("GET rejected with 405", async () => {
  const res = await handleWebhook(new Request("https://w.test/webhook"), makeEnv(), ctx);
  assert.equal(res.status, 405);
});

await check("Subscribe stores as active", async () => {
  const env = makeEnv();
  const res = await post(env, {
    action: "Subscribe", subscriptionId: "sub-1", id: "op-1", planId: "pro", quantity: 5
  }, await webhookToken());
  assert.equal(res.status, 200);
  await settle();
  const sub = await env.SUBSCRIPTIONS.get("sub:sub-1", "json");
  assert.equal(sub.active, true);
  assert.equal(sub.planId, "pro");
});

await check("Subscribe does NOT patch the operation", async () => {
  const env = makeEnv(); mpCalls = [];
  await post(env, { action: "Subscribe", subscriptionId: "sub-x", id: "op-x" }, await webhookToken());
  await settle();
  assert.equal(mpCalls.filter(c => c.method === "PATCH").length, 0,
    "notify-only events must not be acknowledged");
});

await check("ChangePlan patches Success", async () => {
  const env = makeEnv(); mpCalls = [];
  await post(env, { action: "ChangePlan", subscriptionId: "sub-2", id: "op-2", planId: "ent" },
    await webhookToken());
  await settle();
  const patch = mpCalls.find(c => c.method === "PATCH");
  assert.equal(JSON.parse(patch.body).status, "Success");
});

await check("ChangeQuantity patches Success", async () => {
  const env = makeEnv(); mpCalls = [];
  await post(env, { action: "ChangeQuantity", subscriptionId: "sub-3", id: "op-3", quantity: 25 },
    await webhookToken());
  await settle();
  assert.equal(JSON.parse(mpCalls.find(c => c.method === "PATCH").body).status, "Success");
  assert.equal((await env.SUBSCRIPTIONS.get("sub:sub-3", "json")).quantity, 25);
});

await check("Suspend revokes access", async () => {
  const env = makeEnv();
  await post(env, { action: "Suspend", subscriptionId: "sub-4", id: "op-4" }, await webhookToken());
  await settle();
  assert.equal((await env.SUBSCRIPTIONS.get("sub:sub-4", "json")).active, false);
});

await check("Reinstate restores and acknowledges", async () => {
  const env = makeEnv(); mpCalls = [];
  await post(env, { action: "Reinstate", subscriptionId: "sub-5", id: "op-5" }, await webhookToken());
  await settle();
  assert.equal((await env.SUBSCRIPTIONS.get("sub:sub-5", "json")).active, true);
  assert(mpCalls.find(c => c.method === "PATCH"), "Reinstate requires an ack");
});

await check("Unsubscribe revokes access", async () => {
  const env = makeEnv();
  await post(env, { action: "Unsubscribe", subscriptionId: "sub-6", id: "op-6" }, await webhookToken());
  await settle();
  assert.equal((await env.SUBSCRIPTIONS.get("sub:sub-6", "json")).status, "Unsubscribed");
});

await check("replayed event ignored", async () => {
  const env = makeEnv(); mpCalls = [];
  const p = { action: "ChangeQuantity", subscriptionId: "sub-7", id: "op-dup", quantity: 10 };
  await post(env, p, await webhookToken()); await settle();
  const a = mpCalls.filter(c => c.method === "PATCH").length;
  await post(env, p, await webhookToken()); await settle();
  assert.equal(mpCalls.filter(c => c.method === "PATCH").length, a);
});

await check("unverifiable operation patches Failure", async () => {
  const env = makeEnv(); mpCalls = [];
  operationResponse = { status: 500, body: null };
  await post(env, { action: "ChangePlan", subscriptionId: "sub-8", id: "op-8", planId: "x" },
    await webhookToken());
  await settle();
  assert.equal(JSON.parse(mpCalls.find(c => c.method === "PATCH").body).status, "Failure");
  operationResponse = { status: 200, body: { id: "op-1", status: "InProgress" } };
});

await check("unknown future action does not revoke", async () => {
  const env = makeEnv();
  const res = await post(env, { action: "NewThing2027", subscriptionId: "sub-9", id: "op-9" },
    await webhookToken());
  assert.equal(res.status, 200);
  await settle();
  assert.equal((await env.SUBSCRIPTIONS.get("sub:sub-9", "json")).unknownAction, "NewThing2027");
});

await check("extra unknown fields tolerated", async () => {
  const env = makeEnv();
  const res = await post(env, {
    action: "Subscribe", subscriptionId: "sub-10", id: "op-10",
    futureField: { nested: true }, another: [1, 2]
  }, await webhookToken());
  assert.equal(res.status, 200);
});

await check("missing subscriptionId rejected with 400", async () => {
  const res = await post(makeEnv(), { action: "Subscribe" }, await webhookToken());
  assert.equal(res.status, 400);
});

await check("200 returned before processing completes", async () => {
  tasks.length = 0;
  const res = await post(makeEnv(), { action: "Subscribe", subscriptionId: "s11", id: "o11" },
    await webhookToken());
  assert.equal(res.status, 200);
  assert(tasks.length > 0, "work must be deferred to waitUntil");
  await settle();
});

console.log("\nEntitlement, both account types");

async function entitlement(env, claims) {
  const token = await mint({ ...base(), aud: "addin-app", ...claims });
  const res = await worker.fetch(new Request("https://w.test/api/entitlement", {
    headers: { authorization: `Bearer ${token}`, origin: "https://site.test" }
  }), env, ctx);
  return { status: res.status, body: await res.json() };
}

/* seed a subscription owned by a given key */
async function seed(env, subId, ownerKey, extra = {}) {
  const st = await import("./src/store.js");
  await st.putSubscription(env, subId, {
    ownerKey, active: true, status: "Subscribed", planId: "pro", ...extra
  });
}

/* Seed the way the landing page really does it: derive the owner key from the
   buyer's own claims. This keeps the test sensitive to a mis-keying bug
   instead of hard coding the expected answer. */
async function seedAsBuyer(env, subId, buyerClaims, extra = {}) {
  const st = await import("./src/store.js");
  const acct = classifyAccount(buyerClaims);
  assert(acct, "buyer claims must classify");
  await st.putSubscription(env, subId, {
    ownerKey: acct.key, accountKind: acct.kind, seatModel: acct.seatModel,
    active: true, status: "Subscribed", planId: "pro", ...extra
  });
  return acct;
}

await check("work account entitled via tenant", async () => {
  const env = makeEnv();
  await seed(env, "sub-w", "tenant:tid-abc", { seatModel: "tenant" });
  const r = await entitlement(env, { tid: "tid-abc", oid: "any-user" });
  assert.equal(r.body.entitled, true);
  assert.equal(r.body.accountKind, "work");
});

await check("colleague in same tenant also entitled", async () => {
  const env = makeEnv();
  await seed(env, "sub-w", "tenant:tid-abc");
  const r = await entitlement(env, { tid: "tid-abc", oid: "a-different-colleague" });
  assert.equal(r.body.entitled, true, "org purchase should cover the whole tenant");
});

await check("different tenant NOT entitled", async () => {
  const env = makeEnv();
  await seed(env, "sub-w", "tenant:tid-abc");
  const r = await entitlement(env, { tid: "some-other-tenant", oid: "o2" });
  assert.equal(r.body.entitled, false);
});

await check("personal buyer entitled", async () => {
  const env = makeEnv();
  await seed(env, "sub-p", "user:msa-buyer", { seatModel: "user" });
  const r = await entitlement(env, {
    tid: MSA_TENANT, oid: "msa-buyer", preferred_username: "buyer@outlook.com"
  });
  assert.equal(r.body.entitled, true);
  assert.equal(r.body.accountKind, "personal");
  assert.equal(r.body.seatModel, "user");
});

await check("CRITICAL: other personal account NOT entitled", async () => {
  const env = makeEnv();
  /* the buyer subscribes through the real classification path */
  await seedAsBuyer(env, "sub-p", {
    tid: MSA_TENANT, oid: "msa-buyer", preferred_username: "buyer@outlook.com"
  });
  /* an unrelated consumer account asks for entitlement */
  const r = await entitlement(env, {
    tid: MSA_TENANT, oid: "msa-freeloader", preferred_username: "other@outlook.com"
  });
  assert.equal(r.body.entitled, false,
    "one personal purchase must never license another consumer account");
  assert.equal(r.body.reason, "no_subscription");
});

await check("CRITICAL: the real buyer stays entitled", async () => {
  const env = makeEnv();
  const buyer = { tid: MSA_TENANT, oid: "msa-buyer", preferred_username: "buyer@outlook.com" };
  await seedAsBuyer(env, "sub-p", buyer);
  const r = await entitlement(env, buyer);
  assert.equal(r.body.entitled, true, "the actual buyer must remain entitled");
});

await check("personal purchase does not leak to work accounts", async () => {
  const env = makeEnv();
  await seed(env, "sub-p", "user:msa-buyer");
  const r = await entitlement(env, { tid: "tid-abc", oid: "o1" });
  assert.equal(r.body.entitled, false);
});

await check("suspended subscription reports not entitled", async () => {
  const env = makeEnv();
  await seed(env, "sub-s", "tenant:tid-abc", { active: false, status: "Suspended" });
  const r = await entitlement(env, { tid: "tid-abc", oid: "o1" });
  assert.equal(r.body.entitled, false);
  assert.equal(r.body.reason, "suspended");
});

await check("no token returns 401", async () => {
  const res = await worker.fetch(new Request("https://w.test/api/entitlement"), makeEnv(), ctx);
  assert.equal(res.status, 401);
});

await check("entitlement token with wrong audience rejected", async () => {
  const env = makeEnv();
  const token = await mint(base({ aud: "not-the-addin" }));
  const res = await worker.fetch(new Request("https://w.test/api/entitlement", {
    headers: { authorization: `Bearer ${token}` }
  }), env, ctx);
  assert.equal(res.status, 401);
});

console.log("\nRouting");

await check("health endpoint responds", async () => {
  const res = await worker.fetch(new Request("https://w.test/"), makeEnv(), ctx);
  assert.equal(res.status, 200);
  assert.equal((await res.json()).status, "ok");
});

await check("unknown route returns 404", async () => {
  const res = await worker.fetch(new Request("https://w.test/nope"), makeEnv(), ctx);
  assert.equal(res.status, 404);
});

await check("CORS preflight answered", async () => {
  const res = await worker.fetch(new Request("https://w.test/api/entitlement", {
    method: "OPTIONS", headers: { origin: "https://site.test" }
  }), makeEnv(), ctx);
  assert.equal(res.status, 204);
  assert.equal(res.headers.get("access-control-allow-origin"), "https://site.test");
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail ? 1 : 0);
