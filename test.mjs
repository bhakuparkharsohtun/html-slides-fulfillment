/* Worker tests.
 *
 * Generates a real RSA key, mints real tokens, and drives the handlers
 * against a mocked marketplace and an in memory KV.
 *
 * The assertions describe the CURRENT model:
 *   one seat per person, keyed user:<tid>:<oid>
 *   a self serve trial, seven days, no card, hard stop
 *   marketplace purchases limited to work and school accounts
 */

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
const { startTrial, getTrial, trialEntitlement, TRIAL_DAYS } =
  await import("./src/selftrial.js");
const { readTerm, billingFacts, daysLeft } = await import("./src/trial.js");

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

globalThis.fetch = async (url, init = {}) => {
  const u = String(url);

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

/* ============================================================ */
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

/* ============================================================ */
console.log("\nAccount classification: one seat per person");

await check("work account keyed per person, not per tenant", () => {
  const a = classifyAccount({ tid: "tid-abc", oid: "o1", preferred_username: "a@contoso.com" });
  assert.equal(a.kind, "work");
  assert.equal(a.key, "user:tid-abc:o1");
  assert.equal(a.seatModel, "user");
});

await check("personal account uses the same shape", () => {
  const a = classifyAccount({ tid: MSA_TENANT, oid: "msa-1" });
  assert.equal(a.kind, "personal");
  assert.equal(a.key, `user:${MSA_TENANT}:msa-1`);
});

await check("CRITICAL: a personal account has no tenant key", () => {
  assert.equal(classifyAccount({ tid: MSA_TENANT, oid: "msa-1" }).tenantKey, null,
    "the shared consumer tenant must never become a licence key");
});

await check("a work account does have one, for the multi seat case", () => {
  assert.equal(classifyAccount({ tid: "tid-abc", oid: "o1" }).tenantKey, "tenant:tid-abc");
});

await check("CRITICAL: only work accounts can buy from Microsoft", () => {
  assert.equal(classifyAccount({ tid: "tid-abc", oid: "o1" }).canBuyFromMicrosoft, true);
  assert.equal(classifyAccount({ tid: MSA_TENANT, oid: "m1" }).canBuyFromMicrosoft, false);
});

await check("the key never contains an email", () => {
  const k = classifyAccount({ tid: "t1", oid: "o1", preferred_username: "bk@chillibreeze.com" }).key;
  assert(!k.includes("@") && !k.includes("chillibreeze"));
});

await check("CRITICAL: a rename does not change the key", () => {
  const before = classifyAccount({ tid: "t1", oid: "o1", preferred_username: "old@a.com" }).key;
  const after  = classifyAccount({ tid: "t1", oid: "o1", preferred_username: "new@b.com" }).key;
  assert.equal(before, after, "email is mutable and must not be an identifier");
});

await check("two personal accounts get different keys", () => {
  const a = classifyAccount({ tid: MSA_TENANT, oid: "msa-aaa" });
  const b = classifyAccount({ tid: MSA_TENANT, oid: "msa-bbb" });
  assert.notEqual(a.key, b.key);
});

await check("live.com idp treated as personal", () => {
  const a = classifyAccount({ tid: "some-tid", idp: "live.com", oid: "o9" });
  assert.equal(a.kind, "personal");
  assert.equal(a.tenantKey, null);
});

await check("no oid means no account", () => {
  assert.equal(classifyAccount({ tid: "t1" }), null);
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
const store = await import("./src/store.js");
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

/* ============================================================ */
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
    action: "Subscribe", subscriptionId: "sub-1", id: "op-1", planId: "pro", quantity: 1
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

/* ---------- entitlement harness ---------- */

async function entitlement(env, claims) {
  const token = await mint({ ...base(), aud: "addin-app", ...claims });
  const res = await worker.fetch(new Request("https://w.test/api/entitlement", {
    headers: { authorization: `Bearer ${token}`, origin: "https://site.test" }
  }), env, ctx);
  return { status: res.status, body: await res.json() };
}

async function trialStart(env, claims) {
  const token = await mint({ ...base(), aud: "addin-app", ...claims });
  const res = await worker.fetch(new Request("https://w.test/api/trial/start", {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, origin: "https://site.test" }
  }), env, ctx);
  return { status: res.status, body: await res.json() };
}

/* Buy a seat the way landing.js does, deriving keys from real claims so
   the test stays sensitive to a mis-keying bug. */
async function buySeat(env, subId, claims, extra = {}) {
  const acct = classifyAccount(claims);
  assert(acct, "claims must classify");
  await store.putSubscription(env, subId, {
    ownerKey: acct.key,
    tenantKey: acct.tenantKey,
    accountKind: acct.kind,
    seatModel: acct.seatModel,
    planId: "pro", quantity: 1,
    active: true, status: "Subscribed",
    ...extra
  });
  return acct;
}

const WORK_A = { tid: "tid-abc", oid: "oid-a", preferred_username: "a@contoso.com" };
const WORK_B = { tid: "tid-abc", oid: "oid-b", preferred_username: "b@contoso.com" };
const MSA_A  = { tid: MSA_TENANT, oid: "msa-a", preferred_username: "a@outlook.com" };
const MSA_B  = { tid: MSA_TENANT, oid: "msa-b", preferred_username: "b@outlook.com" };

/* ============================================================ */
console.log("\nEntitlement: a licence covers one person");

await check("the buyer is entitled", async () => {
  const env = makeEnv();
  await buySeat(env, "sub-a", WORK_A);
  const r = await entitlement(env, WORK_A);
  assert.equal(r.body.entitled, true);
  assert.equal(r.body.seatModel, "user");
});

await check("CRITICAL: a colleague is NOT covered", async () => {
  const env = makeEnv();
  await buySeat(env, "sub-a", WORK_A);
  const r = await entitlement(env, WORK_B);
  assert.equal(r.body.entitled, false,
    "selling one seat at a time means exactly that");
});

await check("CRITICAL: a single seat writes no tenant index", async () => {
  const env = makeEnv();
  await buySeat(env, "sub-a", WORK_A);
  assert.equal(env.SUBSCRIPTIONS._m.has("tenant:tid-abc"), false,
    "an organisation index would license the whole company");
});

await check("CRITICAL: consumers never share a licence", async () => {
  const env = makeEnv();
  await buySeat(env, "sub-p", MSA_A);
  assert.equal((await entitlement(env, MSA_A)).body.entitled, true);
  assert.equal((await entitlement(env, MSA_B)).body.entitled, false,
    "one purchase must not license every consumer alive");
});

await check("a planted consumer tenant licence cannot be picked up", async () => {
  const env = makeEnv();
  await env.SUBSCRIPTIONS.put(`tenant:${MSA_TENANT}`, "sub-evil");
  await env.SUBSCRIPTIONS.put("sub:sub-evil",
    JSON.stringify({ subscriptionId: "sub-evil", active: true }));
  const r = await entitlement(env, MSA_B);
  assert.equal(r.body.entitled, false, "a null tenant key makes this impossible");
});

await check("a different tenant is not covered", async () => {
  const env = makeEnv();
  await buySeat(env, "sub-a", WORK_A);
  const r = await entitlement(env, { tid: "other-tenant", oid: "oid-a" });
  assert.equal(r.body.entitled, false);
});

await check("suspended reports not entitled", async () => {
  const env = makeEnv();
  await buySeat(env, "sub-a", WORK_A, { active: false, status: "Suspended" });
  const r = await entitlement(env, WORK_A);
  assert.equal(r.body.entitled, false);
  assert.equal(r.body.reason, "suspended");
});

await check("canBuyFromMicrosoft is reported to the add-in", async () => {
  const env = makeEnv();
  assert.equal((await entitlement(env, WORK_A)).body.canBuyFromMicrosoft, true);
  assert.equal((await entitlement(env, MSA_A)).body.canBuyFromMicrosoft, false);
});

console.log("\nEntitlement: multi seat, if one ever arrives");

await check("quantity above one indexes the organisation", async () => {
  const env = makeEnv();
  await buySeat(env, "sub-org", WORK_A, { quantity: 25 });
  assert.equal(env.SUBSCRIPTIONS._m.get("tenant:tid-abc"), "sub-org");
});

await check("CRITICAL: colleagues are covered by a multi seat purchase", async () => {
  const env = makeEnv();
  await buySeat(env, "sub-org", WORK_A, { quantity: 25 });
  const r = await entitlement(env, WORK_B);
  assert.equal(r.body.entitled, true,
    "refusing would mean they paid for something that does not work");
});

await check("a personal multi seat purchase still covers only the buyer", async () => {
  const env = makeEnv();
  await buySeat(env, "sub-p", MSA_A, { quantity: 5 });
  assert.equal((await entitlement(env, MSA_B)).body.entitled, false);
});

/* ============================================================ */
console.log("\nSelf serve trial");

await check("offered when there is no subscription", async () => {
  const env = makeEnv();
  const r = await entitlement(env, WORK_A);
  assert.equal(r.body.entitled, false);
  assert.equal(r.body.reason, "no_subscription");
  assert.equal(r.body.trialAvailable, true);
  assert.equal(r.body.trialDays, TRIAL_DAYS);
});

await check("starting one entitles for " + TRIAL_DAYS + " days", async () => {
  const env = makeEnv();
  const s = await trialStart(env, WORK_A);
  assert.equal(s.body.started, true);
  const r = await entitlement(env, WORK_A);
  assert.equal(r.body.entitled, true);
  assert.equal(r.body.billingStatus, "self_trial");
  assert.equal(r.body.trialDaysLeft, TRIAL_DAYS);
});

await check("CRITICAL: a personal account may still trial", async () => {
  const env = makeEnv();
  const s = await trialStart(env, MSA_A);
  assert.equal(s.body.started, true,
    "the trial is ours, so the marketplace purchase limit does not apply");
  assert.equal((await entitlement(env, MSA_A)).body.entitled, true);
});

await check("CRITICAL: a second trial is refused", async () => {
  const env = makeEnv();
  await trialStart(env, WORK_A);
  const again = await trialStart(env, WORK_A);
  assert.equal(again.status, 409);
  assert.equal(again.body.reason, "already_used");
});

await check("CRITICAL: an elapsed trial cannot be restarted", async () => {
  const env = makeEnv();
  await trialStart(env, WORK_A);
  /* age the record past its end */
  const key = classifyAccount(WORK_A).key;
  const t = await env.SUBSCRIPTIONS.get(`trial:${key}`, "json");
  t.endsAt = new Date(Date.now() - 86400000).toISOString();
  await env.SUBSCRIPTIONS.put(`trial:${key}`, JSON.stringify(t));

  const again = await trialStart(env, WORK_A);
  assert.equal(again.body.started, false, "used is used, forever");
});

await check("CRITICAL: an elapsed trial LOCKS the product", async () => {
  const env = makeEnv();
  await trialStart(env, WORK_A);
  const key = classifyAccount(WORK_A).key;
  const t = await env.SUBSCRIPTIONS.get(`trial:${key}`, "json");
  t.endsAt = new Date(Date.now() - 86400000).toISOString();
  await env.SUBSCRIPTIONS.put(`trial:${key}`, JSON.stringify(t));

  const r = await entitlement(env, WORK_A);
  assert.equal(r.body.entitled, false, "this trial stops, it does not convert");
  assert.equal(r.body.reason, "trial_expired");
  assert.equal(r.body.trialAvailable, false);
});

await check("a colleague's trial does not block mine", async () => {
  const env = makeEnv();
  await trialStart(env, WORK_A);
  const mine = await trialStart(env, WORK_B);
  assert.equal(mine.body.started, true,
    "one curious colleague must not spend the whole company's trial");
});

await check("consumers each get their own", async () => {
  const env = makeEnv();
  assert.equal((await trialStart(env, MSA_A)).body.started, true);
  assert.equal((await trialStart(env, MSA_B)).body.started, true);
});

await check("CRITICAL: a subscription beats an elapsed trial", async () => {
  const env = makeEnv();
  await trialStart(env, WORK_A);
  const key = classifyAccount(WORK_A).key;
  const t = await env.SUBSCRIPTIONS.get(`trial:${key}`, "json");
  t.endsAt = new Date(Date.now() - 86400000).toISOString();
  await env.SUBSCRIPTIONS.put(`trial:${key}`, JSON.stringify(t));

  await buySeat(env, "sub-a", WORK_A);
  const r = await entitlement(env, WORK_A);
  assert.equal(r.body.entitled, true,
    "a paying customer must never see a trial expiry wall");
});

await check("a trial is refused once a subscription exists", async () => {
  const env = makeEnv();
  await buySeat(env, "sub-a", WORK_A);
  const s = await trialStart(env, WORK_A);
  assert.equal(s.status, 409);
  assert.equal(s.body.reason, "has_subscription");
});

await check("GET on the trial endpoint is refused", async () => {
  const env = makeEnv();
  const token = await mint({ ...base(), aud: "addin-app" });
  const res = await worker.fetch(new Request("https://w.test/api/trial/start", {
    headers: { authorization: `Bearer ${token}` }
  }), env, ctx);
  assert.equal(res.status, 405);
});

await check("an unauthenticated trial start is refused", async () => {
  const res = await worker.fetch(new Request("https://w.test/api/trial/start",
    { method: "POST" }), makeEnv(), ctx);
  assert.equal(res.status, 401);
});

/* ============================================================ */
console.log("\nMarketplace trial fields");

await check("readTerm extracts what Microsoft sends", () => {
  const r = readTerm({
    isFreeTrial: true, autoRenew: true,
    term: { termUnit: "P1M", startDate: "2026-09-10", endDate: "2026-10-10" }
  });
  assert.equal(r.isFreeTrial, true);
  assert.equal(r.termEnd, "2026-10-10");
  assert.equal(r.autoRenew, true);
});

await check("absence never implies a trial", () => {
  assert.equal(readTerm({ id: "x" }).isFreeTrial, false);
  assert.equal(readTerm({ isFreeTrial: "true" }).isFreeTrial, false);
  assert.deepEqual(readTerm(null), {});
});

await check("daysLeft never goes negative", () => {
  const past = new Date(Date.now() - 5 * 86400000).toISOString();
  assert.equal(daysLeft(past), 0);
  assert.equal(daysLeft("nonsense"), null);
  assert.equal(daysLeft(null), null);
});

await check("a paid subscription reports paid", () => {
  const f = billingFacts({ isFreeTrial: false, autoRenew: true });
  assert.equal(f.billingStatus, "paid");
  assert.equal(f.trialDaysLeft, null);
});

await check("a marketplace trial reports a countdown", () => {
  const end = new Date(Date.now() + 10 * 86400000).toISOString();
  const f = billingFacts({ isFreeTrial: true, termEnd: end });
  assert.equal(f.billingStatus, "trial");
  assert.equal(f.trialDaysLeft, 10);
});

await check("CRITICAL: an elapsed marketplace trial does not revoke", () => {
  const end = new Date(Date.now() - 86400000).toISOString();
  const f = billingFacts({ isFreeTrial: true, termEnd: end });
  assert.equal(f.billingStatus, "trial_ended");
  assert.equal(f.trialDaysLeft, 0);
  /* entitled is decided by `active`, not by this. The add-in keeps the
     product unlocked because Microsoft converts it to paid. */
});

/* ============================================================ */
console.log("\nRouting and CORS");

await check("health endpoint responds", async () => {
  const res = await worker.fetch(new Request("https://w.test/"), makeEnv(), ctx);
  assert.equal(res.status, 200);
  assert.equal((await res.json()).status, "ok");
});

await check("unknown route returns 404", async () => {
  const res = await worker.fetch(new Request("https://w.test/nope"), makeEnv(), ctx);
  assert.equal(res.status, 404);
});

await check("no token returns 401", async () => {
  const res = await worker.fetch(new Request("https://w.test/api/entitlement"), makeEnv(), ctx);
  assert.equal(res.status, 401);
});

await check("wrong audience rejected on entitlement", async () => {
  const token = await mint(base({ aud: "not-the-addin" }));
  const res = await worker.fetch(new Request("https://w.test/api/entitlement", {
    headers: { authorization: `Bearer ${token}` }
  }), makeEnv(), ctx);
  assert.equal(res.status, 401);
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
