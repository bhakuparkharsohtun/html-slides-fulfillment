/* Microsoft Entra token validation.
 *
 * Microsoft requires the webhook endpoint to validate the bearer token that
 * arrives in the Authorization header before acting on any payload. This
 * module verifies the RS256 signature against the published JWKS, then checks
 * the standard claims.
 */

const JWKS_TTL_MS = 60 * 60 * 1000;
let jwksCache = { at: 0, keys: null, url: null };

/* The tenant that issues tokens for personal Microsoft accounts. Every
   consumer account in the world reports this same tid, so it can never be
   used on its own to identify an individual customer. */
export const MSA_TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad";

function b64urlToBytes(s) {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlToJson(s) {
  return JSON.parse(new TextDecoder().decode(b64urlToBytes(s)));
}

async function loadJwks(jwksUri) {
  const fresh = jwksCache.keys
    && jwksCache.url === jwksUri
    && Date.now() - jwksCache.at < JWKS_TTL_MS;
  if (fresh) return jwksCache.keys;

  const res = await fetch(jwksUri, { cf: { cacheTtl: 3600 } });
  if (!res.ok) throw new Error("JWKS fetch failed: " + res.status);
  const body = await res.json();

  jwksCache = { at: Date.now(), keys: body.keys || [], url: jwksUri };
  return jwksCache.keys;
}

async function importKey(jwk) {
  return crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

/**
 * Verify a JWT and return its payload.
 *
 * @param {string} token       raw bearer token
 * @param {object} opts
 * @param {string[]} opts.audiences  accepted aud values
 * @param {string[]} opts.issuers    accepted iss values, prefix match allowed
 * @param {string} opts.jwksUri      JWKS endpoint
 * @param {number} opts.skewSec      clock skew tolerance
 */
export async function verifyJwt(token, opts) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) throw new Error("malformed token");

  const [rawHeader, rawPayload, rawSig] = parts;
  const header = b64urlToJson(rawHeader);
  const payload = b64urlToJson(rawPayload);

  if (header.alg !== "RS256") throw new Error("unexpected alg: " + header.alg);

  const keys = await loadJwks(opts.jwksUri);
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error("signing key not found for kid " + header.kid);

  const key = await importKey(jwk);
  const signed = new TextEncoder().encode(rawHeader + "." + rawPayload);
  const ok = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5", key, b64urlToBytes(rawSig), signed
  );
  if (!ok) throw new Error("signature check failed");

  const skew = opts.skewSec ?? 300;
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && now > payload.exp + skew) throw new Error("token expired");
  if (payload.nbf && now < payload.nbf - skew) throw new Error("token not yet valid");

  const auds = opts.audiences || [];
  if (auds.length && !auds.includes(payload.aud)) {
    throw new Error("unexpected audience: " + payload.aud);
  }

  const issuers = opts.issuers || [];
  if (issuers.length) {
    const hit = issuers.some((i) => payload.iss === i || payload.iss.startsWith(i));
    if (!hit) throw new Error("unexpected issuer: " + payload.iss);
  }

  return payload;
}

/** Pull the bearer token out of an Authorization header. */
export function bearerFrom(request) {
  const raw = request.headers.get("authorization") || "";
  const m = /^Bearer\s+(.+)$/i.exec(raw.trim());
  return m ? m[1] : null;
}

/**
 * Identify the caller.
 *
 * THE PRODUCT IS SOLD ONE SEAT AT A TIME
 * --------------------------------------
 * Every licence belongs to a person, not to an organisation. A colleague
 * signing in with their own account has their own subscription, or none.
 * So there is a single key scheme, used for both the trial and the
 * licence:
 *
 *     user:<tid>:<oid>
 *
 * Built only from immutable claims. Microsoft documents email, upn and
 * preferred_username as mutable, and advises indexing multi tenant
 * applications on tid plus oid. An email keyed licence would also be
 * trivially farmed, since anyone can mint a fresh address in a minute.
 *
 * `tenantKey` is returned alongside it, but it is NOT the licence key.
 * It exists only so the worker can honour a multi seat subscription if
 * one ever arrives, rather than silently ignoring something a customer
 * paid for. See store.subscriptionForOwner.
 *
 * `canBuyFromMicrosoft` records a limitation of the marketplace rather
 * than a choice of ours: completing a purchase requires a work or school
 * account. A personal account can run the free trial, but has to be sent
 * elsewhere to buy.
 */
export function classifyAccount(claims) {
  if (!claims) return null;

  const rawTid = claims.tid || null;
  const oid = claims.oid || claims.sub || null;
  const upn = String(claims.upn || claims.preferred_username || claims.email || "");

  if (!oid) return null;           /* cannot identify a person */

  const personal = rawTid === MSA_TENANT
    || claims.idp === "live.com"
    || (claims.idp && String(claims.idp).includes("live.com"));

  const tid = personal ? MSA_TENANT : rawTid;
  if (!tid) return null;

  return {
    kind: personal ? "personal" : "work",
    /* The licence and the trial share this key. One seat, one person. */
    key: `user:${tid}:${oid}`,
    userKey: `user:${tid}:${oid}`,
    /* Never set for a personal account, because every consumer shares
       MSA_TENANT. Null makes that mistake impossible by construction. */
    tenantKey: personal ? null : `tenant:${tid}`,
    canBuyFromMicrosoft: !personal,
    tid,
    oid,
    upn,
    seatModel: "user"
  };
}

/** Convenience wrapper kept for readability at call sites. */
export function isPersonalAccount(claims) {
  const a = classifyAccount(claims);
  return Boolean(a && a.kind === "personal");
}
