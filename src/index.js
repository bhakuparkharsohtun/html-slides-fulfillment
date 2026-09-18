/* HTML Slides for PowerPoint - marketplace fulfillment worker.
 *
 * Routes
 *   GET  /                    health
 *   GET  /landing?token=...   marketplace redirect target
 *   GET  /auth/callback       Entra sign in response
 *   POST /webhook             marketplace connection webhook
 *   GET  /api/entitlement     called by the add-in to check access
 *   POST /api/trial/start     starts the self serve free trial
 */

import { handleWebhook } from "./webhook.js";
import { handleLanding, handleAuthCallback } from "./landing.js";
import { verifyJwt, bearerFrom, classifyAccount } from "./jwt.js";
import { billingFacts } from "./trial.js";
import { getTrial, startTrial, trialEntitlement, TRIAL_DAYS } from "./selftrial.js";
import * as store from "./store.js";

const JSON_HEADERS = { "content-type": "application/json" };

function json(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...JSON_HEADERS, ...extra }
  });
}

/* The add-in calls these from a browser context, so they need CORS. */
function corsHeaders(env, request) {
  const allowed = (env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim());
  const origin = request.headers.get("origin") || "";
  const ok = allowed.includes(origin);
  return {
    "access-control-allow-origin": ok ? origin : allowed[0] || "",
    "access-control-allow-headers": "authorization, content-type",
    "access-control-allow-methods": "GET, POST, OPTIONS",
    "access-control-max-age": "86400",
    vary: "Origin"
  };
}

/**
 * Identify the caller from their bearer token.
 * Shared by the entitlement check and the trial endpoint.
 */
async function identify(request, env) {
  const token = bearerFrom(request);
  if (!token) return { ok: false, status: 401, body: { error: "missing token" } };

  let claims;
  try {
    claims = await verifyJwt(token, {
      audiences: [env.ADDIN_CLIENT_ID, `api://${env.ADDIN_CLIENT_ID}`],
      issuers: ["https://login.microsoftonline.com/", "https://sts.windows.net/"],
      jwksUri: "https://login.microsoftonline.com/common/discovery/v2.0/keys"
    });
  } catch (e) {
    return { ok: false, status: 401, body: { error: "invalid token", detail: e.message } };
  }

  const account = classifyAccount(claims);
  if (!account) {
    return {
      ok: false, status: 200,
      body: { entitled: false, reason: "account_not_identified" }
    };
  }
  return { ok: true, account };
}

/** Fields the add-in needs on every answer, whatever the outcome. */
function accountFacts(account) {
  return {
    accountKind: account.kind,
    seatModel: account.seatModel,
    canBuyFromMicrosoft: account.canBuyFromMicrosoft === true
  };
}

/**
 * Entitlement check for the add-in.
 *
 * Order matters. A marketplace subscription always wins, because a
 * customer who has paid must never be told their trial has elapsed. The
 * self serve trial is only consulted when there is no subscription.
 *
 * Licences are per person, keyed user:<tid>:<oid>. A colleague is not
 * covered by someone else's purchase unless that subscription carried
 * more than one seat, in which case the tenant index is consulted as a
 * fallback. See store.subscriptionForOwner.
 */
async function handleEntitlement(request, env) {
  const cors = corsHeaders(env, request);

  const who = await identify(request, env);
  if (!who.ok) return json(who.body, who.status, cors);
  const account = who.account;

  const sub = await store.subscriptionForOwner(env, account.key, account.tenantKey);

  if (sub) {
    return json({
      entitled: Boolean(sub.active),
      reason: sub.active ? "active" : String(sub.status || "inactive").toLowerCase(),
      ...accountFacts(account),
      planId: sub.planId || null,
      quantity: sub.quantity ?? null,
      trialAvailable: false,
      ...billingFacts(sub)
    }, 200, cors);
  }

  /* No subscription. Fall back to the self serve trial. */
  const trial = await getTrial(env, account.key);
  return json({
    ...accountFacts(account),
    planId: null,
    quantity: null,
    ...trialEntitlement(trial)
  }, 200, cors);
}

/**
 * Start the self serve trial.
 *
 * Refuses if this person already has a subscription, because starting a
 * trial would be meaningless, and refuses a second trial at any time.
 */
async function handleTrialStart(request, env) {
  const cors = corsHeaders(env, request);

  if (request.method !== "POST") {
    return json({ error: "method not allowed" }, 405, cors);
  }

  const who = await identify(request, env);
  if (!who.ok) return json(who.body, who.status, cors);
  const account = who.account;

  const sub = await store.subscriptionForOwner(env, account.key, account.tenantKey);
  if (sub) {
    return json({ started: false, reason: "has_subscription" }, 409, cors);
  }

  const res = await startTrial(env, account);

  if (!res.ok) {
    return json({
      started: false,
      reason: res.reason,
      trialEndsOn: res.trial ? res.trial.endsAt : null
    }, res.reason === "already_used" ? 409 : 400, cors);
  }

  return json({
    started: true,
    trialDays: TRIAL_DAYS,
    trialEndsOn: res.trial.endsAt
  }, 200, cors);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env, request) });
    }

    try {
      switch (path) {
        case "/":
          return json({ service: "html-slides-fulfillment", status: "ok" });

        case "/landing":
          return handleLanding(request, env);

        case "/auth/callback":
          return handleAuthCallback(request, env);

        case "/webhook":
          return handleWebhook(request, env, ctx);

        case "/api/entitlement":
          return handleEntitlement(request, env);

        case "/api/trial/start":
          return handleTrialStart(request, env);

        default:
          return json({ error: "not found" }, 404);
      }
    } catch (err) {
      console.error("unhandled", err && err.stack ? err.stack : err);
      return json({ error: "internal error" }, 500);
    }
  }
};
