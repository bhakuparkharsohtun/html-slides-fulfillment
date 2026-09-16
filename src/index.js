/* HTML Slides for PowerPoint - marketplace fulfillment worker.
 *
 * Routes
 *   GET  /                    health
 *   GET  /landing?token=...   marketplace redirect target
 *   GET  /auth/callback       Entra sign in response
 *   POST /webhook             marketplace connection webhook
 *   GET  /api/entitlement     called by the add-in to check access
 */

import { handleWebhook } from "./webhook.js";
import { handleLanding, handleAuthCallback } from "./landing.js";
import { verifyJwt, bearerFrom, classifyAccount } from "./jwt.js";
import * as store from "./store.js";

const JSON_HEADERS = { "content-type": "application/json" };

function json(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...JSON_HEADERS, ...extra }
  });
}

/* The add-in calls this from a browser context, so it needs CORS. */
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
 * Entitlement check for the add-in.
 *
 * A work account is entitled through its tenant, so one purchase covers the
 * organisation. A personal account is entitled through its own object id, so
 * one purchase covers one person. Using the tenant for a personal account
 * would entitle every consumer account in existence, since they all share a
 * single tenant id.
 */
async function handleEntitlement(request, env) {
  const cors = corsHeaders(env, request);

  const token = bearerFrom(request);
  if (!token) return json({ error: "missing token" }, 401, cors);

  let claims;
  try {
    claims = await verifyJwt(token, {
      audiences: [env.ADDIN_CLIENT_ID, `api://${env.ADDIN_CLIENT_ID}`],
      issuers: ["https://login.microsoftonline.com/", "https://sts.windows.net/"],
      jwksUri: "https://login.microsoftonline.com/common/discovery/v2.0/keys"
    });
  } catch (e) {
    return json({ error: "invalid token", detail: e.message }, 401, cors);
  }

  const account = classifyAccount(claims);
  if (!account) {
    return json({
      entitled: false,
      reason: "account_not_identified"
    }, 200, cors);
  }

  const sub = await store.subscriptionForOwner(env, account.key);
  if (!sub) {
    return json({
      entitled: false,
      reason: "no_subscription",
      accountKind: account.kind
    }, 200, cors);
  }

  return json({
    entitled: Boolean(sub.active),
    reason: sub.active ? "active" : String(sub.status || "inactive").toLowerCase(),
    accountKind: account.kind,
    seatModel: account.seatModel,
    planId: sub.planId || null,
    quantity: sub.quantity ?? null
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

        default:
          return json({ error: "not found" }, 404);
      }
    } catch (err) {
      console.error("unhandled", err && err.stack ? err.stack : err);
      return json({ error: "internal error" }, 500);
    }
  }
};
