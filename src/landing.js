/* Landing page flow.
 *
 * Microsoft redirects the buyer here with a marketplace token. We sign the
 * user in with Entra ID, reject anything that is not a work or school
 * account, resolve the token to a subscription, then activate it.
 *
 * Restricting to work accounts is done in two places. The sign in request
 * uses the "organizations" authority, which excludes personal accounts at the
 * identity provider, and the returned claims are checked again here so a
 * hand-crafted request cannot slip past.
 */

import { verifyJwt, isWorkAccount, MSA_TENANT } from "./jwt.js";
import * as mp from "./marketplace.js";
import * as store from "./store.js";

const AUTHORITY = "https://login.microsoftonline.com/organizations";

function page(title, bodyHtml, status = 200) {
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>
  :root{--ink:#201f1e;--dim:#605e5c;--line:#e1dfdd;--brand:#5b21b6;--bg:#faf9f8}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;
       background:var(--bg);color:var(--ink);
       font-family:'Segoe UI',system-ui,sans-serif}
  .card{width:100%;max-width:520px;background:#fff;border:1px solid var(--line);
        border-radius:10px;padding:32px;box-shadow:0 10px 30px rgba(0,0,0,.06)}
  h1{margin:0 0 6px;font-size:22px;letter-spacing:-.02em}
  p{margin:0 0 14px;line-height:1.55;color:var(--dim);font-size:14px}
  .ok{color:#0b6a0b;font-weight:600}
  .bad{color:#a4262c;font-weight:600}
  dl{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;margin:18px 0 0;
     font-size:13px;border-top:1px solid var(--line);padding-top:16px}
  dt{color:var(--dim)}
  dd{margin:0;font-weight:600}
  a.btn{display:inline-block;margin-top:18px;padding:10px 18px;border-radius:5px;
        background:var(--brand);color:#fff;text-decoration:none;font-size:14px;font-weight:600}
  code{background:var(--bg);padding:1px 5px;border-radius:3px;font-size:12px}
</style>
</head>
<body><main class="card">${bodyHtml}</main></body>
</html>`;
  return new Response(html, {
    status,
    headers: { "content-type": "text/html; charset=utf-8" }
  });
}

function randomState() {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/* ---------------- step 1: receive the redirect ---------------- */

export async function handleLanding(request, env) {
  const url = new URL(request.url);
  const token = url.searchParams.get("token");

  if (!token) {
    return page("Purchase not found", `
      <h1>We could not identify this purchase</h1>
      <p>Open the subscription from the Microsoft 365 admin center or the Azure
         portal and choose <strong>Configure Account</strong> again.</p>`, 400);
  }

  /* Park the marketplace token in a short lived cookie and send the user to
     Entra. The organizations authority keeps personal accounts out. */
  const state = randomState();
  const redirectUri = `${url.origin}/auth/callback`;

  const authUrl = new URL(`${AUTHORITY}/oauth2/v2.0/authorize`);
  authUrl.searchParams.set("client_id", env.LANDING_CLIENT_ID);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_mode", "query");
  authUrl.searchParams.set("scope", "openid profile email User.Read");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("prompt", "select_account");

  const cookie = [
    `mp=${encodeURIComponent(token)}`,
    `st=${state}`
  ].join("|");

  return new Response(null, {
    status: 302,
    headers: {
      location: authUrl.toString(),
      "set-cookie": `hsflow=${encodeURIComponent(cookie)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=900`
    }
  });
}

/* ---------------- step 2: handle the sign in ---------------- */

function readFlowCookie(request) {
  const raw = request.headers.get("cookie") || "";
  const m = /(?:^|;\s*)hsflow=([^;]+)/.exec(raw);
  if (!m) return null;
  const parts = decodeURIComponent(m[1]).split("|");
  const out = {};
  for (const p of parts) {
    const [k, v] = p.split("=");
    out[k] = decodeURIComponent(v || "");
  }
  return out;
}

export async function handleAuthCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const err = url.searchParams.get("error_description");

  if (err) {
    return page("Sign in failed", `
      <h1>Sign in failed</h1><p>${escapeHtml(err)}</p>`, 400);
  }

  const flow = readFlowCookie(request);
  if (!flow || !flow.mp || !code) {
    return page("Session expired", `
      <h1>That link has expired</h1>
      <p>Return to the subscription in the Microsoft 365 admin center and choose
         <strong>Configure Account</strong> again.</p>`, 400);
  }
  if (flow.st !== state) {
    return page("Request rejected", `
      <h1>Request rejected</h1><p>The sign in response did not match the request.</p>`, 400);
  }

  /* Exchange the code for an id token. */
  const redirectUri = `${url.origin}/auth/callback`;
  const tokenRes = await fetch(`${AUTHORITY}/oauth2/v2.0/token`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: env.LANDING_CLIENT_ID,
      client_secret: env.LANDING_CLIENT_SECRET,
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      scope: "openid profile email User.Read"
    })
  });

  if (!tokenRes.ok) {
    return page("Sign in failed", `
      <h1>Sign in failed</h1><p>Could not complete authentication.</p>`, 400);
  }

  const tokens = await tokenRes.json();

  let claims;
  try {
    claims = await verifyJwt(tokens.id_token, {
      audiences: [env.LANDING_CLIENT_ID],
      issuers: ["https://login.microsoftonline.com/"],
      jwksUri: "https://login.microsoftonline.com/common/discovery/v2.0/keys"
    });
  } catch (e) {
    return page("Sign in failed", `
      <h1>Sign in failed</h1><p>${escapeHtml(e.message)}</p>`, 400);
  }

  /* Work account gate. */
  const account = isWorkAccount(claims);
  if (!account) {
    return page("Work account required", `
      <h1 class="bad">A work or school account is required</h1>
      <p>This product is licensed to organisations. The account you signed in
         with is a personal Microsoft account, which cannot be used to complete
         this purchase.</p>
      <p>Sign in again with your work or school account. If you reached this
         page after purchasing, contact support and the subscription will be
         cancelled and refunded.</p>
      <a class="btn" href="/landing?token=${encodeURIComponent(flow.mp)}">Try a different account</a>`,
      403);
  }

  /* Resolve the marketplace token. */
  const resolved = await mp.resolve(env, flow.mp);
  if (!resolved.ok || !resolved.body) {
    return page("Purchase not found", `
      <h1>We could not identify this purchase</h1>
      <p>The purchase token may have expired; it is valid for 24 hours.
         Reopen the subscription and choose <strong>Configure Account</strong> again.</p>`,
      400);
  }

  const sub = resolved.body;
  const subscriptionId = sub.id || sub.subscriptionId;
  const planId = sub.planId;
  const quantity = sub.quantity;

  /* The buyer's tenant must match the tenant that owns the subscription. */
  const beneficiaryTid = sub.beneficiary && sub.beneficiary.tenantId;
  if (beneficiaryTid && beneficiaryTid === MSA_TENANT) {
    return page("Work account required", `
      <h1 class="bad">A work or school account is required</h1>
      <p>This subscription is registered to a personal Microsoft account.
         Contact support to have it cancelled and refunded.</p>`, 403);
  }

  await store.putSubscription(env, subscriptionId, {
    planId,
    quantity,
    offerId: sub.offerId,
    tenantId: account.tid,
    beneficiaryTenantId: beneficiaryTid,
    purchaserEmail: (sub.purchaser && sub.purchaser.emailId) || claims.preferred_username,
    signedInAs: claims.preferred_username,
    status: "Resolved",
    active: false
  });

  /* Activate. Plans configured for auto activation are already active, so a
     conflict here is not an error. */
  const act = await mp.activate(env, subscriptionId, planId, quantity);
  const activated = act.ok || act.status === 409;

  if (!activated) {
    return page("Activation failed", `
      <h1 class="bad">We could not activate your subscription</h1>
      <p>Reference <code>${escapeHtml(subscriptionId)}</code>. Please contact
         support and quote that reference.</p>`, 500);
  }

  await store.putSubscription(env, subscriptionId, {
    status: "Subscribed",
    active: true,
    activatedAt: new Date().toISOString()
  });

  return page("You are all set", `
    <h1 class="ok">Your subscription is active</h1>
    <p>Thanks, ${escapeHtml(claims.name || account.upn)}. The add-in is ready to
       use in PowerPoint for everyone in your organisation.</p>
    <dl>
      <dt>Plan</dt><dd>${escapeHtml(planId || "-")}</dd>
      <dt>Licences</dt><dd>${quantity == null ? "-" : escapeHtml(String(quantity))}</dd>
      <dt>Organisation</dt><dd>${escapeHtml(account.tid)}</dd>
      <dt>Reference</dt><dd><code>${escapeHtml(subscriptionId)}</code></dd>
    </dl>
    <a class="btn" href="${escapeHtml(env.PRODUCT_URL || "/")}">Open the documentation</a>`);
}

function escapeHtml(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
