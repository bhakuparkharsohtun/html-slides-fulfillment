/* Client for the SaaS fulfillment APIs, version 2018-08-31.
 *
 * All calls are authorised with a publisher token obtained through client
 * credentials against the PUBLISHER tenant, never the customer tenant.
 */

const API_ROOT = "https://marketplaceapi.microsoft.com/api/saas";
export const API_VERSION = "2018-08-31";

/* Fixed resource identifier for the marketplace fulfillment API. */
const RESOURCE = "20e940b3-4c77-4b0b-9a53-9e16a1b010a7";

let tokenCache = { value: null, expiresAt: 0 };

function uuid() {
  return crypto.randomUUID();
}

/** Acquire, and briefly cache, the publisher access token. */
export async function getPublisherToken(env) {
  if (tokenCache.value && Date.now() < tokenCache.expiresAt - 60_000) {
    return tokenCache.value;
  }

  const url = `https://login.microsoftonline.com/${env.PUBLISHER_TENANT_ID}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    grant_type: "client_credentials",
    client_id: env.PUBLISHER_CLIENT_ID,
    client_secret: env.PUBLISHER_CLIENT_SECRET,
    scope: `${RESOURCE}/.default`
  });

  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body
  });

  if (!res.ok) {
    throw new Error(`token request failed ${res.status}: ${await res.text()}`);
  }

  const json = await res.json();
  tokenCache = {
    value: json.access_token,
    expiresAt: Date.now() + (json.expires_in || 3600) * 1000
  };
  return tokenCache.value;
}

async function call(env, method, path, { body, correlationId } = {}) {
  const token = await getPublisherToken(env);
  const sep = path.includes("?") ? "&" : "?";
  const url = `${API_ROOT}${path}${sep}api-version=${API_VERSION}`;

  const res = await fetch(url, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
      "x-ms-requestid": uuid(),
      "x-ms-correlationid": correlationId || uuid()
    },
    body: body ? JSON.stringify(body) : undefined
  });

  const text = await res.text();
  let parsed = null;
  try { parsed = text ? JSON.parse(text) : null; } catch { parsed = text; }

  return { ok: res.ok, status: res.status, body: parsed };
}

/* ---------------- subscription APIs ---------------- */

/**
 * Exchange a landing page token for the durable subscription record.
 * The marketplace token travels in its own header, so this does not use call().
 */
export async function resolve(env, marketplaceToken, correlationId) {
  const token = await getPublisherToken(env);
  const res = await fetch(
    `${API_ROOT}/subscriptions/resolve?api-version=${API_VERSION}`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
        "x-ms-requestid": uuid(),
        "x-ms-correlationid": correlationId || uuid(),
        "x-ms-marketplace-token": marketplaceToken
      }
    }
  );
  const body = await res.json().catch(() => null);
  return { ok: res.ok, status: res.status, body };
}

/** Confirm that the account has been provisioned. Starts billing. */
export function activate(env, subscriptionId, planId, quantity, correlationId) {
  const payload = { planId };
  if (quantity != null) payload.quantity = quantity;
  return call(env, "POST", `/subscriptions/${subscriptionId}/activate`, {
    body: payload,
    correlationId
  });
}

export function getSubscription(env, subscriptionId, correlationId) {
  return call(env, "GET", `/subscriptions/${subscriptionId}`, { correlationId });
}

export function deleteSubscription(env, subscriptionId, correlationId) {
  return call(env, "DELETE", `/subscriptions/${subscriptionId}`, { correlationId });
}

/* ---------------- operations APIs ---------------- */

/**
 * Read a single operation. Microsoft requires this call to authorise a
 * webhook payload before any action is taken on it.
 */
export function getOperation(env, subscriptionId, operationId, correlationId) {
  return call(
    env, "GET",
    `/subscriptions/${subscriptionId}/operations/${operationId}`,
    { correlationId }
  );
}

export function listOperations(env, subscriptionId, correlationId) {
  return call(env, "GET", `/subscriptions/${subscriptionId}/operations`, {
    correlationId
  });
}

/**
 * Acknowledge an operation. Only ChangePlan, ChangeQuantity and Reinstate
 * expect this; the remaining events are notify only.
 *
 * @param {"Success"|"Failure"} status
 */
export function patchOperation(env, subscriptionId, operationId, status, planId, quantity, correlationId) {
  const body = { status };
  if (planId) body.planId = planId;
  if (quantity != null) body.quantity = quantity;

  return call(
    env, "PATCH",
    `/subscriptions/${subscriptionId}/operations/${operationId}`,
    { body, correlationId }
  );
}
