/* Marketplace connection webhook.
 *
 * Contract, per the Microsoft documentation:
 *
 *   Subscribe        200 to acknowledge, no further action
 *   ChangePlan       200, then PATCH Success or Failure within 10 seconds
 *   ChangeQuantity   200, then PATCH Success or Failure within 10 seconds
 *   Renew            200 to acknowledge, notify only
 *   Suspend          200 to acknowledge, notify only
 *   Unsubscribe      200 to acknowledge, notify only
 *   Reinstate        200 to acknowledge, notify only
 *
 * Two rules drive the shape of this file. The payload must be authorised by
 * calling the Get Operation API before any action is taken, and the schema
 * must not be strictly deserialised because Microsoft may extend it.
 */

import { verifyJwt, bearerFrom } from "./jwt.js";
import * as mp from "./marketplace.js";
import * as store from "./store.js";

const ACK_REQUIRED = new Set(["ChangePlan", "ChangeQuantity", "Reinstate"]);
const NOTIFY_ONLY = new Set(["Subscribe", "Renew", "Suspend", "Unsubscribe"]);

/** Validate the Entra token Microsoft sends with the call. */
async function authorise(request, env) {
  const token = bearerFrom(request);
  if (!token) return { ok: false, reason: "missing bearer token" };

  const audiences = [env.WEBHOOK_AUDIENCE, `api://${env.WEBHOOK_AUDIENCE}`]
    .filter(Boolean);

  try {
    const claims = await verifyJwt(token, {
      audiences,
      issuers: ["https://login.microsoftonline.com/", "https://sts.windows.net/"],
      jwksUri: "https://login.microsoftonline.com/common/discovery/v2.0/keys"
    });
    return { ok: true, claims };
  } catch (err) {
    return { ok: false, reason: err.message };
  }
}

/**
 * Confirm the payload against the Operations API.
 *
 * Microsoft requires this call. Note that the list endpoint only returns
 * operations still awaiting acknowledgement, so a notify-only event will
 * legitimately return nothing; that is not treated as a failure.
 */
async function confirm(env, payload) {
  const { subscriptionId, id: operationId } = payload;
  if (!subscriptionId || !operationId) {
    return { verified: false, reason: "payload missing identifiers" };
  }

  const res = await mp.getOperation(env, subscriptionId, operationId);

  if (res.ok && res.body) {
    return { verified: true, operation: res.body };
  }

  /* 404 on a notify-only event is expected once it has been consumed. */
  if (res.status === 404 && NOTIFY_ONLY.has(payload.action)) {
    return { verified: true, operation: null, note: "notify-only, no pending operation" };
  }

  return { verified: false, reason: `get operation returned ${res.status}` };
}

/** Apply the event to our own records. */
async function apply(env, payload) {
  const action = payload.action;
  const id = payload.subscriptionId;

  const base = {
    planId: payload.planId,
    quantity: payload.quantity,
    offerId: payload.offerId,
    lastAction: action,
    lastOperationId: payload.id
  };

  switch (action) {
    case "Subscribe":
      return store.putSubscription(env, id, {
        ...base,
        status: "Subscribed",
        active: true
      });

    case "ChangePlan":
      return store.putSubscription(env, id, {
        ...base,
        planId: payload.planId,
        status: "Subscribed",
        active: true
      });

    case "ChangeQuantity":
      return store.putSubscription(env, id, {
        ...base,
        quantity: payload.quantity,
        status: "Subscribed",
        active: true
      });

    case "Renew":
      return store.putSubscription(env, id, {
        ...base,
        status: "Subscribed",
        active: true,
        renewedAt: new Date().toISOString()
      });

    case "Suspend":
      /* Payment failed. Keep the record, revoke access. */
      return store.putSubscription(env, id, {
        ...base,
        status: "Suspended",
        active: false
      });

    case "Reinstate":
      return store.putSubscription(env, id, {
        ...base,
        status: "Subscribed",
        active: true
      });

    case "Unsubscribe":
      return store.putSubscription(env, id, {
        ...base,
        status: "Unsubscribed",
        active: false,
        unsubscribedAt: new Date().toISOString()
      });

    default:
      /* Unknown action. Record it and leave access untouched. */
      return store.putSubscription(env, id, {
        ...base,
        unknownAction: action
      });
  }
}

/**
 * Everything that happens after the 200 has already gone back to Microsoft.
 * Runs inside ctx.waitUntil so the response is never delayed by it.
 */
async function process(env, payload) {
  const operationId = payload.id;

  const first = await store.claimEvent(env, operationId, {
    action: payload.action,
    subscriptionId: payload.subscriptionId,
    stage: "received"
  });
  if (!first) return;  /* replay of an event already handled */

  const check = await confirm(env, payload);

  if (!check.verified) {
    await store.logEvent(env, operationId, {
      action: payload.action,
      subscriptionId: payload.subscriptionId,
      stage: "rejected",
      reason: check.reason
    });

    if (ACK_REQUIRED.has(payload.action)) {
      await mp.patchOperation(
        env, payload.subscriptionId, operationId, "Failure",
        payload.planId, payload.quantity
      );
    }
    return;
  }

  try {
    await apply(env, payload);

    if (ACK_REQUIRED.has(payload.action)) {
      await mp.patchOperation(
        env, payload.subscriptionId, operationId, "Success",
        payload.planId, payload.quantity
      );
    }

    await store.logEvent(env, operationId, {
      action: payload.action,
      subscriptionId: payload.subscriptionId,
      stage: "applied"
    });
  } catch (err) {
    await store.logEvent(env, operationId, {
      action: payload.action,
      subscriptionId: payload.subscriptionId,
      stage: "error",
      reason: String(err && err.message ? err.message : err)
    });

    if (ACK_REQUIRED.has(payload.action)) {
      await mp.patchOperation(
        env, payload.subscriptionId, operationId, "Failure",
        payload.planId, payload.quantity
      );
    }
  }
}

export async function handleWebhook(request, env, ctx) {
  if (request.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const auth = await authorise(request, env);
  if (!auth.ok) {
    return new Response(
      JSON.stringify({ error: "unauthorized", detail: auth.reason }),
      { status: 401, headers: { "content-type": "application/json" } }
    );
  }

  /* Deliberately loose parsing. Microsoft reserves the right to add fields. */
  let payload;
  try {
    payload = await request.json();
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }

  if (!payload || !payload.action || !payload.subscriptionId) {
    return new Response("Missing action or subscriptionId", { status: 400 });
  }

  /* Acknowledge immediately, then do the work in the background. Microsoft
     retries 500 times over eight hours if we fail to answer, and an
     unanswered operation eventually fails on their side. */
  ctx.waitUntil(process(env, payload));

  return new Response(JSON.stringify({ received: true }), {
    status: 200,
    headers: { "content-type": "application/json" }
  });
}
