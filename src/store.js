/* Durable record of every subscription and every webhook event.
 *
 * Webhook delivery is at least once, so every write is keyed by something
 * stable and every handler is safe to run twice.
 *
 * KEYS
 * ----
 *   sub:<subscriptionId>      the record itself
 *   user:<tid>:<oid>          the licence index, one seat, one person
 *   tenant:<tid>              only written when a subscription arrives
 *                             carrying more than one seat
 *   trial:<userKey>           the self serve trial, see selftrial.js
 *   evt:<operationId>         webhook de-duplication
 *
 * The product is sold one seat at a time, so the per person index is the
 * normal case. The tenant index exists because refusing to honour a multi
 * seat subscription would mean a customer had paid for something that does
 * not work, and a support case we could not answer. It costs a few lines
 * to accept one gracefully.
 */

const SUB = (id) => `sub:${id}`;
const EVT = (id) => `evt:${id}`;

export async function getSubscription(env, id) {
  return env.SUBSCRIPTIONS.get(SUB(id), "json");
}

export async function putSubscription(env, id, patch) {
  const existing = (await getSubscription(env, id)) || {};
  const merged = {
    ...existing,
    ...patch,
    subscriptionId: id,
    updatedAt: new Date().toISOString()
  };
  if (!merged.createdAt) merged.createdAt = merged.updatedAt;

  await env.SUBSCRIPTIONS.put(SUB(id), JSON.stringify(merged));

  /* The seat. ownerKey is already namespaced as user:<tid>:<oid> */
  if (merged.ownerKey) {
    await env.SUBSCRIPTIONS.put(merged.ownerKey, id);
  }

  /* More seats than the one we sell. Index the organisation as well, so
     everyone the customer paid for is actually covered. */
  const qty = Number(merged.quantity);
  if (merged.tenantKey && Number.isFinite(qty) && qty > 1) {
    await env.SUBSCRIPTIONS.put(merged.tenantKey, id);
  }

  return merged;
}

/**
 * Find the subscription covering this person.
 *
 * Their own seat wins. An organisation wide licence is consulted only as
 * a fallback, and only exists when a multi seat subscription was bought.
 * A personal account has no tenant key, so it can never pick up a licence
 * belonging to the shared consumer tenant.
 */
export async function subscriptionForOwner(env, ownerKey, tenantKey) {
  let id = ownerKey ? await env.SUBSCRIPTIONS.get(ownerKey) : null;
  if (!id && tenantKey) id = await env.SUBSCRIPTIONS.get(tenantKey);
  return id ? getSubscription(env, id) : null;
}

/**
 * Record an event exactly once.
 * Returns false when this operation has already been handled.
 */
export async function claimEvent(env, operationId, detail) {
  if (!operationId) return true;
  const key = EVT(operationId);
  const seen = await env.SUBSCRIPTIONS.get(key);
  if (seen) return false;

  await env.SUBSCRIPTIONS.put(
    key,
    JSON.stringify({ at: new Date().toISOString(), ...detail }),
    { expirationTtl: 60 * 60 * 24 * 30 }
  );
  return true;
}

export async function logEvent(env, operationId, detail) {
  if (!operationId) return;
  await env.SUBSCRIPTIONS.put(
    EVT(operationId),
    JSON.stringify({ at: new Date().toISOString(), ...detail }),
    { expirationTtl: 60 * 60 * 24 * 30 }
  );
}
