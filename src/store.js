/* Durable record of every subscription and every webhook event.
 *
 * Webhook delivery is at least once, so every write is keyed by something
 * stable and every handler is safe to run twice.
 *
 * Two lookup shapes exist:
 *   sub:<subscriptionId>   the record itself
 *   tenant:<tid>           work account index, one per organisation
 *   user:<oid>             personal account index, one per individual
 *
 * The owner key is computed by classifyAccount() so a personal subscription
 * can never be found by tenant, which all consumer accounts share.
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

  /* Secondary index. ownerKey is already namespaced as tenant:… or user:… */
  if (merged.ownerKey) {
    await env.SUBSCRIPTIONS.put(merged.ownerKey, id);
  }
  return merged;
}

/** Look up the subscription belonging to an owner key. */
export async function subscriptionForOwner(env, ownerKey) {
  if (!ownerKey) return null;
  const id = await env.SUBSCRIPTIONS.get(ownerKey);
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
