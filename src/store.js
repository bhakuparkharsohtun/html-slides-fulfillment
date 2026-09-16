/* Durable record of every subscription and every webhook event.
 *
 * Webhook delivery is at least once, so every write is keyed by something
 * stable and every handler is safe to run twice.
 */

const SUB = (id) => `sub:${id}`;
const EVT = (id) => `evt:${id}`;
const TENANT = (tid) => `tenant:${tid}`;

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

  /* Secondary index so the add-in can look a customer up by tenant. */
  if (merged.tenantId) {
    await env.SUBSCRIPTIONS.put(TENANT(merged.tenantId), id);
  }
  return merged;
}

export async function subscriptionForTenant(env, tenantId) {
  const id = await env.SUBSCRIPTIONS.get(TENANT(tenantId));
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
