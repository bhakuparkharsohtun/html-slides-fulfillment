/* Self serve free trial.
 *
 * Seven days, no card, hard stop. One per person, forever.
 *
 * WHY THIS EXISTS
 * ---------------
 * A marketplace plan level trial requires a payment method before it can
 * start, and converts to paid automatically when it ends. That asks for a
 * card before the customer has seen the product work. This is the other
 * model: nothing collected, and when it ends the product locks.
 *
 * The key is the same one the licence uses, because the product is sold
 * one seat at a time:
 *
 *     user:<tid>:<oid>
 *
 * Built only from immutable claims. Email, upn and preferred_username are
 * documented as mutable, so keying on them would hand out a fresh trial on
 * every rename and let a reassigned address inherit someone else's. An
 * email is also free to mint, which makes an email keyed trial unlimited.
 *
 * ONE TRIAL PER PERSON, FOREVER
 * -----------------------------
 * The record is written once and never deleted. Expiry is a comparison
 * against a stored end date, so an elapsed trial stays elapsed. Deleting
 * it on expiry would let anyone restart indefinitely.
 */

const DAY_MS = 24 * 60 * 60 * 1000;

/** How long a self serve trial lasts. */
export const TRIAL_DAYS = 7;

/** The per person key. Falls back to building it if jwt.js is older. */
export function userKeyFor(account) {
  if (!account) return null;
  if (account.userKey) return account.userKey;
  if (account.key && String(account.key).indexOf("user:") === 0) return account.key;

  const oid = account.oid;
  if (!oid) return null;
  const tid = account.tid || "unknown";
  return `user:${tid}:${oid}`;
}

const TRIAL_KEY = (userKey) => `trial:${userKey}`;

/** Read the trial record for a person, or null if they never started one. */
export async function getTrial(env, userKey) {
  if (!userKey) return null;
  return env.SUBSCRIPTIONS.get(TRIAL_KEY(userKey), "json");
}

/**
 * Start a trial.
 *
 * Returns { ok: true, trial } on success, or { ok: false, reason } when
 * this person has already had one. Never extends or restarts.
 */
export async function startTrial(env, account, now) {
  const key = userKeyFor(account);
  if (!key) return { ok: false, reason: "account_not_identified" };

  const existing = await getTrial(env, key);
  if (existing) {
    return { ok: false, reason: "already_used", trial: existing };
  }

  const at = now == null ? Date.now() : now;
  const trial = {
    userKey: key,
    tenantId: account.tid || null,
    accountKind: account.kind,
    startedAt: new Date(at).toISOString(),
    endsAt: new Date(at + TRIAL_DAYS * DAY_MS).toISOString(),
    grantedTo: account.upn || null,
    days: TRIAL_DAYS
  };

  await env.SUBSCRIPTIONS.put(TRIAL_KEY(key), JSON.stringify(trial));
  return { ok: true, trial };
}

/** Whole days left, rounded up so a part day still reads as 1. */
export function trialDaysLeft(trial, now) {
  if (!trial || !trial.endsAt) return null;
  const end = Date.parse(trial.endsAt);
  if (Number.isNaN(end)) return null;
  const ms = end - (now == null ? Date.now() : now);
  if (ms <= 0) return 0;
  return Math.ceil(ms / DAY_MS);
}

export function trialIsActive(trial, now) {
  const left = trialDaysLeft(trial, now);
  return left !== null && left > 0;
}

/**
 * Turn a trial record into the shape the entitlement endpoint returns.
 *
 * An active trial entitles. An elapsed one does not, and says so with a
 * distinct reason so the add-in can show the upgrade prompt rather than
 * the generic "no subscription" message.
 */
export function trialEntitlement(trial, now) {
  if (!trial) {
    return {
      entitled: false,
      reason: "no_subscription",
      trialAvailable: true,
      trialDays: TRIAL_DAYS
    };
  }

  const left = trialDaysLeft(trial, now);

  if (left > 0) {
    return {
      entitled: true,
      reason: "active",
      billingStatus: "self_trial",
      isFreeTrial: true,
      trialEndsOn: trial.endsAt,
      trialDaysLeft: left,
      trialAvailable: false,
      autoRenew: false
    };
  }

  return {
    entitled: false,
    reason: "trial_expired",
    billingStatus: "trial_expired",
    isFreeTrial: true,
    trialEndsOn: trial.endsAt,
    trialDaysLeft: 0,
    trialAvailable: false
  };
}
