/* Marketplace free trial fields.
 *
 * Only used if a plan level free trial is ever enabled in Partner Center.
 * That kind of trial takes a card up front and converts to paid when it
 * ends, which is different from the self serve trial in selftrial.js.
 *
 * Microsoft is the authority. The Subscription object carries:
 *
 *   isFreeTrial   boolean
 *   term          { termUnit, startDate, endDate }
 *   autoRenew     boolean
 *
 * Nothing here decides entitlement. A marketplace trial subscription is
 * active, so the customer keeps access until Microsoft says otherwise
 * through the webhook. All this adds is an accurate label.
 */

const DAY_MS = 24 * 60 * 60 * 1000;

function when(value) {
  if (!value) return null;
  const t = Date.parse(value);
  return Number.isNaN(t) ? null : t;
}

/**
 * Pull the trial and term fields out of a Subscription payload.
 * Tolerant of missing fields, because the schema may be extended.
 */
export function readTerm(sub) {
  if (!sub) return {};
  const term = sub.term || {};

  return {
    isFreeTrial: sub.isFreeTrial === true,
    termUnit: term.termUnit || null,
    termStart: term.startDate || null,
    termEnd: term.endDate || null,
    autoRenew: sub.autoRenew === true,
    isTest: sub.isTest === true,
    sandboxType: sub.sandboxType || null
  };
}

/** Whole days remaining until an end date, never negative. */
export function daysLeft(endDate, now) {
  const end = when(endDate);
  if (end == null) return null;
  const from = now == null ? Date.now() : now;
  const ms = end - from;
  if (ms <= 0) return 0;
  return Math.ceil(ms / DAY_MS);
}

/**
 * Everything the add-in needs to describe billing state for a
 * marketplace subscription.
 */
export function billingFacts(record, now) {
  const out = {
    billingStatus: "paid",
    isFreeTrial: false,
    trialEndsOn: null,
    trialDaysLeft: null,
    autoRenew: record && record.autoRenew === true
  };

  if (!record || record.isFreeTrial !== true) return out;

  out.billingStatus = "trial";
  out.isFreeTrial = true;
  out.trialEndsOn = record.termEnd || null;
  out.trialDaysLeft = daysLeft(record.termEnd, now);

  /* A trial whose end date has passed, but which Microsoft has not yet
     converted or cancelled. Report it honestly; entitlement is unchanged
     until a webhook says so. */
  if (out.trialDaysLeft === 0) out.billingStatus = "trial_ended";

  return out;
}
