# HTML Slides for PowerPoint — marketplace fulfillment worker

A Cloudflare Worker implementing the Microsoft SaaS fulfillment lifecycle:
landing page, connection webhook, and an entitlement endpoint for the add-in.
Purchases are restricted to Microsoft Entra work or school accounts.

## Routes

| Route | Purpose |
|---|---|
| `GET /` | health check |
| `GET /landing?token=…` | marketplace redirect target |
| `GET /auth/callback` | Entra sign in response |
| `POST /webhook` | marketplace connection webhook |
| `GET /api/entitlement` | called by the add-in to check access |

In Partner Center, technical configuration:

```
Landing page URL      https://<worker-domain>/landing
Connection webhook    https://<worker-domain>/webhook
```

## Webhook contract

Implemented exactly as documented:

| Event | Response | Acknowledgement |
|---|---|---|
| Subscribe | 200 | none |
| ChangePlan | 200 | PATCH Success or Failure within 10s |
| ChangeQuantity | 200 | PATCH Success or Failure within 10s |
| Renew | 200 | none |
| Suspend | 200 | none |
| Unsubscribe | 200 | none |
| Reinstate | 200 | none |

Three behaviours are load-bearing:

**The 200 goes back first.** Processing runs in `ctx.waitUntil`, so a slow
downstream call can never cause a timeout. Microsoft retries 500 times over
eight hours, and an operation that is never acknowledged eventually fails.

**The token is validated.** Every call must carry a valid Entra token. The
RS256 signature is checked against the published JWKS, then audience, issuer
and expiry are checked.

**The payload is confirmed.** Before acting, the Get Operation API is called
to authorise the payload, as Microsoft requires. Data is never trusted from
the POST body alone.

Parsing is deliberately loose. Microsoft reserves the right to extend the
schema, so unknown fields are ignored and an unknown `action` is recorded
without changing entitlement.

## Work and school accounts only

Enforced in three places:

1. **Sign in authority.** The landing page uses the `organizations` authority,
   which excludes personal Microsoft accounts at the identity provider.
2. **Claim check.** The `tid` claim is rejected if it is the consumer tenant
   `9188040d-6c67-4c5b-b112-36a304b66dad`, as is any `idp` of `live.com`.
3. **Entitlement check.** `/api/entitlement` repeats the same test, so a
   consumer account is never licensed even if one reached a subscription.

Microsoft does not let a publisher block a purchase outright. A personal
account can still complete checkout; it is stopped at activation, and the
landing page tells the buyer to contact support for a refund. Restrict the
offer's availability in Partner Center as well.

## Setup

```bash
npm install -g wrangler
wrangler login

wrangler kv namespace create SUBSCRIPTIONS
# copy the id into wrangler.toml

wrangler secret put PUBLISHER_CLIENT_SECRET
wrangler secret put LANDING_CLIENT_SECRET

wrangler deploy
```

Fill in the five placeholder values in `wrangler.toml` first.

### Entra app registrations

**Publisher app** — used for the fulfillment API. Client credentials against
the *publisher* tenant, never the customer tenant. Register its app ID in
Partner Center under the offer's technical configuration.

**Landing page app** — web platform, redirect URI `https://<worker>/auth/callback`,
supported account types set to *organizations only*. This is what keeps
personal accounts out at sign in.

**Add-in app** — used by the task pane for SSO against `/api/entitlement`.

## Testing

```bash
node test.mjs
```

30 tests covering signature verification, forged and expired tokens, the
`alg: none` attack, every webhook action, duplicate delivery, and unknown
future events.

For end to end testing, create the offer in the Partner Center preview and
purchase through a preview audience account.

## Notes

The Get Operation list endpoint only returns operations still awaiting
acknowledgement, so it will legitimately return an empty array for notify-only
events. This is handled and is not an error.

Webhook delivery is at least once. Every event is claimed by operation id
before processing, so a replay is discarded rather than acknowledged twice.
