# HTML Slides for PowerPoint — marketplace fulfillment worker

A Cloudflare Worker implementing the Microsoft SaaS fulfillment lifecycle:
landing page, connection webhook, and an entitlement endpoint for the add-in.

Both **work or school accounts** and **personal Microsoft accounts** can buy.

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

## The seat model, and why it matters

The two account types are licensed differently, and the difference is not
cosmetic.

| Account | Entitlement key | One purchase covers |
|---|---|---|
| Work or school | `tenant:<tid>` | the whole organisation |
| Personal | `user:<oid>` | one individual |

**Every personal Microsoft account in the world reports the same tenant id**
(`9188040d-6c67-4c5b-b112-36a304b66dad`). Keying a personal subscription by
tenant would therefore entitle every consumer account on earth from a single
purchase. `classifyAccount()` in `src/jwt.js` is what prevents this, and two
tests in `test.mjs` marked CRITICAL guard it.

Those tests are mutation checked: swapping the personal key back to the tenant
makes them fail, so they are testing real behaviour rather than restating it.

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
to authorise the payload. Data is never trusted from the POST body alone.

Parsing is deliberately loose. Microsoft reserves the right to extend the
schema, so unknown fields are ignored and an unknown `action` is recorded
without changing entitlement.

## Entra app registrations

Three apps, in the tenant you will publish from.

**App 1 — Publisher.** Single tenant. No redirect URI. Client secret required.
Leave *Allow public client flows* set to No. Register the fulfillment service
principal in the same tenant:

```bash
az login --tenant <YOUR_TENANT_ID>
az ad sp create --id 20e940b3-4c77-4b0b-9a53-9e16a1b010a7
```

**App 2 — Landing page.** Account type *Any Entra ID Tenant + Personal
Microsoft accounts*. Platform Web, redirect URI
`https://<worker-domain>/auth/callback`. Client secret required.

**App 3 — Add-in.** Same account type as App 2. Platform SPA, redirect URI
`https://<your-host>/taskpane.html`. Expose an API with scope
`access_as_user` and pre-authorise the Office client IDs.

The tenant id and app id entered on the Partner Center technical
configuration page must be **App 1's**. Tokens have to be generated with that
same pair or the API returns an audience error.

## Setup

1. Fill in the five placeholders in `wrangler.toml`.
2. Cloudflare dashboard → Workers → Settings → Variables and Secrets, add as
   type **Secret**:
   - `PUBLISHER_CLIENT_SECRET`
   - `LANDING_CLIENT_SECRET`
3. Push. Workers Builds deploys automatically.

## Testing

```bash
node test.mjs
```

45 tests: signature verification, forged and expired tokens, the `alg: none`
attack, account classification for both types, cross-account isolation, every
webhook action, duplicate delivery, and unknown future events.

After deploying, confirm the security gate:

```bash
curl -X POST https://<worker-domain>/webhook -d '{}'
```

Must return **401**. A 200 here means token validation is not wired up.

## Notes

The Get Operation list endpoint only returns operations still awaiting
acknowledgement, so it will legitimately return an empty array for notify-only
events. This is handled and is not an error.

Webhook delivery is at least once. Every event is claimed by operation id
before processing, so a replay is discarded rather than acknowledged twice.
