# HTML Slides — consolidated update

Both sides of the final design, in one matched pair. The add-in and the
worker must be deployed together, because they now agree on a key scheme
that differs from what is currently live.

## What changed, and why

**One seat per person.** A licence is keyed `user:<tid>:<oid>`, built from
immutable claims. Your current worker keys a work account by tenant, which
means one purchase licenses the whole organisation. That is the opposite
of selling one seat at a time.

**Self serve trial.** Seven days, no card, hard stop. This has to be ours
because a marketplace plan level trial takes a payment method up front.

**Two purchase destinations.** Completing a marketplace purchase requires
a work or school account. A personal account can run the trial but cannot
buy through Microsoft, so the add-in sends them to us instead. The worker
reports which case applies as `canBuyFromMicrosoft`.

## Upload to the web server

```
taskpane.html            replace
css/taskpane.css         replace
js/config.js             replace
js/entitlement.js        replace
js/app.js                replace
```

Leave alone: `auth.js`, `constants.js`, `capture.js`, `editor.js`,
`pptx.js`, `slides.js`, `library.js`, `assets/`, `.htaccess`,
`manifest.xml`.

## Push to the worker repository

```
src/jwt.js               replace
src/store.js             replace
src/index.js             replace
src/landing.js           replace
src/selftrial.js         NEW
src/trial.js             NEW
test.mjs                 replace
```

Leave alone: `src/webhook.js`, `src/marketplace.js`, `wrangler.toml`.
`marketplace.js` already exports `getSubscription`, which is all the new
code needs from it.

## Before it works

Three placeholders in `js/config.js`:

```javascript
var MARKETPLACE_OFFER_ID = "REPLACE_WITH_OFFER_ID";
var QUADRILA_LICENCE_URL = ".../licence.html";
var QUADRILA_VOLUME_URL  = ".../volume.html";
```

Until the offer exists, the marketplace link falls back to the store home
page rather than building a broken product URL. The two Quadrila pages do
not exist yet; create them, or point those constants at your contact page.

## Your KV will need one new key

Entitlement now looks for `user:<tid>:<oid>`, not `tenant:<tid>`. Your
existing test record will stop matching.

Run `await tokenFacts()` in the task pane console to read your `tid` and
`oid`, then add:

```
user:<tid>:<oid>   ->   test-sub-1
```

Update `ownerKey` inside `sub:test-sub-1` to the same value so the record
is self consistent.

## Testing without Partner Center

Delete every `sub:` and `user:` key and sign in. You should be offered the
trial. Press it, and the product unlocks with a countdown badge.

To watch it expire without waiting a week, edit `trial:user:<tid>:<oid>`
and move `endsAt` into the past. Sign out and back in. The product should
**lock**, and the gate should read "Your free trial has ended".

Press Start free trial again with that record in place. The worker answers
409 and the gate shows "Choose a plan".

## Two deliberate decisions

**An elapsed self trial locks. An elapsed marketplace trial does not.**
The first is our promise of seven days. The second converts to paid unless
the customer cancelled, so locking on the date would cut off someone who
just bought. Two tests marked CRITICAL hold both halves apart.

**A multi seat subscription is still honoured.** A single seat purchase
never writes the tenant index, so a colleague is never licensed by your
purchase. But if a subscription ever arrives with `quantity` above one,
the organisation is indexed too. The alternative is a customer who paid
for twenty five seats, found one worked, and a support case with no good
answer.

## Tests

```bash
cd worker && node test.mjs     # 69 tests
node test-addin.mjs            # 27 tests
```

`test.mjs` imports `webhook.js` and `marketplace.js`, which are not in
this package because they do not change. Drop the new files into your
existing checkout and the tests will run.

`test.mjs` is rewritten. The old one asserted the tenant wide model and
would now fail for the right reasons; these assertions describe the
current design.

Five deliberate regressions were injected to confirm the tests are
meaningful, not decorative:

| Injected bug | Caught |
|---|---|
| work licence reverts to tenant wide | 7 failures |
| personal accounts given a tenant key | 4 failures |
| expired trial can be restarted | 1 failure |
| personal accounts sent to Microsoft anyway | 2 failures |
| expired self trial treated as a marketplace one | 7 failures |

## Still open

- Reserve the name in Partner Center
- Replace the offer id and create the two Quadrila pages
- Publisher verification, so the consent screen stops saying unverified
- The ribbon icon still shows the placeholder
- `docs.html` and `support.html` do not exist yet
- The html2canvas sandbox issue, which is producing the fallback gradient
  rather than a render of the pasted HTML
