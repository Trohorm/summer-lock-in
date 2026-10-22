# Development notes

Everything a user doesn't need lives here.

## Layout
- `web/` — the web app (single `index.html`), the service worker and `_worker.js`.
  Cloudflare Pages deploys it on every push to `main`; `_worker.js` routes the two hostnames
  (web.lockin-app.online and ipa.lockin-app.online) and serves `/api/*`.
- `ios/` — a thin native shell around the web app (offline copy, rest-timer notifications, haptics).
- `scripts/` — app icon and SideStore `source.json` generators used by the build workflow.

## Friends backend (Cloudflare D1)
`web/_worker.js` serves `/api/*`: profiles, invites (`/i/<code>`), requests, privacy, the feed,
reactions, shared splits (`/s/<code>#key`) and photo posts. Sign-in is a Lock In session (see Accounts).
Everything a friend can see is encrypted in the browser before upload, per category and per friend. The account's
own keys are stored with the account (so signing in with just your email gets everything back) — so this protects
the data from other people, not from whoever runs the server. Shared-split links keep their key after the `#`.

It needs one D1 database bound to the Pages project as **`DB`**
(Workers & Pages → lockin-app → Settings → Bindings → D1). Tables and migrations run themselves.

## Releasing a new iOS build
Actions → **Build IPA** → Run workflow → enter the new version (e.g. `3.5.0`).
It builds an unsigned IPA on macOS, attaches it to a GitHub release and updates `source.json`,
which ipa.lockin-app.online serves to SideStore.

Web changes need no app release — the app loads the live site.

## Versions
- **iPhone app:** the web app compares the app's version (`window.__lockinNative.version`) with the latest
  one in `source.json` (served at `/api/appver`). An older app shows a full-screen update screen and can't be used
  until it's updated — so a new release in the Build IPA workflow reaches everyone right away. The check starts
  while the page is still loading and the answer is remembered, so the update screen is the first thing an
  outdated app shows (the splash waits up to 1.5 s for an answer, or not at all if it checked in the last 10 minutes).
- **What's new:** each web release bumps `WEB_VER` and adds an entry to `WHATSNEW` (built from `tools/p30_ver.py`
  in the build scripts). Existing users see it once, the moment the app opens after the update; new accounts don't.

## Storage on the device
The local copy of your data lives in `localStorage` while it's small and moves to IndexedDB (`lockin` database)
once it outgrows it (iPhone caps `localStorage` at about 5 MB). Your Lock In account (D1) is the copy that syncs.
The service worker keeps the app for offline use: the network is tried first, but after 2.5 s on a slow
connection the saved copy opens instead (and the new version is ready next time).

## Accounts and sign-in
Since 2026.10.21.3 the app has its own accounts (no Puter). `web/_worker.js` → `authApi`:
- **Email code:** `POST /api/auth/email` sends a 6-digit code (10 min, 5 tries, 5 codes an hour per address);
  `POST /api/auth/verify` signs in and creates the account the first time. Email goes through **Resend**
  (`RESEND_KEY`) or **Brevo** (`BREVO_KEY`) — whichever is set; the sender is `MAIL_FROM` (default
  `login@lockin-app.online`, on a domain verified with that provider).
- **Password (optional, Setup → Account):** the phone sends `dk = PBKDF2-SHA256(password, "lockin:"+email, 300k)`;
  the server keeps `sha256(dk + ":" + account id)`.
- **Google:** `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` (OAuth "Web application" client) with the redirect URI
  `https://web.lockin-app.online/api/auth/google/callback`. The app opens a pop-up (inside the iPhone app it's the
  sign-in sheet), Google comes back to the callback, and the app picks the session up by polling `/api/auth/poll`.
  With pop-ups blocked the whole page goes to Google and comes back to `/?gs=<state>`.
- **Sessions:** random `lk1.…` tokens, stored hashed (`sessions`), 180 days and extended while used. A session the
  server no longer accepts shows "Signed out on this device" — the data stays on the phone.
- **Keys:** `GET/PUT /api/account/keys` hold the account's encryption keys; `kv` counts changes (compare-and-set).
  Sync and photo writes say which `kv` they were encrypted with and are refused (`409 keys_changed`) if it's old, so
  a phone never writes data the other devices can't read; it loads the new keys and saves again.
- **Moving from Puter:** a phone with data from a Puter account shows "Welcome back, @name"; after signing in it
  calls `POST /api/auth/link` with the saved Puter token (checked with Puter's `/whoami`) and its local keys. The
  friends profile (username, friends), Pro, AI use, synced data and photos move to the account once; the old keys
  become the account's (another device's unreadable copy is dropped and that device uploads again). If the old
  Puter sign-in expired, one Puter sign-in is offered, or the phone keeps just its own data.
- `LEGACY_PUTER=1` (tests only) still accepts Puter tokens for everything. `ADMIN_EMAILS` (comma-separated) makes
  accounts admins by email; `ADMIN` (old Puter usernames) still works for moved accounts.

## Sync on Lock In's own storage (D1)
Since 2026.10.21.2 the account syncs through `/api/sync` (tables `sync`, `photos`, `syncv`), not Puter KV/FS.
Each piece (main document, a month of workouts, a month of food, each progress photo) is gzipped and encrypted on
the phone with the account's own key (the E2E "self" key) before upload; the server stores ciphertext (and, since
2026.10.21.3, the account's keys — see Accounts).
Writes are compare-and-set on a version number: a conflict makes the phone merge the newer copy and retry.
Every app start reads the whole cloud copy before it writes anything. Open devices check `/api/sync/v` every 30 s.
`GET /api/sync` also returns the account's keys version (`kv`): a phone holding older keys loads the new ones,
reads everything again and re-uploads its photos.

## Plans and AI on the app's own key
`/api/ai` runs Claude Haiku 5.5 with the Cloudflare secret **`ANTHROPIC_API_KEY`**; without it AI is off. Free: 5 meal reads, 1 AI workout review, 25 other AI requests per (UTC) day;
Pro: 30, unlimited, 150. `AI_DAY_USD` caps the whole app's AI spend per day (default 3). Admins (`ADMIN_EMAILS`, or
`ADMIN` for accounts moved from Puter) are unlimited and see everyone's use in Setup, where they can give or remove Pro.
Payments — **Stripe Managed Payments** (Stripe is the merchant of record and handles VAT): `STRIPE_LINK_MONTHLY` /
`STRIPE_LINK_YEARLY` (Payment Links with Managed Payments on), `STRIPE_PORTAL` (customer portal login link) and the webhook
signing secret `STRIPE_WHSEC`; webhook URL `https://web.lockin-app.online/api/stripe/webhook` with `checkout.session.completed`
and `customer.subscription.created/updated/deleted` (+ `checkout.session.async_payment_succeeded` for bank payments).
The link carries the account as `client_reference_id` (`a__<id>`).
**Paying inside the app**: with `STRIPE_KEY` (a restricted key: Checkout Sessions write, Prices read, Payment Links read)
and `STRIPE_PK` (publishable key) as well, Get Pro opens Stripe's embedded checkout in a sheet (`POST /api/pay/checkout`
→ a Checkout Session with `ui_mode=embedded_page`, Managed Payments on, the account in `client_reference_id`, `metadata.uid`
and the subscription's `metadata.uid`; Stripe-Version `2026-04-22.dahlia`). The price is `STRIPE_PRICE_MONTHLY` /
`STRIPE_PRICE_YEARLY`, else the one behind the payment link, else the account's active €4.99 / €39.99 price. When it's paid
the app asks `GET /api/pay/status?id=<cs_…>` (the server checks with Stripe) and Pro is on before the webhook lands. A
payment method that leaves the page comes back to `/?paid=<cs_…>`. Stripe errors are logged for the admin card. A
subscription event that can't be linked yet (bought through a link, checkout event still on its way) gets a 409 so Stripe
sends it again. Without the key the payment links are used (in the iPhone app ≥ 3.5 in an in-app browser sheet).
**Pro look**: Pro and the admin get every logo in gold (`html.pro`), a gold accent (`html.gold`, Setup switch), the gold
favicon / home-screen icon, and in the iPhone app ≥ 3.5 the gold app icon (`setAlternateIconName("ProIcon")`) and a gold
launch screen. Free sees Pro on Today and Progress (✕ hides it for 3 days, 14 after the third time), in the Diet line,
in a reminder when the free AI runs low and in What's new — only once someone is using the app and payments are on.
Admins can preview it all in Setup → Plans & AI.
When Stripe links are set they're used; otherwise Lemon Squeezy (merchant of record): `LS_BUY_MONTHLY` / `LS_BUY_YEARLY` (checkout links), `LS_PORTAL`
(customer portal) and the webhook secret `LS_SECRET`; webhook URL `https://web.lockin-app.online/api/ls/webhook`.
The checkout passes the account id as `checkout[custom][uid]` (`a:<account id>`; an old Puter id is mapped to the account
it moved to); subscription events set Pro until the renewal (+3 days).

## Public split links
`/p/<code>#<key>` — anyone can follow; only the owner's app writes (`/api/pub`). The key after `#` never reaches
the server, so the stored copy is encrypted. Followers poll for the latest version; to change it they duplicate it.
