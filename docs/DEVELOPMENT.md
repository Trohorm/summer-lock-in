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
reactions, shared splits (`/s/<code>#key`) and photo posts. Sign-in is the Puter token, checked
server-side. Everything a friend can see is end-to-end encrypted in the browser before upload;
the server stores ciphertext and wrapped keys only.

It needs one D1 database bound to the Pages project as **`DB`**
(Workers & Pages → lockin-app → Settings → Bindings → D1). Tables and migrations run themselves.

## Releasing a new iOS build
Actions → **Build IPA** → Run workflow → enter the new version (e.g. `3.5.0`).
It builds an unsigned IPA on macOS, attaches it to a GitHub release and updates `source.json`,
which ipa.lockin-app.online serves to SideStore.

Web changes need no app release — the app loads the live site.
