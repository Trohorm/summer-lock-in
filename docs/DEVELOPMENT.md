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
once it outgrows it (iPhone caps `localStorage` at about 5 MB). Your account in Puter is the copy that syncs.
The service worker keeps the app for offline use: the network is tried first, but after 2.5 s on a slow
connection the saved copy opens instead (and the new version is ready next time).

## Puter allowance
Every Puter account gets a free allowance each month, and each person's own account pays for their use:
AI calls, KV reads/writes (cloud sync and the encryption keys) and file reads/writes/egress (progress photos).
When it runs out, Puter refuses those calls with `402 insufficient_funds` and Puter.js shows its own
"Low Balance" window.

- The app asks Puter how much is left (`puter.auth.getMonthlyUsage()` — free, never shows that window)
  once per app open, then every 30 min (10 when under a quarter is left, 5 while it's used up).
- While it's used up, nothing that costs credit is called: no AI, no cloud reads or writes, no photo
  downloads or uploads. Everything stays on the device (new photos wait in IndexedDB `lockin_ph`) and
  syncs by itself when a check finds the allowance back. Today shows a note; Setup → Puter allowance shows
  how much is used and what used it.
- A refusal that slips through anyway (402) pauses the same way, and the app waits 30 min before trusting
  "there's some left" again (Setup → Refresh skips that wait).
- Costs: meal photos use Claude Haiku 5.5 (about 20× cheaper than Sonnet 5.5); "Sharper photo estimates"
  in Setup switches photos to Sonnet 5.5 and falls back to Haiku when under a quarter is left. Text uses Haiku 5.5.
- Cloud writes: the main document is written only when something in it changed (or every 10 min to keep its
  timestamp fresh), at most one push every 20 s — every 5 min during a workout — and right away when the app
  is hidden. Automatic AI retries are capped (offline photo queue: 3 tries 30 min apart; a meal grade: 2 more tries).

## Public split links
`/p/<code>#<key>` — anyone can follow; only the owner's app writes (`/api/pub`). The key after `#` never reaches
the server, so the stored copy is encrypted. Followers poll for the latest version; to change it they duplicate it.
