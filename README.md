# Lock In

Gym splits with 2,000+ exercises, per-gym progressive overload, and a diet tracker that estimates
every macro, micronutrient and anti-nutrient from a meal photo, barcode or description.

- **Web app:** https://web.lockin-app.online — the `web/` folder, deployed automatically by
  Cloudflare Pages on every push to `main` (`web/_worker.js` routes the two hostnames).
- **iOS app:** a thin native shell (`ios/`) around the web app, with an offline copy,
  rest-timer notifications and haptics.
- **SideStore / AltStore source:** https://ipa.lockin-app.online (latest IPA: `/latest`).

## Install (SideStore)
1. SideStore → Sources → **Add Source** → `https://ipa.lockin-app.online`
2. Install **Lock In** from the source. Updates show up there automatically.

## Release a new app version
Actions → **Build IPA** → Run workflow → type the new version (e.g. `3.4.0`).
That builds the unsigned IPA on a macOS runner, attaches it to a GitHub release,
and updates `source.json`, which ipa.lockin-app.online serves.

Web changes (`web/index.html`) need no app release — the app loads the live site.
