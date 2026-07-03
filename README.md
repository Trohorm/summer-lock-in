# Summer Lock In — offline iOS app

Offline gym tracker (UL/PPL, progressive overload 8→10, check-ins, cardio, progress photos).
All data lives on the phone. No account, no internet needed.
The online version with cloud sync + AI coach lives at https://summer-lock-in.puter.site — move data
between them with Export/Import backup in Setup.

## Install (SideStore)
1. SideStore → Sources → **Add Source**:
   `https://raw.githubusercontent.com/OWNER/REPO/main/source.json`
2. Install **Summer Lock In** from the source.
3. Updates appear in SideStore automatically whenever a new version is released here.

## Release a new version
Actions → **Build IPA** → Run workflow → type the new version (e.g. `1.0.1`).
That builds the unsigned IPA on a macOS runner, attaches it to a GitHub release,
and updates `source.json` so SideStore notifies about the update.

To change the app itself, edit `ios/Resources/index.html` (single-file app), then release.
