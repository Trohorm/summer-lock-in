#!/usr/bin/env python3
"""Regenerate source.json (SideStore/AltStore source) after a release."""
import json, os, sys, datetime

repo, version, size = sys.argv[1], sys.argv[2], int(sys.argv[3])
today = datetime.date.today().isoformat()

entry = {
    "version": version,
    "date": today,
    "localizedDescription": f"Summer Lock In {version}",
    "downloadURL": f"https://github.com/{repo}/releases/download/v{version}/SummerLockIn.ipa",
    "size": size,
    "minOSVersion": "15.0",
}

src = {
    "name": "Summer Lock In",
    "identifier": "com.summerlockin.source",
    "apps": [{
        "name": "Summer Lock In",
        "bundleIdentifier": "com.summerlockin.app",
        "developerName": "Summer Lock In crew",
        "subtitle": "Offline gym tracker",
        "localizedDescription": ("UL/PPL gym tracker: set-by-set logging with automatic "
                                 "progressive overload (8→10), rest timers, daily check-ins, "
                                 "weight trend, cardio log and progress photos. Fully offline — "
                                 "all data stays on your phone."),
        "iconURL": "https://summer-lock-in.puter.site/icon-512.png",
        "tintColor": "5b93ff",
        "versions": [],
    }],
}

if os.path.exists("source.json"):
    try:
        old = json.load(open("source.json"))
        src["apps"][0]["versions"] = [v for v in old["apps"][0].get("versions", [])
                                      if v.get("version") != version]
    except Exception:
        pass

src["apps"][0]["versions"].insert(0, entry)
json.dump(src, open("source.json", "w"), indent=1)
print("source.json updated for", version)
