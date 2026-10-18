#!/usr/bin/env python3
"""Regenerate source.json (SideStore/AltStore source) after a release."""
import json, os, sys, datetime

repo, version, size = sys.argv[1], sys.argv[2], int(sys.argv[3])
today = datetime.date.today().isoformat()

entry = {
    "version": version,
    "date": today,
    "localizedDescription": f"Lock In {version}",
    "downloadURL": f"https://github.com/{repo}/releases/download/v{version}/SummerLockIn.ipa",
    "size": size,
    "minOSVersion": "15.0",
}

src = {
    "name": "Lock In",
    "identifier": "com.summerlockin.source",
    "apps": [{
        "name": "Lock In",
        "bundleIdentifier": "com.summerlockin.app",
        "developerName": "Lock In crew",
        "subtitle": "Gym splits + full-nutrient tracker",
        "localizedDescription": ("Custom gym splits with 2,000+ exercises and animated demos, per-gym progressive overload, "
                                 "AI split builder, and a diet tracker that estimates every macro, micronutrient and "
                                 "anti-nutrient from a photo of your meal. Syncs with Lock In on the web."),
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
