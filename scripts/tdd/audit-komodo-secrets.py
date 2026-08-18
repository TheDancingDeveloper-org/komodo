#!/usr/bin/env python3
"""Audit how Komodo stacks hold credentials, and how much of that has drifted
away from Infisical.

Read-only. Prints aggregates and key *names* only -- never a secret value.

Usage:
    mydevenv2-agent-auth run -- python3 scripts/tdd/audit-komodo-secrets.py [out.json]

Environment:
    KOMODO_URL                  default http://100.92.54.45:3011
    HOMELAB_KOMODO_API_KEY      required
    HOMELAB_KOMODO_API_SECRET   required
    INFISICAL_API_URL,
    INFISICAL_CLIENT_ID,
    INFISICAL_CLIENT_SECRET     optional; enables the cross-reference section
"""

import collections
import json
import os
import re
import sys
import urllib.parse
import urllib.request

KOMODO_URL = os.environ.get("KOMODO_URL", "http://100.92.54.45:3011")

# Matches on key NAME. Deliberately broad, so it over-captures: entries like
# CROSSSEED_TORRENTLEECH_ENABLED or *_NICK are configuration, not credentials.
# Treat the resulting count as an upper bound needing a human pass.
SECRETISH = re.compile(
    r"(SECRET|TOKEN|PASSWORD|PASSWD|_PW\b|APIKEY|API_KEY|_KEY\b|PRIVATE|CREDENTIAL|"
    r"_PAT\b|CLIENT_SECRET|CLIENT_ID|DSN|CONNECTION_STRING|AUTH|SALT|SEED|CERT|"
    r"WEBHOOK|SESSION|ENCRYPT|SIGNING|BEARER|ACCESS_KEY|PASS\b)",
    re.I,
)
INTERP = re.compile(r"\[\[([^\]]+)\]\]")
PLACEHOLDER = re.compile(r"^(|changeme|change_me|xxx+|your[-_].*|<.*>|none|null|todo)$", re.I)


def komodo_read(request_type, params=None):
    body = json.dumps({"type": request_type, "params": params or {}}).encode()
    req = urllib.request.Request(
        KOMODO_URL + "/read",
        data=body,
        headers={
            "X-Api-Key": os.environ["HOMELAB_KOMODO_API_KEY"],
            "X-Api-Secret": os.environ["HOMELAB_KOMODO_API_SECRET"],
            "Content-Type": "application/json",
        },
    )
    return json.load(urllib.request.urlopen(req, timeout=60))


def parse_environment(env_text):
    """Split a Komodo environment block into classified entries."""
    entries = []
    for line in (env_text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        references = INTERP.findall(value)
        entries.append(
            {
                "key": key,
                "secretish": bool(SECRETISH.search(key)),
                "interp": references,
                "literal_len": 0 if references else len(value),
                "placeholder": bool(PLACEHOLDER.match(value)),
            }
        )
    return entries


def infisical_secret_names():
    """Names only, per project/environment. Returns {} if not configured."""
    url = os.environ.get("INFISICAL_API_URL")
    client_id = os.environ.get("INFISICAL_CLIENT_ID")
    client_secret = os.environ.get("INFISICAL_CLIENT_SECRET")
    if not (url and client_id and client_secret):
        return {}

    login = urllib.request.Request(
        url + "/api/v1/auth/universal-auth/login",
        data=json.dumps({"clientId": client_id, "clientSecret": client_secret}).encode(),
        headers={"Content-Type": "application/json"},
    )
    token = json.load(urllib.request.urlopen(login, timeout=30))["accessToken"]

    def get(path):
        req = urllib.request.Request(url + path, headers={"Authorization": "Bearer " + token})
        return json.load(urllib.request.urlopen(req, timeout=30))

    out = {}
    for project in get("/api/v1/workspace")["workspaces"]:
        for env in (e["slug"] for e in project.get("environments", [])):
            query = urllib.parse.urlencode(
                {"workspaceId": project["id"], "environment": env, "secretPath": "/"}
            )
            try:
                body = get("/api/v3/secrets/raw?" + query)
            except Exception:
                continue
            out[f"{project['slug']}/{env}"] = sorted(
                s["secretKey"] for s in body.get("secrets", [])
            )
    return out


def main():
    stacks = komodo_read("ListStacks")
    per_stack = {}
    for summary in stacks:
        name = summary["name"]
        config = komodo_read("GetStack", {"stack": name}).get("config", {})
        per_stack[name] = {
            "entries": parse_environment(config.get("environment", "")),
            "skip_secret_interp": config.get("skip_secret_interp", False),
            "file_contents_interp": INTERP.findall(config.get("file_contents", "") or ""),
        }

    rows = [e for v in per_stack.values() for e in v["entries"]]
    secretish = [r for r in rows if r["secretish"]]
    using_interp = [r for r in rows if r["interp"]]
    literal = [
        r for r in secretish
        if not r["interp"] and not r["placeholder"] and r["literal_len"] > 0
    ]

    print(f"stacks audited                        : {len(per_stack)}")
    print(f"total environment entries             : {len(rows)}")
    print(f"secret-named entries                  : {len(secretish)}")
    print(f"entries using [[interpolation]]       : {len(using_interp)}")
    print(f"** secret-named LITERAL (drift-prone) : {len(literal)}")
    print(f"Komodo Variables defined              : {len(komodo_read('ListVariables'))}")
    print(f"Core/Periphery secret keys declared   : {len(komodo_read('ListSecrets'))}")

    print("\n=== stacks by literal secret count ===")
    counts = collections.Counter()
    for name, value in per_stack.items():
        counts[name] = len(
            [
                e for e in value["entries"]
                if e["secretish"] and not e["interp"]
                and not e["placeholder"] and e["literal_len"] > 0
            ]
        )
    for name, count in counts.most_common():
        if count:
            print(f"  {count:3d}  {name}")

    key_counts = collections.Counter(r["key"] for r in literal)
    print(f"\n=== distinct secret-ish key names: {len(key_counts)} ===")
    for key, count in key_counts.most_common(40):
        print(f"  {count:3d}  {key}")

    infisical = infisical_secret_names()
    if infisical:
        index = collections.defaultdict(list)
        for scope, names in infisical.items():
            for name in names:
                index[name].append(scope)
        matched = sorted(k for k in key_counts if k in index)
        missing = sorted(k for k in key_counts if k not in index)
        print(f"\n=== cross-reference against Infisical ===")
        print(f"  exact name match     : {len(matched)}")
        print(f"  no exact name match  : {len(missing)}")
        print("  (a non-match is usually a NAMING difference, not a missing secret)")
        for key in matched:
            print(f"    match  {key:46s} -> {','.join(index[key])}")

    if len(sys.argv) > 1:
        with open(sys.argv[1], "w") as handle:
            json.dump({"per_stack": per_stack, "infisical_names": infisical}, handle, indent=1)
        print(f"\nwrote {sys.argv[1]}")


if __name__ == "__main__":
    main()
