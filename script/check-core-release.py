#!/usr/bin/env python3
"""Read-only publication preflight. Only a confirmed 404 means absent."""

import json
import os
import re
import sys
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen


def request(url, headers=None, method="GET"):
    try:
        with urlopen(Request(url, headers=headers or {}, method=method), timeout=30) as response:
            if response.status != 200:
                raise ValueError(f"Unexpected HTTP {response.status}: {url}")
            return response.headers, response.read()
    except HTTPError as error:
        error.close()
        if error.code == 404:
            return None
        raise


def ios_published(version, repository, commit, token):
    api = f"https://api.github.com/repos/{repository}"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    tag = f"v{version}"
    result = request(f"{api}/releases/tags/{quote(tag, safe='')}", headers)
    if result is None:
        return False
    release = json.loads(result[1])
    if release.get("tag_name") != tag or release.get("draft") is not False:
        raise ValueError(f"Release {tag} is incomplete (draft or unexpected tag); reconcile it manually")
    # Resolve the actual Git tag, not target_commitish, which can be a branch name.
    target = request(f"{api}/commits/{quote(tag, safe='')}", headers)
    if target is None or json.loads(target[1]).get("sha") != commit:
        raise ValueError(f"Release {tag} points to a different commit; refusing to skip or overwrite")
    assets = release.get("assets", [])
    for name in (f"ios-ikc-{version}.zip", f"ios-tcx-{version}.zip"):
        matches = [asset for asset in assets if asset.get("name") == name]
        if len(matches) != 1 or matches[0].get("state") != "uploaded" or matches[0].get("size", 0) <= 0:
            raise ValueError(f"Release {tag} is incomplete: {name}; reconcile it manually")
    return True


def android_published(version):
    # Match JReleaser's verification repository and all files it deploys.
    base = "https://repo1.maven.org/maven2/io/github/consenlabs/android/token-core"
    directory = f"{base}/{quote(version, safe='')}"
    found, missing = [], []
    for extension in ("aar", "pom"):
        for suffix in ("", ".asc", ".md5", ".sha1", ".sha256", ".sha512"):
            name = f"token-core-{version}.{extension}{suffix}"
            result = request(f"{directory}/{quote(name, safe='')}", method="HEAD")
            if result is None:
                missing.append(name)
            else:
                if int(result[0].get("Content-Length", "0")) <= 0:
                    raise ValueError(f"Published artifact is empty or has unknown size: {name}")
                found.append(name)
    if found and missing:
        raise ValueError("Maven publication is incomplete; wait for propagation or reconcile manually. "
                         "Missing: " + ", ".join(missing))
    return bool(found)


def main():
    platform = sys.argv[1]
    version = os.environ["RELEASE_VERSION"]
    if not re.fullmatch(r"[0-9A-Za-z._+-]+", version):
        raise ValueError("Invalid release version")
    if platform == "ios":
        published = ios_published(version, os.environ["GITHUB_REPOSITORY"],
                                  os.environ["RELEASE_COMMIT"], os.environ["GH_TOKEN"])
    elif platform == "android":
        published = android_published(version)
    else:
        raise ValueError(f"Unknown platform: {platform}")
    # No output on ambiguous state: workflow publish steps must require false.
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        output.write(f"published={str(published).lower()}\n")
    print(f"{platform} {version}: {'already published' if published else 'not published'}")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Publication check failed: {error}", file=sys.stderr)
        sys.exit(1)
