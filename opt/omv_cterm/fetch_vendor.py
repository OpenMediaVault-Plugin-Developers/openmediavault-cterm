#!/usr/bin/env python3

# Copyright (c) 2025 openmediavault plugin developers
#
# This file is licensed under the terms of the GNU General Public
# License version 2. This program is licensed "as is" without any
# warranty of any kind, whether express or implied.
#
# Downloads the front-end components (xterm.js, socket.io, Font Awesome and
# the Google web fonts) to opt/omv_cterm/static/vendor so the terminal can be
# served without any external CDN requests.  Run on package install and from
# the "Update components" button in the openmediavault web interface.

import os
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

VENDOR_DIR = Path(__file__).resolve().parent / "static" / "vendor"

# A modern browser User-Agent so Google Fonts serves woff2 instead of ttf.
BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
TIMEOUT = 30

# Self-contained single files: {relative target path: source url}
SIMPLE_ASSETS = {
    "xterm/xterm.min.js":
        "https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.min.js",
    "xterm/xterm.css":
        "https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css",
    "xterm/xterm-addon-fit.min.js":
        "https://cdn.jsdelivr.net/npm/xterm-addon-fit@0.7.0/lib/xterm-addon-fit.min.js",
    "socketio/socket.io.min.js":
        "https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.min.js",
}

# CSS bundles whose url(...) references (fonts) are downloaded as well and
# rewritten to point at a local ./assets/ folder, yielding a self-contained
# stylesheet.  {relative target css path: source url}
CSS_BUNDLES = {
    "fontawesome/all.min.css":
        "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css",
    "googlefonts/roboto.css":
        "https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap",
    "googlefonts/inter.css":
        "https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap",
}

URL_RE = re.compile(r"url\(\s*['\"]?([^'\")]+)['\"]?\s*\)")


def _fetch(url, binary=True):
    req = Request(url, headers={"User-Agent": BROWSER_UA})
    with urlopen(req, timeout=TIMEOUT) as resp:
        data = resp.read()
    return data if binary else data.decode("utf-8")


def _write_atomic(path, data):
    """Write bytes to path via a temp file + rename so a failed/partial
    download never leaves a corrupt asset in place."""
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = "wb" if isinstance(data, (bytes, bytearray)) else "w"
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, mode) as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _safe_name(url):
    name = os.path.basename(urlparse(url).path) or "asset"
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


def fetch_simple(rel_path, url):
    print(f"  {url}")
    _write_atomic(VENDOR_DIR / rel_path, _fetch(url, binary=True))


def fetch_css_bundle(rel_path, url):
    print(f"  {url}")
    css = _fetch(url, binary=False)
    css_path = VENDOR_DIR / rel_path
    assets_dir = css_path.parent / "assets"
    seen = {}

    def repl(match):
        raw = match.group(1).strip()
        if raw.startswith("data:"):
            return match.group(0)
        src = urljoin(url, raw)
        if src not in seen:
            name = _safe_name(src)
            # Avoid clobbering distinct urls that share a basename.
            while name in seen.values() and seen.get(src) != name:
                name = "_" + name
            print(f"    -> {src}")
            _write_atomic(assets_dir / name, _fetch(src, binary=True))
            seen[src] = name
        return f"url(assets/{seen[src]})"

    css = URL_RE.sub(repl, css)
    _write_atomic(css_path, css)


def main():
    print(f"Updating terminal components in {VENDOR_DIR}")
    failures = []
    for rel_path, url in SIMPLE_ASSETS.items():
        try:
            fetch_simple(rel_path, url)
        except Exception as e:
            failures.append((rel_path, e))
            print(f"  FAILED: {rel_path}: {e}", file=sys.stderr)
    for rel_path, url in CSS_BUNDLES.items():
        try:
            fetch_css_bundle(rel_path, url)
        except Exception as e:
            failures.append((rel_path, e))
            print(f"  FAILED: {rel_path}: {e}", file=sys.stderr)

    if failures:
        print(f"Finished with {len(failures)} failure(s).", file=sys.stderr)
        return 1
    print("All components updated successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
