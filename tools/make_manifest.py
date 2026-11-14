#!/usr/bin/env python3
"""Write the firmware update manifest the devices check daily.

  python tools/make_manifest.py --version 0.2.0 --bins dist \
      --base-url https://github.com/joanrra2/pocket-adblock/releases/download/v0.2.0 --out dist/manifest.json

Every dist/pocket-adblock-<board>-ota.bin becomes "<board>": "<base-url>/<file>".
The board id must match CONFIG_SINKHOLE_BOARD_ID (or the chip target).
"""
import argparse
import json
import os
import re


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--version', required=True)
    ap.add_argument('--bins', required=True)
    ap.add_argument('--base-url', required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()

    images = {}
    for name in sorted(os.listdir(a.bins)):
        m = re.fullmatch(r'pocket-adblock-(.+)-ota\.bin', name)
        if m:
            images[m.group(1)] = f'{a.base_url.rstrip("/")}/{name}'
    if not images:
        raise SystemExit(f'no *-ota.bin images in {a.bins}')
    with open(a.out, 'w') as f:
        json.dump({'version': a.version.lstrip('v'), 'images': images}, f, indent=2)
    print(f'manifest {a.version}: {", ".join(images)} -> {a.out}')


if __name__ == '__main__':
    main()
