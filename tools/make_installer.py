#!/usr/bin/env python3
"""Assemble the browser installer site (ESP Web Tools) from release images.

  python tools/make_installer.py --bins dist --version 0.2.0 --out _site

Expects dist/esp-dns-sinkhole-<board>-full.bin (merged image, flashed at 0x0)
for the boards below; boards without an image are skipped.
"""
import argparse
import json
import os
import shutil

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')

BOARDS = {  # board id -> ESP Web Tools chipFamily
    'esp32c3': 'ESP32-C3',
    'esp32s3': 'ESP32-S3',
    'esp32s3-octal-flash': 'ESP32-S3',
    'esp32': 'ESP32',
    'esp32c6': 'ESP32-C6',
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bins', required=True)
    ap.add_argument('--version', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--repo', default='https://github.com/', help='source repository URL')
    a = ap.parse_args()

    os.makedirs(os.path.join(a.out, 'manifests'), exist_ok=True)
    os.makedirs(os.path.join(a.out, 'firmware'), exist_ok=True)
    with open(os.path.join(ROOT, 'installer', 'index.html'), encoding='utf-8') as f:
        page = f.read().replace('{{REPO}}', a.repo)
    with open(os.path.join(a.out, 'index.html'), 'w', encoding='utf-8') as f:
        f.write(page)

    made = []
    for board, family in BOARDS.items():
        name = f'esp-dns-sinkhole-{board}-full.bin'
        src = os.path.join(a.bins, name)
        if not os.path.exists(src):
            continue
        shutil.copy(src, os.path.join(a.out, 'firmware', name))
        manifest = {
            'name': 'esp-dns-sinkhole',
            'version': a.version,
            'new_install_prompt_erase': True,
            'builds': [{'chipFamily': family, 'parts': [{'path': f'../firmware/{name}', 'offset': 0}]}],
        }
        with open(os.path.join(a.out, 'manifests', f'{board}.json'), 'w') as f:
            json.dump(manifest, f, indent=2)
        made.append(board)
    print(f'installer for {a.version}: {", ".join(made) or "no boards"} -> {a.out}')


if __name__ == '__main__':
    main()
