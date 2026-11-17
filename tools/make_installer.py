#!/usr/bin/env python3
"""Assemble the browser installer site (ESP Web Tools) from release images.

  python tools/make_installer.py --bins dist --version 0.2.0 --out _site

Expects dist/pocket-adblock-<board>-full.bin (merged image, flashed at 0x0)
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
    'esp32s3-16mb': 'ESP32-S3',
    'esp32': 'ESP32',
    'esp32c6': 'ESP32-C6',
    'esp32c6-8mb': 'ESP32-C6',
    'esp32s3-pro': 'ESP32-S3',
    'esp32s3-octal-flash-pro': 'ESP32-S3',
    'esp32s3-16mb-pro': 'ESP32-S3',
    'esp32-pro': 'ESP32',
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bins', required=True)
    ap.add_argument('--version', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--repo', default='https://github.com/', help='source repository URL')
    ap.add_argument('--web-tools', help='esp-web-tools dist/web folder, served as vendor/esp-web-tools')
    ap.add_argument('--parts', help='folder of <board>/<offset>.bin images (tools/collect_parts.py)')
    a = ap.parse_args()

    os.makedirs(os.path.join(a.out, 'manifests'), exist_ok=True)  # NOSONAR - developer tool: the path is a command-line argument chosen by the person running it
    os.makedirs(os.path.join(a.out, 'firmware'), exist_ok=True)  # NOSONAR - developer tool: the path is a command-line argument chosen by the person running it
    with open(os.path.join(ROOT, 'installer', 'index.html'), encoding='utf-8') as f:
        page = f.read().replace('{{REPO}}', a.repo)
    with open(os.path.join(a.out, 'index.html'), 'w', encoding='utf-8') as f:  # NOSONAR - developer tool: the path is a command-line argument chosen by the person running it
        f.write(page)

    if a.web_tools:
        shutil.copytree(a.web_tools, os.path.join(a.out, 'vendor', 'esp-web-tools'), dirs_exist_ok=True)

    made = []
    for board, family in BOARDS.items():
        # Preferred: separate images at their offsets, so the settings area (NVS)
        # is only erased when the user ticks "erase". Fallback: the merged image.
        pdir = os.path.join(a.parts, board) if a.parts else ''
        if pdir and os.path.isdir(pdir):
            dest = os.path.join(a.out, 'firmware', board)
            os.makedirs(dest, exist_ok=True)  # NOSONAR - developer/CI tool: paths are arguments
            parts = []
            for fname in sorted(os.listdir(pdir), key=lambda n: int(n[:-4], 16)):
                shutil.copy(os.path.join(pdir, fname), os.path.join(dest, fname))
                parts.append({'path': f'../firmware/{board}/{fname}', 'offset': int(fname[:-4], 16)})
        else:
            name = f'pocket-adblock-{board}-full.bin'
            src = os.path.join(a.bins, name)
            if not os.path.exists(src):
                continue
            shutil.copy(src, os.path.join(a.out, 'firmware', name))
            parts = [{'path': f'../firmware/{name}', 'offset': 0}]
        manifest = {
            'name': 'pocket-adblock',
            'version': a.version,
            'new_install_prompt_erase': True,
            'builds': [{'chipFamily': family, 'parts': parts}],
        }
        with open(os.path.join(a.out, 'manifests', f'{board}.json'), 'w') as f:  # NOSONAR - developer tool: the path is a command-line argument chosen by the person running it
            json.dump(manifest, f, indent=2)
        made.append(board)
    print(f'installer for {a.version}: {", ".join(made) or "no boards"} -> {a.out}')


if __name__ == '__main__':
    main()
