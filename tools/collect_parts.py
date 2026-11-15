#!/usr/bin/env python3
"""Copy a build's flash images to <out>/<board>/<offset>.bin, from flasher_args.json.

  python tools/collect_parts.py build esp32s3-pro parts

The browser installer writes these separately (bootloader, partition table,
boot selector, app) instead of one merged image, so the settings area (NVS)
is left alone unless the user ticks "erase": updating from the web page keeps
Wi-Fi, passwords and lists.
"""
import json
import os
import shutil
import sys


def main():
    build, board, out = sys.argv[1:4]
    with open(os.path.join(build, 'flasher_args.json'), encoding='utf-8') as f:  # NOSONAR - developer/CI tool: paths are arguments
        files = json.load(f)['flash_files']
    dest = os.path.join(out, board)
    os.makedirs(dest, exist_ok=True)  # NOSONAR - developer/CI tool: paths are arguments
    for offset, name in files.items():
        shutil.copy(os.path.join(build, name), os.path.join(dest, f'{int(offset, 16):#x}.bin'))
    print(f'{board}: ' + ', '.join(f'{o} {n}' for o, n in sorted(files.items(), key=lambda kv: int(kv[0], 16))))


if __name__ == '__main__':
    main()
