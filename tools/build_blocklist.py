#!/usr/bin/env python3
"""Build a blocklist for esp-dns-sinkhole: 40-bit FNV-1a domain hashes with a
64-byte SHBL header (format, count, SHA-256), ready to upload or serve over HTTPS.

Usage:
  build_blocklist.py OUT.bin [SOURCE ...] [--v1 | --raw] [--sign=KEY.pem] [--allow-missing]

--sign=KEY.pem appends an ECDSA P-256 signature (key from tools/keys.py
blocklist-key; needs `pip install cryptography`).

SOURCE is a URL or a local file: hosts files, plain domain lists, or AdGuard /
Adblock basic rules (||domain^ blocks, @@||domain^ removes). With no sources a
balanced default is used (StevenBlack base + Hagezi Light, ~110k domains).

Formats (the device reads all three):
  default  SHBL v2 "compact": 3 bytes per domain + 65 KB index, ~30-55% smaller
  --v1     SHBL v1: sorted 5-byte hashes
  --raw    headerless v1, the format of esp32-c3-adblock

Source parsing and hashing are derived from esp32-c3-adblock's
tools/build_blocklist.py, Copyright (c) 2026 zed, MIT License.
See THIRD_PARTY_NOTICES.md.
"""
import hashlib
import math
import os
import re
import struct
import sys
import time
import urllib.request

HASH_BYTES = 5  # 40-bit: must match components/blocklist/include/sinkhole/hash_table.hpp
MASK = (1 << (HASH_BYTES * 8)) - 1
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME = 0x100000001b3
U64 = (1 << 64) - 1

DEFAULT_SOURCES = [
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt',
]

ADG = re.compile(r'^(@@)?\|\|([a-z0-9._-]+)\^?(\$.*)?$', re.I)


def fnv(b: bytes) -> int:
    h = FNV_OFFSET
    for c in b:
        h = ((h ^ c) * FNV_PRIME) & U64
    return h & MASK


def norm(d: str) -> str:
    d = d.strip().lower().lstrip('*').lstrip('.').rstrip('.')
    return d[4:] if d.startswith('www.') else d


def read_source(src: str) -> str:
    if os.path.exists(src):
        with open(src, errors='ignore') as f:
            return f.read()
    print(f'  downloading {src} ...', file=sys.stderr)
    with urllib.request.urlopen(src, timeout=180) as r:
        return r.read().decode('utf-8', 'ignore')


def parse(sources, allow_missing):
    domains, allow, skipped = set(), set(), 0
    for src in sources:
        try:
            data = read_source(src)
        except Exception as e:  # fail loudly: a silently missing source shrinks the list
            print(f'  !! FAILED to read {src}: {e}', file=sys.stderr)
            if not allow_missing:
                sys.exit(1)
            continue
        for line in data.splitlines():
            s = line.strip()
            if s.startswith(('||', '@@')):
                line = s
            elif not s.startswith('#') and ('##' in s or '#@#' in s or '#?#' in s or '#%#' in s):
                skipped += 1  # cosmetic rule
                continue
            else:
                line = s.split('#', 1)[0].strip()
            if not line or line[0] in '!/[':
                continue
            m = ADG.match(line)
            if m:
                if m.group(3):
                    skipped += 1
                    continue
                (allow if m.group(1) else domains).add(norm(m.group(2)))
                continue
            if line.startswith(('||', '@@', '|')) or any(c in line for c in '^$*'):
                skipped += 1
                continue
            parts = line.split()
            if parts[0] in ('0.0.0.0', '127.0.0.1', '::1', '::'):
                entries = parts[1:]
            else:
                entries = parts if len(parts) == 1 else []
            for d in entries:
                d = norm(d)
                if '.' in d and ' ' not in d:
                    domains.add(d)
    if allow:
        before = len(domains)
        domains -= allow
        print(f'allowlisted      : {before - len(domains):,} removed', file=sys.stderr)
    if skipped:
        print(f'skipped rules    : {skipped:,} (not expressible as DNS hashes)', file=sys.stderr)
    return domains


def payload_v1(hashes):
    return b''.join(h.to_bytes(HASH_BYTES, 'little') for h in hashes)


def payload_v2(hashes):
    """Compact format: 16-bit buckets with 1-byte counts, 24-bit suffixes.
    Must match HashTable::containsV2 in components/blocklist/include/sinkhole/hash_table.hpp."""
    buckets = [[] for _ in range(65536)]
    for h in hashes:  # sorted, so suffixes come out ascending within each bucket
        buckets[h >> 24].append(h & 0xFFFFFF)
    biggest = max(len(b) for b in buckets)
    if biggest > 255:
        sys.exit(f'bucket with {biggest} entries: too many domains for format v2 (use --format v1)')
    coarse, total = [], 0
    for i, b in enumerate(buckets):
        if i % 256 == 0:
            coarse.append(total)
        total += len(b)
    return (struct.pack('<256I', *coarse) + bytes(len(b) for b in buckets) +
            b''.join(s.to_bytes(3, 'little') for b in buckets for s in b))


def sign_header(header, key_path):
    """ECDSA P-256 over SHA-256(header[:49]) (includes the payload hash and the
    signed flag), raw r||s. Must match BlocklistStore::verifySignature."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    with open(key_path, 'rb') as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    r, s = decode_dss_signature(key.sign(header[:49], ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


def main():
    flags = {a for a in sys.argv[1:] if a.startswith('--')}
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    out = args[0] if args else 'blocklist.bin'
    sources = args[1:] or DEFAULT_SOURCES
    raw = '--raw' in flags
    version = 1 if raw or '--format=v1' in flags or '--v1' in flags else 2
    sign_key = next((a.split('=', 1)[1] for a in flags if a.startswith('--sign=')), None)
    if sign_key and raw:
        sys.exit('--raw lists have no header and cannot be signed')

    domains = parse(sources, '--allow-missing' in flags)
    hashes = sorted({fnv(d.encode()) for d in domains})
    payload = payload_v1(hashes) if version == 1 else payload_v2(hashes)

    with open(out, 'wb') as f:
        if not raw:
            flags_byte = 0x01 if sign_key else 0x00  # reserved[0] bit 0 = signed
            header = struct.pack('<4sBBHII32sB15s', b'SHBL', version, HASH_BYTES, 64, len(hashes),
                                 int(time.time()), hashlib.sha256(payload).digest(), flags_byte, b'\0' * 15)
            assert len(header) == 64
            f.write(header)
        f.write(payload)
        if sign_key:
            f.write(sign_header(header, sign_key))

    n = len(hashes)
    print(f'source domains   : {len(domains):,}')
    print(f'hash entries     : {n:,}  (collisions: {len(domains) - n})')
    print(f'format           : {"raw v1 (esp32-c3-adblock)" if raw else f"SHBL v{version}"}'
          f'{", signed" if sign_key else ""}')
    print(f'file             : {os.path.getsize(out):,} bytes -> {out}')
    if version == 1:
        print(f'lookup           : ~{math.ceil(math.log2(max(n, 2)))} reads/query')
        print('fits             : 4 MB layout up to 144,166 / 8 MB layout up to 511,168')
    else:
        print('fits             : 4 MB layout up to 218,090 / 8 MB layout up to 829,760')


if __name__ == '__main__':
    main()
