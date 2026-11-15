#!/usr/bin/env python3
"""Light minify + deterministic gzip (mtime=0) of a web asset for embedding.

Minification only strips leading/trailing whitespace per line and drops empty
lines, which is safe for www/index.html (no <pre>, no whitespace-sensitive strings).
"""
import gzip
import sys

src, dst = sys.argv[1], sys.argv[2]
with open(src, 'rb') as f:  # NOSONAR - developer tool: the path is a command-line argument chosen by the person running it
    text = f.read().decode('utf-8')
lines = (line.strip() for line in text.splitlines())
data = '\n'.join(line for line in lines if line).encode('utf-8')
with open(dst, 'wb') as f:  # NOSONAR - developer tool: the path is a command-line argument chosen by the person running it
    f.write(gzip.compress(data, compresslevel=9, mtime=0))
print(f'{src}: {len(text.encode())} -> {len(data)} bytes minified, '
      f'{len(gzip.compress(data, 9, mtime=0))} gzipped')
