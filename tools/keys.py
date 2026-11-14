#!/usr/bin/env python3
"""Signing keys for esp-dns-sinkhole (needs: pip install cryptography).

  python tools/keys.py blocklist-key keys/blocklist_signing.pem
      ECDSA P-256 key for signing blocklists. Prints the public key line for
      sdkconfig (CONFIG_SINKHOLE_BLOCKLIST_PUBKEY).

  python tools/keys.py firmware-key keys/firmware_signing.pem
      RSA-3072 key for signed firmware (boards/signed-firmware.defaults).

  python tools/keys.py pubkey keys/blocklist_signing.pem
      Print the public key line again.

Keep the private keys out of git (keys/ is ignored). For CI, store them as
repository secrets.
"""
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def write_key(key, path):
    if os.path.exists(path):
        sys.exit(f'{path} exists; not overwriting a key')
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    with open(path, 'wb') as f:
        f.write(pem)
    print(f'wrote {path}')


def blocklist_pubkey_line(path):
    with open(path, 'rb') as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    point = key.public_key().public_bytes(serialization.Encoding.X962,
                                          serialization.PublicFormat.UncompressedPoint)
    return f'CONFIG_SINKHOLE_BLOCKLIST_PUBKEY="{point.hex()}"'


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in ('blocklist-key', 'firmware-key', 'pubkey'):
        sys.exit(__doc__)
    cmd, path = sys.argv[1], sys.argv[2]
    if cmd == 'blocklist-key':
        write_key(ec.generate_private_key(ec.SECP256R1()), path)
        print(blocklist_pubkey_line(path))
    elif cmd == 'firmware-key':
        write_key(rsa.generate_private_key(public_exponent=65537, key_size=3072), path)
    else:
        print(blocklist_pubkey_line(path))


if __name__ == '__main__':
    main()
