#!/usr/bin/env python3
"""Test the optional home-network DHCP server (no dependencies).

  python tools/dhcp_probe.py 192.168.1.50 --mac aa:bb:cc:dd:ee:ff   (unicast, default)
  python tools/dhcp_probe.py 192.168.1.50 --broadcast

Unicast mode talks only to the device: DISCOVER, REQUEST and RELEASE go to
<server>:67 with this PC's own IP in ciaddr, so the server answers by unicast
to this PC and nothing is broadcast to the rest of the network. Pass the MAC of
the network card that has that IP (ipconfig /all, ip link): the server sends
its replies to the MAC in the request, so a wrong MAC means no visible reply
(the device's status page still counts the requests and offers). The lease it
gets is released at the end.

Broadcast mode behaves like a real new device: broadcast DISCOVER from a made-up
MAC with the broadcast flag, so every DHCP server on the network answers and
the replies are broadcast. Shows whether the device's answers get through the
Wi-Fi access point (some routers drop DHCP server traffic from Wi-Fi clients).
Run it only next to a router whose DHCP is off, or briefly with a small pool
outside the router's range. Port 68 must be free (stop a local DHCP client if
binding fails).
"""
import argparse
import random
import socket
import struct
import sys
import time

DISCOVER, OFFER, REQUEST, DECLINE, ACK, NAK, RELEASE = 1, 2, 3, 4, 5, 6, 7
NAMES = {OFFER: 'OFFER', ACK: 'ACK', NAK: 'NAK'}


def mac_bytes(text):
    b = bytes(int(x, 16) for x in text.replace('-', ':').split(':'))
    if len(b) != 6:
        raise argparse.ArgumentTypeError('MAC must have 6 bytes')
    return b


def packet(xid, mac, msg_type, ciaddr, broadcast, opts=b''):
    p = struct.pack('>BBBBIHH4s4s4s4s16s64s128s', 1, 1, 6, 0, xid, 0, 0x8000 if broadcast else 0,
                    socket.inet_aton(ciaddr), b'\0' * 4, b'\0' * 4, b'\0' * 4, mac + b'\0' * 10, b'', b'')
    return p + b'\x63\x82\x53\x63' + bytes([53, 1, msg_type]) + opts + b'\xff'


def parse(d, xid):
    if len(d) < 240 or d[0] != 2 or struct.unpack('>I', d[4:8])[0] != xid:
        return None
    i, o = 240, {}
    while i + 1 < len(d) and d[i] != 255:
        if d[i] == 0:
            i += 1
            continue
        o[d[i]] = d[i + 2:i + 2 + d[i + 1]]
        i += 2 + d[i + 1]
    ip = lambda b: socket.inet_ntoa(b[:4]) if b and len(b) >= 4 else '-'
    return {'type': o.get(53, b'\0')[0], 'yiaddr': socket.inet_ntoa(d[16:20]), 'server': ip(o.get(54)),
            'router': ip(o.get(3)), 'dns': ip(o.get(6)), 'mask': ip(o.get(1)),
            'lease_s': struct.unpack('>I', o[51])[0] if 51 in o and len(o[51]) == 4 else None}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('server', help="the device's static IP")
    ap.add_argument('--mac', type=mac_bytes, help="this PC's MAC (unicast mode)")
    ap.add_argument('--broadcast', action='store_true', help='behave like a new device (see above)')
    ap.add_argument('--src-port', type=int, default=68,
                    help='send from this port instead of 68 (replies are still awaited on 68). Some routers '
                         "drop DHCP client traffic (to port 67, or 68 -> 67) on its way to Wi-Fi clients; "
                         'another source port gets requests past that filter to test the replies on their own')
    a = ap.parse_args()

    xid = random.getrandbits(32)
    if a.broadcast:
        mac = bytes([0x02, 0x5e, 0x10]) + random.randbytes(3)  # locally administered
        myip, dst = '0.0.0.0', '255.255.255.255'
    else:
        if not a.mac:
            ap.error('unicast mode needs --mac (the MAC of the card that reaches the device)')
        mac = a.mac
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect((a.server, 67))
        myip = probe.getsockname()[0]
        probe.close()
        dst = a.server
    print(f"{'broadcast' if a.broadcast else 'unicast'} probe, client {myip} {mac.hex(':')}, server {a.server}")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        s.bind((myip if not a.broadcast else '0.0.0.0', 68))
    except OSError as e:
        sys.exit(f'cannot listen on port 68: {e}')
    s.settimeout(0.3)

    def collect(seconds, want):
        out, end = [], time.time() + seconds
        while time.time() < end:
            try:
                d, frm = s.recvfrom(2048)
            except socket.timeout:
                continue
            r = parse(d, xid)
            if r and r['type'] in want:
                r['from'] = frm[0]
                print(f"  {NAMES[r['type']]} from {frm[0]}: {r}")
                out.append(r)
        return out

    out = s
    if a.src_port != 68:
        out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        out.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        out.bind((myip if not a.broadcast else '0.0.0.0', a.src_port))
    send = lambda t, opts=b'': out.sendto(packet(xid, mac, t, myip, a.broadcast, opts), (dst, 67))

    send(DISCOVER, bytes([55, 4, 1, 3, 6, 51]))
    mine = [o for o in collect(4, {OFFER}) if o['server'] == a.server]
    if not mine:
        print(f'no OFFER from {a.server}. Check its status page: if "requests seen" went up, it answered and the '
              'reply got lost on the way (wrong --mac, or the access point drops it); if not, nothing reached it.')
        return 1
    offer = mine[0]['yiaddr']
    send(REQUEST, bytes([50, 4]) + socket.inet_aton(offer) + bytes([54, 4]) + socket.inet_aton(a.server))
    acks = [r for r in collect(3, {ACK, NAK}) if r['server'] == a.server]
    if not acks or acks[0]['type'] != ACK:
        print('no ACK for', offer)
        return 1
    # RELEASE goes straight to the server (RFC 2131), from the leased address.
    out.sendto(packet(xid, mac, RELEASE, offer, False, bytes([54, 4]) + socket.inet_aton(a.server)), (a.server, 67))
    print(f'OK: {offer} leased and released')
    return 0


if __name__ == '__main__':
    sys.exit(main())
