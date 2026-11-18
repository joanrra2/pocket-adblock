#!/usr/bin/env python3
"""DNS benchmark for ad-blocking resolvers (no dependencies).

  python tools/dns_bench.py 192.168.1.50 [--label name] [--json out.json]

Tests (each with fresh random names so caches can't help unless intended):
  blocked     300 sequential queries for <random>.doubleclick.net (on every list)
  repeat      200 sequential queries for the same allowed name (cache vs forward)
  throughput  16 parallel clients sending blocked queries for 5 s
  hol         blocked-query latency while uncached names wait on the upstream
              (a resolver that forwards one query at a time stalls here)
  burst       a page load: 32 blocked names sent at once from one socket, 20 times;
              how many are lost and how long until the last answer arrives
  cached      200 sequential queries spread over 50 allowed names (answer cache,
              including names whose answers carry CNAMEs)
  expired     first lookup of 30 names right after their cached answers expired
              (only meaningful on a build whose cache keeps answers <= 30 s)
Uncached upstream traffic is kept small (~40 names) to stay polite to public resolvers.
"""
import argparse
import json
import random
import socket
import statistics
import struct
import threading
import time

TIMEOUT = 2.0


def query(sock, server, name, qtype=1):
    tid = random.randint(0, 0xFFFF)
    pkt = struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0)
    pkt += b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\0' + struct.pack('>HH', qtype, 1)
    t0 = time.perf_counter()
    sock.sendto(pkt, server)
    deadline = t0 + TIMEOUT
    while True:
        left = deadline - time.perf_counter()
        if left <= 0:
            return None
        sock.settimeout(left)
        try:
            data, _ = sock.recvfrom(2048)
        except socket.timeout:
            return None
        if len(data) >= 2 and struct.unpack('>H', data[:2])[0] == tid:
            return (time.perf_counter() - t0) * 1000


def stats(lat, total):
    ok = [x for x in lat if x is not None]
    if not ok:
        return {'answered': 0, 'total': total}
    ok.sort()
    pick = lambda q: ok[min(len(ok) - 1, int(q * len(ok)))]
    return {'answered': len(ok), 'total': total, 'p50': round(pick(.5), 2), 'p95': round(pick(.95), 2),
            'p99': round(pick(.99), 2), 'max': round(ok[-1], 2), 'mean': round(statistics.mean(ok), 2)}


def rnd(n=10):
    return ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(n))


def new_sock():
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def test_blocked(server, n=300):
    s = new_sock()
    return stats([query(s, server, f'{rnd()}.doubleclick.net') for _ in range(n)], n)


def test_repeat(server, n=200, name='example.com'):
    s = new_sock()
    query(s, server, name)  # warm up
    return stats([query(s, server, name) for _ in range(n)], n)


def test_throughput(server, workers=16, seconds=5.0):
    lat, lock, stop = [], threading.Lock(), time.perf_counter() + seconds

    def worker():
        s = new_sock()
        mine = []
        while time.perf_counter() < stop:
            mine.append(query(s, server, f'{rnd()}.doubleclick.net'))
        with lock:
            lat.extend(mine)

    th = [threading.Thread(target=worker) for _ in range(workers)]
    t0 = time.perf_counter()
    for t in th:
        t.start()
    for t in th:
        t.join()
    r = stats(lat, len(lat))
    r['qps'] = round(r['answered'] / (time.perf_counter() - t0), 1)
    r['lost'] = len(lat) - r['answered']
    return r


def test_burst(server, size=32, rounds=20):
    """Like a browser loading a page: many lookups at once. A resolver that can
    only queue a few packets drops the rest, and those clients retry after ~1 s."""
    s = new_sock()
    lost, last, firsts = 0, [], []
    for _ in range(rounds):
        want = {}
        t0 = time.perf_counter()
        for _ in range(size):
            tid = random.randint(0, 0xFFFF)
            name = f'{rnd()}.doubleclick.net'
            pkt = struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0)
            pkt += b''.join(bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\0' + struct.pack('>HH', 1, 1)
            want[tid] = True
            s.sendto(pkt, server)
        got, t_last, t_first = 0, None, None
        deadline = t0 + TIMEOUT
        while got < size and time.perf_counter() < deadline:
            s.settimeout(max(0.001, deadline - time.perf_counter()))
            try:
                data, _ = s.recvfrom(2048)
            except socket.timeout:
                break
            tid = struct.unpack('>H', data[:2])[0]
            if want.pop(tid, None):
                got += 1
                t_last = (time.perf_counter() - t0) * 1000
                t_first = t_first or t_last
        lost += size - got
        if got == size:
            last.append(t_last)
        if t_first:
            firsts.append(t_first)
        time.sleep(0.2)
    r = {'rounds': rounds, 'size': size, 'lost': lost, 'complete_rounds': len(last)}
    if last:
        r['all_answered_p50'] = round(statistics.median(last), 2)
        r['all_answered_max'] = round(max(last), 2)
    return r


def test_expired(server, wait=36):
    """First lookup of a name whose cached answer just expired (needs a build
    whose cache keeps answers at most 30 s). Without serve-stale it goes to the
    upstream again; with it the old answer comes back at once and is refreshed."""
    names = ['www.microsoft.com', 'www.apple.com', 'www.amazon.com', 'www.bbc.co.uk', 'www.cloudflare.com',
             'www.mozilla.org', 'www.python.org', 'en.wikipedia.org', 'www.reddit.com', 'www.netflix.com',
             'www.spotify.com', 'www.linkedin.com', 'www.paypal.com', 'www.ebay.com', 'www.twitch.tv',
             'www.nytimes.com', 'www.theguardian.com', 'www.elpais.com', 'www.rtve.es', 'stackoverflow.com',
             'www.debian.org', 'www.kernel.org', 'www.adobe.com', 'www.dropbox.com', 'www.slack.com',
             'www.imdb.com', 'www.booking.com', 'www.samsung.com', 'www.intel.com', 'www.nvidia.com']
    s = new_sock()
    for name in names:
        query(s, server, name)
    time.sleep(wait)
    first = [query(s, server, name) for name in names]
    time.sleep(1)
    again = [query(s, server, name) for name in names]
    return {'first_after_expiry': stats(first, len(names)), 'next': stats(again, len(names))}


def test_cached(server, n=200):
    """Allowed names answered from the cache (each looked up once first)."""
    names = ['example.com', 'wikipedia.org', 'github.com', 'www.microsoft.com', 'www.apple.com',
             'www.amazon.com', 'www.bbc.co.uk', 'www.cloudflare.com', 'www.mozilla.org', 'www.python.org',
             'en.wikipedia.org', 'www.reddit.com', 'www.youtube.com', 'www.netflix.com', 'www.spotify.com',
             'outlook.office.com', 'www.linkedin.com', 'www.paypal.com', 'www.ebay.com', 'www.twitch.tv',
             'www.nytimes.com', 'www.theguardian.com', 'www.elpais.com', 'www.lavanguardia.com', 'www.rtve.es',
             'www.wordpress.com', 'stackoverflow.com', 'www.debian.org', 'www.kernel.org', 'www.gnu.org',
             'www.adobe.com', 'www.dropbox.com', 'www.zoom.us', 'www.slack.com', 'www.whatsapp.com',
             'www.instagram.com', 'www.facebook.com', 'www.x.com', 'www.tiktok.com', 'www.pinterest.com',
             'www.imdb.com', 'www.booking.com', 'www.airbnb.com', 'www.uber.com', 'www.tesla.com',
             'www.samsung.com', 'www.sony.com', 'www.intel.com', 'www.amd.com', 'www.nvidia.com']
    s = new_sock()
    for name in names:
        query(s, server, name)  # warm up (forwarded once)
    return stats([query(s, server, names[i % len(names)]) for i in range(n)], n)


def test_hol(server, uncached=40, blocked=200):
    fwd, done = [], threading.Event()

    def forwarder():
        s = new_sock()
        for _ in range(uncached):
            fwd.append(query(s, server, f'sk{rnd()}.wikipedia.org'))  # NXDOMAIN, but must go upstream
        done.set()

    t = threading.Thread(target=forwarder)
    t.start()
    s, lat = new_sock(), []
    while not done.is_set() and len(lat) < blocked:
        lat.append(query(s, server, f'{rnd()}.doubleclick.net'))
    t.join()
    return {'blocked_during_upstream_load': stats(lat, len(lat)), 'uncached_forwarded': stats(fwd, uncached)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('server')
    ap.add_argument('--port', type=int, default=53)
    ap.add_argument('--label', default='')
    ap.add_argument('--json')
    ap.add_argument('--tests', default='blocked,repeat,throughput,hol')
    a = ap.parse_args()
    server = (a.server, a.port)
    res = {'label': a.label, 'server': a.server}
    for name in a.tests.split(','):
        res[name] = globals()[f'test_{name}'](server)
        print(f'{a.label} {name}: {json.dumps(res[name])}', flush=True)
        time.sleep(1)
    if a.json:
        with open(a.json, 'w') as f:  # NOSONAR - developer tool: the path is a command-line argument chosen by the person running it
            json.dump(res, f, indent=2)


if __name__ == '__main__':
    main()
