#!/usr/bin/env python3
"""UI development server: serves www/index.html from disk and proxies /api/* to a
running device, so the web UI can be edited and reloaded without reflashing.

  python tools/dev_server.py --device 192.168.18.23 [--port 8088]
  (login from SINKHOLE_USER / SINKHOLE_PASS, default admin / sinkhole)

Then open http://localhost:8088/
"""
import argparse
import base64
import http.server
import os
import urllib.error
import urllib.request

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'www')


def make_handler(device, auth):
    class Handler(http.server.BaseHTTPRequestHandler):
        def _proxy(self, method):
            length = int(self.headers.get('Content-Length') or 0)
            body = self.rfile.read(length) if length else None
            req = urllib.request.Request(f'http://{device}{self.path}', data=body, method=method)
            req.add_header('Authorization', auth)
            for h in ('Content-Type', 'X-Requested-With'):
                if self.headers.get(h):
                    req.add_header(h, self.headers[h])
            try:
                with urllib.request.urlopen(req, timeout=30) as r:
                    status, data, ctype = r.status, r.read(), r.headers.get('Content-Type', '')
            except urllib.error.HTTPError as e:
                status, data, ctype = e.code, e.read(), e.headers.get('Content-Type', '')
            except OSError as e:
                status, data, ctype = 502, f'{{"ok":false,"message":"device unreachable: {e}"}}'.encode(), 'application/json'
            self.send_response(status)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path.startswith('/api/'):
                return self._proxy('GET')
            with open(os.path.join(ROOT, 'index.html'), 'rb') as f:
                data = f.read()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            self._proxy('POST')

        def log_message(self, fmt, *args):
            pass

    return Handler


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--device', required=True, help='device IP or hostname')
    ap.add_argument('--port', type=int, default=8088)
    a = ap.parse_args()
    cred = f"{os.environ.get('SINKHOLE_USER', 'admin')}:{os.environ.get('SINKHOLE_PASS', 'sinkhole')}"
    auth = 'Basic ' + base64.b64encode(cred.encode()).decode()
    srv = http.server.ThreadingHTTPServer(('127.0.0.1', a.port), make_handler(a.device, auth))
    print(f'UI on http://localhost:{a.port}/  ->  API on http://{a.device}/')
    srv.serve_forever()


if __name__ == '__main__':
    main()
