#!/usr/bin/env python3
from http.server import SimpleHTTPRequestHandler, HTTPServer
import json
import os

PORT = int(os.environ.get("PORT", 8000))

class Handler(SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/verify":
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8') if length else "{}"
            try:
                data = json.loads(body)
            except Exception:
                data = {}
            # Simple demo rule: if both fields are non-empty, return a demo PDF link
            valid = bool(data.get("serial_number")) and bool(data.get("national_id"))
            resp = {
                "valid": valid,
                "download_url": "/sample.pdf" if valid else ""
            }
            j = json.dumps(resp).encode('utf-8')
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(j)))
            self.end_headers()
            self.wfile.write(j)
        else:
            self.send_response(404)
            self.end_headers()

    # Serve index.html as default for '/'
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            return super().do_GET()
        return super().do_GET()

if __name__ == "__main__":
    os.chdir(os.path.dirname(__file__) or ".")
    with HTTPServer(("", PORT), Handler) as httpd:
        print(f"Serving on http://localhost:{PORT}")
        httpd.serve_forever()
