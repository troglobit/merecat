#!/bin/sh
# Verify proxy-pass directive: forwarding, header injection, path stripping

set -ex

# Start a minimal Python HTTP backend on port 9090 that echoes the
# request path and selected proxy headers back as a JSON object.
python3 - <<'EOF' &
import http.server, json

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({
            "path":             self.path,
            "x-forwarded-for":  self.headers.get("X-Forwarded-For", ""),
            "x-real-ip":        self.headers.get("X-Real-IP",        ""),
            "x-forwarded-proto":self.headers.get("X-Forwarded-Proto", ""),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

http.server.HTTPServer(("127.0.0.1", 9090), Handler).serve_forever()
EOF
BACKEND=$!
trap "kill $BACKEND 2>/dev/null; true" EXIT
sleep 1

# Pass 1/3: request is forwarded and response comes from the backend
echo "Pass 1/3"
curl -s http://localhost:8086/proxy/hello | grep '"path".*"/proxy/hello"'

# Pass 2/3: X-Forwarded-For and X-Real-IP headers are injected.
# Use 127.0.0.1 explicitly to guarantee an IPv4 loopback address.
echo "Pass 2/3"
curl -s http://127.0.0.1:8086/proxy/test | grep '"x-forwarded-for".*"127.0.0.1"'
curl -s http://127.0.0.1:8086/proxy/test | grep '"x-real-ip".*"127.0.0.1"'

# Pass 3/4: path prefix stripped when backend URL carries a path component
#   GET /v2proxy/hello -> GET /v2/hello forwarded to backend
echo "Pass 3/4"
curl -s http://localhost:8086/v2proxy/hello | grep '"path".*"/v2/hello"'

# Pass 4/4: path prefix stripped when backend URL has a trailing slash only
#   GET /strip/hello -> GET /hello forwarded to backend
echo "Pass 4/4"
curl -s http://localhost:8086/strip/hello | grep '"path".*"/hello"'
