#!/bin/sh
# Verify proxy-pass directive: forwarding, header injection, path stripping,
# and proxy-redirect header rewriting.

set -ex

# Start a minimal Python HTTP backend on port 9090.
# - GET /redir/** returns a 302 with a Location: pointing back to the backend.
# - All other GETs echo the request path and proxy headers as JSON.
python3 - <<'EOF' &
import http.server, json

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/redir/"):
            # Return a redirect whose Location uses the backend's own address.
            # Merecat's proxy-redirect should rewrite it to the frontend URL.
            loc = "http://localhost:9090" + self.path + "/target"
            self.send_response(302)
            self.send_header("Location", loc)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

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

# Pass 1/5: request is forwarded and response comes from the backend
echo "Pass 1/5"
curl -s http://localhost:8086/proxy/hello | grep '"path".*"/proxy/hello"'

# Pass 2/5: X-Forwarded-For and X-Real-IP headers are injected.
# Use 127.0.0.1 explicitly to guarantee an IPv4 loopback address.
echo "Pass 2/5"
curl -s http://127.0.0.1:8086/proxy/test | grep '"x-forwarded-for".*"127.0.0.1"'
curl -s http://127.0.0.1:8086/proxy/test | grep '"x-real-ip".*"127.0.0.1"'

# Pass 3/5: path prefix stripped when backend URL carries a path component
#   GET /v2proxy/hello -> GET /v2/hello forwarded to backend
echo "Pass 3/5"
curl -s http://localhost:8086/v2proxy/hello | grep '"path".*"/v2/hello"'

# Pass 4/5: path prefix stripped when backend URL has a trailing slash only
#   GET /strip/hello -> GET /hello forwarded to backend
echo "Pass 4/5"
curl -s http://localhost:8086/strip/hello | grep '"path".*"/hello"'

# Pass 5/5: proxy-redirect rewrites Location: header in backend response
#   Backend returns: Location: http://localhost:9090/redir/foo/target
#   Merecat rewrites:          Location: http://localhost:8086/redir/foo/target
echo "Pass 5/5"
loc=$(curl -s -o /dev/null -D - http://localhost:8086/redir/foo | grep -i '^Location:')
echo "$loc" | grep "http://localhost:8086/redir/foo/target"
