#!/bin/sh
# Verify proxy-pass directive: forwarding, header injection, path stripping,
# query string and POST body forwarding, and proxy-redirect header rewriting.

set -ex

# Start a minimal Python HTTP backend on port 9090.
# - GET /redir/** returns a 302 with a Location: pointing back to the backend.
# - All other GETs echo the request path and proxy headers as JSON.
python3 - <<'EOF' &
import hashlib, http.server, json

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        data = self.rfile.read(length)
        body = json.dumps({
            "path": self.path,
            "len":  len(data),
            "sha":  hashlib.sha256(data).hexdigest(),
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

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

# Pass 1/11: request is forwarded and response comes from the backend
echo "Pass 1/11"
curl -s http://localhost:8086/proxy/hello | grep '"path".*"/proxy/hello"'

# Pass 2/11: X-Forwarded-For and X-Real-IP headers are injected.
# Use 127.0.0.1 explicitly to guarantee an IPv4 loopback address.
echo "Pass 2/11"
curl -s http://127.0.0.1:8086/proxy/test | grep '"x-forwarded-for".*"127.0.0.1"'
curl -s http://127.0.0.1:8086/proxy/test | grep '"x-real-ip".*"127.0.0.1"'

# Pass 3/11: path prefix stripped when backend URL carries a path component
#   GET /v2proxy/hello -> GET /v2/hello forwarded to backend
echo "Pass 3/11"
curl -s http://localhost:8086/v2proxy/hello | grep '"path".*"/v2/hello"'

# Pass 4/11: path prefix stripped when backend URL has a trailing slash only
#   GET /strip/hello -> GET /hello forwarded to backend
echo "Pass 4/11"
curl -s http://localhost:8086/strip/hello | grep '"path".*"/hello"'

# Pass 5/11: proxy-redirect rewrites Location: header in backend response
#   Backend returns: Location: http://localhost:9090/redir/foo/target
#   Merecat rewrites:          Location: http://localhost:8086/redir/foo/target
echo "Pass 5/11"
loc=$(curl -s -o /dev/null -D - http://localhost:8086/redir/foo | grep -i '^Location:')
echo "$loc" | grep "http://localhost:8086/redir/foo/target"

# Pass 6/11: query string is forwarded exactly once
#   GET /proxy/search?q=foo&n=2 -> same path and query on the backend
echo "Pass 6/11"
curl -s 'http://localhost:8086/proxy/search?q=foo&n=2' | grep '"path".*"/proxy/search?q=foo&n=2"'

# Pass 7/11: query string survives path prefix stripping
#   GET /v2proxy/search?q=bar -> GET /v2/search?q=bar on the backend
echo "Pass 7/11"
curl -s 'http://localhost:8086/v2proxy/search?q=bar' | grep '"path".*"/v2/search?q=bar"'

# Pass 8/11: POST body larger than one read() arrives complete at the backend
#   1 MiB body cannot fit in the socket buffers with the headers, so this
#   exercises the request body buffering (CNST_PROXY_BODY) path.
echo "Pass 8/11"
body=$(mktemp)
head -c 1048576 /dev/urandom > "$body"
sha=$(sha256sum "$body" | cut -d' ' -f1)
resp=$(curl -s --data-binary @"$body" http://localhost:8086/proxy/upload)
rm -f "$body"
echo "$resp" | grep '"len": 1048576'
echo "$resp" | grep "\"sha\": \"$sha\""

# Pass 9/11: POST body over the 8 MiB cap is rejected with 413 up front
echo "Pass 9/11"
code=$(head -c 9437184 /dev/zero | curl -s -o /dev/null -w '%{http_code}' \
	--data-binary @- http://localhost:8086/proxy/upload)
test "$code" = "413"

# Pass 10/11: backend that closes without sending anything yields 502
echo "Pass 10/11"
python3 - <<'EOF' &
import socket
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 9091)); srv.listen(8)
while True:
    c, _ = srv.accept()
    # Read the full request, then close without sending a byte: the
    # proxy sees a clean EOF (not RST) with an empty response buffer.
    req = b""
    while b"\r\n\r\n" not in req:
        data = c.recv(65536)
        if not data:
            break
        req += data
    c.close()
EOF
MUTE=$!
sleep 1
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://localhost:8086/dead/x || true)
kill $MUTE 2>/dev/null || true
test "$code" = "502"

# Pass 11/11: malformed proxy-redirect refuses to start instead of
# silently dropping the rule and serving /api/** from the docroot
echo "Pass 11/11"
badconf=$(mktemp)
cat > "$badconf" <<CONF
server bad {
    port = 8099
    proxy-pass "/api/**" {
        backend        = "http://localhost:9090"
        proxy-redirect = "http://localhost:9090"
    }
}
CONF
# Exit 1 = refused at startup (pass); 0 or 124 (still running when
# timeout fires) = started despite the malformed rule (fail)
timeout 5 ../src/merecat -f "$badconf" -n -l err srv && rc=0 || rc=$?
rm -f "$badconf"
test "$rc" != "0" && test "$rc" != "124"
