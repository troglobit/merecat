#!/bin/sh
# Quick preview of the Merecat default landing page.
# Starts a local merecat instance serving www/ and opens a browser.
#
# Usage: ./preview.sh [PORT]

PORT=${1:-8080}
TOPDIR=$(cd "$(dirname "$0")" && pwd)
WEBROOT="$TOPDIR/www"
MERECAT="$TOPDIR/src/merecat"

if [ ! -x "$MERECAT" ]; then
    echo "error: merecat binary not found at $MERECAT"
    echo "       run 'make' first"
    exit 1
fi

# Pick a browser to open
for browser in xdg-open open firefox chromium-browser chromium google-chrome; do
    if command -v $browser >/dev/null 2>&1; then
        BROWSER=$browser
        break
    fi
done

CONF=$(mktemp /tmp/merecat-preview.XXXXXX.conf)
cat > "$CONF" << EOF
server default {
    port = $PORT
}
EOF

cleanup() {
    echo ""
    echo "Stopping merecat (pid $PID) ..."
    kill "$PID" 2>/dev/null
    wait "$PID" 2>/dev/null
    rm -f "$CONF"
}
trap cleanup INT TERM EXIT

echo "Starting merecat on http://localhost:$PORT ..."
"$MERECAT" -n -l warning -f "$CONF" "$WEBROOT" &
PID=$!

sleep 0.3
if ! kill -0 "$PID" 2>/dev/null; then
    echo "error: merecat failed to start (port $PORT in use?)"
    exit 1
fi

if [ -n "$BROWSER" ]; then
    echo "Opening browser ($BROWSER) ..."
    $BROWSER "http://localhost:$PORT/" 2>/dev/null &
else
    echo "No browser found — open http://localhost:$PORT/ manually"
fi

echo "Press Ctrl-C to stop."
wait "$PID"
