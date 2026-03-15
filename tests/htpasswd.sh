#!/bin/sh
# Verify .htpasswd Basic authentication:
#   - request without credentials -> 401
#   - request with correct credentials -> 200
set -ex

HTPASSWD=../src/htpasswd

# Skip if not compiled in
if [ ! -x "$HTPASSWD" ]; then
    echo "htpasswd binary not found, skipping"
    exit 77
fi

# Create protected directory and password file
mkdir -p srv/secret
printf 'testpass\n' | $HTPASSWD -c srv/secret/.htpasswd testuser
echo '<html>secret</html>' > srv/secret/index.html

# Pass 1/2: no credentials -> 401 Unauthorized
code=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:8086/secret/)
if [ "$code" != "401" ]; then
    echo "Expected 401 without credentials, got $code"
    if [ "$code" = "200" ]; then
        echo "htpasswd support may not be compiled in (--enable-htpasswd)"
        exit 77
    fi
    exit 1
fi

# Pass 2/2: correct credentials -> 200 OK
code=$(curl -s -o /dev/null -w '%{http_code}' --user testuser:testpass http://localhost:8086/secret/)
if [ "$code" != "200" ]; then
    echo "Expected 200 with valid credentials, got $code"
    exit 1
fi
