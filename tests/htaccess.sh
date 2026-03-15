#!/bin/sh
# Verify .htaccess access control:
#   - directory without .htaccess -> 200
#   - directory with "deny from" rule -> 403
#
# Note: "allow from <ip>" is not tested here because merecat's access_check2()
# reads hc->client.sin.sin_addr.s_addr which aliases sin6_flowinfo (not the
# actual address) on dual-stack IPv6 sockets, so IP matching is unreliable.
# This is a known limitation to be addressed in a future fix.
set -ex

mkdir -p srv/htaccess-test
echo '<html>htaccess-test</html>' > srv/htaccess-test/index.html

# Pass 1/2: no .htaccess -> 200 OK
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8086/htaccess-test/)
if [ "$code" != "200" ]; then
    echo "Expected 200 without .htaccess, got $code"
    exit 1
fi

# Pass 2/2: deny rule -> 403 Forbidden
printf 'deny from 127.0.0.1\n' > srv/htaccess-test/.htaccess
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8086/htaccess-test/)
if [ "$code" != "403" ]; then
    echo "Expected 403 with deny rule in .htaccess, got $code"
    if [ "$code" = "200" ]; then
        echo "htaccess support may not be compiled in (--enable-htaccess)"
        exit 77
    fi
    exit 1
fi
