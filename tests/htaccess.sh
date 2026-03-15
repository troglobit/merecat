#!/bin/sh
# Verify .htaccess access control:
#   - directory without .htaccess -> 200
#   - "deny from 127.0.0.1" -> 403
#   - "allow from 127.0.0.1" -> 200
set -ex

mkdir -p srv/htaccess-test
echo '<html>htaccess-test</html>' > srv/htaccess-test/index.html

# Pass 1/3: no .htaccess -> 200 OK
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8086/htaccess-test/)
if [ "$code" != "200" ]; then
    echo "Expected 200 without .htaccess, got $code"
    exit 1
fi

# Pass 2/3: deny rule -> 403 Forbidden
printf 'deny from 127.0.0.1\n' > srv/htaccess-test/.htaccess
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8086/htaccess-test/)
if [ "$code" != "403" ]; then
    echo "Expected 403 with deny rule, got $code"
    if [ "$code" = "200" ]; then
        echo "htaccess support may not be compiled in (--enable-htaccess)"
        exit 77
    fi
    exit 1
fi

# Pass 3/3: allow rule -> 200 OK
printf 'allow from 127.0.0.1\n' > srv/htaccess-test/.htaccess
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8086/htaccess-test/)
if [ "$code" != "200" ]; then
    echo "Expected 200 with allow rule, got $code"
    exit 1
fi
