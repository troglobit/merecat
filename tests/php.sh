#!/bin/sh
set -ex

# Skip if php-cgi is not installed
command -v php-cgi >/dev/null 2>&1 || exit 77

echo "<?php echo 'Hello ' . htmlspecialchars(\$_GET[\"name\"]) . '!'; ?>" >srv/test.php
ls srv
cat srv/test.php

curl http://localhost:8086/test.php?name=foobar 2>/dev/null |grep 'Hello foobar'
