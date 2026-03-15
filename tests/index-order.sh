#!/bin/sh
# Verify index file precedence: when multiple index files exist merecat serves
# the highest-priority one (index.html > index.htm), and falls back to directory
# listing when none are present.
set -ex

# Pass 1/2: index.html takes priority over index.htm
mkdir -p srv/multiindex
echo '<html>this-is-html</html>' > srv/multiindex/index.html
echo '<html>this-is-htm</html>'  > srv/multiindex/index.htm
curl -s http://localhost:8086/multiindex/ | grep 'this-is-html'

# Pass 2/2: without any index file the listing is generated
mkdir -p srv/noindex
echo 'canary.txt' > srv/noindex/canary.txt
curl -s http://localhost:8086/noindex/ | grep -i '<table'
