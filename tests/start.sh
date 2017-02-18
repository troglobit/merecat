#!/bin/sh -e

cd ../www
../src/merecat -n -p 8080 -l none &

gzip -c main.css   > main.css.gz
gzip -c index.html > index.html.gz

sleep 1
