#!/bin/sh

cd ../www
../src/merecat -p 8080 -l none

gzip -c main.css   > main.css.gz
gzip -c index.html > index.html.gz

sleep 1
