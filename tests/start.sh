#!/bin/sh -e

cd ../www

../src/merecat -n -p 8086 -l none -f ${srcdir}/../merecat.conf &
echo $! >/tmp/merecat.test

if [ ! -e main.css ]; then
    cp ${srcdir}/../www/main.css .
    cp ${srcdir}/../www/index.html .

    echo "main.css index.html" >/tmp/merecat.files
fi

gzip -c main.css   > main.css.gz
gzip -c index.html > index.html.gz

sleep 1
