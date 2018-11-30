#!/bin/sh -e

if [ x"${srcdir}" = x ]; then
    srcdir=.
fi

cd ../www

../src/merecat -n -l none -p 8086 &
echo $! >/tmp/merecat.test

if [ ! -e main.css ]; then
    cp ${srcdir}/../www/main.css .
    cp ${srcdir}/../www/index.html .

    echo "main.css index.html" >/tmp/merecat.files
fi

gzip -c main.css   > main.css.gz
gzip -c index.html > index.html.gz

sleep 1
