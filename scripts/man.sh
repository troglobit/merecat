#!/bin/sh -e
# Generates HTML versions of man pages using mandoc

GEN=`which mandoc`
TOP=`git rev-parse --show-toplevel`
HEAD=$TOP/www/header.html
FOOT=$TOP/www/footer.html
for file in `ls $TOP/man/*.[158]`; do
    name=`basename $file`
    web=$TOP/www/$name.html
    echo "Updating $web ..."
    cat $HEAD                        >  $web
    mandoc -T html -O fragment $file >> $web
    cat $FOOT                        >> $web
    sed -i "s/%TITLE%/$name/"           $web
done
