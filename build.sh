#!/bin/sh
./autogen.sh
./configure --prefix=/usr --localstatedir=/var --sysconfdir=/etc --enable-builtin-icons \
	    --without-config --without-ssl --without-symlinks --enable-htaccess --enable-htpasswd

make clean
make -j5
