if [ ! -x configure ]; then
    ./autogen.sh
fi

./configure --prefix=/usr --localstatedir=/var --sysconfdir=/etc --enable-builtin-icons \
	    --without-config --without-ssl --without-symlinks --enable-htaccess --enable-htpasswd

make -j5 clean
make -j5
