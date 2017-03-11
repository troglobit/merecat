Merecat httpd ∴ Small Simple Speedy Server
==========================================
[![Travis Status][]][Travis]

<img align="right" width="500" src="www/img/merecat.jpg">

[Merecat][] started out as a pun at [Mongoose][], but is now useful for
actual web serving purposes.  It is however not a real [Meerkat][],
merely yet another copycat, forked from the great [thttpd][] created by
Jef&nbsp;Poskanzer.

The limited feature set makes it very quick.  This small footprint makes
Merecat suitable for small and embedded systems, even those smaller than
a Raspberry Pi:

- Virtual hosts
- URL-traffic-based throttling
- HTTP/1.1 Keep-alive
- Built-in gzip deflate using zlib
- HTTPS support using OpenSSL

For questions see the included `merecat(8)` man page or the [FAQ][].

Merecat is free software under the simplified 2-clause [BSD license][license].


Authentication
--------------

To protect a directory in your `~USERNAME/public_html/`, create a simple
`.htpasswd` file using the included `htpasswd` tool:

    cd ~/public_html/Downloads
    htpasswd -c .htpasswd friend
	Changing password for user friend
    New password: *****
    Re-type new password: *****


Virtual Hosts
-------------

Setting up virtual hosts on a server can be a bit of a hassle with other
web servers.  With Merecat you simply create directories for each host
in the web server root:

     /var/www/
       |-- icons/
       |-- cgi-bin/
       |-- errors/
       |    `-- err404.html
       |-- ftp.example.com/
       `-- www.example.com/

Edit `/etc/merecat.conf`:

    virtual-host = true
    cgi-pattern = /cgi-bin/*|**.cgi

Now the web server root, `/var/www/`, no longer serves files, only
virtual host directories do, execpt for the shared files in `icons/`,
`cgi-bin/`, and `errors/`.

On Linux bind mounts can be used to set up FTP and web access to the
same files. Example `/etc/fstab`:

    /srv/ftp  /var/www/ftp.example.com  none  defaults,bind  0  0


Optimizing Performance
----------------------

There are many tricks to optimizing the performance of your web server.
One of the most important ones is browser caching.  Merecat supports
both `ETag:` and `Cache-Control:`, however to enable the latter you need
to define the `max-age` setting in `/etc/merecat.conf`:

    max-age = 3600        # One hour

The value is completely site dependent.  For an embedded system you
might want to set it to the maximum value, whereas for other scenarios
you will likely want something else.  By default this is disabled (0).

Another trick is to employ `gzip` compression.  Merecat has built-in
support for serving HTML, CSS, and other `text/*` files if there is a
`.gz` version of the same file.  Here is an example of how to compress
relevant files:

    $ cd /var/www/
    $ for file in `find . -name '*.html' -o -name '*.css'`; do \
          gzip -c $file > $file.gz; done


Build Requirements
------------------

Merecat depends on [libConfuse](https://github.com/martinh/libconfuse/)
which, if built from source, by default installs to `/usr/local`.  Non
Debian/Ubuntu systems rarely support this GNU standard, so this is how
you reference it for the Merecat `configure` script:

    PKG_CONFIG_LIBDIR=/usr/local/lib/pkgconfig ./configure

To build Merecat without support for `/etc/merecat.conf`:

    ./configure --without-config

If you build from GIT sources and not a released tarball, then remember:

    ./autogen.sh

To install `httpd` into `/usr/sbin/`, default index and icons into
`/var/www`, and config file to `/etc/merecat.conf`:

    ./configure --prefix=/usr --localstatedir=/var --sysconfdir=/etc
    make
    sudo make install


Features
--------

Merecat consists of a front-end, `merecat.c`, and a standalone HTTP
library, `libhttpd.c`, which can be tweaked in various ways and used
for embedding a web server in another applications if needed.

The most common options are available from the `merecat` command line
and the `merecat.conf` configuration file.  Other, less common options,
can be enabled using the `configure` script:

    --enable-htaccess      Enable .htaccess files for access control
    --enable-htpasswd      Enable .htpasswd files for authentication
    --enable-public-html   Enable $HOME/public_html as ~USERNAME/
    --enable-msie-padding  Enforce padding of httdp error messages
                           sent to Internet Explorer, otherwise it will
                           detect too short msg and display its own.
    --without-config       Disable /etc/merecat.conf support using libConfuse
    --without-ssl          Disable HTTPS support, default: enabled
    --without-zlib         Disable mod_deflate (gzip) using zlib

The source file `merecat.h` has even more features that can be tweaked,
some of those are mentioned in the man page, but the header file has
very useful comments as well.


Origin & References
-------------------

Merecat is a stiched up fork of [sthttpd][] with lots of lost patches
found lying around the web.  The sthttpd project is a fork from the
original [thttpd][] -- the tiny/turbo/throttling HTTP server.

* [thttpd][] was created by Jef Poskanzer <mailto:jef@mail.acme.com>
* [sthttpd][] was spawned by Anthony G. Basile <mailto:blueness@gentoo.org>
* [Merecat][] is maintained by Joachim Nilsson <mailto:troglobit@gmail.com>

[Merecat]:       http://merecat.troglobit.com
[Meerkat]:       https://en.wikipedia.org/wiki/Meerkat
[license]:       https://github.com/troglobit/merecat/blob/master/LICENSE
[Mongoose]:      https://github.com/cesanta/mongoose
[FAQ]:           http://halplant.com:2001/server/thttpd_FAQ.html
[thttpd]:        http://www.acme.com/software/thttpd/
[sthttpd]:       https://github.com/blueness/sthttpd/
[Travis]:        https://travis-ci.org/troglobit/merecat
[Travis Status]: https://travis-ci.org/troglobit/merecat.png?branch=master
