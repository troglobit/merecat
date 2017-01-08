Merecat httpd ∴ Small Simple Speedy Server
==========================================
[![Travis Status][]][Travis]

<img align="right" width="500" src="www/img/merecat.jpg">

[Merecat][] started out as a pun at [Mongoose][], but is now useful for
actual web serving purposes.  It is however not a real [Meerkat][],
merely yet another copycat, forked from the great [thttpd][] created by
Jef&nbsp;Poskanzer.

The limited feature set makes it very quick.  Virtual hosts and the
URL-traffic-based throttling are just about its only features.  This
small footprint makes Merecat very suitable for small and embedded
systems, even those smaller than a Raspberry Pi.

For questions see the included `merecat(8)` man page or the [FAQ][].

Merecat is free software under the simplified 2-clause [BSD license][license].


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


Origin & References
-------------------

Merecat is a fork of [sthttpd][], which in turn is a fork of the
original [thttpd][] -- the tiny/turbo/throttling HTTP server.

* [thttpd][] was written by Jef Poskanzer <mailto:jef@mail.acme.com>
* [sthttpd][] was created by Anthony G. Basile <mailto:blueness@gentoo.org>


[Merecat]:       http://merecat.troglobit.com
[Meerkat]:       https://en.wikipedia.org/wiki/Meerkat
[license]:       https://github.com/troglobit/merecat/blob/master/LICENSE
[Mongoose]:      https://github.com/cesanta/mongoose
[FAQ]:           http://halplant.com:2001/server/thttpd_FAQ.html
[thttpd]:        http://www.acme.com/software/thttpd/
[sthttpd]:       https://github.com/blueness/sthttpd/
[Travis]:        https://travis-ci.org/troglobit/merecat
[Travis Status]: https://travis-ci.org/troglobit/merecat.png?branch=master

<!--
  -- Local Variables:
  -- mode: markdown
  -- End:
  -->
