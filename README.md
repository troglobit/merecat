Merecat Web Server
==================
[![Travis Status][]][Travis]

![I am only a mere cat web server](www/img/merecat.jpg "Day 37!")

[Merecat][] is a simple, small and fast HTTP server.  Once it was about
as fast as the best full-featured web servers, and even today it remains
sufficient for most use-cases on the web.  It does not have lots of
special features, except for URL-traffic-based throttling.

With its small footprint it is very suitable for small and embedded
systems, even those smaller than a Raspberry Pi.

For questions see the included man page or the [FAQ][].

Merecat is released under the [simplified 2-clause BSD license][license].


Build Requirements
------------------

Merecat depends on [libConfuse](https://github.com/martinh/libconfuse/)
which by default installs to `/usr/local`.  Non Debian/Ubuntu systems
rarely support this GNU standard, so this is how you reference it for
the Merecat `configure` script:

    PKG_CONFIG_LIBDIR=/usr/local/lib/pkgconfig ./configure

If you build from GIT sources and not a released tarball, then remember:

    ./autogen.sh


Origin & References
-------------------

Merecat is a pun at [Mongoose][], and is not even a real Meerkat, merely
a fork of [sthttpd][] by Anthony G. Basile, which in turn is a fork of
[thttpd][] -- the tiny/turbo/throttling HTTP server.

* [thttpd][] was written by Jef Poskanzer <mailto:jef@mail.acme.com>
* [sthttpd][] was created by Anthony G. Basile <mailto:blueness@gentoo.org>


[Merecat]:       https://github.com/troglobit/merecat/
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
