Merecat Web Server
==================

![I am only a mere cat web server](www/img/merecat.jpg "Day 37!")

[Merecat][] is a simple, small and fast HTTP server.  Once it was about
as fast as the best full-featured web servers, and even today it remains
sufficient for most use-case on the web.  It does not have a lot of
special features, except for one extremely useful -- URL-traffic-based
throttling -- something that few other web servers have.

With its small footprint it is very suitable for small and embedded
systems, even those smaller than a Raspberry Pi.

Merecat is released under the [simplified 2-clause BSD license][license].


Origin & References
-------------------

Merecat is a pun at [Mongoose][], and is not even a real Meerkat, merely
a fork of [sthttpd][] by Anthony G. Basile, which in turn is a fork of
[thttpd][] -- the tiny/turbo/throttling HTTP server.

* [thttpd][] was written by Jef Poskanzer <mailto:jef@mail.acme.com>
* [sthttpd][] was created by Anthony G. Basile <mailto:blueness@gentoo.org>


[Merecat]:  https://github.com/troglobit/merecat/
[license]:  https://github.com/troglobit/merecat/blob/master/LICENSE
[Mongoose]: https://github.com/cesanta/mongoose 
[thttpd]:   http://www.acme.com/software/thttpd/
[sthttpd]:  https://github.com/blueness/sthttpd/


