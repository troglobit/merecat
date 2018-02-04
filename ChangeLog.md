Change Log
==========

All relevant changes are documented in this file.


[v2.32][] - 2018-02-XX
----------------------

Notable new features: HTTPS, HTTP/1.1 keep-alive, and built-in gzip
deflate compression using zlib.

### Changes
- Add Dockerfile for ease of deployment in limited setups
- Add gzip deflate compression when built with zlib, also compress HEAD
  as well as GET requests
- Add true `Connection: keep-alive` support
- Add missing `Vary: Accept-Encoding` header
- CGI: Allow `:PORT` in `HTTP_POST`, like Apache
- CGI: Allow trailing slash in `PATH_INFO`, like Apache
- CGI: Change default `CGI_PATTERN` from disabled to `**.cgi|/cgi-bin/*`
- Add support for `php-cgi` and `index.cgi` index file
- Dot files are no longer shown in dir listings, use the `merecat.conf`
  setting `list-dotfiles = true` to enable
- Server stats are no longer periodically sent to syslog, re-enable in
  `merecat.conf` if you need the `STATS_TIME` feature
- Add Debian `SIGBUS` patch for reading from NFS
- Add `-I IDENT` command line option to override program identity.  This
  change makes it possible to change syslog, PID file name, *and* the
  `.conf` file name.  Useful when running multiple instances of Merecat
- Add `--enable-msie-padding` to `configure` script
- Add `.htaccess` support, limited to IPv4.  Feature by Felix J. Ogris
- Allow `.htpasswd` file to be symlinked
- DOC: How to use `.htpasswd` and virtual hosts
- DOC: Added section on how to optimize performance
- Update MIME types, e.g. Ogg video, 7zip, svg
- Cute cat default favicon
- Refactor, deprecated POSIX API's, e.g. `bzero() --> memset()`

### Fixes
- Fixes for non GNU C libraries like musl: `__progname`, `%m`, etc.
- Fix `X-Forwarded-For` when using IPv6, thanks to Steve Kemp!
- Debian packaging fixes
- Make sure both `.htpasswd` *and* `.htaccess` are declared forbidden
  files and not allowed to be downloaded
- Use `memmove()` instead of `strcpy()` for possibly overlapping regions
- Cleanup of default `merecat.conf`, default disabled options to their
  built-in default values
- Spelling fixes and major documentation cleanup


[v2.31][] - 2016-11-06
----------------------

The "it works now" release.

### Changes
- Sort directories first in dir listings
- Include systemd unit file
- Add `debian/` packaging, easy to rebuild and replace for others
- Add `--enable-public-html` to enable `~user/public_html` dirs
- Support for shared `WEBROOT/cgi-bin` as fallback for vhosts
- Update default landing page

### Fixes
- Add missing CSS and jpeg files to install
- Fix dependency tracking when reconfiguring
- Fix `.conf` file parser bugs reported by Gaetan Bisson
- Fix missing `HAVE_LIBCONFUSE` #define causing `.conf` file support to
  not be built, reported by Gaetan Bisson
- Fix malplaced call to `cfg_free()` in .conf file parser, reported by
  Gaetan Bisson
- Update man page and other documentation with missing quotes around CGI
  pattern, issue reported by Gaetan Bisson
- Fix syslog warning: bind 0.0.0.0: Address already in use


[v2.30][] - 2016-10-09
----------------------

Initial release.  Based on [sthttpd][] master, 2015-07-22.

[sthttpd]: https://github.com/blueness/sthttpd/
