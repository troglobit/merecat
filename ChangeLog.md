Change Log
==========

All relevant changes are documented in this file.


[v2.32][] - 2019-07-XX
----------------------

Notable new features: multiple server support from one process, HTTPS,
HTTP/1.1 keep-alive, and built-in gzip deflate compression using zlib.

### Changes
- Add support for HTTPS, works with certificates from Let's Encrypt
- Add support for multiple servers, listen to different ports
- Add support for built-in HTTP redirect, e.g. from HTTP to HTTPS
- Add gzip deflate compression when built with zlib, also compress
  HEAD as well as GET requests
- Add true `Connection: keep-alive` support
- Add missing `Vary: Accept-Encoding` header
- CGI: Allow handling other HTTP methods besides GET/HEAD/POST, from
  thttpd v2.29, change by Jef Poskanzer
- CGI: Allow `:PORT` in `HTTP_POST`, like Apache
- CGI: Allow trailing slash in `PATH_INFO`, like Apache
- CGI: Change default `CGI_PATTERN` from disabled to `**.cgi|/cgi-bin/*`
- CGI: Add support for looking for an `index.cgi` index file
- CGI: Add several missing standard CGI/1.1 environment variables, see
  the file docs/cgi.txt for details
- PHP:
  - Add support for `php-cgi` and `index.php` index file
  - Add support for PHP pattern matching, run php-cgi if `**.php`
- Server-Side Includes (SSI):
  - Add support for SSI pattern matching, run cgi-bin/ssi if `**.shtml`
  - Add support for silencing default SSI `errmsg`
  - Add support for looking for `index.shtml` index file
- Dot files are no longer shown in dir listings, use the `merecat.conf`
  setting `list-dotfiles = true` to enable
- Server stats are no longer periodically sent to syslog, re-enable in
  `merecat.conf` if you need the `STATS_TIME` feature
- Apply Debian thttpd `SIGBUS` patch for reading from NFS
- Add `-I IDENT` command line option to override program identity.
  This change makes it possible to change syslog, PID file name, *and*
  `.conf` file name.  Useful when running multiple instances of Merecat
- Add `--enable-msie-padding` to `configure` script
- Add `.htaccess` support, limited to IPv4.  Feature by Felix J. Ogris
- Allow `.htpasswd` file to be symlinked
- DOC: How to use `.htpasswd` and virtual hosts
- DOC: Added section on how to optimize performance
- Update MIME types, e.g. Ogg video, 7zip, svg
- Add Dockerfile for ease of deployment in limited setups
- Add cute cat default favicon
- Built-in icons for FTP dir listings; folder, file, etc.
- Refactor, deprecated POSIX API's, e.g. `bzero() --> memset()`
- Enable `SO_REUSEPORT` if available, useful for load balancing

### Fixes
- Fix CVE-2017-17663, buffer overrun in htpasswd tool, from thttpd v2.28
- Fixes for non GNU C libraries like musl: `__progname`, `%m`, etc.
- Fix `X-Forwarded-For` when using IPv6, thanks to Steve Kemp!
- Debian packaging fixes
- Make sure both `.htpasswd` *and* `.htaccess` are declared forbidden
  files and not allowed to be downloaded or shown in directory listings
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

[v2.32]: https://github.com/troglobit/merecat/compare/v2.31...v2.32
[v2.31]: https://github.com/troglobit/merecat/compare/v2.30...v2.31
[v2.30]: https://github.com/troglobit/merecat/compare/v2.29...v2.30
[sthttpd]: https://github.com/blueness/sthttpd/
