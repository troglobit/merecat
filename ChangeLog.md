Change Log
==========

All relevant changes are documented in this file.


[v3.00][UNRELEASED]
------------------

Notable new features: reverse proxy support, multiple server support from
one process, HTTPS, HTTP/1.1 keep-alive, and built-in gzip deflate
compression using zlib.

### Changes
- Add reverse proxy support (`proxy-pass`), similar to nginx `proxy_pass`.
  Front local application servers (Node.js, Python, Go, etc.) with Merecat
  acting as the TLS-terminating entry point.  Configure in `merecat.conf`:

      server default {
          proxy-pass "/api/**" {
              backend = "http://localhost:3000"
          }
      }

  The backend hostname is resolved at startup.  Forwarded requests include
  `X-Forwarded-For`, `X-Real-IP`, and `X-Forwarded-Proto` headers.  When
  the backend URL carries a path component, the matched URL prefix is
  stripped before forwarding (nginx-style path rewriting).  Up to 8 rules
  are supported per server block.  Closes #20

- Add `host` filter to `proxy-pass` rules for multihoming (virtual host)
  setups.  When `virtual-host = true` is enabled, each `proxy-pass` rule
  can restrict which `Host:` header it matches, enabling different backends
  on the same port:

      virtual-host = true
      server secure {
          port = 443
          proxy-pass "/**" {
              host    = "git.example.com"
              backend = "http://localhost:3000"
          }
      }

- Add `proxy-redirect` to rewrite `Location:` and `Refresh:` response
  headers returned by the backend.  Use it when a backend issues absolute
  redirects with its own host or path prefix that needs to be rewritten to
  the frontend URL:

      proxy-pass "/app/**" {
          backend        = "http://localhost:4000/"
          proxy-redirect = "http://localhost:4000 http://localhost"
      }

- Add support for HTTPS, works with certificates from Let's Encrypt
- Add support for multiple servers, listen to different ports
- Add support for built-in HTTP redirect, e.g. from HTTP to HTTPS
- Add support for server location directive, similar to nginx but with
  security limitations and native vhost support native to thttpd
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
  the file doc/cgi.txt for details
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
- Fix `htpasswd` silently producing empty password files on some systems.
  An off-by-one in the salt generator left the salt string unterminated,
  causing `crypt()` to return NULL and skip writing the password entry
- Fix `.htaccess` allow/deny rules not working on dual-stack IPv6 systems.
  `allow from <ip>` never matched any client, effectively making access
  control files always deny all traffic
- Fix `Cache-Control` header being emitted twice for error responses
  (4xx/5xx) when `max-age` is set.  Also correct a typo: `no-stored`
  → `no-store`.  Thanks to Ángel (Keisial)
- Fix document root not being set when running without a config file;
  `data_dir` was used instead of `path`.  Thanks to Roman Shterenzon
- Fix `merecat.conf` SSL example to use block syntax instead of the
  invalid `ssl = on` key
- Fix build on macOS: add `-D_DARWIN_C_SOURCE` for Darwin extensions,
  replace `mkostemp()` with `mkstemp()` + `fcntl(FD_CLOEXEC)`, and
  replace deprecated `getdtablesize()` with `sysconf(_SC_OPEN_MAX)`.
  Thanks to Roman Shterenzon
- Fix K&R-style `qsort` comparison callbacks in `libhttpd.c` and
  `tdate_parse.c`; use proper `const void *` prototypes to silence
  warnings on modern compilers.  Thanks to Roman Shterenzon
- ssl: upgrade to OpenSSL 3; replace deprecated `PEM_read_DHparams()`
  with `PEM_read_bio_Parameters()` + `SSL_CTX_set0_tmp_dh_pkey()`.
  Thanks to Roman Shterenzon
- Dockerfile: update base image from Alpine 3.6 to 3.21, fix
  `ENTRYPOINT` to exec form so merecat receives signals directly.
  Thanks to Roman Shterenzon
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

[UNRELEASED]: https://github.com/troglobit/merecat/compare/v2.31...HEAD
[v3.00]:       https://github.com/troglobit/merecat/compare/v2.31...v3.00
[v2.31]:      https://github.com/troglobit/merecat/compare/v2.30...v2.31
[v2.30]:      https://github.com/troglobit/merecat/compare/v2.29...v2.30
[sthttpd]:    https://github.com/blueness/sthttpd/
