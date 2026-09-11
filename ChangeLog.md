Change Log
==========

All relevant changes are documented in this file.


[v3.00][UNRELEASED]
------------------

Notable new features: HTTPS support, multiple servers from one process,
reverse proxy support, HTTP/1.1 keep-alive, and built-in gzip deflate
compression using zlib.

### Changes
- Add support for HTTPS, works with certificates from Let's Encrypt.
  Minimum protocol version, `ciphers`, and DH parameters (`dhfile`)
  can be tuned in the `ssl` section.  Requires OpenSSL >= 3.0
- HTTPS servers always respond with an HSTS header: `max-age=31536000;
  includeSubDomains; preload`.  Not yet configurable, browsers will
  remember the site as HTTPS-only for a full year
- Verify HTTPS certificate validity at startup: an expired, or not yet
  valid, certificate or intermediate is a hard error and the server
  refuses to start.  The new `-k` command line option downgrades this
  to a warning, for embedded systems without a real-time clock
- Add support for multiple servers, listen to different ports.  The
  default port is 80, or 443 when HTTPS is enabled
- Add support for built-in HTTP redirect, e.g. from HTTP to HTTPS
- Add reverse proxy support (`proxy-pass`), similar to nginx `proxy_pass`.
  Front local application servers (Node.js, Python, Go, etc.) with Merecat
  acting as the TLS-terminating entry point.  Configure in `merecat.conf`:

      server default {
          proxy-pass "/api/**" {
              backend = "http://localhost:3000"
          }
      }

  The backend hostname is resolved at startup.  IPv6 backends are
  supported using bracketed literals, e.g. `http://[::1]:3000`; when a
  name has both A and AAAA records the IPv4 address is preferred.
  Forwarded requests include `X-Forwarded-For`, `X-Real-IP`, and
  `X-Forwarded-Proto` headers.  When the backend URL carries a path
  component, the matched URL prefix is stripped before forwarding
  (nginx-style path rewriting).  Up to 8 rules are supported per server
  block.  Closes #20

  Requests are forwarded as HTTP/1.0 and both request body and response
  are buffered in full, capped at 8 MiB: larger bodies are rejected with
  413, larger responses with 502.  A backend that stalls for 60 seconds
  is dropped with a 502 to the client.  Proxied requests are access
  logged with the status code returned by the backend

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

  The keyword `default` derives both prefixes from the rule itself,
  like nginx: FROM is the backend URL and TO the URL pattern up to its
  first glob character

- Add support for server location directive, similar to nginx but with
  security limitations and native vhost support native to thttpd
- Add gzip deflate compression when built with zlib, also compress
  HEAD as well as GET requests
- Add true `Connection: keep-alive` support
- Add missing `Vary: Accept-Encoding` header
- Skip gzip compression for tar archives and `application/octet-stream`
- Serve PDF files with `Content-Disposition: inline` and a filename,
  for a proper name when saving from the browser
- Send `Cache-Control: no-cache,no-store` when `max-age` is unset.  The
  `Expires` header is no longer emitted, and `ETag` only when
  `max-age > 0`
- Allow downloading files with the execute bit set, thttpd returned
  403 Forbidden, which backfires for simple file servers
- Answer `OPTIONS` requests directly, and parse `PUT`, `DELETE`, etc.
  for dispatch to CGI
- CGI: Allow handling other HTTP methods besides GET/HEAD/POST, from
  thttpd v2.29, change by Jef Poskanzer
- CGI: Allow `:PORT` in `HTTP_POST`, like Apache
- CGI: Allow trailing slash in `PATH_INFO`, like Apache
- CGI: Change default `CGI_PATTERN` from disabled to `**.cgi|/cgi-bin/*`
- CGI: Add support for looking for an `index.cgi` index file
- CGI: Add several missing standard CGI/1.1 environment variables, see
  the file doc/cgi.txt for details
- CGI: Raise default concurrency limit from 1 to 50 and the run time
  limit from 30 to 90 seconds
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
- New `merecat.conf` settings: `user-agent-deny` for blocking bad bots,
  `setenv` in the `cgi` section, and `compression-level` for gzip
- Incompatible `merecat.conf` changes: `cgi-pattern` and `cgi-limit`
  are replaced by `cgi "PATTERN" {}` sections, and `check-symlink` is
  renamed `check-symlinks`
- Refuse to start on `.conf` file parse errors, or when the file given
  with `-f` does not exist, instead of silently continuing with
  defaults
- Command line changes: `-s` now means log to syslog in the foreground,
  symlink checking moved to `-S`.  When built with libConfuse (default)
  the options `-c`, `-d`, `-g`, `-r`, `-S`, `-u`, and `-v` are dropped
  in favor of the `.conf` file.  New option `-P PIDFN` overrides the
  PID file path
- `SIGUSR1` no longer shuts the server down, it toggles the debug log
  level.  Use `SIGTERM` or `SIGQUIT` to stop the server
- Apply Debian thttpd `SIGBUS` patch for reading from NFS
- Add `-I IDENT` command line option to override program identity.
  This change makes it possible to change syslog, PID file name, *and*
  `.conf` file name.  Useful when running multiple instances of Merecat
- Add `--enable-msie-padding` to `configure` script
- Add `.htaccess` support, limited to IPv4.  Feature by Felix J. Ogris
- Allow `.htpasswd` file to be symlinked
- `.htaccess` and `.htpasswd` now also protect sub-directories, parent
  directories are searched up to the server root
- Both `.htaccess` and `.htpasswd` support are now opt-in at build
  time: `--enable-htaccess` and `--enable-htpasswd`
- DOC: How to use `.htpasswd` and virtual hosts
- DOC: Added section on how to optimize performance
- Update MIME types, e.g. Ogg video, 7zip, svg
- Add Dockerfile for ease of deployment in limited setups
- Add cute cat default favicon
- Built-in icons for FTP dir listings; folder, file, etc.
- Refactor, deprecated POSIX API's, e.g. `bzero() --> memset()`
- Enable `SO_REUSEPORT` if available, useful for load balancing
- Linux performance: epoll(7) event backend, sendfile(2) for plain-HTTP
  file transfers, `TCP_NODELAY`, and `TCP_DEFER_ACCEPT`
- Remove `redirect` CGI program and man page, superseded by the
  built-in redirect directive
- Move `debian/` packaging to a separate branch for easier downstream
  maintenance
- Building now requires pkg-config.  New configure options:
  `--disable-dirlisting`, `--enable-builtin-icons`, `--without-ssl`,
  `--without-zlib`, and `--without-symlinks`
- Release tarballs now come with SHA256 checksums instead of MD5

### Fixes
- Fix `htpasswd` silently producing empty password files on some systems.
  An off-by-one in the salt generator left the salt string unterminated,
  causing `crypt()` to return NULL and skip writing the password entry
- More `htpasswd` fixes: buffer overflow and EOF hang reading
  passwords, predictable salt, and temp file left behind on error
- Fix TLS handshake blocking the event loop; a client trickling
  handshake bytes stalled the entire server.  Also fix a use-after-free
  when the handshake failed
- Fix missing access log entries for 200 OK responses
- Fix CGI POST body read from the wrong descriptor after daemonizing,
  stdin could be reused for a socket
- Report startup errors before daemonizing, e.g. invalid config or
  port already in use, instead of detaching first and dying silently
- Fix check/use race on `.htaccess` and `.htpasswd` files, found by
  Coverity
- Return 404 instead of 403 for `.htaccess` and `.htpasswd` probes,
  and for missing files, to not advertise what exists
- Validate `X-Forwarded-For` before trusting it for logging, skip
  `unknown` entries from masquerading proxies
- Fix upload of large files when HTTPS is enabled
- Fix `-t FILE` being rejected by the option parser
- Fix dir listing of filenames with HTML entities, skip inaccessible
  files
- Never serve non-regular files, e.g. FIFOs, return 404
- Fix handling of URLs with a leading double slash, e.g. `//main.css`
- Normalize CGI response header line endings to CRLF, per RFC 3875
- Fix overflow in authorization handling, and increase the initial
  request buffer from 500 bytes to 16 kiB, long request lines failed
- Don't treat IPv6 being disabled in the kernel as fatal, warn and
  continue with IPv4 only.  Fixes #47
- systemd unit file no longer chroots the server by default
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
