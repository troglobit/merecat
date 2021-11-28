AC_PREREQ([2.68])
AC_INIT([Merecat httpd], [2.32-rc4], [https://github.com/troglobit/merecat/issues], [merecat])
AC_CONFIG_AUX_DIR(aux)
AM_INIT_AUTOMAKE([1.11 foreign dist-xz])
AM_SILENT_RULES([yes])

AC_CONFIG_SRCDIR([src/libhttpd.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile
                 merecat.service
                 src/Makefile
                 man/Makefile
                 tests/Makefile
                 www/Makefile
                 www/cgi-bin/Makefile
                 www/icons/Makefile]
                 www/img/Makefile)

# Use pkg-config to check for some deps; libConfuse, libssl
PKG_PROG_PKG_CONFIG

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_RANLIB

# Checks for libraries.
AC_CHECK_LIB(crypt, crypt)
AC_CHECK_LIB(rt, clock_gettime)
AC_CHECK_LIB(resolv, hstrerror)

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h grp.h memory.h netdb.h netinet/in.h osreldate.h paths.h poll.h stddef.h stdlib.h string.h termios.h sys/devpoll.h sys/event.h sys/param.h sys/poll.h sys/socket.h sys/time.h syslog.h unistd.h])
AC_CHECK_HEADER_STDBOOL
AC_HEADER_TIME
AC_HEADER_DIRENT

AC_C_INLINE

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_INT64_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Check for missing/broken API's, which we can replace, e.g. lib/lstat.c
AC_REPLACE_FUNCS([strlcpy strlcat tempfile])
AC_CONFIG_LIBOBJ_DIR([lib])

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MMAP
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_WAIT3
AC_CHECK_FUNCS([alarm atexit atoll backtrace clock_gettime daemon dup2 gai_strerror getcwd getaddrinfo gethostbyname gethostname getnameinfo getpass gettimeofday hstrerror inet_ntoa isascii kqueue malloc memmove memset mkdir mmap munmap poll realpath select setenv setlogin setsid sigaction socket strcasecmp strchr strcspn strdup strerror strncasecmp strpbrk strrchr strspn strstr strtoul snprintf tzset waitpid])

# Check for command line options
AC_ARG_ENABLE(builtin-icons,
        AS_HELP_STRING([--enable-builtin-icons], [Enable built-in icons for dir listings]))

AC_ARG_ENABLE(public-html,
        AS_HELP_STRING([--enable-public-html], [Enable ~user/public_html in non-chrooted setups]))

AC_ARG_ENABLE(htaccess,
        AS_HELP_STRING([--enable-htaccess], [Enable .htaccess files for access control]))

AC_ARG_ENABLE(htpasswd,
        AS_HELP_STRING([--enable-htpasswd], [Enable .htpasswd files for authentication]))

AC_ARG_ENABLE(msie-padding,
        AS_HELP_STRING([--enable-msie-padding], [Add padding to error messages for Internet Explorer]))

AC_ARG_ENABLE(dirlisting,
        AS_HELP_STRING([--disable-dirlisting], [Disable directory listings when no index file is found]),,[
		enable_dirlisting=yes])

AC_ARG_WITH([systemd],
	[AS_HELP_STRING([--with-systemd=DIR], [Directory for systemd service files, default: auto])],,
	[with_systemd=auto])

AC_ARG_WITH([config],
        AS_HELP_STRING([--without-config], [Disable /etc/merecat.conf support using libConfuse]),,
	[with_config=yes])

AC_ARG_WITH(ssl,
        AS_HELP_STRING([--without-ssl], [Disable HTTPS support, default: enabled]),,
        [with_ssl=yes])

AC_ARG_WITH([symlinks],
        AS_HELP_STRING([--without-symlinks], [Disable httpd and in.httpd symlinks to merecat]),,
	[with_symlinks=yes])

AC_ARG_WITH([zlib],
        AS_HELP_STRING([--without-zlib], [Disable mod_deflate (gzip) using zlib]),,
	[with_zlib=auto])

AS_IF([test "x$enable_builtin_icons" = "xyes"], [
        AC_DEFINE(BUILTIN_ICONS, [1], [Enables built-in icons for dir listings])])
AM_CONDITIONAL([HAVE_ICONS], [test "x$enable_builtin_icons" != "xyes"])

AS_IF([test "x$enable_public_html" = "xyes"], [
        AC_DEFINE_UNQUOTED(TILDE_MAP_2, "public_html", [Enables ~user/public_html])])

AS_IF([test "x$enable_htaccess" = "xyes"], [
        AC_DEFINE_UNQUOTED(ACCESS_FILE, ".htaccess", [Enables .htaccess access control files])])

AS_IF([test "x$enable_htpasswd" = "xyes"], [
        AC_DEFINE_UNQUOTED(AUTH_FILE, ".htpasswd", [Enables .htpasswd auth. files])])
AM_CONDITIONAL([ENABLE_HTPASSWD], [test "x$enable_htpasswd" = "xyes"])

AS_IF([test "x$enable_msie_padding" = "xyes"], [
        AC_DEFINE(MSIE_PADDING, [1], [Enable padding of error messages for IE])])

AS_IF([test "x$enable_dirlisting" != "xno"], [
        AC_DEFINE(GENERATE_INDEXES, [1], [Automatically generate directory index when index file is missing])])

AC_ARG_VAR(WEBDIR, [Document root of your web server [LOCALSTATEDIR/www]])
AS_IF([test "x${WEBDIR}" = "x"], [
	WEBDIR=$localstatedir/www])

AS_IF([test "x$with_config" != "xno"], [
	AC_DEFINE([HAVE_LIBCONFUSE], [1], [Build with support for /etc/merecat.conf])
	PKG_CHECK_MODULES([confuse], [libconfuse >= 2.7])])
AM_CONDITIONAL([HAVE_CONFUSE], [test "x$with_config" != "xno"])

AM_CONDITIONAL([CREATE_SYMLINKS], [test "x$with_symlinks" != "xno"])

AS_IF([test "x$with_ssl" != "xno"], [
	PKG_CHECK_MODULES([OpenSSL], [openssl >= 1.1.1])
	LDFLAGS="$LDFLAGS $OpenSSL_LIBS"
	CPPFLAGS="$CPPFLAGS $OpenSSL_CFLAGS"
	AC_CHECK_LIB([crypto], [EVP_EncryptInit], [],
		AC_MSG_ERROR([*** Crypto library (OpenSSL) not found!]))
	AC_CHECK_LIB([ssl], [SSL_library_init], [],
		AC_CHECK_LIB([ssl], [OPENSSL_init_ssl], [],
		AC_MSG_ERROR([*** SSL library (OpenSSL) not found!])))
	AC_CHECK_HEADERS([openssl/crypto.h openssl/x509.h openssl/pem.h openssl/ssl.h openssl/tls1.h openssl/err.h], [],
		AC_MSG_ERROR([*** Cannot find required header files!]), [
			#include <openssl/conf.h>
		])
	AC_CHECK_DECLS([SSL_COMP_free_compression_methods,SSL_CTX_set_ecdh_auto], [], [], [
		#ifdef HAVE_OPENSSL_ERR_H
		#include <openssl/err.h>
		#endif

		#ifdef HAVE_OPENSSL_RAND_H
		#include <openssl/rand.h>
		#endif

		#ifdef HAVE_OPENSSL_CONF_H
		#include <openssl/conf.h>
		#endif

		#ifdef HAVE_OPENSSL_ENGINE_H
		#include <openssl/engine.h>
		#endif
		#include <openssl/ssl.h>
		#include <openssl/evp.h>
	])
	AC_DEFINE([ENABLE_SSL], [1], [Enable HTTPS support])
])
AM_CONDITIONAL([ENABLE_SSL], test "x$with_ssl" = "xyes")

AS_IF([test "x$with_zlib" != "xno"], [
	AC_CHECK_HEADERS([zlib.h])
	AS_IF([test "x$ac_cv_header_zlib_h" = "xyes" -o "x$with_zlib" = "xyes"], [
		PKG_CHECK_MODULES([zlib], [zlib >= 1.2.3.4])])
])

# Check where to install the systemd .service file
AS_IF([test "x$with_systemd" = "xyes" -o "x$with_systemd" = "xauto"], [
     def_systemd=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)
     AS_IF([test "x$def_systemd" = "x"],
         [AS_IF([test "x$with_systemd" = "xyes"],
	     [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
	     with_systemd=no], [with_systemd="$def_systemd"])]
)
AS_IF([test "x$with_systemd" != "xno"],
     [AC_SUBST([systemddir], [$with_systemd])])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemd" != "xno"])

# Expand $sbindir early, into $SBINDIR, for systemd unit file
# NOTE: This does *not* take prefix/exec_prefix override at "make
#       install" into account, unfortunately.
test "x$prefix" = xNONE && prefix=
test "x$exec_prefix" = xNONE && exec_prefix='${prefix}'
DOCDIR=`eval echo $docdir`
DOCDIR=`eval echo $DOCDIR`
AC_SUBST(DOCDIR)
SBINDIR=`eval echo $sbindir`
SBINDIR=`eval echo $SBINDIR`
AC_SUBST(SBINDIR)
WWWDIR=`eval echo $WEBDIR`
AC_SUBST(WWWDIR)

AC_OUTPUT
