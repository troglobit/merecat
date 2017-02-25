AC_PREREQ([2.68])
AC_INIT([Merecat httpd], [2.32-beta2], [https://github.com/troglobit/merecat/issues], [merecat])
AC_CONFIG_SRCDIR([src/libhttpd.c])
AC_CONFIG_HEADERS([config.h])
# Add this to automake init if parallel harness rules fails: serial-tests
AM_INIT_AUTOMAKE([1.11 foreign no-dist-gzip dist-xz])

# Checks for programs.
AC_PROG_CC
AC_PROG_LN_S
AC_PROG_INSTALL
AN_MAKEVAR([AR], [AC_PROG_AR])
AN_PROGRAM([ar], [AC_PROG_AR])
AC_DEFUN([AC_PROG_AR], [AC_CHECK_TOOL(AR, ar, :)])
AC_PROG_AR

# Checks for libraries.
AC_CHECK_LIB(crypt, crypt)
AC_CHECK_LIB(rt, clock_gettime)
AC_CHECK_LIB(resolv, hstrerror)

AC_ARG_ENABLE(public-html,
        AS_HELP_STRING([--enable-public-html], [Enable ~user/public_html in non-chrooted setups]))

AC_ARG_ENABLE(htaccess,
        AS_HELP_STRING([--enable-htaccess], [Enable .htaccess files for access control]))

AC_ARG_ENABLE(htpasswd,
        AS_HELP_STRING([--enable-htpasswd], [Enable .htpasswd files for authentication]))

AC_ARG_ENABLE(msie-padding,
        AS_HELP_STRING([--enable-msie-padding], [Add padding to error messages for Internet Explorer]))

AC_ARG_WITH([systemd],
     [AS_HELP_STRING([--with-systemd=DIR], [Directory for systemd service files, default: auto])],
     [with_systemd=auto])

AC_ARG_WITH([config],
        AS_HELP_STRING([--without-config], [Disable /etc/merecat.conf support using libConfuse]),
	[], [with_config=yes])

AC_ARG_WITH([zlib],
        AS_HELP_STRING([--without-zlib], [Disable mod_deflate (gzip) using zlib]),
	[], [with_zlib=yes])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h grp.h memory.h netdb.h netinet/in.h osreldate.h paths.h poll.h stdlib.h string.h sys/devpoll.h sys/event.h sys/param.h sys/poll.h sys/socket.h sys/time.h syslog.h unistd.h])
AC_HEADER_TIME
AC_HEADER_DIRENT
AC_PROG_RANLIB

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_INT64_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MMAP
AC_FUNC_WAIT3
AC_CHECK_FUNCS([alarm atoll clock_gettime daemon dup2 gai_strerror getcwd getaddrinfo gethostbyname gethostname getnameinfo getpass gettimeofday hstrerror inet_ntoa kqueue malloc memmove memset mkdir munmap poll select setlogin setsid sigaction socket strcasecmp strchr strcspn strdup strerror strncasecmp strpbrk strrchr strspn strstr tzset snprintf waitpid])

AS_IF([test "x$enable_public_html" = "xyes"], [
        AC_DEFINE_UNQUOTED(TILDE_MAP_2, "public_html", [Enables ~user/public_html])])

AS_IF([test "x$enable_htaccess" = "xyes"], [
        AC_DEFINE_UNQUOTED(ACCESS_FILE, ".htaccess", [Enables .htaccess access control files])])

AS_IF([test "x$enable_htpasswd" = "xyes"], [
        AC_DEFINE_UNQUOTED(AUTH_FILE, ".htpasswd", [Enables .htpasswd auth. files])])

AS_IF([test "x$enable_msie_padding" = "xyes"], [
        AC_DEFINE(MSIE_PADDING, [1], [Enable padding of error messages for IE])])

AC_ARG_VAR(WEBDIR, [Document root of your web server [LOCALSTATEDIR/www]])
AS_IF([test "x${WEBDIR}" = "x"], [
	WEBDIR=$localstatedir/www])

AS_IF([test "x$with_config" != "xno"], [
	AC_DEFINE([HAVE_LIBCONFUSE], [1], [Build with support for /etc/merecat.conf])
	PKG_CHECK_MODULES([confuse], [libconfuse >= 2.7])])

AS_IF([test "x$with_zlib" != "xno"], [
	PKG_CHECK_MODULES([zlib], [zlib >= 1.2.3.4])
	AC_CHECK_HEADERS([zlib.h])])

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
test "x$prefix" = xNONE && prefix=$ac_default_prefix
test "x$exec_prefix" = xNONE && exec_prefix='${prefix}'
DOCDIR=`eval echo $docdir`
DOCDIR=`eval echo $DOCDIR`
AC_SUBST(DOCDIR)
SBINDIR=`eval echo $sbindir`
SBINDIR=`eval echo $SBINDIR`
AC_SUBST(SBINDIR)
WWWDIR=`eval echo $WEBDIR`
AC_SUBST(WWWDIR)

AC_CONFIG_FILES([Makefile
                 merecat.service
                 src/Makefile
                 man/Makefile
                 scripts/Makefile
                 tests/Makefile
                 www/Makefile
                 www/cgi-bin/Makefile
                 www/icons/Makefile]
                 www/img/Makefile)

AC_OUTPUT
