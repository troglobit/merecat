AC_PREREQ([2.68])
AC_INIT([sthttpd], [2.26], [httpd://bugs.gentoo.org])
AC_CONFIG_SRCDIR([src/thttpd.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([1.11 foreign])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h memory.h netdb.h netinet/in.h stdlib.h string.h sys/param.h sys/socket.h sys/time.h syslog.h unistd.h])

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
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_FUNC_WAIT3
AC_CHECK_FUNCS([alarm bzero clock_gettime dup2 getcwd gethostbyname gethostname getpass gettimeofday inet_ntoa memmove memset mkdir munmap select socket strcasecmp strchr strcspn strdup strerror strncasecmp strpbrk strrchr strspn strstr tzset])

AC_CONFIG_FILES([Makefile
                 docs/Makefile
                 extras/Makefile
                 scripts/Makefile
                 src/Makefile
                 www/Makefile
                 www/cgi-bin/Makefile])

AC_OUTPUT

dnl AC_CHECK_FUNC(crypt, , AC_CHECK_LIB(crypt, crypt))
dnl AC_CHECK_FUNC(hstrerror, , AC_CHECK_LIB(resolv, hstrerror, V_NETLIBS="-lresolv $V_NETLIBS"))

dnl AC_REPLACE_FUNCS(strerror)

dnl AC_CHECK_LIB(rt, clock_gettime)

dnl AC_ACME_TM_GMTOFF
dnl AC_ACME_INT64T
dnl AC_ACME_SOCKLENT

dnl AC_PROG_MAKE_SET
dnl AC_PROG_INSTALL

dnl AC_SUBST(DEFS)
dnl AC_SUBST(V_CCOPT)
dnl AC_SUBST(V_STATICFLAG)
dnl AC_SUBST(V_NETLIBS)
