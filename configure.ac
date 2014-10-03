AC_PREREQ([2.68])
AC_INIT([sthttpd], [2.27.0], [http://opensource.dyc.edu/bugzilla3])
AC_CONFIG_SRCDIR([src/thttpd.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([1.11 foreign])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AN_MAKEVAR([AR], [AC_PROG_AR])
AN_PROGRAM([ar], [AC_PROG_AR])
AC_DEFUN([AC_PROG_AR], [AC_CHECK_TOOL(AR, ar, :)])
AC_PROG_AR

# Checks for libraries.
AC_CHECK_LIB(crypt, crypt)
AC_CHECK_LIB(rt, clock_gettime)
AC_CHECK_LIB(hstrerror, resolv)

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
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_FUNC_WAIT3
AC_CHECK_FUNCS([alarm atoll bzero clock_gettime daemon dup2 gai_strerror getcwd getaddrinfo gethostbyname gethostname getnameinfo getpass gettimeofday inet_ntoa kqueue memmove memset mkdir munmap poll select setlogin setsid sigset socket strcasecmp strchr strcspn strdup strerror strncasecmp strpbrk strrchr strspn strstr tzset vsnprintf waitpid])

AC_ARG_VAR(WEBDIR, [The document root directory of your web page])

if test "x${WEBDIR}" = "x" ; then
	WEBDIR='/usr/local/www'
fi

AC_ARG_VAR(WEBGROUP, [The group that the web server will run as])

if test "x${WEBGROUP}" = "x" ; then
	WEBGROUP='thttpd'
fi

AC_CONFIG_FILES([Makefile
                 docs/Makefile
                 extras/Makefile
                 scripts/Makefile
                 src/Makefile
                 www/Makefile
                 www/cgi-bin/Makefile])

AC_OUTPUT
