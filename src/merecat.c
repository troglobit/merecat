/* Simple, small and fast HTTP server
**
** Copyright © 1995,1998,1999,2000,2001 by Jef Poskanzer <jef@mail.acme.com>.
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
**
** THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
** ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
** FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
** OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
** HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
** OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
** SUCH DAMAGE.
*/

#include <config.h>

#include <errno.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <getopt.h>
#include <pwd.h>
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SYSLOG_NAMES
#include <syslog.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/uio.h>

#ifdef HAVE_LIBCONFUSE
#include <confuse.h>
#define CONF_FILE_OPT "f:"
#else
#define CONF_FILE_OPT ""
#endif

#include "fdwatch.h"
#include "libhttpd.h"
#include "match.h"
#include "mmc.h"
#include "merecat.h"
#include "timers.h"

#ifndef SHUT_WR
#define SHUT_WR 1
#endif

#define SIGNAL(signo, cb)		\
	sa.sa_flags   = SA_RESTART;	\
	sa.sa_handler = cb;		\
	(void)sigaction(signo, &sa, NULL)

/* Instead of non-portable __progname */
char        *prognm;
char        *ident;		/* Used for logging */

static int   background        = 1;
static int   loglevel          = LOG_NOTICE;
static unsigned short port     = DEFAULT_PORT;    /* SERVER_PORT_DEFAULT */
static char *dir               = NULL;            /* SERVER_DIR_DEFUALT: /var/www */
static char *data_dir          = NULL;
static int   do_chroot         = 0;
static int   no_log            = 0;
static int   no_symlink_check  = 1;
static int   do_vhost          = 0;
static int   do_global_passwd  = 0;
static char *cgi_pattern       = CGI_PATTERN;
static int   cgi_limit         = CGI_LIMIT;
static char *url_pattern       = NULL;
static int   no_empty_referers = 0;
static int   list_dotfiles     = 0;
static char *local_pattern     = NULL;
static char *throttlefile      = NULL;
static char *hostname          = NULL;
static char *user              = DEFAULT_USER;    /* Usually www-data or nobody */
static char *charset           = DEFAULT_CHARSET;
static int   max_age           = -1;


typedef struct {
	char *pattern;
	long max_limit, min_limit;
	long rate;
	off_t bytes_since_avg;
	int num_sending;
} throttletab;
static throttletab *throttles;
static int numthrottles, maxthrottles;

#define THROTTLE_NOLIMIT -1


typedef struct {
	int conn_state;
	int next_free_connect;
	httpd_conn *hc;
	int tnums[MAXTHROTTLENUMS];	/* throttle indexes */
	int numtnums;
	long max_limit, min_limit;
	time_t started_at, active_at;
	Timer *wakeup_timer;
	Timer *linger_timer;
	long wouldblock_delay;
	off_t bytes;
	off_t end_byte_index;
	off_t next_byte_index;
} connecttab;
static connecttab *connects;
static int num_connects, max_connects, first_free_connect;
static int httpd_conn_count;

/* The connection states. */
#define CNST_FREE 0
#define CNST_READING 1
#define CNST_SENDING 2
#define CNST_PAUSING 3
#define CNST_LINGERING 4


static httpd_server *hs = NULL;
int terminate = 0;
time_t start_time, stats_time;
long stats_connections;
off_t stats_bytes;
int stats_simultaneous;

static volatile int got_hup, got_usr1, watchdog_flag;

/* External functions */
extern int pidfile(const char *basename);

/* Forwards. */
static void lookup_hostname(httpd_sockaddr *sa4P, size_t sa4_len, int *gotv4P, httpd_sockaddr *sa6P, size_t sa6_len, int *gotv6P);
static void read_throttlefile(char *throttlefile);
static void shut_down(void);
static int handle_newconnect(struct timeval *tvP, int listen_fd);
static void handle_read(connecttab *c, struct timeval *tvP);
static void handle_send(connecttab *c, struct timeval *tvP);
static void handle_linger(connecttab *c, struct timeval *tvP);
static int check_throttles(connecttab *c);
static void clear_throttles(connecttab *c, struct timeval *tvP);
static void update_throttles(ClientData client_data, struct timeval *nowP);
static void finish_connection(connecttab *c, struct timeval *tvP);
static void clear_connection(connecttab *c, struct timeval *tvP);
static void really_clear_connection(connecttab *c, struct timeval *tvP);
static void idle(ClientData client_data, struct timeval *nowP);
static void wakeup_connection(ClientData client_data, struct timeval *nowP);
static void linger_clear_connection(ClientData client_data, struct timeval *nowP);
static void occasional(ClientData client_data, struct timeval *nowP);

#ifdef HAVE_LIBCONFUSE
static int  read_config(char *filename);
#endif
#ifdef STATS_TIME
static void show_stats(ClientData client_data, struct timeval *nowP);
#endif				/* STATS_TIME */
static void logstats(struct timeval *nowP);
static void merecat_logstats(long secs);


/* SIGTERM and SIGINT say to exit immediately. */
static void handle_term(int signo)
{
	shut_down();
	syslog(LOG_NOTICE, "Exiting due to signal %d, dropping %d connections.", signo, num_connects);
	closelog();
	exit(0);
}


/* SIGCHLD - a chile process exitted, so we need to reap the zombie */
static void handle_chld(int signo)
{
	const int oerrno = errno;
	pid_t pid;
	int status;

	/* Reap defunct children until there aren't any more. */
	while (1) {
#ifdef HAVE_WAITPID
		pid = waitpid((pid_t)-1, &status, WNOHANG);
#else
		pid = wait3(&status, WNOHANG, NULL);
#endif
		if ((int)pid == 0)	/* none left */
			break;

		if ((int)pid < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;

			/* ECHILD shouldn't happen with the WNOHANG option,
			 ** but with some kernels it does anyway.  Ignore it.
			 */
			if (errno != ECHILD)
				syslog(LOG_ERR, "child wait: %s", strerror(errno));
			break;
		}

		/* Decrement the CGI count.  Note that this is not accurate, since
		 ** each CGI can involve two or even three child processes.
		 ** Decrementing for each child means that when there is heavy CGI
		 ** activity, the count will be lower than it should be, and therefore
		 ** more CGIs will be allowed than should be.
		 */
		if (hs) {
			--hs->cgi_count;
			if (hs->cgi_count < 0)
				hs->cgi_count = 0;
		}
	}

	/* Restore previous errno. */
	errno = oerrno;
}


/* SIGHUP says to re-open the log file. */
static void handle_hup(int signo)
{
	const int oerrno = errno;

	/* Just set a flag that we got the signal. */
	got_hup = 1;

	/* Restore previous errno. */
	errno = oerrno;
}


/* SIGUSR1 says to exit as soon as all current connections are done. */
static void handle_usr1(int signo)
{
	/* Don't need to set up the handler again, since it's a one-shot. */

	if (num_connects == 0) {
		/* If there are no active connections we want to exit immediately
		 ** here.  Not only is it faster, but without any connections the
		 ** main loop won't wake up until the next new connection.
		 */
		shut_down();
		syslog(LOG_NOTICE, "Exiting due to SIGUSR1");
		closelog();
		exit(0);
	}

	/* Otherwise, just set a flag that we got the signal. */
	got_usr1 = 1;

	/* Don't need to restore old errno, since we didn't do any syscalls. */
}


/* SIGUSR2 says to generate the stats syslogs immediately. */
static void handle_usr2(int signo)
{
	const int oerrno = errno;

	logstats(NULL);

	/* Restore previous errno. */
	errno = oerrno;
}


/* SIGALRM is used as a watchdog. */
static void handle_alrm(int signo)
{
	const int oerrno = errno;

	/* If nothing has been happening */
	if (!watchdog_flag) {
		/* Try changing dirs to someplace we can write. */
		(void)chdir("/tmp");
		/* Dump core. */
		abort();
	}
	watchdog_flag = 0;

	/* Set up alarm again. */
	(void)alarm(OCCASIONAL_TIME * 3);

	/* Restore previous errno. */
	errno = oerrno;
}

static int loglvl(char *level)
{
	for (int i = 0; prioritynames[i].c_name; i++) {
		if (!strcmp(prioritynames[i].c_name, level))
			return prioritynames[i].c_val;
	}

	return atoi(level);
}

static int usage(int code)
{
	printf("\n"
	       "Usage: %s [OPTIONS] [WEBROOT] [HOSTNAME]\n"
	       "\n"
	       "  -c CGI     CGI pattern to allow, e.g. \"**\", \"**.cgi\", \"/cgi-bin/*\",\n"
	       "             the built-in default is: \"" CGI_PATTERN "\"\n"
	       "  -d DIR     Optional DIR to change into after chrooting to WEBROOT\n"
#ifdef HAVE_LIBCONFUSE
	       "  -f FILE    Configuration file name, default: " CONFDIR "/merecat.conf\n"
#endif
	       "  -g         Use global password file, .htpasswd\n"
	       "  -h         This help text\n"
	       "  -I IDENT   Identity to use in log messages, defaults to program name\n"
	       "  -l LEVEL   Set log level: none, err, info, notice*, debug\n"
	       "  -n         Run in foreground, do not detach from controlling terminal\n"
	       "  -p PORT    Port to listen to, default 80\n"
	       "  -r         Chroot into WEBROOT\n"
	       "  -s         Check symlinks so they don't point outside WEBROOT\n"
	       "  -t FILE    Throttle file\n"
	       "  -u USER    Username to drop to, default: nobody\n"
	       "  -v         Enable virtual hosting with WEBROOT as base\n"
	       "  -V         Show Merecat httpd version\n"
	       "\n", prognm);
	printf("The optional 'WEBROOT' defaults to the current directory and 'HOSTNAME' is only\n"
	       "for virtual hosting, to run one httpd per hostname.  The '-d DIR' is not needed\n"
	       "in virtual hosting mode, see merecat(8) for more information on virtual hosting\n"
	       "\nBug report address: %-40s\n\n", PACKAGE_BUGREPORT);

	return code;
}

static int version(void)
{
	printf("%s\n", PACKAGE_VERSION);
	return 0;
}

static char *progname(char *arg0)
{
       char *nm;

       nm = strrchr(arg0, '/');
       if (nm)
	       nm++;
       else
	       nm = arg0;

       return nm;
}

int main(int argc, char **argv)
{
	int c;
	int log_opts = LOG_PID | LOG_CONS | LOG_NDELAY;
#ifdef HAVE_LIBCONFUSE
	char *config = NULL;
#endif
	struct passwd *pwd;
	uid_t uid = 32767;
	gid_t gid = 32767;
	char path[MAXPATHLEN + 1];
	int num_ready;
	int cnum;
	connecttab *ct;
	httpd_conn *hc;
	httpd_sockaddr sa4;
	httpd_sockaddr sa6;
	int gotv4, gotv6;
	struct timeval tv;
	struct sigaction sa;

	ident = prognm = progname(argv[0]);
	while ((c = getopt(argc, argv, CONF_FILE_OPT "c:d:ghI:l:np:rsu:vV")) != EOF) {
		switch (c) {
#ifdef HAVE_LIBCONFUSE
		case 'f':
			config = optarg;
			break;
#endif
		case 'c':
			cgi_pattern = optarg;
			break;

		case 'd':
			data_dir = optarg;
			break;

		case 'g':
			do_global_passwd = 1;
			break;

		case 'h':
			return usage(0);

		case 'I':
			ident = optarg;
			break;

		case 'l':
			loglevel = loglvl(optarg);
			if (-1 == loglevel)
				return usage(1);
			break;

		case 'n':
			background = 0;
			break;

		case 'p':
			port = (unsigned short)atoi(optarg);
			break;

		case 'r':
			do_chroot = 1;
			no_symlink_check = 1;
			break;

		case 's':
			no_symlink_check = 0;
			break;

		case 't':
			throttlefile = optarg;
			break;

		case 'u':
			user = optarg;
			break;

		case 'v':
			do_vhost = 1;
			break;

		case 'V':
			return version();

		default:
			return usage(1);
		}
	}

	if (optind < argc)
		dir = strdup(argv[optind++]);

	if (optind < argc)
		hostname = strdup(argv[optind++]);

	openlog(ident, log_opts, LOG_FACILITY);
	setlogmask(LOG_UPTO(loglevel));

#ifdef HAVE_LIBCONFUSE
	if (!config) {
		snprintf(path, sizeof(path), "%s/%s.conf", CONFDIR, ident);
		config = path;
	}

	if (read_config(config)) {
		fprintf(stderr, "%s: Failed reading config file '%s': %s\n", prognm, config, strerror(errno));
		return 1;
	}
#endif

	/* Read zone info now, in case we chroot(). */
	tzset();

	/* Look up hostname now, in case we chroot(). */
	lookup_hostname(&sa4, sizeof(sa4), &gotv4, &sa6, sizeof(sa6), &gotv6);
	if (!(gotv4 || gotv6)) {
		syslog(LOG_ERR, "cannot find any valid address");
		exit(1);
	}

	/* Throttle file. */
	numthrottles = 0;
	maxthrottles = 0;
	throttles = NULL;
	if (throttlefile)
		read_throttlefile(throttlefile);

	/* If we're root and we're going to become another user, get the uid/gid
	 ** now.
	 */
	if (getuid() == 0) {
		pwd = getpwnam(user);
		if (!pwd) {
			syslog(LOG_CRIT, "Unknown user - '%s'", user);
			exit(1);
		}
		uid = pwd->pw_uid;
		gid = pwd->pw_gid;
	}

	/* Switch directories if requested. */
	if (dir) {
		if (chdir(dir) < 0) {
			syslog(LOG_CRIT, "chdir: %s", strerror(errno));
			exit(1);
		}
	}
#ifdef USE_USER_DIR
	else if (getuid() == 0) {
		/* No explicit directory was specified, we're root, and the
		 ** USE_USER_DIR option is set - switch to the specified user's
		 ** home dir.
		 */
		if (chdir(pwd->pw_dir) < 0) {
			syslog(LOG_CRIT, "chdir %s: %s", pwd->pw_dir, strerror(errno));
			exit(1);
		}
	}
#endif				/* USE_USER_DIR */

	/* Get current directory. */
	(void)getcwd(path, sizeof(path) - 1);
	if (path[strlen(path) - 1] != '/')
		(void)strcat(path, "/");

	if (background) {
		/* We're not going to use stdin stdout or stderr from here on, so close
		 ** them to save file descriptors.
		 */
		(void)fclose(stdin);
		(void)fclose(stdout);
		(void)fclose(stderr);

		/* Daemonize - make ourselves a subprocess. */
#ifdef HAVE_DAEMON
		if (daemon(1, 1) < 0) {
			syslog(LOG_CRIT, "daemon: %s", strerror(errno));
			exit(1);
		}
#else				/* HAVE_DAEMON */
		switch (fork()) {
		case 0:
			break;
		case -1:
			syslog(LOG_CRIT, "fork: %s", strerror(errno));
			exit(1);
		default:
			exit(0);
		}
#ifdef HAVE_SETSID
		(void)setsid();
#endif
#endif /* HAVE_DAEMON */
	} else {
		/* Even if we don't daemonize, we still want to disown our parent
		 ** process.
		 */
#ifdef HAVE_SETSID
		(void)setsid();
#endif
	}

	/* Create PID file */
	pidfile(ident);

	/* Initialize the fdwatch package.  Have to do this before chroot,
	 ** if /dev/poll is used.
	 */
	max_connects = fdwatch_get_nfiles();
	if (max_connects < 0) {
		syslog(LOG_CRIT, "fdwatch initialization failure");
		exit(1);
	}
	max_connects -= SPARE_FDS;

	/* Chroot if requested. */
	if (do_chroot) {
		if (chroot(path) < 0) {
			syslog(LOG_CRIT, "chroot: %s", strerror(errno));
			exit(1);
		}

		(void)strcpy(path, "/");
		/* Always chdir to / after a chroot. */
		if (chdir(path) < 0) {
			syslog(LOG_CRIT, "chroot chdir: %s", strerror(errno));
			exit(1);
		}
	}

	/* Switch directories again if requested. */
	if (data_dir) {
		if (chdir(data_dir) < 0) {
			syslog(LOG_CRIT, "data-directory chdir: %s", strerror(errno));
			exit(1);
		}
	}

	/* Set up to catch signals. */
	SIGNAL(SIGTERM, handle_term);
	SIGNAL(SIGINT, handle_term);
	SIGNAL(SIGCHLD, handle_chld);
	SIGNAL(SIGPIPE, SIG_IGN);	/* get EPIPE instead */
	SIGNAL(SIGHUP, handle_hup);
	SIGNAL(SIGUSR1, handle_usr1);
	SIGNAL(SIGUSR2, handle_usr2);
	SIGNAL(SIGALRM, handle_alrm);

	got_hup = 0;
	got_usr1 = 0;
	watchdog_flag = 0;
	(void)alarm(OCCASIONAL_TIME * 3);

	/* Initialize the timer package. */
	tmr_init();

	/* Initialize the HTTP layer.  Got to do this before giving up root,
	 ** so that we can bind to a privileged port.
	 */
	hs = httpd_init(hostname, gotv4 ? &sa4 : NULL, gotv6 ? &sa6 : NULL,
			port, cgi_pattern, cgi_limit, charset, max_age, path, no_log,
			no_symlink_check, do_vhost, do_global_passwd, url_pattern, local_pattern,
			no_empty_referers, list_dotfiles);
	if (!hs)
		exit(1);

	/* Set up the occasional timer. */
	if (!tmr_create(NULL, occasional, JunkClientData, OCCASIONAL_TIME * 1000L, 1)) {
		syslog(LOG_CRIT, "tmr_create(occasional) failed");
		exit(1);
	}

	/* Set up the idle timer. */
	if (!tmr_create(NULL, idle, JunkClientData, 5 * 1000L, 1)) {
		syslog(LOG_CRIT, "tmr_create(idle) failed");
		exit(1);
	}

	if (numthrottles > 0) {
		/* Set up the throttles timer. */
		if (!tmr_create(NULL, update_throttles, JunkClientData, THROTTLE_TIME * 1000L, 1)) {
			syslog(LOG_CRIT, "tmr_create(update_throttles) failed");
			exit(1);
		}
	}

#ifdef STATS_TIME
	/* Set up the stats timer. */
	if (!tmr_create(NULL, show_stats, JunkClientData, STATS_TIME * 1000L, 1)) {
		syslog(LOG_CRIT, "tmr_create(show_stats) failed");
		exit(1);
	}
#endif

	start_time = stats_time = time(NULL);
	stats_connections = 0;
	stats_bytes = 0;
	stats_simultaneous = 0;

	/* If we're root, try to become someone else. */
	if (getuid() == 0) {
		/* Set aux groups to null. */
		if (setgroups(0, NULL) < 0) {
			syslog(LOG_CRIT, "setgroups: %s", strerror(errno));
			exit(1);
		}

		/* Set primary group. */
		if (setgid(gid) < 0) {
			syslog(LOG_CRIT, "setgid: %s", strerror(errno));
			exit(1);
		}

		/* Try setting aux groups correctly - not critical if this fails. */
		if (initgroups(user, gid) < 0)
			syslog(LOG_WARNING, "initgroups: %s", strerror(errno));

#ifdef HAVE_SETLOGIN
		/* Set login name. */
		(void)setlogin(user);
#endif

		/* Set uid. */
		if (setuid(uid) < 0) {
			syslog(LOG_CRIT, "setuid: %s", strerror(errno));
			exit(1);
		}

		/* Check for unnecessary security exposure. */
		if (!do_chroot)
			syslog(LOG_WARNING, "Started as root without requesting chroot(), warning only");
	}

	/* Initialize our connections table. */
	connects = NEW(connecttab, max_connects);
	if (!connects) {
		syslog(LOG_CRIT, "Out of memory allocating a connecttab");
		exit(1);
	}

	for (cnum = 0; cnum < max_connects; ++cnum) {
		connects[cnum].conn_state = CNST_FREE;
		connects[cnum].next_free_connect = cnum + 1;
		connects[cnum].hc = NULL;
	}
	connects[max_connects - 1].next_free_connect = -1;	/* end of link list */
	first_free_connect = 0;
	num_connects = 0;
	httpd_conn_count = 0;

	if (hs->listen4_fd != -1)
		fdwatch_add_fd(hs->listen4_fd, NULL, FDW_READ);
	if (hs->listen6_fd != -1)
		fdwatch_add_fd(hs->listen6_fd, NULL, FDW_READ);

	/* Main loop. */
	tmr_prepare_timeval(&tv);
	while ((!terminate) || num_connects > 0) {
		/* Do we need to re-open the log file? */
		if (got_hup)
			got_hup = 0;

		/* Do the fd watch. */
		num_ready = fdwatch(tmr_mstimeout(&tv));
		if (num_ready < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;	/* try again */

			syslog(LOG_ERR, "fdwatch: %s", strerror(errno));
			exit(1);
		}
		tmr_prepare_timeval(&tv);

		if (num_ready == 0) {
			/* No fd's are ready - run the timers. */
			tmr_run(&tv);
			continue;
		}

		/* Is it a new connection? */
		if (hs && hs->listen6_fd != -1 && fdwatch_check_fd(hs->listen6_fd)) {
			if (handle_newconnect(&tv, hs->listen6_fd))
				/* Go around the loop and do another fdwatch, rather than
				 ** dropping through and processing existing connections.
				 ** New connections always get priority.
				 */
				continue;
		}

		if (hs && hs->listen4_fd != -1 && fdwatch_check_fd(hs->listen4_fd)) {
			if (handle_newconnect(&tv, hs->listen4_fd))
				/* Go around the loop and do another fdwatch, rather than
				 ** dropping through and processing existing connections.
				 ** New connections always get priority.
				 */
				continue;
		}

		/* Find the connections that need servicing. */
		while ((ct = (connecttab *)fdwatch_get_next_client_data()) != (connecttab *)-1) {
			if (!ct)
				continue;

			hc = ct->hc;
			if (!fdwatch_check_fd(hc->conn_fd)) {
				/* Something went wrong. */
				clear_connection(ct, &tv);
			} else {
				switch (ct->conn_state) {
				case CNST_READING:
					handle_read(ct, &tv);
					break;

				case CNST_SENDING:
					handle_send(ct, &tv);
					break;

				case CNST_LINGERING:
					handle_linger(ct, &tv);
					break;
				}
			}
		}
		tmr_run(&tv);

		if (got_usr1 && !terminate) {
			terminate = 1;
			if (hs) {
				if (hs->listen4_fd != -1)
					fdwatch_del_fd(hs->listen4_fd);
				if (hs->listen6_fd != -1)
					fdwatch_del_fd(hs->listen6_fd);
				httpd_unlisten(hs);
			}
		}
	}

	/* The main loop terminated. */
	shut_down();
	syslog(LOG_NOTICE, "Exiting cleanly, all connections completed.");
	closelog();
	exit(0);
}

#ifdef HAVE_LIBCONFUSE
static void conf_errfunc(cfg_t *cfg, const char *format, va_list args)
{
	char fmt[80];

	if (cfg && cfg->filename && cfg->line)
		snprintf(fmt, sizeof(fmt), "%s:%d: %s", cfg->filename, cfg->line, format);
	else if (cfg && cfg->filename)
		snprintf(fmt, sizeof(fmt), "%s: %s", cfg->filename, format);
	else
		snprintf(fmt, sizeof(fmt), "%s", format);

	vsyslog(LOG_ERR, fmt, args);
}

static int read_config(char *filename)
{
	static cfg_t *cfg = NULL;
	cfg_opt_t opts[] = {
		CFG_INT ("port", port, CFGF_NONE),
		CFG_BOOL("chroot", do_chroot, CFGF_NONE),
		CFG_STR ("directory", dir, CFGF_NONE),
		CFG_STR ("data-directory", data_dir, CFGF_NONE),
		CFG_BOOL("global-passwd", do_global_passwd, CFGF_NONE),
		CFG_BOOL("check-symlink", !no_symlink_check, CFGF_NONE),
		CFG_BOOL("check-referer", cfg_false, CFGF_NONE),
		CFG_STR ("charset", DEFAULT_CHARSET, CFGF_NONE),
		CFG_INT ("cgi-limit", CGI_LIMIT, CFGF_NONE),
		CFG_STR ("cgi-pattern", cgi_pattern, CFGF_NONE),
		CFG_BOOL("list-dotfiles", cfg_false, CFGF_NONE),
		CFG_STR ("local-pattern", NULL, CFGF_NONE),
		CFG_STR ("url-pattern", NULL, CFGF_NONE),
		CFG_INT ("max-age", -1, CFGF_NONE), /* 0: Disabled */
		CFG_STR ("username", user, CFGF_NONE),
		CFG_STR ("hostname", hostname, CFGF_NONE),
		CFG_BOOL("virtual-host", do_vhost, CFGF_NONE),
		CFG_END()
	};

	if (access(filename, F_OK))
		return 0;

	if (cfg)
		cfg_free(cfg);

	cfg = cfg_init(opts, CFGF_NONE);
	if (!cfg) {
		syslog(LOG_ERR, "Failed initializing configuration file parser: %s", strerror(errno));
		return 1;
	}

	/* Custom logging, rather than default Confuse stderr logging */
	cfg_set_error_function(cfg, conf_errfunc);

	switch (cfg_parse(cfg, filename)) {
	case CFG_FILE_ERROR:
		syslog(LOG_ERR, "Cannot read configuration file %s", filename);
		return 1;

	case CFG_PARSE_ERROR:
		syslog(LOG_ERR, "Parse error in %s", filename);
		return 1;

	case CFG_SUCCESS:
		break;
	}

	port = cfg_getint(cfg, "port");
	do_chroot = cfg_getbool(cfg, "chroot");
	if (do_chroot)
		no_symlink_check = 1;
	dir = cfg_getstr(cfg, "directory");
	data_dir = cfg_getstr(cfg, "data-directory");

	if (cfg_getbool(cfg, "check-symlink"))
		no_symlink_check = 0;

	user = cfg_getstr(cfg, "username");
	cgi_pattern = cfg_getstr(cfg, "cgi-pattern");
	cgi_limit = cfg_getint(cfg, "cgi-limit");
	url_pattern = cfg_getstr(cfg, "url-pattern");
	local_pattern = cfg_getstr(cfg, "local-pattern");

	no_empty_referers = cfg_getbool(cfg, "check-referer");
	list_dotfiles = cfg_getbool(cfg, "list-dotfiles");

	hostname = cfg_getstr(cfg, "hostname");
	do_vhost = cfg_getbool(cfg, "virtual-host");
	do_global_passwd = cfg_getbool(cfg, "global-passwd");

	charset = cfg_getstr(cfg, "charset");
	max_age = cfg_getint(cfg, "max-age");

	return 0;
}
#endif /* HAVE_LIBCONFUSE */

static void lookup_hostname(httpd_sockaddr *sa4P, size_t sa4_len, int *gotv4P, httpd_sockaddr *sa6P, size_t sa6_len, int *gotv6P)
{
#ifdef USE_IPV6
	struct addrinfo hints;
	char service[10];
	int gaierr;
	struct addrinfo *ai;
	struct addrinfo *ptr;
	struct addrinfo *aiv6;
	struct addrinfo *aiv4;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_flags = AI_PASSIVE;
	hints.ai_socktype = SOCK_STREAM;
	snprintf(service, sizeof(service), "%d", port);
	if ((gaierr = getaddrinfo(hostname, service, &hints, &ai)) != 0) {
		syslog(LOG_CRIT, "getaddrinfo %s: %s", hostname, gai_strerror(gaierr));
		exit(1);
	}

	/* Find the first IPv6 and IPv4 entries. */
	aiv6 = NULL;
	aiv4 = NULL;
	for (ptr = ai; ptr; ptr = ptr->ai_next) {
		switch (ptr->ai_family) {
		case AF_INET6:
			if (!aiv6)
				aiv6 = ptr;
			break;

		case AF_INET:
			if (!aiv4)
				aiv4 = ptr;
			break;
		}
	}

	if (!aiv6) {
		*gotv6P = 0;
	} else {
		if (sa6_len < aiv6->ai_addrlen) {
			syslog(LOG_CRIT, "%s - sockaddr too small (%lu < %lu)",
			       hostname, (unsigned long)sa6_len, (unsigned long)aiv6->ai_addrlen);
			exit(1);
		}
		memset(sa6P, 0, sa6_len);
		memmove(sa6P, aiv6->ai_addr, aiv6->ai_addrlen);
		*gotv6P = 1;
	}

#ifdef __linux__
	/*
	 * On Linux listening to IN6ADDR_ANY_INIT means also listening
	 * to INADDR_ANY, so for this special case we do not need to
	 * try to bind() to both.  In fact, it will cause an error.
	 */
	if (!aiv4 || (aiv6 && !hostname))
#else
	if (!aiv4)
#endif
		*gotv4P = 0;
	else {
		if (sa4_len < aiv4->ai_addrlen) {
			syslog(LOG_CRIT, "%s - sockaddr too small (%lu < %lu)",
			       hostname, (unsigned long)sa4_len, (unsigned long)aiv4->ai_addrlen);
			exit(1);
		}
		memset(sa4P, 0, sa4_len);
		memmove(sa4P, aiv4->ai_addr, aiv4->ai_addrlen);
		*gotv4P = 1;
	}

	freeaddrinfo(ai);

#else				/* USE_IPV6 */

	struct hostent *he;

	*gotv6P = 0;

	(void)memset(sa4P, 0, sa4_len);
	sa4P->sa.sa_family = AF_INET;
	if (!hostname) {
		sa4P->sa_in.sin_addr.s_addr = htonl(INADDR_ANY);
	} else {
		sa4P->sa_in.sin_addr.s_addr = inet_addr(hostname);
		if ((int)sa4P->sa_in.sin_addr.s_addr == -1) {
			he = gethostbyname(hostname);
			if (!he) {
#ifdef HAVE_HSTRERROR
				syslog(LOG_CRIT, "gethostbyname %s: %s", hostname, hstrerror(h_errno));
#else
				syslog(LOG_CRIT, "gethostbyname %s failed", hostname);
#endif
				exit(1);
			}
			if (he->h_addrtype != AF_INET) {
				syslog(LOG_CRIT, "%s - non-IP network address", hostname);
				exit(1);
			}
			(void)memmove(&sa4P->sa_in.sin_addr.s_addr, he->h_addr, he->h_length);
		}
	}
	sa4P->sa_in.sin_port = htons(port);
	*gotv4P = 1;

#endif				/* USE_IPV6 */
}


static void read_throttlefile(char *throttlefile)
{
	FILE *fp;
	char buf[5000];
	char *cp;
	int len;
	char pattern[5000];
	long max_limit, min_limit;
	struct timeval tv;

	fp = fopen(throttlefile, "r");
	if (!fp) {
		syslog(LOG_CRIT, "%s: %s", throttlefile, strerror(errno));
		exit(1);
	}

	(void)gettimeofday(&tv, NULL);

	while (fgets(buf, sizeof(buf), fp)) {
		/* Nuke comments. */
		cp = strchr(buf, '#');
		if (cp)
			*cp = '\0';

		/* Nuke trailing whitespace. */
		len = strlen(buf);
		while (len > 0 && (buf[len - 1] == ' ' || buf[len - 1] == '\t' || buf[len - 1] == '\n' || buf[len - 1] == '\r'))
			buf[--len] = '\0';

		/* Ignore empty lines. */
		if (len == 0)
			continue;

		/* Parse line. */
		if (sscanf(buf, " %4900[^ \t] %ld-%ld", pattern, &min_limit, &max_limit) == 3) {
		} else if (sscanf(buf, " %4900[^ \t] %ld", pattern, &max_limit) == 2)
			min_limit = 0;
		else {
			syslog(LOG_ERR, "unparsable line in %s: %s", throttlefile, buf);
			continue;
		}

		/* Nuke any leading slashes in pattern. */
		if (pattern[0] == '/')
			(void)memmove(pattern, &pattern[1], strlen(pattern));
		while ((cp = strstr(pattern, "|/")))
			(void)memmove(cp + 1, cp + 2, strlen(cp) - 1);

		/* Check for room in throttles. */
		if (numthrottles >= maxthrottles) {
			if (maxthrottles == 0) {
				maxthrottles = 100;	/* arbitrary */
				throttles = NEW(throttletab, maxthrottles);
			} else {
				maxthrottles *= 2;
				throttles = RENEW(throttles, throttletab, maxthrottles);
			}

			if (!throttles) {
				syslog(LOG_CRIT, "Out of memory allocating a throttletab");
				exit(1);
			}
		}

		/* Add to table. */
		throttles[numthrottles].pattern = strdup(pattern);
		if (!throttles[numthrottles].pattern) {
			syslog(LOG_CRIT, "Failed storing throttle pattern: %s", strerror(errno));
			exit(1);
		}

		throttles[numthrottles].max_limit = max_limit;
		throttles[numthrottles].min_limit = min_limit;
		throttles[numthrottles].rate = 0;
		throttles[numthrottles].bytes_since_avg = 0;
		throttles[numthrottles].num_sending = 0;

		++numthrottles;
	}
	fclose(fp);
}


static void shut_down(void)
{
	int cnum;
	struct timeval tv;

	(void)gettimeofday(&tv, NULL);
	logstats(&tv);
	for (cnum = 0; cnum < max_connects; ++cnum) {
		if (connects[cnum].conn_state != CNST_FREE)
			httpd_close_conn(connects[cnum].hc, &tv);

		if (connects[cnum].hc) {
			httpd_destroy_conn(connects[cnum].hc);
			free(connects[cnum].hc);
			connects[cnum].hc = NULL;
			--httpd_conn_count;
		}
	}

	if (hs) {
		httpd_server *ths = hs;

		hs = NULL;
		if (ths->listen4_fd != -1)
			fdwatch_del_fd(ths->listen4_fd);
		if (ths->listen6_fd != -1)
			fdwatch_del_fd(ths->listen6_fd);
		httpd_exit(ths);
	}

	mmc_destroy();
	tmr_destroy();
	free(connects);
	if (throttles)
		free(throttles);
}


static int handle_newconnect(struct timeval *tvP, int listen_fd)
{
	connecttab *c;

	/* This loops until the accept() fails, trying to start new
	 ** connections as fast as possible so we don't overrun the
	 ** listen queue.
	 */
	for (;;) {
		/* Is there room in the connection table? */
		if (num_connects >= max_connects) {
			/* Out of connection slots.  Run the timers, then the
			 ** existing connections, and maybe we'll free up a slot
			 ** by the time we get back here.
			 */
			syslog(LOG_WARNING, "Too many connections (%d >) %d)!", num_connects, max_connects);
			tmr_run(tvP);
			return 0;
		}

		/* Get the first free connection entry off the free list. */
		if (first_free_connect == -1 || connects[first_free_connect].conn_state != CNST_FREE) {
			syslog(LOG_CRIT, "The connects free list is messed up");
			exit(1);
		}

		/* Make the httpd_conn if necessary. */
		c = &connects[first_free_connect];
		if (!c->hc) {
			c->hc = NEW(httpd_conn, 1);
			if (!c->hc) {
				syslog(LOG_CRIT, "Out of memory allocating an httpd_conn");
				exit(1);
			}

			c->hc->initialized = 0;
			++httpd_conn_count;
		}

		/* Get the connection. */
		switch (httpd_get_conn(hs, listen_fd, c->hc)) {
			/* Some error happened.  Run the timers, then the
			 ** existing connections.  Maybe the error will clear.
			 */
		case GC_FAIL:
			tmr_run(tvP);
			return 0;

			/* No more connections to accept for now. */
		case GC_NO_MORE:
			return 1;
		}

		c->conn_state = CNST_READING;
		/* Pop it off the free list. */
		first_free_connect = c->next_free_connect;
		c->next_free_connect = -1;
		++num_connects;
		c->active_at = tvP->tv_sec;
		c->wakeup_timer = NULL;
		c->linger_timer = NULL;
		c->next_byte_index = 0;
		c->numtnums = 0;

		/* Set the connection file descriptor to no-delay mode. */
		httpd_set_ndelay(c->hc->conn_fd);

		fdwatch_add_fd(c->hc->conn_fd, c, FDW_READ);

		++stats_connections;
		if (num_connects > stats_simultaneous)
			stats_simultaneous = num_connects;
	}
}


static void handle_read(connecttab *c, struct timeval *tvP)
{
	int sz;
	httpd_conn *hc = c->hc;

	/* Is there room in our buffer to read more bytes? */
	if (hc->read_idx >= hc->read_size) {
		if (hc->read_size > 5000) {
			httpd_send_err(hc, 400, httpd_err400title, "", httpd_err400form, "");
			finish_connection(c, tvP);
			return;
		}
		httpd_realloc_str(&hc->read_buf, &hc->read_size, hc->read_size + 1000);
	}

	/* Read some more bytes. */
	sz = read(hc->conn_fd, &(hc->read_buf[hc->read_idx]), hc->read_size - hc->read_idx);
	if (sz == 0) {
		httpd_send_err(hc, 400, httpd_err400title, "", httpd_err400form, "");
		finish_connection(c, tvP);
		return;
	}

	if (sz < 0) {
		/* Ignore EINTR and EAGAIN.  Also ignore EWOULDBLOCK.  At first glance
		 ** you would think that connections returned by fdwatch as readable
		 ** should never give an EWOULDBLOCK; however, this apparently can
		 ** happen if a packet gets garbled.
		 */
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return;

		httpd_send_err(hc, 400, httpd_err400title, "", httpd_err400form, "");
		finish_connection(c, tvP);
		return;
	}

	hc->read_idx += sz;
	c->active_at = tvP->tv_sec;

	/* Do we have a complete request yet? */
	switch (httpd_got_request(hc)) {
	case GR_NO_REQUEST:
		return;

	case GR_BAD_REQUEST:
		httpd_send_err(hc, 400, httpd_err400title, "", httpd_err400form, "");
		finish_connection(c, tvP);
		return;
	}

	/* Yes.  Try parsing and resolving it. */
	if (httpd_parse_request(hc) < 0) {
		finish_connection(c, tvP);
		return;
	}

	/* Check the throttle table */
	if (!check_throttles(c)) {
		httpd_send_err(hc, 503, httpd_err503title, "", httpd_err503form, hc->encodedurl);
		finish_connection(c, tvP);
		return;
	}

	/* Start the connection going. */
	if (httpd_start_request(hc, tvP) < 0) {
		/* Something went wrong.  Close down the connection. */
		finish_connection(c, tvP);
		return;
	}

	/* Fill in end_byte_index. */
	if (hc->got_range) {
		c->next_byte_index = hc->first_byte_index;
		c->end_byte_index = hc->last_byte_index + 1;
	} else if (hc->bytes_to_send < 0) {
		c->end_byte_index = 0;
	} else {
		c->end_byte_index = hc->bytes_to_send;
	}

	/* Check if it's already handled. */
	if (!hc->file_address) {
		/* No file address means someone else is handling it. */
		int tind;

		for (tind = 0; tind < c->numtnums; ++tind)
			throttles[c->tnums[tind]].bytes_since_avg += hc->bytes_sent;
		c->next_byte_index = hc->bytes_sent;

		finish_connection(c, tvP);
		return;
	}

	if (c->next_byte_index >= c->end_byte_index) {
		/* There's nothing to send. */
		finish_connection(c, tvP);
		return;
	}

	/* Cool, we have a valid connection and a file to send to it. */
	c->conn_state = CNST_SENDING;
	c->started_at = tvP->tv_sec;
	c->wouldblock_delay = 0;

	fdwatch_del_fd(hc->conn_fd);
	fdwatch_add_fd(hc->conn_fd, c, FDW_WRITE);
}


static void handle_send(connecttab *c, struct timeval *tvP)
{
	size_t max_bytes;
	ssize_t sz;
	int coast;
	ClientData client_data;
	time_t elapsed;
	httpd_conn *hc = c->hc;
	int tind;

	if (c->max_limit == THROTTLE_NOLIMIT)
		max_bytes = 1000000000L;
	else
		max_bytes = c->max_limit / 4;	/* send at most 1/4 seconds worth */

	/* Do we need to write the headers first? */
	if (hc->responselen == 0) {
		/* No, just write the file. */
		sz = write(hc->conn_fd, &(hc->file_address[c->next_byte_index]),
			   MIN(c->end_byte_index - c->next_byte_index, (off_t)max_bytes));
	} else {
		/* Yes.  We'll combine headers and file into a single writev(),
		 ** hoping that this generates a single packet.
		 */
		struct iovec iv[2];

		iv[0].iov_base = hc->response;
		iv[0].iov_len = hc->responselen;
		iv[1].iov_base = &(hc->file_address[c->next_byte_index]);
		iv[1].iov_len = MIN(c->end_byte_index - c->next_byte_index, (off_t)max_bytes);
		sz = writev(hc->conn_fd, iv, 2);
	}

	if (sz < 0 && errno == EINTR)
		return;

	if (sz == 0 || (sz < 0 && (errno == EWOULDBLOCK || errno == EAGAIN))) {
		/* This shouldn't happen, but some kernels, e.g.
		 ** SunOS 4.1.x, are broken and select() says that
		 ** O_NDELAY sockets are always writable even when
		 ** they're actually not.
		 **
		 ** Current workaround is to block sending on this
		 ** socket for a brief adaptively-tuned period.
		 ** Fortunately we already have all the necessary
		 ** blocking code, for use with throttling.
		 */
		c->wouldblock_delay += MIN_WOULDBLOCK_DELAY;
		c->conn_state = CNST_PAUSING;
		fdwatch_del_fd(hc->conn_fd);
		client_data.p = c;

		if (c->wakeup_timer)
			syslog(LOG_ERR, "replacing non-null wakeup_timer!");

		c->wakeup_timer = tmr_create(tvP, wakeup_connection, client_data, c->wouldblock_delay, 0);
		if (!c->wakeup_timer) {
			syslog(LOG_CRIT, "tmr_create(wakeup_connection) failed");
			exit(1);
		}
		return;
	}

	if (sz < 0) {
		/* Something went wrong, close this connection.
		 **
		 ** If it's just an EPIPE, don't bother logging, that
		 ** just means the client hung up on us.
		 **
		 ** On some systems, write() occasionally gives an EINVAL.
		 ** Dunno why, something to do with the socket going
		 ** bad.  Anyway, we don't log those either.
		 **
		 ** And ECONNRESET isn't interesting either.
		 */
		if (errno != EPIPE && errno != EINVAL && errno != ECONNRESET)
			syslog(LOG_ERR, "write failed: %s while sending %s", strerror(errno), hc->encodedurl);
		clear_connection(c, tvP);
		return;
	}

	/* Ok, we wrote something. */
	c->active_at = tvP->tv_sec;
	/* Was this a headers + file writev()? */
	if (hc->responselen > 0) {
		/* Yes; did we write only part of the headers? */
		if ((size_t)sz < hc->responselen) {
			/* Yes; move the unwritten part to the front of the buffer. */
			int newlen = hc->responselen - sz;

			(void)memmove(hc->response, &(hc->response[sz]), newlen);
			hc->responselen = newlen;
			sz = 0;
		} else {
			/* Nope, we wrote the full headers, so adjust accordingly. */
			sz -= hc->responselen;
			hc->responselen = 0;
		}
	}
	/* And update how much of the file we wrote. */
	c->next_byte_index += sz;
	c->hc->bytes_sent += sz;
	for (tind = 0; tind < c->numtnums; ++tind)
		throttles[c->tnums[tind]].bytes_since_avg += sz;

	/* Are we done? */
	if (c->next_byte_index >= c->end_byte_index) {
		/* This connection is finished! */
		finish_connection(c, tvP);
		return;
	}

	/* Tune the (blockheaded) wouldblock delay. */
	if (c->wouldblock_delay > MIN_WOULDBLOCK_DELAY)
		c->wouldblock_delay -= MIN_WOULDBLOCK_DELAY;

	/* If we're throttling, check if we're sending too fast. */
	if (c->max_limit != THROTTLE_NOLIMIT) {
		elapsed = tvP->tv_sec - c->started_at;
		if (elapsed == 0)
			elapsed = 1;	/* count at least one second */
		if (c->hc->bytes_sent / elapsed > c->max_limit) {
			c->conn_state = CNST_PAUSING;
			fdwatch_del_fd(hc->conn_fd);
			/* How long should we wait to get back on schedule?  If less
			 ** than a second (integer math rounding), use 1/2 second.
			 */
			coast = c->hc->bytes_sent / c->max_limit - elapsed;
			client_data.p = c;
			if (c->wakeup_timer)
				syslog(LOG_ERR, "replacing non-null wakeup_timer!");
			c->wakeup_timer = tmr_create(tvP, wakeup_connection, client_data, coast > 0 ? (coast * 1000L) : 500L, 0);
			if (!c->wakeup_timer) {
				syslog(LOG_CRIT, "tmr_create(wakeup_connection) failed");
				exit(1);
			}
		}
	}
	/* (No check on min_limit here, that only controls connection startups.) */
}


static void handle_linger(connecttab *c, struct timeval *tvP)
{
	httpd_conn *hc = c->hc;

	c->conn_state = CNST_READING;
	c->next_byte_index = 0;

	if (c->linger_timer)
		tmr_reset(tvP, c->linger_timer);

	/* release file memory */
	if (hc->file_address) {
		mmc_unmap(hc->file_address, &hc->sb, tvP);
		hc->file_address = NULL;
	}

	/* release httpd_conn auxiliary memory */
	httpd_destroy_conn(hc);

	/* reinitialize httpd_conn */
	httpd_init_conn_mem(hc);
	httpd_init_conn_content(hc);
}


static int check_throttles(connecttab *c)
{
	int tnum;
	long l;

	c->numtnums = 0;
	c->max_limit = c->min_limit = THROTTLE_NOLIMIT;
	for (tnum = 0; tnum < numthrottles && c->numtnums < MAXTHROTTLENUMS; ++tnum) {
		if (match(throttles[tnum].pattern, c->hc->expnfilename)) {
			/* If we're way over the limit, don't even start. */
			if (throttles[tnum].rate > throttles[tnum].max_limit * 2)
				return 0;

			/* Also don't start if we're under the minimum. */
			if (throttles[tnum].rate < throttles[tnum].min_limit)
				return 0;

			if (throttles[tnum].num_sending < 0) {
				syslog(LOG_ERR, "throttle sending count was negative - shouldn't happen!");
				throttles[tnum].num_sending = 0;
			}
			c->tnums[c->numtnums++] = tnum;
			++throttles[tnum].num_sending;

			l = throttles[tnum].max_limit / throttles[tnum].num_sending;
			if (c->max_limit == THROTTLE_NOLIMIT)
				c->max_limit = l;
			else
				c->max_limit = MIN(c->max_limit, l);

			l = throttles[tnum].min_limit;
			if (c->min_limit == THROTTLE_NOLIMIT)
				c->min_limit = l;
			else
				c->min_limit = MAX(c->min_limit, l);
		}
	}

	return 1;
}


static void clear_throttles(connecttab *c, struct timeval *tvP)
{
	int tind;

	for (tind = 0; tind < c->numtnums; ++tind)
		--throttles[c->tnums[tind]].num_sending;
}


static void update_throttles(ClientData client_data, struct timeval *nowP)
{
	int tnum, tind;
	int cnum;
	connecttab *c;
	long l;

	/* Update the average sending rate for each throttle.  This is only used
	 ** when new connections start up.
	 */
	for (tnum = 0; tnum < numthrottles; ++tnum) {
		throttles[tnum].rate = (2 * throttles[tnum].rate + throttles[tnum].bytes_since_avg / THROTTLE_TIME) / 3;
		throttles[tnum].bytes_since_avg = 0;

		/* Log a warning message if necessary. */
		if (throttles[tnum].rate > throttles[tnum].max_limit && throttles[tnum].num_sending != 0) {
			if (throttles[tnum].rate > throttles[tnum].max_limit * 2)
				syslog(LOG_NOTICE, "throttle #%d '%s' rate %ld greatly exceeding limit %ld; %d sending", tnum,
				       throttles[tnum].pattern, throttles[tnum].rate, throttles[tnum].max_limit,
				       throttles[tnum].num_sending);
			else
				syslog(LOG_INFO, "throttle #%d '%s' rate %ld exceeding limit %ld; %d sending", tnum,
				       throttles[tnum].pattern, throttles[tnum].rate, throttles[tnum].max_limit,
				       throttles[tnum].num_sending);
		}

		if (throttles[tnum].rate < throttles[tnum].min_limit && throttles[tnum].num_sending != 0) {
			syslog(LOG_NOTICE, "throttle #%d '%s' rate %ld lower than minimum %ld; %d sending", tnum,
			       throttles[tnum].pattern, throttles[tnum].rate, throttles[tnum].min_limit,
			       throttles[tnum].num_sending);
		}
	}

	/* Now update the sending rate on all the currently-sending connections,
	 ** redistributing it evenly.
	 */
	for (cnum = 0; cnum < max_connects; ++cnum) {
		c = &connects[cnum];
		if (c->conn_state == CNST_SENDING || c->conn_state == CNST_PAUSING) {
			c->max_limit = THROTTLE_NOLIMIT;

			for (tind = 0; tind < c->numtnums; ++tind) {
				tnum = c->tnums[tind];
				l = throttles[tnum].max_limit / throttles[tnum].num_sending;

				if (c->max_limit == THROTTLE_NOLIMIT)
					c->max_limit = l;
				else
					c->max_limit = MIN(c->max_limit, l);
			}
		}
	}
}


static void finish_connection(connecttab *c, struct timeval *tvP)
{
	/* If we haven't actually sent the buffered response yet, do so now. */
	httpd_write_response(c->hc);

	/* And clear. */
	clear_connection(c, tvP);
}


static void clear_connection(connecttab *c, struct timeval *tvP)
{
	ClientData client_data;

	if (c->wakeup_timer) {
		tmr_cancel(c->wakeup_timer);
		c->wakeup_timer = 0;
	}

	/* This is our version of Apache's lingering_close() routine, which is
	 ** their version of the often-broken SO_LINGER socket option.  For why
	 ** this is necessary, see http://www.apache.org/docs/misc/fin_wait_2.html
	 ** What we do is delay the actual closing for a few seconds, while reading
	 ** any bytes that come over the connection.  However, we don't want to do
	 ** this unless it's necessary, because it ties up a connection slot and
	 ** file descriptor which means our maximum connection-handling rate
	 ** is lower.  So, elsewhere we set a flag when we detect the few
	 ** circumstances that make a lingering close necessary.  If the flag
	 ** isn't set we do the real close now.
	 */
	if (c->conn_state == CNST_LINGERING) {
		/* If we were already lingering, shut down for real. */
		tmr_cancel(c->linger_timer);
		c->linger_timer = NULL;
		c->hc->should_linger = 0;
	}

	if (c->hc->should_linger) {
		if (c->conn_state != CNST_PAUSING)
			fdwatch_del_fd(c->hc->conn_fd);

		c->conn_state = CNST_LINGERING;
		fdwatch_add_fd(c->hc->conn_fd, c, FDW_READ);

		client_data.p = c;
		if (c->linger_timer) {
			tmr_reset(tvP,  c->linger_timer);
		} else {
			c->linger_timer = tmr_create(tvP, linger_clear_connection, client_data, LINGER_TIME, 0);
			if (!c->linger_timer) {
				syslog(LOG_CRIT, "tmr_create(linger_clear_connection) failed");
				exit(1);
			}
		}
	} else {
		really_clear_connection(c, tvP);
	}
}


static void really_clear_connection(connecttab *c, struct timeval *tvP)
{
	stats_bytes += c->hc->bytes_sent;
	if (c->conn_state != CNST_PAUSING)
		fdwatch_del_fd(c->hc->conn_fd);

	httpd_close_conn(c->hc, tvP);
	clear_throttles(c, tvP);
	if (c->linger_timer) {
		tmr_cancel(c->linger_timer);
		c->linger_timer = 0;
	}

	c->conn_state = CNST_FREE;
	c->next_free_connect = first_free_connect;
	first_free_connect = c - connects;	/* division by sizeof is implied */
	--num_connects;
}


static void idle(ClientData client_data, struct timeval *nowP)
{
	int cnum;
	connecttab *c;

	for (cnum = 0; cnum < max_connects; ++cnum) {
		c = &connects[cnum];
		switch (c->conn_state) {
		case CNST_READING:
			if (nowP->tv_sec - c->active_at >= IDLE_READ_TIMELIMIT) {
				syslog(LOG_INFO, "%s connection timed out reading", c->hc->client_addr.real_ip);
				httpd_send_err(c->hc, 408, httpd_err408title, "", httpd_err408form, "");
				finish_connection(c, nowP);
			}
			break;

		case CNST_SENDING:
		case CNST_PAUSING:
			if (nowP->tv_sec - c->active_at >= IDLE_SEND_TIMELIMIT) {
				syslog(LOG_INFO, "%s connection timed out sending", c->hc->client_addr.real_ip);
				clear_connection(c, nowP);
			}
			break;
		}
	}
}


static void wakeup_connection(ClientData client_data, struct timeval *nowP)
{
	connecttab *c;

	c = (connecttab *)client_data.p;
	c->wakeup_timer = NULL;
	if (c->conn_state == CNST_PAUSING) {
		c->conn_state = CNST_SENDING;
		fdwatch_add_fd(c->hc->conn_fd, c, FDW_WRITE);
	}
}

static void linger_clear_connection(ClientData client_data, struct timeval *nowP)
{
	connecttab *c;

	c = (connecttab *)client_data.p;
	c->linger_timer = NULL;
	really_clear_connection(c, nowP);
}


static void occasional(ClientData client_data, struct timeval *nowP)
{
	mmc_cleanup(nowP);
	tmr_cleanup();
	watchdog_flag = 1;	/* let the watchdog know that we are alive */
}


#ifdef STATS_TIME
static void show_stats(ClientData client_data, struct timeval *nowP)
{
	logstats(nowP);
}
#endif


/* Generate debugging statistics syslog messages for all packages. */
static void logstats(struct timeval *nowP)
{
	struct timeval tv;
	time_t now;
	long up_secs, stats_secs;

	if (!nowP) {
		(void)gettimeofday(&tv, NULL);
		nowP = &tv;
	}
	now = nowP->tv_sec;
	up_secs = now - start_time;
	stats_secs = now - stats_time;
	if (stats_secs == 0)
		stats_secs = 1;	/* fudge */
	stats_time = now;
	syslog(LOG_INFO, "up %ld seconds, stats for %ld seconds:", up_secs, stats_secs);

	merecat_logstats(stats_secs);
	httpd_logstats(stats_secs);
	mmc_logstats(stats_secs);
	fdwatch_logstats(stats_secs);
	tmr_logstats(stats_secs);
}


/* Generate debugging statistics syslog message. */
static void merecat_logstats(long secs)
{
	if (secs > 0)
		syslog(LOG_INFO,
		       "  %s - %ld connections (%g/sec), %d max simultaneous, %ld bytes (%g/sec), %d httpd_conns allocated",
		       PACKAGE_NAME, stats_connections, (float)stats_connections / secs,
		       stats_simultaneous, (long int)stats_bytes, (float)stats_bytes / secs, httpd_conn_count);
	stats_connections = 0;
	stats_bytes = 0;
	stats_simultaneous = 0;
}
