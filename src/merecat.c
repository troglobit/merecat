/* Simple, small and fast HTTP server
**
** Copyright (C) 1995-2015  Jef Poskanzer <jef@mail.acme.com>
** Copyright (C) 2016-2021  Joachim Wiberg <troglobit@gmail.com>
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
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
** AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNERS OR CONTRIBUTORS BE
** LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
** CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
** SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
** INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
** CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
** ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
** THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <config.h>

#include <getopt.h>
#include <pwd.h>
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#include <stdio.h>
#include <signal.h>

#define SYSLOG_NAMES
#include <syslog.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/uio.h>

#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

#include "conf.h"
#include "fdwatch.h"
#include "libhttpd.h"
#include "match.h"
#include "mmc.h"
#include "merecat.h"
#include "srv.h"
#include "ssl.h"
#include "timers.h"

#ifndef SHUT_WR
#define SHUT_WR 1
#endif

/* For content-encoding: gzip */
#ifdef HAVE_ZLIB_H
#define ZLIB_OUTPUT_BUF_SIZE 262136
#define DEFAULT_COMPRESSION  Z_DEFAULT_COMPRESSION
#else
#define DEFAULT_COMPRESSION  0
#endif

char        *prognm;		/* Instead of non-portable __progname */
char        *ident;		/* Used for logging */
int          loglevel          = LOG_NOTICE;
int          dbglevel          = LOG_DEBUG;
char         path[MAXPATHLEN + 1];

/* Global config settings */
uint16_t     port              = 0;
int          max_age           = 0;		      /* Disabled globally since v2.32 */
int          compression_level = DEFAULT_COMPRESSION; /* For content-encoding: gzip */
int          do_chroot         = 0;
int          do_vhost          = 0;
int          do_global_passwd  = 0;
int          do_list_dotfiles  = 0;
int          no_symlink_check  = 1;
int          no_empty_referers = 0;
int          cgi_enabled       = 0;
int          cgi_limit         = CGI_LIMIT;
char        *cgi_pattern       = CGI_PATTERN;
char        *local_pattern     = NULL;
char        *php_cgi           = NULL;
char        *php_pattern       = NULL;
char        *ssi_cgi           = NULL;
int          ssi_silent        = 0;
char        *ssi_pattern       = NULL;
char        *url_pattern       = NULL;
char        *dir               = NULL;
char        *data_dir          = NULL;
char        *hostname          = NULL;
char        *user              = DEFAULT_USER;    /* Usually www-data or nobody */
char        *charset           = DEFAULT_CHARSET;
char        *useragent_deny    = NULL;

/* Global options */
static char *throttlefile      = NULL;

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
	struct http_conn *hc;
	int tnums[MAXTHROTTLENUMS];	/* throttle indexes */
	int numtnums;
	long max_limit, min_limit;
	time_t started_at, active_at;
	struct timer *wakeup_timer;
	struct timer *linger_timer;
	long wouldblock_delay;
	off_t bytes;
	off_t end_byte_index;
	off_t next_byte_index;

#ifdef HAVE_ZLIB_H
	z_stream zs;
	int      zs_state;
	void    *zs_output_head;
#endif

	/* Proxy-pass state */
	int                proxy_fd;        /* Backend socket fd, -1 if none */
	struct http_proxy *proxy_rule;      /* Matched proxy rule */
	char              *proxy_req;       /* HTTP request to send to backend */
	size_t             proxy_req_len;   /* Total request length */
	size_t             proxy_req_sent;  /* Bytes forwarded to backend so far */
	char              *proxy_resp;      /* Buffered response from backend */
	size_t             proxy_resp_size; /* Allocated response buffer size */
	size_t             proxy_resp_len;  /* Bytes received from backend */
	size_t             proxy_resp_sent; /* Bytes forwarded to client so far */
} connecttab;
static connecttab *connects;
static int num_connects, max_connects, first_free_connect;
static int httpd_conn_count;

/* The connection states. */
#define CNST_FREE             0
#define CNST_READING          1
#define CNST_SENDING          2
#define CNST_PAUSING          3
#define CNST_LINGERING        4
/* Proxy-pass states: backend fd is in fdwatch (not conn_fd) */
#define CNST_PROXY_CONNECTING 5  /* Waiting for non-blocking connect() */
#define CNST_PROXY_SENDING    6  /* Sending HTTP request to backend */
#define CNST_PROXY_READING    7  /* Reading HTTP response from backend */
/* Response-forwarding state: conn_fd is back in fdwatch */
#define CNST_PROXY_SEND_RESP  8  /* Forwarding buffered response to client */

static struct httpd *server_list = NULL;
int terminate = 0;
time_t start_time, stats_time;
long stats_connections;
off_t stats_bytes;
int stats_simultaneous;

/* Configured by conf_srv(), or globals if no .conf support */
static struct srv srvtab[2];

static volatile int got_hup, got_bus, got_usr1, watchdog_flag;

/* External functions */
extern int pidfile(const char *basename);


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

	gettimeofday(&tv, NULL);

	while (fgets(buf, sizeof(buf), fp)) {
		/* Nuke comments. */
		cp = strchr(buf, '#');
		if (cp)
			*cp = '\0';

		/* Nuke trailing whitespace. */
		len = strlen(buf);
		while (len > 0 && (buf[len - 1] == ' '  ||
				   buf[len - 1] == '\t' ||
				   buf[len - 1] == '\n' ||
				   buf[len - 1] == '\r'))
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
			memmove(pattern, &pattern[1], strlen(pattern));
		while ((cp = strstr(pattern, "|/")))
			memmove(cp + 1, cp + 2, strlen(cp) - 1);

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
	(void)fclose(fp);
}


/* Generate debugging statistics syslog message. */
static void merecat_logstats(long secs)
{
	if (secs > 0)
		syslog(LOG_INFO, "  %s - %ld connections (%g/sec), %d max simultaneous, %ld bytes (%g/sec), %d httpd_conns allocated",
		       PACKAGE_NAME, stats_connections, (float)stats_connections / secs,
		       stats_simultaneous, (long int)stats_bytes, (float)stats_bytes / secs, httpd_conn_count);
	stats_connections = 0;
	stats_bytes = 0;
	stats_simultaneous = 0;
}


/* Generate debugging statistics syslog messages for all packages. */
static void logstats(struct timeval *now)
{
	struct timeval tv;
	time_t sec;
	long up_secs, stats_secs;

	if (!now) {
		gettimeofday(&tv, NULL);
		now = &tv;
	}

	sec = now->tv_sec;
	up_secs = sec - start_time;
	stats_secs = sec - stats_time;
	if (stats_secs == 0)
		stats_secs = 1;	/* fudge */

	stats_time = sec;
	syslog(LOG_INFO, "up %ld seconds, stats for %ld seconds:", up_secs, stats_secs);

	merecat_logstats(stats_secs);
	httpd_logstats(stats_secs);
	mmc_logstats(stats_secs);
	fdwatch_logstats(stats_secs);
	tmr_logstats(stats_secs);
}


static void shut_down(void)
{
	struct httpd *server;
	struct timeval tv;
	int i;

	gettimeofday(&tv, NULL);
	logstats(&tv);
	for (i = 0; i < max_connects; ++i) {
		if (connects[i].conn_state != CNST_FREE)
			httpd_close_conn(connects[i].hc, &tv);

		if (connects[i].hc) {
			httpd_destroy_conn(connects[i].hc);
			free(connects[i].hc);
			connects[i].hc = NULL;
			--httpd_conn_count;
		}
	}

	LIST_FOREACH(server, server_list) {
		LIST_REMOVE(server, server_list);
		srv_exit(server);
	}

	conf_exit();
	fdwatch_put_nfiles();
	mmc_destroy();
	tmr_destroy();
	free(connects);
	if (throttles)
		free(throttles);
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


static void clear_throttles(connecttab *c, struct timeval *tv)
{
	int tind;

	for (tind = 0; tind < c->numtnums; ++tind)
		--throttles[c->tnums[tind]].num_sending;
}


static void update_throttles(arg_t arg, struct timeval *now)
{
	int tnum, tind;
	int cnum;
	connecttab *c;
	long l;

	/* Update the average sending rate for each throttle.
	** This is only used when new connections start up.
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

	/* Now update the sending rate on all the currently-sending
	** connections, redistributing it evenly.
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


static void really_clear_connection(connecttab *c, struct timeval *tv)
{
	stats_bytes += c->hc->bytes_sent;

	/* conn_fd is NOT in fdwatch during proxy backend states or PAUSING */
	if (c->conn_state != CNST_PAUSING &&
	    c->conn_state != CNST_PROXY_CONNECTING &&
	    c->conn_state != CNST_PROXY_SENDING &&
	    c->conn_state != CNST_PROXY_READING)
		fdwatch_del_fd(c->hc->conn_fd);

	/* Close any open proxy backend connection */
	if (c->proxy_fd != -1) {
		fdwatch_del_fd(c->proxy_fd);
		close(c->proxy_fd);
		c->proxy_fd = -1;
	}
	free(c->proxy_req);  c->proxy_req  = NULL;
	free(c->proxy_resp); c->proxy_resp = NULL;
	c->proxy_rule = NULL;

	httpd_close_conn(c->hc, tv);
	clear_throttles(c, tv);
	if (c->linger_timer) {
		tmr_cancel(c->linger_timer);
		c->linger_timer = 0;
	}

#ifdef HAVE_ZLIB_H
	if (c->zs_output_head) {
		free(c->zs_output_head);
		c->zs_output_head = NULL;
		deflateEnd(&c->zs);
	}
#endif
	c->conn_state = CNST_FREE;
	c->next_free_connect = first_free_connect;
	first_free_connect = c - connects;	/* division by sizeof is implied */
	--num_connects;
}


static void wakeup_connection(arg_t arg, struct timeval *now)
{
	connecttab *c;

	c = (connecttab *)arg.p;
	c->wakeup_timer = NULL;
	if (c->conn_state == CNST_PAUSING) {
		c->conn_state = CNST_SENDING;
		fdwatch_add_fd(c->hc->conn_fd, c, FDW_WRITE);
	}
}

static void linger_clear_connection(arg_t arg, struct timeval *now)
{
	connecttab *c;

	c = (connecttab *)arg.p;
	c->hc->do_keep_alive = 0;
	c->linger_timer = NULL;
	really_clear_connection(c, now);
}


static void clear_connection(connecttab *c, struct timeval *tv)
{
	arg_t arg;

	if (c->wakeup_timer) {
		tmr_cancel(c->wakeup_timer);
		c->wakeup_timer = 0;
	}

	/* This is our version of Apache's lingering_close() routine, which is
	** their version of the often-broken SO_LINGER socket option.  For why
	** this is necessary, see [1].  What we do is delay the actual closing
	** for a few seconds, while reading any bytes that come over the
	** connection.  However, we don't want to do this unless it's
	** necessary, because it ties up a connection slot and file descriptor
	** which means our maximum connection-handling rate is lower.  So,
	** elsewhere we set a flag when we detect the few circumstances that
	** make a lingering close necessary.  If the flag isn't set we do the
	** real close now.
	**
	** [1]: http://www.apache.org/docs/misc/fin_wait_2.html
	*/
	if (c->conn_state == CNST_LINGERING && !c->hc->do_keep_alive) {
		/* If we were already lingering, shut down for real. */
		tmr_cancel(c->linger_timer);
		c->linger_timer = NULL;
		c->hc->should_linger = 0;
	}

	if (c->hc->do_keep_alive) {
		if (c->conn_state != CNST_PAUSING)
			fdwatch_del_fd(c->hc->conn_fd);
		fdwatch_add_fd(c->hc->conn_fd, c, FDW_READ);

		c->conn_state = CNST_READING;
		c->next_byte_index = 0;

		arg.p = c;
		if (c->linger_timer)
			tmr_cancel(c->linger_timer);

		/* release file memory */
		if (c->hc->file_address) {
			mmc_unmap(c->hc->file_address, &c->hc->sb, tv);
			c->hc->file_address = NULL;
		}

		/* release httpd_conn auxiliary memory */
		httpd_destroy_conn(c->hc);

		/* reinitialize httpd_conn */
		httpd_init_conn_mem(c->hc);
		httpd_init_conn_content(c->hc);

		/* Reset the connection file descriptor to no-delay mode. */
		(void)httpd_set_ndelay(c->hc->conn_fd);

		c->linger_timer = tmr_create(tv, linger_clear_connection, arg, KEEPALIVE_TIMELIMIT, 0);
		if (!c->linger_timer) {
			syslog(LOG_CRIT, "tmr_create(linger_clear_connection)2 failed");
			exit(1);
		}
	} else if (c->hc->should_linger) {
		if (c->conn_state != CNST_PAUSING)
			fdwatch_del_fd(c->hc->conn_fd);

		c->conn_state = CNST_LINGERING;
		shutdown(c->hc->conn_fd, SHUT_WR);
		fdwatch_add_fd(c->hc->conn_fd, c, FDW_READ);

		arg.p = c;
		if (c->linger_timer) {
			tmr_reset(tv,  c->linger_timer);
		} else {
			c->linger_timer = tmr_create(tv, linger_clear_connection, arg, LINGER_TIME, 0);
			if (!c->linger_timer) {
				syslog(LOG_CRIT, "tmr_create(linger_clear_connection) failed");
				exit(1);
			}
		}
	} else {
		really_clear_connection(c, tv);
	}
}


static void finish_connection(connecttab *c, struct timeval *tv)
{
	/* If we haven't actually sent the buffered response yet, do so now. */
	httpd_send_response(c->hc);

	/* And clear. */
	clear_connection(c, tv);
}


int handle_newconnect(struct httpd *hs, struct timeval *tv, int fd)
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
			tmr_run(tv);
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
			c->hc = NEW(struct http_conn, 1);
			if (!c->hc) {
				syslog(LOG_CRIT, "Out of memory allocating an httpd_conn");
				exit(1);
			}

			c->hc->initialized = 0;
			++httpd_conn_count;
		}

		/* Get the connection. */
		switch (httpd_get_conn(hs, fd, c->hc)) {
			/* Some error happened.  Run the timers, then the
			** existing connections.  Maybe the error will clear.
			*/
		case GC_FAIL:
			tmr_run(tv);
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
		c->active_at = tv->tv_sec;
		c->wakeup_timer = NULL;
		c->linger_timer = NULL;
		c->next_byte_index = 0;
		c->numtnums = 0;
		c->proxy_fd        = -1;
		c->proxy_rule      = NULL;
		c->proxy_req       = NULL;
		c->proxy_req_len   = 0;
		c->proxy_req_sent  = 0;
		c->proxy_resp      = NULL;
		c->proxy_resp_size = 0;
		c->proxy_resp_len  = 0;
		c->proxy_resp_sent = 0;

		/* Set the connection file descriptor to no-delay mode. */
		(void)httpd_set_ndelay(c->hc->conn_fd);

		fdwatch_add_fd(c->hc->conn_fd, c, FDW_READ);

		++stats_connections;
		if (num_connects > stats_simultaneous)
			stats_simultaneous = num_connects;
	}
}


/* -------------------------------------------------------------------------
** Proxy-pass: non-blocking reverse proxy state machine
** -----------------------------------------------------------------------*/

#define PROXY_RESP_INITIAL  65536
#define PROXY_RESP_MAX      (8 * 1024 * 1024)

/*
** Build the HTTP/1.0 request to forward to the backend server.
** Adds X-Forwarded-For, X-Real-IP, X-Forwarded-Proto and passes through
** the relevant client headers (Cookie, Authorization, Content-Type, etc.).
*/
static char *proxy_build_request(connecttab *c)
{
	struct http_conn  *hc  = c->hc;
	struct http_proxy *pr  = c->proxy_rule;
	const char        *method = httpd_method_str(hc->method);
	const char        *client = httpd_client(hc);
	const char        *proto  = hc->hs->ctx ? "https" : "http";
	const char        *url    = hc->encodedurl;
	char               url_buf[4096];
	char               cl_buf[64];
	char              *req = NULL;
	int                hlen;

	cl_buf[0] = '\0';

	/*
	 * URL to forward:
	 * - If backend has a non-trivial path (/something), strip the matched
	 *   URL prefix and prepend the backend path (nginx proxy_pass style).
	 * - Otherwise (backend path is "/" or empty) forward the original URL.
	 */
	if (pr->strip_prefix) {
		int         rc   = match(pr->pattern, url);
		const char *rem  = (rc > 1) ? url + rc : url;
		const char *base = strcmp(pr->path, "/") == 0 ? "" : pr->path;

		snprintf(url_buf, sizeof(url_buf), "%s%s%s",
			 base,
			 (rem[0] && rem[0] != '/') ? "/" : "",
			 rem);
		url = url_buf[0] ? url_buf : "/";
	}

	/* Pre-format Content-Length header only when a body is expected */
	if (hc->contentlength > 0)
		snprintf(cl_buf, sizeof(cl_buf),
			 "Content-Length: %zu\r\n", (size_t)hc->contentlength);

	hlen = asprintf(&req,
		"%s %s%s%s HTTP/1.0\r\n"
		"Host: %s\r\n"
		"Connection: close\r\n"
		"X-Forwarded-For: %s\r\n"
		"X-Real-IP: %s\r\n"
		"X-Forwarded-Proto: %s\r\n"
		"%s%s%s"   /* Accept */
		"%s%s%s"   /* Accept-Encoding */
		"%s%s%s"   /* User-Agent */
		"%s%s%s"   /* Referer */
		"%s%s%s"   /* Cookie */
		"%s%s%s"   /* Authorization */
		"%s%s%s"   /* Content-Type */
		"%s"       /* Content-Length (pre-formatted above) */
		"\r\n",
		method,
		url,
		(hc->query && hc->query[0]) ? "?" : "",
		(hc->query && hc->query[0]) ? hc->query : "",
		pr->host,
		client, client, proto,
		(hc->accept    && *hc->accept)    ? "Accept: "          : "",
		(hc->accept    && *hc->accept)    ? hc->accept          : "",
		(hc->accept    && *hc->accept)    ? "\r\n"              : "",
		(hc->accepte   && *hc->accepte)   ? "Accept-Encoding: " : "",
		(hc->accepte   && *hc->accepte)   ? hc->accepte         : "",
		(hc->accepte   && *hc->accepte)   ? "\r\n"              : "",
		(hc->useragent && *hc->useragent) ? "User-Agent: "      : "",
		(hc->useragent && *hc->useragent) ? hc->useragent       : "",
		(hc->useragent && *hc->useragent) ? "\r\n"              : "",
		(hc->referer   && *hc->referer)   ? "Referer: "         : "",
		(hc->referer   && *hc->referer)   ? hc->referer         : "",
		(hc->referer   && *hc->referer)   ? "\r\n"              : "",
		(hc->cookie    && *hc->cookie)    ? "Cookie: "          : "",
		(hc->cookie    && *hc->cookie)    ? hc->cookie          : "",
		(hc->cookie    && *hc->cookie)    ? "\r\n"              : "",
		(hc->authorization && *hc->authorization) ? "Authorization: " : "",
		(hc->authorization && *hc->authorization) ? hc->authorization : "",
		(hc->authorization && *hc->authorization) ? "\r\n"           : "",
		(hc->contenttype && *hc->contenttype) ? "Content-Type: " : "",
		(hc->contenttype && *hc->contenttype) ? hc->contenttype  : "",
		(hc->contenttype && *hc->contenttype) ? "\r\n"           : "",
		cl_buf);

	if (hlen < 0)
		return NULL;

	/* Append request body if present (POST, PUT, PATCH) */
	if (hc->contentlength > 0 && hc->read_idx > hc->checked_idx) {
		size_t avail    = hc->read_idx - hc->checked_idx;
		size_t body_len = avail < (size_t)hc->contentlength
		                  ? avail : (size_t)hc->contentlength;
		char  *full     = realloc(req, hlen + body_len + 1);

		if (!full) {
			free(req);
			return NULL;
		}
		memcpy(full + hlen, hc->read_buf + hc->checked_idx, body_len);
		full[hlen + body_len] = '\0';
		req   = full;
		hlen += body_len;
	}

	c->proxy_req_len = hlen;
	return req;
}

/*
** Send a 502 Bad Gateway error to the client and tear down the proxy
** connection.  Restores conn_fd in fdwatch so the normal close path works.
*/
static void proxy_error(connecttab *c, struct timeval *tv)
{
	struct http_conn *hc = c->hc;

	if (c->proxy_fd != -1) {
		fdwatch_del_fd(c->proxy_fd);
		close(c->proxy_fd);
		c->proxy_fd = -1;
	}
	free(c->proxy_req);  c->proxy_req  = NULL;
	free(c->proxy_resp); c->proxy_resp = NULL;
	c->proxy_rule = NULL;

	/*
	 * Restore conn_fd and reset state so the normal finish/clear path
	 * (which expects CNST_SENDING or similar) works correctly.
	 */
	fdwatch_add_fd(hc->conn_fd, c, FDW_WRITE);
	c->conn_state = CNST_SENDING;

	httpd_send_err(hc, 502, httpd_err502title, "", httpd_err502form, hc->encodedurl);
	finish_connection(c, tv);
}

/*
** Initiate a non-blocking connection to the proxy backend and build the
** request to forward.  Transitions to CNST_PROXY_CONNECTING.
*/
static int proxy_start(connecttab *c, struct timeval *tv)
{
	struct http_conn  *hc = c->hc;
	struct http_proxy *pr = c->proxy_rule;
	struct sockaddr_in sa;
	int                fd;

	/* Allocate response buffer */
	c->proxy_resp = malloc(PROXY_RESP_INITIAL);
	if (!c->proxy_resp) {
		syslog(LOG_ERR, "proxy-pass: out of memory for response buffer");
		return -1;
	}
	c->proxy_resp_size = PROXY_RESP_INITIAL;
	c->proxy_resp_len  = 0;
	c->proxy_resp_sent = 0;

	/* Build the forwarded request (headers + optional body) */
	c->proxy_req = proxy_build_request(c);
	if (!c->proxy_req) {
		syslog(LOG_ERR, "proxy-pass: failed building request");
		free(c->proxy_resp); c->proxy_resp = NULL;
		return -1;
	}
	c->proxy_req_sent = 0;

	if (!pr->resolved) {
		syslog(LOG_ERR, "proxy-pass: backend '%s' not resolved", pr->host);
		free(c->proxy_req);  c->proxy_req  = NULL;
		free(c->proxy_resp); c->proxy_resp = NULL;
		return -1;
	}

	/* Create a non-blocking TCP socket for the backend connection */
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		syslog(LOG_ERR, "proxy-pass: socket: %s", strerror(errno));
		free(c->proxy_req);  c->proxy_req  = NULL;
		free(c->proxy_resp); c->proxy_resp = NULL;
		return -1;
	}
	httpd_set_ndelay(fd);

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port   = htons(pr->port);
	sa.sin_addr   = pr->addr;

	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 &&
	    errno != EINPROGRESS) {
		syslog(LOG_ERR, "proxy-pass: connect %s:%d: %s",
		       pr->host, pr->port, strerror(errno));
		close(fd);
		free(c->proxy_req);  c->proxy_req  = NULL;
		free(c->proxy_resp); c->proxy_resp = NULL;
		return -1;
	}

	c->proxy_fd = fd;

	/* Stop watching the client fd; watch the backend fd for writability */
	fdwatch_del_fd(hc->conn_fd);
	fdwatch_add_fd(fd, c, FDW_WRITE);
	c->conn_state = CNST_PROXY_CONNECTING;

	syslog(LOG_DEBUG, "proxy-pass: connecting to %s:%d for %s",
	       pr->host, pr->port, hc->encodedurl);
	return 0;
}

/* CNST_PROXY_CONNECTING: connect() completed, start sending the request */
static void handle_proxy_connect(connecttab *c, struct timeval *tv)
{
	int       err    = 0;
	socklen_t errlen = sizeof(err);
	ssize_t   sz;

	if (getsockopt(c->proxy_fd, SOL_SOCKET, SO_ERROR, &err, &errlen) < 0 || err) {
		syslog(LOG_ERR, "proxy-pass: connect failed: %s",
		       err ? strerror(err) : strerror(errno));
		proxy_error(c, tv);
		return;
	}

	/* Connected — try to send the request right away */
	sz = write(c->proxy_fd,
		   c->proxy_req + c->proxy_req_sent,
		   c->proxy_req_len - c->proxy_req_sent);

	if (sz < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			c->conn_state = CNST_PROXY_SENDING;
			return;
		}
		syslog(LOG_ERR, "proxy-pass: write: %s", strerror(errno));
		proxy_error(c, tv);
		return;
	}

	c->proxy_req_sent += sz;
	if (c->proxy_req_sent >= c->proxy_req_len) {
		/* Request fully sent — switch to reading the response */
		fdwatch_del_fd(c->proxy_fd);
		fdwatch_add_fd(c->proxy_fd, c, FDW_READ);
		c->conn_state = CNST_PROXY_READING;
	} else {
		c->conn_state = CNST_PROXY_SENDING;
	}
}

/* CNST_PROXY_SENDING: continue draining the request buffer to the backend */
static void handle_proxy_send(connecttab *c, struct timeval *tv)
{
	ssize_t sz;

	sz = write(c->proxy_fd,
		   c->proxy_req + c->proxy_req_sent,
		   c->proxy_req_len - c->proxy_req_sent);

	if (sz < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return;
		syslog(LOG_ERR, "proxy-pass: write backend: %s", strerror(errno));
		proxy_error(c, tv);
		return;
	}

	c->proxy_req_sent += sz;
	if (c->proxy_req_sent >= c->proxy_req_len) {
		fdwatch_del_fd(c->proxy_fd);
		fdwatch_add_fd(c->proxy_fd, c, FDW_READ);
		c->conn_state = CNST_PROXY_READING;
	}
}

/*
 * Rewrite Location: and Refresh: response headers in the fully-buffered
 * backend response, replacing redirect_from with redirect_to.
 *
 * This corrects root-relative redirects when a backend is proxied under a
 * sub-path: e.g. backend sends "Location: /login", proxy-redirect rewrites
 * it to "Location: /app/login" so the browser stays inside the proxy prefix.
 *
 * Only the header region (before "\r\n\r\n") is modified.  If the replacement
 * would cause the buffer to exceed PROXY_RESP_MAX the rewrite is skipped and
 * a warning is logged.
 */
static void proxy_rewrite_headers(connecttab *c)
{
	struct http_proxy *pr   = c->proxy_rule;
	const char        *from = pr->redirect_from;
	const char        *to   = pr->redirect_to;
	size_t  from_len = strlen(from);
	size_t  to_len   = strlen(to);
	char   *buf      = c->proxy_resp;
	size_t  len      = c->proxy_resp_len;
	char   *hdr_end;
	size_t  hdr_len;

	/* Targets: header names whose URL value we may rewrite */
	static const char *const targets[] = {
		"\r\nLocation: ",
		"\r\nRefresh: ",
	};

	/* Locate end of HTTP headers */
	hdr_end = memmem(buf, len, "\r\n\r\n", 4);
	if (!hdr_end)
		return;
	hdr_len = (size_t)(hdr_end - buf) + 4;

	for (size_t t = 0; t < NELEMS(targets); t++) {
		const char *tgt     = targets[t];
		size_t      tgt_len = strlen(tgt);
		char       *p       = buf;
		char       *end     = buf + hdr_len;

		while (p + tgt_len < end) {
			/* Case-insensitive search for the header name */
			char *found = NULL;

			for (char *q = p; q + tgt_len <= end; q++) {
				if (*q == '\r' &&
				    strncasecmp(q, tgt, tgt_len) == 0) {
					found = q + tgt_len;
					break;
				}
			}
			if (!found)
				break;

			/* For Refresh: skip past "N; url=" */
			char *val = found;
			if (tgt == targets[1]) {
				char *u = NULL;
				char *eol = memchr(val, '\r', (size_t)(end - val));
				size_t vlen = eol ? (size_t)(eol - val) : (size_t)(end - val);

				for (size_t i = 0; i + 4 <= vlen; i++) {
					if (strncasecmp(val + i, "url=", 4) == 0) {
						u = val + i + 4;
						break;
					}
				}
				if (!u) {
					p = found;
					continue;
				}
				val = u;
			}

			/* Check if the URL value starts with redirect_from */
			if ((size_t)(end - val) < from_len ||
			    strncmp(val, from, from_len) != 0) {
				p = found;
				continue;
			}

			/* Grow or shrink the buffer to accommodate the replacement */
			ssize_t delta = (ssize_t)to_len - (ssize_t)from_len;
			if (delta > 0) {
				size_t new_len = len + (size_t)delta;
				if (new_len > PROXY_RESP_MAX) {
					syslog(LOG_WARNING,
					       "proxy-redirect: skipping rewrite, "
					       "buffer would exceed %d bytes",
					       PROXY_RESP_MAX);
					return;
				}
				if (new_len > c->proxy_resp_size) {
					char *nb = realloc(c->proxy_resp, new_len);
					if (!nb) {
						syslog(LOG_WARNING,
						       "proxy-redirect: skipping rewrite, "
						       "out of memory");
						return;
					}
					/* Recalculate pointers after realloc */
					size_t val_off = (size_t)(val - buf);
					size_t end_off = (size_t)(end - buf);
					c->proxy_resp      = nb;
					c->proxy_resp_size = new_len;
					buf = nb;
					val = buf + val_off;
					end = buf + end_off;
				}
			}

			/* Shift everything after FROM to make room for TO */
			char  *after_from = val + from_len;
			size_t tail_len   = len - (size_t)(after_from - buf);
			memmove(val + to_len, after_from, tail_len);
			memcpy(val, to, to_len);

			len     += (size_t)delta;
			hdr_len += (size_t)delta;
			end      = buf + hdr_len;

			/* Advance past the replacement to avoid re-matching */
			p = val + to_len;
		}
	}

	c->proxy_resp_len = len;
}

/* CNST_PROXY_READING: buffer the backend response until the connection closes */
static void handle_proxy_read(connecttab *c, struct timeval *tv)
{
	struct http_conn *hc = c->hc;
	ssize_t           sz;

	/* Grow the response buffer if it is full */
	if (c->proxy_resp_len >= c->proxy_resp_size) {
		size_t  new_size = c->proxy_resp_size * 2;
		char   *new_buf;

		if (new_size > PROXY_RESP_MAX) {
			syslog(LOG_ERR, "proxy-pass: response exceeds %d bytes", PROXY_RESP_MAX);
			proxy_error(c, tv);
			return;
		}
		new_buf = realloc(c->proxy_resp, new_size);
		if (!new_buf) {
			syslog(LOG_ERR, "proxy-pass: out of memory growing response buffer");
			proxy_error(c, tv);
			return;
		}
		c->proxy_resp      = new_buf;
		c->proxy_resp_size = new_size;
	}

	sz = read(c->proxy_fd,
		  c->proxy_resp + c->proxy_resp_len,
		  c->proxy_resp_size - c->proxy_resp_len);

	if (sz < 0) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return;
		syslog(LOG_ERR, "proxy-pass: read backend: %s", strerror(errno));
		proxy_error(c, tv);
		return;
	}

	if (sz == 0) {
		/* Backend closed the connection — full response is buffered */
		syslog(LOG_DEBUG, "proxy-pass: %zu byte response from %s for %s",
		       c->proxy_resp_len, c->proxy_rule->host, hc->encodedurl);

		fdwatch_del_fd(c->proxy_fd);
		close(c->proxy_fd);
		c->proxy_fd = -1;

		free(c->proxy_req);
		c->proxy_req = NULL;

		/* Rewrite Location:/Refresh: headers if proxy-redirect is configured */
		if (c->proxy_rule->redirect_from)
			proxy_rewrite_headers(c);

		/* Hand the buffered response back to the client */
		hc->bytes_sent = 0;
		fdwatch_add_fd(hc->conn_fd, c, FDW_WRITE);
		c->conn_state = CNST_PROXY_SEND_RESP;
		return;
	}

	c->proxy_resp_len += sz;
}

/* CNST_PROXY_SEND_RESP: stream the buffered backend response to the client */
static void handle_proxy_send_resp(connecttab *c, struct timeval *tv)
{
	struct http_conn *hc = c->hc;
	ssize_t           sz;

	sz = httpd_write(hc,
			 c->proxy_resp + c->proxy_resp_sent,
			 c->proxy_resp_len - c->proxy_resp_sent);

	if (sz == 0 || (sz < 0 && (errno == EWOULDBLOCK || errno == EAGAIN)))
		return;

	if (sz < 0) {
		if (errno != EPIPE && errno != ECONNRESET)
			syslog(LOG_ERR, "proxy-pass: write client: %s", strerror(errno));
		clear_connection(c, tv);
		return;
	}

	c->proxy_resp_sent += sz;
	hc->bytes_sent     += sz;

	if (c->proxy_resp_sent >= c->proxy_resp_len) {
		/* Proxy response fully delivered — close gracefully */
		hc->do_keep_alive = 0;
		finish_connection(c, tv);
	}
}

/* -----------------------------------------------------------------------*/

static void handle_read(connecttab *c, struct timeval *tv)
{
	int sz;
	struct http_conn *hc = c->hc;

	/* Is there room in our buffer to read more bytes? */
	if (hc->read_idx >= hc->read_size) {
		if (hc->read_size > 5000) {
			httpd_send_err(hc, 400, httpd_err400title, "", httpd_err400form, "");
			finish_connection(c, tv);
			return;
		}
		httpd_realloc_str(&hc->read_buf, &hc->read_size, hc->read_size + 1000);
	}

	/* Read some more bytes. */
	sz = httpd_read(hc, &(hc->read_buf[hc->read_idx]), hc->read_size - hc->read_idx);
	if (sz == 0) {
//		if (!hc->do_keep_alive)
//			httpd_send_err(hc, 400, httpd_err400title, "", httpd_err400form, "");
		if (hc->do_keep_alive)
			hc->do_keep_alive--;

		c->active_at = tv->tv_sec;
		finish_connection(c, tv);
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

//		httpd_send_err(hc, 400, httpd_err400title, "", httpd_err400form, "");
		finish_connection(c, tv);
		return;
	}

	hc->read_idx += sz;
	c->active_at = tv->tv_sec;

	/* Do we have a complete request yet? */
	switch (httpd_got_request(hc)) {
	case GR_NO_REQUEST:
		return;

	case GR_BAD_REQUEST:
//		httpd_send_err(hc, 400, httpd_err400title, "", httpd_err400form, "");
		finish_connection(c, tv);
		return;
	}

	/* Must tell libhttpd if we can deflate files */
#ifdef HAVE_ZLIB_H
	hc->has_deflate = compression_level != 0;
#else
	hc->has_deflate = 0;
#endif

	/* Yes.  Try parsing and resolving it. */
	if (httpd_parse_request(hc) < 0) {
		finish_connection(c, tv);
		return;
	}

	/* Check the throttle table */
	if (!check_throttles(c)) {
		httpd_send_err(hc, 503, httpd_err503title, "", httpd_err503form, hc->encodedurl);
		finish_connection(c, tv);
		return;
	}

	/* Check for a proxy-pass rule before trying to serve a local file */
	{
		struct http_proxy *pr = httpd_proxy_match(hc);

		if (pr) {
			c->proxy_rule = pr;
			if (proxy_start(c, tv) < 0) {
				httpd_send_err(hc, 502, httpd_err502title, "",
					       httpd_err502form, hc->encodedurl);
				finish_connection(c, tv);
			}
			return;
		}
	}

	/* Start the connection going. */
	if (httpd_start_request(hc, tv) < 0) {
		/* Something went wrong.  Close down the connection. */
		finish_connection(c, tv);
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

		finish_connection(c, tv);
		return;
	}

	if (c->next_byte_index >= c->end_byte_index) {
		/* There's nothing to send. */
		finish_connection(c, tv);
		return;
	}

	/* Cool, we have a valid connection and a file to send to it. */
	c->conn_state = CNST_SENDING;
	c->started_at = tv->tv_sec;
	c->wouldblock_delay = 0;

#ifdef HAVE_ZLIB_H
	if (hc->compression_type != COMPRESSION_NONE) {
		/* setup default zlib memory allocation routines */
		c->zs.zalloc = Z_NULL;
		c->zs.zfree  = Z_NULL;
		c->zs.opaque = Z_NULL;

		/* setup zlib input file to mmap'ed location */
		c->zs.next_in  = (Bytef *)c->hc->file_address;
		c->zs.avail_in = c->hc->sb.st_size;

		/* allocate memory for output buffer, if it's not already allocated */
		if (!c->zs_output_head) {
			c->zs_output_head = malloc(ZLIB_OUTPUT_BUF_SIZE + 8);
			if (!c->zs_output_head) {
				syslog(LOG_CRIT, "out of memory allocating deflate buffer");
				exit(1);
			}
		}

		if (hc->compression_type == COMPRESSION_GZIP) {
			/* add gzip header to output file */
			sprintf(c->zs_output_head, "%c%c%c%c%c%c%c%c%c%c",
				0x1f, 0x8b,
				Z_DEFLATED,
				0 /*flags*/,
#if 0 /* Seems to be optional according to https://tools.ietf.org/html/rfc1952 */
				&c->hc->sb.st_mtime, /* XXX: use a more transportable implementation! */
				&c->hc->sb.st_mtime + 1,
				&c->hc->sb.st_mtime + 2,
				&c->hc->sb.st_mtime + 3,
#else
				0, 0, 0, 0,
#endif
				0 /*xflags*/,
				0x03);

			c->zs.next_out  = c->zs_output_head + 10;
			c->zs.avail_out = ZLIB_OUTPUT_BUF_SIZE - 10;
		}

		/* call the initialization for zlib with negative window
		** size to omit the "deflate" prefix
		*/
		c->zs_state = deflateInit2(&c->zs, compression_level, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY);
		if (c->zs_state != Z_OK) {
			syslog(LOG_CRIT, "zlib deflateInit2() failed!");
			exit(1);
		}
	}
#endif /* HAVE_ZLIB_H */

	fdwatch_del_fd(hc->conn_fd);
	fdwatch_add_fd(hc->conn_fd, c, FDW_WRITE);
}


static void handle_send(connecttab *c, struct timeval *tv)
{
	size_t max_bytes;
	ssize_t sz = -1;
	int coast;
	arg_t arg;
	time_t elapsed;
	struct http_conn *hc = c->hc;
	int tind;

	if (c->max_limit == THROTTLE_NOLIMIT)
		max_bytes = 1000000000L;
	else
		max_bytes = c->max_limit / 4;	/* send at most 1/4 seconds worth */

	if (hc->compression_type == COMPRESSION_NONE) {
		/* Do we need to write the headers first? */
		if (hc->responselen == 0) {
			/* No, just write the file. */
			sz = httpd_write(hc, &(hc->file_address[c->next_byte_index]),
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
			sz = httpd_writev(hc, iv, 2);
		}
#ifdef HAVE_ZLIB_H
	} else {
		int iv_count;
		struct iovec iv[2];

		/* call deflate only if necessary */
		if ((c->zs_state == Z_OK) && (c->zs.avail_out > 0)) {
			c->zs_state = deflate(&c->zs, Z_FINISH);

			/* when zlib claims to be done, add the suffix info */
			if (c->zs_state == Z_STREAM_END) {
				uLong crc = crc32(0L, Z_NULL, 0);

				/* crc32 must not be converted into network byte order */
				crc = crc32(crc, (Bytef *)c->hc->file_address, c->hc->sb.st_size);
				memcpy(c->zs.next_out, &crc, sizeof(uLong));
				memcpy(c->zs.next_out + 4, &(hc->sb.st_size), 4);
				c->zs.next_out += 8;
			}
		}

		/* Do we need to write the headers first? */
		iv_count = 1;
		iv[0].iov_base = c->zs_output_head;
		iv[0].iov_len = c->zs.next_out - (Bytef *)c->zs_output_head;

		if (hc->responselen != 0) {
			/* Yes.  We'll combine headers and file into a single writev(),
			** hoping that this generates a single packet.
			*/
			iv_count = 2;
			iv[0].iov_base = hc->response;
			iv[0].iov_len  = hc->responselen;
			iv[1].iov_base = c->zs_output_head;
			iv[1].iov_len  = c->zs.next_out - (Bytef *)c->zs_output_head;
		}
		sz = httpd_writev(hc, iv, iv_count);
#endif /* HAVE_ZLIB_H */
	}

	if (sz < 0 && errno == EINTR) {
		clear_connection(c, tv);
		return;
	}

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
		arg.p = c;

		if (c->wakeup_timer)
			syslog(LOG_ERR, "replacing non-null wakeup_timer!");

		c->wakeup_timer = tmr_create(tv, wakeup_connection, arg, c->wouldblock_delay, 0);
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
		if (errno != EPIPE && errno != EINVAL && errno != ECONNRESET && hc->errmsg)
			syslog(LOG_ERR, "write failed: %s while sending %s", hc->errmsg, hc->encodedurl);
		clear_connection(c, tv);
		return;
	}

	/* Ok, we wrote something. */
	c->active_at = tv->tv_sec;
	/* Was this a headers + file writev()? */
	if (hc->responselen > 0) {
		/* Yes; did we write only part of the headers? */
		if ((size_t)sz < hc->responselen) {
			/* Yes; move the unwritten part to the front of the buffer. */
			int newlen = hc->responselen - sz;

			memmove(hc->response, &(hc->response[sz]), newlen);
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
	if (c->hc->compression_type == COMPRESSION_NONE) {
		if (c->next_byte_index >= c->end_byte_index) {
			/* This connection is finished! */
			finish_connection(c, tv);
			return;
		}
#ifdef HAVE_ZLIB_H
	} else {
		if ((c->zs_state == Z_STREAM_END) && (c->zs_output_head + sz == c->zs.next_out)) {
			/* This conection is finished! */
			clear_connection(c, tv);
			return;
		} else if (sz > 0) {
			/* move data to beginning of zlib output buffer
			** and set up pointers so next zlib output goes
			** to where we left off */
			/* this can be optimized by using a looping buffer thing */
			memcpy(c->zs_output_head, c->zs_output_head + sz, ZLIB_OUTPUT_BUF_SIZE - sz + 8);
			c->zs.next_out -= sz;
			c->zs.avail_out = sz;
		}
#endif /* HAVE_ZLIB_H */
	}

	/* Tune the (blockheaded) wouldblock delay. */
	if (c->wouldblock_delay > MIN_WOULDBLOCK_DELAY)
		c->wouldblock_delay -= MIN_WOULDBLOCK_DELAY;

	/* If we're throttling, check if we're sending too fast. */
	if (c->max_limit != THROTTLE_NOLIMIT) {
		elapsed = tv->tv_sec - c->started_at;
		if (elapsed == 0)
			elapsed = 1;	/* count at least one second */

		if (c->hc->bytes_sent / elapsed > c->max_limit) {
			c->conn_state = CNST_PAUSING;
			fdwatch_del_fd(hc->conn_fd);
			/* How long should we wait to get back on schedule?  If less
			 ** than a second (integer math rounding), use 1/2 second.
			 */
			coast = c->hc->bytes_sent / c->max_limit - elapsed;
			arg.p = c;
			if (c->wakeup_timer)
				syslog(LOG_ERR, "replacing non-null wakeup_timer!");
			c->wakeup_timer = tmr_create(tv, wakeup_connection, arg,
						     coast > 0 ? (coast * 1000L) : 500L, 0);
			if (!c->wakeup_timer) {
				syslog(LOG_CRIT, "tmr_create(wakeup_connection) failed");
				exit(1);
			}
		}
	}
	/* (No check on min_limit here, that only controls connection startups.) */
}


static void handle_linger(connecttab *c, struct timeval *tv)
{
	ssize_t r;
	char buf[512];

	/* In lingering-close mode we just read and ignore bytes.  An error
	** or EOF ends things, otherwise we go until a timeout.
	*/
	do {
		r = httpd_read(c->hc, buf, sizeof(buf));
		if (r < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
			return;
	} while (r > 0);

	if (r <= 0)
		really_clear_connection(c, tv);
}


static void idle(arg_t arg, struct timeval *now)
{
	int cnum;
	connecttab *c;

	for (cnum = 0; cnum < max_connects; ++cnum) {
		c = &connects[cnum];
		switch (c->conn_state) {
		case CNST_READING:
			if (now->tv_sec - c->active_at >= IDLE_READ_TIMELIMIT) {
				syslog(LOG_INFO, "%.80s: connection timed out reading",
				       httpd_client(c->hc));
//				httpd_send_err(c->hc, 408, httpd_err408title, "", httpd_err408form, "");
				finish_connection(c, now);
			}
			break;

		case CNST_SENDING:
		case CNST_PAUSING:
			if (now->tv_sec - c->active_at >= IDLE_SEND_TIMELIMIT) {
				syslog(LOG_INFO, "%.80s: connection timed out sending",
				       httpd_client(c->hc));
				clear_connection(c, now);
			}
			break;
		}
	}
}


static void occasional(arg_t arg, struct timeval *now)
{
	mmc_cleanup(now);
	tmr_cleanup();
	watchdog_flag = 1;	/* let the watchdog know that we are alive */
}


#ifdef STATS_TIME
static void show_stats(arg_t arg, struct timeval *now)
{
	logstats(now);
}
#endif


/* SIGTERM and SIGINT say to exit immediately. */
static void handle_term(int signo)
{
	syslog(LOG_NOTICE, "Exiting due to signal %d, dropping %d connections.", signo, num_connects);
	shut_down();
	closelog();
	exit(0);
}


/* SIGCHLD - a chile process exitted, so we need to reap the zombie */
static void handle_chld(int signo)
{
	struct httpd *server;
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
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
				continue;

			/* ECHILD shouldn't happen with the WNOHANG option,
			** but with some kernels it does anyway.  Ignore it.
			*/
			if (errno != ECHILD)
				syslog(LOG_ERR, "child wait: %s", strerror(errno));
			break;
		}

		/* Decrement CGI count.  Ignore PID from any CGI children */
		LIST_FOREACH(server, server_list) {
			if (!httpd_cgi_untrack(server, pid))
				break;
		}
	}

	/* Restore previous errno. */
	errno = oerrno;
}


/* SIGBUS is a workaround for Linux 2.4.x / NFS */
static void handle_bus(int sig)
{
	const int oerrno = errno;

	/* Just set a flag that we got the signal. */
	got_bus = 1;

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


/* SIGUSR1 says to toggle debug mode. */
static void handle_usr1(int signo)
{
	if (!got_usr1)
		got_usr1 = 1;
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
		syslog(LOG_WARNING, "Got caught reading Vogon poetry ... aborting.");
#ifdef HAVE_BACKTRACE
		stack_trace();
#endif

		/* Try changing dirs to someplace we can write. */
		chdir("/tmp");

		/* Dump core. */
		abort();
	}
	watchdog_flag = 0;

	/* Set up alarm again. */
	alarm(OCCASIONAL_TIME * 3);

	/* Restore previous errno. */
	errno = oerrno;
}

static void init_signals(void)
{
	size_t i;
	struct sigaction sa;
	struct { int signo; void (*cb)(int); } signals[] = {
		{ SIGTERM,  handle_term },
		{ SIGTERM,  handle_term },
		{ SIGINT,   handle_term },
		{ SIGCHLD,  handle_chld },
		{ SIGPIPE,  SIG_IGN     }, /* get EPIPE instead */
		{ SIGHUP,   handle_bus  },
		{ SIGHUP,   handle_hup  },
		{ SIGUSR1,  handle_usr1 },
		{ SIGUSR2,  handle_usr2 },
		{ SIGALRM,  handle_alrm },
	};

	memset(&sa, 0, sizeof(sa));
	for (i = 0; i < NELEMS(signals); i++) {
		sa.sa_flags   = SA_RESTART;
		sa.sa_handler = signals[i].cb;
		if (sigaction(signals[i].signo, &sa, NULL))
			syslog(LOG_WARNING, "Failed setting up handler for signo %d: %s",
			       signals[i].signo, strerror(errno));
	}

	got_bus = 0;
	got_hup = 0;
	got_usr1 = 0;
	watchdog_flag = 0;
	alarm(OCCASIONAL_TIME * 3);
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
#ifdef HAVE_LIBCONFUSE
	printf("Usage: %s [OPTIONS] [WEBROOT]\n"
	       "\n"
	       "  -f FILE    Configuration file, default: " CONFDIR "/%s.conf\n"
#else
	printf("Usage: %s [OPTIONS] [WEBROOT] [HOSTNAME]\n"
	       "\n"
	       "  -c CGI     CGI pattern to allow, e.g. \"**\", \"**.cgi\", \"/cgi-bin/*\",\n"
	       "             built-in default: \"" CGI_PATTERN "\"\n"
	       "  -d DIR     Optional DIR to change into after chrooting to WEBROOT\n"
	       "  -g         Use global password, .htpasswd, and .htaccess files\n"
#endif
	       "  -h         This help text\n"
	       "  -I IDENT   Identity for syslog, .conf, and PID file, default: %s\n"
	       "  -l LEVEL   Set log level: none, err, warning, notice*, info, debug\n"
	       "  -n         Run in foreground, do not detach from controlling terminal\n"
	       "  -p PORT    Port to listen to, default 80, or 443 if HTTPS is enabled\n"
	       "  -P PIDFN   Path to PID file, default: " RUNDIR "/%s.pid\n"
#ifndef HAVE_LIBCONFUSE
	       "  -r         Chroot into WEBROOT\n"
	       "  -S         Check symlinks so they don't point outside WEBROOT\n"
#endif
	       "  -s         Log to syslog, even though running in foreground, -n\n"
	       "  -t FILE    Throttle file\n"
#ifndef HAVE_LIBCONFUSE
	       "  -u USER    Username to drop to, default: nobody\n"
	       "  -v         Enable virtual hosting with WEBROOT as base\n"
#endif
	       "  -V         Show Merecat httpd version\n"
	       "\n", prognm,
#ifdef HAVE_LIBCONFUSE
	       ident,
#endif
	       prognm, ident);

	printf(
#ifndef HAVE_LIBCONFUSE
		"WEBROOT defaults to the current directory.  HOSTNAME is for virtual\n"
		"hosting, one httpd per hostname.  Note, '-d DIR' is not required in\n"
		"virtual hosting mode, see merecat(8) for details.\n"
		"\n"
#endif
		"*) Default log level\n"
		"\n"
		"Bug report address: %-40s\n", PACKAGE_BUGREPORT);

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
	struct http_conn *hc;
	struct httpd *server;
	struct timeval tv;
	struct passwd *pwd;
	connecttab *ct;
	uid_t uid = 32767;
	gid_t gid = 32767;
	char *pidfn = NULL;
	char *config = NULL;
	int log_opts = LOG_PID | LOG_NDELAY;
	int background = 1;
	int do_syslog  = 1;
	int num_ready;
	int num, cnum;
	int c;

	ident = prognm = progname(argv[0]);
	while ((c = getopt(argc, argv, "c:d:f:ghI:l:np:P:rsSt:u:vV")) != EOF) {
		switch (c) {
#ifndef HAVE_LIBCONFUSE
		case 'c':
			cgi_pattern = optarg;
			break;

		case 'd':
			data_dir = optarg;
			break;

		case 'g':
			do_global_passwd = 1;
			break;
#endif

		case 'f':
#ifndef HAVE_LIBCONFUSE
			syslog(LOG_ERR, "%s is not built with .conf file support", PACKAGE_NAME);
			return 1;
#else
			config = optarg;
#endif
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
			if (LOG_DEBUG == loglevel)
				dbglevel = LOG_NOTICE;
			break;

		case 'n':
			background = 0;
			do_syslog--;
			break;

		case 'p':
			port = (unsigned short)atoi(optarg);
			break;

		case 'P':
			pidfn = optarg;
			break;

		case 's':
			do_syslog++;
			break;

#ifndef HAVE_LIBCONFUSE
		case 'r':
			do_chroot = 1;
			no_symlink_check = 1;
			break;

		case 'S':
			no_symlink_check = 0;
			break;
#endif

		case 't':
			throttlefile = optarg;
			break;

#ifndef HAVE_LIBCONFUSE
		case 'u':
			user = optarg;
			break;

		case 'v':
			do_vhost = 1;
			break;
#endif

		case 'V':
			return version();

		default:
			return usage(1);
		}
	}

	if (optind < argc)
		dir = argv[optind++];

	if (optind < argc)
		hostname = argv[optind++];

#ifdef LOG_PERROR
	if (!background && !do_syslog)
		log_opts |= LOG_PERROR;
#endif
	openlog(ident, log_opts, LOG_FACILITY);
	setlogmask(LOG_UPTO(loglevel));

	/* Read merecat.conf, if available */
	conf_init(config);

	/* Read zone info now, in case we chroot(). */
	tzset();

	/* Throttle file. */
	numthrottles = 0;
	maxthrottles = 0;
	throttles = NULL;
	if (throttlefile)
		read_throttlefile(throttlefile);

	/* If we're root and we're going to drop privileges to become another
	** user, get their uid/gid now.
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
#endif /* USE_USER_DIR */

	/* Get current directory. */
	getcwd(path, sizeof(path) - 1);
	if (path[strlen(path) - 1] != '/')
		strlcat(path, "/", sizeof(path));

	if (background) {
		/* We're not going to use stdin stdout or stderr from here on,
		** so close them to save file descriptors.
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
#else /* HAVE_DAEMON */
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
		setsid();
#endif
#endif /* HAVE_DAEMON */
	} else {
		/* Even if we don't daemonize, we still want to disown our
		** parent process.
		*/
#ifdef HAVE_SETSID
		setsid();
#endif
	}

	/* Initialize the fdwatch package.  We have to do this before
	** chrooting, if /dev/poll is used.
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

		strlcpy(path, "/", sizeof(path));
		/* Always chdir to / after a chroot. */
		if (chdir(path) < 0) {
			syslog(LOG_CRIT, "chroot chdir: %s", strerror(errno));
			exit(1);
		}
	}

	/* Switch directories again if requested. */
	if (data_dir) {
		if (data_dir[0] == '/')
			strlcat(path, &data_dir[1], sizeof(path));
		else
			strlcat(path, data_dir, sizeof(path));

		if (chdir(path) < 0) {
			syslog(LOG_CRIT, "data-directory chdir: %s", strerror(errno));
			exit(1);
		}

		if (path[strlen(path) - 1] != '/')
			strlcat(path, "/", sizeof(path));
	}

	/* Set up to catch signals. */
	init_signals();

	/* Initialize the timer package. */
	tmr_init();

	/* Set up the occasional timer. */
	if (!tmr_create(NULL, occasional, noarg, OCCASIONAL_TIME * 1000L, 1)) {
		syslog(LOG_CRIT, "tmr_create(occasional) failed");
		exit(1);
	}

	/* Set up the idle timer. */
	if (!tmr_create(NULL, idle, noarg, 5 * 1000L, 1)) {
		syslog(LOG_CRIT, "tmr_create(idle) failed");
		exit(1);
	}

	if (numthrottles > 0) {
		/* Set up the throttles timer. */
		if (!tmr_create(NULL, update_throttles, noarg, THROTTLE_TIME * 1000L, 1)) {
			syslog(LOG_CRIT, "tmr_create(update_throttles) failed");
			exit(1);
		}
	}

#ifdef STATS_TIME
	/* Set up the stats timer. */
	if (!tmr_create(NULL, show_stats, noarg, STATS_TIME * 1000L, 1)) {
		syslog(LOG_CRIT, "tmr_create(show_stats) failed");
		exit(1);
	}
#endif

	start_time = stats_time = time(NULL);
	stats_connections = 0;
	stats_bytes = 0;
	stats_simultaneous = 0;

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
#ifdef HAVE_ZLIB_H
		connects[cnum].zs_output_head = NULL;
#endif
	}
	connects[max_connects - 1].next_free_connect = -1;	/* end of link list */
	first_free_connect = 0;
	num_connects = 0;
	httpd_conn_count = 0;

	/* Create PID file */
	if (!pidfn)
		pidfn = ident;
	pidfile(pidfn);

	/* Get servers from .conf file */
	num = conf_srv(srvtab, NELEMS(srvtab));
	if (num == -1) {
		syslog(LOG_CRIT, "No server{} directive in .conf file and no valid global settings ...");
		exit(1);
	}

	for (int i = 0; i < num; i++) {
		/* Create the server */
		server = srv_init(&srvtab[i]);

		/* Add to list of servers */
		if (server)
			LIST_INSERT(server, server_list);
	}

	/* Start socket watchers for all servers */
	LIST_FOREACH(server, server_list)
		srv_start(server);

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
		setlogin(user);
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

	/* Main loop. */
	tmr_prepare_timeval(&tv);
	while ((!terminate) || num_connects > 0) {
		int got = 0;

		/* Do we need to re-open the log file? */
		if (got_hup)
			got_hup = 0;

		/* Do the fd watch. */
		num_ready = fdwatch(tmr_mstimeout(&tv));
		if (num_ready < 0) {
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
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

		LIST_FOREACH(server, server_list) {
			if ((got = srv_connect(server, &tv)))
				break;
		}

		/* Go around the loop and do another fdwatch,
		** rather than dropping through and processing
		** existing connections.  New connections
		** always get priority.
		*/
		if (got)
			continue;

		/* Find the connections that need servicing. */
		while ((ct = (connecttab *)fdwatch_get_next_arg()) != (connecttab *)-1) {
			int fd_ok;

			if (!ct)
				continue;

			hc = ct->hc;

			/*
			 * During proxy backend states the backend fd (not the
			 * client fd) is registered in fdwatch.  Check the right
			 * one so we don't mistake a quiescent client fd for an
			 * error and tear down a live proxy connection.
			 */
			if (ct->conn_state == CNST_PROXY_CONNECTING ||
			    ct->conn_state == CNST_PROXY_SENDING    ||
			    ct->conn_state == CNST_PROXY_READING)
				fd_ok = fdwatch_check_fd(ct->proxy_fd);
			else
				fd_ok = fdwatch_check_fd(hc->conn_fd);

			if (!fd_ok) {
				/* Something went wrong. */
				hc->do_keep_alive = 0;
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

				case CNST_PROXY_CONNECTING:
					handle_proxy_connect(ct, &tv);
					break;

				case CNST_PROXY_SENDING:
					handle_proxy_send(ct, &tv);
					break;

				case CNST_PROXY_READING:
					handle_proxy_read(ct, &tv);
					break;

				case CNST_PROXY_SEND_RESP:
					handle_proxy_send_resp(ct, &tv);
					break;
				}
			}
		}
		tmr_run(&tv);

		if (got_usr1) {
			loglevel = loglevel + dbglevel;
			dbglevel = loglevel - dbglevel;
			loglevel = loglevel - dbglevel;
			setlogmask(LOG_UPTO(loglevel));
			got_usr1 = 0;
		}

		/* From handle_send()/writev; see handle_sigbus(). */
		if (got_bus) {
			syslog(LOG_WARNING, "SIGBUS received - stale NFS-handle?");
			got_bus = 0;
		}
	}

	/* The main loop terminated. */
	shut_down();
	syslog(LOG_NOTICE, "Exiting cleanly, all connections completed.");
	closelog();

	exit(0);
}
