/* libhttpd.h - defines for libhttpd
**
** Copyright (C) 1995-2015  Jef Poskanzer <jef@mail.acme.com>
** Copyright (C) 2016-2018  Joachim Nilsson <troglobit@gmail.com>
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

#ifndef LIBHTTPD_H_
#define LIBHTTPD_H_

#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#if defined(AF_INET6) && defined(IN6_IS_ADDR_V4MAPPED)
#define USE_IPV6
#endif


/* A few convenient defines. */

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif
#define NEW(t,n)     calloc(1, sizeof(t) * (n))
#define RENEW(o,t,n) realloc((void*) o, sizeof(t) * (n))

/* From The Practice of Programming, by Kernighan and Pike */
#ifndef NELEMS
#define NELEMS(array) (sizeof(array) / sizeof(array[0]))
#endif

/* Doubly linked list macros */
#define LIST_FOREACH(node, list)		\
	for (typeof (node) next, node = list;	\
	     node && (next = node->next, 1);	\
	     node = next)

#define LIST_INSERT(node, list) do {		\
	typeof (node) next;			\
	next       = list;			\
	list       = node;			\
	if (next)				\
		next->prev = node;		\
	node->next = next;			\
	node->prev = NULL;			\
} while (0)

#define LIST_REMOVE(node, list) do {		\
	typeof (node) prev, next;		\
	prev = node->prev;			\
	next = node->next;			\
	if (prev)				\
		prev->next = next;		\
	if (next)				\
		next->prev = prev;		\
	node->prev = NULL;			\
	node->next = NULL;			\
	if (list == node)			\
		list = next;			\
} while (0)


/* The httpd structs. */

/* A multi-family sockaddr. */
typedef union {
	struct sockaddr         sa;
	struct sockaddr_in      sa_in;
#ifdef USE_IPV6
	struct sockaddr_in6     sa_in6;
	struct sockaddr_storage sa_stor;
#endif
	char                    sa_addr[200]; /* Real IP address */
} sockaddr_t;

/* A redirect. */
struct http_redir {
	struct http_redir *prev, *next;

	int    code;
	char  *pattern;
	char  *location;
};

/* A server. */
struct httpd {
	struct httpd *prev, *next;

	char *binding_hostname;
	char *server_hostname;
	unsigned short port;

	pid_t *cgi_tracker;
	char  *cgi_pattern;
	int    cgi_limit;
	int    cgi_count;

	char *php_cgi;
	char *php_pattern;

	char *ssi_cgi;
	char *ssi_pattern;

	char *charset;
	int   max_age;
	char *cwd;

	int listen4_fd;
	int listen6_fd;

	int no_log;
	int no_symlink_check;
	int no_empty_referers;
	int list_dotfiles;
	int vhost;
	int global_passwd;

	char *url_pattern;
	char *local_pattern;

	struct http_redir *redirect;

	void *ctx;		/* Opaque SSL_CTX* */
};

/* A connection. */
struct http_conn {
	int initialized;
	struct httpd *hs;
	sockaddr_t client_addr;
	char *read_buf;
	size_t read_size, read_idx, checked_idx;
	int checked_state;
	int method;
	int status;
	off_t bytes_to_send;
	off_t bytes_sent;
	char *encodedurl;
	char *decodedurl;
	char *protocol;
	char *origfilename;
	char *indexname;
	char *expnfilename;
	char *encodings;
	char *pathinfo;
	char *query;
	char *referer;
	char *useragent;
	char *accept;
	char *accepte;
	char *acceptl;
	char *cookie;
	char *contenttype;
	char *reqhost;
	char *hdrhost;
	char *hostdir;
	char *authorization;
	char *remoteuser;
	char *response;
	size_t maxdecodedurl, maxindexname, maxorigfilename, maxexpnfilename, maxencodings,
	    maxpathinfo, maxquery, maxaccept, maxaccepte, maxreqhost, maxhostdir, maxremoteuser, maxresponse;
#ifdef TILDE_MAP_2
	char *altdir;
	size_t maxaltdir;
#endif
#ifdef ACCESS_FILE
	size_t maxaccesspath;
	char *accesspath;
#endif
#ifdef AUTH_FILE
	size_t maxauthpath, maxprevauthpath, maxprevuser, maxprevcryp;
	char *authpath;
	char *prevauthpath;
	char *prevuser;
	char *prevcryp;
#endif
	size_t responselen;
	time_t if_modified_since, range_if;
	size_t contentlength;
	const char *type;	/* not malloc()ed */
	char *hostname;		/* not malloc()ed */
	int mime_flag;
	int one_one;		/* HTTP/1.1 or better */
	int got_range;
	int tildemapped;	/* this connection got tilde-mapped */
	off_t first_byte_index, last_byte_index;
	int keep_alive;		/* Client signaled */
	int do_keep_alive;	/* Our intention, which may change */
	int should_linger;
	struct stat sb;
	int conn_fd;
	int has_deflate;	/* Built with zlib:deflate() and enabled */
	int compression_type;
	char *file_address;

	void *ssl;		/* Opaque SSL* */
};

/* Methods. */
#define METHOD_UNKNOWN 0
#define METHOD_GET     1
#define METHOD_HEAD    2
#define METHOD_POST    3
#define METHOD_PUT     4
#define METHOD_DELETE  5
#define METHOD_CONNECT 6
#define METHOD_OPTIONS 7
#define METHOD_TRACE   8

/* States for checked_state. */
#define CHST_FIRSTWORD 0
#define CHST_FIRSTWS 1
#define CHST_SECONDWORD 2
#define CHST_SECONDWS 3
#define CHST_THIRDWORD 4
#define CHST_THIRDWS 5
#define CHST_LINE 6
#define CHST_LF 7
#define CHST_CR 8
#define CHST_CRLF 9
#define CHST_CRLFCR 10
#define CHST_BOGUS 11

/* For content-encoding: gzip */
#define COMPRESSION_NONE 0
#define COMPRESSION_GZIP 1

/* Initializes main HTTPD server. Returns NULL on error. */
extern struct httpd *httpd_init(char *hostname, unsigned short port, void *ssl_ctx,
				char *charset, int max_age, char *cwd, int no_log,
				int no_symlink_check, int vhost, int global_passwd,
				char *url_pattern, char *local_pattern,
				int no_empty_referers, int list_dotfiles);

/* Enable CGI/1.1 support */
extern int httpd_cgi_init(struct httpd *hs, char *cgi_pattern, int cgi_limit);

/* Enable HTTP redirect -- Note: O(n) lookup per HTTP request */
extern int httpd_redirect_add(struct httpd *hs, int code, char *pattern, char *location);

/* Start httpd */
extern int httpd_listen(struct httpd *hs, sockaddr_t *sav4, sockaddr_t *sav6);

/* Call to shut down. */
extern void httpd_exit(struct httpd *hs);

/* Call to unlisten/close socket(s) listening for new connections. */
extern void httpd_unlisten(struct httpd *hs);

/* Used to reinitialize the connection for pipelined keep-alive requets */
extern void httpd_init_conn_mem(struct http_conn *hc);
extern void httpd_init_conn_content(struct http_conn *hc);

/* When a listen fd is ready to be read, call this.  It does the accept() and
** returns a struct http_conn* which includes the fd to read the request from
** and write the response to.  Returns an indication of whether the accept()
** failed, succeeded, or if there were no more connections to accept.
**
** In order to minimize malloc()s, the caller passes in the struct http_conn.
** The caller is also responsible for setting initialized to zero before the
** first call using each different struct http_conn.
*/
extern int httpd_get_conn(struct httpd *hs, int listen_fd, struct http_conn *hc);

#define GC_FAIL 0
#define GC_OK 1
#define GC_NO_MORE 2

/* Checks whether the data in hc->read_buf constitutes a complete request
** yet.  The caller reads data into hc->read_buf[hc->read_idx] and advances
** hc->read_idx.  This routine checks what has been read so far, using
** hc->checked_idx and hc->checked_state to keep track, and returns an
** indication of whether there is no complete request yet, there is a
** complete request, or there won't be a valid request due to a syntax error.
*/
extern int httpd_got_request(struct http_conn *hc);

#define GR_NO_REQUEST 0
#define GR_GOT_REQUEST 1
#define GR_BAD_REQUEST 2

/* Parses the request in hc->read_buf.  Fills in lots of fields in hc,
** like the URL and the various headers.
**
** Returns -1 on error.
*/
extern int httpd_parse_request(struct http_conn *hc);

/* Starts sending data back to the client.  In some cases (directories,
** CGI programs), finishes sending by itself - in those cases, hc->file_fd
** is <0.  If there is more data to be sent, then hc->file_fd is a file
** descriptor for the file to send.  If you don't have a current timeval
** handy just pass in 0.
**
** Returns -1 on error.
*/
extern int httpd_start_request(struct http_conn *hc, struct timeval *now);

/* Actually sends any buffered response text. */
extern void httpd_send_response(struct http_conn *hc);

/* Call this to close down a connection and free the data.  A fine point,
** if you fork() with a connection open you should still call this in the
** parent process - the connection will stay open in the child.
** If you don't have a current timeval handy just pass in 0.
*/
extern void httpd_close_conn(struct http_conn *hc, struct timeval *now);

/* Call this to de-initialize a connection struct and *really* free the
** mallocced strings.
*/
extern void httpd_destroy_conn(struct http_conn *hc);

/* Client IP addresses can be overridden by a proxy using X-Forwarded-For */
extern char *httpd_client(struct http_conn *hc);

/* Send an error message back to the client. */
extern void httpd_send_err(struct http_conn *hc, int status, char *title,
			   const char *extraheads, char *form, char *arg);

/* Some error messages. */
extern char *httpd_err400title;
extern char *httpd_err400form;
extern char *httpd_err408title;
extern char *httpd_err408form;
extern char *httpd_err503title;
extern char *httpd_err503form;

/* Generate a string representation of a method number. */
extern char *httpd_method_str(int method);

/* Reallocate a string. */
extern void httpd_realloc_str(char **str, size_t *curr_len, size_t new_len);

/* Format a network socket to a string representation. */
extern char *httpd_ntoa(sockaddr_t *sa);

/* Return port from sockaddr */
extern short httpd_port(sockaddr_t *sa);

/* Set NDELAY mode on a socket. */
extern void httpd_set_ndelay(int fd);

/* Clear NDELAY mode on a socket. */
extern void httpd_clear_ndelay(int fd);

/* Read the requested buffer completely, accounting for interruptions. */
extern ssize_t httpd_read(struct http_conn *hc, void *buf, size_t len);

/* Write the requested buffer completely, accounting for interruptions. */
extern ssize_t httpd_write(struct http_conn *hc, void *buf, size_t len);
extern ssize_t httpd_writev(struct http_conn *hc, struct iovec *iov, size_t num);

/* Generate debugging statistics syslog message. */
extern void httpd_logstats(long secs);

/* Track PID of CGI scripts, server calls untrack for each collected PID */
extern int httpd_cgi_track(struct httpd *hs, pid_t pid);
extern int httpd_cgi_untrack(struct httpd *hs, pid_t pid);

/*
** Default CSS used in error pages
*/
static inline const char *httpd_css_default(void)
{
	const char *style = "  <style type=\"text/css\">\n"
		"    body { background-color:#f2f1f0; font-family: sans-serif;}\n"
		"    h2 { border-bottom: 1px solid #f2f1f0; font-weight: normal;}"
		"    address { border-top: 1px solid #f2f1f0; margin-top: 1em; padding-top: 5px; color:#c8c5c2; }"
		"    table { table-layout: fixed; border-collapse: collapse;}\n"
		"    table tr:hover { background-color:#f2f1f0;}\n"
		"    table tr td { text-align: left; padding: 0 5px 0 0px; }\n"
		"    table tr th { text-align: left; padding: 0 5px 0 0px; }\n"
		"    table tr td.icon  { text-align: center; }\n"
		"    table tr th.icon  { text-align: center; }\n"
		"    table tr td.right { text-align: right; }\n"
		"    table tr th.right { text-align: right; }\n"
		"    .right { padding-right: 20px; }\n"
		"    #wrapper {\n"
		"     background-color:white; width:1024px;\n"
		"     padding:1.5em; margin:4em auto; position:absolute;\n"
		"     top:0; left:0; right:0;\n"
		"     border-radius: 10px; border: 1px solid #c8c5c2;\n"
		"    }\n"
		"    #table {\n"
		"     padding: 0em; margin: 0em auto; overflow: auto;\n"
		"    }\n"
		"  </style>\n";

	return style;
}

#endif /* LIBHTTPD_H_ */
