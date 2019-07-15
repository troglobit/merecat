/* ssl.c - HTTPS support functions
**
** Copyright (C) 2017-2018  Joachim Nilsson <troglobit@gmail.com>
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

#ifndef MERECAT_SSL_H_
#define MERECAT_SSL_H_

#include <config.h>
#include <sys/uio.h>
#include "libhttpd.h"

#ifdef ENABLE_SSL

/* Initialize SSL and load certificate and key file */
void *httpd_ssl_init(char *cert, char *key, char *dhparm, char *proto, char *ciphers);

/* Unload SSL, called automatically at httpd_exit() */
void httpd_ssl_exit(struct httpd *hs);

/* Open a new HTTPS connection */
int httpd_ssl_open(struct http_conn *hc);

/* Close a HTTP/HTTPS connection */
void httpd_ssl_close(struct http_conn *hc);

/* Called before httpd_ssl_close() to signal connection shut down */
void httpd_ssl_shutdown(struct http_conn *hc);

/* Reads SSL error log and sends to syslog */
void httpd_ssl_log_errors(void);

/* Wrappers for read()/write() and writev() */
ssize_t httpd_ssl_read   (struct http_conn *hc, void *buf, size_t len);
ssize_t httpd_ssl_write  (struct http_conn *hc, void *buf, size_t len);
ssize_t httpd_ssl_writev (struct http_conn *hc, struct iovec *iov, size_t num);

#else
#define httpd_ssl_init(cert, key, dhparm) NULL
#define httpd_ssl_exit(hs)

#define httpd_ssl_open(hc)             (hc->ssl = NULL)
#define httpd_ssl_close(hc)            close(hc->conn_fd)
#define httpd_ssl_shutdown(hc)

#define httpd_ssl_log_errors()

#define httpd_ssl_read(hc, buf, len)   read       (hc->conn_fd, buf, len)
#define httpd_ssl_write(hc, buf, len)  file_write (hc->conn_fd, buf, len)
#define httpd_ssl_writev(hc, iov, num) writev     (hc->conn_fd, iov, num)
#endif

#endif /* MERECAT_SSL_H_ */
