/* Start, stop, and act on a single HTTP server
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

#ifndef SRV_H_
#define SRV_H_

#define MAX_REDIRECTS 2
#define MAX_LOCATIONS 2

struct srv {
	char      *title;
	char      *host;	/* specific virtual-host, unused for now */
	uint16_t   port;	/* Server listening port */
	char      *path;	/* path within chroot/server dir, unused for now */

	int        ssl;		/* HTTPS or HTTP */
	char      *ssl_proto;
	char      *ciphers;
	char      *certfile;
	char      *keyfile;
	char      *dhfile;

	struct {
		char *pattern;	/* Pattern to match() against */

		int   code;	/* HTTP status code, default: 301 */
		char *location;	/* Location: to redirect to, supports format specifiers */
	} redirect[MAX_REDIRECTS];

	struct {
		char *pattern;	/* Pattern to match() against */

		char *path;	/* Path to use for matching requests */
	} location[MAX_LOCATIONS];
};

struct httpd *srv_init   (struct srv *srv);
void          srv_exit   (struct httpd *hs);

void          srv_start  (struct httpd *hs);
void          srv_stop   (struct httpd *hs);

int           srv_connect(struct httpd *hs, struct timeval *tv);

#endif /*  SRV_H_ */
