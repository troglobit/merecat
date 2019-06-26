/* libConfuse based merecat.conf parser
**
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

#ifndef MERECAT_CONF_H_
#define MERECAT_CONF_H_

#include <config.h>
#include <stdint.h>
#include <stdbool.h>
#include "srv.h"

/* Command line argument always wins */
struct conf {
	struct conf *prev, *next;

	char     *hostname;
	char     *user;		/* DEFAULT_USER or command line */
	uint16_t  port;		/* ... or command line */

	bool      vhost;
	bool      check_referer;
	bool      dotfiles;
	bool      global_pwd;   /* ... or command line */

	bool      chroot;	/* ... or command line */
	char     *dir;		/* SERVER_DIR_DEFUALT: /var/www or command line */
	char     *data_dir;

	char     *cgi_pattern;	/* CGI_PATTERN or command line */
	int       cgi_limit;	/* CGI_LIMIT */
	char     *url_pattern;
	char     *local_pattern;
	char     *useragent_deny;

	char     *charset;	/* DEFAULT_CHARSET */
	int       max_age;	/* DEFAULT_MAX_AGE */
	int       z_level;      /* DEFAULT_COMPRESSION: For content-encoding: gzip */

	bool      ssl;
	char     *certfile;
	char     *keyfile;
	char     *dhfile;
};

#ifdef HAVE_LIBCONFUSE
int     conf_init(char *file);
void    conf_exit(void);

int     conf_srv(struct srv *arr, size_t len);
#else
#define conf_init(foo)
#define conf_exit()

#define conf_srv(arr, len) {			\
		arr[0].port = port;		\
		arr[0].ssl  = do_ssl;		\
		arr[0].host = hostname;		\
		arr[0].path = data_dir;		\
		1;				\
	}
#endif

#endif /* MERECAT_CONF_H_ */
