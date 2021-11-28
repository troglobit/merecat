/* Utility functions for file descriptor access
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

#include <errno.h>
#include <unistd.h>

/* Read the requested buffer completely, accounting for interruptions. */
ssize_t file_read(int fd, void *buf, size_t len)
{
	ssize_t sz, retry = 3;

	sz = 0;
	while ((size_t)sz < len) {
		ssize_t r;

		r = read(fd, (char *)buf + sz, len - sz);
		if (r < 0) {
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
				if (retry-- > 0) {
					sleep(1);
					continue;
				}
			}

			return r;
		}

		if (r == 0)
			break;

		sz += r;
	}

	return sz;
}

/* Write the requested buffer completely, accounting for interruptions. */
ssize_t file_write(int fd, void *buf, size_t len)
{
	ssize_t sz, retry = 3;

	sz = 0;
	while ((size_t)sz < len) {
		ssize_t r;

		r = write(fd, (char *)buf + sz, len - sz);
		if (r < 0) {
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
				if (retry-- > 0) {
					sleep(1);
					continue;
				}
				continue;
			}

			return r;
		}

		if (r == 0)
			break;

		sz += r;
	}

	return sz;
}

