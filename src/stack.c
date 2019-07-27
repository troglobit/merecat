/* Simple, stupid and silly stack probe :P
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
#include <config.h>
#ifdef HAVE_BACKTRACE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>		/* readlink() */
#include <execinfo.h>		/* backtrace() */

/* From The Practice of Programming, by Kernighan and Pike */
#ifndef NELEMS
#define NELEMS(array) (sizeof(array) / sizeof(array[0]))
#endif

static char *addr2line(char *exec, char *addr)
{
	static char buf[512];
	FILE *fp;

	snprintf(buf, sizeof(buf), "addr2line -e %s %s", exec, addr);
	fp = popen(buf, "r");
	if (!fp)
		return NULL;

	fgets(buf, sizeof(buf), fp);
	pclose(fp);

	return buf;
}

/*
 * Build with: ./configure CFLAGS="-g -Og -rdynamic"
 */
void stack_trace(void)
{
	char **messages;
	void *trace[16];
	char exec[256] = { 0 };
	int i, rc, len;

	rc = readlink("/proc/self/exe", exec, sizeof(exec));
	if (-1 == rc)
		return;

	len = backtrace(trace, NELEMS(trace));
	messages = backtrace_symbols(trace, len);
	if (!messages)
		return;

	syslog(LOG_NOTICE, ">>> STACK TRACE");
	for (i = 0; i < len; i++) {
		char *line;

		line = strstr(messages[i], " [0x");
		if (line)
			line = addr2line(exec, line + 2);
		if (!line)
			line = "";

		syslog(LOG_NOTICE, ">>> %s%s", messages[i], line);
	}

	free(messages);
}

#endif /* HAVE_BACKTRACE */
