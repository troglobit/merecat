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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>		/* readlink() */
#include <execinfo.h>		/* backtrace() */

static char *addr2line(char *addr)
{
	FILE *fp;
	char *tmp;
	char exec[256];
	static char buf[256];

	readlink("/proc/self/exe", exec, sizeof(exec));
	tmp = tmpnam(NULL);
	snprintf(buf, sizeof(buf), "addr2line -e %s %s > %s", exec, addr, tmp);
	system(buf);

	fp = fopen(tmp, "r");
	if (!fp) {
		buf[0] = 0;
		goto end;
	}
	fgets(buf, sizeof(buf), fp);
	fclose(fp);
end:
	remove(tmp);
	return buf;
}

/*
 * Build with: ./configure CFLAGS="-g -Og -rdynamic"
 */
void stack_trace(void)
{
	void *trace[16];
	char **messages = (char **)NULL;
	int i, trace_size = 0;

	trace_size = backtrace(trace, 16);
	messages = backtrace_symbols(trace, trace_size);

	syslog(LOG_DEBUG, ">>> STACK TRACE");
	for (i = 0; i < trace_size; i++) {
		char *line;

		line = strstr(messages[i], " [0x");
		if (line) {
			line += 2;
			line = addr2line(line);
		} else {
			line = "";
		}
		syslog(LOG_DEBUG, ">>> %s%s", messages[i], line);
	}

	free(messages);
}

