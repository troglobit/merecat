/* match.c - simple shell-style filename matcher
**
** Only does ? * and **, and multiple patterns separated by |.  Returns 1 or 0.
**
** Copyright (C) 1995-2015  Jef Poskanzer <jef@mail.acme.com>
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
#include <string.h>
#include "match.h"

static int match_one(const char *pattern, int patternlen, const char *string);

int match(const char *pattern, const char *string)
{
	if (!pattern)
		return 0;

	for (;;) {
		const char *or;
		int rc;

		or = strchr(pattern, '|');
		if (!or)
			return match_one(pattern, strlen(pattern), string);

		rc = match_one(pattern, or - pattern, string);
		if (rc)
			return rc;

		pattern = or + 1;
	}
}


static int match_one(const char *pattern, int patternlen, const char *string)
{
	const char *p, *s;

	for (p = pattern, s = string; p - pattern < patternlen; ++p, ++s) {
		if (*p == '?' && *s != '\0')
			continue;

		if (*p == '*') {
			int i, pl;

			++p;
			if (*p == '*') {
				/* Double-wildcard matches anything. */
				++p;
				i = strlen(s);
			} else {
				/* Single-wildcard matches anything but slash. */
				i = strcspn(s, "/");
			}

			pl = patternlen - (p - pattern);
			for (; i >= 0; --i) {
				if (match_one(p, pl, &(s[i])))
					return s - string;
			}

			return 0;
		}

		if (*p != *s)
			return 0;
	}

	if (*s == '\0')
		return 1;

	return 0;
}
