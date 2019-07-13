/* timers.h - header file for timers package
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

#ifndef _TIMERS_H_
#define _TIMERS_H_

#include <sys/time.h>
#include <time.h>

#ifndef INFTIM
#define INFTIM -1
#endif

/* arg_t is a random value that tags along with a timer.  The client
** can use it for whatever, and it gets passed to the callback when the
** timer triggers.
*/
typedef union {
	void *p;
	int   i;
	long  l;
} arg_t;

extern arg_t noarg;	/* for use when you don't care */

struct timer {
	struct timer  *prev;
	struct timer  *next;

	int            hash;
	struct timeval time;
	long           msecs;
	int            periodic;

	void         (*cb)(arg_t, struct timeval *);
	arg_t          arg;
};

/* Initialize the timer package. */
extern void tmr_init(void);

/* Set up a timer, either periodic or one-shot. Returns NULL on errors. */
extern struct timer *tmr_create(struct timeval *now, void (*cb)(arg_t, struct timeval *),
				arg_t arg, long msecs, int periodic);

/* Returns a timeout indicating how long until the next timer triggers.  You
** can just put the call to this routine right in your select().  Returns
** (struct timeval*) 0 if no timers are pending.
*/
extern struct timeval *tmr_timeout(struct timeval *now);

/* Returns a timeout in milliseconds indicating how long until the next timer
** triggers.  You can just put the call to this routine right in your poll().
** Returns INFTIM (-1) if no timers are pending.
*/
extern long tmr_mstimeout(struct timeval *now);

/* Run the list of timers. Your main program needs to call this every so often,
** or as indicated by tmr_timeout().
*/
extern void tmr_run(struct timeval *now);

/* Reset the clock on a timer, to current time plus the original timeout. */
extern void tmr_reset(struct timeval *now, struct timer *timer);

/* Deschedule a timer.  Note that non-periodic timers are automatically
** descheduled when they run, so you don't have to call this on them.
*/
extern void tmr_cancel(struct timer *timer);

/* Clean up the timers package, freeing any unused storage. */
extern void tmr_cleanup(void);

/* Cancel all timers and free storage, usually in preparation for exitting. */
extern void tmr_destroy(void);

/* Generate debugging statistics syslog message. */
extern void tmr_logstats(long secs);

/* Fill timeval structure for further usage by the package. */
extern void tmr_prepare_timeval(struct timeval *tv);

#endif /* _TIMERS_H_ */
