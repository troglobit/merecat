/* mmc.c - mmap cache
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
** THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
** ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
** IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
** ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
** FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
** DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
** OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
** HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
** LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
** OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
** SUCH DAMAGE.
*/

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
 
#ifdef HAVE_MMAP
#include <sys/mman.h>
#endif				/* HAVE_MMAP */

#include "file.h"
#include "libhttpd.h"
#include "mmc.h"


/* Defines. */
#ifndef DEFAULT_EXPIRE_AGE
#define DEFAULT_EXPIRE_AGE 600
#endif
#ifndef DESIRED_FREE_COUNT
#define DESIRED_FREE_COUNT 100
#endif
#ifndef DESIRED_MAX_MAPPED_FILES
#define DESIRED_MAX_MAPPED_FILES 2000
#endif
#ifndef DESIRED_MAX_MAPPED_BYTES
#define DESIRED_MAX_MAPPED_BYTES 1000000000
#endif
#ifndef INITIAL_HASH_SIZE
#define INITIAL_HASH_SIZE (1 << 10)
#endif

#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif
#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

/* The Map struct. */
typedef struct MapStruct {
	ino_t ino;
	dev_t dev;
	off_t size;
	time_t ctime;
	int refcount;
	time_t reftime;
	void *addr;
	unsigned int hash;
	int hash_idx;
	struct MapStruct *next;
} Map;

/* Globals. */
static Map *maps = NULL;
static Map *free_maps = NULL;
static int alloc_count = 0, map_count = 0, free_count = 0;
static Map **hash_table = NULL;
static int hash_size;
static unsigned int hash_mask;
static time_t expire_age = DEFAULT_EXPIRE_AGE;
static off_t mapped_bytes = 0;

/* Forwards. */
static void panic(void);
static void really_unmap(Map **mm);
static int check_hash_size(void);
static int add_hash(Map *m);
static Map *find_hash(ino_t ino, dev_t dev, off_t size, time_t ctime);
static unsigned int hash(ino_t ino, dev_t dev, off_t size, time_t ctime);

#ifdef BUILTIN_ICONS
#include "base64.h"

struct {
	char *name;
	char *buf;
} icons[] = {
	{
		"icons/back.gif",
		"R0lGODlhFAAWAMIAAP///8z//5mZmWZmZjMzMwAAAAAAAAAAACH+TlRoaXMgYXJ0IGlzIGluIHRo"
		"ZSBwdWJsaWMgZG9tYWluLiBLZXZpbiBIdWdoZXMsIGtldmluaEBlaXQuY29tLCBTZXB0ZW1iZXIg"
		"MTk5NQAh+QQBAAABACwAAAAAFAAWAAADSxi63P4jEPJqEDNTu6LO3PVpnDdOFnaCkHQGBTcqRRxu"
		"WG0v+5LrNUZQ8QPqeMakkaZsFihOpyDajMCoOoJAGNVWkt7QVfzokc+LBAA7"
	},
	{
		"icons/blank.gif",
		"R0lGODlhFAAWAKEAAP///8z//wAAAAAAACH+TlRoaXMgYXJ0IGlzIGluIHRoZSBwdWJsaWMgZG9t"
		"YWluLiBLZXZpbiBIdWdoZXMsIGtldmluaEBlaXQuY29tLCBTZXB0ZW1iZXIgMTk5NQAh+QQBAAAB"
		"ACwAAAAAFAAWAAACE4yPqcvtD6OctNqLs968+w+GSQEAOw=="
	},
	{
		"icons/folder.gif",
		"R0lGODlhFAAWAMIAAP/////Mmcz//5lmMzMzMwAAAAAAAAAAACH+TlRoaXMgYXJ0IGlzIGluIHRo"
		"ZSBwdWJsaWMgZG9tYWluLiBLZXZpbiBIdWdoZXMsIGtldmluaEBlaXQuY29tLCBTZXB0ZW1iZXIg"
		"MTk5NQAh+QQBAAACACwAAAAAFAAWAAADVCi63P4wyklZufjOErrvRcR9ZKYpxUB6aokGQyzHKxyO"
		"9RoTV54PPJyPBewNSUXhcWc8soJOIjTaSVJhVphWxd3CeILUbDwmgMPmtHrNIyxM8Iw7AQA7"
	},
	{
		"icons/generic.gif",
		"R0lGODlhFAAWAMIAAP///8z//5mZmTMzMwAAAAAAAAAAAAAAACH+TlRoaXMgYXJ0IGlzIGluIHRo"
		"ZSBwdWJsaWMgZG9tYWluLiBLZXZpbiBIdWdoZXMsIGtldmluaEBlaXQuY29tLCBTZXB0ZW1iZXIg"
		"MTk5NQAh+QQBAAABACwAAAAAFAAWAAADUDi6vPEwDECrnSO+aTvPEddVIriN1wWJKDG48IlSRG0T"
		"8kwJvIBLOkvvxwoCfDnjkaisIIHNZdL4LAarUSm0iY12uUwvcdArm3mvyG3N/iUAADs="
	}
};

static struct stat icost;
static int  cico = -1;
static unsigned char icon[512];	/* Only small icons allowed atm */

int mmc_icon_check(char *filename, struct stat *st)
{
	char *ptr;
	size_t i;

	cico = -1;
	ptr = strstr(filename, "icons/");
	if (!ptr)
		return 0;

	for (i = 0; i < NELEMS(icons); i++) {
		off_t len;

		if (strcmp(ptr, icons[i].name))
			continue;

		len = b64_decode(icons[i].buf, icon, sizeof(icon));
		if (len <= 0)
			break;

		memset(&icost, 0, sizeof(icost));
		icost.st_size = len;
		icost.st_ctim.tv_sec = 18446744073359756536UL;
		if (st)
			memcpy(st, &icost, sizeof(icost));

		cico = i;
		return 1;
	}

	return 0;
}

/* Check if this is a small icon we have built-in */
static off_t mmc_icon_open(char *filename, char **buf, struct stat *st)
{
	int found = 1;

	if (cico < 0 || cico > (int)NELEMS(icons) || strcmp(icons[cico].name, filename))
		found = mmc_icon_check(filename, st);

	if (!found)
		return -1;

	*buf = (char *)icon;
	*st = icost;

	return 0;
}
#else /* BUILTIN_ICONS */
int mmc_icon_check(char *filename, struct stat *st)
{
	return 0;
}
static off_t mmc_icon_open(char *filename, char **buf, struct stat *st)
{
	return -1;
}
#endif /* BUILTIN_ICONS */

void *mmc_map(char *filename, struct stat *sbP, struct timeval *nowP)
{
	time_t now;
	char *buf = NULL;
	struct stat sb;
	Map *m;
	int fd;

	/* Stat the file, if necessary. */
	if (sbP) {
		sb = *sbP;
	} else {
		if (stat(filename, &sb) != 0) {
			syslog(LOG_ERR, "stat: %s", strerror(errno));
			return NULL;
		}
	}

	/* Get the current time, if necessary. */
	if (nowP)
		now = nowP->tv_sec;
	else
		now = time(NULL);

	/* See if we have it mapped already, via the hash table. */
	if (check_hash_size() < 0) {
		syslog(LOG_ERR, "check_hash_size() failure");
		return NULL;
	}

	m = find_hash(sb.st_ino, sb.st_dev, sb.st_size, sb.st_ctime);
	if (m) {
		/* Yep.  Just return the existing map */
		++m->refcount;
		m->reftime = now;

		return m->addr;
	}

	/* Open the file. */
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		if (mmc_icon_open(filename, &buf, &sb)) {
			syslog(LOG_ERR, "open: %s", strerror(errno));
			return NULL;
		}
	}

	/* Find a free Map entry or make a new one. */
	if (free_maps) {
		m = free_maps;
		free_maps = m->next;
		--free_count;
	} else {
		m = (Map *)malloc(sizeof(Map));
		if (!m) {
			if (!buf)
				close(fd);
			syslog(LOG_ERR, "out of memory allocating a Map");

			return NULL;
		}
		++alloc_count;
	}

	/* Fill in the Map entry. */
	m->ino = sb.st_ino;
	m->dev = sb.st_dev;
	m->size = sb.st_size;
	m->ctime = sb.st_ctime;
	m->refcount = 1;
	m->reftime = now;

	/* Avoid doing anything for zero-length files; some systems don't like
	 ** to mmap them, other systems dislike mallocing zero bytes.
	 */
	if (m->size == 0) {
		/* arbitrary non-NULL address */
		m->addr = (void *)1;
	} else {
		size_t size_size = (size_t)m->size;	/* loses on files >2GB */

		if (buf) {
			m->addr = malloc(size_size);
			if (!m->addr) {
				syslog(LOG_ERR, "%s: %s", __func__, strerror(errno));
				free(m);
				--alloc_count;
				return NULL;
			}
			memcpy(m->addr, buf, size_size);
			goto cont;
		}
#ifdef HAVE_MMAP
		/* Map the file into memory. */
		m->addr = mmap(0, size_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (m->addr == (void *)-1 && errno == ENOMEM) {
			/* Ooo, out of address space.  Free all unreferenced maps
			 ** and try again.
			 */
			panic();
			m->addr = mmap(0, size_size, PROT_READ, MAP_PRIVATE, fd, 0);
		}

		if (m->addr == (void *)-1) {
			syslog(LOG_ERR, "mmap: %s", strerror(errno));
			close(fd);
			free(m);
			--alloc_count;

			return NULL;
		}
#else /* HAVE_MMAP */
		/* Read the file into memory. */
		m->addr = (void *)malloc(size_size);
		if (!m->addr) {
			/* Ooo, out of memory.  Free all unreferenced maps
			 ** and try again.
			 */
			panic();
			m->addr = (void *)malloc(size_size);
		}

		if (!m->addr) {
			syslog(LOG_ERR, "out of memory storing a file");
			close(fd);
			free(m);
			--alloc_count;

			return NULL;
		}

		if (file_read(fd, m->addr, size_size) != m->size) {
			syslog(LOG_ERR, "read: %s", strerror(errno));
			close(fd);
			free(m->addr);
			free(m);
			--alloc_count;

			return NULL;
		}
#endif /* HAVE_MMAP */
	}
	close(fd);
cont:
	/* Put the Map into the hash table. */
	if (add_hash(m) < 0) {
		syslog(LOG_ERR, "add_hash() failure");
#ifndef HAVE_MMAP
		free(m->addr);
#endif
		free(m);
		--alloc_count;

		return NULL;
	}

	/* Put the Map on the active list. */
	m->next = maps;
	maps = m;
	++map_count;

	/* Update the total byte count. */
	mapped_bytes += m->size;

	/* And return the address. */
	return m->addr;
}


void mmc_unmap(void *addr, struct stat *sbP, struct timeval *nowP)
{
	Map *m = NULL;

	/* Find the Map entry for this address.  First try a hash. */
	if (sbP) {
		m = find_hash(sbP->st_ino, sbP->st_dev, sbP->st_size, sbP->st_ctime);
		if (m && m->addr != addr)
			m = NULL;
	}

	/* If that didn't work, try a full search. */
	if (!m) {
		for (m = maps; m; m = m->next) {
			if (m->addr == addr)
				break;
		}
	}

	if (!m) {
		syslog(LOG_ERR, "mmc_unmap failed to find entry!");
		return;
	}
        if (m->refcount <= 0) {
		syslog(LOG_ERR, "mmc_unmap found zero or negative refcount!");
		return;
	}

	--m->refcount;
	if (nowP)
		m->reftime = nowP->tv_sec;
	else
		m->reftime = time(NULL);
}


void mmc_cleanup(struct timeval *nowP)
{
	time_t now;
	Map **mm;
	Map *m;

	/* Get the current time, if necessary. */
	if (nowP)
		now = nowP->tv_sec;
	else
		now = time(NULL);

	/* Really unmap any unreferenced entries older than the age limit. */
	for (mm = &maps; *mm;) {
		m = *mm;
		if (m->refcount == 0 && now - m->reftime >= expire_age)
			really_unmap(mm);
		else
			mm = &(*mm)->next;
	}

	/* Adjust the age limit if there are too many bytes mapped, or
	 ** too many or too few files mapped.
	 */
	if (mapped_bytes > DESIRED_MAX_MAPPED_BYTES)
		expire_age = MAX((expire_age * 2) / 3, DEFAULT_EXPIRE_AGE / 10);
	else if (map_count > DESIRED_MAX_MAPPED_FILES)
		expire_age = MAX((expire_age * 2) / 3, DEFAULT_EXPIRE_AGE / 10);
	else if (map_count < DESIRED_MAX_MAPPED_FILES / 2)
		expire_age = MIN((expire_age * 5) / 4, DEFAULT_EXPIRE_AGE * 3);

	/* Really free excess blocks on the free list. */
	while (free_count > DESIRED_FREE_COUNT) {
		m = free_maps;
		free_maps = m->next;
		free(m);
		--free_count;
		--alloc_count;
	}
}


static void panic(void)
{
	Map **mm;
	Map *m;

	syslog(LOG_ERR, "mmc panic - freeing all unreferenced maps");

	/* Really unmap all unreferenced entries. */
	for (mm = &maps; *mm;) {
		m = *mm;
		if (m->refcount == 0)
			really_unmap(mm);
		else
			mm = &(*mm)->next;
	}
}


static void really_unmap(Map **mm)
{
	Map *m;

	m = *mm;
	if (m->size) {
#ifdef HAVE_MMAP
		if (munmap(m->addr, m->size) < 0)
			syslog(LOG_ERR, "munmap: %s", strerror(errno));
#else
		free(m->addr);
#endif
	}

	/* Update the total byte count. */
	mapped_bytes -= m->size;

	/* And move the Map to the free list. */
	*mm = m->next;
	--map_count;
	m->next = free_maps;
	free_maps = m;
	++free_count;

	/* This will sometimes break hash chains, but that's harmless; the
	 ** unmapping code that searches the hash table knows to keep searching.
	 */
	hash_table[m->hash_idx] = NULL;
}


void mmc_destroy(void)
{
	Map *m;

	while (maps)
		really_unmap(&maps);

	while (free_maps) {
		m         = free_maps;
		free_maps = m->next;

		--free_count;
		--alloc_count;

		free(m);
	}

	if (hash_table)
		free(hash_table);
}


/* Make sure the hash table is big enough. */
static int check_hash_size(void)
{
	int i;
	Map *m;

	/* At least three times bigger than the number of entries? */
	if (hash_table && hash_size >= map_count * 3)
		return 0;

	/* Are we just starting out? */
	if (!hash_table) {
		hash_size = INITIAL_HASH_SIZE;
		hash_mask = hash_size - 1;
	} else {
		/* No, got to expand. */
		free(hash_table);

		/* Double the hash size until it's big enough. */
		while (hash_size < map_count * 6)
			hash_size = hash_size << 1;

		hash_mask = hash_size - 1;
	}

	/* Make the new table. */
	hash_table = (Map **)malloc(hash_size * sizeof(Map *));
	if (!hash_table)
		return -1;

	/* Clear it. */
	for (i = 0; i < hash_size; ++i)
		hash_table[i] = NULL;

	/* And rehash all entries. */
	for (m = maps; m; m = m->next) {
		if (add_hash(m) < 0)
			return -1;
	}

	return 0;
}


static int add_hash(Map *m)
{
	unsigned int h, he, i;

	h = hash(m->ino, m->dev, m->size, m->ctime);
	he = (h + hash_size - 1) & hash_mask;
	for (i = h;; i = (i + 1) & hash_mask) {
		if (!hash_table[i]) {
			hash_table[i] = m;
			m->hash = h;
			m->hash_idx = i;
			return 0;
		}

		if (i == he)
			break;
	}

	return -1;
}


static Map *find_hash(ino_t ino, dev_t dev, off_t size, time_t ctime)
{
	unsigned int h, he, i;
	Map *m;

	h = hash(ino, dev, size, ctime);
	he = (h + hash_size - 1) & hash_mask;
	for (i = h;; i = (i + 1) & hash_mask) {
		m = hash_table[i];
		if (!m)
			break;

		if (m->hash == h && m->ino == ino && m->dev == dev && m->size == size && m->ctime == ctime)
			return m;

		if (i == he)
			break;
	}

	return NULL;
}


static unsigned int hash(ino_t ino, dev_t dev, off_t size, time_t ctime)
{
	unsigned int h = 177573;

	h ^= ino;
	h += h << 5;
	h ^= dev;
	h += h << 5;
	h ^= size;
	h += h << 5;
	h ^= ctime;

	return h & hash_mask;
}


/* Generate debugging statistics syslog message. */
void mmc_logstats(long secs)
{
	syslog(LOG_INFO, "map cache - %d allocated, %d active (%ld bytes), %d free; hash size: %d; expire age: %ld",
	       alloc_count, map_count, (long int)mapped_bytes, free_count, hash_size, expire_age);

	if (map_count + free_count != alloc_count)
		syslog(LOG_ERR, "map counts don't add up!");
}
