#if HAVE_CONFIG_H
# include <config.h>
#endif
#undef realloc
#undef malloc

#include <stdlib.h>

#include <errno.h>

void * rpl_realloc (void *p, size_t n)
{
	void *result;

	if (n == 0)
		n = 1;

	if (p == NULL)
		result = malloc (n);
	else
		result = realloc (p, n);

	if (result == NULL)
		errno = ENOMEM;

	return result;
}
