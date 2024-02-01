/* log wrapper, for libreswan
 *
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2017 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2017 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2020 Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#include <pthread.h>

#include "lswglob.h"
#include "lswlog.h"

static pthread_mutex_t lswglob_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct logger *lswglob_logger;
static const char *lswglob_what;

static int lswglob_errfunc(const char *epath, int eerrno)
{
	llog_error(lswglob_logger, eerrno,
		   "problem with %s file \"%s\"", lswglob_what, epath);
	return 1;	/* stop glob */
}

int lswglob(const char *pattern, glob_t *pglob, const char *what, struct logger *logger)
{
	int r;
	pthread_mutex_lock(&lswglob_mutex);
	{
		lswglob_logger = logger;
		lswglob_what = what;
#ifndef GLOB_BRACE
# define GLOB_BRACE 0	/* musl libc */
#endif
		r = glob(pattern, GLOB_ERR|GLOB_BRACE, lswglob_errfunc, pglob);
		lswglob_logger = NULL;
		lswglob_what = NULL;
	}
	pthread_mutex_unlock(&lswglob_mutex);
	return r;
}
