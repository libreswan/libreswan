/* Thread / logger friendly glob(), for libreswan
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
#include <glob.h>

#ifndef GLOB_ABORTED
#define GLOB_ABORTED GLOB_ABEND        /* fix for old versions */
#endif

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

bool lswglob(const char *pattern, const char *what,
	     void (*matches)(unsigned count, char **files,
			     struct lswglob_context *context,
			     struct logger *logger),
	     struct lswglob_context *context,
	     struct logger *logger)
{
	int r;
	glob_t globbuf;
	/*
	 * Call glob() locked.
	 *
	 * GLOB_ERR means bail when a directory can't be read which is
	 * possibly redundant as having lswlog_errfunc() return 1
	 * means the same thing!?!
	 */
	pthread_mutex_lock(&lswglob_mutex);
	{
		lswglob_logger = logger;
		lswglob_what = what;
		r = glob(pattern, GLOB_ERR, lswglob_errfunc, &globbuf);
		lswglob_logger = NULL;
		lswglob_what = NULL;
	}
	pthread_mutex_unlock(&lswglob_mutex);

	bool ok;
	switch (r) {
	case 0:	/* success */
		ok = true;
		matches(globbuf.gl_pathc, globbuf.gl_pathv, context, logger);
		break;

	case GLOB_NOSPACE:
		llog_passert(logger, HERE, "out of memory processing %s", what);
		break;

	case GLOB_ABORTED:
		/* already logged by lswglob_errfunc() */
		ok = true;
		break;

	case GLOB_NOMATCH:
		/*
		 * Only NOMATCH is a fail, and then only when
		 * no-wildcards.
		 */
		ok = (strchr(pattern, '*') != NULL);
		break;

	default:
		ok = true;
		llog_pexpect(logger, HERE,
			     "%s pattern %s: unknown glob error %d",
			     what, pattern, r);
	}
	globfree(&globbuf);
	return ok;
}
