/*
 * misc functions to get compile time and runtime options
 *
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2016, Andrew Cagney <cagney@gnu.org>
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
 */

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <stdarg.h>

#include "lswlog.h"
#include "lswconf.h"
#include "lswalloc.h"


#include <nspr.h>
#include <pk11pub.h>

static struct lsw_conf_options global_oco;

#define SUBDIRNAME(X) X

static void lsw_conf_setdefault(void)
{
	if (global_oco.is_set) {
		return;
	}

	global_oco.is_set = true;

	/* copy everything to the heap for consistency. */

	lsw_conf_confddir(IPSEC_CONFDDIR, NULL);
}

PRINTF_LIKE(2)
static void subst(char **field, const char *value, ...)
{
	pfreeany(*field);
	va_list ap;
	va_start(ap, value);
	*field = alloc_vprintf(value, ap);
	va_end(ap);
}

void lsw_conf_free_oco(void)
{
	/*
	 * Must be a nicer way to loop over this?
	 *
	 * for (char *p = (char*)&global_oco; p < (char*)(&global_oco + 1); p++)
	 */

	pfreeany(global_oco.confddir);

	messup(&global_oco);
}

const struct lsw_conf_options *lsw_init_options(void)
{
	lsw_conf_setdefault();
	return &global_oco;
}

void lsw_conf_confddir(const char *confddir, struct logger *logger)
{
	lsw_conf_setdefault();
	subst(&global_oco.confddir, "%s", confddir);

	if (logger != NULL &&
	    !streq(global_oco.confddir, IPSEC_CONFDDIR))
		llog(RC_LOG, logger, " adjusting ipsec.d to %s", global_oco.confddir);
}
