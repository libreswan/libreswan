/*
 * Panic, for libreswan.
 *
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003  Michael Richardson <mcr@freeswan.org>
 * Copyright (C) 2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2015-2016 Andrew Cagney <cagney@gnu.org>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 */

#include <signal.h>	/* for sig_atomic_t */
#include "err.h"
#include "libreswan.h"

#ifndef _LIBRESWAN_PASSERT_H
#define _LIBRESWAN_PASSERT_H
/* our versions of assert: log result */

extern void lsw_passert_fail(const char *file_str,
			     unsigned long line_no,
			     const char *func_str,
			     const char *fmt, ...)
	NEVER_RETURNS
	PRINTF_LIKE(4);

/*
 * http://stackoverflow.com/questions/8487986/file-macro-shows-full-path#8488201
 *
 * It is tempting to tweak the .c.o line so that it passes in the
 * required value.
 */
#ifndef PASSERT_BASENAME
#define PASSERT_BASENAME (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

#define PASSERT_FAIL(FMT, ...)					\
	lsw_passert_fail(PASSERT_BASENAME, __LINE__,		\
			 __func__, FMT, __VA_ARGS__)

#define passert(ASSERTION) {						\
		/* wrapping ASSERTION in parens suppresses -Wparen */	\
		bool assertion__ = ASSERTION; /* no parens */		\
		if (!assertion__) {					\
			PASSERT_FAIL("%s", #ASSERTION);			\
		}							\
	}

/* evaluate x exactly once; assert that err_t result is NULL; */
#define happy(x) {					\
		err_t ugh = x;				\
		if (ugh != NULL) {			\
			PASSERT_FAIL("%s", ugh);	\
		}					\
	}

#endif /* _LIBRESWAN_PASSERT_H */
