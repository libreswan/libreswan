/*
 * sanitize a string into a printable format.
 *
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003  Michael Richardson <mcr@freeswan.org>
 * Copyright (C) 2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2015 Andrew Cagney <cagney@gnu.org>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/lgpl.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 */

#include "libreswan.h"

#ifndef _LIBRESWAN_PASSERT_H
#define _LIBRESWAN_PASSERT_H
/* our versions of assert: log result */

typedef void (*libreswan_passert_fail_t)(const char *pred_str,
					 const char *file_str,
					 unsigned long line_no) NEVER_RETURNS;

extern libreswan_passert_fail_t libreswan_passert_fail;

extern void pexpect_log(const char *pred_str,
			const char *file_str, unsigned long line_no);

#define impossible()  libreswan_passert_fail("impossible", __FILE__, __LINE__)

extern void libreswan_switch_fail(int n,
				  const char *file_str,
				  unsigned long line_no) NEVER_RETURNS;

#define bad_case(n) libreswan_switch_fail((int) (n), __FILE__, __LINE__)

#define passert(pred) {							\
		/* Shorter if(!(pred)) suppresses -Wparen */		\
		if (pred) {} else {					\
			libreswan_passert_fail(#pred, __FILE__,		\
					       __LINE__);		\
		}							\
	}

#define pexpect(pred) {							\
		/* Shorter if(!(pred)) suppresses -Wparen */		\
		if (pred) {} else {					\
			pexpect_log(#pred, __FILE__, __LINE__);		\
		}							\
	}

/* evaluate x exactly once; assert that err_t result is NULL; */
#define happy(x) { \
		err_t ugh = x; \
		if (ugh != NULL) \
			libreswan_passert_fail(ugh, __FILE__, __LINE__); \
	}

#endif /* _LIBRESWAN_PASSERT_H */
