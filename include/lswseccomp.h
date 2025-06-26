/*
 * seccomp wrappers, for libreswan
 *
 * Copyright (c) 2018 Andrew Cagney
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

#ifndef LSWSECCOMP_H
#define LSWSECCOMP_H

#include <seccomp.h>		/* rpm:libseccomp-devel */

#include "lswlog.h"		/* for libreswan_exit() et.al. referred to by macro */

/*
 * Add system call NAME to seccomp.
 *
 * Needs to be a macro so that SCMP_SYS(NAME) expands correctly.
 *
 * XXX: seccomp_release() isn't technically needed - the context
 * hasn't been loaded so can be dropped on the floor.
 */

#define LSW_SECCOMP_ADD(NAME) {						\
		/* returns 0 or -ve errno */				\
		int rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW,		\
					  SCMP_SYS(NAME), 0);		\
		if (rc != 0) {						\
			seccomp_release(ctx); /* XXX: needed? */	\
			if (rc < 0) {					\
				fatal(PLUTO_EXIT_SECCOMP_FAIL, logger, -rc, \
				      "seccomp_rule_add() failed for system call '%s'", \
				      #NAME);				\
			} else {					\
				fatal(PLUTO_EXIT_SECCOMP_FAIL, logger, /*no-errno*/0, \
				      "seccomp_rule_add() failed for system call '%s' with unexpected error %d", \
				      #NAME, rc);			\
			}						\
		}							\
	}

#endif
