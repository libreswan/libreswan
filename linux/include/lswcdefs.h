/* sys/cdefs.h like compiler macros, for libreswan
 *
 * Copyright (C) 1998, 1999, 2000  Henry Spencer.
 * Copyright (C) 1999, 2000, 2001  Richard Guy Briggs
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
 *
 */

#ifndef LSWCDEFS_H
#define LSWCDEFS_H

/* GCC magic for use in function definitions! */
#ifdef GCC_LINT
# define PRINTF_LIKE(n) __attribute__ ((format(printf, n, n + 1)))
# define STRFTIME_LIKE(n) __attribute__ ((format (strftime, n, 0)))
# define NEVER_RETURNS __attribute__ ((noreturn))
# define UNUSED __attribute__ ((unused))
# define MUST_USE_RESULT  __attribute__ ((warn_unused_result))
#else
# define PRINTF_LIKE(n) /* ignore */
# define STRFTIME_LIKE(n) /* ignore */
# define NEVER_RETURNS  /* ignore */
# define UNUSED         /* ignore */
# define MUST_USE_RESULT	/* ignore */
#endif

#ifdef COMPILER_HAS_NO_PRINTF_LIKE
# undef PRINTF_LIKE
# define PRINTF_LIKE(n) /* ignore */
# undef STRFTIME_LIKE
# define STRFTIME_LIKE(n) /* ignore */
#endif

#endif
