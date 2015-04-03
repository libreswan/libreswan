/* misc. universal things
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 */

#ifndef _DEFS_H
#define _DEFS_H

#include "lswalloc.h"

/* type of serial number of a state object
 * Needed in connections.h and state.h; here to simplify dependencies.
 */
typedef unsigned long so_serial_t;
#define SOS_NOBODY      0       /* null serial number */
#define SOS_FIRST       1       /* first normal serial number */

extern monotime_t mononow(void);	/* monotonic variant of time(2) */

/* warns a predefined interval before expiry */
extern const char *check_expiry(realtime_t expiration_date,
				time_t warning_interval, bool strict);

/* cleanly exit Pluto */

extern void exit_pluto(int /*status*/) NEVER_RETURNS;

typedef u_int32_t msgid_t;      /* Network order for ikev1, host order for ikev2 */

/* are all bytes 0? */
extern bool all_zero(const unsigned char *m, size_t len);

/* pad_up(n, m) is the amount to add to n to make it a multiple of m */
#define pad_up(n, m) (((m) - 1) - (((n) + (m) - 1) % (m)))

/* a macro to discard the const portion of a variable to avoid
 * otherwise unavoidable -Wcast-qual warnings.
 * USE WITH CAUTION and only when you know it's safe to discard the const
 */
#ifdef __GNUC__
#define DISCARD_CONST(vartype, \
		      varname) (__extension__({ const vartype tmp = (varname); \
						(vartype)(uintptr_t)tmp; }))
#else
#define DISCARD_CONST(vartype, varname) ((vartype)(uintptr_t)(varname))
#endif

#endif /* _DEFS_H */
