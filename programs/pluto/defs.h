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

#ifdef KLIPS
# define USED_BY_KLIPS	/* ignore */
#else
# define USED_BY_KLIPS	UNUSED
#endif

#ifdef DEBUG
# define USED_BY_DEBUG	/* ignore */
#else
# define USED_BY_DEBUG	UNUSED
#endif

/* type of serial number of a state object
 * Needed in connections.h and state.h; here to simplify dependencies.
 */
typedef unsigned long so_serial_t;
#define SOS_NOBODY	0	/* null serial number */
#define SOS_FIRST	1	/* first normal serial number */

/* warns a predefined interval before expiry */
extern const char* check_expiry(time_t expiration_date,
    int warning_interval, bool strict);

/* cleanly exit Pluto */

extern void exit_pluto(int /*status*/) NEVER_RETURNS;

typedef u_int32_t msgid_t;	/* Network order for ikev1, host order for ikev2 */

/* zero all bytes */
#define zero(x) memset((x), '\0', sizeof(*(x)))

/* are all bytes 0? */
extern bool all_zero(const unsigned char *m, size_t len);

/* pad_up(n, m) is the amount to add to n to make it a multiple of m */
#define pad_up(n, m) (((m) - 1) - (((n) + (m) - 1) % (m)))

#endif /* _DEFS_H */
