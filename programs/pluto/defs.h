/* misc. universal things, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2018-2019 Andrew Cagney <cagney@gnu.org>
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

#ifndef _DEFS_H
#define _DEFS_H

#include "lswcdefs.h"
#include "lswalloc.h"
#include "realtime.h"

/*
 * Type of serial number of a state object.
 *
 * Used everywhere as a safe proxy for a state object.  Needed in
 * connections.h and state.h; here to simplify dependencies.
 */
typedef unsigned long so_serial_t;
#define SOS_NOBODY      0       /* null serial number */
#define SOS_FIRST       1       /* first normal serial number */

enum sa_type {
#define SA_TYPE_FLOOR 0
	IKE_SA = SA_TYPE_FLOOR,
	IPSEC_SA,
#define SA_TYPE_ROOF (IPSEC_SA+1)
};

extern enum_names v1_sa_type_names;
extern enum_names v2_sa_type_names;
extern enum_enum_names sa_type_names;


/* warns a predefined interval before expiry */
extern const char *check_expiry(realtime_t expiration_date,
				time_t warning_interval, bool strict);

typedef uint32_t msgid_t;      /* Host byte ordered */
#define PRI_MSGID "%"PRIu32
#define v1_MAINMODE_MSGID  ((msgid_t) 0)		/* network and host order */
#define v2_FIRST_MSGID  ((msgid_t) 0)			/* network and host order */
#define v2_INVALID_MSGID  ((msgid_t) 0xffffffff)	/* network and host order */


/* are all bytes 0? */
extern bool all_zero(const unsigned char *m, size_t len);

/* pad_up(n, m) is the amount to add to n to make it a multiple of m */
#define pad_up(n, m) (((m) - 1) - (((n) + (m) - 1) % (m)))

extern bool in_main_thread(void);	/* in plutomain.c */

void delete_lock(void);		/* XXX: better home? */
void free_pluto_main(void);	/* XXX: better home? */

#endif /* _DEFS_H */
