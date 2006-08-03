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
 * RCSID $Id: defs.h,v 1.36 2004/05/27 00:39:59 mcr Exp $
 */

#ifndef _DEFS_H
#define _DEFS_H

#include "oswalloc.h"

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

#ifdef SMARTCARD
# define USED_BY_SMARTCARD /* ignore */
#else
# define USED_BY_SMARTCARD UNUSED
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

/* filter eliminating the directory entries '.' and '..' */
typedef struct dirent dirent_t;
extern int file_select(
#ifdef SCANDIR_HAS_CONST
		       const
#endif
		       dirent_t *entry);

/* cleanly exit Pluto */

extern void exit_pluto(int /*status*/) NEVER_RETURNS;


/* zero all bytes */
#define zero(x) memset((x), '\0', sizeof(*(x)))

/* are all bytes 0? */
extern bool all_zero(const unsigned char *m, size_t len);

/* pad_up(n, m) is the amount to add to n to make it a multiple of m */
#define pad_up(n, m) (((m) - 1) - (((n) + (m) - 1) % (m)))

#ifdef HAVE_THREADS
extern void lock_crl_list(const char *who);
extern void unlock_crl_list(const char *who);
extern void lock_cacert_list(const char *who);
extern void unlock_cacert_list(const char *who);
extern void lock_ocsp_cache(const char *who);
extern void unlock_ocsp_cache(const char *who);
extern void lock_authcert_list(const char *who);
extern void unlock_authcert_list(const char *who);
#else
#define lock_crl_list(who) /* nothing */
#define unlock_crl_list(who) /* nothing */
#define lock_cacert_list(who) /* nothing */
#define unlock_cacert_list(who) /* nothing */
#define lock_ocsp_cache(who) /* nothing */
#define unlock_ocsp_cache(who) /* nothing */
#define lock_authcert_list(who) /* nothing */
#define unlock_authcert_list(who) /* nothing */
#endif


#endif /* _DEFS_H */
