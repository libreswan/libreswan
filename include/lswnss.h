/*
 * NSS boilerplate stuff, for libreswan.
 *
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

#ifndef _LSWNSS_H_
#define _LSWNSS_H_

#include <prerror.h>		/* for PRErrorCode, for PR_GetError() */
#include <pk11pub.h>

#include "lswcdefs.h"		/* for PRINTF_LIKE() */
#include "lset.h"
#include "lswalloc.h"
#include "secrets.h"
#include "diag.h"

enum lsw_nss_flags {
	LSW_NSS_READONLY = 1,
	/*
	 * Should shutdown call PR_CLEANUP.
	 */
	LSW_NSS_SKIP_PR_CLEANUP = 2,
};

/*
 * If something goes wrong, the error gets dumped into this null
 * terminated buffer.
 */

diag_t lsw_nss_setup(const char *config_dir, unsigned flags, struct logger *logger);
void lsw_nss_shutdown(void);

/*
 * Any code that could call back into lsw_nss_get_password() needs to
 * pass in a context parameter - the logger is it.  Otherwise the
 * password code can't log!
 *
 * Just a wrapper but type checked.
 */
#define lsw_nss_get_password_context(LOGGER) ({ struct logger *l_ = LOGGER; l_; })

PK11SlotInfo *lsw_nss_get_authenticated_slot(struct logger *logger);

/*
 * XXX: these get the error using the thread-local PR_GetError() which
 * should always be set.
 */
/* SECERR: N (0xX): <error-string> */
size_t jam_nss_error(struct jambuf *log);
/* NSS: <message...>: SECERR: N (0xX): <error-string> */
void log_nss_error(lset_t rc_log, struct logger *logger,
		   const char *message, ...) PRINTF_LIKE(3);
diag_t diag_nss_error(const char *message, ...) PRINTF_LIKE(1);
void passert_nss_error(struct logger *logger, where_t where,
		       const char *message, ...) PRINTF_LIKE(3) NEVER_RETURNS;
void pexpect_nss_error(struct logger *logger, where_t where,
		       const char *message, ...) PRINTF_LIKE(3);
void DBG_nss_error(struct logger *logger, const char *message, ...) PRINTF_LIKE(2);
#define dbg_nss_error(LOGGER, MESSAGE, ...)				\
	{								\
		if (DBGP(DBG_BASE)) {					\
			DBG_nss_error(LOGGER, MESSAGE, ##__VA_ARGS__);	\
		}							\
	}

size_t jam_nss_ckm(struct jambuf *buf, CK_MECHANISM_TYPE mechanism);
size_t jam_nss_ckf(struct jambuf *buf, CK_FLAGS flags);
size_t jam_nss_cka(struct jambuf *buf, CK_ATTRIBUTE_TYPE attribute);
size_t jam_nss_secitem(struct jambuf *buf, const SECItem *secitem);

#endif
