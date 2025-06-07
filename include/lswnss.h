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

#ifndef LSWNSS_H
#define LSWNSS_H

#include <prerror.h>		/* for PRErrorCode, for PR_GetError() */
#include <pk11pub.h>

#include "lswcdefs.h"		/* for PRINTF_LIKE() */
#include "lset.h"
#include "lswalloc.h"
#include "secrets.h"
#include "diag.h"

struct nss_flags {
	const char *password;

	bool open_readonly;
	/*
	 * Should shutdown call PR_CLEANUP.
	 */
	bool skip_pr_cleanup;
};

/*
 * If something goes wrong, fatal(PLUTO_EXIT_FAIL, logger, ...) is called.
 */

void init_nss(const char *config_dir, struct nss_flags flags, struct logger *logger);
void shutdown_nss(void);

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
 * These get the error using the thread-local PR_GetError() which
 * should always be set (or is passed in).
 *
 * jam: <error-string> (...)
 * log: NSS: <message...>: <error-string> (...)
 *
 * XXX: not all are implemented.
 */

size_t jam_nss_error_code(struct jambuf *log, PRErrorCode code);

void llog_nss_error_code(lset_t rc_log, struct logger *logger,
			 PRErrorCode code,
			 const char *message, ...) PRINTF_LIKE(4);
#define llog_nss_error(RC_LOG, LOGGER, MESSAGE, ...)		\
	llog_nss_error_code(RC_LOG, LOGGER, PR_GetError(),	\
			    MESSAGE, ##__VA_ARGS__)

diag_t diag_nss_error(const char *message, ...) PRINTF_LIKE(1);

void passert_nss_error(const struct logger *logger, where_t where,
		       const char *message, ...) PRINTF_LIKE(3) NEVER_RETURNS;

void pexpect_nss_error(struct logger *logger, where_t where,
		       const char *message, ...) PRINTF_LIKE(3);

#define ldbg_nss_error(LOGGER, MESSAGE, ...)				\
	{								\
		if (DBGP(DBG_BASE)) {					\
			llog_nss_error(DEBUG_STREAM, logger,		\
				       MESSAGE, ##__VA_ARGS__);		\
		}							\
	}

size_t jam_nss_ckg(struct jambuf *buf, CK_GENERATOR_FUNCTION generate);
size_t jam_nss_cka(struct jambuf *buf, CK_ATTRIBUTE_TYPE attribute);
size_t jam_nss_ckf(struct jambuf *buf, CK_FLAGS flags);
size_t jam_nss_ckm(struct jambuf *buf, CK_MECHANISM_TYPE mechanism);
size_t jam_nss_oid(struct jambuf *buf, SECOidTag oidtag);
size_t jam_nss_secitem(struct jambuf *buf, const SECItem *secitem);

const char *str_nss_oid(SECOidTag oid, name_buf *buf);
const char *str_nss_ckm(CK_MECHANISM_TYPE mechanism, name_buf *buf);

/* these do not clone */
chunk_t same_secitem_as_chunk(SECItem si);
shunk_t same_secitem_as_shunk(SECItem si);
SECItem same_chunk_as_secitem(chunk_t chunk, SECItemType type);
SECItem same_shunk_as_secitem(shunk_t chunk, SECItemType type); /* NSS doesn't do const */

/* this clones */
chunk_t clone_secitem_as_chunk(SECItem si, const char *name);

#endif
