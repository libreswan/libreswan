/* selinux routines
 * Copyright (C) 2011 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2020 Richard Haines <richard_c_haines@btinternet.com>
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

#include <errno.h>

#include "labeled_ipsec.h"

#include "defs.h"		/* for so_serial_t */
#include "log.h"
#include "connections.h"

#ifdef HAVE_LABELED_IPSEC
#include <selinux/selinux.h>		/* rpm:libselinux-devel */
#endif

err_t vet_seclabel(shunk_t sl)
{
#ifdef HAVE_LABELED_IPSEC
	if (sl.len > MAX_SECCTX_LEN)
		return "security label is too long";

	if (sl.len <= 1)
		return "security label is empty";

	size_t strl = hunk_strnlen(sl);

	if (strl == sl.len)
		return "security label is missing the NUL terminator";

	if (strl + 1 < sl.len)
		return "security label has an embedded NUL";

	return NULL;
#else
	dbg("%s() not implemented: %zu", __func__, sl.len);
	return "Labeled IPsec not supported";
#endif
}

void init_labeled_ipsec(const struct logger *logger)
{
#ifdef HAVE_LABELED_IPSEC
	if (!is_selinux_enabled()) {
		llog(RC_LOG, logger, "selinux support is NOT enabled.");
		return;
	}
	llog(RC_LOG, logger, "SELinux support is enabled in %s mode.",
	     security_getenforce() ? "ENFORCING" : "PERMISSIVE");
#else
	ldbg(logger, "%s() not implemented", __func__);
#endif
}

#ifdef HAVE_LABELED_IPSEC
static bool check_access(const char *perm,
			 const char *source, const char *scontext,
			 const char *target, const char *tcontext,
			 const struct logger *logger)
{
	const char tclass[] = "association";
	errno = 0;	/* selinux_check_access(3) is not documented to set errno */
	int rtn = selinux_check_access(scontext, tcontext, tclass, perm, /*auditdata*/NULL);
	if (rtn != 0) {
		/* make error look like an audit record */
		llog_errno(RC_LOG, logger, errno,
			   "selinux denied { %s } %s scontext=%s %s tcontext=%s tclass=%s: ",
			   perm, source, scontext, target, tcontext, tclass);
		return false;
	}
	ldbg(logger,
	     "selinux granted { %s } %s sec_label=scontext=%s %s sec_label=tcontext=%s tclass=%s",
	     perm, source, scontext, target, tcontext, tclass);
	return true;
}
#endif

bool sec_label_within_range(const char *source, shunk_t label, chunk_t range,
			    const struct logger *logger)
{
#ifdef HAVE_LABELED_IPSEC
	if (label.len == 0 || range.len == 0) {
		return false;
	}
	/*
	 * NUL must be part of HUNK.  Too weak?
	 *
	 * Translate names into selinux speak.
	 */
	passert(hunk_strnlen(label) < label.len);
	passert(hunk_strnlen(range) < range.len);
	const char *scontext = label.ptr;
	const char *tcontext = (const char*)range.ptr;

	/*
	 * Check access permission for sl (connection policy label from SAD)
	 * and range (connection flow label from SPD but initially the
	 * conn policy-label= entry of the ipsec.conf(5) configuration file).
	 *
	 * XXX: Check access permission for SCONTEXT (sec_label from
	 * acquire, or remote traffic selector) within TCONTEXT
	 * (sec_label from the connection template).
	 */
	if (!check_access("polmatch", source, scontext,
			  "connection", tcontext, logger)) {
		return false;
	}

	char *domain;
	errno = 0;	/* getcon(3) is not documented to set errno */
	if(getcon(&domain) != 0) {
		/* note: getcon(3) does not specify that errno is set */
		llog_errno(RC_LOG, logger, errno, "getcon(): ");
		return false;
	}
	dbg("our SElinux context is '%s'", domain);

	/*
	 * Check if `pluto`'s SELinux domain can `setcontext` against the child/IPsec SA label.
	 *
	 * XXX: Pluto's context is within the acquire/ts context.
	 * XXX: is this the right way around.
	 */
	if (!check_access("setcontext", "Pluto's SELinux domain", domain,
			  source, scontext, logger)) {
		return false;
	}

	freecon(domain);
	return true;
#else
	ldbg(logger, "%s() not implemented: %s "PRI_SHUNK" "PRI_SHUNK,
	     __func__, source, pri_shunk(label), pri_shunk(range));
	return false;
#endif
}
