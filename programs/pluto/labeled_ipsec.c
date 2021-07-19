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

#ifdef HAVE_LABELED_IPSEC

#include <selinux/selinux.h>
#ifdef HAVE_OLD_SELINUX
#include <selinux/avc.h>
#include <selinux/context.h>
#endif

err_t vet_seclabel(shunk_t sl)
{
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
}

void init_labeled_ipsec(struct logger *logger)
{
	if (!is_selinux_enabled()) {
		llog(RC_LOG, logger, "selinux support is NOT enabled.");
		return;
	}
#ifdef HAVE_OLD_SELINUX
	if (avc_init("libreswan", NULL, NULL, NULL, NULL) != 0) {
		fatal(PLUTO_EXIT_SELINUX_FAIL, logger, "selinux: could not initialize avc");
	}
#endif
	llog(RC_LOG, logger, "SELinux support is enabled in %s mode.",
	     security_getenforce() ? "ENFORCING" : "PERMISSIVE");
}

#ifdef HAVE_OLD_SELINUX
static bool within_range(security_context_t sl, security_context_t range, struct logger *logger)
{
	int rtn;

	/* Get the sids for the sl and range contexts */

	security_id_t slsid;
	rtn = avc_context_to_sid(sl, &slsid);
	if (rtn != 0) {
		/* ??? log message should report errno */
		llog(RC_LOG, logger, "selinux within_range: Unable to retrieve sid for sl context (%s)", sl);
		return false;
	}
	security_id_t rangesid;
	rtn = avc_context_to_sid(range, &rangesid);
	if (rtn != 0) {
		/* ??? log message should report errno */
		llog(RC_LOG, logger, "selinux within_range: Unable to retrieve sid for range context (%s)", range);
		return false;
	}

	/* Straight up test between sl and range */

	security_class_t tclass = string_to_security_class("association");
	access_vector_t av = string_to_av_perm(tclass, "polmatch");
	struct av_decision avd;
	rtn = avc_has_perm(slsid, rangesid, tclass, av, NULL, &avd);
	if (rtn != 0) {
		/* ??? log message should report errno */
		llog(RC_LOG, logger, "selinux within_range: The sl (%s) is not within range of (%s)", sl, range);
		return false;
	}
	dbg("selinux within_range: The sl (%s) is within range of (%s)", sl, range);
	return true;
}
#else
static bool within_range(const char *sl, const char *range, struct logger *logger)
{
	/*
	 * Check access permission for sl (connection policy label from SAD)
	 * and range (connection flow label from SPD but initially the
	 * conn policy-label= entry of the ipsec.conf(5) configuration file).
	 */
	int rtn = selinux_check_access(sl, range, "association", "polmatch", NULL);
	if (rtn != 0) {
		/* note: selinux_check_access(3) does not specify that errno is set */
		llog(RC_LOG, logger, "selinux within_range: sl (%s) - range (%s) error: %s",
		     sl, range, strerror(errno));
		return false;
	}
	dbg("selinux within_range: Permission granted sl (%s) - range (%s)", sl, range);
	return true;
}
#endif

bool sec_label_within_range(shunk_t label, chunk_t range, struct logger *logger)
{
	if (label.len == 0 || range.len == 0) {
		return false;
	}
	/*
	 * NUL must be part of HUNK.  Too weak?
	 */
	passert(hunk_strnlen(label) < label.len);
	passert(hunk_strnlen(range) < range.len);
	/* use as strings */
	bool within = within_range(label.ptr, (const char*)range.ptr, logger);
	if (DBGP(DBG_BASE)) {
		LLOG_JAMBUF(DEBUG_STREAM, logger, buf) {
			jam(buf, "security label '");
			jam_sanitized_hunk(buf, label);
			jam(buf, "' %s within range '", within ? "is" : "is not");
			jam_sanitized_hunk(buf, range);
			jam(buf, "'");
		}
	}
	return within;
}

#else

err_t vet_seclabel(shunk_t sl UNUSED)
{
	return "Labeled IPsec not supported";
}

void init_labeled_ipsec(struct logger *logger UNUSED)
{
}

bool sec_label_within_range(shunk_t label UNUSED, chunk_t range UNUSED, struct logger *logger UNUSED)
{
	return false;
}

#endif
