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

#ifndef HAVE_LABELED_IPSEC
#error this file should only be compiled when labeled ipsec support is enabled
#endif

#include <errno.h>
#include "security_selinux.h"

#include "defs.h"		/* for so_serial_t */
#include "log.h"

void init_selinux(struct logger *logger)
{
	if (!is_selinux_enabled()) {
		llog(RC_LOG, logger, "selinux support is NOT enabled.");
	} else {
#ifdef HAVE_OLD_SELINUX
		if (avc_init("libreswan", NULL, NULL, NULL, NULL) != 0) {
			fatal(PLUTO_EXIT_SELINUX_FAIL, logger, "selinux: could not initialize avc");
		}
#endif
		llog(RC_LOG, logger, "SELinux support is enabled in %s mode.",
			security_getenforce() ? "ENFORCING" : "PERMISSIVE");
	}
}

#ifdef HAVE_OLD_SELINUX
int within_range(security_context_t sl, security_context_t range, struct logger *logger)
{
	int rtn = 1;
	security_id_t slsid;
	security_id_t rangesid;
	struct av_decision avd;
	security_class_t tclass;
	access_vector_t av;

	/*
	 * * Get the sids for the sl and range contexts
	 */
	rtn = avc_context_to_sid(sl, &slsid);
	if (rtn != 0) {
		llog(RC_LOG, logger, "selinux within_range: Unable to retrieve sid for sl context (%s)", sl);
		return 0;
	}
	rtn = avc_context_to_sid(range, &rangesid);
	if (rtn != 0) {
		llog(RC_LOG, logger, "selinux within_range: Unable to retrieve sid for range context (%s)", range);
		return 0;
	}

	/*
	** Straight up test between sl and range
	**/
	tclass = string_to_security_class("association");
	av = string_to_av_perm(tclass, "polmatch");
	rtn = avc_has_perm(slsid, rangesid, tclass, av, NULL, &avd);
	if (rtn != 0) {
		llog(RC_LOG, logger, "selinux within_range: The sl (%s) is not within range of (%s)", sl, range);
		return 0;
	}
	dbg("selinux within_range: The sl (%s) is within range of (%s)", sl, range);
	return 1;
}
#else
int within_range(const char *sl, const char *range, struct logger *logger)
{
	int rtn;
	/*
	 * Check access permission for sl (connection policy label from SAD)
	 * and range (connection flow label from SPD but initially the
	 * conn policy-label= entry of the ipsec.conf(5) configuration file).
	 */
	rtn = selinux_check_access(sl, range, "association", "polmatch", NULL);
	if (rtn != 0) {
		llog(RC_LOG, logger, "selinux within_range: sl (%s) - range (%s) error: %s",
		     sl, range, strerror(errno));
		return 0;
	}
	dbg("selinux within_range: Permission granted sl (%s) - range (%s)", sl, range);
	return 1;
}
#endif
