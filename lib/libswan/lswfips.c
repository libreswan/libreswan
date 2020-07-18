/*
 * misc functions to get compile time and runtime options
 *
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012,2020 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
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

#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "lswlog.h"
#include "lswnss.h"
#include "lswfips.h"

/*
 * Is the machine running in FIPS kernel mode (fips=1 kernel argument)
 * We no longer check this ourselves, but depend solely on NSS, as
 * the mechanisms are expected to change in the future.
 */
static enum lsw_fips_mode lsw_fips_system(void)
{
	return PK11_IsFIPS() ? LSW_FIPS_ON : LSW_FIPS_OFF;
}

/*
 * Legacy FIPS product test. This is only used for RHEL6 to RHEL8 
 *
 * Return TRUE if we are a fips product.
 * This is irrespective of whether we are running in FIPS mode
 * yes (1), no (0), unknown(-1)
 */
#ifdef FIPS_CHECK
static enum lsw_fips_mode lsw_fipsproduct(void)
{
	if (access(FIPSPRODUCTCHECK, F_OK) != 0) {
		if (errno == ENOENT || errno == ENOTDIR) {
			return LSW_FIPS_OFF;
		} else {
			loglog(RC_LOG_SERIOUS,
				"FIPS ABORT: FIPS product check failed to determine status for %s: %d: %s",
				FIPSPRODUCTCHECK, errno, strerror(errno));
			return LSW_FIPS_UNKNOWN;
		}
	}
	return LSW_FIPS_ON;
}
#endif

static enum lsw_fips_mode fips_mode = LSW_FIPS_UNKNOWN;

/*
 * Only called by lsw_nss_setup().
 */

enum lsw_fips_mode lsw_get_fips_mode(void)
{
	/*
	 * NSS returns bogus results for the FIPS check if you did not
	 * open a database. If the program/tool runs libswan code
	 * without a config file (and so it doesn't know where any nss
	 * db lives), that tool should call NSS_NoDB_Init("."); before
	 * using libswan code. See lsw_nss_setup() for an example.
	 */
	passert(NSS_IsInitialized());

	/*
	 * Has FIPS mode been forced using set_fips_mode()?
	 */
	if (fips_mode > LSW_FIPS_UNKNOWN) {
		return fips_mode;
	}

#ifdef FIPS_CHECK
	enum lsw_fips_mode product = lsw_fipsproduct();
#endif
	enum lsw_fips_mode system = lsw_fips_system();

	fips_mode = system;

#ifdef FIPS_CHECK
	if (product == LSW_FIPS_UNKNOWN)
		fips_mode = LSW_FIPS_UNKNOWN;
	if (product == LSW_FIPS_OFF && system == LSW_FIPS_ON)
		fips_mode = LSW_FIPS_OFF;

	libreswan_log("FIPS Product: %s", product == LSW_FIPS_UNKNOWN ? "UNKNOWN" : product == LSW_FIPS_ON ? "YES" : "NO");
	libreswan_log("FIPS System: %s",  system == LSW_FIPS_UNKNOWN ? "UNKNOWN" :  system == LSW_FIPS_ON ? "YES" : "NO");
#endif
	libreswan_log("FIPS Mode: %s", fips_mode == LSW_FIPS_ON ? "YES" : fips_mode == LSW_FIPS_OFF ? "NO" : "UNKNOWN");
	return fips_mode;
}

/*
 * Is the machine running in FIPS mode (fips product AND fips system
 * (kernel) mode) Only pluto needs to know UNKNOWN, so it can
 * abort. Every other caller can just check for fips mode using: if
 * (libreswan_fipsmode())
 */
bool libreswan_fipsmode(void)
{
	pexpect(fips_mode != LSW_FIPS_UNKNOWN);
	return fips_mode == LSW_FIPS_ON;
}

/*
 * used only for debugging with --impair-force-fips
 */
void lsw_set_fips_mode(enum lsw_fips_mode fips)
{
	fips_mode = fips;
}
