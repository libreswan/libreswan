/*
 * misc functions to get compile time and runtime options
 *
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
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
 */

#ifdef FIPS_CHECK

#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include "lswlog.h"
#include "lswfips.h"

/*
 * Is the machine running in FIPS kernel mode (fips=1 kernel argument)
 */
static enum lsw_fips_mode lsw_fipskernel(void)
{
	char fips_flag[1];
	int n;
	FILE *fd = fopen("/proc/sys/crypto/fips_enabled", "r");

	if (fd == NULL) {
		DBG(DBG_CONTROL,
			DBG_log("FIPS: could not open /proc/sys/crypto/fips_enabled");
			);
		return LSW_FIPS_OFF;
	}

	n = fread((void *)fips_flag, 1, 1, fd);
	fclose(fd);
	if (n != 1) {
		loglog(RC_LOG_SERIOUS,
			"FIPS: could not read 1 byte from /proc/sys/crypto/fips_enabled");
		return LSW_FIPS_UNKNOWN;
	}

	if (fips_flag[0] == '1')
		return LSW_FIPS_ON;

	return LSW_FIPS_OFF;
}

/*
 * Return TRUE if we are a fips product.
 * This is irrespective of whether we are running in FIPS mode
 * yes (1), no (0), unknown(-1)
 */
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

static enum lsw_fips_mode fips_mode = LSW_FIPS_UNSET;

/*
 * Should only be called directly by plutomain.c
 */
enum lsw_fips_mode lsw_get_fips_mode(void)
{
	/*
	 * Fips mode as set by the below.
	 *
	 * Otherwise determine value using fipsproduct and fipskernel.
	 * The problem here is that confread.c calls this (from
	 * addconn) without first calling set_fipsmode.
	 */
	if (fips_mode > LSW_FIPS_UNSET) {
		return fips_mode;
	}

	enum lsw_fips_mode product = lsw_fipsproduct();
	enum lsw_fips_mode kernel = lsw_fipskernel();

	if (product == LSW_FIPS_UNKNOWN || kernel == LSW_FIPS_UNKNOWN) {
		fips_mode = LSW_FIPS_UNKNOWN;
	} else if (product == LSW_FIPS_ON && kernel== LSW_FIPS_ON)  {
		fips_mode = LSW_FIPS_ON;
	} else {
		fips_mode = LSW_FIPS_OFF;
	}

	libreswan_log("FIPS Product: %s", product == LSW_FIPS_UNKNOWN ? "UNKNOWN" : product == LSW_FIPS_ON ? "YES" : "NO");
	libreswan_log("FIPS Kernel: %s",  kernel == LSW_FIPS_UNKNOWN ? "UNKNOWN" :  kernel == LSW_FIPS_ON ? "YES" : "NO");
	libreswan_log("FIPS Mode: %s", fips_mode == LSW_FIPS_ON ? "YES" : fips_mode == LSW_FIPS_OFF ? "NO" : "UNKNOWN");
	return fips_mode;
}

/*
 * Is the machine running in FIPS mode (fips product AND fips kernel mode)
 * Only pluto needs to know UNKNOWN, so it can abort. Every other caller can
 * just check for fips mode using: if (libreswan_fipsmode())
 */
bool libreswan_fipsmode(void)
{
	if (fips_mode == LSW_FIPS_UNSET)
		fips_mode = lsw_get_fips_mode();

	return fips_mode == LSW_FIPS_ON;
}

/*
 * used only for debugging with --impair-force-fips
 */
void lsw_set_fips_mode(enum lsw_fips_mode fips)
{
	fips_mode = fips;
}

#endif
