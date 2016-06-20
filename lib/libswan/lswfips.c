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

static int has_fips(bool force, const char *check, int fips)
{
	if (fips > 0) {
		libreswan_log("FIPS %s detected", check);
	} else if (fips == 0) {
		if (force) {
			libreswan_log("FIPS %s forced (not detected)", check);
			fips = 1;
		} else {
			libreswan_log("FIPS %s disabled (not detected)", check);
		}
	} else {
		if (force) {
			libreswan_log("FIPS %s forced (detection failed)", check);
			fips = 1;
		} else {
			libreswan_log("FIPS %s detection failed", check);
		}
	}
	return fips;
}

/*
 * Is the machine running in FIPS kernel mode (fips=1 kernel argument)
 * yes (1), no (0), unknown(-1)
 */
int libreswan_fipskernel(void)
{
	char fips_flag[1];
	int n;
	FILE *fd = fopen("/proc/sys/crypto/fips_enabled", "r");

	if (fd == NULL) {
		DBG(DBG_CONTROL,
			DBG_log("FIPS: could not open /proc/sys/crypto/fips_enabled");
			);
		return 0;
	}

	n = fread((void *)fips_flag, 1, 1, fd);
	fclose(fd);
	if (n != 1) {
		loglog(RC_LOG_SERIOUS,
			"FIPS: could not read 1 byte from /proc/sys/crypto/fips_enabled");
		return -1;
	}

	if (fips_flag[0] == '1')
		return 1;

	return 0;
}

int libreswan_has_fips_kernel(bool force)
{
	return has_fips(force, "Kernel Mode", libreswan_fipskernel());
}

/*
 * Return TRUE if we are a fips product.
 * This is irrespective of whether we are running in FIPS mode
 * yes (1), no (0), unknown(-1)
 */
int
libreswan_fipsproduct(void)
{
	if (access(FIPSPRODUCTCHECK, F_OK) != 0) {
		if (errno == ENOENT || errno == ENOTDIR) {
			return 0;
		} else {
			loglog(RC_LOG_SERIOUS,
				"FIPS ABORT: FIPS product check failed to determine status for %s: %d: %s",
				FIPSPRODUCTCHECK, errno, strerror(errno));
			return -1;
		}
	}

	return 1;

}

int libreswan_has_fips_product(bool force)
{
	return has_fips(force, "Product", libreswan_fipsproduct());
}

static int fips_mode = -1;

/*
 * Is the machine running in FIPS mode (fips product AND fips kernel mode)
 * yes (1), no (0), unknown(-1)
 * Only pluto needs to know -1, so it can abort. Every other caller can
 * just check for fips mode using: if (libreswan_fipsmode())
 */
int
libreswan_fipsmode(void)
{
	/*
	 * Fips mode as set by the below.
	 *
	 * Otherwise determine value using fipsproduct and fipskernel.
	 * The problem here is that confread.c calls this (from
	 * addconn) without first calling set_fipsmode.
	 */
	if (fips_mode >= 0) {
		return fips_mode;
	}

	int product = libreswan_fipsproduct();
	int kernel = libreswan_fipskernel();

	if (product == -1 || kernel == -1)
		return -1;

	if (product && kernel)
		return 1;

	return 0;
}

void libreswan_set_fips_mode(bool fips)
{
	fips_mode = fips;
}

#endif
