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

#include <nss.h>		/* for NSS_IsInitialized() */

#include "lswlog.h"
#include "lswnss.h"
#include "fips_mode.h"
#include "enum_names.h"

static enum fips_mode fips_mode = FIPS_MODE_UNSET;

/*
 * Only called by lsw_nss_setup().
 */

enum fips_mode get_fips_mode(const struct logger *logger)
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
	if (fips_mode > FIPS_MODE_UNSET) {
		return fips_mode;
	}

	/*
	 * Is the machine running in FIPS kernel mode (fips=1 kernel
	 * argument).
	 *
	 * We no longer check this ourselves, but depend solely on
	 * NSS, as the mechanisms are expected to change in the
	 * future.
	 */

	fips_mode = (PK11_IsFIPS() ? FIPS_MODE_ON : FIPS_MODE_OFF);

	name_buf eb;
	llog(RC_LOG, logger, "FIPS Mode: %s",
	     str_enum_short(&fips_mode_names, fips_mode, &eb));

	return fips_mode;
}

/*
 * Is the machine running in FIPS mode (fips product AND fips system
 * (kernel) mode) Only pluto needs to know UNKNOWN, so it can
 * abort. Every other caller can just check for fips mode using: if
 * (is_fips_mode())
 */
bool is_fips_mode(void)
{
	pexpect(fips_mode != FIPS_MODE_UNSET);
	return fips_mode == FIPS_MODE_ON;
}

/*
 * used only for debugging with --impair-force-fips
 */
void set_fips_mode(enum fips_mode fips)
{
	fips_mode = fips;
}

/*
 * 0 disabled
 * 1 enabled
 * 2 indeterminate
 */
int libreswan_selinux(struct logger *logger)
{
	char selinux_flag[1];
	int n;
	FILE *fd = fopen("/sys/fs/selinux/enforce", "r");

	if (fd == NULL) {
		/* try new location first, then old location */
		fd = fopen("/selinux/enforce", "r");
		if (fd == NULL) {
			ldbg(logger, "SElinux: disabled, could not open /sys/fs/selinux/enforce or /selinux/enforce");
			return 0;
		}
	}

	n = fread((void *)selinux_flag, 1, 1, fd);
	fclose(fd);
	if (n != 1) {
		llog(RC_LOG, logger, "SElinux: could not read 1 byte from the selinux enforce file");
		return 2;
	}
	if (selinux_flag[0] == '1')
		return 1;
	else
		return 0;
}
