/*
 * NSS boilerplate stuff, for libreswan.
 *
 * Copyright (C) 2016, Andrew Cagney <cagney@gnu.org>
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

#ifndef _LSWNSS_H_
#define _LSWNSS_H_

#include <stdbool.h>

#include <pk11pub.h>

enum lsw_nss_flags {
	LSW_NSS_READONLY = 1,
	LSW_NSS_CLEANUP = 2,
};

/*
 * If something goes wrong, the error gets dumped into this null
 * terminated buffer.
 */
typedef char lsw_nss_buf_t[100];

bool lsw_nss_setup(const char *config_dir, unsigned flags,
		   PK11PasswordFunc get_nss_password, lsw_nss_buf_t err);
void lsw_nss_shutdown(unsigned flags);

#endif
