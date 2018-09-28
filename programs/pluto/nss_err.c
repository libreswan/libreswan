/*
 * NSS error conversion
 * Copyright (C) 2015 Matt Rogers <mrogers@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <libreswan.h>
#include <prerror.h>
#include <secport.h>
#include "nss_err.h"

const char *nss_err_str(PRInt32 err)
{
	const char *errstr = PORT_ErrorToString(err);
	if (errstr == NULL) {
		errstr = "(no description)";
	}
	return errstr;
}
