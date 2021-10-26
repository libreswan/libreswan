/* Output an (NS)PR error, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney
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

#include <stdio.h>
#include <stdarg.h>

#include <prerror.h>
#include <secerr.h>

#include "lswlog.h"
#include "lswalloc.h"
#include "lswnss.h"

/*
 * See https://bugzilla.mozilla.org/show_bug.cgi?id=172051
 */

size_t jam_nss_error_code(struct jambuf *buf, PRErrorCode code)
{
	if (code == 0) {
		return jam_string(buf, "error code not saved by NSS");
	}

	size_t size = 0;

	/*
	 * Print the symbolic name, if known.  This makes tracking
	 * down the error in NSS's code base easier.
	 *
	 * If the name isn't known print the magic code (but would
	 * that ever happen?).
	 */
	const char *name = PR_ErrorToName(code);
	if (name != NULL) {
		size += jam_string(buf, name);
	} else if (IS_SEC_ERROR(code)) {
		size += jam(buf, "SEC_ERROR_BASE+%d", code - SEC_ERROR_BASE);
#if 0
	} else if (IS_SSL_ERROR(code)) {
		size += jam(buf, "SSL_ERROR_BASE+%d", code - SSL_ERROR_BASE);
#endif
	} else {
		size += jam(buf, "NSS %d 0x%x", code, code);
	}

	jam_string(buf, ": ");

	/*
	 * NSPR should contain string tables for all known error
	 * classes.  When it doesn't it returns "Unknown code ...".
	 * Should this specify the english language?
	 *
	 * Note: PORT_ErrorToString(err) is just a macro wrapper that
	 * expands to the below call.
	 */
	const char *string = PR_ErrorToString(code, PR_LANGUAGE_I_DEFAULT);
	size += jam_string(buf, string);

	return size;
}
