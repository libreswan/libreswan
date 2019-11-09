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

size_t lswlog_nss_error(struct lswlog *buf)
{
	size_t size = 0;
	int error = PR_GetError(); /* at least 32-bits */
	size += lswlogs(buf, " (");
	/* the number */
	if (IS_SEC_ERROR(error)) {
		size += lswlogf(buf, "SECERR: %d (0x%x): ",
				error - SEC_ERROR_BASE,
				error - SEC_ERROR_BASE);
	} else {
		size += lswlogf(buf, "NSS: %d (0x%x): ", error, error);
	}

	/*
	 * NSPR should contain string tables for all known error
	 * classes.  Query that first.  Should this specify the
	 * english language?
	 */
	const char *text = PR_ErrorToString(error, PR_LANGUAGE_I_DEFAULT);
	if (text != NULL) {
		size += lswlogs(buf, text);
	} else {
		/*
		 * Try NSPR directly, is this redundant?  Sometimes
		 * NSS forgets to set the actual error and this
		 * handles that case.
		 */
		PRInt32 length = PR_GetErrorTextLength();
		if (length != 0) {
			char *text = alloc_things(char, length, "error message");
			PR_GetErrorText(text);
			size += lswlogs(buf, text);
			pfree(text);
		} else {
			size += lswlogs(buf, "unknown error");
		}
	}
	if (error == 0) {
		size += lswlogs(buf, "; 0 indicates NSS lost the error code");
	}
	size += lswlogs(buf, ")");
	return size;
}
