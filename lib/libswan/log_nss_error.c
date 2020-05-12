/* Output an (NS)PR error, for libreswan
 *
 * Copyright (C) 2020 Andrew Cagney
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
#include <stdarg.h>

#include <prerror.h>
#include <secerr.h>

#include "lswlog.h"
#include "lswalloc.h"
#include "lswnss.h"

/*
 * See https://bugzilla.mozilla.org/show_bug.cgi?id=172051
 */

void log_nss_error(lset_t rc_flags, struct logger *logger,
		   PRErrorCode error, const char *message, ...)
{
	LOG_MESSAGE(rc_flags, logger, buf) {
		jam(buf, "NSS: ");
		/* text */
		va_list ap;
		va_start(ap, message);
		jam_va_list(buf, message, ap);
		va_end(ap);
		jam(buf, ": ");
		if (error != 0) {
			/* error, numeric */
			if (IS_SEC_ERROR(error)) {
				jam(buf, "SECERR: %ld (0x%lx): ",
				    (long)(error - SEC_ERROR_BASE),
				    (long)(error - SEC_ERROR_BASE));
			} else {
				jam(buf, "Error: %ld (0x%lx): ",
				    (long)error,
				    (long)error);
			}
			/*
			 * NSPR should contain string tables for all known
			 * error classes.  Query that first.  Should this
			 * specify the english language?
			 */
			const char *text = PR_ErrorToString(error, PR_LANGUAGE_I_DEFAULT);
			if (text != NULL) {
				jam_string(buf, text);
			} else {
				jam(buf, "unknown error");
			}
		} else {
			jam(buf, " error code not saved by NSS");
		}
	}
}
