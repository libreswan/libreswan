/* Output an (NS)PR error, for libreswan
 *
 * Copyright (C) 2017 Andrew Cagney
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
 *
 */

#include <stdio.h>
#include <stdarg.h>

#include <prerror.h>

#include "lswlog.h"
#include "lswalloc.h"

size_t lswlog_pr_error(struct lswlog *buf)
{
	PRInt32 length = PR_GetErrorTextLength();
	int error = PR_GetError(); /* at least 32-bits */
	if (length == 0) {
		/*
		 * NSS sometimes forgets to set the error and/or text?
		 */
		return lswlogf(buf, "unknown error (%d 0x%x)", error, error);
	} else {
		char *text = alloc_things(char, length, "error message");
		PR_GetErrorText(text);
		size_t size = lswlogf(buf, "%s (%d 0x%x)", text, error, error);
		pfree(text);
		return size;
	}
}
