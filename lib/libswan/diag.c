/*
 * Diagnostic builder
 * Copyright (C) 1998-2003  D. Hugh Redelmeier
 * Copyright (C) 2004       Michael Richardson <mcr@xelerance.com>
 *
 * alg_info.c,v 1.1.2.1 2003/11/21 18:12:23 jjo Exp
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
#include <stdarg.h>

#include <libreswan.h>

#include "constants.h"
#include "lswlog.h"

/*
 * Build up a diagnostic in a static buffer -- NOT RE-ENTRANT.
 *
 * Although this would be a generally useful function, it is very
 * hard to come up with a discipline that prevents different uses
 * from interfering.  It is intended that by limiting it to building
 * diagnostics, we will avoid this problem.
 * Juggling is performed to allow an argument to be a previous
 * result: the new string may safely depend on the old one.  This
 * restriction is not checked in any way: violators will produce
 * confusing results (without crashing!).
 *
 * @param fmt String format
 * @param ... strings
 * @return err_t
 */
err_t builddiag(const char *fmt, ...)
{
	/* longer messages will be truncated */
	static char mydiag_space[LOG_WIDTH];
	char t[sizeof(mydiag_space)];	/* build result here first */
	va_list args;
	va_start(args, fmt);
	t[0] = '\0';	/* in case nothing terminates string */
	vsnprintf(t, sizeof(t), fmt, args);
	va_end(args);
	strcpy(mydiag_space, t);
	return mydiag_space;
}
