/* misc. universal things
 * Header: "defs.h"
 *
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2014  D. Hugh Redelmeier.
 * Copyright (C) 2015  Paul Wouters
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

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>


#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "log.h"
#include "whack.h"      /* for RC_LOG */

bool all_zero(const unsigned char *m, size_t len)
{
	size_t i;

	for (i = 0; i != len; i++)
		if (m[i] != '\0')
			return false;

	return true;
}
