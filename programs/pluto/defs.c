/* misc. universal things
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "libreswan/ipsec_policy.h"
#include "lswtime.h"
#include "defs.h"
#include "log.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */

/*  checks if the expiration date has been reached and
 *  warns during the warning_interval of the imminent
 *  expiry. strict=TRUE declares a fatal error,
 *  strict=FALSE issues a warning upon expiry.
 */
const char*
check_expiry(time_t expiration_date, int warning_interval, bool strict)
{
    time_t tnow;
    int time_left;

    if (expiration_date == UNDEFINED_TIME)
      return "ok (expires never)";

    /* determine the current time */
    time(&tnow);

    time_left = (expiration_date - tnow);
    if (time_left < 0)
	return strict? "fatal (expired)" : "warning (expired)";

    if (time_left > 86400*warning_interval)
	return "ok";
    {
	static char buf[35]; /* temporary storage */
	const char* unit = "second";

	if (time_left > 172800)
	{
	    time_left /= 86400;
	    unit = "day";
	}
	else if (time_left > 7200)
	{
	    time_left /= 3600;
	    unit = "hour";
	}
	else if (time_left > 120)
	{
	    time_left /= 60;
	    unit = "minute";
	}
	snprintf(buf, 35, "warning (expires in %d %s%s)", time_left,
		 unit, (time_left == 1)?"":"s");
	return buf;
    }
}


/*  compare two chunks, returns zero if a equals b
 *  negative/positive if a is earlier/later in the alphabet than b
 */
bool
cmp_chunk(chunk_t a, chunk_t b)
{
    int cmp_len, len, cmp_value;
    
    cmp_len = a.len - b.len;
    len = (cmp_len < 0)? a.len : b.len;
    cmp_value = memcmp(a.ptr, b.ptr, len);

    return (cmp_value == 0)? cmp_len : cmp_value;
};

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
