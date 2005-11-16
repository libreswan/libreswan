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
 *
 * RCSID $Id: defs.c,v 1.30 2004/06/27 22:32:45 mcr Exp $
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>

#include <openswan.h>

#include "constants.h"
#include "openswan/ipsec_policy.h"
#include "defs.h"
#include "log.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */

/* Convert MP_INT to network form (binary octets, big-endian).
 * We do the malloc; caller must eventually do free.
 */
chunk_t
mpz_to_n(const MP_INT *mp, size_t bytes)
{
    chunk_t r;
    MP_INT temp1, temp2;
    int i;

    r.len = bytes;
    r.ptr = alloc_bytes(r.len, "host representation of large integer");

    mpz_init(&temp1);
    mpz_init(&temp2);

    mpz_set(&temp1, mp);

    for (i = r.len-1; i >= 0; i--)
    {
	r.ptr[i] = mpz_mdivmod_ui(&temp2, NULL, &temp1, 1 << BITS_PER_BYTE);
	mpz_set(&temp1, &temp2);
    }

    passert(mpz_sgn(&temp1) == 0);	/* we must have done all the bits */
    mpz_clear(&temp1);
    mpz_clear(&temp2);

    return r;
}

/* Convert network form (binary bytes, big-endian) to MP_INT.
 * The *mp must not be previously mpz_inited.
 */
void
n_to_mpz(MP_INT *mp, const u_char *nbytes, size_t nlen)
{
    size_t i;

    mpz_init_set_ui(mp, 0);

    for (i = 0; i != nlen; i++)
    {
	mpz_mul_ui(mp, mp, 1 << BITS_PER_BYTE);
	mpz_add_ui(mp, mp, nbytes[i]);
    }
}

/* Names of the months */

static const char* months[] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};


/*
 *  Display a date either in local or UTC time
 */
char *
timetoa(const time_t *time, bool utc, char *b, size_t blen)
{
    if (*time == UNDEFINED_TIME)
	snprintf(b, blen, "--- -- --:--:--%s----", (utc)?" UTC ":" ");
    else
    {
	struct tm *t = (utc)? gmtime(time) : localtime(time);

	snprintf(b, blen, "%s %02d %02d:%02d:%02d%s%04d",
	    months[t->tm_mon], t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec,
	    (utc)?" UTC ":" ", t->tm_year + 1900
	);
    }
    return b;
}

/*  checks if the expiration date has been reached and
 *  warns during the warning_interval of the imminent
 *  expiry. strict=TRUE declares a fatal error,
 *  strict=FALSE issues a warning upon expiry.
 */
const char*
check_expiry(time_t expiration_date, int warning_interval, bool strict)
{
    time_t now;
    int time_left;

    if (expiration_date == UNDEFINED_TIME)
      return "ok (expires never)";

    /* determine the current time */
    time(&now);

    time_left = (expiration_date - now);
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


/*
 * Filter eliminating the directory entries starting with .,
 * and also "CVS" (thus eliminating '.' and '..')
 */
int
file_select(const struct dirent *entry)
{
  return (entry->d_name[0] != '.' &&
	  strcmp(entry->d_name, "CVS")!=0 &&
	  strcmp(entry->d_name, "RCS")!=0);
	  
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */

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

