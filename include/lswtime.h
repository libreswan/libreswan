/* time related functions
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
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

#ifndef _LSWTIME_H_
#define _LSWTIME_H_

extern time_t now(void);        /* careful version of time(2) */

/* no time defined in time_t */
#define UNDEFINED_TIME  0

/* size of timetoa string buffer */
#define TIMETOA_BUF     30

/* display a date either in local or UTC time */
extern char* timetoa(const time_t *timep, bool utc, char *buf, size_t blen);

#endif

