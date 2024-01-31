/* Libreswan IPsec starter (starter.c)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2006-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
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
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>

#include "constants.h"

#include "ipsecconf/starterlog.h"

#define BUFF_SIZE  16384

/**
 * TODO:
 * o use syslog option in config file
 */

static bool log_debugging = false;

static void log_one_line(const char *buff)
{
	fprintf(stderr, "%s\n", buff);
}

void starter_log(int level, const char *fmt, ...)
{
	va_list args;
	char buff[BUFF_SIZE];
	char *b;

	if (!log_debugging && level == LOG_LEVEL_DEBUG)
		return;

	va_start(args, fmt);
	vsnprintf(buff, BUFF_SIZE - 1, fmt, args);
	buff[BUFF_SIZE - 1] = '\0';

	/* log each '\n'-terminated segment separately */
	for (b = buff;;) {
		char *p = strchr(b, '\n');

		if (p == NULL)
			break;
		*p = '\0';
		log_one_line(b);
		b = p + 1;
	}

	/* log the '\0'- terminated segment */
	log_one_line(b);

	va_end(args);
}

void starter_use_log(bool debug)
{
	log_debugging = debug;
	if (log_debugging)
		starter_log(LOG_LEVEL_ERR, "debugging mode enabled");
}
