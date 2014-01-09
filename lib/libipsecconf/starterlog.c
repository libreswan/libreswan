/* FreeS/WAN IPsec starter (starter.c)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2006-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
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
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <syslog.h>

#include "libreswan.h"
#include "constants.h"

#include "ipsecconf/starterlog.h"

#define BUFF_SIZE  16384

/**
 * TODO:
 * o use syslog option in config file
 */

static bool log_debugging = FALSE;
static bool log_to_console = FALSE;
static bool log_to_syslog = FALSE;

static void do_print_info(int level, const char *buff)
{
	if ((!log_debugging) && (level == LOG_LEVEL_DEBUG))
		return;

	if (log_to_console)
		fprintf(stderr, "%s\n", buff);
	if (log_to_syslog) {
		if (level == LOG_LEVEL_ERR)
			syslog(LOG_ERR, "%s\n", buff);
		else
			syslog(LOG_INFO, "%s\n", buff);
	}
}

static void log_info_multiline(int level, const char *buff)
{
	char *copy, *b, *ptr, *end;

	if (!buff)
		return;

	if ((!log_debugging) && (level == LOG_LEVEL_DEBUG))
		return;

	copy = strdup(buff);
	if (!copy)
		return;

	end = copy + strlen(copy);
	for (ptr = copy, b = copy; ptr <= end; ptr++) {
		if (*ptr == '\n')
			*ptr = '\0';
		if (*ptr == '\0') {
			if (b != end)
				do_print_info(level, b);
			b = ptr + 1;
		}
	}
	free(copy);
}

void starter_log(int level, const char *fmt, ...)
{
	va_list args;
	static char buff[BUFF_SIZE];

	if ((!log_debugging) && (level == LOG_LEVEL_DEBUG))
		return;

	va_start(args, fmt);
	vsnprintf(buff, BUFF_SIZE - 1, fmt, args);
	buff[BUFF_SIZE - 1] = '\0';
	log_info_multiline(level, buff);
	va_end(args);
}

void starter_use_log(bool debug, bool console, bool mysyslog)
{
	log_debugging = debug;
	log_to_console = console;
	if (mysyslog != log_to_syslog) {
		if (mysyslog)
			openlog("ipsec_starter", LOG_PID, LOG_USER);
		else
			closelog();
		log_to_syslog = mysyslog;
	}
	if (log_debugging)
		starter_log(LOG_LEVEL_ERR, "debugging mode enabled\n");
}
