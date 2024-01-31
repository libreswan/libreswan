/* Libreswan command interface to Pluto
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2004-2006  Michael Richardson <mcr@xelerance.com>
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
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <assert.h>
#include <stdarg.h>

#include "sysdep.h"
#include "constants.h"
#include "lswalloc.h"
#include "lswlog.h"
#include "whack.h"
#include "lswlog.h"
#include "ip_info.h"

void clear_end(const char *leftright, struct whack_end *e)
{
	static const struct whack_end zero_end;	/* zeros and NULL pointers */
	*e = zero_end;
	e->leftright = leftright;
}

int whack_get_value(char *buf, size_t bufsize)
{
	int len;
	int try;

	fflush(stdout);

	try = 3;
	len = 0;
	while (try > 0 && len == 0) {
		fprintf(stderr, "Enter username:   ");

		memset(buf, 0, bufsize);

		if (fgets(buf, bufsize, stdin) != buf) {
			if (errno == 0) {
				fprintf(stderr,
					"Cannot read username from standard in\n");
				exit(RC_WHACK_PROBLEM);
			} else {
				perror("fgets value");
				exit(RC_WHACK_PROBLEM);
			}
		}

		/* send the value to pluto, including \0, but fgets adds \n */
		len = strlen(buf);
		if (len == 0)
			fprintf(stderr, "answer was empty, retry\n");

		try--;
	}

	if (len ==  0)
		exit(RC_WHACK_PROBLEM);

	return len;
}

/* Get password from user.  Truncate it to fit in buf. */
/* ??? the function getpass(3) is obsolete! */
size_t whack_get_secret(char *buf, size_t bufsize)
{
	fflush(stdout);
	assert(bufsize > 0);	/* room for terminal NUL */

	char *secret = getpass("Enter passphrase: ");
	/* jam_str would be good but it requires too much library */
	size_t len = strlen(secret) + 1;
	size_t trunc_len = len <= bufsize ? len : bufsize;

	memcpy(buf, secret, trunc_len);
	buf[trunc_len-1] = '\0';	/* force NUL termination */
	memset(secret, 0, len);	/* scrub secret from RAM */
	return trunc_len;
}
