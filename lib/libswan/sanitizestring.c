/*
 * sanitize a string into a printable format.
 *
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003  Michael Richardson <mcr@freeswan.org>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/lgpl-2.1.txt>.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Library General Public
 * License for more details.
 */
#include <ctype.h>
#include <string.h>
#include "libreswan.h"
#include "libreswan/passert.h"
#include "constants.h"
#include "lswlog.h"

/*
 * Sanitize character string in situ: turns dangerous characters into \OOO.
 * With a bit of work, we could use simpler reps for \\, \r, etc.,
 * but this is only to protect against something that shouldn't be used.
 * Truncate resulting string to what fits in buffer.
 */
void sanitize_string(char *buf, size_t size)
{
#define UGLY_WIDTH 4	/* width for ugly character: \OOO */
	size_t added = 0;
	char *p;

	passert(size >= UGLY_WIDTH);	/* need room to swing cat */

	/*
	 * find right side of string to be sanitized and count
	 * number of columns to be added.  Stop on end of string
	 * or lack of room for more result.
	 */
	for (p = buf; *p != '\0' && &p[added] < &buf[size - UGLY_WIDTH]; p++) {
		unsigned char c = *p;

		/*
		 * exception is that all veritical space just becomes
		 * white space
		 */
		if (c == '\n' || c == '\r') {
			*p = ' ';
		} else if (c == '\\' || !isprint(c)) {
			added += UGLY_WIDTH - 1;
		}
	}

	/*
	 * at this point, p points after last original character to be
	 * included.  added is how many characters are added to sanitize.
	 * so p[added] will point after last sanitized character.
	 */

	p[added] = '\0';

	/*
	 * scan backwards, copying characters to their new home
	 * and inserting the expansions for ugly characters.
	 *
	 * vertical space is changed to horizontal.
	 *
	 * It is finished when no more shifting is required.
	 * This is a predecrement loop.
	 */
	while (added != 0) {
		char fmtd[UGLY_WIDTH + 1];
		unsigned char c;

		while ((c = *--p) != '\\' && isprint(c))
			p[added] = c;

		added -= UGLY_WIDTH - 1;
		snprintf(fmtd, sizeof(fmtd), "\\%03o", c);
		memcpy(p + added, fmtd, UGLY_WIDTH);
	}

#undef UGLY_WIDTH
}

#ifdef SANITIZESTRING_MAIN

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void regress(void);

void libreswan_passert_fail(const char *pred_str,
			const char *file_str,
			unsigned long line_no)
{
	fprintf(stderr, "Passert failed: %s: %d, %s\n",
		file_str, line_no, pred_str);
	exit(20);
}

void pexpect_log(const char *pred_str,
		const char *file_str, unsigned long line_no)
{
	fprintf(stderr, "Pexpect dismayed: %s: %d, %s\n",
		file_str, line_no, pred_str);
}

void switch_fail(int n,
		const char *file_str, unsigned long line_no)
{
	fprintf(stderr, "switch failed: %s: %d, %s\n",
		file_str, line_no, pred_str);
	exit(20);
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s -r\n", argv[0]);
		exit(2);
	}

	if (streq(argv[1], "-r")) {
		regress();
		fprintf(stderr, "regress() returned?!?\n");
		exit(1);
	}
	exit(0);
}

struct rtab {
	char *input;
	char *output;	/* NULL means error expected */
} rtab[] = {
	{ "there\001 \002 \003\n\rhi", "1.2.3.0" },
	{ "there\231\t\n\177\\\n\rhi", "1.2.3.0" },
	{ "there\001 \002 \003\n\rhi", "1.2.3.0" },
	{ NULL, NULL }
};

void regress(void)
{
	struct rtab *r;
	ip_address a;
	char in[256];
	int count, status;

	count = 0;
	status = 0;

	for (r = rtab; r->input != NULL; r++) {
		strcpy(in, r->input);

		sanitize(in, sizeof(in));

		if (!streq(in, r->output)) {
			printf("Item %d failed; %s vs %s\n",
				count, in, r->output);
			status = 1;
		}
	}
	exit(status);
}

#endif /* SANITIZESTRING_MAIN */
