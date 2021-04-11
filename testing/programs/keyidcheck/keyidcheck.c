/* printable key IDs, for libreswan
 *
 * Copyright (C) 2002  Henry Spencer.
 * Copyright (C) 2020  Andrew Cagney
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>		/* for exit() */

#include "keyid.h"
#include "constants.h"		/* for streq() */
#include "lswcdefs.h"		/* for UNUSED */

void regress(void);

static int st;

static void check_keyblob_to_keyid(void)
{
	keyid_t buf;
	char b64nine[] = "AQOF8tZ2m";
	uint8_t hexblob[] = "\x01\x03\x85\xf2\xd6\x76\x9b\x03\x59\xb6\x21\x52";
	err_t e = keyblob_to_keyid(hexblob, sizeof(hexblob) - 1, &buf);
	if (e != NULL) {
		fprintf(stderr, "%s: keyblob_to_keyid returned '%s' not NULL\n",
			__func__, e);
		st += 1;
		return;
	}
	if (!streq(str_keyid(buf), b64nine)) {
		fprintf(stderr, "%s: keyblobtoid generated `%s' not `%s'\n",
			__func__, str_keyid(buf), b64nine);
		st += 1;
		return;
	}
}

static void check_splitkey_to_keyid(void)
{
	keyid_t buf;
	char b64nine[] = "AQOF8tZ2m";
	uint8_t hexe[] = "\x03";
	uint8_t hexm[] = "\x85\xf2\xd6\x76\x9b\x03\x59\xb6\x21\x52\xef\x85";
	err_t e = splitkey_to_keyid(hexe, sizeof(hexe) - 1, hexm, sizeof(hexm) - 1, &buf);
	if (e != NULL) {
		fprintf(stderr, "%s: keyblob_to_keyid returned '%s' not NULL\n",
			__func__, e);
		st += 1;
		return;
	}
	if (!streq(str_keyid(buf), b64nine)) {
		fprintf(stderr, "%s: splitkeytoid generated `%s' not `%s'\n",
			__func__, str_keyid(buf), b64nine);
		st += 1;
		return;
	}
}

int main()
{
	check_keyblob_to_keyid();
	check_splitkey_to_keyid();

	if (st > 0) {
		fprintf(stderr, "%d errors", st);
	}
	exit(st > 0);
}
