/* Read Whack Message
 * Header: readwhackmsg.h
 *
 * This is only used for test cases in lib/cryto and formerly liblibpluto
 *
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include "constants.h"
#include "lswalloc.h"
#include "whack.h"
#include "lswlog.h"

#include "readwhackmsg.h"

void readwhackmsg(char *infile)
{
	int iocount;
	FILE *record;
	char b1[8192];
	u_int32_t plen;

	if ((record = fopen(infile, "r")) == NULL) {
		perror(infile);
		exit(9);
	}

	/* okay, eat first line, it's a comment, but log it. */
	if (fgets(b1, sizeof(b1), record) == NULL)
		DBG(DBG_PARSING, DBG_log("readwhackmsg: fgets returned NULL"));


	printf("Pre-amble: %s", b1);

	plen = 0;
	while ((iocount = fread(&plen, 4, 1, record)) == 1) {
		u_int32_t a[2];
		err_t ugh = NULL;
		struct whackpacker wp;
		struct whack_message m1;
		size_t abuflen;

		if (fread(&a, 4, 2, record) == 0) /* eat time stamp */
			DBG(DBG_PARSING,
			    DBG_log("readwhackmsg: fread returned 0"));

		/* account for this header we just consumed */
		plen -= 12;

		/* round up to multiple of 4 */
		abuflen = (plen + 3) & ~0x3;

		if (abuflen > sizeof(m1) || abuflen < plen) {
			fprintf(stderr,
				"whackmsg file has too big a record=%zu > %zu\n",
				abuflen, sizeof(m1));
			fclose(record);
			exit(6);
		}

		if ((iocount = fread(&m1, abuflen, 1, record)) != 1) {
			if (feof(record))
				break;
			perror(infile);
			fclose(record);
			exit(5);
		}

		if (plen <= 4) {
			/* empty message */
			continue;
		}

		wp.msg = &m1;
		wp.n   = plen;
		wp.str_next = m1.string;
		wp.str_roof = (unsigned char *)&m1 + plen;

		if ((ugh = unpack_whack_msg(&wp)) != NULL) {
			fprintf(stderr, "failed to parse whack msg: %s\n",
				ugh);
			continue;
		}

		m1.keyval.ptr = wp.str_next; /* grab chunk */

		/*
		 * okay, we have plen bytes in b1, so turn it into a whack
		 * message, and call whack_handle.
		 */
		whack_process(NULL_FD, m1);
	}

	if (iocount != 0 || !feof(record)) {
		fclose(record);
		perror(infile);
	}
}
