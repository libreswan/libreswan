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
#include "rcv_whack.h"

#include "readwhackmsg.h"

/* readwhackmsg must match writewhackrecord */

void readwhackmsg(char *infile)
{
	FILE *record = fopen(infile, "r");

	if (record == NULL) {
		perror(infile);
		exit(9);
	}

	/* log the first line: it's a comment */
	{
		char b1[8192];

		if (fgets(b1, sizeof(b1), record) == NULL)
			DBG(DBG_PARSING, DBG_log("readwhackmsg: fgets returned NULL"));

		printf("Pre-amble: %s", b1);
	}

	uint32_t header[3];	/* length, high time, low time */

	while (fread(header, sizeof(header), 1, record) != 1) {
		size_t buflen = header[0] - sizeof(header);
		struct whackpacker wp;
		struct whack_message m1;

		/* round up */
		size_t abuflen = (buflen + sizeof(header[0]) - 1) & ~(sizeof(header[0]) - 1);

		if (abuflen > sizeof(m1) || abuflen < buflen) {
			fprintf(stderr,
				"whackmsg file record too big: %zu > %zu\n",
				abuflen, sizeof(m1));
			exit(6);
		}

		if (fread(&m1, abuflen, 1, record) != 1)
			break;

		if (abuflen == sizeof(uint32_t) &&
		    *(uint32_t *)&m1 == WHACK_BASIC_MAGIC)
		{
			/* ignore initial WHACK_BASIC_MAGIC message */
			continue;
		}

		wp.msg = &m1;
		wp.n = buflen;
		wp.str_next = m1.string;
		wp.str_roof = (unsigned char *)&m1 + buflen;

		err_t ugh = unpack_whack_msg(&wp);
		if (ugh != NULL) {
			fprintf(stderr, "failed to parse whack msg: %s\n",
				ugh);
			exit(7);
		}

		/*
		 * okay, we have buflen bytes in b1, so turn it into a whack
		 * message, and call whack_handle.
		 */
		whack_process(null_fd, &m1);
	}

	if (ferror(record)) {
		perror(infile);
		exit(5);
	}

	fclose(record);
}
