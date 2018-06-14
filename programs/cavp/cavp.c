/* Parse CAVP test vectors, for libreswan (CAVP)
 *
 * Copyright (C) 2015-2018, Andrew Cagney
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

#include <stdio.h>

#include "lswtool.h"
#include "lswfips.h"
#include "lswnss.h"
#include "ike_alg.h"

#include "cavp.h"
#include "cavps.h"
#include "cavp_parser.h"

static void usage(void)
{
	fprintf(stderr, "Usage:\n\n");
	fprintf(stderr, "    cavp [ -TEST ] <test-vector>|-\n\n");
	fprintf(stderr, "Where -TEST specifies the test type:\n\n");
	for (struct cavp **cavpp = cavps; *cavpp != NULL; cavpp++) {
		fprintf(stderr, "    -%-8s %s\n",
			(*cavpp)->alias,
			(*cavpp)->description);
	}
	fprintf(stderr, "\n");
	fprintf(stderr, "If -TEST is omitted then the test type is determined from the\n");
	fprintf(stderr, "file header by matching one of the patterns:\n\n");
	for (struct cavp **cavpp = cavps; *cavpp != NULL; cavpp++) {
		const char *sep = (*cavpp)->alias;
		for (const char **matchp = (*cavpp)->match; *matchp; matchp++) {
			fprintf(stderr, "    %-8s  '%s'\n", sep, *matchp);
			sep = "";
		}
	}
}

int main(int argc, char *argv[])
{
	tool_init_log(argv[0]);

	if (argc <= 1) {
		usage();
		exit(1);
	}
	char **argp = argv + 1;

	/* a -XXX option? */
	struct cavp *cavp = NULL;
	while ((*argp)[0] == '-') {
		if (strcmp(*argp, "--") == 0) {
			argp++;
			break;
		} else if (strcmp(*argp, "-fips") == 0) {
			argp++;
			lsw_set_fips_mode(LSW_FIPS_ON);
		} else {
			struct cavp **cavpp;
			for (cavpp = cavps; *cavpp != NULL; cavpp++) {
				if (strcmp(argv[1]+1, (*cavpp)->alias) == 0) {
					cavp = *cavpp;
					fprintf(stderr, "test: %s\n", cavp->description);
					break;
				}
			}
			if (cavp == NULL) {
				fprintf(stderr, "Unknown test %s\n", argv[1]);
				usage();
				exit(1);
			}
			argp++;
		}
	}
	if (cavp == NULL) {
		fprintf(stderr, "Guessing test type ...\n");
	}

	if (*argp == NULL) {
		fprintf(stderr, "missing test file\n");
		usage();
		exit(1);
	}
	if (strcmp(*argp, "-") == 0) {
		fprintf(stderr, "Reading from stdin\n");
	} else {
		fprintf(stderr, "reading from %s\n", *argp);
		if (freopen(*argp, "r", stdin) == NULL) {
			perror("freopen");
			exit(1);
		}
	}
	argp++;

	if (*argp != NULL) {
		fprintf(stderr, "unexpected %s", *argp);
		usage();
		exit(1);
	}

	setbuf(stdout, NULL);

	lsw_nss_buf_t err;
	if (!lsw_nss_setup(NULL, 0, NULL, err)) {
		fprintf(stderr, "unexpected %s\n", err);
		exit(1);
	}

	init_ike_alg();

	cavp_parser(cavp);

	lsw_nss_shutdown();
	exit(0);
}
