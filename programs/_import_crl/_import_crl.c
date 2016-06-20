/* CRL import helper, for libreswan.
 *
 * Copyright (C) 2015 Matt Rogers <mrogers@libreswan.org>
 * Copyright (C) 2016, Andrew Cagney <cagney@gnu.org>
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
 */

#include <unistd.h>
#include <libreswan.h>
#include "lswconf.h"
#include "lswnss.h"
#include <prlong.h>
#include <secder.h>
#include <errno.h>
#include <nss.h>
#include <secerr.h>
#include <cert.h>
#include <certdb.h>
#ifdef __clang__
/*
 * clang complains about these from nss.h, gcc does not?
 */
extern SECStatus NSS_Shutdown(void);
extern SECStatus NSS_InitReadWrite(const char *configdir);
#endif
/*
 * not needed here, but squelch a lswconf.h build error
 */
char *progname;

static int import_crl(const char *url, unsigned char *buf, size_t len)
{
	CERTSignedCrl *crl = NULL;
	SECItem si = {siBuffer, NULL, 0};
	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();

	if (handle == NULL)
		return -1;

	si.data = buf;
	si.len = len;

	if ((crl = CERT_ImportCRL(handle, &si, (char *)url, SEC_CRL_TYPE,
							NULL)) == NULL) {
		return PORT_GetError();
	}

	SEC_DestroyCrl(crl);
	return 0;
}

/*
 * _import_crl <url> <der size>
 * the der blob is passed through STDIN from pluto's fork
 */
int main(int argc, char *argv[])
{

	char *url, *lenstr;
	unsigned char *buf, *tbuf;
	size_t len, tlen;
	ssize_t rd;
	int fin;

	if (argc != 3)
		exit(-1);

	progname = argv[0];
	url = argv[1];
	lenstr = argv[2];

	/* can't be 0 */
	if (*lenstr == '0' && strlen(lenstr) == 1)
		exit(-1);

	while (*lenstr != '\0') {
		if (!isalnum(*lenstr++)) {
			exit(-1);
		}
	}

	tlen = len = (size_t) atoi(argv[2]);
	tbuf = buf = (unsigned char *) malloc(len);

	if (tbuf == NULL)
		exit(-1);

	while (tlen != 0 && (rd = read(STDIN_FILENO, buf, len)) != 0) {
		if (rd == -1) {
			if (errno == EINTR)
				continue;
			exit(-1);
		}
		tlen -= rd;
		buf += rd;
	}

	if ((size_t)(buf - tbuf) != len)
		exit(-1);

	const struct lsw_conf_options *oco = lsw_init_options();
	lsw_nss_buf_t err;
	if (!lsw_nss_setup(oco->nssdb, 0, lsw_nss_get_password, err)) {
		fprintf(stderr, "%s: %s\n", progname, err);
		exit(1);
	}

	fin = import_crl(url, tbuf, len);

	if (tbuf != NULL)
		free(tbuf);

	NSS_Shutdown();

	return fin;
}
