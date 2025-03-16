/* CRL import helper, for libreswan.
 *
 * Copyright (C) 2015 Matt Rogers <mrogers@libreswan.org>
 * Copyright (C) 2016, Andrew Cagney <cagney@gnu.org>
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

#include <unistd.h>
#include <prlong.h>
#include <secder.h>
#include <errno.h>
#include <secerr.h>
#include <cert.h>
#include <certdb.h>
#include <nss.h>		/* for NSS_Shutdown() */

#include "lswconf.h"
#include "lswnss.h"
#include "lswtool.h"
#include "lswalloc.h"
#include "lswlog.h"		/* for fatal() */

#ifdef __clang__
/*
 * clang complains about these from nss.h, gcc does not?
 */
extern SECStatus NSS_Shutdown(void);
extern SECStatus NSS_InitReadWrite(const char *configdir);
#endif

/*
 * _import_crl <url> <der size>
 * the der blob is passed through STDIN from pluto's fork
 */
int main(int argc, char *argv[])
{
	struct logger *logger = tool_logger(argc, argv);

	if (argc != 3) {
		fatal(PLUTO_EXIT_FAIL, logger, "expecting: <url> <der-size>");
	}

	/* <url */
	const char *url = argv[1];

	/* <der-size> */
	const char *len_str = argv[2];
	char *len_end;
	errno = 0; /* strtol() doesn't clear errno; see "pertinent standards" */
	ssize_t len = strtol(len_str, &len_end, 0);
	if (len_end == len_str) {
		fatal(PLUTO_EXIT_FAIL, logger, "<der-size> is not a number: %s", len_str);
	} else if (*len_end != '\0') {
		fatal(PLUTO_EXIT_FAIL, logger, "<der-size> contains grailing garbage: %s", len_str);
	} else if (errno != 0) {
		fatal_errno(PLUTO_EXIT_FAIL, logger, errno,
			    "<der-size> '%s' is out-of-range", len_str);
	}

	if (len <= 0) {
		fatal(PLUTO_EXIT_FAIL, logger, "<der-size> must be positive: %s", len_str);
	}

	uint8_t *buf = alloc_things(uint8_t, len, "der buf");
	if (buf == NULL)
		exit(-1);

	ssize_t tlen = len;
	uint8_t *tbuf = buf;

	while (tlen > 0) {
		ssize_t rd = read(STDIN_FILENO, buf, len);
		if (rd == 0) {
			/* EOF */
			break;
		}
		if (rd == -1) {
			if (errno == EINTR)
				continue;
			fatal(PLUTO_EXIT_FAIL, logger, "read error");
		}
		tlen -= rd;
		tbuf += rd;
	}

	if ((tbuf - buf) != len) {
		fatal(PLUTO_EXIT_FAIL, logger, "less then %zd bytes read", len);
	}

	const struct lsw_conf_options *oco = lsw_init_options();
	init_nss(oco->nssdir, (struct nss_flags){0}, logger);

	/* should never fail */
	CERTCertDBHandle *handle = CERT_GetDefaultCertDB();
	if (handle == NULL) {
		return PLUTO_EXIT_FAIL;
	}

	SECItem si = {
		.type = siBuffer,
		.data = buf,
		.len = len,
	};

	CERTSignedCrl *crl = CERT_ImportCRL(handle, &si, (char *)url, SEC_CRL_TYPE, NULL);
	if (crl == NULL) {
		llog_nss_error(RC_LOG, logger, "import of CRL failed, ");
		return PLUTO_EXIT_FAIL;
	}

	llog_pem_bytes(RC_LOG|NO_PREFIX, logger, "NAME", crl->crl.derName.data, crl->crl.derName.len);

	pfree(buf);
	SEC_DestroyCrl(crl);
	NSS_Shutdown();

	return 0;
}
