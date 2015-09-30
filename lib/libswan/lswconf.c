/*
 * misc functions to get compile time and runtime options
 *
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
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

#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include "lswlog.h"
#include "lswconf.h"
#include "lswalloc.h"

#include <errno.h>

#include <string.h>
#include <nss.h>
#include <nspr.h>
#include <pk11pub.h>

static struct lsw_conf_options global_oco;
static bool setup = FALSE;

#define NSSpwdfilesize 4096
static secuPWData NSSPassword;

#ifdef SINGLE_CONF_DIR
#define SUBDIRNAME(X) ""
#else
#define SUBDIRNAME(X) X
#endif

static void lsw_conf_calculate(struct lsw_conf_options *oco)
{
	char buf[PATH_MAX];

	/* will be phased out for NSS in the near future */
	snprintf(buf, sizeof(buf), "%s" SUBDIRNAME("/cacerts"), oco->confddir);
	oco->cacerts_dir = clone_str(buf, "cacert path");

	snprintf(buf, sizeof(buf), "%s" SUBDIRNAME("/crls"), oco->confddir);
	oco->crls_dir = clone_str(buf, "crls path");

	/* old OE policies - might get re-used in the near future */
	snprintf(buf, sizeof(buf), "%s/policies", oco->confddir);
	oco->policies_dir = clone_str(buf, "policies path");
}

static void lsw_conf_setdefault(void)
{
	char buf[PATH_MAX];
	static const struct lsw_conf_options zero_oco;	/* full of null pointers */

	global_oco = zero_oco;

	/* allocate them all to make it consistent */
	global_oco.rootdir = clone_str("","rootdir");
	global_oco.confddir = clone_str(IPSEC_CONFDDIR, "default conf ipsecd_dir");
	global_oco.vardir  = clone_str(IPSEC_VARDIR, "default vardir");
	global_oco.confdir = clone_str(IPSEC_CONFDIR, "default conf ipsec_conf_dir");
	global_oco.conffile = clone_str(IPSEC_CONF, "default conf conffile");
	global_oco.nssdir = clone_str(IPSEC_NSSDIR, "default nssdir");

	/* path to NSS password file */
	snprintf(buf, sizeof(buf), "%s/nsspassword", global_oco.confddir);
	NSSPassword.data = clone_str(buf, "nss password file path");
	NSSPassword.source =  PW_FROMFILE;
}

void lsw_conf_free_oco(void)
{
	/* Must be a nicer way to loop over this? */
	pfree(global_oco.rootdir);
	pfree(global_oco.confdir);
	pfree(global_oco.conffile);
	pfree(global_oco.confddir);
	pfree(global_oco.vardir);
	pfree(global_oco.policies_dir);
	pfree(global_oco.cacerts_dir);
	pfree(global_oco.crls_dir);
	pfree(global_oco.nssdir);
	pfree(NSSPassword.data);
}

const struct lsw_conf_options *lsw_init_options(void)
{
	if (!setup) {
		setup = TRUE;

		lsw_conf_setdefault();
		lsw_conf_calculate(&global_oco);
	}

	return &global_oco;
}

/* This is only used in testing/crypto (and formerly in testing/lib/libpluto) */
void lsw_init_rootdir(const char *root_dir)
{
	if (!setup)
		lsw_conf_setdefault();
	pfreeany(global_oco.rootdir);
	global_oco.rootdir = clone_str(root_dir, "override /");
	lsw_conf_calculate(&global_oco);
	setup = TRUE;
}

void lsw_init_ipsecdir(const char *ipsec_dir)
{
	if (!setup)
		lsw_conf_setdefault();
	global_oco.confddir = clone_str(ipsec_dir, "override ipsec.d");
	global_oco.nssdir = clone_str(ipsec_dir, "override nssdir");
	lsw_conf_calculate(&global_oco);
	setup = TRUE;

	libreswan_log("adjusting ipsec.d to %s", global_oco.confddir);
}

secuPWData *lsw_return_nss_password_file_info(void)
{
	return &NSSPassword;
}

/*
 * 0 disabled
 * 1 enabled
 * 2 indeterminate
 */
int libreswan_selinux(void)
{
	char selinux_flag[1];
	int n;
	FILE *fd = fopen("/sys/fs/selinux/enforce","r");

	if (fd == NULL) {
		/* try new location first, then old location */
		fd = fopen("/selinux/enforce","r");
		if (fd == NULL) {
			DBG(DBG_CONTROL,
				DBG_log("SElinux: disabled, could not open /sys/fs/selinux/enforce or /selinux/enforce");
				);
			return 0;
		}
	}

	n = fread((void *)selinux_flag, 1, 1, fd);
	fclose(fd);
	if (n != 1) {
		libreswan_log("SElinux: could not read 1 byte from the selinux enforce file");
		return 2;
	}
	if (selinux_flag[0] == '1')
		return 1;
	else
		return 0;

}

#ifdef FIPS_CHECK
/*
 * Is the machine running in FIPS kernel mode (fips=1 kernel argument)
 * yes (1), no (0), unknown(-1)
 */
int libreswan_fipskernel(void)
{
	char fips_flag[1];
	int n;
	FILE *fd = fopen("/proc/sys/crypto/fips_enabled", "r");

	if (fd == NULL) {
		DBG(DBG_CONTROL,
			DBG_log("FIPS: could not open /proc/sys/crypto/fips_enabled");
			);
		return 0;
	}

	n = fread((void *)fips_flag, 1, 1, fd);
	fclose(fd);
	if (n != 1) {
		loglog(RC_LOG_SERIOUS,
			"FIPS: could not read 1 byte from /proc/sys/crypto/fips_enabled");
		return -1;
	}

	if (fips_flag[0] == '1')
		return 1;

	return 0;
}

/*
 * Return TRUE if we are a fips product.
 * This is irrespective of whether we are running in FIPS mode
 * yes (1), no (0), unknown(-1)
 */
int
libreswan_fipsproduct(void)
{
	if (access(FIPSPRODUCTCHECK, F_OK) != 0) {
		if (errno == ENOENT || errno == ENOTDIR) {
			return 0;
		} else {
			loglog(RC_LOG_SERIOUS,
				"FIPS ABORT: FIPS product check failed to determine status for %s: %d: %s",
				FIPSPRODUCTCHECK, errno, strerror(errno));
			return -1;
		}
	}

	return 1;

}

/*
 * Is the machine running in FIPS mode (fips product AND fips kernel mode)
 * yes (1), no (0), unknown(-1)
 * Only pluto needs to know -1, so it can abort. Every other caller can
 * just check for fips mode using: if (libreswan_fipsmode())
 */
int
libreswan_fipsmode(void)
{
	int product = libreswan_fipsproduct();
	int kernel = libreswan_fipskernel();

	if (product == -1 || kernel == -1)
		return -1;

	if (product && kernel)
		return 1;

	return 0;
}
#endif

char *getNSSPassword(PK11SlotInfo *slot, PRBool retry, void *arg)
{
	secuPWData *pwdInfo = (secuPWData *)arg;
	PRFileDesc *fd;
	PRInt32 nb;	/* number of bytes */
	char *token;
	int toklen;
	const long maxPwdFileSize = NSSpwdfilesize;
	int i;

	if (slot == NULL)
		return NULL;

	if (pwdInfo == NULL)
		return NULL;

	token = PK11_GetTokenName(slot);
	if (token == NULL)
		return NULL;

	toklen = PORT_Strlen(token);

	/* Start all log messages with "NSS Password ..."! */
	DBG(DBG_CRYPT, DBG_log("NSS Password for token '%s' required", token));

	if (retry)
		return NULL;

	if (pwdInfo->source != PW_FROMFILE) {
		libreswan_log("NSS Password source is not a file");
		return NULL;
	}

	if (pwdInfo->data == NULL) {
		libreswan_log("NSS Password file name not provided");
		return NULL;
	}

	char *strings = PORT_ZAlloc(maxPwdFileSize);
	if (strings == NULL) {
		libreswan_log("NSS Password file could not be loaded, NSS memory allocate failed");
		return NULL;
	}

	/* From here on, every return must be preceded by PORT_Free(strings) */

	fd = PR_Open(pwdInfo->data, PR_RDONLY, 0);
	if (fd == NULL) {
		libreswan_log("NSS Password file \"%s\" could not be opened for reading",
			      pwdInfo->data);
		PORT_Free(strings);
		return NULL;
	}

	nb = PR_Read(fd, strings, maxPwdFileSize);
	PR_Close(fd);

	for (i = 0; i < nb; ) {
		/*
		 * examine a line of the password file
		 * token_name:password
		 */
		int start = i;
		char *p;
		int linelen;

		/* find end of line */
		while (i < nb &&
		       (strings[i] != '\0' &&
			strings[i] != '\r' &&
			strings[i] != '\n'))
			i++;

		if (i == nb) {
			libreswan_log("NSS Password file ends with a partial line (ignored)");
			break;	/* no match found */
		}

		linelen = i - start;

		/* turn delimiter into NUL and skip over it */
		strings[i++] = '\0';

		p = &strings[start];

		if (linelen >= toklen + 1 &&
		    PORT_Strncmp(p, token, toklen) == 0 &&
		    p[toklen] == ':') {
			/* we have a winner! */
			p = PORT_Strdup(&p[toklen + 1]);
			DBG(DBG_PRIVATE, DBG_log(
				"Password passed to NSS is %s with length %zu",
				 p, PORT_Strlen(p)));
			PORT_Free(strings);
			return p;
		}
	}

	/* no match found in password file */
	libreswan_log("NSS Password file \"%s\" does not contain token '%s'",
		      pwdInfo->data, token);
	PORT_Free(strings);
	return NULL;
}
