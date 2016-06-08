/*
 * misc functions to get compile time and runtime options
 *
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Tuomo Soini <tis@foobar.fi>
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

#define NSSpwdfilesize 4096
static secuPWData NSSPassword;

#ifdef SINGLE_CONF_DIR
#define SUBDIRNAME(X) ""
#else
#define SUBDIRNAME(X) X
#endif

/*
 * Fill in the basics, return true, of lsw_conf_calculate should be
 * called.
 */
static bool lsw_conf_setdefault(void)
{
	if (global_oco.rootdir != NULL) {
		return FALSE;
	}

	/* copy everything to the heap for consistency. */
	global_oco.rootdir = clone_str("","rootdir");

	global_oco.confdir = clone_str(IPSEC_CONFDIR, "default conf ipsec_conf_dir");
	global_oco.conffile = clone_str(IPSEC_CONF, "default conf conffile");
	global_oco.secretsfile = clone_str(IPSEC_SECRETS_FILE, "default ipsec.secrets");

	global_oco.vardir  = clone_str(IPSEC_VARDIR, "default vardir");

	global_oco.confddir = clone_str(IPSEC_CONFDDIR, "default conf ipsecd_dir");

	global_oco.nssdb = clone_str(IPSEC_NSSDIR, "default nssdb");

	/* see also lsw_conf_calculate() below */
	return TRUE;
}

static void subst(char **field, const char *value, const char *name)
{
	pfreeany(*field);
	*field = clone_str(value, name);
}

/*
 * Some things are rooted under CONFDDIR, re-compute them.
 */
static void lsw_conf_calculate(void)
{
	char buf[PATH_MAX];

	/* will be phased out for NSS in the near future */
	snprintf(buf, sizeof(buf), "%s" SUBDIRNAME("/cacerts"), global_oco.confddir);
	subst(&global_oco.cacerts_dir, buf, "cacert path");

	snprintf(buf, sizeof(buf), "%s" SUBDIRNAME("/crls"), global_oco.confddir);
	subst(&global_oco.crls_dir, buf, "crls path");

	/* old OE policies - might get re-used in the near future */
	snprintf(buf, sizeof(buf), "%s/policies", global_oco.confddir);
	subst(&global_oco.policies_dir, buf, "policies path");

	snprintf(buf, sizeof(buf), "%s/nsspassword", global_oco.confddir);
	subst(&global_oco.nsspassword_file, buf, "nsspassword file");
}

void lsw_conf_free_oco(void)
{
	/*
	 * Must be a nicer way to loop over this?
	 *
	 * for (char *p = (char*)&global_oco; p < (char*)(&global_oco + 1); p++)
	 */
	pfreeany(global_oco.rootdir);

	pfreeany(global_oco.confdir);
	pfreeany(global_oco.conffile);
	pfreeany(global_oco.secretsfile);

	pfreeany(global_oco.vardir);

	pfreeany(global_oco.confddir);
	pfreeany(global_oco.policies_dir);
	pfreeany(global_oco.cacerts_dir);
	pfreeany(global_oco.crls_dir);
	pfreeany(global_oco.nsspassword_file);
	pfreeany(global_oco.nsspassword);

	pfreeany(global_oco.nssdb);

	global_oco = (struct lsw_conf_options) {0};
}

const struct lsw_conf_options *lsw_init_options(void)
{
	if (lsw_conf_setdefault()) {
		lsw_conf_calculate();
	}
	return &global_oco;
}

/* This is only used in testing/crypto (and formerly in testing/lib/libpluto) */
void lsw_conf_rootdir(const char *root_dir)
{
	lsw_conf_setdefault();
	subst(&global_oco.rootdir, root_dir, "override /");
	lsw_conf_calculate();
}

void lsw_conf_confddir(const char *confddir)
{
	lsw_conf_setdefault();
	subst(&global_oco.confddir, confddir, "override ipsec.d");
	lsw_conf_calculate();

	libreswan_log("adjusting ipsec.d to %s", global_oco.confddir);
}

void lsw_conf_nssdb(const char *nssdb)
{
	lsw_conf_setdefault();
	subst(&global_oco.nssdb, nssdb, "override nssdir");
	lsw_conf_calculate();

	libreswan_log("adjusting nssdb to %s", global_oco.confddir);
}

void lsw_init_ipsecdir(const char *confddir)
{
	lsw_conf_setdefault();
	subst(&global_oco.confddir, confddir, "override ipsec.d");
	subst(&global_oco.nssdb, confddir, "override nssdir");
	lsw_conf_calculate();

	libreswan_log("adjusting ipsec.d and nssdb to %s", global_oco.confddir);
}

void lsw_conf_secretsfile(const char *secretsfile)
{
	lsw_conf_setdefault();
	subst(&global_oco.secretsfile, secretsfile, "secretsfile");
	lsw_conf_calculate();
}

void lsw_conf_nsspassword(const char *nsspassword)
{
	lsw_conf_setdefault();
	subst(&global_oco.nsspassword, nsspassword, "nsspassword");
	lsw_conf_calculate();
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

secuPWData *lsw_return_nss_password_file_info(void)
{
	return &NSSPassword;
}

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
