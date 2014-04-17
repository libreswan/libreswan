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

	zero(&global_oco);

	/* allocate them all to make it consistent */
	global_oco.rootdir = clone_str("","rootdir");
	global_oco.confddir = clone_str(IPSEC_CONFDDIR, "default conf ipsecd_dir");
	global_oco.vardir  = clone_str(IPSEC_VARDIR, "default vardir");
	global_oco.confdir = clone_str(IPSEC_CONFDIR, "default conf ipsec_conf_dir");
	global_oco.conffile = clone_str(IPSEC_CONF, "default conf conffile");

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
	pfree(NSSPassword.data);
}

const struct lsw_conf_options *lsw_init_options(void)
{
	if (setup)
		return &global_oco;

	setup = TRUE;

	lsw_conf_setdefault();
	lsw_conf_calculate(&global_oco);

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
	PRInt32 nb;	/*number of bytes*/
	char* password;
	char* strings;
	char* token = NULL;
	const long maxPwdFileSize = NSSpwdfilesize;
	int i, tlen = 0;

	if (slot) {
		token = PK11_GetTokenName(slot);
		if (token) {
			tlen = PORT_Strlen(token);
			/*
			 * libreswan_log("authentication needed for "
			 *	"token name %s with length %d", token, tlen);
			 */
		} else {
			return 0;
		}
	} else {
		return 0;
	}

	if (retry)
		return 0;

	strings = PORT_ZAlloc(maxPwdFileSize);
	if (!strings) {
		libreswan_log("Not able to allocate memory for reading "
			"NSS password file");
		return 0;
	}

	if (pwdInfo->source == PW_FROMFILE) {
		if (pwdInfo->data != NULL) {
			fd = PR_Open(pwdInfo->data, PR_RDONLY, 0);
			if (!fd) {
				PORT_Free(strings);
				libreswan_log(
					"No password file \"%s\" exists.",
					pwdInfo->data);
				return 0;
			}

			nb = PR_Read(fd, strings, maxPwdFileSize);
			PR_Close(fd);

			if (nb == 0) {
				libreswan_log("password file contains "
					"no data");
				PORT_Free(strings);
				return 0;
			}

			i = 0;
			do {
				int start = i;
				int slen;

				while (strings[i] != '\r' &&
				       strings[i] != '\n' && i < nb)
					i++;
				strings[i++] = '\0';

				while ((i < nb) && (strings[i] == '\r' ||
					strings[i] == '\n'))
					 strings[i++] = '\0';

				password = &strings[start];

				if (PORT_Strncmp(password, token, tlen))
					continue;
				slen = PORT_Strlen(password);

				if (slen < (tlen + 1))
					continue;
				if (password[tlen] != ':')
					continue;
				password = &password[tlen + 1];
				break;

			} while (i < nb);

			password = PORT_Strdup((char*)password);
			PORT_Free(strings);

			/*
			 * libreswan_log("Password passed to NSS is %s with "
			 *	"length %d", password, PORT_Strlen(password));
			 */
			return password;
		} else {
			libreswan_log("File with Password to NSS DB is "
				"not provided");
			return 0;
		}
	}

	libreswan_log("nss password source is not specified as file");
	return 0;
}

