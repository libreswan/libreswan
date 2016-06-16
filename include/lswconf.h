/* misc functions to get compile time and runtime options
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
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

#ifndef _LSW_CONF_H
#define _LSW_CONF_H

#include "constants.h"

# include <nss.h>
# include <pk11pub.h>	/* from nss3 devel */

struct lsw_conf_options {
	char *rootdir;			/* default is "" --- used for testing */
	char *confdir;			/* "/etc" */
	char *conffile;			/* "/etc/ipsec.conf" */
	char *secretsfile;		/* "/etc/ipsec.secrets" */
	char *vardir;			/* "/var/run/pluto" */
	char *confddir;			/* "/etc/ipsec.d" */
	char *policies_dir;		/* "/etc/ipsec.d/policies" */
	char *cacerts_dir;		/* "/etc/ipsec.d/cacerts" */
	char *crls_dir;			/* "/etc/ipsec.d/crls" */
	char *nsspassword_file;		/* "/etc/ipsec.d/nsspassword" */
	char *nsspassword;		/* <password> overrides ^ */
	char *nssdb;			/* "/var/lib/ipsec" */
};

const struct lsw_conf_options *lsw_init_options(void);
void lsw_conf_free_oco(void);
void lsw_conf_rootdir(const char *root_dir);
void lsw_conf_secretsfile(const char *secretsfile);
void lsw_conf_confddir(const char *confddir);
void lsw_conf_nssdb(const char *nssdb);
void lsw_conf_nsspassword(const char *nsspassword);

/*
 * XXX: Going away - sets both confddir and nssdb.
 */
void lsw_init_ipsecdir(const char *ipsec_dir);

extern int libreswan_selinux(void);

#endif /* _LSW_ALLOC_H_ */
