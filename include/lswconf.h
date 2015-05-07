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
	char *confddir;			/* "/etc/ipsec.d" */
	char *vardir;			/* "/var/run/pluto" */
	char *policies_dir;		/* "/etc/ipsec.d/policies" */
	char *cacerts_dir;		/* "/etc/ipsec.d/cacerts" */
	char *crls_dir;			/* "/etc/ipsec.d/crls" */
	char *nssdir;			/* "/var/lib/pluto" */
};

typedef struct {
	enum {
		PW_NONE = 0,		/* no password */
		PW_FROMFILE = 1,	/* password data in a text file */
		PW_PLAINTEXT = 2,	/* password data in the clear in memory buffer */
		PW_EXTERNAL = 3		/* external source, user will be prompted */
	} source;
	char *data;
} secuPWData;

extern const struct lsw_conf_options *lsw_init_options(void);
extern void lsw_conf_free_oco(void);
extern void lsw_init_ipsecdir(const char *ipsec_dir);
extern void lsw_init_rootdir(const char *root_dir);

extern secuPWData *lsw_return_nss_password_file_info(void);
extern char *getNSSPassword(PK11SlotInfo *slot, PRBool retry, void *arg);
extern int libreswan_fipsmode(void);
extern int libreswan_fipsproduct(void);
extern int libreswan_fipskernel(void);
extern int libreswan_selinux(void);

#endif /* _LSW_ALLOC_H_ */
