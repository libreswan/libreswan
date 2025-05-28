/* misc functions to get compile time and runtime options
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2016 Tuomo Soini <tis@foobar.fi>
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

#ifndef LSW_CONF_H
#define LSW_CONF_H

#include <stdbool.h>

struct logger;

struct lsw_conf_options {
	bool is_set;			/* public never see false */
	char *confdir;			/* "/etc" */
	char *conffile;			/* "/etc/ipsec.conf" */
	char *secretsfile;		/* "/etc/ipsec.secrets" */
	char *ppkdir;			/* "/etc/ipsec.d" , for now */
	char *confddir;			/* "/etc/ipsec.d" */
	char *policies_dir;		/* "/etc/ipsec.d/policies" */
	char *nsspassword_file;		/* "/etc/ipsec.d/nsspassword" */
	char *nsspassword;		/* <password> overrides ^ */
	char *nssdir;			/* "/var/lib/ipsec" */
};

const struct lsw_conf_options *lsw_init_options(void);
void lsw_conf_free_oco(void);

void lsw_conf_secretsfile(const char *secretsfile);
void lsw_conf_confddir(const char *confddir, struct logger *logger);
void lsw_conf_nssdir(const char *nssdir, struct logger *logger);
void lsw_conf_nsspassword(const char *nsspassword);

#endif
