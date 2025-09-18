/* Libreswan config file parser (confread.h)
 *
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2009 Jose Quaresma <josequaresma@gmail.com>
 * Copyright (C) 2003-2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2016, Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2019 D. Hugh Redelmeier <hugh@mimosa.com>
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
 */

#ifndef IPSECCONF_CONFREAD_H
#define IPSECCONF_CONFREAD_H

#include <sys/queue.h>		/* for TAILQ_ENTRY() */
#include <stdint.h>

#include "ipsecconf/config_setup.h"
#include "ipsecconf/config_conn.h"

#include "deltatime.h"
#include "ip_address.h"
#include "authby.h"
#include "shunt.h"		/* for SHUNT_KIND_ROOF */
#include "end.h"

struct logger;

/*
 * Code tests <<set[flag] != k_set>> to detect either k_unset or
 * k_default and allow an override.
 */

enum keyword_set {
	k_unset   = false,
	k_set     = true,
	k_default = 2
};

struct keyword_value {
	enum keyword_set set;
	char *string;
	intmax_t option;
	deltatime_t deltatime;
};

typedef struct keyword_value config_setup_values[CONFIG_SETUP_KEYWORD_ROOF];
typedef struct keyword_value config_conn_values[CONFIG_CONN_KEYWORD_ROOF];

/*
 * Note: string fields in struct starter_end and struct starter_conn
 * should correspond to STR_FIELD calls in copy_conn_default() and confread_free_conn.
 */

struct starter_end {
	const char *leftright;
	config_conn_values values;
};

/*
 * Note: string fields in struct starter_end and struct starter_conn
 * should correspond to STR_FIELD calls in copy_conn_default() and confread_free_conn.
 */

struct starter_conn {
	TAILQ_ENTRY(starter_conn) link;
	char *name;

	config_conn_values values;
	struct starter_end end[END_ROOF];

	enum shunt_policy shunt[SHUNT_KIND_ROOF];


	enum {
		STATE_INVALID,
		STATE_LOADED,
		STATE_INCOMPLETE,
		STATE_ADDED,
		STATE_FAILED,
	} state;

};

struct config_setup {
	config_setup_values values;
};

struct starter_config {
	/* conn %default */
	struct starter_conn conn_default;

	/* connections list (without %default) */
	TAILQ_HEAD(conns_head, starter_conn) conns;
};

struct starter_config *confread_load(const char *file,
				     bool setuponly,
				     struct logger *logger,
				     unsigned verbosity);

struct starter_config *confread_load_argv(const char *file,
					  const char *name, char *argv[], int start,
					  struct logger *logger, unsigned verbosity);

void confread_free(struct starter_config *cfg);

#endif /* _IPSEC_CONFREAD_H_ */
