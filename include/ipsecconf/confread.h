/* Libreswan config file parser (confread.h)
 *
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2009 Jose Quaresma <josequaresma@gmail.com>
 * Copyright (C) 2003-2006 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Coprright (C) 2016, Andrew Cagney <cagney@gnu.org>
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

#ifndef _IPSEC_CONFREAD_H_
#define _IPSEC_CONFREAD_H_

#include "ipsecconf/keywords.h"

# define DEFAULT_UPDOWN "ipsec _updown"

#include "lset.h"
#include "err.h"

#ifndef _LIBRESWAN_H
#include <libreswan.h>
#include "constants.h"
#endif

/* define an upper limit to number of times also= can be used */
#define ALSO_LIMIT 32

enum keyword_set {
	k_unset   = FALSE,
	k_set     = TRUE,
	k_default = 2
};
typedef char *ksf[KEY_STRINGS_MAX];
typedef int knf[KEY_NUMERIC_MAX];
typedef enum keyword_set str_set[KEY_STRINGS_MAX];
typedef enum keyword_set int_set[KEY_NUMERIC_MAX];

struct starter_end {
	sa_family_t addr_family;
	enum keyword_host addrtype;
	enum keyword_host nexttype;
	ip_address addr, nexthop, sourceip;
	bool has_client;
	ip_subnet subnet, vti_ip;
	char *iface;
	char *id;
	enum keyword_authby authby;

	enum keyword_pubkey rsakey1_type, rsakey2_type;
	char *rsakey1;
	char *rsakey2;
	uint16_t port;
	uint8_t protocol;
	bool has_client_wildcard;
	bool key_from_DNS_on_demand;
	bool has_port_wildcard;
	char *virt;
	char *cert;
	char *ckaid;
	char *ca;
	char *updown;
	ip_range pool_range;    /* store start of v4 addresspool */
	ksf strings;
	knf options;

	str_set strings_set;
	int_set options_set;
};

struct starter_conn {
	TAILQ_ENTRY(starter_conn) link;
	struct starter_comments_list comments;
	char *name;
	char *connalias;

	ksf strings;
	knf options;
	str_set strings_set;
	int_set options_set;

	lset_t policy;
	lset_t sighash_policy;

	char **alsos;

	struct starter_end left, right;

	unsigned long id;

	enum keyword_auto desired_state;

	enum {
		STATE_INVALID,
		STATE_LOADED,
		STATE_INCOMPLETE,
		STATE_ADDED,
		STATE_FAILED,
	} state;

	char *esp;
	char *ike;
	char *modecfg_dns;
	char *modecfg_domains;
	char *modecfg_banner;
	char *policy_label;
	char *conn_mark_both;
	char *conn_mark_in;
	char *conn_mark_out;
	char *vti_iface;
	bool vti_routing;
	bool vti_shared;
};

struct starter_config {
	struct {
		ksf strings;
		knf options;
		str_set strings_set;
		int_set options_set;
	} setup;

	/* conn %default */
	struct starter_conn conn_default;

	char *ctlsocket;  /* location of pluto control socket */

	/* connections list (without %default) */
	TAILQ_HEAD(, starter_conn) conns;
};

/*
 * accumulate errors in this struct.
 * This is a string with newlines separating messages.
 * The string is heap-allocated so the caller is responsible
 * for freeing it.
 */
typedef struct {
	char *errors;
} starter_errors_t;

extern void starter_error_append(starter_errors_t *perrl, const char *fmt, ...) PRINTF_LIKE(2);


extern struct config_parsed *parser_load_conf(const char *file, starter_errors_t *perr);
extern void parser_free_conf(struct config_parsed *cfg);

extern struct starter_config *confread_load(const char *file,
					    starter_errors_t *perrl,
					    const char *ctlsocket,
					    bool setuponly);
extern struct starter_conn *alloc_add_conn(struct starter_config *cfg,
					   const char *name);
extern void confread_free(struct starter_config *cfg);

extern void ipsecconf_default_values(struct starter_config *cfg);

#endif /* _IPSEC_CONFREAD_H_ */
