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

#ifndef _IPSEC_CONFREAD_H_
#define _IPSEC_CONFREAD_H_

#include <sys/queue.h>		/* for TAILQ_ENTRY() */

#include "ipsecconf/keywords.h"

#include "lset.h"
#include "err.h"
#include "ip_range.h"
#include "ip_subnet.h"
#include "ip_protoport.h"
#include "ip_cidr.h"
#include "lswcdefs.h"
#include "authby.h"

struct logger;

enum keyword_set {
	k_unset   = false,
	k_set     = true,
	k_default = 2
};
typedef char *ksf[KEY_STRINGS_ROOF];
typedef intmax_t knf[KEY_NUMERIC_ROOF];
typedef enum keyword_set str_set[KEY_STRINGS_ROOF];
typedef enum keyword_set int_set[KEY_NUMERIC_ROOF];

/*
 * Note: string fields in struct starter_end and struct starter_conn
 * should correspond to STR_FIELD calls in copy_conn_default() and confread_free_conn.
 */

struct starter_end {
	const char *leftright;
	const struct ip_info *host_family;	/* XXX: move to starter_conn? */
	enum keyword_host addrtype;
	enum keyword_host nexttype;
	ip_address addr;
	ip_address nexthop;
	char *sourceip;
	char *subnet;
	ip_cidr vti_ip;
	ip_cidr ifaceip;
	char *iface;
	char *id;

	ip_protoport protoport;

	enum keyword_pubkey pubkey_type;
	enum ipseckey_algorithm_type pubkey_alg;
	char *pubkey;

	bool key_from_DNS_on_demand;
	char *virt;
	char *certx;
	char *ckaid;
	char *ca;
	ksf strings;
	knf options;

	str_set strings_set;
	int_set options_set;
};

/*
 * Note: string fields in struct starter_end and struct starter_conn
 * should correspond to STR_FIELD calls in copy_conn_default() and confread_free_conn.
 */

struct starter_conn {
	TAILQ_ENTRY(starter_conn) link;
	struct starter_comments_list comments;
	char *name;
	char *connalias;

	ksf strings;
	knf options;
	str_set strings_set;
	int_set options_set;

	enum ike_version ike_version;
	struct authby authby;
	lset_t sighash_policy;
	enum shunt_policy shunt[SHUNT_KIND_ROOF];

	struct starter_end left, right;

	unsigned long id;

	const struct ip_info *clientaddrfamily;

	enum autostart autostart; /*"auto" is a C reserved word*/

	enum {
		STATE_INVALID,
		STATE_LOADED,
		STATE_INCOMPLETE,
		STATE_ADDED,
		STATE_FAILED,
	} state;

	char *ike_crypto;
	char *esp;
	char *modecfg_dns;
	char *modecfg_domains;
	char *modecfg_banner;
	char *sec_label;
	char *conn_mark_both;
	char *conn_mark_in;
	char *conn_mark_out;
	char *ppk_ids;
	uint32_t xfrm_if_id;
	char *dpd_delay;
	char *dpd_timeout;
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

	/* connections list (without %default) */
	TAILQ_HEAD(, starter_conn) conns;
};

extern struct config_parsed *parser_load_conf(const char *file,
					      struct logger *logger);
extern void parser_free_conf(struct config_parsed *cfg);

extern struct starter_config *confread_load(const char *file,
					    bool setuponly,
					    struct logger *logger);

extern void confread_free(struct starter_config *cfg);

#endif /* _IPSEC_CONFREAD_H_ */
