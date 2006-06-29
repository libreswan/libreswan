/* Openswan config parser -- create Opportunistic Encryption conns
 * Copyright (C) 2006 Michael Richardson <mcr@xelerance.com>
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
 * RCSID $Id: confread.c,v 1.11 2004/04/11 15:17:30 ken Exp $
 */

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <sys/queue.h>
#include <stdio.h>

#include "ipsecconf/parser.h"
#include "ipsecconf/confread.h"
#include "ipsecconf/interfaces.h"
#include "ipsecconf/starterlog.h"
#include "ipsecconf/oeconns.h"

enum oe_conn_type {
	OE_PACKETDEFAULT=1,
	OE_CLEAR=2,
	OE_CLEAR_OR_PRIVATE=3,
	OE_PRIVATE_OR_CLEAR=4,
	OE_PRIVATE=5,
	OE_BLOCK=6,
	OE_MAX=7
};

struct oe_conn {
	enum oe_conn_type    oe_ct;
	char                *oe_cn;
	struct starter_conn  oe_sc;
};

/*
 * This replaces the _confread.in awk script that did:
 *
 *		if (jam("packetdefault", "route")) {
 *			output(o_parm, "type", "tunnel")
 *			output(o_parm, "leftsubnet", "0.0.0.0/0")
 *			output(o_parm, "rightnexthop", "%defaultroute")
 *			output(o_parm, "right", "%opportunistic")
 *			output(o_parm, "failureshunt", "passthrough")
 *			output(o_parm, "keyingtries", "3")
 *			output(o_parm, "ikelifetime", "1h")
 *			output(o_parm, "keylife", "1h")
 *			output(o_parm, "rekey", "no")
 *		}
 */

struct oe_conn oe_packet_default = {
	.oe_ct = OE_PACKETDEFAULT,
	.oe_cn = "packetdefault",
	.oe_sc = {
		.policy = POLICY_TUNNEL|POLICY_RSASIG|POLICY_ENCRYPT|POLICY_PFS|
		POLICY_OPPO|POLICY_FAIL_PASS,
		
		.options[KBF_REKEY]=FALSE,
		.options_set[KBF_REKEY]=TRUE,

		.options[KBF_KEYINGTRIES]=3,
		.options_set[KBF_KEYINGTRIES]=TRUE,

		.options[KBF_IKELIFETIME]=3600,
		.options_set[KBF_IKELIFETIME]=TRUE,
		
		.options[KBF_SALIFETIME]=1800,
		.options_set[KBF_SALIFETIME]=TRUE,
		
		.desired_state = STARTUP_ROUTE,
		
		.left.addrtype = KH_DEFAULTROUTE,
		.left.addr_family = AF_INET,
		.left.has_client=TRUE,
		.left.addr={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.left.nexttype = KH_DEFAULTROUTE,
		.left.nexthop={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.left.subnet = {
			 .addr={
				 .u={.v4 = { .sin_family=AF_INET,
					     .sin_addr.s_addr=0 }},
			 },
			 .maskbits=0
		 },
		.left.key_from_DNS_on_demand = TRUE,
		
		.right.addr_family = AF_INET,
		.right.addrtype = KH_OPPO,
		.right.addr={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.right.has_client=TRUE,
		.right.subnet = {
			 .addr={
				 .u={.v4 = { .sin_family=AF_INET,
					     .sin_addr.s_addr=0 }},
			 },
			 .maskbits=0
		 },
		.right.nexttype = KH_DEFAULTROUTE,
		.right.nexthop={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.right.key_from_DNS_on_demand = TRUE,
	},
};

/*
 *		if (jam("clear", "route")) {
 *			output(o_parm, "type", "passthrough")
 *			output(o_parm, "authby", "never")
 *			output(o_parm, "right", "%group")
 *			output(o_parm, "rightnexthop", "%defaultroute")
 *		}
 */

struct oe_conn oe_clear = {
	.oe_ct = OE_CLEAR,
	.oe_cn = "clear",
	.oe_sc = {
		.policy = POLICY_TUNNEL|POLICY_PFS|POLICY_GROUP|POLICY_GROUTED|POLICY_SHUNT_PASS,
		
		.desired_state = STARTUP_ROUTE,
		
		.left.addrtype = KH_DEFAULTROUTE,
		.left.addr_family = AF_INET,
		.left.has_client=FALSE,
		.left.addr={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.left.nexttype = KH_DEFAULTROUTE,
		.left.nexthop={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.left.subnet = {
			 .addr={
				 .u={.v4 = { .sin_family=AF_INET,
					     .sin_addr.s_addr=0 }},
			 },
			 .maskbits=0
		 },
		
		.right.addr_family = AF_INET,
		.right.addrtype = KH_GROUP,
		.right.addr={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.right.has_client=TRUE,
		.right.subnet = {
			 .addr={
				 .u={.v4 = { .sin_family=AF_INET,
					     .sin_addr.s_addr=0 }},
			 },
			 .maskbits=0
		 },
		.right.nexttype = KH_DEFAULTROUTE,
		.right.nexthop={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
	},
};



/*
 *		if (jam("clear-or-private", "route")) {
 *			output(o_parm, "type", "passthrough")
 *			output(o_parm, "right", "%opportunisticgroup")
 *			output(o_parm, "rightnexthop", "%defaultroute")
 *			output(o_parm, "failureshunt", "passthrough")
 *			output(o_parm, "keyingtries", "3")
 *			output(o_parm, "ikelifetime", "1h")
 *			output(o_parm, "keylife", "1h")
 *			output(o_parm, "rekey", "no")
 *		}
 */

struct oe_conn oe_clear_or_private = {
	.oe_ct = OE_CLEAR_OR_PRIVATE,
	.oe_cn = "clear-or-private",
	.oe_sc = {
		.policy = POLICY_RSASIG|POLICY_ENCRYPT|POLICY_TUNNEL|POLICY_PFS|
		POLICY_DONT_REKEY|POLICY_OPPO|POLICY_GROUP|POLICY_GROUTED|
		POLICY_SHUNT_PASS|POLICY_FAIL_PASS,
		
		.options[KBF_KEYINGTRIES]=3,
		.options_set[KBF_KEYINGTRIES]=TRUE,

		.options[KBF_IKELIFETIME]=3600,
		.options_set[KBF_IKELIFETIME]=TRUE,
		
		.options[KBF_SALIFETIME]=1800,
		.options_set[KBF_SALIFETIME]=TRUE,
		
		.desired_state = STARTUP_ROUTE,
		
		.left.addrtype = KH_DEFAULTROUTE,
		.left.addr_family = AF_INET,
		.left.has_client=FALSE,
		.left.addr={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.left.nexttype = KH_DEFAULTROUTE,
		.left.nexthop={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.left.subnet = {
			 .addr={
				 .u={.v4 = { .sin_family=AF_INET,
					     .sin_addr.s_addr=0 }},
			 },
			 .maskbits=0
		 },
		.left.key_from_DNS_on_demand = TRUE,
		
		.right.addr_family = AF_INET,
		.right.addrtype = KH_OPPOGROUP,
		.right.addr={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.right.has_client=TRUE,
		.right.subnet = {
			 .addr={
				 .u={.v4 = { .sin_family=AF_INET,
					     .sin_addr.s_addr=0 }},
			 },
			 .maskbits=0
		 },
		.right.nexttype = KH_DEFAULTROUTE,
		.right.nexthop={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.right.key_from_DNS_on_demand = TRUE,
	},
};


/*
 *		if (jam("private-or-clear", "route")) {
 *			output(o_parm, "type", "tunnel")
 *			output(o_parm, "right", "%opportunisticgroup")
 *			output(o_parm, "rightnexthop", "%defaultroute")
 *			output(o_parm, "failureshunt", "passthrough")
 *			output(o_parm, "keyingtries", "3")
 *			output(o_parm, "ikelifetime", "1h")
 *			output(o_parm, "keylife", "1h")
 *			output(o_parm, "rekey", "no")
 *		}
 */

struct oe_conn oe_private_or_clear = {
	.oe_ct = OE_PRIVATE_OR_CLEAR,
	.oe_cn = "private-or-clear",
	.oe_sc = {
		.policy = POLICY_RSASIG|POLICY_ENCRYPT|POLICY_TUNNEL|POLICY_PFS|
		POLICY_DONT_REKEY|POLICY_OPPO|POLICY_GROUP|POLICY_GROUTED|
		POLICY_FAIL_PASS,
		
		.desired_state = STARTUP_ROUTE,
		
		.options[KBF_KEYINGTRIES]=3,
		.options_set[KBF_KEYINGTRIES]=TRUE,

		.options[KBF_IKELIFETIME]=3600,
		.options_set[KBF_IKELIFETIME]=TRUE,
		
		.options[KBF_SALIFETIME]=1800,
		.options_set[KBF_SALIFETIME]=TRUE,
		
		.left.addrtype = KH_DEFAULTROUTE,
		.left.addr_family = AF_INET,
		.left.has_client=FALSE,
		.left.addr={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.left.nexttype = KH_DEFAULTROUTE,
		.left.nexthop={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.left.subnet = {
			 .addr={
				 .u={.v4 = { .sin_family=AF_INET,
					     .sin_addr.s_addr=0 }},
			 },
			 .maskbits=0
		 },
		.left.key_from_DNS_on_demand = TRUE,
		
		.right.addr_family = AF_INET,
		.right.addrtype = KH_OPPOGROUP,
		.right.addr={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.right.has_client=TRUE,
		.right.subnet = {
			 .addr={
				 .u={.v4 = { .sin_family=AF_INET,
					     .sin_addr.s_addr=0 }},
			 },
			 .maskbits=0
		 },
		.right.nexttype = KH_DEFAULTROUTE,
		.right.nexthop={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.right.key_from_DNS_on_demand = TRUE,
	},
};

/*
 *		if (jam("private", "route")) {
 *			output(o_parm, "type", "tunnel")
 *			output(o_parm, "right", "%opportunisticgroup")
 *			output(o_parm, "rightnexthop", "%defaultroute")
 *			output(o_parm, "failureshunt", "drop")
 *			output(o_parm, "keyingtries", "3")
 *			output(o_parm, "ikelifetime", "1h")
 *			output(o_parm, "keylife", "1h")
 *			output(o_parm, "rekey", "no")
 *		}
 *
 */

struct oe_conn oe_private = {
	.oe_ct = OE_PRIVATE,
	.oe_cn = "private",
	.oe_sc = {
		/* RSASIG+ENCRYPT+TUNNEL+PFS+DONTREKEY+OPPORTUNISTIC+GROUP
		 * +GROUTED+failureDROP+lKOD+rKOD
		 */

		.policy = POLICY_RSASIG|POLICY_ENCRYPT|POLICY_TUNNEL|POLICY_PFS|
		POLICY_DONT_REKEY|POLICY_OPPO|POLICY_GROUP|POLICY_GROUTED|
		POLICY_FAIL_DROP,


		.desired_state = STARTUP_ROUTE,
		
		.options[KBF_KEYINGTRIES]=3,
		.options_set[KBF_KEYINGTRIES]=TRUE,

		.options[KBF_IKELIFETIME]=3600,
		.options_set[KBF_IKELIFETIME]=TRUE,
		
		.options[KBF_SALIFETIME]=1800,
		.options_set[KBF_SALIFETIME]=TRUE,
		
		.left.addrtype = KH_DEFAULTROUTE,
		.left.addr_family = AF_INET,
		.left.has_client=FALSE,
		.left.addr={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.left.nexttype = KH_DEFAULTROUTE,
		.left.nexthop={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.left.subnet = {
			 .addr={
				 .u={.v4 = { .sin_family=AF_INET,
					     .sin_addr.s_addr=0 }},
			 },
			 .maskbits=0
		 },
		.left.key_from_DNS_on_demand = TRUE,
		
		.right.addr_family = AF_INET,
		.right.addrtype = KH_OPPOGROUP,
		.right.addr={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.right.has_client=TRUE,
		.right.subnet = {
			 .addr={
				 .u={.v4 = { .sin_family=AF_INET,
					     .sin_addr.s_addr=0 }},
			 },
			 .maskbits=0
		 },
		.right.nexttype = KH_DEFAULTROUTE,
		.right.nexthop={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.right.key_from_DNS_on_demand = TRUE,
	},
};

/*
 *		if (jam("block", "route")) {
 *			output(o_parm, "type", "reject")
 *			output(o_parm, "authby", "never")
 *			output(o_parm, "right", "%group")
 *			output(o_parm, "rightnexthop", "%defaultroute")
 *		}
 *
 * However, in addition it also does "also=%oedefault"
 * 
 */

struct oe_conn oe_block = {
	.oe_ct = OE_BLOCK,
	.oe_cn = "block",
	.oe_sc = {
		.policy = POLICY_TUNNEL|POLICY_PFS|
		POLICY_GROUP|POLICY_GROUTED|POLICY_SHUNT_REJECT,
		
		.desired_state = STARTUP_ROUTE,
		
		.left.addrtype = KH_DEFAULTROUTE,
		.left.addr_family = AF_INET,
		.left.has_client=FALSE,
		.left.addr={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.left.nexttype = KH_DEFAULTROUTE,
		.left.nexthop={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.left.subnet = {
			 .addr={
				 .u={.v4 = { .sin_family=AF_INET,
					     .sin_addr.s_addr=0 }},
			 },
			 .maskbits=0
		 },
		.left.key_from_DNS_on_demand = TRUE,
		
		.right.addr_family = AF_INET,
		.right.addrtype = KH_OPPOGROUP,
		.right.addr={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.right.has_client=TRUE,
		.right.subnet = {
			 .addr={
				 .u={.v4 = { .sin_family=AF_INET,
					     .sin_addr.s_addr=0 }},
			 },
			 .maskbits=0
		 },
		.right.nexttype = KH_DEFAULTROUTE,
		.right.nexthop={
			 .u={.v4 = { .sin_family=AF_INET }},
		 },
		.right.key_from_DNS_on_demand = TRUE,
	},
};

struct oe_conn *implicit_conns[]={
	&oe_packet_default,
	&oe_clear,
	&oe_clear_or_private,
	&oe_private_or_clear,
	&oe_private,
	&oe_block,
	NULL
};


void add_any_oeconns(struct starter_config *cfg,
		     struct config_parsed *cfgp)
{
	bool found_conns[OE_MAX];
	struct section_list *sconn;
	struct oe_conn **oc;
	err_t perr;
	int i;

	for(i=0;i<OE_MAX;i++) found_conns[i]=FALSE;

	/* look for the conn. */
	for(sconn = cfgp->sections.tqh_first; sconn != NULL; sconn = sconn->link.tqe_next)
		
	{
		for(i=0, oc=implicit_conns; *oc!=NULL; oc++) {
			if(strcasecmp((*oc)->oe_cn, sconn->name)==0) {
				found_conns[i]=TRUE;
			}
		}
	}

	
	for(i=0, oc=implicit_conns; *oc!=NULL; oc++, i++) {
		if(found_conns[i]==FALSE) {
			int connerr = 0;
			struct starter_conn *conn;
			const struct starter_conn *tconn;

			tconn = &((*oc)->oe_sc);
			starter_log(LOG_LEVEL_DEBUG,
				    "did not found conn: %s, loading implicit\n",
				    (*oc)->oe_cn);

			conn = alloc_add_conn(cfg, (*oc)->oe_cn, &perr);
			if(conn == NULL) {
				starter_log(LOG_LEVEL_INFO, "Can not create conn %s:\n",
					    (*oc)->oe_cn, perr);
				continue;
			}

#if 0
			/* this doesn't help at all, since we memcpy below. */
			if(cfg->got_oedefault) {
				/* get oedefaults too */
				conn_default (conn, &cfg->conn_oedefault);
			}
#endif

			memcpy(&conn->strings, &tconn->strings, sizeof(tconn->strings));
			memcpy(&conn->options, &tconn->options, sizeof(tconn->options));
			memcpy(&conn->strings_set, &tconn->strings_set, sizeof(tconn->strings_set));
			memcpy(&conn->options_set, &tconn->options_set, sizeof(tconn->options_set));
			conn->left = tconn->left;
			conn->right= tconn->right;
			conn->esp  = tconn->esp;
			conn->ike  = tconn->ike;
			conn->desired_state = tconn->desired_state;
			conn->policy = tconn->policy;

			if(connerr) {
				starter_log(LOG_LEVEL_INFO, "implicit %s: %s"
					    , (*oc)->oe_cn, perr);
			}

		}
	}
}

	    
