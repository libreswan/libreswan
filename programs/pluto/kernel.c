/* routines that interface with the kernel's IPsec mechanism, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2009-2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2010 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2015 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2016-2022 Andrew Cagney
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
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

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>		/* for WIFEXITED() et.al. */
#include <unistd.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/thread.h>


#include "sysdep.h"
#include "constants.h"

#include "defs.h"
#include "rnd.h"
#include "id.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "timer.h"
#include "kernel.h"
#include "kernel_ops.h"
#include "kernel_xfrm.h"
#include "packet.h"
#include "x509.h"
#include "pluto_x509.h"
#include "certs.h"
#include "secrets.h"
#include "log.h"
#include "server.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "keys.h"
#include "ike_alg.h"
#include "ike_alg_encrypt.h"
#include "ike_alg_integ.h"

#include "packet.h"  /* for pb_stream in nat_traversal.h */
#include "nat_traversal.h"
#include "ip_address.h"
#include "ip_info.h"
#include "lswfips.h" /* for libreswan_fipsmode() */
# include "kernel_xfrm_interface.h"
#include "iface.h"
#include "ip_selector.h"
#include "ip_encap.h"
#include "show.h"
#include "rekeyfuzz.h"

static bool route_and_eroute(struct connection *c,
			     struct spd_route *sr,
			     struct state *st,
			     /* st or c */
			     struct logger *logger);

static bool eroute_connection(enum kernel_policy_op op, const char *opname,
			      const struct spd_route *sr,
			      enum shunt_policy shunt_policy,
			      const struct kernel_policy *kernel_policy,
			      uint32_t sa_priority,
			      const struct sa_marks *sa_marks,
			      const struct pluto_xfrmi *xfrmi,
			      shunk_t sec_label,
			      struct logger *logger);

static global_timer_cb kernel_scan_shunts;
static bool invoke_command(const char *verb, const char *verb_suffix,
			   const char *cmd, struct logger *logger);

/*
 * Add/replace/delete a shunt eroute.
 *
 * Such an eroute determines the fate of packets without the use
 * of any SAs.  These are defaults, in effect.
 * If a negotiation has not been attempted, use %trap.
 * If negotiation has failed, the choice between %trap/%pass/%drop/%reject
 * is specified in the policy of connection c.
 *
 * The kernel policy is bare (naked, global) it is not paired with a
 * kernel state.
 */

static bool bare_policy_op(enum kernel_policy_op op,
			   enum expect_kernel_policy expect_kernel_policy,
			   const struct connection *c,
			   const struct spd_route *sr,
			   enum routing_t rt_kind,
			   const char *opname,
			   struct logger *logger)
{
	shunk_t sec_label = HUNK_AS_SHUNK(c->config->sec_label);

	/*
	 * We are constructing a special SAID for the policy.
	 *
	 * The destination doesn't seem to matter, but the family
	 * does.  The protocol is &ip_protocol_internal -- mark this
	 * as shunt.  The satype has no meaning, but is required for
	 * PF_KEY header!  The SPI signifies the kind of shunt.
	 */
	enum shunt_policy shunt_policy =
		(rt_kind == RT_ROUTED_PROSPECTIVE ? c->config->prospective_shunt :
		 c->config->failure_shunt);

	LSWDBGP(DBG_BASE, buf) {
		jam(buf, "kernel: %s() ", __func__);
		jam_enum_short(buf, &kernel_policy_op_names, op);

		jam_string(buf, " ");
		jam_string(buf, expect_kernel_policy_name(expect_kernel_policy));

		jam(buf, " %s", opname);
		jam(buf, " ");
		jam_connection(buf, c);

		enum_buf rtb;
		jam(buf, " rt_kind '%s'",
		    str_enum_short(&routing_story, rt_kind, &rtb));

		enum_buf spb;
		jam(buf, " shunt_policy=%s",
		    str_enum_short(&shunt_policy_names, shunt_policy, &spb));

		jam(buf, " ");
		jam_selector_subnet_port(buf, &sr->this.client);
		jam(buf, "-%s->", selector_protocol(sr->this.client)->name);
		jam_selector_subnet_port(buf, &sr->that.client);

		jam(buf, " (config)sec_label=");
		if (c->config->sec_label.len > 0) {
			jam_sanitized_hunk(buf, sec_label);
		}
	}

	if (shunt_policy == SHUNT_NONE) {
		/*
		 * We're supposed to end up with no policy: rejig op
		 * and opname.
		 */
		switch (op) {
		case KP_REPLACE_OUTBOUND:
			/* replace with nothing == delete */
			op = KP_DELETE_OUTBOUND;
			opname = "delete";
			break;
		case KP_ADD_OUTBOUND:
			/* add nothing == do nothing */
			return true;

		case KP_DELETE_OUTBOUND:
			/* delete remains delete */
			break;

		case KP_ADD_INBOUND:
		case KP_REPLACE_INBOUND:
		case KP_DELETE_INBOUND:
			/* never inbound */
			bad_case(op);
		}
	}

	if (sr->routing == RT_ROUTED_ECLIPSED && c->kind == CK_TEMPLATE) {
		/*
		 * We think that we have an eroute, but we don't.
		 * Adjust the request and account for eclipses.
		 */
		passert(eclipsable(sr));
		switch (op) {
		case KP_REPLACE_OUTBOUND:
			/* really an add */
			op = KP_ADD_OUTBOUND;
			opname = "replace eclipsed";
			break;
		case KP_DELETE_OUTBOUND:
			/*
			 * delete unnecessary:
			 * we don't actually have an eroute
			 */
			return true;

		case KP_ADD_OUTBOUND: /*never eclipsed add*/
		case KP_ADD_INBOUND:
		case KP_REPLACE_INBOUND:
		case KP_DELETE_INBOUND:
			/* never inbound */
			bad_case(op);
		}
	} else if (op == KP_DELETE_OUTBOUND) {
		/* maybe we are uneclipsing something */
		struct spd_route *esr = eclipsing(sr);
		if (esr != NULL) {
			set_spd_routing(esr, RT_ROUTED_PROSPECTIVE);
			return bare_policy_op(KP_REPLACE_OUTBOUND,
					      EXPECT_KERNEL_POLICY_OK,
					      esr->connection, esr,
					      RT_ROUTED_PROSPECTIVE,
					      "restoring eclipsed",
					      logger);
		}
	}

	/*
	 * XXX: the two calls below to raw_policy() seems to be the
	 * only place where SA_PROTO and ESATYPE disagree - when
	 * ENCAPSULATION_MODE_TRANSPORT SA_PROTO==&ip_protocol_esp and
	 * ESATYPE==ET_INT!?!  Looking in the function there's a weird
	 * test involving both SA_PROTO and ESATYPE.
	 *
	 * XXX: suspect sa_proto should be dropped (when is SPI not
	 * internal) and instead esatype (encapsulated sa type) should
	 * receive &ip_protocol ...
	 *
	 * Use raw_policy() as it gives a better log result.
	 */

	bool delete = (op & KERNEL_POLICY_DELETE);

	pexpect(op & KERNEL_POLICY_OUTBOUND);
	struct kernel_policy outbound_kernel_policy =
		bare_kernel_policy(&sr->this.client, &sr->that.client);
	if (!raw_policy(op,
			EXPECT_KERNEL_POLICY_OK,
			&outbound_kernel_policy.src.client,
			&outbound_kernel_policy.dst.client,
			shunt_policy,
			((delete || shunt_policy == SHUNT_PASS) ? NULL :
			 &outbound_kernel_policy),
			deltatime(0),
			calculate_sa_prio(c, false),
			&c->sa_marks, c->xfrmi,
			sec_label, logger,
			"%s() outbound shunt for %s", __func__, opname))
		return false;

	switch (op) {
	case KP_ADD_OUTBOUND:
		op = KP_ADD_INBOUND;
		break;
	case KP_DELETE_OUTBOUND:
		op = KP_DELETE_INBOUND;
		break;
	case KP_REPLACE_OUTBOUND:
	case KP_ADD_INBOUND:
	case KP_REPLACE_INBOUND:
	case KP_DELETE_INBOUND:
		return true;
	}

	/*
	 * Note the crossed streams since inbound.
	 *
	 * Note the NO_INBOUND_ENTRY.  It's a hack to get around a
	 * connection being unrouted, deleting both inbound and
	 * outbound policies when there's only the basic outbound
	 * policy installed.
	 */
	struct kernel_policy inbound_kernel_policy =
		bare_kernel_policy(&sr->that.client, &sr->this.client);
	return raw_policy(op, expect_kernel_policy,
			  &inbound_kernel_policy.src.client,
			  &inbound_kernel_policy.dst.client,
			  shunt_policy,
			  ((delete || shunt_policy == SHUNT_PASS) ? NULL :
			   &inbound_kernel_policy),
			  deltatime(0),
			  calculate_sa_prio(c, false),
			  &c->sa_marks, c->xfrmi,
			  sec_label, logger,
			  "%s() inbound shunt for %s", __func__, opname);
}

struct kernel_policy bare_kernel_policy(const ip_selector *src,
					const ip_selector *dst)
{
	const struct ip_info *child_afi = selector_type(src);
	pexpect(selector_type(dst) == child_afi);
	struct kernel_policy transport_esp = {
		/* what will capture packets */
		.src.client = *src,
		.dst.client = *dst,
		.src.route = *src,
		.dst.route = *dst,
		/*
		 * With transport mode, the encapsulated packet on the
		 * host interface must have the same family as the raw
		 * packet on the client interface.  Even though it is
		 * UNSPEC.
		 */
		.src.host = child_afi->address.unspec,
		.dst.host = child_afi->address.unspec,
		.mode = ENCAP_MODE_TRANSPORT,
		.nr_rules = 1,
		.rule[1] = {
			.proto = ENCAP_PROTO_ESP,
			.reqid = 0,
		},
	};
	return transport_esp;
}

struct bare_shunt {
	policy_prio_t policy_prio;
	ip_selector our_client;
	ip_selector peer_client;
	enum shunt_policy shunt_policy;
	const struct ip_protocol *transport_proto; /* XXX: same value in local/remote */
	unsigned long count;
	monotime_t last_activity;

	/*
	 * Note: "why" must be in stable storage (not auto, not heap)
	 * because we use it indefinitely without copying or pfreeing.
	 * Simple rule: use a string literal.
	 */
	const char *why;

	/* the connection from where it came - used to re-load /32 conns */
	co_serial_t from_serialno;

	struct bare_shunt *next;
};

static struct bare_shunt *bare_shunts = NULL;

#ifdef IPSEC_CONNECTION_LIMIT
static int num_ipsec_eroute = 0;
#endif

static void jam_bare_shunt(struct jambuf *buf, const struct bare_shunt *bs)
{
	jam(buf, "bare shunt %p ", bs);
	jam_selectors(buf, &bs->our_client, &bs->peer_client);
	jam(buf, " => ");
	jam_enum_short(buf, &shunt_policy_names, bs->shunt_policy);
	jam(buf, " ");
	jam_policy_prio(buf, bs->policy_prio);
	jam(buf, "    %s", bs->why);
}

static void llog_bare_shunt(lset_t rc_flags, struct logger *logger,
			    const struct bare_shunt *bs, const char *op)
{
	LLOG_JAMBUF(rc_flags, logger, buf) {
		jam(buf, "%s ", op);
		jam_bare_shunt(buf, bs);
	}
}

static void dbg_bare_shunt(const char *op, const struct bare_shunt *bs)
{
	LSWDBGP(DBG_BASE, buf) {
		jam(buf, "%s ", op);
		jam_bare_shunt(buf, bs);
	}
}

/*
 * Note: "why" must be in stable storage (not auto, not heap)
 * because we use it indefinitely without copying or pfreeing.
 * Simple rule: use a string literal.
 */
void add_bare_shunt(const ip_selector *our_client,
		    const ip_selector *peer_client,
		    enum shunt_policy shunt_policy,
		    co_serial_t from_serialno,
		    const char *why, struct logger *logger)
{
	/* report any duplication; this should NOT happen */
	struct bare_shunt **bspp = bare_shunt_ptr(our_client, peer_client, why);

	if (bspp != NULL) {
		/* maybe: passert(bsp == NULL); */
		llog_bare_shunt(RC_LOG, logger, *bspp,
				"CONFLICTING existing");
	}

	struct bare_shunt *bs = alloc_thing(struct bare_shunt, "bare shunt");

	bs->why = why;
	bs->our_client = *our_client;
	bs->peer_client = *peer_client;
	const struct ip_protocol *transport_proto = selector_protocol(*our_client);
	pexpect(transport_proto == selector_protocol(*peer_client));
	bs->transport_proto = transport_proto;
	bs->policy_prio = BOTTOM_PRIO;
	bs->from_serialno = from_serialno;

	bs->shunt_policy = shunt_policy;
	bs->count = 0;
	bs->last_activity = mononow();

	bs->next = bare_shunts;
	bare_shunts = bs;
	dbg_bare_shunt("add", bs);

	/* report duplication; this should NOT happen */
	if (bspp != NULL) {
		llog_bare_shunt(RC_LOG, logger, bs,
				"CONFLICTING      new");
	}
}

static reqid_t get_proto_reqid(reqid_t base, const struct ip_protocol *proto)
{
	if (proto == &ip_protocol_ipcomp)
		return reqid_ipcomp(base);

	if (proto == &ip_protocol_esp)
		return reqid_esp(base);

	if (proto == &ip_protocol_ah)
		return reqid_ah(base);

	llog_passert(&global_logger, HERE,
		     "bad protocol %s", proto->name);
}

static const char *said_str(const ip_address dst,
			    const struct ip_protocol *sa_proto,
			    ipsec_spi_t spi,
			    said_buf *buf)
{
	ip_said said = said_from_address_protocol_spi(dst, sa_proto, spi);
	return str_said(&said, buf);
}

ipsec_spi_t get_ipsec_spi(ipsec_spi_t avoid,
			  const struct ip_protocol *proto,
			  const struct spd_route *sr,
			  struct logger *logger)
{
	passert(proto == &ip_protocol_ah || proto == &ip_protocol_esp);
	return kernel_ops_get_ipsec_spi(avoid, &sr->that.host->addr,
					&sr->this.host->addr, proto,
					get_proto_reqid(sr->reqid, proto),
					IPSEC_DOI_SPI_OUR_MIN, 0xffffffffU,
					"SPI", logger);
}

/* Generate Unique CPI numbers.
 * The result is returned as an SPI (4 bytes) in network order!
 * The real bits are in the nework-low-order 2 bytes.
 * Modelled on get_ipsec_spi, but range is more limited:
 * 256-61439.
 * If we can't find one easily, return 0 (a bad SPI,
 * no matter what order) indicating failure.
 */
ipsec_spi_t get_ipsec_cpi(const struct spd_route *sr, struct logger *logger)
{
	return kernel_ops_get_ipsec_spi(0,
					&sr->that.host->addr,
					&sr->this.host->addr,
					&ip_protocol_ipcomp,
					get_proto_reqid(sr->reqid, &ip_protocol_ipcomp),
					IPCOMP_FIRST_NEGOTIATED,
					IPCOMP_LAST_NEGOTIATED,
					"CPI", logger);
}

/*
 * Remove all characters but [-_.0-9a-zA-Z] from a character string.
 * Truncates the result if it would be too long.
 */

static void jam_clean_xauth_username(struct jambuf *buf,
				     const char *src,
				     struct logger *logger)
{
	bool changed = false;
	const char *dst = jambuf_cursor(buf);
	while (*src != '\0') {
		if ((*src >= '0' && *src <= '9') ||
		    (*src >= 'a' && *src <= 'z') ||
		    (*src >= 'A' && *src <= 'Z') ||
		    *src == '_' || *src == '-' || *src == '.') {
			jam_char(buf, *src);
		} else {
			changed = true;
		}
		src++;
	}
	if (changed || !jambuf_ok(buf)) {
		llog(RC_LOG, logger,
			    "Warning: XAUTH username changed from '%s' to '%s'",
			    src, dst);
	}
}

/*
 * fmt_common_shell_out: form the command string
 *
 * note: this mutates *st by calling get_sa_bundle_info().
 */
bool fmt_common_shell_out(char *buf,
			  size_t blen,
			  const struct connection *c,
			  const struct spd_route *sr,
			  struct state *st)
{
	struct jambuf jb = array_as_jambuf(buf, blen);
	const bool tunneling = LIN(POLICY_TUNNEL, c->policy);

	/* macros to jam definitions of various forms */
#	define JDstr(name, string)  jam(&jb, name "='%s' ", string)
#	define JDuint(name, u)  jam(&jb, name "=%u ", u)
#	define JDuint64(name, u)  jam(&jb, name "=%" PRIu64 " ", u)
#	define JDemitter(name, emitter)  { jam_string(&jb, name "='"); emitter; jam_string(&jb, "' "); }
#	define JDipaddr(name, addr)  JDemitter(name, { ip_address ta = addr; jam_address(&jb, &ta); } )

	JDstr("PLUTO_CONNECTION", c->name);
	JDstr("PLUTO_CONNECTION_TYPE", tunneling ? "tunnel" : "transport");
	JDstr("PLUTO_VIRT_INTERFACE", (c->xfrmi != NULL && c->xfrmi->name != NULL) ?
		c->xfrmi->name : "NULL");
	JDstr("PLUTO_INTERFACE", c->interface == NULL ? "NULL" : c->interface->ip_dev->id_rname);
	JDstr("PLUTO_XFRMI_ROUTE",  (c->xfrmi != NULL && c->xfrmi->if_id > 0) ? "yes" : "");

	if (address_is_specified(sr->this.host->nexthop)) {
		JDipaddr("PLUTO_NEXT_HOP", sr->this.host->nexthop);
	}

	JDipaddr("PLUTO_ME", sr->this.host->addr);
	JDemitter("PLUTO_MY_ID", jam_id_bytes(&jb, &c->local->host.id, jam_shell_quoted_bytes));
	JDemitter("PLUTO_MY_CLIENT", jam_selector_subnet(&jb, &sr->this.client));
	JDipaddr("PLUTO_MY_CLIENT_NET", selector_prefix(sr->this.client));
	JDipaddr("PLUTO_MY_CLIENT_MASK", selector_prefix_mask(sr->this.client));

	if (cidr_is_specified(c->local->config->client.host_vtiip)) {
		JDemitter("VTI_IP", jam_cidr(&jb, &c->local->config->client.host_vtiip));
	}

	if (cidr_is_specified(c->local->config->client.ifaceip)) {
		JDemitter("INTERFACE_IP", jam_cidr(&jb, &c->local->config->client.ifaceip));
	}

	JDuint("PLUTO_MY_PORT", sr->this.client.hport);
	JDuint("PLUTO_MY_PROTOCOL", sr->this.client.ipproto);
	JDuint("PLUTO_SA_REQID", sr->reqid);
	JDstr("PLUTO_SA_TYPE",
		st == NULL ? "none" :
		st->st_esp.present ? "ESP" :
		st->st_ah.present ? "AH" :
		st->st_ipcomp.present ? "IPCOMP" :
		"unknown?");

	JDipaddr("PLUTO_PEER", sr->that.host->addr);
	JDemitter("PLUTO_PEER_ID", jam_id_bytes(&jb, &c->remote->host.id, jam_shell_quoted_bytes));

	/* for transport mode, things are complicated */
	jam_string(&jb, "PLUTO_PEER_CLIENT='");
	if (!tunneling && st != NULL && LHAS(st->hidden_variables.st_nat_traversal, NATED_PEER)) {
		/* pexpect(selector_eq_address(sr->that.client, sr->that.host->addr)); */
		jam_address(&jb, &sr->that.host->addr);
		jam(&jb, "/%d", address_type(&sr->this.host->addr)->mask_cnt/*32 or 128*/);
	} else {
		jam_selector_subnet(&jb, &sr->that.client);
	}
	jam_string(&jb, "' ");

	JDipaddr("PLUTO_PEER_CLIENT_NET",
		(!tunneling && st != NULL && LHAS(st->hidden_variables.st_nat_traversal, NATED_PEER)) ?
			sr->that.host->addr : selector_prefix(sr->that.client));

	JDipaddr("PLUTO_PEER_CLIENT_MASK", selector_prefix_mask(sr->that.client));
	JDuint("PLUTO_PEER_PORT", sr->that.client.hport);
	JDuint("PLUTO_PEER_PROTOCOL", sr->that.client.ipproto);

	jam_string(&jb, "PLUTO_PEER_CA='");
	for (struct pubkey_list *p = pluto_pubkeys; p != NULL; p = p->next) {
		struct pubkey *key = p->key;
		int pathlen;	/* value ignored */
		if (key->content.type == &pubkey_type_rsa &&
		    same_id(&c->remote->host.id, &key->id) &&
		    trusted_ca(key->issuer, ASN1(sr->that.config->host.ca), &pathlen)) {
			jam_dn_or_null(&jb, key->issuer, "", jam_shell_quoted_bytes);
			break;
		}
	}
	jam_string(&jb, "' ");

	JDstr("PLUTO_STACK", kernel_ops->updown_name);

	if (c->metric != 0) {
		jam(&jb, "PLUTO_METRIC=%d ", c->metric);
	}

	if (c->connmtu != 0) {
		jam(&jb, "PLUTO_MTU=%d ", c->connmtu);
	}

	JDuint64("PLUTO_ADDTIME", st == NULL ? (uint64_t)0 : st->st_esp.add_time);
	JDemitter("PLUTO_CONN_POLICY",	jam_connection_policies(&jb, c));
	JDemitter("PLUTO_CONN_KIND", jam_enum(&jb, &connection_kind_names, c->kind));
	jam(&jb, "PLUTO_CONN_ADDRFAMILY='ipv%d' ", address_type(&sr->this.host->addr)->ip_version);
	JDuint("XAUTH_FAILED", (st != NULL && st->st_xauth_soft) ? 1 : 0);

	if (st != NULL && st->st_xauth_username[0] != '\0') {
		JDemitter("PLUTO_USERNAME", jam_clean_xauth_username(&jb, st->st_xauth_username, st->st_logger));
	}

	if (address_is_specified(sr->this.host_srcip)) {
		JDipaddr("PLUTO_MY_SOURCEIP", sr->this.host_srcip);
		if (st != NULL)
			JDstr("PLUTO_MOBIKE_EVENT",
			    st->st_mobike_del_src_ip ? "yes" : "");
	}

	JDuint("PLUTO_IS_PEER_CISCO", c->remotepeertype /* ??? kind of odd printing an enum with %u */);
	JDstr("PLUTO_PEER_DNS_INFO", (st != NULL && st->st_seen_cfg_dns != NULL) ? st->st_seen_cfg_dns : "");
	JDstr("PLUTO_PEER_DOMAIN_INFO", (st != NULL && st->st_seen_cfg_domains != NULL) ? st->st_seen_cfg_domains : "");
	JDstr("PLUTO_PEER_BANNER", (st != NULL && st->st_seen_cfg_banner != NULL) ? st->st_seen_cfg_banner : "");
	JDuint("PLUTO_CFG_SERVER", sr->this.modecfg_server);
	JDuint("PLUTO_CFG_CLIENT", sr->this.modecfg_client);
#ifdef HAVE_NM
	JDuint("PLUTO_NM_CONFIGURED", c->nmconfigured);
#endif

	const struct ipsec_proto_info *const first_pi =
		st == NULL ? NULL :
		st->st_esp.present ? &st->st_esp :
		st->st_ah.present ? &st->st_ah :
		st->st_ipcomp.present ? &st->st_ipcomp :
		NULL;

	if (first_pi != NULL) {
		/*
		 * note: this mutates *st by calling get_sa_bundle_info
		 *
		 * XXX: does the get_sa_bundle_info() call order matter? Should this
		 * be a single "atomic" call?
		 */
		if (get_sa_bundle_info(st, true, NULL)) {
			JDuint64("PLUTO_INBYTES", first_pi->inbound.bytes);
		}
		if (get_sa_bundle_info(st, false, NULL)) {
			JDuint64("PLUTO_OUTBYTES", first_pi->outbound.bytes);
		}
	}

	if (c->nflog_group != 0) {
		jam(&jb, "NFLOG=%d ", c->nflog_group);
	}

	if (c->sa_marks.in.val != 0) {
		jam(&jb, "CONNMARK_IN=%" PRIu32 "/%#08" PRIx32 " ",
		    c->sa_marks.in.val, c->sa_marks.in.mask);
	}
	if (c->sa_marks.out.val != 0 && c->xfrmi == NULL) {
		jam(&jb, "CONNMARK_OUT=%" PRIu32 "/%#08" PRIx32 " ",
		    c->sa_marks.out.val, c->sa_marks.out.mask);
	}
	if (c->xfrmi != NULL) {
		if (c->sa_marks.out.val != 0) {
			/* user configured XFRMI_SET_MARK (a.k.a. output mark) add it */
			jam(&jb, "PLUTO_XFRMI_FWMARK='%" PRIu32 "/%#08" PRIx32 "' ",
			    c->sa_marks.out.val, c->sa_marks.out.mask);
		} else if (address_in_selector_range(sr->that.host->addr, sr->that.client)) {
			jam(&jb, "PLUTO_XFRMI_FWMARK='%" PRIu32 "/0xffffffff' ",
			    c->xfrmi->if_id);
		} else {
			address_buf bpeer;
			selector_buf peerclient_str;
			dbg("not adding PLUTO_XFRMI_FWMARK. PLUTO_PEER=%s is not inside PLUTO_PEER_CLIENT=%s",
			    str_address(&sr->that.host->addr, &bpeer),
			    str_selector_subnet_port(&sr->that.client, &peerclient_str));
			jam(&jb, "PLUTO_XFRMI_FWMARK='' ");
		}
	}
	JDstr("VTI_IFACE", c->vti_iface ? c->vti_iface : "");
	JDstr("VTI_ROUTING", bool_str(c->vti_routing));
	JDstr("VTI_SHARED", bool_str(c->vti_shared));

	if (sr->this.has_cat) {
		jam_string(&jb, "CAT='YES' ");
	}

	jam(&jb, "SPI_IN=0x%x SPI_OUT=0x%x " /* SPI_IN SPI_OUT */,
		first_pi == NULL ? 0 : ntohl(first_pi->outbound.spi),
		first_pi == NULL ? 0 : ntohl(first_pi->inbound.spi));

	return jambuf_ok(&jb);

#	undef JDstr
#	undef JDuint
#	undef JDuint64
#	undef JDemitter
#	undef JDipaddr
}

bool do_command(const struct connection *c,
		const struct spd_route *sr,
		const char *verb,
		struct state *st,
		/* either st, or c's logger */
		struct logger *logger)
{
	/*
	 * Support for skipping updown, eg leftupdown=""
	 * Useful on busy servers that do not need to use updown for anything
	 */
	const char *updown = sr->this.config->client.updown;
	if (updown == NULL || streq(updown, "%disabled")) {
		dbg("kernel: skipped updown %s command - disabled per policy", verb);
		return true;
	}
	dbg("kernel: running updown command \"%s\" for verb %s ", updown, verb);

	/*
	 * Figure out which verb suffix applies.
	 * NOTE: this is a duplicate of code in mast_do_command_vs.
	 */
	const char *verb_suffix;

	{
		const char *hs, *cs;
		const struct ip_info *afi = address_type(&sr->this.host->addr);
		if (afi == NULL) {
			llog_pexpect(logger, HERE, "unknown address family");
			return false;
		}

		switch (afi->af) {
		case AF_INET:
			hs = "-host";
			cs = "-client";
			break;
		case AF_INET6:
			hs = "-host-v6";
			cs = "-client-v6";
			break;
		default:
			bad_case(afi->af);
		}
		verb_suffix = selector_range_eq_address(sr->this.client, sr->this.host->addr) ? hs : cs;
	}

	dbg("kernel: command executing %s%s", verb, verb_suffix);

	char common_shell_out_str[2048];
	if (!fmt_common_shell_out(common_shell_out_str,
				  sizeof(common_shell_out_str), c, sr,
				  st)) {
		llog(RC_LOG_SERIOUS, logger,
			    "%s%s command too long!", verb,
			    verb_suffix);
		return false;
	}

	/* must free */
	char *cmd = alloc_printf("2>&1 "      /* capture stderr along with stdout */
				 "PLUTO_VERB='%s%s' "
				 "%s"         /* other stuff */
				 "%s",        /* actual script */
				 verb, verb_suffix,
				 common_shell_out_str,
				 updown);
	if (cmd == NULL) {
		llog(RC_LOG_SERIOUS, logger,
			    "%s%s command too long!", verb,
			    verb_suffix);
		return false;
	}

	bool ok = invoke_command(verb, verb_suffix, cmd, logger);
	pfree(cmd);
	return ok;
}

bool invoke_command(const char *verb, const char *verb_suffix, const char *cmd,
		    struct logger *logger)
{
#	define CHUNK_WIDTH	80	/* units for cmd logging */
	if (DBGP(DBG_BASE)) {
		int slen = strlen(cmd);
		int i;

		DBG_log("executing %s%s: %s",
			verb, verb_suffix, cmd);
		DBG_log("popen cmd is %d chars long", slen);
		for (i = 0; i < slen; i += CHUNK_WIDTH)
			DBG_log("cmd(%4d):%.*s:", i,
				slen-i < CHUNK_WIDTH? slen-i : CHUNK_WIDTH,
				&cmd[i]);
	}
#	undef CHUNK_WIDTH


	{
		/*
		 * invoke the script, catching stderr and stdout
		 * It may be of concern that some file descriptors will
		 * be inherited.  For the ones under our control, we
		 * have done fcntl(fd, F_SETFD, FD_CLOEXEC) to prevent this.
		 * Any used by library routines (perhaps the resolver or
		 * syslog) will remain.
		 */
		FILE *f = popen(cmd, "r");

		if (f == NULL) {
#ifdef HAVE_BROKEN_POPEN
			/*
			 * See bug #1067  Angstrom Linux on a arm7 has no
			 * popen()
			 */
			if (errno == ENOSYS) {
				/*
				 * Try system(), though it will not give us
				 * output
				 */
				DBG_log("unable to popen(), falling back to system()");
				system(cmd);
				return true;
			}
#endif
			llog(RC_LOG_SERIOUS, logger,
				    "unable to popen %s%s command",
				    verb, verb_suffix);
			return false;
		}

		/* log any output */
		for (;; ) {
			/*
			 * if response doesn't fit in this buffer, it will
			 * be folded
			 */
			char resp[256];

			if (fgets(resp, sizeof(resp), f) == NULL) {
				if (ferror(f)) {
					llog_error(logger, errno,
						   "fgets failed on output of %s%s command",
						   verb, verb_suffix);
					pclose(f);
					return false;
				} else {
					passert(feof(f));
					break;
				}
			} else {
				char *e = resp + strlen(resp);

				if (e > resp && e[-1] == '\n')
					e[-1] = '\0'; /* trim trailing '\n' */
				llog(RC_LOG, logger, "%s%s output: %s", verb,
					    verb_suffix, resp);
			}
		}

		/* report on and react to return code */
		{
			int r = pclose(f);

			if (r == -1) {
				llog_error(logger, errno,
					   "pclose failed for %s%s command",
					   verb, verb_suffix);
				return false;
			} else if (WIFEXITED(r)) {
				if (WEXITSTATUS(r) != 0) {
					llog(RC_LOG_SERIOUS, logger,
						    "%s%s command exited with status %d",
						    verb, verb_suffix,
						    WEXITSTATUS(r));
					return false;
				}
			} else if (WIFSIGNALED(r)) {
				llog(RC_LOG_SERIOUS, logger,
					    "%s%s command exited with signal %d",
					    verb, verb_suffix, WTERMSIG(r));
				return false;
			} else {
				llog(RC_LOG_SERIOUS, logger,
					    "%s%s command exited with unknown status %d",
					    verb, verb_suffix, r);
				return false;
			}
		}
	}
	return true;
}

/*
 * Build an array of encapsulation rules/tmpl.  Order things
 * inner-most to outer-most so the last entry is what will go across
 * the wire.  A -1 entry of the packet to be encapsulated is implied.
 */

static struct kernel_policy kernel_policy_from_spd(lset_t policy,
						   const struct spd_route *spd,
						   enum encap_mode mode,
						   enum encap_direction direction)
{
	/*
	 * With pfkey and transport mode with nat-traversal we need to
	 * change the remote IPsec SA to point to external ip of the
	 * peer.  Here we substitute real client ip with NATD ip.
	 *
	 * Bug #1004 fix.
	 *
	 * There really isn't "client" with XFRM and transport mode so
	 * eroute must be done to natted, visible ip. If we don't hide
	 * internal IP, communication doesn't work.
	 */
	ip_selector remote_client;
	switch (mode) {
	case ENCAP_MODE_TUNNEL:
		remote_client = spd->that.client;
		break;
	case ENCAP_MODE_TRANSPORT:
		remote_client = selector_from_address_protocol_port(spd->that.host->addr,
								    selector_protocol(spd->that.client),
								    selector_port(spd->that.client));
		break;
	default:
		bad_case(mode);
	}

	const struct end *src;
	const struct end *dst;
	ip_selector src_route, dst_route;
	switch (direction) {
	case ENCAP_DIRECTION_INBOUND:
		src = &spd->that;
		dst = &spd->this;
		src_route = remote_client;
		dst_route = dst->client;
		break;
	case ENCAP_DIRECTION_OUTBOUND:
		src = &spd->this;
		dst = &spd->that;
		src_route = src->client;
		dst_route = remote_client;
		break;
	default:
		bad_case(direction);
	}

	struct kernel_policy kernel_policy = {
		.src.client = src->client,
		.dst.client = dst->client,
		.src.host = src->host->addr,
		.dst.host = dst->host->addr,
		.src.route = src_route,
		.dst.route = dst_route,
		.mode = mode,
		.nr_rules = 0,
	};

	/*
	 * Construct the kernel policy rules inner-to-outer (matching
	 * the flow of an outgoing packet).
	 *
	 * Note: the order is fixed: compress -> encrypt ->
	 * authenticate.
	 *
	 * Note: only the inner most policy rule gets the tunnel bit
	 * (aka worm) (currently the global .mode is set and kernel
	 * backends handle this).
	 *
	 * Note: the stack order matches kernel_sa's array.
	 */

	struct kernel_policy_rule *last = kernel_policy.rule; /* rule[0] is empty */
	if (policy & POLICY_COMPRESS) {
		last++;
		last->reqid = reqid_ipcomp(spd->reqid);
		last->proto = ENCAP_PROTO_IPCOMP;
	}
	if (policy & POLICY_ENCRYPT) {
		last++;
		last->reqid = reqid_esp(spd->reqid);
		last->proto = ENCAP_PROTO_ESP;
	}
	if (policy & POLICY_AUTHENTICATE) {
		last++;
		last->reqid = reqid_ah(spd->reqid);
		last->proto = ENCAP_PROTO_AH;
	}

	passert(last < kernel_policy.rule + elemsof(kernel_policy.rule));
	kernel_policy.nr_rules = last - kernel_policy.rule;
	passert(kernel_policy.nr_rules < elemsof(kernel_policy.rule));

	return kernel_policy;
}

static struct kernel_policy kernel_policy_from_state(const struct state *st,
						     const struct spd_route *spd,
						     enum encap_direction direction)
{
	bool tunnel = false;
	lset_t policy = LEMPTY;
	if (st->st_ipcomp.present) {
		policy |= POLICY_COMPRESS;
		tunnel |= (st->st_ipcomp.attrs.mode == ENCAPSULATION_MODE_TUNNEL);
	}

	if (st->st_esp.present) {
		policy |= POLICY_ENCRYPT;
		tunnel |= (st->st_esp.attrs.mode == ENCAPSULATION_MODE_TUNNEL);
	}

	if (st->st_ah.present) {
		policy |= POLICY_AUTHENTICATE;
		tunnel |= (st->st_ah.attrs.mode == ENCAPSULATION_MODE_TUNNEL);
	}

	enum encap_mode mode = (tunnel ? ENCAP_MODE_TUNNEL : ENCAP_MODE_TRANSPORT);
	struct kernel_policy kernel_policy = kernel_policy_from_spd(policy, spd, mode, direction);
	return kernel_policy;
}

/*
 * handle co-terminal attempt of the "near" kind
 *
 * Note: it mutates both inside and outside
 */

enum routability {
	route_impossible,
	route_easy,
	route_nearconflict,
	route_farconflict,
	route_unnecessary
};

static enum routability note_nearconflict(struct connection *outside,	/* CK_PERMANENT */
					  struct connection *inside,	/* CK_TEMPLATE */
					  struct logger *logger)
{
	/*
	 * this is a co-terminal attempt of the "near" kind.
	 * when chaining, we chain from inside to outside
	 *
	 * XXX permit multiple deep connections?
	 */
	passert(inside->policy_next == NULL);

	inside->policy_next = outside;

	/*
	 * since we are going to steal the eroute from the secondary
	 * policy, we need to make sure that it no longer thinks that
	 * it owns the eroute.
	 */
	set_spd_routing(&outside->spd, RT_UNROUTED_KEYED);
	set_spd_owner(&outside->spd, SOS_NOBODY);

	/*
	 * set the priority of the new eroute owner to be higher
	 * than that of the current eroute owner
	 */
	inside->policy_prio = outside->policy_prio + 1;

	connection_buf inst;
	llog(RC_LOG_SERIOUS, logger,
	     "conflict on eroute (%s), switching eroute to %s and linking %s",
	     str_connection_instance(inside, &inst),
	     inside->name, outside->name);

	return route_nearconflict;
}

/*
 * Note: this may mutate c
 */

static enum routability could_route(struct connection *c, struct logger *logger)
{
	esb_buf b;
	dbg("kernel: could_route called for %s; kind=%s that.has_client=%s oppo=%s this.host_port=%u sec_label="PRI_SHUNK,
	    c->name,
	    enum_show(&connection_kind_names, c->kind, &b),
	    bool_str(c->spd.that.has_client),
	    bool_str(c->policy & POLICY_OPPORTUNISTIC),
	    c->spd.this.host->port,
	    pri_shunk(c->config->sec_label));

	/* it makes no sense to route a connection that is ISAKMP-only */
	if (!NEVER_NEGOTIATE(c->policy) && !HAS_IPSEC_POLICY(c->policy)) {
		llog(RC_ROUTE, logger,
			    "cannot route an ISAKMP-only connection");
		return route_impossible;
	}

	/*
	 * if this is a transport SA, and overlapping SAs are supported, then
	 * this route is not necessary at all.
	 */
	if (kernel_ops->overlap_supported && !LIN(POLICY_TUNNEL, c->policy))
		return route_unnecessary;

	/*
	 * If this is a template connection, we cannot route.
	 * However, opportunistic and sec_label templates can be
	 * routed (as in install the policy).
	 */
	if (!c->spd.that.has_client &&
	    c->kind == CK_TEMPLATE &&
	    !(c->policy & POLICY_OPPORTUNISTIC) &&
	    c->config->sec_label.len == 0) {
		policy_buf pb;
		llog(RC_ROUTE, logger,
		     "cannot route template policy of %s",
		     str_connection_policies(c, &pb));
		return route_impossible;
	}

	struct spd_route *esr, *rosr;
	struct connection *ero;		/* who, if anyone, owns our eroute? */
	struct connection *ro = route_owner(c, &c->spd, &rosr, &ero, &esr);	/* who owns our route? */

	/*
	 * If there is already a route for peer's client subnet and it
	 * disagrees about interface or nexthop, we cannot steal it.
	 *
	 * Note: if this connection is already routed (perhaps for
	 * another state object), the route will agree.  This is as it
	 * should be -- it will arise during rekeying.
	 */

	if (ro != NULL &&
	    (ro->interface->ip_dev != c->interface->ip_dev ||
	     !address_eq_address(ro->local->host.nexthop, c->local->host.nexthop))) {

		bool compatible_overlap = (kernel_ops->overlap_supported &&
					   c != NULL &&
					   ero != NULL &&
					   c != ero &&
					   LIN(POLICY_OVERLAPIP, c->policy & ero->policy));

		if (!compatible_overlap) {
			/*
			 * Another connection is already using the
			 * eroute.
			 *
			 * TODO: XFRM supports this. For now, only
			 * allow this for OE
			 */
			if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
				connection_buf cib;
				llog(RC_LOG_SERIOUS, logger,
				     "cannot route -- route already in use for "PRI_CONNECTION"",
				     pri_connection(ro, &cib));
				return route_impossible;
			} else {
				connection_buf cib;
				llog(RC_LOG_SERIOUS, logger,
				     "cannot route -- route already in use for "PRI_CONNECTION" - but allowing anyway",
				     pri_connection(ro, &cib));
			}
		}
	}

	/* if there is an eroute for another connection, there is a problem */
	if (ero != NULL && ero != c) {
		/*
		 * note, wavesec (PERMANENT) goes *outside* and
		 * OE goes *inside* (TEMPLATE)
		 */
		if (ero->kind == CK_PERMANENT &&
			c->kind == CK_TEMPLATE) {
			return note_nearconflict(ero, c, logger);
		} else if (c->kind == CK_PERMANENT &&
			ero->kind == CK_TEMPLATE) {
			return note_nearconflict(c, ero, logger);
		}

		/* look along the chain of policies for one with the same name */

		for (struct connection *ep = ero; ep != NULL; ep = ero->policy_next) {
			if (ep->kind == CK_TEMPLATE &&
				streq(ep->name, c->name))
				return route_easy;
		}

		/*
		 * If we fell off the end of the list, then we found no
		 * TEMPLATE so there must be a conflict that we can't resolve.
		 * As the names are not equal, then we aren't
		 * replacing/rekeying.
		 *
		 * ??? should there not be a conflict if ANYTHING in the list,
		 * other than c, conflicts with c?
		 */

		if (LDISJOINT(POLICY_OVERLAPIP, c->policy | ero->policy) && c->config->sec_label.len == 0) {
			/*
			 * another connection is already using the eroute,
			 * TODO: XFRM apparently can do this though
			 */
			connection_buf erob;
			llog(RC_LOG_SERIOUS, logger,
				    "cannot install eroute -- it is in use for "PRI_CONNECTION" #%lu",
				    pri_connection(ero, &erob), esr->eroute_owner);
			return route_impossible;
		}

		connection_buf erob;
		dbg("kernel: overlapping permitted with "PRI_CONNECTION" #%lu",
		    pri_connection(ero, &erob), esr->eroute_owner);
	}
	return route_easy;
}

bool trap_connection(struct connection *c)
{
	enum routability r = could_route(c, c->logger);

	switch (r) {
	case route_impossible:
		return false;

	case route_easy:
	case route_nearconflict:
		if (c->config->ike_version == IKEv2 && c->config->sec_label.len > 0) {
			/*
			 * IKEv2 security labels are treated
			 * specially: this allocates and installs a
			 * full REQID, the route_and_eroute() call
			 * does not (and who knows what else it does).
			 */
			dbg("kernel: installing SE trap policy");
			return install_sec_label_connection_policies(c, c->logger);
		} else if (c->spd.routing >= RT_ROUTED_TUNNEL) {
			/*
			 * RT_ROUTED_TUNNEL is treated specially: we
			 * don't override because we don't want to
			 * lose track of the IPSEC_SAs etc.
			 *
			 * ??? The test treats RT_UNROUTED_KEYED
			 * specially too.
			 *
			 * XXX: ah, I was wondering ...
			 */
			dbg("kernel: skipping trap policy as >=ROUTED_TUNNEL");
			return true;
		} else {
			return route_and_eroute(c, &c->spd, NULL, c->logger);
		}

	case route_farconflict:
		return false;

	case route_unnecessary:
		return true;

	default:
		bad_case(r);
	}
}

static bool sag_eroute(const struct state *st,
		       const struct spd_route *sr,
		       enum kernel_policy_op op,
		       const char *opname)
{
	struct connection *c = st->st_connection;

	/*
	 * Figure out the SPI and protocol (in two forms) for the
	 * outer transformation.
	 */

	struct kernel_policy kernel_policy =
		kernel_policy_from_state(st, sr, ENCAP_DIRECTION_OUTBOUND);
	/* check for no transform at all */
	passert(kernel_policy.nr_rules > 0);

	pexpect(op & KERNEL_POLICY_OUTBOUND);

	/* hack */
	char why[256];
	snprintf(why, sizeof(why), "%s() %s", __func__, opname);

	return eroute_connection(op, why, sr, SHUNT_UNSET,
				 &kernel_policy,
				 calculate_sa_prio(c, false),
				 &c->sa_marks, c->xfrmi,
				 HUNK_AS_SHUNK(c->config->sec_label),
				 st->st_logger);
}

void migration_up(struct child_sa *child)
{
	struct connection *c = child->sa.st_connection;
	for (struct spd_route *sr = &c->spd; sr != NULL; sr = sr->spd_next) {
#ifdef IPSEC_CONNECTION_LIMIT
		num_ipsec_eroute++;
#endif
		/* do now so route_owner won't find us */
		set_spd_routing(sr, RT_ROUTED_TUNNEL);
		do_command(c, sr, "up", &child->sa, child->sa.st_logger);
		do_command(c, sr, "route", &child->sa, child->sa.st_logger);
	}
}

void migration_down(struct child_sa *child)
{
	struct connection *c = child->sa.st_connection;
	for (struct spd_route *sr = &c->spd; sr != NULL; sr = sr->spd_next) {
		enum routing_t cr = sr->routing;

#ifdef IPSEC_CONNECTION_LIMIT
		if (erouted(cr))
			num_ipsec_eroute--;
#endif
		/* do now so route_owner won't find us */
		set_spd_routing(sr, RT_UNROUTED);

		/* only unroute if no other connection shares it */
		if (routed(cr) && route_owner(c, sr, NULL, NULL, NULL) == NULL) {
			do_command(c, sr, "down", &child->sa, child->sa.st_logger);
			child->sa.st_mobike_del_src_ip = true;
			do_command(c, sr, "unroute", &child->sa, child->sa.st_logger);
			child->sa.st_mobike_del_src_ip = false;
		}
	}
}

/*
 * Delete any eroute for a connection and unroute it if route isn't
 * shared.
 */
void unroute_connection(struct connection *c)
{
	for (struct spd_route *sr = &c->spd; sr != NULL; sr = sr->spd_next) {
		enum routing_t cr = sr->routing;

		if (erouted(cr)) {
			/* cannot handle a live one */
			passert(cr != RT_ROUTED_TUNNEL);
			/*
			 * XXX: note the hack where missing inbound
			 * policies are ignored.  The connection
			 * should know if there's an inbound policy,
			 * in fact the connection shouldn't even have
			 * inbound policies, just the state.
			 */
			bare_policy_op(KP_DELETE_OUTBOUND,
				       EXPECT_NO_INBOUND,
				       c, sr, RT_UNROUTED,
				       "unrouting connection",
				       c->logger);
#ifdef IPSEC_CONNECTION_LIMIT
			num_ipsec_eroute--;
#endif
		}

		/* do now so route_owner won't find us */
		set_spd_routing(sr, RT_UNROUTED);

		/* only unroute if no other connection shares it */
		if (routed(cr) && route_owner(c, sr, NULL, NULL, NULL) == NULL) {
			do_command(c, sr, "unroute", NULL, c->logger);
		}
	}
}

#include "kernel_alg.h"

/* find an entry in the bare_shunt table.
 * Trick: return a pointer to the pointer to the entry;
 * this allows the entry to be deleted.
 */
struct bare_shunt **bare_shunt_ptr(const ip_selector *our_client,
				   const ip_selector *peer_client,
				   const char *why)

{
	const struct ip_protocol *transport_proto = protocol_by_ipproto(our_client->ipproto);
	pexpect(peer_client->ipproto == transport_proto->ipproto);

	selectors_buf sb;
	dbg("kernel: %s looking for %s",
	    why, str_selectors(our_client, peer_client, &sb));
	for (struct bare_shunt **pp = &bare_shunts; *pp != NULL; pp = &(*pp)->next) {
		struct bare_shunt *p = *pp;
		dbg_bare_shunt("comparing", p);
		if (transport_proto == p->transport_proto &&
		    selector_range_eq_selector_range(*our_client, p->our_client) &&
		    selector_range_eq_selector_range(*peer_client, p->peer_client)) {
			return pp;
		}
	}
	return NULL;
}

/* free a bare_shunt entry, given a pointer to the pointer */
static void free_bare_shunt(struct bare_shunt **pp)
{
	struct bare_shunt *p;

	passert(pp != NULL);

	p = *pp;

	*pp = p->next;
	dbg_bare_shunt("delete", p);
	pfree(p);
}

unsigned shunt_count(void)
{
	unsigned i = 0;

	for (const struct bare_shunt *bs = bare_shunts; bs != NULL; bs = bs->next)
	{
		i++;
	}

	return i;
}

void show_shunt_status(struct show *s)
{
	show_separator(s);
	show_comment(s, "Bare Shunt list:");
	show_separator(s);

	for (const struct bare_shunt *bs = bare_shunts; bs != NULL; bs = bs->next) {
		/* Print interesting fields.  Ignore count and last_active. */
		selector_buf ourb;
		selector_buf peerb;
		said_buf sat;
		policy_prio_buf prio;

		/* XXX: hack to preserve output */
		ip_said said = said_from_address_protocol_spi(selector_type(&bs->our_client)->address.unspec,
							      &ip_protocol_internal,
							      htonl(shunt_policy_spi(bs->shunt_policy)));

		show_comment(s, "%s -%d-> %s => %s %s    %s",
			     str_selector_subnet_port(&(bs)->our_client, &ourb),
			     bs->transport_proto->ipproto,
			     str_selector_subnet_port(&(bs)->peer_client, &peerb),
			     str_said(&said, &sat),
			     str_policy_prio(bs->policy_prio, &prio),
			     bs->why);
	}
}

static bool delete_bare_shunt_kernel_policy(const struct bare_shunt *bsp,
					    struct logger *logger,
					    where_t where)
{
	/* this strips the port (but why?) */
	const struct ip_protocol *transport_proto = bsp->transport_proto;
	ip_address src_address = selector_prefix(bsp->our_client);
	ip_address dst_address = selector_prefix(bsp->peer_client);
	ip_selector src = selector_from_address_protocol(src_address, transport_proto);
	ip_selector dst = selector_from_address_protocol(dst_address, transport_proto);
	selectors_buf sb;
	dbg("kernel: deleting bare shunt %s from kernel "PRI_WHERE,
	    str_selectors(&src, &dst, &sb), pri_where(where));
	/* assume low code logged action */
	return raw_policy(KP_DELETE_OUTBOUND,
			  EXPECT_KERNEL_POLICY_OK,
			  &src, &dst,
			  SHUNT_PASS,
			  /*kernel_policy*/NULL/*delete->no-policy-rules*/,
			  deltatime(SHUNT_PATIENCE),
			  0, /* we don't know connection for priority yet */
			  /*sa_marks+xfrmi*/NULL,NULL,
			  null_shunk, logger,
			  "%s() %s", __func__, where->func);
}

/*
 * Clear any bare shunt holds that overlap with the network we have
 * just routed.  We only consider "narrow" holds: ones for a single
 * address to single address.
 */
static void clear_narrow_holds(const ip_selector *src_client,
			       const ip_selector *dst_client,
			       struct logger *logger)
{
	const ip_protocol *transport_proto = protocol_by_ipproto(src_client->ipproto);
	struct bare_shunt **bspp = &bare_shunts;
	while (*bspp != NULL) {
		/*
		 * is bsp->{local,remote} within {local,remote}.
		 */
		struct bare_shunt *bsp = *bspp;
		if (bsp->shunt_policy == SHUNT_HOLD &&
		    transport_proto == bsp->transport_proto &&
		    selector_in_selector(bsp->our_client, *src_client) &&
		    selector_in_selector(bsp->peer_client, *dst_client)) {
			if (!delete_bare_shunt_kernel_policy(bsp, logger, HERE)) {
				/* ??? we could not delete a bare shunt */
				llog_bare_shunt(RC_LOG, logger, bsp, "failed to delete");
			}
			free_bare_shunt(bspp);
		} else {
			bspp = &(*bspp)->next;
		}
	}
}

/*
 * If there's kernel policy and/or a bare shunt, delete it.  If there
 * isn't ignore the error.
 */

bool flush_bare_shunt(const ip_address *src_address,
		      const ip_address *dst_address,
		      const struct ip_protocol *transport_proto,
		      enum expect_kernel_policy expect_kernel_policy,
		      const char *why, struct logger *logger)
{
	const struct ip_info *afi = address_type(src_address);
	pexpect(afi == address_type(dst_address));
	/* port? assumed wide? */
	ip_selector src = selector_from_address_protocol(*src_address, transport_proto);
	ip_selector dst = selector_from_address_protocol(*dst_address, transport_proto);

	/* assume low code logged action */
	selectors_buf sb;
	dbg("kernel: deleting bare shunt %s from kernel for %s",
	    str_selectors(&src, &dst, &sb), why);
	/* assume low code logged action */
	bool ok = raw_policy(KP_DELETE_OUTBOUND, expect_kernel_policy,
			     &src, &dst,
			     SHUNT_PASS,
			     /*kernel_policy*/NULL/*delete->no-policy-rules*/,
			     deltatime(SHUNT_PATIENCE),
			     0, /* we don't know connection for priority yet */
			     /*sa_marks+xfrmi*/NULL,NULL,
			     null_shunk, logger,
			     "%s() %s", __func__, why);
	if (!ok) {
		/* did/should kernel log this? */
		selectors_buf sb;
		llog(RC_LOG, logger,
		     "delete kernel shunt %s failed - deleting from pluto shunt table",
		     str_selectors_sensitive(&src, &dst, &sb));
	}

	/*
	 * We can have proto mismatching acquires with xfrm - this is
	 * a bad workaround.
	 *
	 * ??? what is the nature of those mismatching acquires?
	 *
	 * XXX: for instance, when whack initiates an OE connection.
	 * There is no kernel-acquire shunt to remove.
	 */

	struct bare_shunt **bs_pp = bare_shunt_ptr(&src, &dst, why);
	if (bs_pp == NULL) {
		selectors_buf sb;
		llog(RC_LOG, logger,
		     "can't find expected bare shunt to delete: %s",
		     str_selectors_sensitive(&src, &dst, &sb));
		return ok;
	}

	free_bare_shunt(bs_pp);
	return ok;
}

bool install_sec_label_connection_policies(struct connection *c, struct logger *logger)
{
	connection_buf cb;
	dbg("kernel: %s() "PRI_CO" "PRI_CO" "PRI_CONNECTION" routed %s sec_label="PRI_SHUNK,
	    __func__, pri_co(c->serialno), pri_co(c->serial_from),
	    pri_connection(c, &cb),
	    enum_name(&routing_story, c->spd.routing),
	    pri_shunk(c->config->sec_label));

	if (!pexpect(c->config->ike_version == IKEv2) ||
	    !pexpect(c->config->sec_label.len > 0) ||
	    !pexpect(c->kind == CK_TEMPLATE)) {
		return false;
	}

	if (c->spd.routing != RT_UNROUTED) {
		dbg("kernel: %s() connection already routed", __func__);
		return true;
	}

	enum encap_mode mode = (c->policy & POLICY_TUNNEL ? ENCAP_MODE_TUNNEL :
				ENCAP_MODE_TRANSPORT);

	uint32_t priority = calculate_sa_prio(c, /*oe_shunt*/false);

	/*
	 * SE installs both an outgoing and incoming policy.  Normal
	 * connections do not.
	 */
	FOR_EACH_THING(direction, ENCAP_DIRECTION_OUTBOUND, ENCAP_DIRECTION_INBOUND) {
		bool inbound = (direction == ENCAP_DIRECTION_INBOUND);
		const struct kernel_policy kernel_policy =
			kernel_policy_from_spd(c->policy, &c->spd, mode, direction);
		if (kernel_policy.nr_rules == 0) {
			/* XXX: log? */
			return false;
		}
		if (!raw_policy(inbound ? KP_ADD_INBOUND : KP_ADD_OUTBOUND,
				EXPECT_KERNEL_POLICY_OK,
				&kernel_policy.src.client, &kernel_policy.dst.client,
				SHUNT_UNSET,
				&kernel_policy,
				/*use_lifetime*/deltatime(0),
				/*sa_priority*/priority,
				/*sa_marks+xfrmi*/NULL,NULL,
				/*sec_label*/HUNK_AS_SHUNK(c->config->sec_label),
				/*logger*/logger,
				"%s() security label policy", __func__)) {
			if (inbound) {
				/*
				 * Need to pull the just installed
				 * outbound policy.
				 *
				 * XXX: this call highlights why
				 * having both KP_*_REVERSED and and
				 * reversed parameters is just so
				 * lame.  raw_policy can handle this.
				 */
				dbg("pulling previously installed outbound policy");
				pexpect(direction == ENCAP_DIRECTION_INBOUND);
				raw_policy(KP_DELETE_OUTBOUND,
					   EXPECT_KERNEL_POLICY_OK,
					   &c->spd.this.client, &c->spd.that.client,
					   SHUNT_UNSET,
					   /*kernel_policy*/NULL/*delete->no-policy-rules*/,
					   /*use_lifetime*/deltatime(0),
					   /*sa_priority*/priority,
					   /*sa_marks+xfrmi*/NULL,NULL,
					   /*sec_label*/HUNK_AS_SHUNK(c->config->sec_label),
					   /*logger*/logger,
					   "%s() security label policy", __func__);
			}
			return false;
		}
	}

	/* a new route: no deletion required, but preparation is */
	if (!do_command(c, &c->spd, "prepare", NULL/*ST*/, logger)) {
		dbg("kernel: %s() prepare command returned an error", __func__);
	}

	if (!do_command(c, &c->spd, "route", NULL/*ST*/, logger)) {
		/* Failure!  Unwind our work. */
		dbg("kernel: %s() route command returned an error", __func__);
		if (!do_command(c, &c->spd, "down", NULL/*st*/, logger)) {
			dbg("kernel: down command returned an error");
		}
		dbg("kernel: %s() pulling policies", __func__);
		for (unsigned i = 0; i < 2; i++) {
			bool inbound = (i > 0);
			struct end *src = inbound ? &c->spd.that : &c->spd.this;
			struct end *dst = inbound ? &c->spd.this : &c->spd.that;
			/* ignore result */
			raw_policy(inbound ? KP_DELETE_INBOUND : KP_DELETE_OUTBOUND,
				   EXPECT_KERNEL_POLICY_OK,
				   &src->client, &dst->client,
				   SHUNT_PASS,
				   /*kernel_policy*/NULL/*delete->no-policy-rules*/,
				   /*use_lifetime*/deltatime(0),
				   /*sa_priority*/priority,
				   /*sa_marks+xfrmi*/NULL,NULL,
				   /*sec_label*/HUNK_AS_SHUNK(c->config->sec_label),
				   /*logger*/logger,
				   "%s() security label policy", __func__);
		}
		return false;
	}

	/* Success! */
	set_spd_routing(&c->spd, RT_ROUTED_PROSPECTIVE);
	return true;
}

bool eroute_connection(enum kernel_policy_op op, const char *opname,
		       const struct spd_route *sr,
		       enum shunt_policy shunt_policy,
		       const struct kernel_policy *kernel_policy,
		       uint32_t sa_priority,
		       const struct sa_marks *sa_marks,
		       const struct pluto_xfrmi *xfrmi,
		       shunk_t sec_label,
		       struct logger *logger)
{
	if (sr->this.has_cat) {
		ip_selector client = selector_from_address(sr->this.host->addr);
		bool t = raw_policy(op, EXPECT_KERNEL_POLICY_OK,
				    &client, &kernel_policy->dst.route,
				    shunt_policy,
				    kernel_policy,
				    deltatime(0),
				    sa_priority,
				    sa_marks, xfrmi,
				    sec_label,
				    logger,
				    "CAT: %s() %s", __func__, opname);
		if (!t) {
			llog(RC_LOG, logger,
			     "CAT: failed to eroute additional Client Address Translation policy");
		}

		dbg("kernel: %s CAT extra route added return=%d", __func__, t);
	}

	return raw_policy(op,
			  EXPECT_KERNEL_POLICY_OK,
			  &kernel_policy->src.route, &kernel_policy->dst.route,
			  shunt_policy,
			  kernel_policy,
			  deltatime(0),
			  sa_priority,
			  sa_marks, xfrmi,
			  sec_label,
			  logger,
			  "%s() %s", __func__, opname);
}

/* install a bare hold or pass policy to a connection */
bool assign_holdpass(const struct connection *c,
		     struct spd_route *sr,
		     enum shunt_policy negotiation_shunt,
		     const ip_packet *packet)
{
	/*
	 * either the automatically installed %hold eroute is broad enough
	 * or we try to add a broader one and delete the automatic one.
	 * Beware: this %hold might be already handled, but still squeak
	 * through because of a race.
	 */
	enum routing_t ro = sr->routing;	/* routing, old */
	enum routing_t rn = ro;			/* routing, new */

	passert(LHAS(LELEM(CK_PERMANENT) | LELEM(CK_INSTANCE), c->kind));
	/* figure out what routing should become */
	switch (ro) {
	case RT_UNROUTED:
		rn = RT_UNROUTED_HOLD;
		break;
	case RT_ROUTED_PROSPECTIVE:
		rn = RT_ROUTED_HOLD;
		break;
	default:
		/* no change: this %hold or %pass is old news */
		break;
	}

	dbg("kernel: assign hold, routing was %s, needs to be %s",
	    enum_name(&routing_story, ro),
	    enum_name(&routing_story, rn));

	if (eclipsable(sr)) {
		/*
		 * Although %hold or %pass is appropriately broad, it will
		 * no longer be bare so we must ditch it from the bare table
		 */
		struct bare_shunt **old = bare_shunt_ptr(&sr->this.client, &sr->that.client,
							 "assign_holdpass");

		if (old == NULL) {
			/* ??? should this happen?  It does. */
			llog(RC_LOG, c->logger,
			     "assign_holdpass() no bare shunt to remove? - mismatch?");
		} else {
			/* ??? should this happen? */
			dbg("kernel: assign_holdpass() removing bare shunt");
			free_bare_shunt(old);
		}
	} else {
		dbg("kernel: assign_holdpass() need broad(er) shunt");
		/*
		 * we need a broad %hold, not the narrow one.
		 * First we ensure that there is a broad %hold.
		 * There may already be one (race condition): no need to
		 * create one.
		 * There may already be a %trap: replace it.
		 * There may not be any broad eroute: add %hold.
		 * Once the broad %hold is in place, delete the narrow one.
		 */
		if (rn != ro) {
			int op;
			const char *reason;

			if (erouted(ro)) {
				op = KP_REPLACE_OUTBOUND;
				reason = "assign_holdpass() replace %trap with broad %pass or %hold";
			} else {
				op = KP_ADD_OUTBOUND;
				reason = "assign_holdpass() add broad %pass or %hold";
			}

			pexpect(op & KERNEL_POLICY_OUTBOUND);

			struct kernel_policy outbound_kernel_policy =
				bare_kernel_policy(&sr->this.client, &sr->that.client);
			if (eroute_connection(op, reason, sr, negotiation_shunt,
					      &outbound_kernel_policy,
					      calculate_sa_prio(c, false),
					      NULL, 0 /* xfrm_if_id */,
					      HUNK_AS_SHUNK(c->config->sec_label),
					      c->logger))
			{
				dbg("kernel: assign_holdpass() eroute_connection() done");
			} else {
				llog(RC_LOG, c->logger,
				     "assign_holdpass() eroute_connection() failed");
				return false;
			}
		}

		ip_address src_host_addr = packet_src_address(*packet);
		ip_address dst_host_addr = packet_dst_address(*packet);

		if (!flush_bare_shunt(&src_host_addr, &dst_host_addr,
				      packet->protocol, IGNORE_KERNEL_POLICY_MISSING,
				      (c->config->negotiation_shunt == SHUNT_PASS ? "delete narrow %pass" :
				       "assign_holdpass() delete narrow %hold"),
				      c->logger)) {
			dbg("kernel: assign_holdpass() delete_bare_shunt() succeeded");
		} else {
			llog(RC_LOG, c->logger,
			     "assign_holdpass() delete_bare_shunt() failed");
			return false;
		}
	}
	set_spd_routing(sr, rn);
	dbg("kernel:  assign_holdpass() done - returning success");
	return true;
}

/* compute a (host-order!) SPI to implement the policy in connection c */
enum policy_spi shunt_policy_spi(enum shunt_policy sp)
{
	/* note: these are in host order :-( */
	if (!pexpect(sp != SHUNT_UNSET)) {
		return SPI_NONE;
	}

	static const enum policy_spi shunt_spi[SHUNT_POLICY_ROOF] = {
		[SHUNT_NONE] = SPI_NONE,	/* --none */
		[SHUNT_HOLD] = SPI_HOLD,	/* --negotiationshunt=hold */
		[SHUNT_TRAP] = SPI_TRAP,	/* --initiateontraffic */
		[SHUNT_PASS] = SPI_PASS,	/* --pass */
		[SHUNT_DROP] = SPI_DROP,	/* --drop */
		[SHUNT_REJECT] = SPI_REJECT,	/* --reject */
	};
	passert(sp < elemsof(shunt_spi));
	return shunt_spi[sp];
}

static void setup_esp_nic_offload(struct kernel_sa *sa, struct connection *c,
		bool *nic_offload_fallback)
{
	if (c->config->nic_offload == yna_no ||
	    c->interface == NULL || c->interface->ip_dev == NULL ||
	    c->interface->ip_dev->id_rname == NULL) {
		dbg("kernel: NIC esp-hw-offload disabled for connection '%s'", c->name);
		return;
	}

	if (c->config->nic_offload == yna_auto) {
		if (!c->interface->ip_dev->id_nic_offload) {
			dbg("kernel: NIC esp-hw-offload not for connection '%s' not available on interface %s",
				c->name, c->interface->ip_dev->id_rname);
			return;
		}
		*nic_offload_fallback = true;
		dbg("kernel: NIC esp-hw-offload offload for connection '%s' enabled on interface %s",
		    c->name, c->interface->ip_dev->id_rname);
	}
	sa->nic_offload_dev = c->interface->ip_dev->id_rname;
}

/*
 * Set up one direction of the SA bundle
 */
static bool setup_half_ipsec_sa(struct state *st, bool inbound)
{
	/* Build an inbound or outbound SA */

	struct connection *c = st->st_connection;
	bool replace = inbound && (kernel_ops->get_ipsec_spi != NULL);
	bool nic_offload_fallback = false;

	/* SPIs, saved for spigrouping or undoing, if necessary */
	struct kernel_sa said[EM_MAXRELSPIS];
	struct kernel_sa *said_next = said;

	/* same scope as said[] */
	said_buf text_ipcomp;
	said_buf text_esp;
	said_buf text_ah;

	/*
	 * Construct the policy policysulation rules; it determines
	 * tunnel mode as a side effect.  There needs to be at least
	 * one rule.
	 */
	struct kernel_policy kernel_policy =
		kernel_policy_from_state(st, &c->spd,
					 (inbound ? ENCAP_DIRECTION_INBOUND :
					  ENCAP_DIRECTION_OUTBOUND));
	if (!pexpect(kernel_policy.nr_rules > 0)) {
		return false;
	}

	uint64_t sa_ipsec_soft_bytes =  c->config->sa_ipsec_max_bytes;
	uint64_t sa_ipsec_soft_packets = c->config->sa_ipsec_max_packets;

	if (!LIN(POLICY_DONT_REKEY, c->policy)) {
		sa_ipsec_soft_bytes = fuzz_soft_limit("ipsec-max-bytes",st->st_sa_role,
						      c->config->sa_ipsec_max_bytes,
						      IPSEC_SA_MAX_SOFT_LIMIT_PERCENTAGE,
						      st->st_logger);
		sa_ipsec_soft_packets = fuzz_soft_limit("ipsec-max-packets", st->st_sa_role,
							c->config->sa_ipsec_max_packets,
							IPSEC_SA_MAX_SOFT_LIMIT_PERCENTAGE,
							st->st_logger);
	}
	const struct kernel_sa said_boilerplate = {
		.src.address = kernel_policy.src.host,
		.dst.address = kernel_policy.dst.host,
		.src.client = kernel_policy.src.route,
		.dst.client = kernel_policy.dst.route,
		.inbound = inbound,
		.tunnel = (kernel_policy.mode == ENCAP_MODE_TUNNEL),
		.transport_proto = c->spd.this.client.ipproto,
		.sa_lifetime = c->sa_ipsec_life_seconds,
		.sa_max_soft_bytes = sa_ipsec_soft_bytes,
		.sa_max_soft_packets = sa_ipsec_soft_packets,
		.sa_ipsec_max_bytes = c->config->sa_ipsec_max_bytes,
		.sa_ipsec_max_packets = c->config->sa_ipsec_max_packets,
		.sec_label = (st->st_v1_seen_sec_label.len > 0 ? st->st_v1_seen_sec_label :
			      st->st_v1_acquired_sec_label.len > 0 ? st->st_v1_acquired_sec_label :
			      c->spd.this.sec_label /* assume connection outlive their kernel_sa's */),
	};



	address_buf sab, dab;
	selector_buf scb, dcb;
	dbg("kernel: %s() %s %s-%s->[%s=%s=>%s]-%s->%s sec_label="PRI_SHUNK"%s",
	    __func__,
	    said_boilerplate.inbound ? "inbound" : "outbound",
	    str_selector_subnet_port(&said_boilerplate.src.client, &scb),
	    protocol_by_ipproto(said_boilerplate.transport_proto)->name,
	    str_address(&said_boilerplate.src.address, &sab),
	    encap_mode_name(kernel_policy.mode),
	    str_address(&said_boilerplate.dst.address, &dab),
	    protocol_by_ipproto(said_boilerplate.transport_proto)->name,
	    str_selector_subnet_port(&said_boilerplate.dst.client, &dcb),
	    /* see above */
	    pri_shunk(said_boilerplate.sec_label),
	    (st->st_v1_seen_sec_label.len > 0 ? " (IKEv1 seen)" :
	     st->st_v1_acquired_sec_label.len > 0 ? " (IKEv1 acquired)" :
	     c->spd.this.sec_label.len > 0 ? " (IKEv2 this)" :
	     ""))

	/* set up IPCOMP SA, if any */

	if (st->st_ipcomp.present) {
		ipsec_spi_t ipcomp_spi = (inbound ? st->st_ipcomp.inbound.spi :
					  st->st_ipcomp.outbound.spi);
		*said_next = said_boilerplate;
		said_next->spi = ipcomp_spi;
		said_next->esatype = ET_IPCOMP;

		said_next->ipcomp = st->st_ipcomp.attrs.transattrs.ta_ipcomp;
		said_next->level = said_next - said;
		said_next->reqid = reqid_ipcomp(c->spd.reqid);
		said_next->story = said_str(kernel_policy.dst.host,
					    &ip_protocol_ipcomp,
					    ipcomp_spi, &text_ipcomp);

		if (!kernel_ops_add_sa(said_next, replace, st->st_logger)) {
			log_state(RC_LOG, st, "add_sa ipcomp failed");
			goto fail;
		}
		said_next++;
	}

	/* set up ESP SA, if any */

	if (st->st_esp.present) {
		ipsec_spi_t esp_spi = (inbound ? st->st_esp.inbound.spi :
				       st->st_esp.outbound.spi);
		chunk_t esp_dst_keymat = (inbound ? st->st_esp.inbound.keymat :
					  st->st_esp.outbound.keymat);
		const struct trans_attrs *ta = &st->st_esp.attrs.transattrs;

		const struct ip_encap *encap_type = NULL;
		uint16_t encap_sport = 0, encap_dport = 0;
		ip_address natt_oa;

		if (st->hidden_variables.st_nat_traversal & NAT_T_DETECTED ||
		    st->st_interface->io->protocol == &ip_protocol_tcp) {
			encap_type = st->st_interface->io->protocol->encap_esp;
			if (inbound) {
				encap_sport = endpoint_hport(st->st_remote_endpoint);
				encap_dport = endpoint_hport(st->st_interface->local_endpoint);
			} else {
				encap_sport = endpoint_hport(st->st_interface->local_endpoint);
				encap_dport = endpoint_hport(st->st_remote_endpoint);
			}
			natt_oa = st->hidden_variables.st_nat_oa;
			dbg("kernel: natt/tcp sa encap_type="PRI_IP_ENCAP" sport=%d dport=%d",
			    pri_ip_encap(encap_type), encap_sport, encap_dport);
		}

		dbg("kernel: looking for alg with encrypt: %s keylen: %d integ: %s",
		    ta->ta_encrypt->common.fqn, ta->enckeylen, ta->ta_integ->common.fqn);

		/*
		 * Check that both integrity and encryption are
		 * supported by the kernel.
		 *
		 * Since the parser uses these exact same checks when
		 * loading the connection, they should never fail (if
		 * they do then strange things have been going on
		 * since the connection was loaded).
		 */
		if (!kernel_alg_integ_ok(ta->ta_integ)) {
			log_state(RC_LOG_SERIOUS, st,
				  "ESP integrity algorithm %s is not implemented or allowed",
				  ta->ta_integ->common.fqn);
			goto fail;
		}
		if (!kernel_alg_encrypt_ok(ta->ta_encrypt)) {
			log_state(RC_LOG_SERIOUS, st,
				  "ESP encryption algorithm %s is not implemented or allowed",
				  ta->ta_encrypt->common.fqn);
			goto fail;
		}

		/*
		 * Validate the encryption key size.
		 */
		size_t encrypt_keymat_size;
		if (!kernel_alg_encrypt_key_size(ta->ta_encrypt, ta->enckeylen,
						 &encrypt_keymat_size)) {
			log_state(RC_LOG_SERIOUS, st,
				  "ESP encryption algorithm %s with key length %d not implemented or allowed",
				  ta->ta_encrypt->common.fqn, ta->enckeylen);
			goto fail;
		}

		/* Fixup key lengths for special cases */
#ifdef USE_3DES
		if (ta->ta_encrypt == &ike_alg_encrypt_3des_cbc) {
			/* Grrrrr.... f*cking 7 bits jurassic algos */
			/* 168 bits in kernel, need 192 bits for keymat_len */
			if (encrypt_keymat_size == 21) {
				dbg("kernel: %s requires a 7-bit jurassic adjust",
				    ta->ta_encrypt->common.fqn);
				encrypt_keymat_size = 24;
			}
		}
#endif

		if (ta->ta_encrypt->salt_size > 0) {
			dbg("kernel: %s requires %zu salt bytes",
			    ta->ta_encrypt->common.fqn, ta->ta_encrypt->salt_size);
			encrypt_keymat_size += ta->ta_encrypt->salt_size;
		}

		size_t integ_keymat_size = ta->ta_integ->integ_keymat_size; /* BYTES */

		dbg("kernel: st->st_esp.keymat_len=%zu is encrypt_keymat_size=%zu + integ_keymat_size=%zu",
		    esp_dst_keymat.len, encrypt_keymat_size, integ_keymat_size);

		passert(esp_dst_keymat.len == encrypt_keymat_size + integ_keymat_size);

		*said_next = said_boilerplate;
		said_next->spi = esp_spi;
		said_next->esatype = ET_ESP;
		said_next->replay_window = c->sa_replay_window;
		dbg("kernel: setting IPsec SA replay-window to %d", c->sa_replay_window);

		if (c->xfrmi != NULL) {
			said_next->xfrm_if_id = c->xfrmi->if_id;
			said_next->mark_set = c->sa_marks.out;
		}

		if (!inbound && c->sa_tfcpad != 0 && !st->st_seen_no_tfc) {
			dbg("kernel: Enabling TFC at %d bytes (up to PMTU)", c->sa_tfcpad);
			said_next->tfcpad = c->sa_tfcpad;
		}

		if (c->policy & POLICY_DECAP_DSCP) {
			dbg("kernel: Enabling Decap ToS/DSCP bits");
			said_next->decap_dscp = true;
		}
		if (c->policy & POLICY_NOPMTUDISC) {
			dbg("kernel: Disabling Path MTU Discovery");
			said_next->nopmtudisc = true;
		}

		said_next->integ = ta->ta_integ;
#ifdef USE_SHA2
		if (said_next->integ == &ike_alg_integ_sha2_256 &&
			LIN(POLICY_SHA2_TRUNCBUG, c->policy)) {
			if (kernel_ops->sha2_truncbug_support) {
				if (libreswan_fipsmode() == 1) {
					log_state(RC_LOG_SERIOUS, st,
						  "Error: sha2-truncbug=yes is not allowed in FIPS mode");
					goto fail;
				}
				dbg("kernel:  authalg converted for sha2 truncation at 96bits instead of IETF's mandated 128bits");
				/*
				 * We need to tell the kernel to mangle
				 * the sha2_256, as instructed by the user
				 */
				said_next->integ = &ike_alg_integ_hmac_sha2_256_truncbug;
			} else {
				log_state(RC_LOG_SERIOUS, st,
					  "Error: %s stack does not support sha2_truncbug=yes",
					  kernel_ops->interface_name);
				goto fail;
			}
		}
#endif
		if (st->st_esp.attrs.transattrs.esn_enabled) {
			dbg("kernel: Enabling ESN");
			said_next->esn = true;
		}

		/*
		 * XXX: Assume SADB_ and ESP_ numbers match!  Clearly
		 * setting .compalg is wrong, don't yet trust
		 * lower-level code to be right.
		 */
		said_next->encrypt = ta->ta_encrypt;

		/* divide up keying material */
		said_next->enckey = esp_dst_keymat.ptr;
		said_next->enckeylen = encrypt_keymat_size; /* BYTES */
		said_next->authkey = esp_dst_keymat.ptr + encrypt_keymat_size;
		said_next->authkeylen = integ_keymat_size; /* BYTES */

		said_next->level = said_next - said;
		said_next->reqid = reqid_esp(c->spd.reqid);

		said_next->src.encap_port = encap_sport;
		said_next->dst.encap_port = encap_dport;
		said_next->encap_type = encap_type;
		said_next->natt_oa = &natt_oa;
		said_next->story = said_str(kernel_policy.dst.host,
					    &ip_protocol_esp,
					    esp_spi, &text_esp);

		if (DBGP(DBG_PRIVATE) || DBGP(DBG_CRYPT)) {
			DBG_dump("ESP enckey:",  said_next->enckey,
				 said_next->enckeylen);
			DBG_dump("ESP authkey:", said_next->authkey,
				 said_next->authkeylen);
		}

		setup_esp_nic_offload(said_next, c, &nic_offload_fallback);

		bool ret = kernel_ops_add_sa(said_next, replace, st->st_logger);

		if (!ret && nic_offload_fallback &&
			said_next->nic_offload_dev != NULL) {
			/* Fallback to non-nic-offload crypto */
			said_next->nic_offload_dev = NULL;
			ret = kernel_ops_add_sa(said_next, replace, st->st_logger);
		}

		/* scrub keys from memory */
		memset(said_next->enckey, 0, said_next->enckeylen);
		memset(said_next->authkey, 0, said_next->authkeylen);

		if (!ret)
			goto fail;

		said_next++;
	}

	/* set up AH SA, if any */

	if (st->st_ah.present) {
		ipsec_spi_t ah_spi = (inbound ? st->st_ah.inbound.spi :
				      st->st_ah.outbound.spi);
		chunk_t ah_dst_keymat = (inbound ? st->st_ah.inbound.keymat :
					 st->st_ah.outbound.keymat);

		const struct integ_desc *integ = st->st_ah.attrs.transattrs.ta_integ;
		size_t keymat_size = integ->integ_keymat_size;
		int authalg = integ->integ_ikev1_ah_transform;
		if (authalg <= 0) {
			log_state(RC_LOG_SERIOUS, st,
				  "%s not implemented",
				  integ->common.fqn);
			goto fail;
		}

		passert(ah_dst_keymat.len == keymat_size);

		*said_next = said_boilerplate;
		said_next->spi = ah_spi;
		said_next->esatype = ET_AH;
		said_next->integ = integ;
		said_next->authkeylen = ah_dst_keymat.len;
		said_next->authkey = ah_dst_keymat.ptr;
		said_next->level = said_next - said;
		said_next->reqid = reqid_ah(c->spd.reqid);
		said_next->story = said_str(kernel_policy.dst.host,
					    &ip_protocol_ah,
					    ah_spi, &text_ah);

		said_next->replay_window = c->sa_replay_window;
		dbg("kernel: setting IPsec SA replay-window to %d", c->sa_replay_window);

		if (st->st_ah.attrs.transattrs.esn_enabled) {
			dbg("kernel: Enabling ESN");
			said_next->esn = true;
		}

		if (DBGP(DBG_PRIVATE) || DBGP(DBG_CRYPT)) {
			DBG_dump("AH authkey:", said_next->authkey,
				 said_next->authkeylen);
		}

		if (!kernel_ops_add_sa(said_next, replace, st->st_logger)) {
			/* scrub key from memory */
			memset(said_next->authkey, 0, said_next->authkeylen);
			goto fail;
		}
		/* scrub key from memory */
		memset(said_next->authkey, 0, said_next->authkeylen);

		said_next++;
	}

	/*
	 * Add an inbound eroute to enforce an arrival check.
	 *
	 * If inbound,
	 * ??? and some more mysterious conditions,
	 * Note reversed ends.
	 * Not much to be done on failure.
	 */
	dbg("kernel: %s() is thinking about installing inbound eroute? inbound=%d owner=#%lu %s",
	    __func__, inbound, c->spd.eroute_owner,
	    encap_mode_name(kernel_policy.mode));
	if (inbound &&
	    c->spd.eroute_owner == SOS_NOBODY &&
	    (c->config->sec_label.len == 0 || c->config->ike_version == IKEv1)) {
		dbg("kernel: %s() is installing inbound eroute", __func__);

		/*
		 * MCR - should be passed a spd_eroute structure here.
		 *
		 * Note: this and that are intentionally reversed
		 * because the policy is inbound.
		 *
		 * XXX: yes, that is redundan - KP_ADD_INBOUND is
		 * already indicating that the parameters are going to
		 * need reversing ...
		 */
		struct kernel_policy kernel_policy =
			kernel_policy_from_state(st, &c->spd,
						 ENCAP_DIRECTION_INBOUND);
		if (!raw_policy(KP_ADD_INBOUND,
				EXPECT_KERNEL_POLICY_OK,
				&kernel_policy.src.route,	/* src_client */
				&kernel_policy.dst.route,	/* dst_client */
				SHUNT_UNSET,
				&kernel_policy,			/* " */
				deltatime(0),		/* lifetime */
				calculate_sa_prio(c, false),	/* priority */
				&c->sa_marks, c->xfrmi,		/* IPsec SA marks */
				HUNK_AS_SHUNK(c->config->sec_label),
				st->st_logger,
				"%s() add inbound Child SA", __func__)) {
			llog(RC_LOG, st->st_logger,
			     "raw_policy() in setup_half_ipsec_sa() failed to add inbound");
		}
	}

	/* If there are multiple SPIs, group them. */

	if (kernel_ops->grp_sa != NULL && said_next > &said[1]) {
		struct kernel_sa *s;

		/*
		 * group SAs, two at a time, inner to outer (backwards in
		 * said[])
		 *
		 * The grouping is by pairs.  So if said[] contains
		 * ah esp ipip,
		 *
		 * the grouping would be ipip:esp, esp:ah.
		 */
		for (s = said; s < said_next - 1; s++) {
			dbg("kernel: grouping %s and %s",
			    s[0].story, s[1].story);
			if (!kernel_ops->grp_sa(s + 1, s)) {
				log_state(RC_LOG, st, "grp_sa failed");
				goto fail;
			}
		}
		/* could update said, but it will not be used */
	}

	/* if the impaired is set, pretend this fails */
	if (impair.sa_creation) {
		DBG_log("Impair SA creation is set, pretending to fail");
		goto fail;
	}
	return true;

fail:
	log_state(RC_LOG, st, "setup_half_ipsec_sa() hit fail:");
	/*
	 * Undo the done SPIs.
	 *
	 * Deleting the SPI also deletes any SAs attached to them.
	 */
	while (said_next-- != said) {
		if (said_next->proto != NULL) {
			kernel_ops_del_ipsec_spi(said_next->spi,
						 said_next->proto,
						 &said_next->src.address,
						 &said_next->dst.address,
						 st->st_logger);
		}
	}
	return false;
}

/*
 * XXX: Two cases:
 *
 * - the protocol was negotiated (and presumably installed)
 *   (.present)
 *
 * - the protocol was proposed but never finished (.out_spi
 *   inbound)
 */

struct dead_sa {	/* XXX: this is ip_said+src */
	const struct ip_protocol *protocol;
	ipsec_spi_t spi;
	ip_address src;
	ip_address dst;
};

static unsigned append_teardown(struct dead_sa *dead, bool inbound,
				const struct ipsec_proto_info *proto,
				ip_address host_addr, ip_address effective_remote_address)
{
	bool present = proto->present;
	if (!present && inbound && proto->inbound.spi != 0 && proto->outbound.spi == 0) {
		dbg("kernel: forcing inbound delete of %s as .inbound.spi: "PRI_IPSEC_SPI"; attrs.spi: "PRI_IPSEC_SPI,
		    proto->protocol->name,
		    pri_ipsec_spi(proto->inbound.spi),
		    pri_ipsec_spi(proto->outbound.spi));
		present = true;
	}
	if (present) {
		dead->protocol = proto->protocol;
		if (inbound) {
			if (proto->inbound.kernel_sa_expired & SA_HARD_EXPIRED) {
				dbg("kernel expired SPI 0x%x skip deleting",
				    ntohl(proto->inbound.spi));
				return 0;
			}
			dead->spi = proto->inbound.spi; /* incoming */
			dead->src = effective_remote_address;
			dead->dst = host_addr;
		} else {
			if (proto->outbound.kernel_sa_expired & SA_HARD_EXPIRED) {
				dbg("kernel hard expired SPI 0x%x skip deleting",
				    ntohl(proto->outbound.spi));
				return 0;
			}
			dead->spi = proto->outbound.spi; /* outgoing */
			dead->src = host_addr;
			dead->dst = effective_remote_address;
		}
		return 1;
	}
	return 0;
}

/*
 * Delete any AH, ESP, and IPCOMP kernel states.
 *
 * Deleting only requires the addresses, protocol, and IPsec SPIs.
 */

static bool teardown_half_ipsec_sa(struct state *st, bool inbound)
{
	struct connection *const c = st->st_connection;

	/*
	 * If we have a new address in c->remote->host.addr,
	 * we are the initiator, have been redirected,
	 * and yet this routine must use the old address.
	 *
	 * We point effective_remote_host_address to the appropriate
	 * address.
	 */

	ip_address effective_remote_address = c->remote->host.addr;
	if (!endpoint_address_eq_address(st->st_remote_endpoint, effective_remote_address) &&
	    address_is_specified(c->temp_vars.redirect_ip)) {
		effective_remote_address = endpoint_address(st->st_remote_endpoint);
	}

	/* collect each proto SA that needs deleting */

	struct dead_sa dead[3];	/* at most 3 entries */
	unsigned nr = 0;
	nr += append_teardown(dead + nr, inbound, &st->st_ah,
			      c->local->host.addr, effective_remote_address);
	nr += append_teardown(dead + nr, inbound, &st->st_esp,
			      c->local->host.addr, effective_remote_address);
	nr += append_teardown(dead + nr, inbound, &st->st_ipcomp,
			      c->local->host.addr, effective_remote_address);
	passert(nr < elemsof(dead));

	/*
	 * If the SAs have been grouped, deleting any one will do: we
	 * just delete the first one found.
	 */
	if (kernel_ops->grp_sa != NULL && nr > 1) {
		nr = 1;
	}

	/*
	 * Delete each proto that needs deleting.
	 *
	 * Deleting the SPI also deletes any corresponding SA.
	 */
	bool result = true;
	for (unsigned i = 0; i < nr; i++) {
		const struct dead_sa *tbd = &dead[i];
		result &= kernel_ops_del_ipsec_spi(tbd->spi,
						   tbd->protocol,
						   &tbd->src, &tbd->dst,
						   st->st_logger);
	}

	return result;
}

static void kernel_process_msg_cb(int fd, void *arg, struct logger *logger)
{
	const struct kernel_ops *kernel_ops = arg;

	dbg("kernel: %s() process %s message", __func__, kernel_ops->interface_name);
	threadtime_t start = threadtime_start();
	kernel_ops->process_msg(fd, logger);
	threadtime_stop(&start, SOS_NOBODY, "kernel message");
}

static global_timer_cb kernel_process_queue_cb;

static void kernel_process_queue_cb(struct logger *unused_logger UNUSED)
{
	if (pexpect(kernel_ops->process_queue != NULL)) {
		kernel_ops->process_queue();
	}
}

const struct kernel_ops *const kernel_stacks[] = {
#ifdef KERNEL_XFRM
	&xfrm_kernel_ops,
#endif
#ifdef KERNEL_PFKEYV2
	&pfkeyv2_kernel_ops,
#endif
	NULL,
};

const struct kernel_ops *kernel_ops = NULL/*kernel_stacks[0]*/;

deltatime_t bare_shunt_interval = DELTATIME_INIT(SHUNT_SCAN_INTERVAL);

void init_kernel(struct logger *logger)
{
	struct utsname un;

	/* get kernel version */
	uname(&un);
	llog(RC_LOG, logger,
	     "using %s %s kernel support code on %s",
	     un.sysname, kernel_ops->interface_name, un.version);

	passert(kernel_ops->init != NULL);
	kernel_ops->init(logger);

	/* Add the port bypass polcies */

	if (kernel_ops->v6holes != NULL) {
		/* may not return */
		kernel_ops->v6holes(logger);
	}

	enable_periodic_timer(EVENT_SHUNT_SCAN, kernel_scan_shunts,
			      bare_shunt_interval);

	dbg("kernel: setup kernel fd callback");

	if (kernel_ops->async_fdp != NULL)
		/* Note: kernel_ops is const but pluto_event_add cannot know that */
		add_fd_read_listener(*kernel_ops->async_fdp, "KERNEL_XRM_FD",
				     kernel_process_msg_cb, (void*)kernel_ops);

	if (kernel_ops->route_fdp != NULL && *kernel_ops->route_fdp > NULL_FD) {
		add_fd_read_listener(*kernel_ops->route_fdp, "KERNEL_ROUTE_FD",
				     kernel_process_msg_cb, (void*)kernel_ops);
	}

	if (kernel_ops->process_queue != NULL) {
		/*
		 * AA_2015 this is untested code. only for non xfrm ???
		 * It seems in klips we should, besides kernel_process_msg,
		 * call process_queue periodically.  Does the order
		 * matter?
		 */
		enable_periodic_timer(EVENT_PROCESS_KERNEL_QUEUE,
				      kernel_process_queue_cb,
				      deltatime(KERNEL_PROCESS_Q_PERIOD));
	}
}

void show_kernel_interface(struct show *s)
{
	if (kernel_ops != NULL) {
		show_comment(s, "using kernel interface: %s",
			     kernel_ops->interface_name);
	}
}

/*
 * Note: install_inbound_ipsec_sa is only used by the Responder.
 * The Responder will subsequently use install_ipsec_sa for the outbound.
 * The Initiator uses install_ipsec_sa to install both at once.
 */
bool install_inbound_ipsec_sa(struct state *st)
{
	struct connection *const c = st->st_connection;

	/*
	 * If our peer has a fixed-address client, check if we already
	 * have a route for that client that conflicts.  We will take this
	 * as proof that that route and the connections using it are
	 * obsolete and should be eliminated.  Interestingly, this is
	 * the only case in which we can tell that a connection is obsolete.
	 */
	passert(c->kind == CK_PERMANENT || c->kind == CK_INSTANCE);
	if (c->spd.that.has_client) {
		for (;; ) {
			struct spd_route *esr;	/* value is ignored */
			struct connection *o = route_owner(c, &c->spd, &esr,
							NULL, NULL);

			if (o == NULL || c == o)
				break; /* nobody interesting has a route */

			/* note: we ignore the client addresses at this end */
			if (sameaddr(&o->remote->host.addr,
					&c->remote->host.addr) &&
				o->interface == c->interface)
				break;  /* existing route is compatible */

			if (kernel_ops->overlap_supported) {
				/*
				 * Both are transport mode, allow overlapping.
				 * [bart] not sure if this is actually
				 * intended, but am leaving it in to make it
				 * behave like before
				 */
				if (!LIN(POLICY_TUNNEL, c->policy | o->policy))
					break;

				/* Both declared that overlapping is OK. */
				if (LIN(POLICY_OVERLAPIP, c->policy & o->policy))
					break;
			}

			address_buf b;
			connection_buf cib;
			log_state(RC_LOG_SERIOUS, st,
				  "route to peer's client conflicts with "PRI_CONNECTION" %s; releasing old connection to free the route",
				  pri_connection(o, &cib),
				  str_address_sensitive(&o->remote->host.addr, &b));
			if (o->kind == CK_INSTANCE) {
				delete_connection(&o);
			} else {
				release_connection(o);
			}
		}
	}

	dbg("kernel: install_inbound_ipsec_sa() checking if we can route");
	/* check that we will be able to route and eroute */
	switch (could_route(c, st->st_logger)) {
	case route_easy:
	case route_nearconflict:
		dbg("kernel:    routing is easy, or has resolvable near-conflict");
		break;

	case route_unnecessary:
		/*
		 * in this situation, we should look and see if there is
		 * a state that our connection references, that we are
		 * in fact replacing.
		 */
		break;

	default:
		return false;
	}

	/*
	 * we now have to set up the outgoing SA first, so that
	 * we can refer to it in the incoming SA.
	 */
	if (!st->st_outbound_done) {
		dbg("kernel: installing outgoing SA now");
		if (!setup_half_ipsec_sa(st, false)) {
			dbg("failed to install outgoing SA");
			return false;
		}

		st->st_outbound_done = true;
	}

	/* (attempt to) actually set up the SAs */

	return setup_half_ipsec_sa(st, true);
}

/* Install a route and then a prospective shunt eroute or an SA group eroute.
 * Assumption: could_route gave a go-ahead.
 * Any SA Group must have already been created.
 * On failure, steps will be unwound.
 */
bool route_and_eroute(struct connection *c,
		      struct spd_route *sr,
		      struct state *st/*can be NULL*/,
		      struct logger *logger/*st or c */)
{
	selectors_buf sb;
	dbg("kernel: route_and_eroute() for %s; proto %d, and source port %d dest port %d sec_label",
	    str_selectors(&sr->this.client, &sr->that.client, &sb),
	    sr->this.client.ipproto, sr->this.client.hport, sr->that.client.hport);

	struct spd_route *esr, *rosr;
	struct connection *ero;
	struct connection *ro = route_owner(c, sr, &rosr, &ero, &esr);	/* who, if anyone, owns our eroute? */

	dbg("kernel: route_and_eroute with c: %s (next: %s) ero:%s esr:{%p} ro:%s rosr:{%p} and state: #%lu",
	    c->name,
	    (c->policy_next ? c->policy_next->name : "none"),
	    ero == NULL ? "null" : ero->name,
	    esr,
	    ro == NULL ? "null" : ro->name,
	    rosr,
	    st == NULL ? 0 : st->st_serialno);

	/* look along the chain of policies for same one */

	/* we should look for dest port as well? */
	/* ports are now switched to the ones in this.client / that.client ??????? */
	/* but port set is sr->this.port and sr.that.port ! */
	struct bare_shunt **bspp = ((ero == NULL) ? bare_shunt_ptr(&sr->this.client,
								   &sr->that.client,
								   "route and eroute") :
				    NULL);

	/* install the eroute */

	bool eroute_installed = false;

#ifdef IPSEC_CONNECTION_LIMIT
	bool new_eroute = false;
#endif

	passert(bspp == NULL || ero == NULL);   /* only one non-NULL */

	if (bspp != NULL || ero != NULL) {
		dbg("kernel: we are replacing an eroute");
		/* if no state provided, then install a shunt for later */
		if (st == NULL) {
			eroute_installed = bare_policy_op(KP_REPLACE_OUTBOUND,
							  EXPECT_KERNEL_POLICY_OK,
							  c, sr, RT_ROUTED_PROSPECTIVE,
							  "route_and_eroute() replace shunt",
							  logger);
		} else {
			eroute_installed = sag_eroute(st, sr, KP_REPLACE_OUTBOUND,
						      "route_and_eroute() replace sag");
		}

		/* remember to free bspp if we make it out of here alive */
	} else {
		/* we're adding an eroute */
#ifdef IPSEC_CONNECTION_LIMIT
		if (num_ipsec_eroute == IPSEC_CONNECTION_LIMIT) {
			llog(RC_LOG_SERIOUS, logger,
				    "Maximum number of IPsec connections reached (%d)",
				    IPSEC_CONNECTION_LIMIT);
			return false;
		}
		new_eroute = true;
#endif

		/* if no state provided, then install a shunt for later */
		if (st == NULL) {
			eroute_installed = bare_policy_op(KP_ADD_OUTBOUND,
							  EXPECT_KERNEL_POLICY_OK,
							  c, sr, RT_ROUTED_PROSPECTIVE,
							  "route_and_eroute() add",
							  logger);
		} else {
			eroute_installed = sag_eroute(st, sr, KP_ADD_OUTBOUND, "add");
		}
	}

	/* notify the firewall of a new tunnel */

	bool firewall_notified = false;

	if (eroute_installed) {
		/*
		 * do we have to notify the firewall?
		 * Yes, if we are installing
		 * a tunnel eroute and the firewall wasn't notified
		 * for a previous tunnel with the same clients.  Any Previous
		 * tunnel would have to be for our connection, so the actual
		 * test is simple.
		 */
		firewall_notified = st == NULL || /* not a tunnel eroute */
			sr->eroute_owner != SOS_NOBODY || /* already notified */
			do_command(c, sr, "up", st, logger); /* go ahead and notify */
	}

	/* install the route */

	bool route_installed = false;

	dbg("kernel: route_and_eroute: firewall_notified: %s",
	    firewall_notified ? "true" : "false");
	if (!firewall_notified) {
		/* we're in trouble -- don't do routing */
	} else if (ro == NULL) {
		/* a new route: no deletion required, but preparation is */
		if (!do_command(c, sr, "prepare", st, logger))
			dbg("kernel: prepare command returned an error");
		route_installed = do_command(c, sr, "route", st, logger);
		if (!route_installed)
			dbg("kernel: route command returned an error");
	} else if (routed(sr->routing)) {
		route_installed = true; /* nothing to be done */
	} else if (ro->interface->ip_dev == c->interface->ip_dev &&
		   address_eq_address(ro->local->host.nexthop, c->local->host.nexthop)) {
		/*
		 * The routes required for two different connections
		 * agree (it is assumed that the destination subnets
		 * agree).
		 */
		route_installed = true; /* nothing to be done */
	} else {
		/*
		 * Some other connection must own the route
		 * and the route must disagree.  But since could_route
		 * must have allowed our stealing it, we'll do so.
		 *
		 * A feature of LINUX allows us to install the new route
		 * before deleting the old if the nexthops differ.
		 * This reduces the "window of vulnerability" when packets
		 * might flow in the clear.
		 */
		if (sameaddr(&sr->this.host->nexthop,
			     &esr->this.host->nexthop)) {
			if (!do_command(ro, sr, "unroute", st, logger)) {
				dbg("kernel: unroute command returned an error");
			}
			route_installed = do_command(c, sr, "route", st, logger);
			if (!route_installed)
				dbg("kernel: route command returned an error");
		} else {
			route_installed = do_command(c, sr, "route", st, logger);
			if (!route_installed)
				dbg("kernel: route command returned an error");

			if (!do_command(ro, sr, "unroute", st, logger)) {
				dbg("kernel: unroute command returned an error");
			}
		}

		/* record unrouting */
		if (route_installed) {
			do {
				dbg("kernel: installed route: ro name=%s, rosr->routing was %s",
				    ro->name, enum_name(&routing_story, rosr->routing));
				pexpect(!erouted(rosr->routing)); /* warn for now - requires fixing */
				set_spd_routing(rosr, RT_UNROUTED);
				/* no need to keep old value */
				ro = route_owner(c, sr, &rosr, NULL, NULL);
			} while (ro != NULL);
		}
	}

	/* all done -- clean up */
	if (route_installed) {
		/* Success! */

		if (bspp != NULL) {
			free_bare_shunt(bspp);
		}

		if (st == NULL) {
			passert(sr->eroute_owner == SOS_NOBODY);
			set_spd_routing(sr, RT_ROUTED_PROSPECTIVE);
		} else {
			set_spd_routing(sr, RT_ROUTED_TUNNEL);
			set_spd_owner(sr, st->st_serialno);
			/* clear host shunts that clash with freshly installed route */
			clear_narrow_holds(&sr->this.client, &sr->that.client, logger);
		}

#ifdef IPSEC_CONNECTION_LIMIT
		if (new_eroute) {
			num_ipsec_eroute++;
			llog(RC_COMMENT, logger,
				    "%d IPsec connections are currently being managed",
				    num_ipsec_eroute);
		}
#endif

		return true;
	} else {
		/* Failure!  Unwind our work. */
		if (firewall_notified && sr->eroute_owner == SOS_NOBODY) {
			if (!do_command(c, sr, "down", st, logger))
				dbg("kernel: down command returned an error");
		}

		if (eroute_installed) {
			/*
			 * Restore original eroute, if we can.
			 * Since there is nothing much to be done if
			 * the restoration fails, ignore success or failure.
			 */
			if (bspp != NULL) {
				/*
				 * Restore old bare_shunt.
				 * I don't think that this case is very likely.
				 * Normally a bare shunt would have been
				 * assigned to a connection before we've
				 * gotten this far.
				 */
				struct bare_shunt *bs = *bspp;
				struct kernel_policy outbound_kernel_policy =
					bare_kernel_policy(&bs->our_client,
							   &bs->peer_client);
				if (!raw_policy(KP_REPLACE_OUTBOUND,
						EXPECT_KERNEL_POLICY_OK,
						&outbound_kernel_policy.src.client,
						&outbound_kernel_policy.dst.client,
						bs->shunt_policy,
						&outbound_kernel_policy,
						deltatime(SHUNT_PATIENCE),
						calculate_sa_prio(c, false),
						/*sa_mars+xfrmi*/NULL,NULL,
						/* bare shunt are not associated with any connection so no security label */
						null_shunk, logger,
						"%s() restore", __func__)) {
					llog(RC_LOG, logger,
					     "raw_policy() in route_and_eroute() failed to restore/replace SA");
				}
			} else if (ero != NULL) {
				passert(esr != NULL);
				/* restore ero's former glory */
				if (esr->eroute_owner == SOS_NOBODY) {
					/* note: normal or eclipse case */
					if (!bare_policy_op(KP_REPLACE_OUTBOUND,
							    EXPECT_KERNEL_POLICY_OK,
							    ero, esr, esr->routing,
							    "route_and_eroute() restore",
							    logger)) {
						llog(RC_LOG, logger,
						     "shunt_policy() in route_and_eroute() failed restore/replace");
					}
				} else {
					/*
					 * Try to find state that owned eroute.
					 * Don't do anything if it cannot be
					 * found.
					 * This case isn't likely since we
					 * don't run the updown script when
					 * replacing a SA group with its
					 * successor (for the same conn).
					 */
					struct state *ost =
						state_by_serialno(esr->eroute_owner);

					if (ost != NULL) {
						if (!sag_eroute(ost, esr,
								KP_REPLACE_OUTBOUND,
								"restore"))
							llog(RC_LOG, logger,
							     "sag_eroute() in route_and_eroute() failed restore/replace");
					}
				}
			} else {
				/* there was no previous eroute: delete whatever we installed */
				if (st == NULL) {
					if (!bare_policy_op(KP_DELETE_OUTBOUND,
							    EXPECT_KERNEL_POLICY_OK,
							    c, sr, sr->routing,
							    "route_and_eroute() delete",
							    logger)) {
						llog(RC_LOG, logger,
						     "shunt_policy() in route_and_eroute() failed in !st case");
					}
				} else {
					if (!sag_eroute(st, sr,
							KP_DELETE_OUTBOUND,
							"delete")) {
						llog(RC_LOG, logger,
							    "sag_eroute() in route_and_eroute() failed in st case for delete");
					}
				}
			}
		}

		return false;
	}
}

bool install_ipsec_sa(struct state *st, bool inbound_also)
{
	dbg("kernel: install_ipsec_sa() for #%lu: %s", st->st_serialno,
	    inbound_also ? "inbound and outbound" : "outbound only");

	enum routability rb = could_route(st->st_connection, st->st_logger);

	switch (rb) {
	case route_easy:
	case route_unnecessary:
	case route_nearconflict:
		break;

	default:
		return false;
	}

	/* (attempt to) actually set up the SA group */

	/* setup outgoing SA if we haven't already */
	if (!st->st_outbound_done) {
		if (!setup_half_ipsec_sa(st, false)) {
			return false;
		}

		dbg("kernel: set up outgoing SA");
		st->st_outbound_done = true;
	}

	/* now setup inbound SA */
	if (inbound_also) {
		if (!setup_half_ipsec_sa(st, true))
			return false;

		dbg("kernel: set up incoming SA");

		/*
		 * We successfully installed an IPsec SA, meaning it is safe
		 * to clear our revival back-off delay. This is based on the
		 * assumption that an unwilling partner might complete an IKE
		 * SA to us, but won't complete an IPsec SA to us.
		 */
		st->st_connection->temp_vars.revive_delay = 0;
	}

	if (rb == route_unnecessary)
		return true;

	struct spd_route *sr = &st->st_connection->spd;

	if (st->st_connection->remotepeertype == CISCO && sr->spd_next != NULL)
		sr = sr->spd_next;

	/* for (sr = &st->st_connection->spd; sr != NULL; sr = sr->next) */
	struct connection *c = st->st_connection;
	if (c->config->ike_version == IKEv2 &&
	    c->spd.this.sec_label.len > 0) {
		dbg("kernel: %s() skipping route_and_eroute(st) as security label", __func__);
	} else {
		for (; sr != NULL; sr = sr->spd_next) {
			dbg("kernel: sr for #%lu: %s", st->st_serialno,
			    enum_name(&routing_story, sr->routing));

			/*
			 * if the eroute owner is not us, then make it
			 * us.  See test co-terminal-02,
			 * pluto-rekey-01, pluto-unit-02/oppo-twice
			 */
			pexpect(sr->eroute_owner == SOS_NOBODY ||
				sr->routing >= RT_ROUTED_TUNNEL);

			if (sr->eroute_owner != st->st_serialno &&
			    sr->routing != RT_UNROUTED_KEYED) {
				if (!route_and_eroute(st->st_connection, sr, st, st->st_logger)) {
					delete_ipsec_sa(st);
					/*
					 * XXX go and unroute any SRs that were
					 * successfully routed already.
					 */
					return false;
				}
			}
		}
	}

	/* XXX why is this needed? Skip the bogus original conn? */
	if (st->st_connection->remotepeertype == CISCO) {
		struct spd_route *srcisco = st->st_connection->spd.spd_next;

		if (srcisco != NULL) {
			set_spd_owner(&st->st_connection->spd, srcisco->eroute_owner);
			set_spd_routing(&st->st_connection->spd, srcisco->routing);
		}
	}

	if (inbound_also)
		linux_audit_conn(st, LAK_CHILD_START);
	return true;
}

/*
 * Delete an IPSEC SA.
 *
 * We may not succeed, but we bull ahead anyway because we cannot do
 * anything better by recognizing failure.  This used to have a
 * parameter bool inbound_only, but the saref code changed to always
 * install inbound before outbound so this it was always false, and
 * thus removed.
 *
 * But this means that while there's now always an outbound policy,
 * there may not yet be an inbound policy!  For instance, IKEv2 IKE
 * AUTH initiator gets rejected.  So what is there, and should this
 * even be called?  EXPECT_KERNEL_POLICY is trying to help sort this
 * out.
 */

static void teardown_kernel_policies(enum kernel_policy_op outbound_op,
				     enum shunt_policy outbound_shunt,
				     struct spd_route *out,
				     struct spd_route *in,
				     enum expect_kernel_policy expect_kernel_policy,
				     struct logger *logger, const char *story)
{
	pexpect(outbound_op == KP_DELETE_OUTBOUND || outbound_op == KP_REPLACE_OUTBOUND);
	/*
	 * The restored policy uses TRANSPORT mode (the host
	 * .{src,dst} provides the family but the address isn't used).
	 */
	struct kernel_policy outbound_kernel_policy =
		bare_kernel_policy(&out->this.client, &out->that.client);
	if (!raw_policy(outbound_op,
			EXPECT_KERNEL_POLICY_OK,
			&outbound_kernel_policy.src.client,
			&outbound_kernel_policy.dst.client,
			outbound_shunt,
			(outbound_op == KP_REPLACE_OUTBOUND ? &outbound_kernel_policy : NULL),
			deltatime(0),
			calculate_sa_prio(out->connection, false),
			&out->connection->sa_marks, out->connection->xfrmi,
			HUNK_AS_SHUNK(out->connection->config->sec_label),
			out->connection->logger,
			"%s() outbound kernel policy for %s", __func__, story)) {
		llog(RC_LOG, logger,
		     "kernel: %s() outbound failed %s", __func__, story);
	}
	dbg("kernel: %s() calling raw_policy(delete-inbound), eroute_owner==NOBODY",
	    __func__);
	if (!raw_policy(KP_DELETE_INBOUND, expect_kernel_policy,
			&in->that.client, &in->this.client,
			SHUNT_UNSET,
			NULL/*no-policy-template as delete*/,
			deltatime(0),
			calculate_sa_prio(in->connection, false),
			&in->connection->sa_marks,
			in->connection->xfrmi,
			/*sec_label:always-null*/null_shunk,
			in->connection->logger,
			"%s() inbound kernel policy for %s", __func__, story)) {
		llog(RC_LOG, logger,
		     "kernel: %s() outbound failed %s", __func__, story);
	}
}

static void teardown_ipsec_sa(struct state *st, enum expect_kernel_policy expect_kernel_policy)
{
	/* XXX in IKEv2 we get a spurious call with a parent st :( */
	if (!pexpect(IS_CHILD_SA(st))) {
		return;
	}

	if (st->st_esp.present || st->st_ah.present) {
		/* ESP or AH means this was an established IPsec SA */
		linux_audit_conn(st, LAK_CHILD_DESTROY);
	}

	dbg("kernel: %s() for "PRI_SO" ...", __func__, pri_so(st->st_serialno));

	for (struct spd_route *sr = &st->st_connection->spd; sr != NULL; sr = sr->spd_next) {

		if (sr->eroute_owner != st->st_serialno) {
			dbg("kernel: %s() skipping, eroute_owner "PRI_SO" doesn't match Child SA "PRI_SO,
			    __func__, pri_so(sr->eroute_owner), pri_so(st->st_serialno));
			continue;
		}

		if (sr->routing != RT_ROUTED_TUNNEL) {
			enum_buf rb;
			dbg("kernel: %s() skipping, routing %s isn't TUNNEL",
			    __func__, str_enum_short(&routing_story, sr->routing, &rb));
			continue;
		}

		set_spd_owner(sr, SOS_NOBODY);

		if (sr == &sr->connection->spd && sr->connection->remotepeertype == CISCO) {
			/*
			 * XXX: this is currently the only reason for
			 * spd_next walking.
			 *
			 * Routing should become RT_ROUTED_FAILURE,
			 * but if POLICY_FAIL_NONE, then we just go
			 * right back to RT_ROUTED_PROSPECTIVE as if
			 * no failure happened.
			 */
			enum routing_t new_routing =
				(sr->connection->config->failure_shunt == SHUNT_NONE ? RT_ROUTED_PROSPECTIVE :
				 RT_ROUTED_FAILURE);
			set_spd_routing(sr, new_routing);
			dbg("kernel: %s() skipping, first SPD and remotepeertype is CISCO, damage done",
			    __func__);
			continue;
		}

		dbg("kernel: %s() running 'down'", __func__);
		(void) do_command(sr->connection, sr, "down", st, st->st_logger);

		struct spd_route *esr = eclipsing(sr);
		if (esr != NULL) {

			/*
			 * ESR was eclipsed by SR.
			 *
			 * Instead of deleting SR's kernel policy,
			 * replace it with what ever the eclipsed ESR
			 * connection had before being eclipsed.
			 *
			 * The restored policy uses TRANSPORT mode
			 * (the host .{src,dst} provides the family
			 * but the address isn't used).
			 */
			pexpect(esr->routing == RT_ROUTED_ECLIPSED);
			set_spd_routing(esr, RT_ROUTED_PROSPECTIVE);
			teardown_kernel_policies(KP_REPLACE_OUTBOUND,
						 esr->connection->config->prospective_shunt,
						 esr, sr, expect_kernel_policy,
						 st->st_logger,
						 "restoring eclipsed");
#ifdef IPSEC_CONNECTION_LIMIT
			num_ipsec_eroute--;
#endif
			/* do now so route_owner() won't find us */
			set_spd_routing(sr, RT_UNROUTED);
			/* only unroute if no other connection shares it */
			if (route_owner(sr->connection, sr, NULL, NULL, NULL) == NULL) {
				do_command(sr->connection, sr, "unroute", NULL,
					   sr->connection->logger);
			}

		} else if (sr->connection->kind == CK_INSTANCE &&
			   ((sr->connection->policy & POLICY_OPPORTUNISTIC) ||
			    (sr->connection->policy & POLICY_DONT_REKEY))) {

			/*
			 *
			 * Case 1: just get rid of the IPSEC SA
			 *
			 * Case 2: even if the connection is still
			 * alive (due to an ISAKMP SA), we get rid of
			 * routing.
			 */
			teardown_kernel_policies(KP_DELETE_OUTBOUND,
						 sr->connection->config->failure_shunt/*delete so almost ignored!?!*/,
						 sr, sr, expect_kernel_policy,
						 st->st_logger,
						 "deleting instance");
#ifdef IPSEC_CONNECTION_LIMIT
			num_ipsec_eroute--;
#endif
			/* do now so route_owner won't find us */
			set_spd_routing(sr, RT_UNROUTED);
			/* only unroute if no other connection shares it */
			if (route_owner(sr->connection, sr, NULL, NULL, NULL) == NULL) {
				do_command(sr->connection, sr, "unroute", NULL,
					   sr->connection->logger);
			}

		} else {

			dbg("kernel: %s() calling bare_policy_op(REPLACE_OUTBOUND), it is the default", __func__);
			/*
			 * + if the .failure_shunt==SHUNT_NONE then
			 * the .prospective_shunt is chosen and that
			 * can't be SHUNT_NONE
			 *
			 * + if the .failure_shunt!=SHUNT_NONE then
			 * the .failure_shunt is chosen, and that
			 * isn't SHUNT_NONE.
			 *
			 * This code installs a TRANSPORT mode policy
			 * (the host .{src,dst} provides the family
			 * but the address isn't used).  The actual
			 * connection might be TUNNEL.
			 */
			enum routing_t new_routing = (sr->connection->config->failure_shunt == SHUNT_NONE ?
						      RT_ROUTED_PROSPECTIVE :
						      RT_ROUTED_FAILURE);
			enum shunt_policy shunt_policy = (sr->connection->config->failure_shunt == SHUNT_NONE ?
							  sr->connection->config->prospective_shunt :
							  sr->connection->config->failure_shunt);
			pexpect(shunt_policy != SHUNT_NONE);
			teardown_kernel_policies(KP_REPLACE_OUTBOUND,
						 shunt_policy,
						 sr, sr, expect_kernel_policy,
						 st->st_logger,
						 "replace");
			/* update routing; route_owner() will see this and fail */
			set_spd_routing(sr, new_routing);

		}
	}

	dbg("kernel: %s() calling teardown_half_ipsec_sa(outbound)", __func__);
	teardown_half_ipsec_sa(st, /*inbound?*/false);
	/* For larval IPsec SAs this may not exist */
	dbg("kernel: %s() calling teardown_half_ipsec_sa(inbound)", __func__);
	teardown_half_ipsec_sa(st, /*inbound*/true);
}

void delete_ipsec_sa(struct state *st)
{
	teardown_ipsec_sa(st, EXPECT_KERNEL_POLICY_OK);
}

void delete_larval_ipsec_sa(struct state *st)
{
	teardown_ipsec_sa(st, EXPECT_NO_INBOUND);
}

/*
 * Check if there was traffic on given SA during the last idle_max
 * seconds.  If TRUE, the SA was idle and DPD exchange should be
 * performed.  If FALSE, DPD is not necessary.  We also return TRUE
 * for errors, as they could mean that the SA is broken and needs to
 * be replace anyway.
 *
 * note: this mutates *st by calling get_sa_bundle_info
 *
 * XXX:
 *
 * The use of get_sa_bundle_info() here is likely bogus.  The function
 * returns the SA's add time (PF_KEY v2 documents it as such, xfrm
 * returns the .add_time field so presumably ...) when it is assumed
 * to be returning the idle time.
 *
 * Code most likely needs to track data+call-time and see if traffic
 * flowed since the last call.
 */

bool was_eroute_idle(struct state *st, deltatime_t since_when)
{
	passert(st != NULL);
	monotime_t last_contact;
	if (!get_sa_bundle_info(st, /*inbound*/true, &last_contact)) {
		/* snafu; assume idle!?! */
		return true;
	}
	deltatime_t idle_time = monotimediff(mononow(), last_contact);
	return deltatime_cmp(idle_time, >=, since_when);
}

static void set_sa_info(struct ipsec_proto_info *p2, uint64_t bytes,
			 uint64_t add_time, bool inbound, deltatime_t *ago)
{
	if (p2->add_time == 0 && add_time != 0)
		p2->add_time = add_time; /* this should happen exactly once */

	pexpect(p2->add_time == add_time);

	if (inbound) {
		if (bytes > p2->inbound.bytes) {
			p2->inbound.bytes = bytes;
			p2->inbound.last_used = mononow();
		}
		if (ago != NULL)
			*ago = monotimediff(mononow(), p2->inbound.last_used);
	} else {
		if (bytes > p2->outbound.bytes) {
			p2->outbound.bytes = bytes;
			p2->outbound.last_used = mononow();
		}
		if (ago != NULL)
			*ago = monotimediff(mononow(), p2->outbound.last_used);
	}
}

/*
 * get information about a given SA bundle
 *
 * ??? needs merging with was_eroute_idle
 *
 * Note: this mutates *st.
 * Note: this only changes counts in the first SA in the bundle!
 */
bool get_sa_bundle_info(struct state *st, bool inbound, monotime_t *last_contact /* OUTPUT */)
{
	struct connection *const c = st->st_connection;

	if (kernel_ops->get_sa == NULL) {
		return false;
	}

	const struct ip_protocol *proto;
	struct ipsec_proto_info *pi;

	if (st->st_esp.present) {
		proto = &ip_protocol_esp;
		pi = &st->st_esp;
	} else if (st->st_ah.present) {
		proto = &ip_protocol_ah;
		pi = &st->st_ah;
	} else if (st->st_ipcomp.present) {
		proto = &ip_protocol_ipcomp;
		pi = &st->st_ipcomp;
	} else {
		return false;
	}

	if (inbound) {
		if (pi->inbound.kernel_sa_expired & SA_HARD_EXPIRED) {
			dbg("kernel expired inbound SA SPI "PRI_IPSEC_SPI" skip get_sa_info()",
			    pri_ipsec_spi(pi->inbound.spi));
			return true; /* all is well use the last known info */
		}
	} else {
		if (pi->outbound.kernel_sa_expired & SA_HARD_EXPIRED) {
			dbg("kernel expired outbound SA SPI "PRI_IPSEC_SPI" get_sa_info()",
			    pri_ipsec_spi(pi->outbound.spi));
			return true; /* all is well use last known info */
		}
	}

	/*
	 * If we were redirected (using the REDIRECT mechanism),
	 * change remote->host.addr temporarily, we reset it back
	 * later.
	 */
	bool redirected = false;
	ip_address tmp_host_addr = unset_address;
	unsigned tmp_host_port = 0;
	if (!endpoint_address_eq_address(st->st_remote_endpoint, c->remote->host.addr) &&
	    address_is_specified(c->temp_vars.redirect_ip)) {
		redirected = true;
		tmp_host_addr = c->remote->host.addr;
		tmp_host_port = c->spd.that.host->port; /* XXX: needed? */
		c->remote->host.addr = endpoint_address(st->st_remote_endpoint);
		c->spd.that.host->port = endpoint_hport(st->st_remote_endpoint);
	}

	ip_address src, dst;
	ipsec_spi_t spi;
	if (inbound) {
		src = c->remote->host.addr;
		dst = c->local->host.addr;
		spi = pi->inbound.spi;
	} else {
		src = c->local->host.addr;
		dst = c->remote->host.addr;
		spi = pi->outbound.spi;
	}

	said_buf sb;
	struct kernel_sa sa = {
		.spi = spi,
		.proto = proto,
		.src.address = src,
		.dst.address = dst,
		.story = said_str(dst, proto, spi, &sb),
	};

	dbg("kernel: get_sa_bundle_info %s", sa.story);

	uint64_t bytes;
	uint64_t add_time;
	if (!kernel_ops->get_sa(&sa, &bytes, &add_time, st->st_logger))
		return false;

	pi->add_time = add_time;

	/* field has been set? */
	passert(!is_monotime_epoch(pi->inbound.last_used));
	passert(!is_monotime_epoch(pi->outbound.last_used));

	uint64_t *pb = inbound ? &pi->inbound.bytes : &pi->outbound.bytes;
	monotime_t *plu = inbound ? &pi->inbound.last_used : &pi->outbound.last_used;

	if (bytes > *pb) {
		*pb = bytes;
		*plu = mononow();
	}
	if (last_contact != NULL)
		*last_contact = *plu;

	if (redirected) {
		c->remote->host.addr = tmp_host_addr;
		c->spd.that.host->port = tmp_host_port;
	}

	return true;
}

bool orphan_holdpass(const struct connection *c, struct spd_route *sr,
		     enum shunt_policy failure_shunt, struct logger *logger)
{
	enum routing_t ro = sr->routing,        /* routing, old */
			rn = ro;                 /* routing, new */
	enum shunt_policy negotiation_shunt = c->config->negotiation_shunt;

	if (negotiation_shunt != failure_shunt ) {
		dbg("kernel: failureshunt != negotiationshunt, needs replacing");
	} else {
		dbg("kernel: failureshunt == negotiationshunt, no replace needed");
	}

	dbg("kernel: orphan_holdpass() called for %s with transport_proto '%d' and sport %d and dport %d",
	    c->name, sr->this.client.ipproto, sr->this.client.hport, sr->that.client.hport);

	passert(LHAS(LELEM(CK_PERMANENT) | LELEM(CK_INSTANCE) |
				LELEM(CK_GOING_AWAY), c->kind));

	switch (ro) {
	case RT_UNROUTED_HOLD:
		rn = RT_UNROUTED;
		dbg("kernel: orphan_holdpass unrouted: hold -> pass");
		break;
	case RT_UNROUTED:
		rn = RT_UNROUTED_HOLD;
		dbg("kernel: orphan_holdpass unrouted: pass -> hold");
		break;
	case RT_ROUTED_HOLD:
		rn = RT_ROUTED_PROSPECTIVE;
		dbg("kernel: orphan_holdpass routed: hold -> trap (?)");
		break;
	default:
		dbg("kernel: no routing change needed for ro=%s - negotiation shunt matched failure shunt?",
		    enum_name(&routing_story, ro));
		break;
	}

	dbg("kernel: orphaning holdpass for connection '%s', routing was %s, needs to be %s",
	    c->name,
	    enum_name(&routing_story, ro),
	    enum_name(&routing_story, rn));

	{
		/* are we replacing a bare shunt ? */
		struct bare_shunt **old = bare_shunt_ptr(&sr->this.client,
							 &sr->that.client,
							 "orphan holdpass");
		if (old != NULL) {
			free_bare_shunt(old);
		}
	}

	{
		/*
		 * Create the bare shunt and ...
		 */
		add_bare_shunt(&sr->this.client, &sr->that.client,
			       negotiation_shunt,
			       ((strstr(c->name, "/32") != NULL ||
				 strstr(c->name, "/128") != NULL) ? c->serialno : 0),
			       "oe-failing", logger);

		/*
		 * ... UPDATE kernel policy if needed.
		 *
		 * This really causes the name to remain "oe-failing",
		 * we should be able to update only only the name of
		 * the shunt.
		 */
		if (negotiation_shunt != failure_shunt ) {

			dbg("kernel: replacing negotiation_shunt with failure_shunt");

			/* fudge up parameter list */
			const ip_address *src_address = &sr->this.host->addr;
			const ip_address *dst_address = &sr->that.host->addr;
			policy_prio_t policy_prio = BOTTOM_PRIO;	/* of replacing shunt*/
			const char *why = "oe-failed";

			/* fudge up replace_bare_shunt() */
			const struct ip_info *afi = address_type(src_address);
			passert(afi == address_type(dst_address));
			const ip_protocol *protocol = protocol_by_ipproto(sr->this.client.ipproto);
			/* ports? assumed wide? */
			ip_selector src = selector_from_address_protocol(*src_address, protocol);
			ip_selector dst = selector_from_address_protocol(*dst_address, protocol);

			selectors_buf sb;
			dbg("kernel: replace bare shunt %s for %s",
			    str_selectors(&src, &dst, &sb), why);

			/*
			 * ??? this comment might be obsolete.
			 *
			 * If the transport protocol is not the
			 * wildcard (0), then we need to look for a
			 * host<->host shunt, and replace that with
			 * the shunt spi, and then we add a %HOLD for
			 * what was there before.
			 *
			 * This is at odds with !repl, which should
			 * delete things.
			 */

			struct kernel_policy outbound_kernel_policy =
				bare_kernel_policy(&src, &dst);
			bool ok = raw_policy(KP_REPLACE_OUTBOUND,
					     EXPECT_KERNEL_POLICY_OK,
					     &outbound_kernel_policy.src.client,
					     &outbound_kernel_policy.dst.client,
					     failure_shunt,
					     (failure_shunt == SHUNT_PASS ? NULL :
					      &outbound_kernel_policy),
					     deltatime(SHUNT_PATIENCE),
					     0, /* we don't know connection for priority yet */
					     /*sa_marks+xfrmi*/NULL,NULL,
					     null_shunk, logger,
					     "%s() %s", __func__, why);
			if (!ok) {
				llog(RC_LOG, logger,
				     "replace kernel shunt %s failed - deleting from pluto shunt table",
				     str_selectors_sensitive(&src, &dst, &sb));
			}

			/*
			 * We can have proto mismatching acquires with
			 * xfrm - this is a bad workaround.
			 *
			 * ??? what is the nature of those mismatching
			 * acquires?
			 *
			 * XXX: for instance, when whack initiates an
			 * OE connection.  There is no kernel-acquire
			 * shunt to remove.
			 *
			 * XXX: see above, this code is looking for
			 * and fiddling with the shunt only just added
			 * above?
			 */
			struct bare_shunt **bs_pp = bare_shunt_ptr(&src, &dst, why);
			/* passert(bs_pp != NULL); */
			if (bs_pp == NULL) {
				selectors_buf sb;
				llog(RC_LOG, logger,
				     "can't find expected bare shunt to %s: %s",
				     ok ? "replace" : "delete",
				     str_selectors_sensitive(&src, &dst, &sb));
			} else if (ok) {
				/*
				 * change over to new bare eroute
				 * ours, peers, transport_proto are
				 * the same.
				 */
				struct bare_shunt *bs = *bs_pp;
				bs->why = why;
				bs->policy_prio = policy_prio;
				bs->shunt_policy = failure_shunt;
				bs->count = 0;
				bs->last_activity = mononow();
				dbg_bare_shunt("replace", bs);
			} else {
				llog(RC_LOG, logger,
				     "assign_holdpass() failed to update shunt policy");
				free_bare_shunt(bs_pp);
			}
		} else {
			dbg("kernel: No need to replace negotiation_shunt with failure_shunt - they are the same");
		}
	}

	/* change routing so we don't get cleared out when state/connection dies */
	set_spd_routing(sr, rn);
	dbg("kernel: orphan_holdpas() done - returning success");
	return true;
}

static void expire_bare_shunts(struct logger *logger)
{
	dbg("kernel: checking for aged bare shunts from shunt table to expire");
	for (struct bare_shunt **bspp = &bare_shunts; *bspp != NULL; ) {
		struct bare_shunt *bsp = *bspp;
		time_t age = deltasecs(monotimediff(mononow(), bsp->last_activity));

		if (age > deltasecs(pluto_shunt_lifetime)) {
			dbg_bare_shunt("expiring old", bsp);
			if (co_serial_is_set(bsp->from_serialno)) {
				/*
				 * Time to restore the connection's
				 * shunt.  Presumably the bare shunt
				 * was a place holder while things
				 * were given time to rest (back-off).
				 */
				struct connection *c = connection_by_serialno(bsp->from_serialno);
				if (c != NULL) {
					if (!bare_policy_op(KP_ADD_OUTBOUND,
							    EXPECT_KERNEL_POLICY_OK,
							    c, &c->spd,
							    RT_ROUTED_PROSPECTIVE,
							    "expire_bare_shunts() add",
							    logger)) {
						llog(RC_LOG, logger,
						     "trap shunt install failed ");
					}
				}
			} else {
				if (!delete_bare_shunt_kernel_policy(bsp, logger, HERE)) {
					llog_bare_shunt(RC_LOG_SERIOUS, logger, bsp,
							"failed to delete bare shunt");
				}
			}
			free_bare_shunt(bspp);
		} else {
			dbg_bare_shunt("keeping recent", bsp);
			bspp = &bsp->next;
		}
	}
}

static void delete_bare_shunts(struct logger *logger)
{
	dbg("kernel: emptying bare shunt table");
	while (bare_shunts != NULL) { /* nothing left */
		const struct bare_shunt *bsp = bare_shunts;
		if (!delete_bare_shunt_kernel_policy(bsp, logger, HERE)) {
			llog_bare_shunt(RC_LOG_SERIOUS, logger, bsp,
					"failed to delete bare shunt's kernel policy"); /* big oops */
		}
		free_bare_shunt(&bare_shunts); /* also updates BARE_SHUNTS */
	}
}

static void kernel_scan_shunts(struct logger *logger)
{
	expire_bare_shunts(logger);
}

void shutdown_kernel(struct logger *logger)
{

	if (kernel_ops->shutdown != NULL) {
		kernel_ops->shutdown(logger);
	}
	delete_bare_shunts(logger);
}

void handle_sa_expire(ipsec_spi_t spi, uint8_t protoid, ip_address *dst,
		       bool hard, uint64_t bytes, uint64_t packets, uint64_t add_time)
{
	struct child_sa *child = find_v2_child_sa_by_spi(spi, protoid, dst);

	if (child == NULL) {
		address_buf a;
		dbg("received kernel %s EXPIRE event for IPsec SPI 0x%x, but there is no connection with this SPI and dst %s bytes %" PRIu64 " packets %" PRIu64,
		     hard ? "hard" : "soft",
		     ntohl(spi), str_address(dst, &a), bytes, packets);
		return;
	}

	const struct connection *c = child->sa.st_connection;

	if ((hard && impair.ignore_hard_expire) ||
	    (!hard && impair.ignore_soft_expire)) {
		address_buf a;
		llog_sa(RC_LOG, child,
			"IMPAIR: suppressing a %s EXPIRE event spi 0x%x dst %s bytes %" PRIu64 " packets %" PRIu64,
			hard ? "hard" : "soft", ntohl(spi), str_address(dst, &a),
			bytes, packets);
		return;
	}

	bool rekey = !LIN(POLICY_DONT_REKEY, c->policy);
	bool newest = c->newest_ipsec_sa == child->sa.st_serialno;
	struct state *st =  &child->sa;
	struct ipsec_proto_info *pr = (st->st_esp.present ? &st->st_esp :
				       st->st_ah.present ? &st->st_ah :
				       st->st_ipcomp.present ? &st->st_ipcomp :
				       NULL);

	bool already_softexpired = ((pr->inbound.kernel_sa_expired & SA_SOFT_EXPIRED) ||
				    (pr->outbound.kernel_sa_expired & SA_SOFT_EXPIRED));

	bool already_hardexpired = ((pr->inbound.kernel_sa_expired & SA_HARD_EXPIRED) ||
				    (pr->outbound.kernel_sa_expired & SA_HARD_EXPIRED));

	enum sa_expire_kind expire = hard ? SA_HARD_EXPIRED : SA_SOFT_EXPIRED;

	/*
	 * OUR_SPI was sent by us to our peer, so that our peer can
	 * include it in all inbound IPsec messages.
	 */
	const bool inbound = (pr->inbound.spi == spi);

	llog_sa(RC_LOG, child,
		"received %s EXPIRE for %s SPI "PRI_IPSEC_SPI" bytes %" PRIu64 " packets %" PRIu64 " rekey=%s%s%s%s%s",
		hard ? "hard" : "soft",
		(inbound ? "inbound" : "outbound"), pri_ipsec_spi(spi),
		bytes, packets,
		rekey ?  "yes" : "no",
		already_softexpired ? "; already soft expired" : "",
		already_hardexpired ? "; already hard expired" : "",
		(newest ? "" : "; deleting old SA"),
		(newest && rekey && !already_softexpired && !already_hardexpired) ? "; replacing" : "");

	if ((already_softexpired && expire == SA_SOFT_EXPIRED)  ||
	    (already_hardexpired && expire == SA_HARD_EXPIRED)) {
		dbg("#%lu one of the SA has already expired ignore this %s EXPIRE",
		    child->sa.st_serialno, hard ? "hard" : "soft");
		/*
		 * likely the other direction SA EXPIRED, it triggered a rekey first.
		 * It should be safe to ignore the second one. No need to log.
		 */
	} else if (!already_hardexpired && expire == SA_HARD_EXPIRED) {
		if (inbound) {
			pr->inbound.kernel_sa_expired |= expire;
			set_sa_info(pr, bytes, add_time, true /* inbound */, NULL);
		} else {
			pr->outbound.kernel_sa_expired |= expire;
			set_sa_info(pr, bytes, add_time, false /* outbound */, NULL);
		}
		set_sa_expire_next_event(EVENT_SA_EXPIRE, &child->sa);
	} else if (newest && rekey && !already_hardexpired && !already_softexpired && expire == SA_SOFT_EXPIRED) {
		if (inbound) {
			pr->inbound.kernel_sa_expired |= expire;
			set_sa_info(pr, bytes, add_time, true /* inbound */, NULL);
		} else {
			pr->outbound.kernel_sa_expired |= expire;
			set_sa_info(pr, bytes, add_time, false /* outbound */, NULL);
		}
		set_sa_expire_next_event(EVENT_NULL/*either v2 REKEY or v1 REPLACE*/, &child->sa);
	} else {
		/*
		 * 'if' and multiple 'else if's are using multiple variables.
		 * I may have overlooked some cases. lets break hard on unexpected cases.
		 */
		passert(1); /* lets break! */
	}
}
