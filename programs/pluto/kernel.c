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
#include "kernel_xfrm_interface.h"
#include "iface.h"
#include "ip_selector.h"
#include "ip_encap.h"
#include "show.h"
#include "rekeyfuzz.h"
#include "orient.h"

static bool sag_eroute(const struct state *st,
		       const struct spd_route *sr,
		       enum kernel_policy_op op,
		       const char *opname);

static struct kernel_policy kernel_policy_from_spd(lset_t policy,
						   reqid_t child_reqid,
						   const struct spd_route *spd,
						   enum encap_mode mode,
						   enum direction direction,
						   kernel_priority_t priority,
						   where_t where);
static void free_bare_shunt(struct bare_shunt **pp);
static void delete_bare_kernel_policy(const struct bare_shunt *bsp,
				      struct logger *logger,
				      where_t where);

/*
 * The priority assigned to a kernel policy.
 *
 * Lowest wins.
 */

kernel_priority_t highest_kernel_priority = { .value = 0, };

kernel_priority_t calculate_kernel_priority(const struct connection *c)
{
	if (c->sa_priority != 0) {
		ldbg(c->logger,
		     "priority calculation overruled by connection specification of %"PRIu32" (%#"PRIx32")",
		     c->sa_priority, c->sa_priority);
		return (kernel_priority_t) { c->sa_priority, };
	}

	if (LIN(POLICY_GROUP, c->policy)) {
		llog_pexpect(c->logger, HERE,
			     "priority calculation of connection skipped - group template does not install SPDs");
		return highest_kernel_priority;
	}

	/* XXX: assume unsigned >= 32-bits */
	PASSERT(c->logger, sizeof(unsigned) >= sizeof(uint32_t));

	/*
	 * Accumulate the priority.
	 *
	 * Add things most-important to least-important. Before ORing
	 * in the new bits, left-shift PRIO to make space.
	 */
	unsigned prio = 0;

	/* Determine the base priority (2 bits) (0 is manual by user). */
	unsigned base;
	if (LIN(POLICY_GROUPINSTANCE, c->policy)) {
		if (c->remote->host.config->authby.null) {
			base = 3; /* opportunistic anonymous */
		} else {
			base = 2; /* opportunistic */
		}
	} else {
		base = 1; /* static connection */
	}

	/* XXX: yes the shift is pointless (but it is consistent) */
	prio = (prio << 2) | base;

	/* Penalize wildcard ports (2 bits). */
	unsigned portsw =
		((c->spd->local->client.hport == 0 ? 1 : 0) +
		 (c->spd->remote->client.hport == 0 ? 1 : 0));
	prio = (prio << 2) | portsw;

	/* Penalize wildcard protocol (1 bit). */
	unsigned protow = c->spd->local->client.ipproto == 0 ? 1 : 0;
	prio = (prio << 1) | protow;

	/*
	 * For transport mode or /32 to /32, the client mask bits are
	 * set based on the host_addr parameters.
	 *
	 * A longer prefix wins over a shorter prefix, hence the
	 * reversal.  Value needs to fit 0-128, hence 8 bits.
	 */
	unsigned srcw = 128 - c->spd->local->client.maskbits;
	prio = (prio << 8) | srcw;
	unsigned dstw = 128 - c->spd->remote->client.maskbits;
	prio = (prio << 8) | dstw;

	/*
	 * Penalize template (1 bit).
	 *
	 * "Ensure an instance always has preference over it's
	 * template/OE-group always has preference."
	 */
	unsigned instw = (c->kind == CK_INSTANCE ? 0 : 1);
	prio = (prio << 1) | instw;

	ldbg(c->logger,
	     "priority calculation of is %u (%#x) base=%u portsw=%u protow=%u, srcw=%u dstw=%u instw=%u",
	     prio, prio, base, portsw, protow, srcw, dstw, instw);
	return (kernel_priority_t) { prio, };
}

static bool eroute_outbound_connection(enum kernel_policy_op op,
				       const char *opname,
				       const struct spd_route *sr,
				       const struct kernel_policy *kernel_policy,
				       const struct sa_marks *sa_marks,
				       const struct pluto_xfrmi *xfrmi,
				       shunk_t sec_label,
				       struct logger *logger);

static global_timer_cb kernel_scan_shunts;

bool prospective_shunt_ok(enum shunt_policy shunt)
{
	switch (shunt) {
	case SHUNT_TRAP:
	case SHUNT_PASS:
	case SHUNT_DROP:
	case SHUNT_REJECT:
		return true;
	case SHUNT_UNSET:
	case SHUNT_NONE: /* XXX: no default */
	case SHUNT_HOLD:
		break;
	}
	return false;
}

bool negotiation_shunt_ok(enum shunt_policy shunt)
{
	switch (shunt) {
	case SHUNT_PASS:
	case SHUNT_HOLD:
		return true;
	case SHUNT_UNSET:
	case SHUNT_TRAP: /* XXX: no default */
	case SHUNT_DROP:
	case SHUNT_REJECT:
	case SHUNT_NONE:
		break;
	}
	return false;
}

bool failure_shunt_ok(enum shunt_policy shunt)
{
	switch (shunt) {
	case SHUNT_NONE:
	case SHUNT_PASS:
	case SHUNT_DROP:
	case SHUNT_REJECT:
		return true;
	case SHUNT_UNSET:
	case SHUNT_TRAP: /* XXX: no default */
	case SHUNT_HOLD:
		break;
	}
	return false;
}

/*
 * Add an outbound bare kernel policy, aka shunt.
 *
 * Such a kernel policy determines the fate of packets without the use
 * of any SAs.  These are defaults, in effect.  If a negotiation has
 * not been attempted, use %trap.  If negotiation has failed, the
 * choice between %trap/%pass/%drop/%reject is specified in the policy
 * of connection c.
 *
 * The kernel policy is refered to as bare (naked, global) as it is
 * not paired with a kernel state.
 */

static bool install_prospective_kernel_policies(enum expect_kernel_policy expect_inbound_policy,
						const struct spd_route *spd,
						struct logger *logger, where_t where)
{
	const struct connection *c = spd->connection;

	/*
	 * Only the following shunts are valid.
	 */
	enum shunt_policy prospective_shunt = c->config->prospective_shunt;
	passert(prospective_shunt_ok(prospective_shunt));

	LSWDBGP(DBG_BASE, buf) {
		jam(buf, "kernel: %s() ", __func__);

		jam_string(buf, " ");
		jam_string(buf, expect_kernel_policy_name(expect_inbound_policy));

		jam_connection(buf, c);

		enum_buf spb;
		jam(buf, " prospective_shunt=%s",
		    str_enum_short(&shunt_policy_names, prospective_shunt, &spb));

		jam(buf, " ");
		jam_selector_pair(buf, &spd->local->client, &spd->remote->client);

		jam(buf, " config.sec_label=");
		if (c->config->sec_label.len > 0) {
			jam_sanitized_hunk(buf, c->config->sec_label);
		}

		jam(buf, PRI_WHERE, pri_where(where));
	}

	kernel_priority_t priority = calculate_kernel_priority(c);

	/*
	 * Only the following shunts are valid.
	 */
	FOR_EACH_THING(direction, DIRECTION_OUTBOUND, DIRECTION_INBOUND) {

		/*
		 * Security labels install a full policy which
		 * includes REQID and assumed mode when adding the
		 * prospective shunt but normal connections do not.
		 */
		struct kernel_policy policy;
		if (c->config->sec_label.len > 0) {
			enum encap_mode encap_mode = (c->policy & POLICY_TUNNEL ? ENCAP_MODE_TUNNEL :
						      ENCAP_MODE_TRANSPORT);
			policy = kernel_policy_from_spd(c->policy,
							c->child.reqid,
							spd,
							encap_mode, direction,
							priority, HERE);
		} else {
			policy = kernel_policy_from_void(spd->local->client, spd->remote->client,
							 direction, priority,
							 prospective_shunt, where);
		}

		/*
		 * Note the NO_INBOUND_ENTRY.  It's a hack to get
		 * around a connection being unrouted, deleting both
		 * inbound and outbound policies when there's only the
		 * basic outbound policy installed.
		 */

		if (!raw_policy(KERNEL_POLICY_OP_ADD, direction,
				(direction == DIRECTION_OUTBOUND ? EXPECT_KERNEL_POLICY_OK :
				 expect_inbound_policy),
				&policy.src.client, &policy.dst.client, &policy,
				deltatime(0),
				&c->sa_marks, c->xfrmi,
				DEFAULT_KERNEL_POLICY_ID,
				HUNK_AS_SHUNK(c->config->sec_label),
				logger,
				"%s() prospective kernel policy "PRI_WHERE,
				__func__, pri_where(where))) {
			return false;
		}
	}
	return true;
}


struct kernel_policy kernel_policy_from_void(ip_selector local, ip_selector remote,
					     enum direction direction,
					     kernel_priority_t priority,
					     enum shunt_policy shunt_policy,
					     where_t where)
{
	const ip_selector *src;
	const ip_selector *dst;
	switch (direction) {
	case DIRECTION_OUTBOUND:
		src = &local;
		dst = &remote;
		break;
	case DIRECTION_INBOUND:
		src = &remote;
		dst = &local;
		break;
	default:
		bad_case(direction);
	}

	const struct ip_info *child_afi = selector_type(src);
	pexpect(selector_type(dst) == child_afi);

	struct kernel_policy transport_esp = {
		/* what will capture packets */
		.src.client = *src,
		.dst.client = *dst,
		.src.route = *src,
		.dst.route = *dst,
		.priority = priority,
		.shunt = shunt_policy,
		.where = where,
		/*
		 * With transport mode, the encapsulated packet on the
		 * host interface must have the same family as the raw
		 * packet on the client interface.  Even though it is
		 * UNSPEC.
		 */
		.src.host = child_afi->address.unspec,
		.dst.host = child_afi->address.unspec,
		.mode = ENCAP_MODE_TRANSPORT,
	};
	if (shunt_policy != SHUNT_PASS) {
		transport_esp.nr_rules = 1;
		transport_esp.rule[0] = (struct kernel_policy_rule) {
			.proto = ENCAP_PROTO_ESP,
			.reqid = 0,
		};
	}
	return transport_esp;
}

struct bare_shunt {
	connection_priority_t policy_prio;
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
	jam_selector_pair(buf, &bs->our_client, &bs->peer_client);
	jam(buf, " => ");
	jam_enum_short(buf, &shunt_policy_names, bs->shunt_policy);
	jam(buf, " ");
	jam_connection_priority(buf, bs->policy_prio);
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
	bs->policy_prio = BOTTOM_PRIORITY;
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

ipsec_spi_t get_ipsec_spi(const struct connection *c,
			  const struct ip_protocol *proto,
			  ipsec_spi_t avoid,
			  struct logger *logger)
{
	passert(proto == &ip_protocol_ah || proto == &ip_protocol_esp);
	return kernel_ops_get_ipsec_spi(avoid,
					/*src*/&c->remote->host.addr,
					/*dst*/&c->local->host.addr,
					proto,
					get_proto_reqid(c->child.reqid, proto),
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
ipsec_spi_t get_ipsec_cpi(const struct connection *c, struct logger *logger)
{
	return kernel_ops_get_ipsec_spi(0,
					/*src*/&c->remote->host.addr,
					/*dst*/&c->local->host.addr,
					&ip_protocol_ipcomp,
					get_proto_reqid(c->child.reqid, &ip_protocol_ipcomp),
					IPCOMP_FIRST_NEGOTIATED,
					IPCOMP_LAST_NEGOTIATED,
					"CPI", logger);
}

/*
 * Build an array of encapsulation rules/tmpl.  Order things
 * inner-most to outer-most so the last entry is what will go across
 * the wire.  A -1 entry of the packet to be encapsulated is implied.
 */

struct kernel_route {
	enum encap_mode mode;
	struct {
		ip_address address; /* ip_endpoint? */
		ip_selector route; /* ip_address? */
	} src, dst;
};

static struct kernel_route kernel_route_from_state(const struct state *st, enum direction direction)
{
	const struct connection *c = st->st_connection;

	enum encap_mode mode = ENCAP_MODE_TRANSPORT;
	FOR_EACH_THING(proto, &st->st_esp, &st->st_ah) {
		if (proto->present && proto->attrs.mode == ENCAPSULATION_MODE_TUNNEL) {
			mode = ENCAP_MODE_TUNNEL;
			break;
		}
	}

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
	ip_selector local_route;
	ip_selector remote_route;
	const ip_selectors *local = &c->local->child.selectors.accepted;
	const ip_selectors *remote = &c->remote->child.selectors.accepted;
	switch (mode) {
	case ENCAP_MODE_TUNNEL:
		local_route = unset_selector;	/* XXX: kernel_policy has spd->client */
		remote_route = unset_selector;	/* XXX: kernel_policy has spd->client */
		break;
	case ENCAP_MODE_TRANSPORT:
		/*
		 * XXX: need to work around:
		 *
		 * - IKEv1 which is clueless to selectors.accepted
		 * - CP which skips setting TS
		 * - CK_PERMENANT that doesn't update TS
		 */
		local_route = (local->len > 0 ? local->list[0] :
			       c->spd->local->client);
		ip_selector remote_client = (remote->len > 0 ? remote->list[0] :
					     c->spd->remote->client);
		/* reroute remote to pair up with dest */
		remote_route = selector_from_address_protocol_port(c->remote->host.addr,
								   selector_protocol(remote_client),
								   selector_port(remote_client));
		break;
	default:
		bad_case(mode);
	}

	switch (direction) {
	case DIRECTION_INBOUND:
		return (struct kernel_route) {
			.mode = mode,
			.src.address = c->remote->host.addr,
			.dst.address = c->local->host.addr,
			.src.route = remote_route,
			.dst.route = local_route,
		};
	case DIRECTION_OUTBOUND:
		return (struct kernel_route) {
			.mode = mode,
			.src.address = c->local->host.addr,
			.dst.address = c->remote->host.addr,
			.src.route = local_route,
			.dst.route = remote_route,
		};
	default:
		bad_case(direction);
	}
}

static struct kernel_policy kernel_policy_from_spd(lset_t policy,
						   reqid_t child_reqid,
						   const struct spd_route *spd,
						   enum encap_mode mode,
						   enum direction direction,
						   kernel_priority_t priority,
						   where_t where)
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
		remote_client = spd->remote->client;
		break;
	case ENCAP_MODE_TRANSPORT:
		remote_client = selector_from_address_protocol_port(spd->remote->host->addr,
								    selector_protocol(spd->remote->client),
								    selector_port(spd->remote->client));
		break;
	default:
		bad_case(mode);
	}

	const struct spd_end *src;
	const struct spd_end *dst;
	ip_selector src_route, dst_route;
	switch (direction) {
	case DIRECTION_INBOUND:
		src = spd->remote;
		dst = spd->local;
		src_route = remote_client;
		dst_route = dst->client;	/* XXX: kernel_route has unset_selector */
		break;
	case DIRECTION_OUTBOUND:
		src = spd->local;
		dst = spd->remote;
		src_route = src->client;	/* XXX: kernel_route has unset_selector */
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
		.priority = priority,
		.mode = mode,
		.shunt = SHUNT_UNSET,
		.where = where,
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

	struct kernel_policy_rule *last = kernel_policy.rule;
	if (policy & POLICY_COMPRESS) {
		last->reqid = reqid_ipcomp(child_reqid);
		last->proto = ENCAP_PROTO_IPCOMP;
		last++;
	}
	if (policy & POLICY_ENCRYPT) {
		last->reqid = reqid_esp(child_reqid);
		last->proto = ENCAP_PROTO_ESP;
		last++;
	}
	if (policy & POLICY_AUTHENTICATE) {
		last->reqid = reqid_ah(child_reqid);
		last->proto = ENCAP_PROTO_AH;
		last++;
	}

	passert(last < kernel_policy.rule + elemsof(kernel_policy.rule));
	kernel_policy.nr_rules = last - kernel_policy.rule;
	passert(kernel_policy.nr_rules < elemsof(kernel_policy.rule));

	return kernel_policy;
}

static struct kernel_policy kernel_policy_from_state(const struct state *st,
						     const struct spd_route *spd,
						     enum direction direction,
						     kernel_priority_t priority,
						     where_t where)
{
	const struct connection *cc = st->st_connection;
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
	struct kernel_policy kernel_policy = kernel_policy_from_spd(policy,
								    cc->child.reqid,
								    spd, mode, direction,
								    priority,
								    where);
	return kernel_policy;
}

/*
 * Find the connection to connection c's peer's client with the
 * largest value of .routing.  If none is routed, return NULL.
 *
 * The return value is used to find other connections sharing a
 * destination (route).
 */

static struct spd_route *route_owner(const struct spd_route *spd)
{
	struct connection *c = spd->connection;
	if (!oriented(c)) {
		llog(RC_LOG, c->logger,
		     "route_owner: connection no longer oriented - system interface change?");
		return NULL;
	}

	enum routing best_routing = RT_UNROUTED;
	struct spd_route *best_route_spd = NULL;

	struct spd_route_filter srf = {
		.remote_client_range = &spd->remote->client,
		.where = HERE,
	};
	while (next_spd_route(NEW2OLD, &srf)) {
		struct spd_route *d_spd = srf.spd;
		struct connection *d = d_spd->connection;

		if (spd == d_spd)
			continue;

		if (!oriented(d))
			continue;

		if (d->child.routing == RT_UNROUTED)
			continue;

		/* lookup did it's job */
		pexpect(selector_range_eq_selector_range(spd->remote->client,
							 d_spd->remote->client));
		if (!selector_eq_selector(spd->remote->client,
					  d_spd->remote->client)) {
			continue;
		}
		if (!address_eq_address(c->local->host.addr,
					d->local->host.addr)) {
			continue;
		}

		/*
		 * Consider policies different if the either
		 * in or out marks differ (after masking).
		 */
		if (DBGP(DBG_BASE)) {
			connection_buf cb;
			DBG_log(" conn "PRI_CONNECTION" mark %" PRIu32 "/%#08" PRIx32 ", %" PRIu32 "/%#08" PRIx32 " vs",
				pri_connection(c, &cb),
				c->sa_marks.in.val, c->sa_marks.in.mask,
				c->sa_marks.out.val, c->sa_marks.out.mask);
			connection_buf db;
			DBG_log(" conn "PRI_CONNECTION" mark %" PRIu32 "/%#08" PRIx32 ", %" PRIu32 "/%#08" PRIx32,
				pri_connection(d, &db),
				d->sa_marks.in.val, d->sa_marks.in.mask,
				d->sa_marks.out.val, d->sa_marks.out.mask);
		}

		if ( (c->sa_marks.in.val & c->sa_marks.in.mask) != (d->sa_marks.in.val & d->sa_marks.in.mask) ||
		     (c->sa_marks.out.val & c->sa_marks.out.mask) != (d->sa_marks.out.val & d->sa_marks.out.mask) )
			continue;

		if (d->child.routing > best_routing) {
			dbg("    saving route");
			best_route_spd = d_spd;
			best_routing = d->child.routing;
		}

	}

	LSWDBGP(DBG_BASE, buf) {
		connection_buf cib;
		jam(buf, "route owner of "PRI_CONNECTION" %s; routing: ",
		    pri_connection(c, &cib),
		    enum_name(&routing_story, c->child.routing));

		if (!routed(best_routing)) {
			jam(buf, "NULL");
		} else if (best_route_spd->connection == spd->connection &&
			   best_route_spd != spd) {
			jam(buf, "sibling");
		} else if (best_route_spd == spd) {
			jam(buf, "self");
		} else {
			connection_buf cib;
			jam(buf, ""PRI_CONNECTION" %s",
			    pri_connection(best_route_spd->connection, &cib),
			    enum_name(&routing_story, best_routing));
		}
	}

	return routed(best_routing) ? best_route_spd : NULL;
}

/*
 * handle co-terminal attempt of the "near" kind
 *
 * Note: it mutates both inside and outside
 */

enum routability {
	ROUTE_IMPOSSIBLE,
	ROUTE_UNNECESSARY,
	ROUTEABLE,
};

static enum routability connection_routability(struct connection *c,
					       struct logger *logger)
{
	esb_buf b;
	ldbg(logger,
	     "kernel: %s() kind=%s remote.has_client=%s oppo=%s local.host.port=%u sec_label="PRI_SHUNK,
	     __func__,
	     enum_show(&connection_kind_names, c->kind, &b),
	     bool_str(c->remote->child.has_client),
	     bool_str(c->policy & POLICY_OPPORTUNISTIC),
	     c->local->host.port,
	     pri_shunk(c->config->sec_label));

	/* it makes no sense to route a connection that is ISAKMP-only */
	if (!NEVER_NEGOTIATE(c->policy) && !HAS_IPSEC_POLICY(c->policy)) {
		llog(RC_ROUTE, logger,
		     "cannot route an %s-only connection",
		     c->config->ike_info->sa_name[IKE_SA]);
		return ROUTE_IMPOSSIBLE;
	}

	/*
	 * if this is a transport SA, and overlapping SAs are supported, then
	 * this route is not necessary at all.
	 */
	if (kernel_ops->overlap_supported && !LIN(POLICY_TUNNEL, c->policy)) {
		ldbg(logger, "route-unnecessary: overlap and !tunnel");
		return ROUTE_UNNECESSARY;
	}

	/*
	 * If this is a template connection, we cannot route.
	 *
	 * However, opportunistic and sec_label templates can be
	 * routed (as in install the policy).
	 */
	if (c->kind == CK_TEMPLATE) {
		if (c->policy & POLICY_OPPORTUNISTIC) {
			ldbg(logger, "template-route-possible: opportunistic");
		} else if (c->config->sec_label.len > 0) {
			ldbg(logger, "template-route-possible: has sec-label");
		} else if (c->local->config->child.virt != NULL) {
			ldbg(logger, "template-route-possible: local is virtual");
		} else if (c->remote->child.has_client) {
			/* see extract_child_end() */
			ldbg(logger, "template-route-possible: remote %s.child.has_client==true",
			     c->remote->config->leftright);
		} else {
			policy_buf pb;
			llog(RC_ROUTE, logger,
			     "cannot route template policy of %s",
			     str_connection_policies(c, &pb));
			return ROUTE_IMPOSSIBLE;
		}
	}
	return ROUTEABLE; /* aka keep looking */
}

static bool spd_route_conflicts(struct spd_route *spd UNUSED,
				struct spd_route *d_spd UNUSED,
				struct logger *logger UNUSED,
				unsigned indent UNUSED)
{
	return true;
}

static bool spd_policy_conflicts(struct spd_route *spd,
				 struct spd_route *d_spd,
				 struct logger *logger,
				 unsigned indent)
{
	struct connection *c = spd->connection;
	struct connection *d = d_spd->connection;

	if ((c->sa_marks.in.val & c->sa_marks.in.mask) != (d->sa_marks.in.val & d->sa_marks.in.mask)) {
		ldbg(logger, "%*s skipping policy %s; marks in don't match",
		     indent, "", d->name);
		return false;
	}

	if ((c->sa_marks.out.val & c->sa_marks.out.mask) != (d->sa_marks.out.val & d->sa_marks.out.mask) ) {
		ldbg(logger, "%*s skipping policy %s; marks out don't match",
		     indent, "", d->name);
		return false;
	}

	if (!selector_eq_selector(spd->local->client, d_spd->local->client)) {
		ldbg(logger, "%*s skipping policy %s; local selector doesn't match",
		     indent, "", d->name);
		return false;
	}
	return true;
}

/*
 * XXX: can this and/or route_owner() be merged?
 */

static void get_connection_spd_conflict(struct spd_route *spd, struct logger *logger)
{
	zero(&spd->wip);
	spd->wip.conflicting.ok = true; /* hope for the best */

	struct connection *c = spd->connection;

	if (c->config->sec_label.len > 0) {
		/* sec-labels ignore conflicts */
		return;
	}

	enum routing best_routing = RT_UNROUTED;
	enum routing best_policy = RT_UNROUTED;

	struct spd_route_filter srf = {
		.remote_client_range = &spd->remote->client,
		.where = HERE,
	};

	unsigned indent = 4;

	while (next_spd_route(NEW2OLD, &srf)) {
		struct spd_route *d_spd = srf.spd;
		struct connection *d = d_spd->connection;

		/*
		 * Don't conflict with self.
		 */
		if (spd == d_spd) {
			ldbg(logger, "%*s skipping route %s; same spd",
			     indent, "", d->name);
			continue;
		}

		/*
		 * For instance, a connection with:
		 *    [1.2.3/25]->[5.6.7/24]
		 *    [2.4.6/25]->[5.6.7/24]
		 */
		if (c == d) {
			ldbg(logger, "%*s skipping route %s; same connection family",
			     indent, "", d->name);
			continue;
		}

		if (d->child.routing == RT_UNROUTED) {
			ldbg(logger, "%*s skipping route %s; unrouted",
			     indent, "", d->name);
			continue;
		}

		if (!oriented(d)) {
			/* being routed implies orented() */
			llog_pexpect(logger, HERE, "%*s skipping route %s; unoriented",
				     indent, "", d->name);
			continue;
		}

		/* lookup did it's job */
		pexpect(selector_range_eq_selector_range(spd->remote->client,
							 d_spd->remote->client));
		if (!selector_eq_selector(spd->remote->client,
					  d_spd->remote->client)) {
			ldbg(logger, "%*s skipping route %s; remote selectors don't match",
			     indent, "", d->name);
			continue;
		}

		/*
		 * XXX: this doesn't make much sense for a route or
		 * policy!?!
		 */
		if (!address_eq_address(c->local->host.addr,
					d->local->host.addr)) {
			ldbg(logger, "%*s skipping route %s; host addresses don't match",
			     indent, "", d->name);
			continue;
		}

		/*
		 * Having got rid of the obvious, what conflicts?
		 */

		if (spd_route_conflicts(spd, d_spd, logger, indent) &&
		    d->child.routing > best_routing) {
			ldbg(logger, "%*s saving route %s; best so far",
			     indent, "", d->name);
			spd->wip.conflicting.route = d_spd;
			best_routing = d->child.routing;
		}

		if (spd_policy_conflicts(spd, d_spd, logger, indent) &&
		    d->child.routing > best_policy) {
			ldbg(logger, "%*s saving policy %s; best so far",
			     indent, "", d->name);
			spd->wip.conflicting.policy = d_spd;
			best_policy = d->child.routing;
		}
	}

	/*
	 * If there's no SPD with a conflicting policy, perhaps
	 * there's a bare one.
	 *
	 * XXX: why not add this to the above hash table?
	 */

	spd->wip.conflicting.shunt =
		(spd->wip.conflicting.policy != NULL ? NULL :
		 bare_shunt_ptr(&spd->local->client, &spd->remote->client, __func__));

	/*
	 * Report what was found.
	 */

	selector_pair_buf sb;
	ldbg(logger,
	     "%*s kernel: %s() %s; wip.conflicting_route %s wip.conflicting_policy %s wip.conflicting_shunt=%s",
	     indent, "",
	     __func__, str_selector_pair(&spd->local->client, &spd->remote->client, &sb),
	     (spd->wip.conflicting.route == NULL ? "<none>" : spd->wip.conflicting.route->connection->name),
	     (spd->wip.conflicting.policy == NULL ? "<none>" : spd->wip.conflicting.policy->connection->name),
	     (spd->wip.conflicting.shunt == NULL ? "<none>" : (*spd->wip.conflicting.shunt)->why));

	/*
	 * If there is already a route owner for peer's client subnet
	 * and it disagrees about interface or nexthop, we cannot
	 * steal it.
	 *
	 * XXX: should route_owner() have filtered out this already?
	 *
	 * Note: if this connection is already routed (perhaps for
	 * another state object), the route will agree.  This is as it
	 * should be -- it will arise during rekeying.
	 */
	struct connection *ro = (spd->wip.conflicting.route == NULL ? NULL :
				 spd->wip.conflicting.route->connection);
	if (ro != NULL && (ro->interface->ip_dev != c->interface->ip_dev ||
			   !address_eq_address(ro->local->host.nexthop, c->local->host.nexthop))) {
		/*
		 * Another connection is already using the eroute.
		 *
		 * TODO: XFRM supports this. For now, only allow this
		 * for OE.
		 */
		if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
			connection_buf cib;
			llog(RC_LOG_SERIOUS, logger,
			     "cannot route -- route already in use for "PRI_CONNECTION"",
			     pri_connection(ro, &cib));
			spd->wip.conflicting.ok = false;
		} else {
			connection_buf cib;
			llog(RC_LOG_SERIOUS, logger,
			     "cannot route -- route already in use for "PRI_CONNECTION" - but allowing anyway",
			     pri_connection(ro, &cib));
		}
	}

	/*
	 * If there is an eroute for another connection, there is a
	 * problem.
	 */

	struct connection *po = (spd->wip.conflicting.policy == NULL ? NULL :
				 spd->wip.conflicting.policy->connection);
	if (po != NULL && po != c) {
		if ((po->kind == CK_PERMANENT && c->kind == CK_TEMPLATE) ||
		    (c->kind == CK_PERMANENT && po->kind == CK_TEMPLATE)) {
			/*
			 * note, wavesec (PERMANENT) goes *outside*
			 * and OE goes *inside* (TEMPLATE)
			 */
			connection_buf pob;
			ldbg(logger,
			     "%*s kernel: need to juggle permenant and template "PRI_CONNECTION" "PRI_SO,
			     indent, "",
			     pri_connection(po, &pob),
			     pri_so(spd->wip.conflicting.policy->connection->child.kernel_policy_owner));
		} else if (po->kind == CK_TEMPLATE && streq(po->name, c->name)) {
			/*
			 * Look along the chain of policies for one
			 * with the same name.
			 */
			connection_buf pob;
			ldbg(po->logger,
			     "%*s kernel: allowing policy conflict with template "PRI_CONNECTION" "PRI_SO,
			     indent, "",
			     pri_connection(po, &pob),
			     pri_so(spd->wip.conflicting.policy->connection->child.kernel_policy_owner));
		} else if (LDISJOINT(POLICY_OVERLAPIP, c->policy | po->policy) &&
			   c->config->sec_label.len == 0) {

			/*
			 * If we fell off the end of the list, then we
			 * found no TEMPLATE so there must be a
			 * conflict that we can't resolve.  As the
			 * names are not equal, then we aren't
			 * replacing/rekeying.
			 *
			 * ??? should there not be a conflict if
			 * ANYTHING in the list, other than c,
			 * conflicts with c?
			 *
			 * Another connection is already using the
			 * eroute, TODO: XFRM apparently can do this
			 * though
			 */
			connection_buf pob;
			llog(RC_LOG_SERIOUS, logger,
			     "cannot install eroute -- it is in use for "PRI_CONNECTION" "PRI_SO,
			     pri_connection(po, &pob),
			     pri_so(spd->wip.conflicting.policy->connection->child.kernel_policy_owner));
			spd->wip.conflicting.ok = false;
		} else {
			connection_buf pob;
			ldbg(logger,
			     "%*s kernel: overlapping permitted with "PRI_CONNECTION" "PRI_SO,
			     indent, "",
			     pri_connection(po, &pob),
			     pri_so(spd->wip.conflicting.policy->connection->child.kernel_policy_owner));
		}
	}
}

static bool get_connection_spd_conflicts(struct connection *c, struct logger *logger)
{
	ldbg(logger, "checking %s for conflicts", c->name);
	bool routable = false;
	for (struct spd_route *spd = c->spd; spd != NULL; spd = spd->spd_next) {
		get_connection_spd_conflict(spd, logger);
		routable |= spd->wip.conflicting.ok;
	}
	return routable;
}

static void revert_kernel_policy(struct spd_route *spd, struct state *st/*could be NULL*/,
				 struct logger *logger)
{
	struct connection *c = spd->connection;
	PEXPECT(logger, st == NULL || st->st_connection == c);
	PEXPECT(logger, (logger == c->logger ||
			 logger == st->st_logger));

	/*
	 * Kill the firewall if previously there was no owner.
	 */
	if (spd->wip.installed.firewall && c->child.kernel_policy_owner == SOS_NOBODY) {
		PEXPECT(logger, st != NULL);
		ldbg(logger, "kernel: %s() reverting the firewall", __func__);
		if (!do_updown(UPDOWN_DOWN, c, spd, st, logger))
			dbg("kernel: down command returned an error");
	}

	/*
	 * Now unwind the policy.
	 *
	 * Of course, if things failed before the policy was
	 * installed, there's nothing to do.
	 */

	if (!spd->wip.installed.policy) {
		ldbg(logger, "kernel: %s() no kernel policy to revert", __func__);
		return;
	}

	/*
	 * If there was no conflicting kernel policy and/or
	 * bare shunt, just delete everything.
	 */

	if (spd->wip.conflicting.shunt == NULL &&
	    spd->wip.conflicting.policy == NULL) {
		ldbg(logger, "kernel: %s() no previous kernel policy or shunt: delete whatever we installed",
		     __func__);
		if (st == NULL) {
			if (!delete_kernel_policies(EXPECT_KERNEL_POLICY_OK,
						    spd->local->client,
						    spd->remote->client,
						    &c->sa_marks,
						    c->xfrmi,
						    DEFAULT_KERNEL_POLICY_ID,
						    HUNK_AS_SHUNK(c->config->sec_label),
						    c->logger, HERE, "deleting route and eroute")) {
				llog(RC_LOG, logger,
				     "shunt_policy() in route_and_eroute() failed in !st case");
			}
		} else {
			if (!sag_eroute(st, spd,
					KERNEL_POLICY_OP_DELETE,
					"delete")) {
				llog(RC_LOG, logger,
				     "sag_eroute() in route_and_eroute() failed in st case for delete");
			}
		}
		return;
	}

	/* only one - shunt set when no policy */
	PEXPECT(logger, ((spd->wip.conflicting.shunt != NULL) !=
			 (spd->wip.conflicting.policy != NULL)));

	/*
	 * If there's a bare shunt, restore it.
	 *
	 * I don't think that this case is very likely.
	 * Normally a bare shunt would have been assigned to a
	 * connection before we've gotten this far.
	 */

	if (spd->wip.conflicting.shunt != NULL) {
		ldbg(logger, "kernel: %s() restoring bare shunt", __func__);
		struct bare_shunt *bs = *spd->wip.conflicting.shunt;
		struct kernel_policy outbound_kernel_policy =
			kernel_policy_from_void(bs->our_client, bs->peer_client,
						DIRECTION_OUTBOUND,
						calculate_kernel_priority(c),
						bs->shunt_policy, HERE);
		if (!raw_policy(KERNEL_POLICY_OP_REPLACE,
				DIRECTION_OUTBOUND,
				EXPECT_KERNEL_POLICY_OK,
				&outbound_kernel_policy.src.client,
				&outbound_kernel_policy.dst.client,
				&outbound_kernel_policy,
				deltatime(SHUNT_PATIENCE),
				/*sa_marks*/NULL,
				/*xfrmi*/NULL,
				DEFAULT_KERNEL_POLICY_ID,
				/* bare shunt are not
				 * associated with any
				 * connection so no security
				 * label */
				null_shunk, logger,
				"%s() restore", __func__)) {
			llog(RC_LOG, st->st_logger,
			     "raw_policy() in %s() failed to restore/replace SA",
			     __func__);
		}
		return;
	}

	/*
	 * Restore original kernel policy, if we can.
	 *
	 * Since there is nothing much to be done if the restoration
	 * fails, ignore success or failure.
	 */

	PEXPECT(logger, spd->wip.conflicting.policy != NULL);
	struct spd_route *esr = spd->wip.conflicting.policy;
	struct connection *ero = esr->connection;

	if (ero->child.kernel_policy_owner != SOS_NOBODY) {
		/*
		 * Try to find state that owned eroute.  Don't do
		 * anything if it cannot be found.  This case isn't
		 * likely since we don't run the updown script when
		 * replacing a SA group with its successor (for the
		 * same conn).
		 */
		ldbg(logger, "kernel: %s() restoring kernel policy for "PRI_SO,
		     __func__, pri_so(ero->child.kernel_policy_owner));
		struct state *ost = state_by_serialno(ero->child.kernel_policy_owner);
		if (ost != NULL) {
			if (!sag_eroute(ost, esr,
					KERNEL_POLICY_OP_REPLACE,
					"restore"))
				llog(RC_LOG, logger,
				     "sag_eroute() in %s() failed restore/replace", __func__);
		}
		return;
	}

	PEXPECT(logger, ero->child.kernel_policy_owner == SOS_NOBODY);

	if (c->child.routing == RT_ROUTED_PROSPECTIVE) {
		ldbg(logger, "kernel: %s() restoring prespective policy", __func__);
		if (!delete_kernel_policies(EXPECT_KERNEL_POLICY_OK,
					    esr->local->client,
					    esr->remote->client,
					    &ero->sa_marks,
					    ero->xfrmi,
					    DEFAULT_KERNEL_POLICY_ID,
					    HUNK_AS_SHUNK(ero->config->sec_label),
					    logger, HERE,
					    "restore eclipsed prospective")) {
			llog(RC_LOG, logger,
			     "shunt_policy() in %s() failed restore/replace",
			     __func__);
		}
		return;
	}

	if (c->config->failure_shunt == SHUNT_NONE) {
		ldbg(logger, "kernel: %s() installing SHUNT_NONE aka block", __func__);
		struct kernel_policy outbound_policy =
			kernel_policy_from_void(esr->local->client,
						esr->remote->client,
						DIRECTION_OUTBOUND,
						calculate_kernel_priority(ero),
						SHUNT_NONE, HERE);
		if (!raw_policy(KERNEL_POLICY_OP_REPLACE,
				DIRECTION_OUTBOUND,
				EXPECT_KERNEL_POLICY_OK,
				&outbound_policy.src.client,
				&outbound_policy.dst.client,
				&outbound_policy,
				deltatime(0),
				&ero->sa_marks, ero->xfrmi,
				DEFAULT_KERNEL_POLICY_ID,
				HUNK_AS_SHUNK(ero->config->sec_label),
				logger,
				"%s() restore eclipsed failure =- NONE", __func__)) {
			llog(RC_LOG, logger,
			     "shunt_policy() %s() failed restore/replace", __func__);

		}
		return;
	}

	/* some other failure shunt */
	ldbg(logger, "kernel: %s() deleting some other failure shunt", __func__);
	if (!delete_kernel_policies(EXPECT_KERNEL_POLICY_OK,
				    esr->local->client,
				    esr->remote->client,
				    &ero->sa_marks,
				    ero->xfrmi,
				    DEFAULT_KERNEL_POLICY_ID,
				    HUNK_AS_SHUNK(ero->config->sec_label),
				    logger, HERE,
				    "restore eclipsed failure != NONE")) {
		llog(RC_LOG, logger,
		     "shunt_policy() in %s() failed restore/replace", __func__);
	}
}

static bool install_prospective_kernel_policy(struct connection *c)
{
	enum routability r = connection_routability(c, c->logger);
	switch (r) {
	case ROUTE_IMPOSSIBLE:
		return false;
	case ROUTE_UNNECESSARY:
		return true;
	case ROUTEABLE:
		break;
	}

	/*
	 * Pass +0: Lookup the status of each SPD.
	 *
	 * Still call find_spd_conflicts() when a sec_label so that
	 * the structure is zeroed (sec_labels ignore conflicts).
	 */

	if (!get_connection_spd_conflicts(c, c->logger)) {
		return false;
	}

	/*
	 * Pass +1: install / replace kernel policy where needed.
	 */

	bool ok = true;
	for (struct spd_route *spd = c->spd; spd != NULL && ok; spd = spd->spd_next) {

		/*
		 * When overlap isn't supported, the old clashing bare
		 * shunt needs to be deleted before the new one can be
		 * installed.  Else it can be deleted after.
		 *
		 * For linux this also requires SA_MARKS to be set
		 * uniquely.
		 */

		if (spd->wip.conflicting.shunt != NULL &&
		    PEXPECT(c->logger, !kernel_ops->overlap_supported)) {
			delete_bare_kernel_policy(*spd->wip.conflicting.shunt, c->logger, HERE);
			/* if everything succeeds, delete below */
		}

		if (spd->wip.conflicting.policy == NULL) {
			ok &= spd->wip.installed.policy =
				install_prospective_kernel_policies(EXPECT_KERNEL_POLICY_OK,
								    spd, c->logger, HERE);
		}

		if (spd->wip.conflicting.shunt != NULL &&
		    /* double negative */
		    !PEXPECT(c->logger, !kernel_ops->overlap_supported)) {
			delete_bare_kernel_policy(*spd->wip.conflicting.shunt, c->logger, HERE);
			/* if everything succeeds, delete below */
		}
	}

	/*
	 * Pass +2: add the route.
	 */

	for (struct spd_route *spd = c->spd; spd != NULL && ok; spd = spd->spd_next) {
		struct spd_route *ro = spd->wip.conflicting.route;
		if (ro == NULL) {
			/* a new route: no deletion required, but preparation is */
			if (!do_updown(UPDOWN_PREPARE, c, spd, NULL/*state*/, c->logger))
				ldbg(c->logger, "kernel: prepare command returned an error");
			ok &= spd->wip.installed.route =
				do_updown(UPDOWN_ROUTE, c, spd, NULL/*state*/, c->logger);
			continue;
		}
		if (ro->connection->interface->ip_dev == c->interface->ip_dev &&
		    address_eq_address(ro->local->host->nexthop, c->local->host.nexthop)) {
			/*
			 * The routes required for two different
			 * connections agree (it is assumed that the
			 * destination subnets agree).
			 */
			ldbg(c->logger, "%s is sharing a route with %s",
			     c->name, ro->connection->name);
			continue;
		}
		struct spd_route *po = spd->wip.conflicting.policy;
		if (po == NULL) {
			llog_pexpect(c->logger, HERE,
				     "trying to use policy owner to decide routing but there isn't one");
			continue;
		}
		/*
		 * Some other connection must own the route and the
		 * route must disagree.  But since could_route must
		 * have allowed our stealing it, we'll do so.
		 *
		 * A feature of LINUX allows us to install the new
		 * route before deleting the old if the nexthops
		 * differ.  This reduces the "window of vulnerability"
		 * when packets might flow in the clear.
		 *
		 * XXX: the original version of this code compared
		 * things to ESR (aka the conflicting policy).  Why?
		 */
		llog_pexpect(c->logger, HERE,
			     "trying to use policy owner %s to decide routing",
			     po->connection->name);
		if (address_eq_address(spd->local->host->nexthop,
				       po->local->host->nexthop)) {
			if (!do_updown(UPDOWN_UNROUTE, ro->connection, ro, NULL, c->logger)) {
				dbg("kernel: unroute command returned an error");
			}
			if (!do_updown(UPDOWN_ROUTE, c, spd, NULL, c->logger)) {
				dbg("kernel: route command returned an error");
			}
		} else {
			if (!do_updown(UPDOWN_ROUTE, c, spd, NULL, c->logger)) {
				dbg("kernel: route command returned an error");
			}
			if (!do_updown(UPDOWN_UNROUTE, ro->connection, ro, NULL, c->logger)) {
				dbg("kernel: unroute command returned an error");
			}
		}
	}

	/*
	 * If things failed bail.
	 */

	if (!ok) {
		for (struct spd_route *spd = c->spd; spd != NULL; spd = spd->spd_next) {
			revert_kernel_policy(spd, NULL/*st*/, c->logger);
		}
		return false;
	}

	/*
	 * Now clean up any shunts that were replaced.
	 */

	for (struct spd_route *spd = c->spd; spd != NULL; spd = spd->spd_next) {
		struct bare_shunt **bspp = spd->wip.conflicting.shunt;
		if (bspp != NULL) {
			free_bare_shunt(bspp);
		}
	}

	set_child_routing(c, RT_ROUTED_PROSPECTIVE);

	return true;
}

static bool connection_route_transition(struct connection *c, enum routing new_routing)
{
#define ON(O,N) ((O << 8) | N)
	switch (ON(c->child.routing, new_routing)) {
	case ON(RT_UNROUTED, RT_ROUTED_PROSPECTIVE):
		return install_prospective_kernel_policy(c);
	default:
		llog_pexpect(c->logger, HERE, "%s -> %s",
			     enum_name_short(&routing_names, c->child.routing),
			     enum_name_short(&routing_names, new_routing));
		return false;
	}
#undef ON
}

bool route_and_trap_connection(struct connection *c)
{
	return connection_route_transition(c, RT_ROUTED_PROSPECTIVE);
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
		kernel_policy_from_state(st, sr, DIRECTION_OUTBOUND,
					 calculate_kernel_priority(c),
					 HERE);
	/* check for no transform at all */
	passert(kernel_policy.nr_rules > 0);

	/* hack */
	char why[256];
	snprintf(why, sizeof(why), "%s() %s", __func__, opname);

	return eroute_outbound_connection(op, why, sr,
					  &kernel_policy,
					  &c->sa_marks, c->xfrmi,
					  HUNK_AS_SHUNK(c->config->sec_label),
					  st->st_logger);
}

void migration_up(struct child_sa *child)
{
	struct connection *c = child->sa.st_connection;
	/* do now so route_owner won't find us */
	set_child_routing(c, RT_ROUTED_TUNNEL);
	for (struct spd_route *sr = c->spd; sr != NULL; sr = sr->spd_next) {
#ifdef IPSEC_CONNECTION_LIMIT
		num_ipsec_eroute++;
#endif
		do_updown(UPDOWN_UP, c, sr, &child->sa, child->sa.st_logger);
		do_updown(UPDOWN_ROUTE, c, sr, &child->sa, child->sa.st_logger);
	}
}

void migration_down(struct child_sa *child)
{
	struct connection *c = child->sa.st_connection;
	/* do now so route_owner won't find us */
	enum routing cr = c->child.routing;
	set_child_routing(c, RT_UNROUTED);
	for (struct spd_route *sr = c->spd; sr != NULL; sr = sr->spd_next) {
#ifdef IPSEC_CONNECTION_LIMIT
		if (erouted(cr))
			num_ipsec_eroute--;
#endif
		/* only unroute if no other connection shares it */
		if (routed(cr) && route_owner(sr) == NULL) {
			do_updown(UPDOWN_DOWN, c, sr, &child->sa, child->sa.st_logger);
			child->sa.st_mobike_del_src_ip = true;
			do_updown(UPDOWN_UNROUTE, c, sr, &child->sa, child->sa.st_logger);
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
	enum routing cr = c->child.routing;
	if (erouted(cr)) {
		for (struct spd_route *sr = c->spd; sr != NULL; sr = sr->spd_next) {
			/* cannot handle a live one */
			passert(cr != RT_ROUTED_TUNNEL);
			/*
			 * XXX: note the hack where missing inbound
			 * policies are ignored.  The connection
			 * should know if there's an inbound policy,
			 * in fact the connection shouldn't even have
			 * inbound policies, just the state.
			 *
			 * For sec_label, it's tearing down the route,
			 * hence that is included.
			 */
			delete_kernel_policies(EXPECT_NO_INBOUND,
					       sr->local->client,
					       sr->remote->client,
					       &c->sa_marks, c->xfrmi,
					       DEFAULT_KERNEL_POLICY_ID,
					       HUNK_AS_SHUNK(c->config->sec_label),
					       c->logger, HERE, "unrouting connection");
#ifdef IPSEC_CONNECTION_LIMIT
			num_ipsec_eroute--;
#endif
		}
	}

	/* do now so route_owner won't find us */
	set_child_routing(c, RT_UNROUTED);

	if (routed(cr)) {
		for (struct spd_route *spd = c->spd; spd != NULL; spd = spd->spd_next) {
			/* only unroute if no other connection shares it */
			if (route_owner(spd) == NULL) {
				do_updown(UPDOWN_UNROUTE, c, spd, NULL, c->logger);
			}
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
	const struct ip_protocol *transport_proto = protocol_from_ipproto(our_client->ipproto);
	pexpect(peer_client->ipproto == transport_proto->ipproto);

	selector_pair_buf sb;
	dbg("kernel: %s looking for %s",
	    why, str_selector_pair(our_client, peer_client, &sb));
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
		connection_priority_buf prio;

		/* XXX: hack to preserve output */
		ip_said said = said_from_address_protocol_spi(selector_type(&bs->our_client)->address.unspec,
							      &ip_protocol_internal,
							      htonl(shunt_policy_spi(bs->shunt_policy)));

		show_comment(s, "%s -%d-> %s => %s %s    %s",
			     str_selector_subnet_port(&(bs)->our_client, &ourb),
			     bs->transport_proto->ipproto,
			     str_selector_subnet_port(&(bs)->peer_client, &peerb),
			     str_said(&said, &sat),
			     str_connection_priority(bs->policy_prio, &prio),
			     bs->why);
	}
}

static void delete_bare_kernel_policy(const struct bare_shunt *bsp,
				      struct logger *logger,
				      where_t where)
{
	/*
	 * XXX: bare_kernel_policy() does not strip the port but this
	 * code does.
	 *
	 * Presumably it is because bare shunts is widened to include
	 * all protocols / ports.  But if that were true the selectors
	 * would have already excluded the port.
	 *
	 * XXX: this is probably a bug.  Any widening should happen
	 * before the bare shunt is added.
	 */
#if 0
	pexpect(bsp->our_client.hport == 0);
	pexpect(bsp->peer_client.hport == 0);
#endif
	const struct ip_protocol *transport_proto = bsp->transport_proto;
	ip_address src_address = selector_prefix(bsp->our_client);
	ip_address dst_address = selector_prefix(bsp->peer_client);
	ip_selector src = selector_from_address_protocol(src_address, transport_proto);
	ip_selector dst = selector_from_address_protocol(dst_address, transport_proto);
	/* assume low code logged action */
	if (!delete_kernel_policy(DIRECTION_OUTBOUND,
				  EXPECT_KERNEL_POLICY_OK,
				  src, dst,
				  /*sa_marks*/NULL, /*xfrmi*/NULL, /*bare-shunt*/
				  DEFAULT_KERNEL_POLICY_ID,
				  /* bare-shunt: no sec_label XXX: ?!? */
				  null_shunk,
				  logger, where, "delete bare shunt")) {
		/* ??? we could not delete a bare shunt */
		llog_bare_shunt(RC_LOG, logger, bsp, "failed to delete kernel policy");
	}
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
	const struct ip_protocol *transport_proto = protocol_from_ipproto(src_client->ipproto);
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
			delete_bare_kernel_policy(bsp, logger, HERE);
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
	/*
	 * Strip the port; i.e., widen to an address.
	 */
	const struct ip_info *afi = address_type(src_address);
	pexpect(afi == address_type(dst_address));
	ip_selector src = selector_from_address_protocol(*src_address, transport_proto);
	ip_selector dst = selector_from_address_protocol(*dst_address, transport_proto);

	/* assume low code logged action */
	selector_pair_buf sb;
	dbg("kernel: deleting bare shunt %s from kernel for %s",
	    str_selector_pair(&src, &dst, &sb), why);
	/* assume low code logged action */
	bool ok = delete_kernel_policy(DIRECTION_OUTBOUND,
				       expect_kernel_policy,
				       src, dst,
				       /*sa_marks*/NULL, /*xfrmi*/NULL, /*bare-shunt*/
				       DEFAULT_KERNEL_POLICY_ID,
				       /*sec-label*/null_shunk,/*bare-shunt*/
				       logger, HERE, why);
	if (!ok) {
		/* did/should kernel log this? */
		selector_pair_buf sb;
		llog(RC_LOG, logger,
		     "delete kernel shunt %s failed - deleting from pluto shunt table",
		     str_selector_pair_sensitive(&src, &dst, &sb));
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
		selector_pair_buf sb;
		llog(RC_LOG, logger,
		     "can't find expected bare shunt to delete: %s",
		     str_selector_pair_sensitive(&src, &dst, &sb));
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
	    enum_name(&routing_story, c->child.routing),
	    pri_shunk(c->config->sec_label));

	if (!pexpect(c->config->ike_version == IKEv2) ||
	    !pexpect(c->config->sec_label.len > 0) ||
	    !pexpect(c->kind == CK_TEMPLATE)) {
		return false;
	}

	if (erouted(c->child.routing)) {
		dbg("kernel: %s() connection already routed", __func__);
		return true;
	}

	enum encap_mode mode = (c->policy & POLICY_TUNNEL ? ENCAP_MODE_TUNNEL :
				ENCAP_MODE_TRANSPORT);

	kernel_priority_t priority = calculate_kernel_priority(c);

	/*
	 * SE installs both an outgoing and incoming policy.  Normal
	 * connections do not.
	 */
	FOR_EACH_THING(direction, DIRECTION_OUTBOUND, DIRECTION_INBOUND) {
		const struct kernel_policy kernel_policy =
			kernel_policy_from_spd(c->policy, c->child.reqid, c->spd,
					       mode, direction,
					       priority, HERE);
		if (kernel_policy.nr_rules == 0) {
			/* XXX: log? */
			return false;
		}
		if (!raw_policy(KERNEL_POLICY_OP_ADD, direction,
				EXPECT_KERNEL_POLICY_OK,
				&kernel_policy.src.client, &kernel_policy.dst.client,
				&kernel_policy,
				/*use_lifetime*/deltatime(0),
				/*sa_marks*/NULL, /* XXX:bug? */
				/*xfrmi*/NULL, /* XXX: bug? */
				DEFAULT_KERNEL_POLICY_ID,
				/*sec_label*/HUNK_AS_SHUNK(c->config->sec_label),
				/*logger*/logger,
				"%s() security label policy", __func__)) {
			if (direction == DIRECTION_INBOUND) {
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
				pexpect(direction == DIRECTION_INBOUND);
				delete_kernel_policy(DIRECTION_OUTBOUND,
						     EXPECT_KERNEL_POLICY_OK,
						     c->spd->local->client,
						     c->spd->remote->client,
						     /*sa_marks*/NULL, /* XXX: bug? */
						     /*xfrmi*/NULL, /* XXX: bug? */
						     DEFAULT_KERNEL_POLICY_ID,
						     /*sec_label*/HUNK_AS_SHUNK(c->config->sec_label),
						     /*logger*/logger, HERE, "security label policy");
			}
			return false;
		}
	}

	/* a new route: no deletion required, but preparation is */
	if (!do_updown(UPDOWN_PREPARE, c, c->spd, NULL/*ST*/, logger)) {
		dbg("kernel: %s() prepare command returned an error", __func__);
	}

	if (!do_updown(UPDOWN_ROUTE, c, c->spd, NULL/*ST*/, logger)) {
		/* Failure!  Unwind our work. */
		dbg("kernel: %s() route command returned an error", __func__);
		if (!do_updown(UPDOWN_DOWN, c, c->spd, NULL/*st*/, logger)) {
			dbg("kernel: down command returned an error");
		}
		dbg("kernel: %s() pulling policies", __func__);
		delete_kernel_policies(EXPECT_KERNEL_POLICY_OK,
				       c->spd->local->client,
				       c->spd->remote->client,
				       /*sa_marks*/NULL,  /* XXX: bug? */
				       /*xfrmi*/NULL, /* XXX: bug? */
				       DEFAULT_KERNEL_POLICY_ID,
				       /*sec_label*/HUNK_AS_SHUNK(c->config->sec_label),
				       /*logger*/logger, HERE,
				       "security label policy");
		return false;
	}

	/* Success! */
	set_child_routing(c, RT_ROUTED_PROSPECTIVE);
	return true;
}

bool eroute_outbound_connection(enum kernel_policy_op op,
				const char *opname,
				const struct spd_route *sr,
				const struct kernel_policy *kernel_policy,
				const struct sa_marks *sa_marks,
				const struct pluto_xfrmi *xfrmi,
				shunk_t sec_label,
				struct logger *logger)
{
	if (sr->local->child->has_cat) {
		ip_selector client = selector_from_address(sr->local->host->addr);
		bool t = raw_policy(op, DIRECTION_OUTBOUND,
				    EXPECT_KERNEL_POLICY_OK,
				    &client, &kernel_policy->dst.route,
				    kernel_policy,
				    deltatime(0),
				    sa_marks, xfrmi,
				    DEFAULT_KERNEL_POLICY_ID,
				    sec_label,
				    logger,
				    "CAT: %s() %s", __func__, opname);
		if (!t) {
			llog(RC_LOG, logger,
			     "CAT: failed to eroute additional Client Address Translation policy");
		}

		dbg("kernel: %s CAT extra route added return=%d", __func__, t);
	}

	return raw_policy(op, DIRECTION_OUTBOUND,
			  EXPECT_KERNEL_POLICY_OK,
			  &kernel_policy->src.route, &kernel_policy->dst.route,
			  kernel_policy,
			  deltatime(0),
			  sa_marks, xfrmi,
			  DEFAULT_KERNEL_POLICY_ID,
			  sec_label,
			  logger,
			  "%s() %s", __func__, opname);
}

/* install a bare hold or pass policy to a connection */

bool assign_holdpass(struct connection *c,
		     struct spd_route *sr,
		     const ip_packet *packet)
{
	/*
	 * either the automatically installed %hold eroute is broad enough
	 * or we try to add a broader one and delete the automatic one.
	 * Beware: this %hold might be already handled, but still squeak
	 * through because of a race.
	 */
	enum routing ro = c->child.routing;	/* routing, old */
	enum routing rn = ro;			/* routing, new */

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

	ldbg(c->logger, "kernel: %s() routing was %s, needs to be %s",
	     __func__,
	     enum_name(&routing_story, ro),
	     enum_name(&routing_story, rn));

	/*
	 * A template connection's eroute can be eclipsed by either a
	 * %hold or an eroute for an instance IFF the template is a
	 * /32 -> /32.  This requires some special casing.
	 *
	 * XXX: is this still needed?
	 */
	if (selector_contains_one_address((sr)->local->client) &&
	    selector_contains_one_address((sr)->remote->client)) {
		/*
		 * Although %hold or %pass is appropriately broad, it
		 * will no longer be bare so we must ditch it from the
		 * bare table.
		 */
		ldbg(c->logger, "kernel: %s() no longer bare so ditching", __func__);
		struct bare_shunt **old = bare_shunt_ptr(&sr->local->client, &sr->remote->client,
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
		ldbg(c->logger, "kernel: %s() need broad(er) shunt", __func__);
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
			enum kernel_policy_op op;
			const char *reason;

			if (erouted(ro)) {
				op = KERNEL_POLICY_OP_REPLACE;
				reason = "assign_holdpass() replace %trap with broad %pass or %hold";
			} else {
				op = KERNEL_POLICY_OP_ADD;
				reason = "assign_holdpass() add broad %pass or %hold";
			}

			struct kernel_policy outbound_kernel_policy =
				kernel_policy_from_void(sr->local->client, sr->remote->client,
							DIRECTION_OUTBOUND,
							calculate_kernel_priority(c),
							c->config->negotiation_shunt, HERE);

			if (eroute_outbound_connection(op, reason, sr,
						       &outbound_kernel_policy,
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
	set_child_routing(c, rn);
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

static void setup_esp_nic_offload(struct kernel_state *sa, struct connection *c,
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

static bool setup_half_kernel_state(struct state *st, enum direction direction)
{
	/* Build an inbound or outbound SA */

	struct connection *c = st->st_connection;
	bool replace = (direction == DIRECTION_INBOUND && (kernel_ops->get_ipsec_spi != NULL));
	bool nic_offload_fallback = false;

	/* SPIs, saved for spigrouping or undoing, if necessary */
	struct kernel_state said[EM_MAXRELSPIS];
	struct kernel_state *said_next = said;

	/* same scope as said[] */
	said_buf text_ipcomp;
	said_buf text_esp;
	said_buf text_ah;

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


	struct kernel_route route = kernel_route_from_state(st, direction);

	const struct kernel_state said_boilerplate = {
		.src.address = route.src.address,
		.dst.address = route.dst.address,
		.src.route = route.src.route,
		.dst.route = route.dst.route,
		.direction = direction,
		.tunnel = (route.mode == ENCAP_MODE_TUNNEL),
		.sa_lifetime = c->config->sa_ipsec_max_lifetime,
		.sa_max_soft_bytes = sa_ipsec_soft_bytes,
		.sa_max_soft_packets = sa_ipsec_soft_packets,
		.sa_ipsec_max_bytes = c->config->sa_ipsec_max_bytes,
		.sa_ipsec_max_packets = c->config->sa_ipsec_max_packets,
		.sec_label = (st->st_v1_seen_sec_label.len > 0 ? st->st_v1_seen_sec_label :
			      st->st_v1_acquired_sec_label.len > 0 ? st->st_v1_acquired_sec_label :
			      c->child.sec_label /* assume connection outlive their kernel_sa's */),
	};

	address_buf sab, dab;
	selector_buf scb, dcb;
	dbg("kernel: %s() %s %s->[%s=%s=>%s]->%s sec_label="PRI_SHUNK"%s",
	    __func__,
	    enum_name_short(&direction_names, said_boilerplate.direction),
	    str_selector(&said_boilerplate.src.route, &scb),
	    str_address(&said_boilerplate.src.address, &sab),
	    enum_name_short(&encap_mode_names, route.mode),
	    str_address(&said_boilerplate.dst.address, &dab),
	    str_selector(&said_boilerplate.dst.route, &dcb),
	    /* see above */
	    pri_shunk(said_boilerplate.sec_label),
	    (st->st_v1_seen_sec_label.len > 0 ? " (IKEv1 seen)" :
	     st->st_v1_acquired_sec_label.len > 0 ? " (IKEv1 acquired)" :
	     c->child.sec_label.len > 0 ? " (IKEv2 this)" :
	     ""))

	/* set up IPCOMP SA, if any */

	if (st->st_ipcomp.present) {
		ipsec_spi_t ipcomp_spi = (direction == DIRECTION_INBOUND ? st->st_ipcomp.inbound.spi :
					  st->st_ipcomp.outbound.spi);
		*said_next = said_boilerplate;
		said_next->spi = ipcomp_spi;
		said_next->proto = &ip_protocol_ipcomp;

		said_next->ipcomp = st->st_ipcomp.attrs.transattrs.ta_ipcomp;
		said_next->level = said_next - said;
		said_next->reqid = reqid_ipcomp(c->child.reqid);
		said_next->story = said_str(route.dst.address,
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
		ipsec_spi_t esp_spi = (direction == DIRECTION_INBOUND ? st->st_esp.inbound.spi :
				       st->st_esp.outbound.spi);
		chunk_t esp_keymat = (direction == DIRECTION_INBOUND ? st->st_esp.inbound.keymat :
				      st->st_esp.outbound.keymat);
		const struct trans_attrs *ta = &st->st_esp.attrs.transattrs;

		const struct ip_encap *encap_type = NULL;
		uint16_t encap_sport = 0, encap_dport = 0;
		ip_address natt_oa;

		if (st->hidden_variables.st_nat_traversal & NAT_T_DETECTED ||
		    st->st_interface->io->protocol == &ip_protocol_tcp) {
			encap_type = st->st_interface->io->protocol->encap_esp;
			switch (direction) {
			case DIRECTION_INBOUND:
				encap_sport = endpoint_hport(st->st_remote_endpoint);
				encap_dport = endpoint_hport(st->st_interface->local_endpoint);
				break;
			case DIRECTION_OUTBOUND:
				encap_sport = endpoint_hport(st->st_interface->local_endpoint);
				encap_dport = endpoint_hport(st->st_remote_endpoint);
				break;
			default:
				bad_case(direction);
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
		    esp_keymat.len, encrypt_keymat_size, integ_keymat_size);

		PASSERT(st->st_logger, esp_keymat.len == encrypt_keymat_size + integ_keymat_size);

		*said_next = said_boilerplate;
		said_next->spi = esp_spi;
		said_next->proto = &ip_protocol_esp;
		said_next->replay_window = c->sa_replay_window;
		dbg("kernel: setting IPsec SA replay-window to %d", c->sa_replay_window);

		if (c->xfrmi != NULL) {
			said_next->xfrm_if_id = c->xfrmi->if_id;
			said_next->mark_set = c->sa_marks.out;
		}

		if (direction == DIRECTION_OUTBOUND && c->sa_tfcpad != 0 && !st->st_seen_no_tfc) {
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
		said_next->encrypt_key = shunk2(esp_keymat.ptr, encrypt_keymat_size); /*BYTES*/
		said_next->integ_key = shunk2(esp_keymat.ptr + encrypt_keymat_size, integ_keymat_size); /*BYTES*/

		said_next->level = said_next - said;
		said_next->reqid = reqid_esp(c->child.reqid);

		said_next->src.encap_port = encap_sport;
		said_next->dst.encap_port = encap_dport;
		said_next->encap_type = encap_type;
		said_next->natt_oa = &natt_oa;
		said_next->story = said_str(route.dst.address,
					    &ip_protocol_esp,
					    esp_spi, &text_esp);

		if (DBGP(DBG_PRIVATE) || DBGP(DBG_CRYPT)) {
			DBG_dump_hunk("ESP encrypt key:",  said_next->encrypt_key);
			DBG_dump_hunk("ESP integrity key:", said_next->integ_key);
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
		memset(esp_keymat.ptr, 0, esp_keymat.len);

		if (!ret)
			goto fail;

		said_next++;
	}

	/* set up AH SA, if any */

	if (st->st_ah.present) {
		ipsec_spi_t ah_spi = (direction == DIRECTION_INBOUND ? st->st_ah.inbound.spi :
				      st->st_ah.outbound.spi);
		chunk_t ah_keymat = (direction == DIRECTION_INBOUND ? st->st_ah.inbound.keymat :
				     st->st_ah.outbound.keymat);

		const struct integ_desc *integ = st->st_ah.attrs.transattrs.ta_integ;
		if (integ->integ_ikev1_ah_transform <= 0) {
			log_state(RC_LOG_SERIOUS, st,
				  "%s not implemented",
				  integ->common.fqn);
			goto fail;
		}

		PASSERT(st->st_logger, ah_keymat.len == integ->integ_keymat_size);

		*said_next = said_boilerplate;
		said_next->spi = ah_spi;
		said_next->proto = &ip_protocol_ah;
		said_next->integ = integ;
		said_next->integ_key = shunk2(ah_keymat.ptr, ah_keymat.len);
		said_next->level = said_next - said;
		said_next->reqid = reqid_ah(c->child.reqid);
		said_next->story = said_str(route.dst.address,
					    &ip_protocol_ah,
					    ah_spi, &text_ah);

		said_next->replay_window = c->sa_replay_window;
		dbg("kernel: setting IPsec SA replay-window to %d", c->sa_replay_window);

		if (st->st_ah.attrs.transattrs.esn_enabled) {
			dbg("kernel: Enabling ESN");
			said_next->esn = true;
		}

		if (DBGP(DBG_PRIVATE) || DBGP(DBG_CRYPT)) {
			DBG_dump_hunk("AH authkey:", said_next->integ_key);
		}

		bool ret = kernel_ops_add_sa(said_next, replace, st->st_logger);
		/* scrub key from memory */
		memset(ah_keymat.ptr, 0, ah_keymat.len);

		if (!ret) {
			goto fail;
		}

		said_next++;
	}

	/* If there are multiple SPIs, group them. */

	if (kernel_ops->grp_sa != NULL && said_next > &said[1]) {
		/*
		 * group SAs, two at a time, inner to outer (backwards in
		 * said[])
		 *
		 * The grouping is by pairs.  So if said[] contains
		 * ah esp ipip,
		 *
		 * the grouping would be ipip:esp, esp:ah.
		 */
		for (struct kernel_state *s = said; s < said_next - 1; s++) {
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

static bool install_inbound_ipsec_kernel_policies(struct state *st)
{
	const struct connection *c = st->st_connection;
	struct logger *logger = st->st_logger;
	/*
	 * Add an inbound eroute to enforce an arrival check.
	 *
	 * If inbound,
	 * ??? and some more mysterious conditions,
	 * Note reversed ends.
	 * Not much to be done on failure.
	 */
	ldbg(logger, "kernel: %s() owner="PRI_SO,
	     __func__, pri_so(c->child.kernel_policy_owner));

	if (c->child.kernel_policy_owner != SOS_NOBODY) {
		ldbg(logger, "kernel: %s() skipping as already has owner "PRI_SO,
		     __func__, pri_so(c->child.kernel_policy_owner));
		return true;
	}

	if (c->config->sec_label.len > 0 &&
	    c->config->ike_version == IKEv2) {
		ldbg(logger, "kernel: %s() skipping as IKEv2 config.sec_label="PRI_SHUNK,
		     __func__, pri_shunk(c->config->sec_label));
		return true;
	}

	for (struct spd_route *spd = c->spd; spd != NULL; spd = spd->spd_next) {

		struct kernel_policy kernel_policy =
			kernel_policy_from_state(st, spd, DIRECTION_INBOUND,
						 calculate_kernel_priority(c),
						 HERE);
		selector_pair_buf spb;
		ldbg(logger, "kernel: %s() is installing SPD for %s",
		     __func__, str_selector_pair(&kernel_policy.src.client, &kernel_policy.dst.client, &spb));

		if (!raw_policy(KERNEL_POLICY_OP_ADD,
				DIRECTION_INBOUND,
				EXPECT_KERNEL_POLICY_OK,
				&kernel_policy.src.route,	/* src_client */
				&kernel_policy.dst.route,	/* dst_client */
				&kernel_policy,			/* " */
				deltatime(0),		/* lifetime */
				&c->sa_marks, c->xfrmi,		/* IPsec SA marks */
				DEFAULT_KERNEL_POLICY_ID,
				HUNK_AS_SHUNK(c->config->sec_label),
				st->st_logger,
				"%s() add inbound Child SA", __func__)) {
			selector_pair_buf spb;
			llog(RC_LOG, st->st_logger,
			     "kernel: %s() failed to add SPD for %s",
			     __func__,
			     str_selector_pair(&kernel_policy.src.client, &kernel_policy.dst.client, &spb));
		}
	}

	return true;
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

static unsigned append_teardown(struct dead_sa *dead, enum direction direction,
				const struct ipsec_proto_info *proto,
				ip_address host_addr, ip_address effective_remote_address)
{
	bool present = proto->present;
	if (!present &&
	    direction == DIRECTION_INBOUND &&
	    proto->inbound.spi != 0 &&
	    proto->outbound.spi == 0) {
		dbg("kernel: forcing inbound delete of %s as .inbound.spi: "PRI_IPSEC_SPI"; attrs.spi: "PRI_IPSEC_SPI,
		    proto->protocol->name,
		    pri_ipsec_spi(proto->inbound.spi),
		    pri_ipsec_spi(proto->outbound.spi));
		present = true;
	}
	if (present) {
		dead->protocol = proto->protocol;
		switch (direction) {
		case DIRECTION_INBOUND:
			if (proto->inbound.kernel_sa_expired & SA_HARD_EXPIRED) {
				dbg("kernel expired SPI 0x%x skip deleting",
				    ntohl(proto->inbound.spi));
				return 0;
			}
			dead->spi = proto->inbound.spi; /* incoming */
			dead->src = effective_remote_address;
			dead->dst = host_addr;
			break;
		case DIRECTION_OUTBOUND:
			if (proto->outbound.kernel_sa_expired & SA_HARD_EXPIRED) {
				dbg("kernel hard expired SPI 0x%x skip deleting",
				    ntohl(proto->outbound.spi));
				return 0;
			}
			dead->spi = proto->outbound.spi; /* outgoing */
			dead->src = host_addr;
			dead->dst = effective_remote_address;
			break;
		default:
			bad_case(direction);
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

static bool teardown_half_ipsec_sa(struct state *st, enum direction direction)
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
	nr += append_teardown(dead + nr, direction, &st->st_ah,
			      c->local->host.addr, effective_remote_address);
	nr += append_teardown(dead + nr, direction, &st->st_esp,
			      c->local->host.addr, effective_remote_address);
	nr += append_teardown(dead + nr, direction, &st->st_ipcomp,
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
	 * have a route for that client that conflicts.  We will take
	 * this as proof that that route and the connections using it
	 * are obsolete and should be eliminated.  Interestingly, this
	 * is the only case in which we can tell that a connection is
	 * obsolete.
	 *
	 * XXX: can this make use of connection_routability() and / or
	 * get_connection_spd_conflicts() below?
	 */
	passert(c->kind == CK_PERMANENT || c->kind == CK_INSTANCE);
	if (c->remote->child.has_client) {
		for (;; ) {
			struct spd_route *ro = route_owner(c->spd);

			if (ro == NULL)
				break; /* nobody interesting has a route */
			struct connection *co = ro->connection;
			if (co == c) {
				break; /* nobody interesting has a route */
			}

			/* note: we ignore the client addresses at this end */
			/* XXX: but compating interfaces doesn't ?!? */
			if (sameaddr(&co->remote->host.addr,
				     &c->remote->host.addr) &&
			    co->interface == c->interface)
				break;  /* existing route is compatible */

			if (kernel_ops->overlap_supported) {
				/*
				 * Both are transport mode, allow overlapping.
				 * [bart] not sure if this is actually
				 * intended, but am leaving it in to make it
				 * behave like before
				 */
				if (!LIN(POLICY_TUNNEL, c->policy | co->policy))
					break;

				/* Both declared that overlapping is OK. */
				if (LIN(POLICY_OVERLAPIP, c->policy & co->policy))
					break;
			}

			address_buf b;
			connection_buf cib;
			log_state(RC_LOG_SERIOUS, st,
				  "route to peer's client conflicts with "PRI_CONNECTION" %s; releasing old connection to free the route",
				  pri_connection(co, &cib),
				  str_address_sensitive(&co->remote->host.addr, &b));
			if (co->kind == CK_INSTANCE) {
				delete_connection(&co);
			} else {
				release_connection(co);
			}
		}
	}

	/*
	 * Check that we will be able to route and eroute.
	 */

	enum routability r = connection_routability(c, st->st_logger);
	switch (r) {
	case ROUTEABLE:
		dbg("kernel:    routing is easy");
		break;
	case ROUTE_UNNECESSARY:
		dbg("kernel:    routing unnecessary");
		/*
		 * in this situation, we should look and see if there
		 * is a state that our connection references, that we
		 * are in fact replacing.
		 */
		break;
	case ROUTE_IMPOSSIBLE:
		dbg("kernel:    impossible");
		return false;
	default:
		bad_case(r);
	}

	if (!get_connection_spd_conflicts(c, st->st_logger)) {
		return false;
	}


	/*
	 * we now have to set up the outgoing SA first, so that
	 * we can refer to it in the incoming SA.
	 */
	if (!st->st_outbound_done) {
		dbg("kernel: installing outgoing SA now");
		if (!setup_half_kernel_state(st, DIRECTION_OUTBOUND)) {
			dbg("kernel: %s() failed to install outbound kernel state", __func__);
			return false;
		}
		dbg("kernel: %s() setup outbound SA (kernel policy installed earlier?)", __func__);
		st->st_outbound_done = true;
	}

	/* (attempt to) actually set up the SAs */

	if (!setup_half_kernel_state(st, DIRECTION_INBOUND)) {
		dbg("kernel: %s() failed to install inbound kernel state", __func__);
		return false;
	}

	if (!install_inbound_ipsec_kernel_policies(st)) {
		dbg("kernel: %s() failed to install inbound kernel policy", __func__);
		return false;
	}

	dbg("kernel: %s() setup inbound SA", __func__);

	return true;
}

static bool install_ipsec_kernel_policies(struct state *st)
{
	struct connection *c = st->st_connection;

	if (c->config->ike_version == IKEv2 && c->child.sec_label.len > 0) {
		ldbg(st->st_logger, "kernel: %s() skipping install of IPsec policies as security label", __func__);
		return true;
	}

	if (c->child.kernel_policy_owner == st->st_serialno) {
		ldbg(st->st_logger, "kernel: %s() skipping kernel policies as already owner", __func__);
		return true;
	}

	ldbg(st->st_logger,
	     "kernel: %s() installing IPsec policies for "PRI_SO": connection is currently "PRI_SO" %s",
	    __func__,
	    pri_so(st->st_serialno),
	    pri_so(c->child.kernel_policy_owner),
	    enum_name(&routing_story, c->child.routing));

	struct spd_route *start = c->spd;
	if (c->remotepeertype == CISCO && start->spd_next != NULL) {
		/* XXX: why is CISCO skipped? */
		start = start->spd_next;
	}

	bool ok = true;

#ifdef IPSEC_CONNECTION_LIMIT
	unsigned new_spds = 0;
	for (struct spd_route *spd = start; ok && spd != NULL; spd = spd->spd_next) {
		if (spd->wip.conflicting.policy == NULL &&
		    spd->wip.conflicting.shunt == NULL) {
			new_spds++;
		}
	}
	if (num_ipsec_eroute + new_spds >= IPSEC_CONNECTION_LIMIT) {
		llog(RC_LOG_SERIOUS, logger,
		     "Maximum number of IPsec connections reached (%d)",
		     IPSEC_CONNECTION_LIMIT);
		return false;
	}
#endif

	/*
	 * Install the IPsec kernel policies.
	 */

	for (struct spd_route *spd = start; ok && spd != NULL; spd = spd->spd_next) {
		enum kernel_policy_op op =
			(spd->wip.conflicting.policy != NULL ||
			 spd->wip.conflicting.shunt != NULL ? KERNEL_POLICY_OP_REPLACE :
			 KERNEL_POLICY_OP_ADD);
		ok &= spd->wip.installed.policy = sag_eroute(st, spd, op, "install IPsec policy");
	}

	/*
	 * Do we have to notify the firewall?
	 *
	 * Yes, if we are installing a tunnel eroute and the firewall
	 * wasn't notified for a previous tunnel with the same
	 * clients.  Any Previous tunnel would have to be for our
	 * connection, so the actual test is simple.
	 */

	for (struct spd_route *spd = start; ok && spd != NULL; spd = spd->spd_next) {
		if (c->child.kernel_policy_owner != SOS_NOBODY) {
			/* already notified */
			spd->wip.installed.firewall = true;
		} else {
			/* go ahead and notify */
			ok &= spd->wip.installed.firewall =
				do_updown(UPDOWN_UP, c, spd, st, st->st_logger);
		}
	}

	/*
	 * Do we have to make a mess of the routing?
	 *
	 * Probably.  This code path needs a re-think.
	 */

	for (struct spd_route *spd = start; ok && spd != NULL; spd = spd->spd_next) {
		struct connection *ro =
			(spd->wip.conflicting.route == NULL ? NULL :
			 spd->wip.conflicting.route->connection);
		if (ro == NULL) {
			/* a new route: no deletion required, but preparation is */
			if (!do_updown(UPDOWN_PREPARE, c, spd, st, st->st_logger))
				dbg("kernel: prepare command returned an error");
			ok &= spd->wip.installed.route =
				do_updown(UPDOWN_ROUTE, c, spd, st, st->st_logger);
		} else if (routed(c->child.routing)) {
			spd->wip.installed.route = true; /* nothing to be done */
		} else if (ro->interface->ip_dev == c->interface->ip_dev &&
			   address_eq_address(ro->local->host.nexthop, c->local->host.nexthop)) {
			/*
			 * The routes required for two different
			 * connections agree (it is assumed that the
			 * destination subnets agree).
			 */
			spd->wip.installed.route = true; /* nothing to be done */
		} else {
			/*
			 * Some other connection must own the route
			 * and the route must disagree.  But since
			 * could_route must have allowed our stealing
			 * it, we'll do so.
			 *
			 * A feature of LINUX allows us to install the
			 * new route before deleting the old if the
			 * nexthops differ.  This reduces the "window
			 * of vulnerability" when packets might flow
			 * in the clear.
			 */
			if (sameaddr(&spd->local->host->nexthop,
				     &spd->wip.conflicting.policy->connection->local->host.nexthop)) {
				if (!do_updown(UPDOWN_UNROUTE, ro, spd, st, st->st_logger)) {
					dbg("kernel: unroute command returned an error");
				}
				ok &= spd->wip.installed.route =
					do_updown(UPDOWN_ROUTE, c, spd, st, st->st_logger);
			} else {
				ok &= spd->wip.installed.route =
					do_updown(UPDOWN_ROUTE, c, spd, st, st->st_logger);
				/* XXX: shouldn't this be the RO route? */
				if (!do_updown(UPDOWN_UNROUTE, ro, spd, st, st->st_logger)) {
					dbg("kernel: unroute command returned an error");
				}
			}

			/* record unrouting */
			if (spd->wip.installed.route) {
				/*
				 * XXX: Given above code isn't
				 * executed (it would likely SEGV),
				 * this probably isn't either.
				 *
				 * XXX: This is looking for other
				 * conflicting routes and unrouting
				 * them.
				 */
				do {
					dbg("kernel: installed route: ro .name=%s, .child.routing was %s",
					    ro->name, enum_name(&routing_story, ro->child.routing));
					pexpect(!erouted(ro->child.routing)); /* warn for now - requires fixing */
					set_child_routing(ro, RT_UNROUTED);
					/* no need to keep old value */
					struct spd_route *rosr = route_owner(spd);
					ro = (rosr == NULL ? NULL : rosr->connection);
				} while (ro != NULL);
			}
		}
	}

	if (!ok) {
		for (struct spd_route *spd = start; spd != NULL; spd = spd->spd_next) {
			revert_kernel_policy(spd, st, st->st_logger);
		}
		return false;
	}

	/*
	 * Finally clean up.
	 */

	for (struct spd_route *spd = start; ok && spd != NULL; spd = spd->spd_next) {
		struct bare_shunt **bspp = spd->wip.conflicting.shunt;
		if (bspp != NULL) {
			free_bare_shunt(bspp);
		}
		/* clear host shunts that clash with freshly installed route */
		clear_narrow_holds(&spd->local->client, &spd->remote->client, st->st_logger);
	}


#ifdef IPSEC_CONNECTION_LIMIT
	num_ipsec_eroute += new_spds;
	llog(RC_COMMENT, st->st_logger,
	     "%d IPsec connections are currently being managed",
	     num_ipsec_eroute);
#endif

	/* include CISCO's SPD */
	set_child_kernel_policy_owner(c, st->st_serialno);

	set_child_routing(c, RT_ROUTED_TUNNEL);
	return true;
}

bool install_ipsec_sa(struct state *st, bool inbound_also)
{
	struct connection *c = st->st_connection;
	dbg("kernel: install_ipsec_sa() for #%lu: %s", st->st_serialno,
	    inbound_also ? "inbound and outbound" : "outbound only");

	/*
	 * Pass +0: Lookup the status of each SPD.
	 *
	 * Still call find_spd_conflicts() when a sec_label so that
	 * the structure is zeroed (sec_labels ignore conflicts).
	 */

	enum routability r = connection_routability(st->st_connection, st->st_logger);

	switch (r) {
	case ROUTEABLE:
		break;
	case ROUTE_UNNECESSARY:
		/* will install kernel state but not policy */
		break;
	case ROUTE_IMPOSSIBLE:
		return false;
	default:
		bad_case(r);
	}

	if (!get_connection_spd_conflicts(c, st->st_logger)) {
		return false;
	}

	/* (attempt to) actually set up the SA group */

	/* setup outgoing SA if we haven't already */
	if (!st->st_outbound_done) {
		if (!setup_half_kernel_state(st, DIRECTION_OUTBOUND)) {
			dbg("kernel: %s() failed to install outbound kernel state", __func__);
			return false;
		}
		dbg("kernel: %s() setup outbound SA (kernel policy installed earlier?)", __func__);
		st->st_outbound_done = true;
	}

	/* now setup inbound SA */
	if (inbound_also) {
		if (!setup_half_kernel_state(st, DIRECTION_INBOUND)) {
			dbg("kernel: %s() failed to install inbound kernel state", __func__);
			return false;
		}
		if (!install_inbound_ipsec_kernel_policies(st)) {
			dbg("kernel: %s() failed to install inbound kernel policy", __func__);
			return false;
		}
		dbg("kernel: %s() setup inbound SA", __func__);

		/*
		 * We successfully installed an IPsec SA, meaning it
		 * is safe to clear our revival back-off delay. This
		 * is based on the assumption that an unwilling
		 * partner might complete an IKE SA to us, but won't
		 * complete an IPsec SA to us.
		 */
		st->st_connection->temp_vars.revive_delay = 0;
	}

	if (r == ROUTE_UNNECESSARY) {
		return true;
	}

	if (!install_ipsec_kernel_policies(st)) {
		delete_ipsec_sa(st);
		return false;
	}

	if (inbound_also)
		linux_audit_conn(st, LAK_CHILD_START);
	return true;
}

/*
 * Delete an IPSEC SA's kernel policy.
 *
 * We may not succeed, but we bull ahead anyway because we cannot do
 * anything better by recognizing failure.
 *
 * This used to have a parameter inbound_only, but the saref code
 * changed to always install inbound before outbound so this it was
 * always false, and thus removed.  But this means that while there's
 * now always an outbound policy, there may not yet be an inbound
 * policy!  For instance, IKEv2 IKE AUTH initiator gets rejected.  So
 * what is there, and should this even be called?
 *
 * EXPECT_KERNEL_POLICY is trying to help sort this out.
 */

static void teardown_spd_kernel_policies(enum kernel_policy_op outbound_op,
					 enum shunt_policy outbound_shunt,
					 struct spd_route *spd,
					 enum expect_kernel_policy expect_inbound_policy,
					 struct logger *logger, const char *story)
{
	pexpect(outbound_op == KERNEL_POLICY_OP_DELETE ||
		outbound_op == KERNEL_POLICY_OP_REPLACE);
	/*
	 * The restored policy uses TRANSPORT mode (the host
	 * .{src,dst} provides the family but the address isn't used).
	 */
	struct kernel_policy outbound_kernel_policy =
		kernel_policy_from_void(spd->local->client, spd->remote->client,
					DIRECTION_OUTBOUND,
					calculate_kernel_priority(spd->connection),
					outbound_shunt, HERE);

	/*
	 * Since this is tearing down a real policy; all the critical
	 * parameters from the add need to match.
	 */

	if (!raw_policy(outbound_op,
			DIRECTION_OUTBOUND,
			EXPECT_KERNEL_POLICY_OK,
			&outbound_kernel_policy.src.client,
			&outbound_kernel_policy.dst.client,
			(outbound_op == KERNEL_POLICY_OP_DELETE ? NULL : &outbound_kernel_policy),
			deltatime(0),
			&spd->connection->sa_marks,
			spd->connection->xfrmi,
			DEFAULT_KERNEL_POLICY_ID,
			HUNK_AS_SHUNK(spd->connection->config->sec_label),
			spd->connection->logger,
			"%s() outbound kernel policy for %s", __func__, story)) {
		llog(RC_LOG, logger,
		     "kernel: %s() outbound failed %s", __func__, story);
	}
	dbg("kernel: %s() calling raw_policy(delete-inbound), eroute_owner==NOBODY",
	    __func__);
	if (!delete_kernel_policy(DIRECTION_INBOUND,
				  expect_inbound_policy,
				  spd->remote->client,
				  spd->local->client,
				  &spd->connection->sa_marks,
				  spd->connection->xfrmi,/*real*/
				  DEFAULT_KERNEL_POLICY_ID,
				  /*sec_label*/null_shunk,/*always*/
				  spd->connection->logger, HERE, story)) {
		llog(RC_LOG, logger,
		     "kernel: %s() outbound failed %s", __func__, story);
	}
}

/*
 * Delete an IPSEC SA
 *
 * We may not succeed, but we bull ahead anyway because we cannot do
 * anything better by recognizing failure.
 *
 * This used to have a parameter inbound_only, but the saref code
 * changed to always install inbound before outbound so this it was
 * always false, and thus removed.  But this means that while there's
 * now always an outbound policy, there may not yet be an inbound
 * policy!  For instance, IKEv2 IKE AUTH initiator gets rejected.  So
 * what is there, and should this even be called?
 *
 * EXPECT_KERNEL_POLICY is trying to help sort this out.
 */

static void teardown_ipsec_kernel_policies(struct state *st,
					   enum expect_kernel_policy expect_inbound_policy)
{
	struct connection *c = st->st_connection;

	enum routing new_routing;
	if (c->remotepeertype == CISCO) {
		/*
		 * XXX: this comment is out-of-date.
		 *
		 * XXX: this is currently the only reason for spd_next
		 * walking.
		 *
		 * Routing should become RT_ROUTED_FAILURE, but if
		 * POLICY_FAIL_NONE, then we just go right back to
		 * RT_ROUTED_PROSPECTIVE as if no failure happened.
		 */
		new_routing = (c->config->failure_shunt == SHUNT_NONE ? RT_ROUTED_PROSPECTIVE :
			       RT_ROUTED_FAILURE);
	} else if (c->kind == CK_INSTANCE &&
		   ((c->policy & POLICY_OPPORTUNISTIC) ||
		    (c->policy & POLICY_DONT_REKEY))) {
		new_routing = RT_UNROUTED;
	} else {
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
		new_routing = (c->config->failure_shunt == SHUNT_NONE ? RT_ROUTED_PROSPECTIVE :
			       RT_ROUTED_FAILURE);
	}

	/*
	 * Pass 1: see if there's work to do.
	 *
	 * XXX: can this instead look at the latest_ipsec?
	 */

	if (c->child.kernel_policy_owner != st->st_serialno) {
		ldbg(st->st_logger,
		     "kernel: %s() skipping, kernel policy ownere (aka eroute_owner) "PRI_SO" doesn't match Child SA "PRI_SO,
		     __func__,
		     pri_so(c->child.kernel_policy_owner),
		     pri_so(st->st_serialno));
		return;
	}

	set_child_kernel_policy_owner(c, SOS_NOBODY);

	/*
	 * update routing; route_owner() will see this and not think
	 * this route is the owner?
	 */
	set_child_routing(c, new_routing);

	for (struct spd_route *spd = c->spd; spd != NULL; spd = spd->spd_next) {

		if (spd == c->spd && c->remotepeertype == CISCO) {
			/*
			 * XXX: this comment is out-of-date:
			 *
			 * XXX: this is currently the only reason for
			 * spd_next walking.
			 *
			 * Routing should become RT_ROUTED_FAILURE,
			 * but if POLICY_FAIL_NONE, then we just go
			 * right back to RT_ROUTED_PROSPECTIVE as if
			 * no failure happened.
			 */
			ldbg(c->logger,
			     "kernel: %s() skipping, first SPD and remotepeertype is CISCO, damage done",
			     __func__);
			continue;
		}

		do_updown(UPDOWN_DOWN, c, spd, st, st->st_logger);

		if (c->kind == CK_INSTANCE &&
		    ((c->policy & POLICY_OPPORTUNISTIC) ||
		     (c->policy & POLICY_DONT_REKEY))) {

			/*
			 *
			 * Case 1: just get rid of the IPSEC SA
			 *
			 * Case 2: even if the connection is still
			 * alive (due to an ISAKMP SA), we get rid of
			 * routing.
			 */
			teardown_spd_kernel_policies(KERNEL_POLICY_OP_DELETE,
						     c->config->failure_shunt/*delete so almost ignored!?!*/,
						     spd, expect_inbound_policy,
						     st->st_logger,
						     "deleting instance");
#ifdef IPSEC_CONNECTION_LIMIT
			num_ipsec_eroute--;
#endif
			/* only unroute if no other connection shares it */
			if (route_owner(spd) == NULL) {
				do_updown(UPDOWN_UNROUTE, c, spd, NULL, c->logger);
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
			enum shunt_policy shunt_policy = (c->config->failure_shunt == SHUNT_NONE ?
							  c->config->prospective_shunt :
							  c->config->failure_shunt);
			pexpect(shunt_policy != SHUNT_NONE);
			teardown_spd_kernel_policies(KERNEL_POLICY_OP_REPLACE,
						     shunt_policy,
						     spd, expect_inbound_policy,
						     st->st_logger,
						     "replace");
		}
	}
}

static void teardown_ipsec_sa(struct state *st, enum expect_kernel_policy expect_inbound_policy)
{
	struct connection *c = st->st_connection;

	/* XXX in IKEv2 we get a spurious call with a parent st :( */
	if (!pexpect(IS_CHILD_SA(st))) {
		return;
	}

	if (st->st_esp.present || st->st_ah.present) {
		/* ESP or AH means this was an established IPsec SA */
		linux_audit_conn(st, LAK_CHILD_DESTROY);
	}

	dbg("kernel: %s() for "PRI_SO" ...", __func__, pri_so(st->st_serialno));

	if (c->child.routing == RT_ROUTED_TUNNEL) {
		teardown_ipsec_kernel_policies(st, expect_inbound_policy);
	}

	dbg("kernel: %s() calling teardown_half_ipsec_sa(outbound)", __func__);
	teardown_half_ipsec_sa(st, DIRECTION_OUTBOUND);
	/* For larval IPsec SAs this may not exist */
	dbg("kernel: %s() calling teardown_half_ipsec_sa(inbound)", __func__);
	teardown_half_ipsec_sa(st, DIRECTION_INBOUND);
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
	struct ipsec_proto_info *first_proto_info =
		(st->st_ah.present ? &st->st_ah :
		 st->st_esp.present ? &st->st_esp :
		 st->st_ipcomp.present ? &st->st_ipcomp :
		 NULL);

	if (!get_ipsec_traffic(st, first_proto_info, DIRECTION_INBOUND)) {
		/* snafu; assume idle!?! */
		return true;
	}
	deltatime_t idle_time = monotimediff(mononow(), first_proto_info->inbound.last_used);
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
 * Note: this mutates *st.
 * Note: this only changes counts in the first SA in the bundle!
 */
bool get_ipsec_traffic(struct state *st,
		       struct ipsec_proto_info *proto_info,
		       enum direction direction)
{
	struct connection *const c = st->st_connection;

	if (!pexpect(proto_info != NULL)) {
		/* pacify coverity */
		return false;
	}

	if (kernel_ops->get_kernel_state == NULL) {
		return false;
	}
	/*
	 * If we're being redirected (using the REDIRECT mechanism),
	 * then use the state's current remote endpoint, and not the
	 * connection's value.
	 *
	 * XXX: why not just use redirect_ip?
	 */
	bool redirected = (!endpoint_address_eq_address(st->st_remote_endpoint, c->remote->host.addr) &&
			   address_is_specified(c->temp_vars.redirect_ip));
	ip_address remote_ip = (redirected ?  endpoint_address(st->st_remote_endpoint) :
				c->remote->host.addr);

	struct ipsec_flow *flow;
	ip_address src, dst;
	switch (direction) {
	case DIRECTION_INBOUND:
		flow = &proto_info->inbound;
		src = remote_ip;
		dst = c->local->host.addr;
		break;
	case DIRECTION_OUTBOUND:
		flow = &proto_info->outbound;
		src = c->local->host.addr;
		dst = remote_ip;
		break;
	default:
		bad_case(direction);
	}

	if (flow->kernel_sa_expired & SA_HARD_EXPIRED) {
		dbg("kernel expired %s SA SPI "PRI_IPSEC_SPI" get_sa_info()",
		    enum_name_short(&direction_names, direction),
		    pri_ipsec_spi(flow->spi));
		return true; /* all is well use last known info */
	}

	said_buf sb;
	struct kernel_state sa = {
		.spi = flow->spi,
		.proto = proto_info->protocol,
		.src.address = src,
		.dst.address = dst,
		.story = said_str(dst, proto_info->protocol, flow->spi, &sb),
	};

	dbg("kernel: get_sa_bundle_info %s", sa.story);

	uint64_t bytes;
	uint64_t add_time;
	if (!kernel_ops->get_kernel_state(&sa, &bytes, &add_time, st->st_logger))
		return false;

	proto_info->add_time = add_time;

	/* field has been set? */
	passert(!is_monotime_epoch(flow->last_used));

	if (bytes > flow->bytes) {
		flow->bytes = bytes;
		flow->last_used = mononow();
	}

	return true;
}

bool orphan_holdpass(struct connection *c, struct spd_route *sr,
		     enum shunt_policy failure_shunt, struct logger *logger)
{
	enum routing ro = c->child.routing;        /* routing, old */
	enum routing rn = c->child.routing;        /* routing, new */
	enum shunt_policy negotiation_shunt = c->config->negotiation_shunt;

	if (negotiation_shunt != failure_shunt ) {
		dbg("kernel: failureshunt != negotiationshunt, needs replacing");
	} else {
		dbg("kernel: failureshunt == negotiationshunt, no replace needed");
	}

	dbg("kernel: orphan_holdpass() called for %s with transport_proto '%d' and sport %d and dport %d",
	    c->name, sr->local->client.ipproto, sr->local->client.hport, sr->remote->client.hport);

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
		struct bare_shunt **old = bare_shunt_ptr(&sr->local->client,
							 &sr->remote->client,
							 "orphan holdpass");
		if (old != NULL) {
			free_bare_shunt(old);
		}
	}

	{
		/*
		 * Create the bare shunt and ...
		 */
		add_bare_shunt(&sr->local->client, &sr->remote->client,
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
			const ip_address *src_address = &sr->local->host->addr;
			const ip_address *dst_address = &sr->remote->host->addr;
			connection_priority_t policy_prio = BOTTOM_PRIORITY;	/* of replacing shunt*/
			const char *why = "oe-failed";

			/* fudge up replace_bare_shunt() */
			const struct ip_info *afi = address_type(src_address);
			passert(afi == address_type(dst_address));
			const struct ip_protocol *protocol = protocol_from_ipproto(sr->local->client.ipproto);
			/* ports? assumed wide? */
			ip_selector src = selector_from_address_protocol(*src_address, protocol);
			ip_selector dst = selector_from_address_protocol(*dst_address, protocol);

			selector_pair_buf sb;
			dbg("kernel: replace bare shunt %s for %s",
			    str_selector_pair(&src, &dst, &sb), why);

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
				kernel_policy_from_void(src, dst, DIRECTION_OUTBOUND,
							/* we don't know connection for priority yet */
							highest_kernel_priority,
							failure_shunt, HERE);

			bool ok = raw_policy(KERNEL_POLICY_OP_REPLACE,
					     DIRECTION_OUTBOUND,
					     EXPECT_KERNEL_POLICY_OK,
					     &outbound_kernel_policy.src.client,
					     &outbound_kernel_policy.dst.client,
					     &outbound_kernel_policy,
					     deltatime(SHUNT_PATIENCE),
					     /*sa_marks*/NULL, /*xfrmi*/NULL,
					     DEFAULT_KERNEL_POLICY_ID,
					     null_shunk, logger,
					     "%s() %s", __func__, why);
			if (!ok) {
				llog(RC_LOG, logger,
				     "replace kernel shunt %s failed - deleting from pluto shunt table",
				     str_selector_pair_sensitive(&src, &dst, &sb));
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
				selector_pair_buf sb;
				llog(RC_LOG, logger,
				     "can't find expected bare shunt to %s: %s",
				     ok ? "replace" : "delete",
				     str_selector_pair_sensitive(&src, &dst, &sb));
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
	set_child_routing(c, rn);
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
					if (!install_prospective_kernel_policies(EXPECT_KERNEL_POLICY_OK,
										 c->spd, logger, HERE)) {
						llog(RC_LOG, logger,
						     "trap shunt install failed ");
					}
				}
			} else {
				delete_bare_kernel_policy(bsp, logger, HERE);
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
		delete_bare_kernel_policy(bsp, logger, HERE);
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

void jam_kernel_acquire(struct jambuf *buf, const struct kernel_acquire *b)
{
	jam(buf, "initiate on-demand for packet ");
	jam_packet(buf, &b->packet);
	if (!b->by_acquire) {
		jam(buf, " by whack");
	}
	if (b->sec_label.len > 0) {
		jam(buf, " sec_label=");
		jam_sanitized_hunk(buf, b->sec_label);
	}
#if 0
	if (b->state_id > 0) {
		jam(buf, " seq=%u", (unsigned)b->state_id);
	}
	if (b->policy_id > 0) {
		jam(buf, " policy=%u", (unsigned)b->policy_id);
	}
#endif
}
