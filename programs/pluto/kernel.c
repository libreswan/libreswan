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
 * Copyright (C) 2016-2019 Andrew Cagney <cagney@gnu.org>
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
#include "lswlog.h"

#include "defs.h"
#include "rnd.h"
#include "id.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "timer.h"
#include "kernel.h"
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

bool can_do_IPcomp = TRUE;  /* can system actually perform IPCOMP? */

/* test if the routes required for two different connections agree
 * It is assumed that the destination subnets agree; we are only
 * testing that the interfaces and nexthops match.
 */
#define routes_agree(c, d) \
	((c)->interface->ip_dev == (d)->interface->ip_dev && \
	 sameaddr(&(c)->spd.this.host_nexthop, &(d)->spd.this.host_nexthop))

const struct pfkey_proto_info null_proto_info[2] = {
	{
		.proto = IPPROTO_ESP,
		.mode = ENCAPSULATION_MODE_TRANSPORT,
		.reqid = 0
	},
	{
		.proto = 0,
		.mode = 0,
		.reqid = 0
	}
};

struct bare_shunt {
	policy_prio_t policy_prio;
	ip_selector our_client;
	ip_selector peer_client;
	ip_said said;
	int transport_proto; /* XXX: same value in local/remote */
	unsigned long count;
	monotime_t last_activity;

	/*
	 * Note: "why" must be in stable storage (not auto, not heap)
	 * because we use it indefinitely without copying or pfreeing.
	 * Simple rule: use a string literal.
	 */
	const char *why;
	/* the connection from where it came - used to re-load /32 conns */
	char *from_cn;

	struct bare_shunt *next;
};

static struct bare_shunt *bare_shunts = NULL;

#ifdef IPSEC_CONNECTION_LIMIT
static int num_ipsec_eroute = 0;
#endif

static void log_bare_shunt(lset_t rc_flags, const char *op, const struct bare_shunt *bs)
{
	said_buf sat;
	selector_buf ourb;
	selector_buf peerb;

	char prio[POLICY_PRIO_BUF];
	fmt_policy_prio(bs->policy_prio, prio);

	log_global(rc_flags, null_fd,
		   "%s bare shunt %p %s --%d--> %s => %s %s    %s",
		   op, (const void *)bs,
		   str_selector(&bs->our_client, &ourb),
		   bs->transport_proto,
		   str_selector(&bs->peer_client, &peerb),
		   str_said(&bs->said, &sat),
		   prio, bs->why);
}

static void dbg_bare_shunt(const char *op, const struct bare_shunt *bs)
{
	/* same as log_bare_shunt but goes to debug log */
	if (DBGP(DBG_BASE)) {
		log_bare_shunt(DEBUG_STREAM, op, bs);
	}
}

/*
 * Note: "why" must be in stable storage (not auto, not heap)
 * because we use it indefinitely without copying or pfreeing.
 * Simple rule: use a string literal.
 */
void add_bare_shunt(const ip_subnet *our_client, const ip_subnet *peer_client,
		    int transport_proto, ipsec_spi_t shunt_spi,
		    const char *why)
{
	/* report any duplication; this should NOT happen */
	struct bare_shunt **bspp = bare_shunt_ptr(our_client, peer_client, transport_proto);

	if (bspp != NULL) {
		/* maybe: passert(bsp == NULL); */
		log_bare_shunt(RC_LOG, "CONFLICTING existing", *bspp);
	}

	struct bare_shunt *bs = alloc_thing(struct bare_shunt,
					"bare shunt");

	bs->why = why;
	bs->from_cn = NULL;
	bs->our_client = *our_client;
	bs->peer_client = *peer_client;
	bs->transport_proto = transport_proto;
	bs->policy_prio = BOTTOM_PRIO;

	bs->said = said3(&subnet_type(our_client)->any_address, htonl(shunt_spi), &ip_protocol_internal);
	bs->count = 0;
	bs->last_activity = mononow();

	bs->next = bare_shunts;
	bare_shunts = bs;
	dbg_bare_shunt("add", bs);

	/* report duplication; this should NOT happen */
	if (bspp != NULL) {
		log_bare_shunt(RC_LOG, "CONFLICTING      new", bs);
	}
}


/*
 * Note: "why" must be in stable storage (not auto, not heap)
 * because we use it indefinitely without copying or pfreeing.
 * Simple rule: use a string literal.
 */

void record_and_initiate_opportunistic(const ip_selector *our_client,
				       const ip_selector *peer_client,
				       unsigned transport_proto,
				       struct xfrm_user_sec_ctx_ike *uctx,
				       const char *why)
{
	passert(selector_type(our_client) == selector_type(peer_client));
	passert(selector_ipproto(our_client) == transport_proto);
	passert(selector_ipproto(peer_client) == transport_proto);
	/* XXX: port may or may not be zero */

	/*
	 * Add the kernel shunt to the pluto bare shunt list.
	 *
	 * We need to do this because the %hold shunt was installed by
	 * kernel and we want to keep track of it inside pluto.
	 */

	/*const*/ struct bare_shunt **bspp = bare_shunt_ptr(our_client, peer_client,
							    transport_proto);
	if (bspp != NULL &&
	    (*bspp)->said.proto == &ip_protocol_internal &&
	    (*bspp)->said.spi == htonl(SPI_HOLD)) {
		log_global(RC_LOG_SERIOUS, null_fd, "existing bare shunt found - refusing to add a duplicate");
		/* should we continue with initiate_ondemand() ? */
	} else {
		add_bare_shunt(our_client, peer_client, transport_proto, SPI_HOLD, why);
	}

	/* XXX: missing transport_proto */
	ip_address sp = subnet_prefix(our_client);
	ip_address dp = subnet_prefix(peer_client);
	ip_endpoint src = endpoint(&sp, subnet_hport(our_client));
	ip_endpoint dst = endpoint(&dp, subnet_hport(peer_client));
	passert(endpoint_type(&src) == endpoint_type(&dst)); /* duh */

	/* actually initiate opportunism / ondemand */
	initiate_ondemand(&src, &dst, transport_proto,
			  TRUE, null_fd, true/*background*/,
			  uctx, "acquire");

	if (kernel_ops->remove_orphaned_holds != NULL) {
		dbg("record_and_initiate_opportunistic(): tell kernel to remove orphan hold for our bare shunt");
		kernel_ops->remove_orphaned_holds(transport_proto,
						  our_client, peer_client);
	}
}

static reqid_t get_proto_reqid(reqid_t base, const struct ip_protocol *proto)
{
	if (proto == &ip_protocol_comp)
		return reqid_ipcomp(base);

	if (proto == &ip_protocol_esp)
		return reqid_esp(base);

	if (proto == &ip_protocol_ah)
		return reqid_ah(base);

	PASSERT_FAIL("bad protocol %s", proto->name);
}

/* Generate Unique SPI numbers.
 *
 * The specs say that the number must not be less than IPSEC_DOI_SPI_MIN.
 * Pluto generates numbers not less than IPSEC_DOI_SPI_OUR_MIN,
 * reserving numbers in between for manual keying (but we cannot so
 * restrict numbers generated by our peer).
 * XXX This should be replaced by a call to the kernel when
 * XXX we get an API.
 * The returned SPI is in network byte order.
 * We use a random number as the initial SPI so that there is
 * a good chance that different Pluto instances will choose
 * different SPIs.  This is good for two reasons.
 * - the keying material for the initiator and responder only
 *   differs if the SPIs differ.
 * - if Pluto is restarted, it would otherwise recycle the SPI
 *   numbers and confuse everything.  When the kernel generates
 *   SPIs, this will no longer matter.
 * We then allocate numbers sequentially.  Thus we don't have to
 * check if the number was previously used (assuming that no
 * SPI lives longer than 4G of its successors).
 */
ipsec_spi_t get_ipsec_spi(ipsec_spi_t avoid,
			const struct ip_protocol *proto,
			const struct spd_route *sr,
			bool tunnel)
{
	passert(proto == &ip_protocol_ah || proto == &ip_protocol_esp);

	if (kernel_ops->get_spi != NULL) {
		char text_said[SATOT_BUF];
		set_text_said(text_said, &sr->this.host_addr, 0, proto);
		return kernel_ops->get_spi(&sr->that.host_addr,
					&sr->this.host_addr, proto, tunnel,
					get_proto_reqid(sr->reqid, proto),
					IPSEC_DOI_SPI_OUR_MIN, 0xffffffff,
					text_said);
	} else {
		static ipsec_spi_t spi = 0; /* host order, so not returned directly! */

		spi++;
		while (spi < IPSEC_DOI_SPI_OUR_MIN || spi == ntohl(avoid))
			get_rnd_bytes((u_char *)&spi, sizeof(spi));

		if (DBGP(DBG_BASE)) {
			ipsec_spi_t spi_net = htonl(spi);
			DBG_dump("generate SPI:", (u_char *)&spi_net,
				 sizeof(spi_net));
		}

		return htonl(spi);
	}
}

/* Generate Unique CPI numbers.
 * The result is returned as an SPI (4 bytes) in network order!
 * The real bits are in the nework-low-order 2 bytes.
 * Modelled on get_ipsec_spi, but range is more limited:
 * 256-61439.
 * If we can't find one easily, return 0 (a bad SPI,
 * no matter what order) indicating failure.
 */
ipsec_spi_t get_my_cpi(const struct spd_route *sr, bool tunnel)
{
	if (kernel_ops->get_spi != NULL) {
		char text_said[SATOT_BUF];
		set_text_said(text_said, &sr->this.host_addr, 0, &ip_protocol_comp);
		return kernel_ops->get_spi(&sr->that.host_addr,
					&sr->this.host_addr, &ip_protocol_comp,
					tunnel,
					get_proto_reqid(sr->reqid, &ip_protocol_comp),
					IPCOMP_FIRST_NEGOTIATED,
					IPCOMP_LAST_NEGOTIATED,
					text_said);
	} else {
		static cpi_t first_busy_cpi = 0;
		static cpi_t latest_cpi = 0;

		while (!(IPCOMP_FIRST_NEGOTIATED <= first_busy_cpi &&
				first_busy_cpi < IPCOMP_LAST_NEGOTIATED)) {
			get_rnd_bytes((u_char *)&first_busy_cpi,
				sizeof(first_busy_cpi));
			latest_cpi = first_busy_cpi;
		}

		latest_cpi++;

		if (latest_cpi == first_busy_cpi)
			find_my_cpi_gap(&latest_cpi, &first_busy_cpi);

		if (latest_cpi > IPCOMP_LAST_NEGOTIATED)
			latest_cpi = IPCOMP_FIRST_NEGOTIATED;

		return htonl((ipsec_spi_t)latest_cpi);
	}
}

/*
 * Remove all characters but [-_.0-9a-zA-Z] from a character string.
 * Truncates the result if it would be too long.
 */

static void jam_clean_xauth_username(struct lswlog *buf, const char *src)
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
		libreswan_log("Warning: XAUTH username changed from '%s' to '%s'",
			      src, dst);
	}
}

/*
 * form the command string
 *
 * note: this mutates *st by calling get_sa_info().
 */
static void jam_common_shell_out(jambuf_t *buf, const struct connection *c,
				 const struct spd_route *sr, struct state *st,
				 bool inbytes, bool outbytes)
{
	ip_address ta;

	char *id_vname = NULL;

	if (c->xfrmi != NULL && c->xfrmi->name != NULL)
		id_vname = c->xfrmi->name;
	else
		id_vname = "NULL";

	/* change VERSION when interface spec changes */
	jam(buf, "PLUTO_VERSION='2.0' ");
	jam(buf, "PLUTO_CONNECTION='%s' ", c->name);
	jam(buf, "PLUTO_VIRT_INTERFACE='%s' ", id_vname);
	jam(buf, "PLUTO_INTERFACE='%s' ", c->interface == NULL ? "NULL" : c->interface->ip_dev->id_rname);
	jam(buf, "PLUTO_XFRMI_ROUTE='%s' ",  (c->xfrmi != NULL && c->xfrmi->if_id > 0) ? "yes" : "");

	if (address_is_specified(&sr->this.host_nexthop)) {
		jam(buf, "PLUTO_NEXT_HOP='");
		jam_address(buf, &sr->this.host_nexthop);
		jam(buf, "' ");
	}

	ipstr_buf bme;
	jam(buf, "PLUTO_ME='%s' ", ipstr(&sr->this.host_addr, &bme));

	jam(buf, "PLUTO_MY_ID='");
	jam_id(buf, &sr->this.id, jam_meta_escaped_bytes);
	jam(buf, "' ");

	jam(buf, "PLUTO_MY_CLIENT='");
	jam_subnet(buf, &sr->this.client);
	jam(buf, "' ");

	jam(buf, "PLUTO_MY_CLIENT_NET='");
	ta = subnet_prefix(&sr->this.client);
	jam_address(buf, &ta);
	jam(buf, "' ");

	jam(buf, "PLUTO_MY_CLIENT_MASK='");
	ta = subnet_mask(&sr->this.client);
	jam_address(buf, &ta);
	jam(buf, "' ");

	if (subnet_is_specified(&sr->this.host_vtiip)) {
		jam(buf, "VTI_IP='");
		jam_subnet(buf, &sr->this.host_vtiip);
		jam(buf, "' ");
	}

	if (!isanyaddr(&sr->this.ifaceip.addr)) {
		jam(buf, "INTERFACE_IP='");
		jam_subnet(buf, &sr->this.ifaceip);
		jam(buf, "' ");
	}

	jam(buf, "PLUTO_MY_PORT='%u' ", sr->this.port);
	jam(buf, "PLUTO_MY_PROTOCOL='%u' ", sr->this.protocol);
	jam(buf, "PLUTO_SA_REQID='%u' ", sr->reqid);
	jam(buf, "PLUTO_SA_TYPE='%s' ", (st == NULL ? "none" :
					st->st_esp.present ? "ESP" :
					st->st_ah.present ? "AH" :
					st->st_ipcomp.present ? "IPCOMP" :
					"unknown?"));
	ipstr_buf bpeer;
	jam(buf, "PLUTO_PEER='%s' ", ipstr(&sr->that.host_addr, &bpeer));

	jam(buf, "PLUTO_PEER_ID='");
	jam_id(buf, &sr->that.id, jam_meta_escaped_bytes);
	jam(buf, "' ");

	jam(buf, "PLUTO_PEER_CLIENT='");
	jam_subnet(buf, &sr->that.client);
	jam(buf, "' ");

	jam(buf, "PLUTO_PEER_CLIENT_NET='");
	ta = subnet_prefix(&sr->that.client);
	jam_address(buf, &ta);
	jam(buf, "' ");

	jam(buf, "PLUTO_PEER_CLIENT_MASK='");
	ta = subnet_mask(&sr->that.client);
	jam_address(buf, &ta);
	jam(buf, "' ");

	jam(buf, "PLUTO_PEER_PORT='%u' ", sr->that.port);
	jam(buf, "PLUTO_PEER_PROTOCOL='%u' ", sr->that.protocol);

	jam(buf, "PLUTO_PEER_CA='");
	for (struct pubkey_list *p = pluto_pubkeys; p != NULL; p = p->next) {
		struct pubkey *key = p->key;
		int pathlen;	/* value ignored */
		if (key->type == &pubkey_type_rsa &&
		    same_id(&sr->that.id, &key->id) &&
		    trusted_ca_nss(key->issuer, sr->that.ca, &pathlen)) {
			jam_dn_or_null(buf, key->issuer, "", jam_meta_escaped_bytes);
			break;
		}
	}
	jam(buf, "' ");

	jam(buf, "PLUTO_STACK='%s' ", kernel_ops->kern_name);

	if (c->metric != 0) {
		jam(buf, "PLUTO_METRIC=%d ", c->metric);
	}

	if (c->connmtu != 0) {
		jam(buf, "PLUTO_MTU=%d ", c->connmtu);
	}

	jam(buf, "PLUTO_ADDTIME='%" PRIu64 "' ", st == NULL ? (uint64_t)0 : st->st_esp.add_time);
	jam(buf, "PLUTO_CONN_POLICY='%s%s' ", prettypolicy(c->policy), NEVER_NEGOTIATE(c->policy) ? "+NEVER_NEGOTIATE" : "");
	jam(buf, "PLUTO_CONN_KIND='%s' ", enum_show(&connection_kind_names, c->kind));
	jam(buf, "PLUTO_CONN_ADDRFAMILY='ipv%d' ", address_type(&sr->this.host_addr)->ip_version);
	jam(buf, "XAUTH_FAILED=%d ", (st != NULL && st->st_xauth_soft) ? 1 : 0);

	if (st != NULL && st->st_xauth_username[0] != '\0') {
		jam(buf, "PLUTO_USERNAME='");
		jam_clean_xauth_username(buf, st->st_xauth_username);
		jam(buf, "' ");
	}

	if (address_is_specified(&sr->this.host_srcip)) {
		jam(buf, "PLUTO_MY_SOURCEIP='");
		jam_address(buf, &sr->this.host_srcip);
		jam(buf, "' ");
		if (st != NULL)
			jam(buf, "PLUTO_MOBIKE_EVENT='%s' ",
					st->st_mobike_del_src_ip ? "yes" : "");
	}

	jam(buf, "PLUTO_IS_PEER_CISCO='%u' ", c->remotepeertype /* ??? kind of odd printing an enum with %u */);
	jam(buf, "PLUTO_PEER_DNS_INFO='%s' ", (st != NULL && st->st_seen_cfg_dns != NULL) ? st->st_seen_cfg_dns : "");
	jam(buf, "PLUTO_PEER_DOMAIN_INFO='%s' ", (st != NULL && st->st_seen_cfg_domains != NULL) ? st->st_seen_cfg_domains : "");
	jam(buf, "PLUTO_PEER_BANNER='%s' ", (st != NULL && st->st_seen_cfg_banner != NULL) ? st->st_seen_cfg_banner : "");
	jam(buf, "PLUTO_CFG_SERVER='%u' ", sr->this.modecfg_server);
	jam(buf, "PLUTO_CFG_CLIENT='%u' ", sr->this.modecfg_client);
#ifdef HAVE_NM
	jam(buf, "PLUTO_NM_CONFIGURED='%u' ", c->nmconfigured);
#endif

	if (inbytes) {
		jam(buf, "PLUTO_INBYTES='%" PRIu64 "' ",
		    st->st_esp.present ? st->st_esp.our_bytes :
		    st->st_ah.present ? st->st_ah.our_bytes :
		    st->st_ipcomp.present ? st->st_ipcomp.our_bytes :
		    0);
	}
	if (outbytes) {
		jam(buf, "PLUTO_OUTBYTES='%" PRIu64 "' ",
		    st->st_esp.present ? st->st_esp.peer_bytes :
		    st->st_ah.present ? st->st_ah.peer_bytes :
		    st->st_ipcomp.present ? st->st_ipcomp.peer_bytes :
		    0);
	}

	if (c->nflog_group != 0) {
		jam(buf, "NFLOG=%d ", c->nflog_group);
	}

	if (c->sa_marks.in.val != 0) {
		jam(buf, "CONNMARK_IN=%" PRIu32 "/%#08" PRIx32 " ",
		    c->sa_marks.in.val, c->sa_marks.in.mask);
	}
	if (c->sa_marks.out.val != 0) {
		jam(buf, "CONNMARK_OUT=%" PRIu32 "/%#08" PRIx32 " ",
		    c->sa_marks.out.val, c->sa_marks.out.mask);
	}
	if (c->xfrmi != NULL && c->xfrmi->if_id > 0) {
		if (addrinsubnet(&sr->that.host_addr, &sr->that.client)) {
			jam(buf, "PLUTO_XFRMI_FWMARK='%" PRIu32 "/0xffffffff' ",
					c->xfrmi->if_id);
		} else {
			address_buf bpeer;
			subnet_buf peerclient_str;
			dbg("not adding PLUTO_XFRMI_FWMARK. PLUTO_PEER=%s is not inside PLUTO_PEER_CLIENT=%s",
			    str_address(&sr->that.host_addr, &bpeer),
			    str_subnet(&sr->that.client, &peerclient_str));
			jam(buf, "PLUTO_XFRMI_FWMARK='' ");
		}
	}
	jam(buf, "VTI_IFACE='%s' ", c->vti_iface ? c->vti_iface : "");
	jam(buf, "VTI_ROUTING='%s' ", bool_str(c->vti_routing));
	jam(buf, "VTI_SHARED='%s' ", bool_str(c->vti_shared));

	if (sr->this.has_cat) {
		jam(buf, "CAT='YES' ");
	}

	jam(buf, "SPI_IN=0x%x SPI_OUT=0x%x " /* SPI_IN SPI_OUT */,
	    (st == NULL ? 0 : st->st_esp.present ? ntohl(st->st_esp.attrs.spi) :
	     st->st_ah.present ? ntohl(st->st_ah.attrs.spi) :
	     st->st_ipcomp.present ? ntohl(st->st_ipcomp.attrs.spi) : 0),
	    (st == NULL ? 0 : st->st_esp.present ? ntohl(st->st_esp.our_spi) :
	     st->st_ah.present ? ntohl(st->st_ah.our_spi) :
	     st->st_ipcomp.present ? ntohl(st->st_ipcomp.our_spi) : 0));
}

/*
 * form the command string
 *
 * note: this mutates *st by calling fmt_traffic_str
 */
bool fmt_common_shell_out(char *buf, size_t blen, const struct connection *c,
			  const struct spd_route *sr, struct state *st)
{
	/*
	 * note: this mutates *st by calling get_sa_info
	 *
	 * XXX: does the get_sa_info() call order matter? Should this
	 * be a single "atomic" call?
	 *
	 * true==inbound: inbound updates OUR_BYTES; !inbound updates
	 * PEER_BYTES.
	 */
	bool outbytes = st != NULL && get_sa_info(st, false, NULL);
	bool inbytes = st != NULL && get_sa_info(st, true, NULL);
	jambuf_t jambuf = array_as_jambuf(buf, blen);
	jam_common_shell_out(&jambuf, c, sr, st, inbytes, outbytes);
	return jambuf_ok(&jambuf);
}

bool do_command(const struct connection *c,
		const struct spd_route *sr,
		const char *verb,
		struct state *st)
{
	const char *verb_suffix;

	/*
	 * Support for skipping updown, eg leftupdown=""
	 * Useful on busy servers that do not need to use updown for anything
	 */
	if (sr->this.updown == NULL || streq(sr->this.updown, "%disabled")) {
		dbg("skipped updown %s command - disabled per policy", verb);
		return TRUE;
	}
	dbg("running updown command \"%s\" for verb %s ", sr->this.updown, verb);

	/*
	 * Figure out which verb suffix applies.
	 * NOTE: this is a duplicate of code in mast_do_command_vs.
	 */
	{
		const char *hs, *cs;

		switch (addrtypeof(&sr->this.host_addr)) {
		case AF_INET:
			hs = "-host";
			cs = "-client";
			break;
		case AF_INET6:
			hs = "-host-v6";
			cs = "-client-v6";
			break;
		default:
			loglog(RC_LOG_SERIOUS, "unknown address family");
			return FALSE;
		}
		verb_suffix = subnetisaddr(&sr->this.client,
					&sr->this.host_addr) ?
			hs : cs;
	}

	dbg("command executing %s%s", verb, verb_suffix);

	if (kernel_ops->docommand == NULL) {
		dbg("no do_command for method %s", kernel_ops->kern_name);
	} else {
		return (*kernel_ops->docommand)(c, sr, verb, verb_suffix, st);
	}
	return TRUE;
}

bool invoke_command(const char *verb, const char *verb_suffix, const char *cmd)
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
				return TRUE;
			}
#endif
			loglog(RC_LOG_SERIOUS, "unable to popen %s%s command",
				verb, verb_suffix);
			return FALSE;
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
					LOG_ERRNO(errno, "fgets failed on output of %s%s command",
						  verb, verb_suffix);
					pclose(f);
					return FALSE;
				} else {
					passert(feof(f));
					break;
				}
			} else {
				char *e = resp + strlen(resp);

				if (e > resp && e[-1] == '\n')
					e[-1] = '\0'; /* trim trailing '\n' */
				libreswan_log("%s%s output: %s", verb,
					verb_suffix, resp);
			}
		}

		/* report on and react to return code */
		{
			int r = pclose(f);

			if (r == -1) {
				LOG_ERRNO(errno, "pclose failed for %s%s command",
					  verb, verb_suffix);
				return FALSE;
			} else if (WIFEXITED(r)) {
				if (WEXITSTATUS(r) != 0) {
					loglog(RC_LOG_SERIOUS,
						"%s%s command exited with status %d",
						verb, verb_suffix,
						WEXITSTATUS(r));
					return FALSE;
				}
			} else if (WIFSIGNALED(r)) {
				loglog(RC_LOG_SERIOUS,
					"%s%s command exited with signal %d",
					verb, verb_suffix, WTERMSIG(r));
				return FALSE;
			} else {
				loglog(RC_LOG_SERIOUS,
					"%s%s command exited with unknown status %d",
					verb, verb_suffix, r);
				return FALSE;
			}
		}
	}
	return TRUE;
}

/* Check that we can route (and eroute).  Diagnose if we cannot. */

enum routability {
	route_impossible,
	route_easy,
	route_nearconflict,
	route_farconflict,
	route_unnecessary
};

/*
 * handle co-terminal attempt of the "near" kind
 *
 * Note: it mutates both inside and outside
 */
static enum routability note_nearconflict(
	struct connection *outside,	/* CK_PERMANENT */
	struct connection *inside)	/* CK_TEMPLATE */
{
	char inst[CONN_INST_BUF];

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
	outside->spd.eroute_owner = SOS_NOBODY;
	outside->spd.routing = RT_UNROUTED_KEYED;

	/*
	 * set the priority of the new eroute owner to be higher
	 * than that of the current eroute owner
	 */
	inside->prio = outside->prio + 1;

	loglog(RC_LOG_SERIOUS,
		"conflict on eroute (%s), switching eroute to %s and linking %s",
		fmt_conn_instance(inside, inst),
		inside->name, outside->name);

	return route_nearconflict;
}

/*
 * Note: this may mutate c
 */
static enum routability could_route(struct connection *c, struct logger *logger)
{
	dbg("could_route called for %s; kind=%s that.has_client=%s oppo=%s this.host_port=%u",
	    c->name,
	    enum_show(&connection_kind_names, c->kind),
	    bool_str(c->spd.that.has_client),
	    bool_str(c->policy & POLICY_OPPORTUNISTIC),
	    c->spd.this.host_port);

	/* it makes no sense to route a connection that is ISAKMP-only */
	if (!NEVER_NEGOTIATE(c->policy) && !HAS_IPSEC_POLICY(c->policy)) {
		log_message(RC_ROUTE, logger,
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
	 * if this is a Road Warrior template, we cannot route.
	 * Opportunistic template is OK.
	 */
	if (!c->spd.that.has_client &&
	    c->kind == CK_TEMPLATE &&
	    !(c->policy & POLICY_OPPORTUNISTIC)) {
		log_message(RC_ROUTE, logger,
			    "cannot route template policy of %s",
			    prettypolicy(c->policy));
		return route_impossible;
	}

	/* if routing would affect IKE messages, reject */
	if (c->spd.this.host_port != NAT_IKE_UDP_PORT &&
	    c->spd.this.host_port != IKE_UDP_PORT &&
	    addrinsubnet(&c->spd.that.host_addr, &c->spd.that.client)) {
		log_message(RC_LOG_SERIOUS, logger,
			    "cannot install route: peer is within its client");
		return route_impossible;
	}

	struct spd_route *esr, *rosr;
	struct connection *ero,		/* who, if anyone, owns our eroute? */
		*ro = route_owner(c, &c->spd, &rosr, &ero, &esr);	/* who owns our route? */

	/*
	 * If there is already a route for peer's client subnet
	 * and it disagrees about interface or nexthop, we cannot steal it.
	 * Note: if this connection is already routed (perhaps for another
	 * state object), the route will agree.
	 * This is as it should be -- it will arise during rekeying.
	 */
	if (ro != NULL && !routes_agree(ro, c)) {

		if (!compatible_overlapping_connections(c, ero)) {
			/*
			 * Another connection is already using the eroute.
			 * TODO: XFRM can do this? For now excempt OE only
			 */
			if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
				connection_buf cib;
				log_message(RC_LOG_SERIOUS, logger,
					    "cannot route -- route already in use for "PRI_CONNECTION"",
					    pri_connection(ro, &cib));
				return route_impossible;
			} else {
				connection_buf cib;
				log_message(RC_LOG_SERIOUS, logger,
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
			return note_nearconflict(ero, c);
		} else if (c->kind == CK_PERMANENT &&
			ero->kind == CK_TEMPLATE) {
			return note_nearconflict(c, ero);
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

		if (LDISJOINT(POLICY_OVERLAPIP, c->policy | ero->policy)) {
			/*
			 * another connection is already using the eroute,
			 * TODO: XFRM apparently can do this though
			 */
			connection_buf erob;
			log_message(RC_LOG_SERIOUS, logger,
				    "cannot install eroute -- it is in use for "PRI_CONNECTION" #%lu",
				    pri_connection(ero, &erob), esr->eroute_owner);
			return route_impossible;
		}

		connection_buf erob;
		dbg("overlapping permitted with "PRI_CONNECTION" #%lu",
		    pri_connection(ero, &erob), esr->eroute_owner);
	}
	return route_easy;
}

bool trap_connection(struct connection *c, struct fd *whackfd)
{
	struct logger logger = CONNECTION_LOGGER(c, whackfd);
	enum routability r = could_route(c, &logger);

	switch (r) {
	case route_impossible:
		return FALSE;

	case route_easy:
	case route_nearconflict:
		/*
		 * RT_ROUTED_TUNNEL is treated specially: we don't override
		 * because we don't want to lose track of the IPSEC_SAs etc.
		 * ??? The test treats RT_UNROUTED_KEYED specially too.
		 */
		if (c->spd.routing < RT_ROUTED_TUNNEL)
			return route_and_eroute(c, &c->spd, NULL);

		return TRUE;

	case route_farconflict:
		return FALSE;

	case route_unnecessary:
		return TRUE;
	default:
		bad_case(r);
	}
}

/*
 * Add/replace/delete a shunt eroute.
 *
 * Such an eroute determines the fate of packets without the use
 * of any SAs.  These are defaults, in effect.
 * If a negotiation has not been attempted, use %trap.
 * If negotiation has failed, the choice between %trap/%pass/%drop/%reject
 * is specified in the policy of connection c.
 */
static bool shunt_eroute(const struct connection *c,
			const struct spd_route *sr,
			enum routing_t rt_kind,
			enum pluto_sadb_operations op,
			const char *opname)
{
	if (DBGP(DBG_BASE)) {
		selector_buf thisb, thatb;
		DBG_log("shunt_eroute() called for connection '%s' to '%s' for rt_kind '%s' using protoports %s --%d->- %s",
			c->name, opname, enum_name(&routing_story, rt_kind),
			str_selector(&sr->this.client, &thisb),
			sr->this.protocol,
			str_selector(&sr->that.client, &thatb));
	}

	if (kernel_ops->shunt_eroute != NULL) {
		return kernel_ops->shunt_eroute(c, sr, rt_kind, op, opname);
	}

	loglog(RC_COMMENT, "no shunt_eroute implemented for %s interface",
		kernel_ops->kern_name);
	return TRUE;
}

static bool sag_eroute(const struct state *st,
		const struct spd_route *sr,
		enum pluto_sadb_operations op,
		const char *opname)
{
	pexpect(kernel_ops->sag_eroute != NULL);
	if (kernel_ops->sag_eroute != NULL)
		return kernel_ops->sag_eroute(st, sr, op, opname);

	return FALSE;
}

void migration_up(struct connection *c,  struct state *st)
{
	for (struct spd_route *sr = &c->spd; sr != NULL; sr = sr->spd_next) {
#ifdef IPSEC_CONNECTION_LIMIT
		num_ipsec_eroute++;
#endif
		sr->routing = RT_ROUTED_TUNNEL; /* do now so route_owner won't find us */
		(void) do_command(c, sr, "up", st);
		(void) do_command(c, sr, "route", st);
	}
}

void migration_down(struct connection *c,  struct state *st)
{
	for (struct spd_route *sr = &c->spd; sr != NULL; sr = sr->spd_next) {
		enum routing_t cr = sr->routing;

#ifdef IPSEC_CONNECTION_LIMIT
		if (erouted(cr))
			num_ipsec_eroute--;
#endif

		sr->routing = RT_UNROUTED; /* do now so route_owner won't find us */

		/* only unroute if no other connection shares it */
		if (routed(cr) && route_owner(c, sr, NULL, NULL, NULL) == NULL) {
			(void) do_command(c, sr, "down", st);
			st->st_mobike_del_src_ip = true;
			(void) do_command(c, sr, "unroute", st);
			st->st_mobike_del_src_ip = false;
		}
	}
}


/* delete any eroute for a connection and unroute it if route isn't shared */
void unroute_connection(struct connection *c)
{
	for (struct spd_route *sr = &c->spd; sr != NULL; sr = sr->spd_next) {
		enum routing_t cr = sr->routing;

		if (erouted(cr)) {
			/* cannot handle a live one */
			passert(cr != RT_ROUTED_TUNNEL);
			shunt_eroute(c, sr, RT_UNROUTED, ERO_DELETE, "delete");
#ifdef IPSEC_CONNECTION_LIMIT
			num_ipsec_eroute--;
#endif
		}

		sr->routing = RT_UNROUTED; /* do now so route_owner won't find us */

		/* only unroute if no other connection shares it */
		if (routed(cr) && route_owner(c, sr, NULL, NULL, NULL) == NULL)
			(void) do_command(c, sr, "unroute", NULL);
	}
}

#include "kernel_alg.h"

void set_text_said(char *text_said, const ip_address *dst,
			ipsec_spi_t spi, const struct ip_protocol *sa_proto)
{
	ip_said said = said3(dst, spi, sa_proto);
	jambuf_t jam = array_as_jambuf(text_said, SATOT_BUF);
	jam_said(&jam, &said);
}

/* find an entry in the bare_shunt table.
 * Trick: return a pointer to the pointer to the entry;
 * this allows the entry to be deleted.
 */
struct bare_shunt **bare_shunt_ptr(const ip_selector *our_client,
				   const ip_selector *peer_client,
				   int transport_proto)

{
	struct bare_shunt *p, **pp;

	for (pp = &bare_shunts; (p = *pp) != NULL; pp = &p->next) {
		if (transport_proto == p->transport_proto &&
		    selector_eq(our_client, &p->our_client) &&
		    selector_eq(peer_client, &p->peer_client)) {
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
	pfreeany(p->from_cn);
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

		char prio[POLICY_PRIO_BUF];
		fmt_policy_prio(bs->policy_prio, prio);

		show_comment(s, "%s -%d-> %s => %s %s    %s",
			     str_selector(&(bs)->our_client, &ourb),
			     bs->transport_proto,
			     str_selector(&(bs)->peer_client, &peerb),
			     str_said(&(bs)->said, &sat),
			     prio, bs->why);
	}
}

/* Setup an IPsec route entry.
 * op is one of the ERO_* operators.
 */

// should be made static again once we fix initiate.c calling this directly!
bool raw_eroute(const ip_address *this_host,
		const ip_subnet *this_client,
		const ip_address *that_host,
		const ip_subnet *that_client,
		ipsec_spi_t cur_spi,
		ipsec_spi_t new_spi,
		const struct ip_protocol *sa_proto,
		unsigned int transport_proto,
		enum eroute_type esatype,
		const struct pfkey_proto_info *proto_info,
		deltatime_t use_lifetime,
		uint32_t sa_priority,
		const struct sa_marks *sa_marks,
		const uint32_t xfrm_if_id,
		enum pluto_sadb_operations op,
		const char *opname,
		const char *policy_label)
{
	char text_said[SATOT_BUF + SATOT_BUF];

	switch (op) {
	case ERO_ADD:
	case ERO_ADD_INBOUND:
		set_text_said(text_said, that_host, new_spi, sa_proto);
		break;
	case ERO_DELETE:
	case ERO_DEL_INBOUND:
		set_text_said(text_said, that_host, cur_spi, sa_proto);
		break;
	case ERO_REPLACE:
	case ERO_REPLACE_INBOUND:
	{
		size_t w;

		set_text_said(text_said, that_host, cur_spi, sa_proto);
		w = strlen(text_said);
		text_said[w] = '>';
		set_text_said(text_said + w + 1, that_host, new_spi, sa_proto);
		break;
	}
	default:
		bad_case(op);
	}

	if (DBGP(DBG_BASE)) {
		selector_buf mybuf;
		selector_buf peerbuf;
		DBG_log("%s eroute %s --%d-> %s => %s using reqid %d (raw_eroute) proto=%d",
			opname,
			str_selector(this_client, &mybuf),
			transport_proto,
			str_selector(that_client, &peerbuf),
			text_said,
			proto_info->reqid,
			proto_info->proto);

		if (policy_label != NULL)
			DBG_log("policy security label %s",
				policy_label);
	}

	bool result = kernel_ops->raw_eroute(this_host, this_client,
					that_host, that_client,
					cur_spi, new_spi, sa_proto,
					transport_proto,
					esatype, proto_info,
					use_lifetime, sa_priority, sa_marks,
					xfrm_if_id, op, text_said,
					policy_label);
	dbg("raw_eroute result=%s", result ? "success" : "failed");

	return result;
}

/*
 * Clear any bare shunt holds that overlap with the network we have
 * just routed.  We only consider "narrow" holds: ones for a single
 * address to single address.
 */
static void clear_narrow_holds(const ip_selector *our_client,
			       const ip_selector *peer_client,
			       int transport_proto)
{
	struct bare_shunt *p, **pp;

	for (pp = &bare_shunts; (p = *pp) != NULL; ) {
		/*
		 * is p->{local,remote} within {local,remote}.
		 */
		if (p->said.spi == htonl(SPI_HOLD) &&
		    transport_proto == p->transport_proto &&
		    selector_in_selector(&p->our_client, our_client) &&
		    selector_in_selector(&p->peer_client, peer_client)) {
			if (!delete_bare_shunt(&p->our_client.addr, &p->peer_client.addr,
					       transport_proto, SPI_HOLD,
					       "removing clashing narrow hold")) {
				/* ??? we could not delete a bare shunt */
				log_bare_shunt(RC_LOG, "failed to delete", p);
				break;	/* unlikely to succeed a second time */
			} else if (*pp == p) {
				/*
				 * ??? We deleted the wrong bare shunt!
				 * This happened because more than one entry
				 * matched and we happened to delete a
				 * different one.
				 * Log it!  And keep deleting.
				 */
				log_bare_shunt(RC_LOG, "UNEXPECTEDLY SURVIVING", p);
				pp = &bare_shunts;	/* just in case, start over */
			}
			/*
			 * ??? if we were sure that there could only be one
			 * matching entry, we could break out of the FOR.
			 * For an unknown reason this is not always the case,
			 * so we will continue the loop, with pp unchanged.
			 */
		} else {
			pp = &p->next;
		}
	}
}

/*
 * Replace (or delete) a shunt that is in the bare_shunts table.
 * Issues the PF_KEY commands and updates the bare_shunts table.
 */
static bool fiddle_bare_shunt(const ip_address *src, const ip_address *dst,
			policy_prio_t policy_prio,	/* of replacing shunt*/
			ipsec_spi_t cur_shunt_spi,	/* in host order! */
			ipsec_spi_t new_shunt_spi,	/* in host order! */
			bool repl,		/* if TRUE, replace; if FALSE, delete */
			int transport_proto,
			const char *why)
{
	ip_subnet this_client, that_client;
	const ip_address null_host = address_any(address_type(src));

	dbg("fiddle_bare_shunt called");

	passert(addrtypeof(src) == addrtypeof(dst));
	happy(endtosubnet(src, &this_client, HERE));
	happy(endtosubnet(dst, &that_client, HERE));

	/*
	 * ??? this comment might be obsolete.
	 * If the transport protocol is not the wildcard (0), then we need
	 * to look for a host<->host shunt, and replace that with the
	 * shunt spi, and then we add a %HOLD for what was there before.
	 *
	 * This is at odds with !repl, which should delete things.
	 *
	 */

	dbg("fiddle_bare_shunt with transport_proto %d", transport_proto);

	enum pluto_sadb_operations op = repl ? ERO_REPLACE : ERO_DELETE;

	dbg("%s specific host-to-host bare shunt", repl ? "replacing" : "removing");
	if (kernel_ops->type == USE_XFRM && strstr(why, "IGNORE_ON_XFRM:") != NULL) {
		dbg("skipping raw_eroute because IGNORE_ON_XFRM");
		struct bare_shunt **bs_pp = bare_shunt_ptr(
			&this_client,
			&that_client,
			transport_proto);

		free_bare_shunt(bs_pp);
		libreswan_log("raw_eroute() to op='%s' with transport_proto='%d' kernel shunt skipped - deleting from pluto shunt table",
			repl ? "replace" : "delete",
			transport_proto);
		return TRUE;
	} else if (raw_eroute(&null_host, &this_client,
			&null_host, &that_client,
			htonl(cur_shunt_spi),
			htonl(new_shunt_spi),
			&ip_protocol_internal, transport_proto,
			ET_INT, null_proto_info,
			deltatime(SHUNT_PATIENCE),
			0, /* we don't know connection for priority yet */
			NULL, /* sa_marks */
			0 /* xfrm interface id */,

			op, why, NULL))
	{
		struct bare_shunt **bs_pp = bare_shunt_ptr(
			&this_client,
			&that_client,
			transport_proto);

		dbg("raw_eroute with op='%s' for transport_proto='%d' kernel shunt succeeded, bare shunt lookup %s",
		    repl ? "replace" : "delete", transport_proto,
		    (bs_pp == NULL) ? "failed" : "succeeded");

		/* we can have proto mismatching acquires with xfrm - this is a bad workaround */
		/* ??? what is the nature of those mismatching acquires? */
		/* passert(bs_pp != NULL); */
		if (bs_pp == NULL) {
			ipstr_buf srcb, dstb;

			libreswan_log("can't find expected bare shunt to %s: %s->%s transport_proto='%d'",
				repl ? "replace" : "delete",
				ipstr(src, &srcb), ipstr(dst, &dstb),
				transport_proto);
			return TRUE;
		}

		if (repl) {
			/*
			 * change over to new bare eroute
			 * ours, peers, transport_proto are the same.
			 */
			struct bare_shunt *bs = *bs_pp;

			bs->why = why;
			bs->policy_prio = policy_prio;
			bs->said = said3(&null_host, htonl(new_shunt_spi), &ip_protocol_internal);
			bs->count = 0;
			bs->last_activity = mononow();
			dbg_bare_shunt("change", bs);
		} else {
			/* delete pluto bare shunt */
			free_bare_shunt(bs_pp);
		}
		return TRUE;
	} else {
		struct bare_shunt **bs_pp = bare_shunt_ptr(
			&this_client,
			&that_client,
			transport_proto);

		free_bare_shunt(bs_pp);
		libreswan_log("raw_eroute() to op='%s' with transport_proto='%d' kernel shunt failed - deleting from pluto shunt table",
			repl ? "replace" : "delete",
			transport_proto);

		return FALSE;
	}
}

bool replace_bare_shunt(const ip_address *src, const ip_address *dst,
			policy_prio_t policy_prio,	/* of replacing shunt*/
			ipsec_spi_t cur_shunt_spi,	/* in host order! */
			ipsec_spi_t new_shunt_spi,	/* in host order! */
			int transport_proto,
			const char *why)
{
	return fiddle_bare_shunt(src, dst, policy_prio, cur_shunt_spi, new_shunt_spi, TRUE, transport_proto, why);
}

bool delete_bare_shunt(const ip_address *src, const ip_address *dst,
			int transport_proto, ipsec_spi_t cur_shunt_spi,
			const char *why)
{
	return fiddle_bare_shunt(src, dst, BOTTOM_PRIO, cur_shunt_spi, SPI_PASS /* unused */, FALSE, transport_proto, why);
}

bool eroute_connection(const struct spd_route *sr,
		ipsec_spi_t cur_spi,
		ipsec_spi_t new_spi,
		const struct ip_protocol *sa_proto,
		enum eroute_type esatype,
		const struct pfkey_proto_info *proto_info,
		uint32_t sa_priority,
		const struct sa_marks *sa_marks,
		const uint32_t xfrm_if_id,
		unsigned int op,
	       	const char *opname,
		const char *policy_label)
{
	ip_address peer = sr->that.host_addr;
	char buf2[256];

	snprintf(buf2, sizeof(buf2),
		"eroute_connection %s", opname);

	if (sa_proto == &ip_protocol_internal)
		peer = address_any(address_type(&peer));

	if (sr->this.has_cat) {
		ip_subnet client;

		endtosubnet(&sr->this.host_addr, &client, HERE);
		bool t = raw_eroute(&sr->this.host_addr, &client,
				    &peer, &sr->that.client,
				cur_spi,
				new_spi,
				sa_proto,
				sr->this.protocol,
				esatype,
				proto_info,
				deltatime(0),
				sa_priority, sa_marks, 
				xfrm_if_id,
				op, buf2,
				policy_label);
		if (!t)
			libreswan_log("CAT: failed to eroute additional Client Address Translation policy");

		dbg("%s CAT extra route added return=%d", __func__, t);
	}

	return raw_eroute(&sr->this.host_addr, &sr->this.client,
			  &peer, &sr->that.client,
			cur_spi,
			new_spi,
			sa_proto,
			sr->this.protocol,
			esatype,
			proto_info,
			deltatime(0),
			sa_priority, sa_marks,
			xfrm_if_id,
		       	op, buf2,
			policy_label);
}

/* assign a bare hold or pass to a connection */

bool assign_holdpass(const struct connection *c,
		struct spd_route *sr,
		int transport_proto, ipsec_spi_t negotiation_shunt,
		const ip_address *src, const ip_address *dst)
{
	/*
	 * either the automatically installed %hold eroute is broad enough
	 * or we try to add a broader one and delete the automatic one.
	 * Beware: this %hold might be already handled, but still squeak
	 * through because of a race.
	 */
	enum routing_t ro = sr->routing,	/* routing, old */
		rn = ro;			/* routing, new */

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

	dbg("assign hold, routing was %s, needs to be %s",
	    enum_name(&routing_story, ro),
	    enum_name(&routing_story, rn));

	if (eclipsable(sr)) {
		/*
		 * Although %hold or %pass is appropriately broad, it will
		 * no longer be bare so we must ditch it from the bare table
		 */
		struct bare_shunt **old = bare_shunt_ptr(&sr->this.client, &sr->that.client, sr->this.protocol);

		if (old == NULL) {
			/* ??? should this happen?  It does. */
			libreswan_log("assign_holdpass() no bare shunt to remove? - mismatch?");
		} else {
			/* ??? should this happen? */
			dbg("assign_holdpass() removing bare shunt");
			free_bare_shunt(old);
		}
	} else {
		dbg("assign_holdpass() need broad(er) shunt");
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
				op = ERO_REPLACE;
				reason = "replace %trap with broad %pass or %hold";
			} else {
				op = ERO_ADD;
				reason = "add broad %pass or %hold";
			}

			if (eroute_connection(sr,
						htonl(SPI_HOLD), /* kernel induced */
						htonl(negotiation_shunt),
						&ip_protocol_internal, ET_INT,
						null_proto_info,
						calculate_sa_prio(c, FALSE),
						NULL, 0 /* xfrm_if_id */,
						op,
						reason,
						c->policy_label))
			{
				dbg("assign_holdpass() eroute_connection() done");
			} else {
				libreswan_log("assign_holdpass() eroute_connection() failed");
				return FALSE;
			}
		}

		if (!delete_bare_shunt(src, dst,
					transport_proto,
					(c->policy & POLICY_NEGO_PASS) ? SPI_PASS : SPI_HOLD,
					(c->policy & POLICY_NEGO_PASS) ? "delete narrow %pass" :
						"delete narrow %hold")) {
			dbg("assign_holdpass() delete_bare_shunt() succeeded");
		} else {
			libreswan_log("assign_holdpass() delete_bare_shunt() failed");
				return FALSE;
		}
	}
	sr->routing = rn;
	dbg(" assign_holdpass() done - returning success");
	return TRUE;
}

/* compute a (host-order!) SPI to implement the policy in connection c */
ipsec_spi_t shunt_policy_spi(const struct connection *c, bool prospective)
{
	/* note: these are in host order :-( */
	static const ipsec_spi_t shunt_spi[] =
	{
		SPI_TRAP,       /* --initiateontraffic */
		SPI_PASS,       /* --pass */
		SPI_DROP,       /* --drop */
		SPI_REJECT,     /* --reject */
	};

	static const ipsec_spi_t fail_spi[] =
	{
		0,              /* --none*/
		SPI_PASS,       /* --failpass */
		SPI_DROP,       /* --faildrop */
		SPI_REJECT,     /* --failreject */
	};

	return prospective ?
		shunt_spi[(c->policy & POLICY_SHUNT_MASK) >>
			POLICY_SHUNT_SHIFT] :
		fail_spi[(c->policy & POLICY_FAIL_MASK) >> POLICY_FAIL_SHIFT];
}

bool del_spi(ipsec_spi_t spi, const struct ip_protocol *proto,
	     const ip_address *src, const ip_address *dest)
{
	char text_said[SATOT_BUF];

	set_text_said(text_said, dest, spi, proto);

	dbg("delete %s", text_said);

	struct kernel_sa sa = {
		.spi = spi,
		.proto = proto,
		.src.address = src,
		.dst.address = dest,
		.text_said = text_said,
	};

	passert(kernel_ops->del_sa != NULL);
	return kernel_ops->del_sa(&sa);
}

static void setup_esp_nic_offload(struct kernel_sa *sa, struct connection *c,
		bool *nic_offload_fallback)
{
	if (c->nic_offload == yna_no ||
	    c->interface == NULL || c->interface->ip_dev == NULL ||
	    c->interface->ip_dev->id_rname == NULL) {
		dbg("NIC esp-hw-offload disabled for connection '%s'", c->name);
		return;
	}

	if (c->nic_offload == yna_auto) {
		if (!c->interface->ip_dev->id_nic_offload) {
			dbg("NIC esp-hw-offload not for connection '%s' not available on interface %s",
				c->name, c->interface->ip_dev->id_rname);
			return;
		}
		*nic_offload_fallback = TRUE;
		dbg("NIC esp-hw-offload offload for connection '%s' enabled on interface %s",
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
	ipsec_spi_t inner_spi = 0;
	const struct ip_protocol *proto = NULL;
	enum eroute_type esatype = ET_UNSPEC;
	bool replace = inbound && (kernel_ops->get_spi != NULL);
	bool outgoing_ref_set = FALSE;
	bool incoming_ref_set = FALSE;
	IPsecSAref_t ref_peer = st->st_ref_peer;
	IPsecSAref_t new_ref_peer = IPSEC_SAREF_NULL;
	bool nic_offload_fallback = FALSE;

	/* SPIs, saved for spigrouping or undoing, if necessary */
	struct kernel_sa said[EM_MAXRELSPIS];
	struct kernel_sa *said_next = said;

	char text_ipcomp[SATOT_BUF];
	char text_esp[SATOT_BUF];
	char text_ah[SATOT_BUF];

	ip_address src, dst;
	ip_selector src_client, dst_client;
	if (inbound) {
		src = c->spd.that.host_addr;
		src_client = c->spd.that.client;
		dst = c->spd.this.host_addr;
		dst_client = c->spd.this.client;
	} else {
		src = c->spd.this.host_addr,
		src_client = c->spd.this.client;
		dst = c->spd.that.host_addr;
		dst_client = c->spd.that.client;
	}
	/* XXX: code is stuffing an endpoint in .host_addr */
	src = strip_endpoint(&src, HERE);
	dst = strip_endpoint(&dst, HERE);

	/*
	 * mode: encapsulation mode called for
	 * encap_oneshot: copy of "encapsulation" but reset to
	 *	ENCAPSULATION_MODE_TRANSPORT after use.
	 */
	int mode = ENCAPSULATION_MODE_TRANSPORT;
	bool add_selector;

	if (st->st_ah.attrs.mode == ENCAPSULATION_MODE_TUNNEL ||
	    st->st_esp.attrs.mode == ENCAPSULATION_MODE_TUNNEL ||
	    st->st_ipcomp.attrs.mode == ENCAPSULATION_MODE_TUNNEL) {
		mode = ENCAPSULATION_MODE_TUNNEL;
		add_selector = FALSE; /* Don't add selectors for tunnel mode */
	} else {
		/*
		 * RFC 4301, Section 5.2 Requires traffic selectors to be set
		 * on transport mode
		 */
		add_selector = TRUE;
	}
	c->ipsec_mode = mode;

	int encap_oneshot = mode;

	struct kernel_sa said_boilerplate = {
		.src.address = &src,
		.dst.address = &dst,
		.src.client = &src_client,
		.dst.client = &dst_client,
		.inbound = inbound,
		.add_selector = add_selector,
		.transport_proto = c->spd.this.protocol,
		.sa_lifetime = c->sa_ipsec_life_seconds,
		.outif = -1,
		.sec_ctx = st->sec_ctx,
	};

	inner_spi = SPI_PASS;
	if (mode == ENCAPSULATION_MODE_TUNNEL) {
		/* If we are tunnelling, set up IP in IP pseudo SA */
		proto = &ip_protocol_ipip;
		esatype = ET_IPIP;
	} else {
		/* For transport mode set ESP */
		/* ??? why are we sure that this isn't AH? */
		proto = &ip_protocol_esp;
		esatype = ET_ESP;
	}

	/* set up IPCOMP SA, if any */

	if (st->st_ipcomp.present) {
		ipsec_spi_t ipcomp_spi =
			inbound ? st->st_ipcomp.our_spi : st->st_ipcomp.attrs.spi;
		unsigned compalg;

		switch (st->st_ipcomp.attrs.transattrs.ta_comp) {
		case IPCOMP_DEFLATE:
			compalg = SADB_X_CALG_DEFLATE;
			break;

		default:
			loglog(RC_LOG_SERIOUS,
			       "IPCOMP transform %s not implemented",
			       st->st_ipcomp.attrs.transattrs.ta_encrypt->common.fqn);
			goto fail;
		}

		set_text_said(text_ipcomp, &dst, ipcomp_spi, &ip_protocol_comp);

		*said_next = said_boilerplate;
		said_next->spi = ipcomp_spi;
		said_next->esatype = ET_IPCOMP;
		said_next->compalg = compalg;
		said_next->mode = encap_oneshot;
		said_next->reqid = reqid_ipcomp(c->spd.reqid);
		said_next->text_said = text_ipcomp;

		if (inbound) {
			/*
			 * set corresponding outbound SA. We can do this on
			 * each SA in the bundle without harm.
			 */
			said_next->ref_peer = ref_peer;
		} else if (!outgoing_ref_set) {
			/* on outbound, pick up the SAref if not already done */
			said_next->ref    = ref_peer;
			outgoing_ref_set  = TRUE;
		}

		if (!kernel_ops->add_sa(said_next, replace)) {
			libreswan_log("add_sa ipcomp failed");
			goto fail;
		}

		/*
		 * SA refs will have been allocated for this SA.
		 * The inner most one is interesting for the outgoing SA,
		 * since we refer to it in the policy that we instantiate.
		 */
		if (new_ref_peer == IPSEC_SAREF_NULL && !inbound) {
			new_ref_peer = said_next->ref;
			if (kernel_ops->type != USE_XFRM && new_ref_peer == IPSEC_SAREF_NULL)
				new_ref_peer = IPSEC_SAREF_NA;
		}
		if (!incoming_ref_set && inbound) {
			st->st_ref = said_next->ref;
			incoming_ref_set = TRUE;
		}
		said_next++;

		encap_oneshot = ENCAPSULATION_MODE_TRANSPORT;
	}

	/* set up ESP SA, if any */

	if (st->st_esp.present) {
		ipsec_spi_t esp_spi =
			inbound ? st->st_esp.our_spi : st->st_esp.attrs.spi;
		u_char *esp_dst_keymat =
			inbound ? st->st_esp.our_keymat : st->st_esp.
			peer_keymat;
		const struct trans_attrs *ta = &st->st_esp.attrs.transattrs;

		const struct ip_encap *encap_type = NULL;
		uint16_t encap_sport = 0, encap_dport = 0;
		ip_address natt_oa;

		if (st->hidden_variables.st_nat_traversal & NAT_T_DETECTED ||
		    st->st_interface->protocol == &ip_protocol_tcp) {
			encap_type = st->st_interface->protocol->encap_esp;
			if (inbound) {
				encap_sport = endpoint_hport(&st->st_remote_endpoint);
				encap_dport = endpoint_hport(&st->st_interface->local_endpoint);
			} else {
				encap_sport = endpoint_hport(&st->st_interface->local_endpoint);
				encap_dport = endpoint_hport(&st->st_remote_endpoint);
			}
			natt_oa = st->hidden_variables.st_nat_oa;
			dbg("natt/tcp sa encap_type="PRI_IP_ENCAP" sport=%d dport=%d",
			    pri_ip_encap(encap_type), encap_sport, encap_dport);
		}

		dbg("looking for alg with encrypt: %s keylen: %d integ: %s",
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
			loglog(RC_LOG_SERIOUS,
			       "ESP integrity algorithm %s is not implemented or allowed",
			       ta->ta_integ->common.fqn);
			goto fail;
		}
		if (!kernel_alg_encrypt_ok(ta->ta_encrypt)) {
			loglog(RC_LOG_SERIOUS,
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
			loglog(RC_LOG_SERIOUS,
			       "ESP encryption algorithm %s with key length %d not implemented or allowed",
			       ta->ta_encrypt->common.fqn, ta->enckeylen);
			goto fail;
		}

		/* Fixup key lengths for special cases */
#ifdef USE_3DES
		if (ta->ta_encrypt == &ike_alg_encrypt_3des_cbc) {
			/* Grrrrr.... f*cking 7 bits jurassic algos  */
			/* 168 bits in kernel, need 192 bits for keymat_len */
			if (encrypt_keymat_size == 21) {
				dbg("%s requires a 7-bit jurassic adjust",
				    ta->ta_encrypt->common.fqn);
				encrypt_keymat_size = 24;
			}
		}
#endif

		if (ta->ta_encrypt->salt_size > 0) {
			dbg("%s requires %zu salt bytes",
			    ta->ta_encrypt->common.fqn, ta->ta_encrypt->salt_size);
			encrypt_keymat_size += ta->ta_encrypt->salt_size;
		}

		size_t integ_keymat_size = ta->ta_integ->integ_keymat_size; /* BYTES */

		dbg("st->st_esp.keymat_len=%" PRIu16 " is encrypt_keymat_size=%zu + integ_keymat_size=%zu",
		    st->st_esp.keymat_len, encrypt_keymat_size, integ_keymat_size);

		passert(st->st_esp.keymat_len == encrypt_keymat_size + integ_keymat_size);

		set_text_said(text_esp, &dst, esp_spi, &ip_protocol_esp);

		*said_next = said_boilerplate;
		said_next->spi = esp_spi;
		said_next->esatype = ET_ESP;
		said_next->replay_window = c->sa_replay_window;
		dbg("setting IPsec SA replay-window to %d", c->sa_replay_window);

		if (c->xfrmi != NULL)
			said_next->xfrm_if_id = c->xfrmi->if_id;

		if (!inbound && c->sa_tfcpad != 0 && !st->st_seen_no_tfc) {
			dbg("Enabling TFC at %d bytes (up to PMTU)", c->sa_tfcpad);
			said_next->tfcpad = c->sa_tfcpad;
		}

		if (c->policy & POLICY_DECAP_DSCP) {
			dbg("Enabling Decap ToS/DSCP bits");
			said_next->decap_dscp = TRUE;
		}
		if (c->policy & POLICY_NOPMTUDISC) {
			dbg("Disabling Path MTU Discovery");
			said_next->nopmtudisc = TRUE;
		}

		said_next->integ = ta->ta_integ;
#ifdef USE_SHA2
		if (said_next->integ == &ike_alg_integ_sha2_256 &&
			LIN(POLICY_SHA2_TRUNCBUG, c->policy)) {
			if (kernel_ops->sha2_truncbug_support) {
				if (libreswan_fipsmode() == 1) {
					loglog(RC_LOG_SERIOUS,
						"Error: sha2-truncbug=yes is not allowed in FIPS mode");
					goto fail;
				}
				dbg(" authalg converted for sha2 truncation at 96bits instead of IETF's mandated 128bits");
				/*
				 * We need to tell the kernel to mangle
				 * the sha2_256, as instructed by the user
				 */
				said_next->integ = &ike_alg_integ_hmac_sha2_256_truncbug;
			} else {
				loglog(RC_LOG_SERIOUS,
					"Error: %s stack does not support sha2_truncbug=yes",
					kernel_ops->kern_name);
				goto fail;
			}
		}
#endif
		said_next->authalg = said_next->integ->integ_ikev1_ah_transform;

		if (st->st_esp.attrs.transattrs.esn_enabled) {
			dbg("Enabling ESN");
			said_next->esn = TRUE;
		}

		/*
		 * XXX: Assume SADB_ and ESP_ numbers match!  Clearly
		 * setting .compalg is wrong, don't yet trust
		 * lower-level code to be right.
		 */
		said_next->encrypt = ta->ta_encrypt;
		said_next->compalg = said_next->encrypt->common.id[IKEv1_ESP_ID];

		/* divide up keying material */
		said_next->enckey = esp_dst_keymat;
		said_next->enckeylen = encrypt_keymat_size; /* BYTES */
		said_next->authkey = esp_dst_keymat + encrypt_keymat_size;
		said_next->authkeylen = integ_keymat_size; /* BYTES */

		said_next->mode = encap_oneshot;
		said_next->reqid = reqid_esp(c->spd.reqid);

		said_next->src.encap_port = encap_sport;
		said_next->dst.encap_port = encap_dport;
		said_next->encap_type = encap_type;
		said_next->natt_oa = &natt_oa;
		said_next->text_said = text_esp;

		DBG(DBG_PRIVATE, {
			DBG_dump("ESP enckey:",  said_next->enckey,
				said_next->enckeylen);
			DBG_dump("ESP authkey:", said_next->authkey,
				said_next->authkeylen);
		});

		if (inbound) {
			/*
			 * set corresponding outbound SA. We can do this on
			 * each SA in the bundle without harm.
			 */
			said_next->ref_peer = ref_peer;
		} else if (!outgoing_ref_set) {
			/* on outbound, pick up the SAref if not already done */
			said_next->ref = ref_peer;
			outgoing_ref_set = TRUE;
		}
		setup_esp_nic_offload(said_next, c, &nic_offload_fallback);

		bool ret = kernel_ops->add_sa(said_next, replace);

		if (!ret && nic_offload_fallback &&
			said_next->nic_offload_dev != NULL) {
			/* Fallback to non-nic-offload crypto */
			said_next->nic_offload_dev = NULL;
			ret = kernel_ops->add_sa(said_next, replace);
		}

		/* scrub keys from memory */
		memset(said_next->enckey, 0, said_next->enckeylen);
		memset(said_next->authkey, 0, said_next->authkeylen);

		if (!ret)
			goto fail;

		/*
		 * SA refs will have been allocated for this SA.
		 * The inner most one is interesting for the outgoing SA,
		 * since we refer to it in the policy that we instantiate.
		 */
		if (new_ref_peer == IPSEC_SAREF_NULL && !inbound) {
			new_ref_peer = said_next->ref;
			if (kernel_ops->type != USE_XFRM && new_ref_peer == IPSEC_SAREF_NULL)
				new_ref_peer = IPSEC_SAREF_NA;
		}
		if (!incoming_ref_set && inbound) {
			st->st_ref = said_next->ref;
			incoming_ref_set = TRUE;
		}
		said_next++;

		encap_oneshot = ENCAPSULATION_MODE_TRANSPORT;
	}

	/* set up AH SA, if any */

	if (st->st_ah.present) {
		ipsec_spi_t ah_spi =
			inbound ? st->st_ah.our_spi : st->st_ah.attrs.spi;
		u_char *ah_dst_keymat =
			inbound ? st->st_ah.our_keymat : st->st_ah.peer_keymat;

		const struct integ_desc *integ = st->st_ah.attrs.transattrs.ta_integ;
		size_t keymat_size = integ->integ_keymat_size;
		int authalg = integ->integ_ikev1_ah_transform;
		if (authalg <= 0) {
			loglog(RC_LOG_SERIOUS, "%s not implemented",
			       integ->common.fqn);
			goto fail;
		}

		passert(st->st_ah.keymat_len == keymat_size);

		set_text_said(text_ah, &dst, ah_spi, &ip_protocol_ah);

		*said_next = said_boilerplate;
		said_next->spi = ah_spi;
		said_next->esatype = ET_AH;
		said_next->integ = integ;
		said_next->authalg = authalg;
		said_next->authkeylen = st->st_ah.keymat_len;
		said_next->authkey = ah_dst_keymat;
		said_next->mode = encap_oneshot;
		said_next->reqid = reqid_ah(c->spd.reqid);
		said_next->text_said = text_ah;
		said_next->replay_window = c->sa_replay_window;
		dbg("setting IPsec SA replay-window to %d", c->sa_replay_window);

		if (st->st_ah.attrs.transattrs.esn_enabled) {
			dbg("Enabling ESN");
			said_next->esn = TRUE;
		}

		DBG(DBG_PRIVATE, {
			DBG_dump("AH authkey:", said_next->authkey,
				said_next->authkeylen);
			});

		if (inbound) {
			/*
			 * set corresponding outbound SA. We can do this on
			 * each SA in the bundle without harm.
			 */
			said_next->ref_peer = ref_peer;
		} else if (!outgoing_ref_set) {
			/* on outbound, pick up the SAref if not already done */
			said_next->ref = ref_peer;
			outgoing_ref_set = TRUE;	/* outgoing_ref_set not subsequently used */
		}

		if (!kernel_ops->add_sa(said_next, replace)) {
			/* scrub key from memory */
			memset(said_next->authkey, 0, said_next->authkeylen);
			goto fail;
		}
		/* scrub key from memory */
		memset(said_next->authkey, 0, said_next->authkeylen);

		/*
		 * SA refs will have been allocated for this SA.
		 * The inner most one is interesting for the outgoing SA,
		 * since we refer to it in the policy that we instantiate.
		 */
		if (new_ref_peer == IPSEC_SAREF_NULL && !inbound) {
			new_ref_peer = said_next->ref;
			if (kernel_ops->type != USE_XFRM && new_ref_peer == IPSEC_SAREF_NULL)
				new_ref_peer = IPSEC_SAREF_NA;
		}
		if (!incoming_ref_set && inbound) {
			st->st_ref = said_next->ref;
			incoming_ref_set = TRUE;	/* incoming_ref_set not subsequently used */
		}
		said_next++;

		encap_oneshot = ENCAPSULATION_MODE_TRANSPORT;	/* encap_oneshot not subsequently used */
	}

	/*
	 * Add an inbound eroute to enforce an arrival check.
	 *
	 * If inbound,
	 * ??? and some more mysterious conditions,
	 * Note reversed ends.
	 * Not much to be done on failure.
	 */
	dbg("%s() is installing inbound eroute? inbound=%d owner=#%lu mode=%d",
	    __func__, inbound, c->spd.eroute_owner, mode);
	if (inbound && c->spd.eroute_owner == SOS_NOBODY) {
		dbg("%s() is installing inbound eroute", __func__);
		struct pfkey_proto_info proto_info[4];
		int i = 0;

		/*
		 * ??? why does this code care about
		 * st->st_*.attrs.mode?
		 * We have gone do some trouble to compute
		 * "mode".  And later code uses
		 * "mode".
		 */
		if (st->st_ipcomp.present) {
			proto_info[i].proto = ip_protocol_comp.ipproto;
			proto_info[i].mode =
				st->st_ipcomp.attrs.mode;
			proto_info[i].reqid = reqid_ipcomp(c->spd.reqid);
			i++;
		}

		if (st->st_esp.present) {
			proto_info[i].proto = IPPROTO_ESP;
			proto_info[i].mode =
				st->st_esp.attrs.mode;
			proto_info[i].reqid = reqid_esp(c->spd.reqid);
			i++;
		}

		if (st->st_ah.present) {
			proto_info[i].proto = IPPROTO_AH;
			proto_info[i].mode =
				st->st_ah.attrs.mode;
			proto_info[i].reqid = reqid_ah(c->spd.reqid);
			i++;
		}

		dbg("%s() before proto %d", __func__, proto_info[0].proto);
		proto_info[i].proto = 0;

		/*
		 * ??? why is mode overwritten ONLY if true
		 * (kernel_ops->inbound_eroute)?
		 */
		if (mode == ENCAPSULATION_MODE_TUNNEL) {
			proto_info[0].mode =
				ENCAPSULATION_MODE_TUNNEL;
			for (i = 1; proto_info[i].proto; i++)
				proto_info[i].mode =
					ENCAPSULATION_MODE_TRANSPORT;
		}
		dbg("%s() after proto %d", __func__, proto_info[0].proto);

		uint32_t xfrm_if_id = c->xfrmi != NULL ?
			c->xfrmi->if_id : 0;

		dbg("%s() calling raw_eroute backwards (i.e., inbound)", __func__);
		/* MCR - should be passed a spd_eroute structure here */
		/* note: this and that are intentionally reversed */
		if (!raw_eroute(&c->spd.that.host_addr,		/* this_host */
				&c->spd.that.client,	/* this_client */
				&c->spd.this.host_addr,	/* that_host */
				&c->spd.this.client,	/* that_client */
				inner_spi,		/* current spi - might not be used? */
				inner_spi,		/* new spi */
				proto,			/* SA proto */
				c->spd.this.protocol,	/* transport_proto */
				esatype,		/* esatype */
				proto_info,		/* " */
				deltatime(0),		/* lifetime */
				calculate_sa_prio(c, FALSE),	/* priority */
				&c->sa_marks,		/* IPsec SA marks */
				xfrm_if_id,
				ERO_ADD_INBOUND,	/* op */
				"add inbound",		/* opname */
				st->st_connection->policy_label))
		{
			libreswan_log("raw_eroute() in setup_half_ipsec_sa() failed to add inbound");
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
			dbg("grouping %s (ref=%u) and %s (ref=%u)",
			    s[0].text_said, s[0].ref,
			    s[1].text_said, s[1].ref);
			if (!kernel_ops->grp_sa(s + 1, s)) {
				libreswan_log("grp_sa failed");
				goto fail;
			}
		}
		/* could update said, but it will not be used */
	}

	if (new_ref_peer != IPSEC_SAREF_NULL)
		st->st_ref_peer = new_ref_peer;

	/* if the impaired is set, pretend this fails */
	if (impair.sa_creation) {
		DBG_log("Impair SA creation is set, pretending to fail");
		goto fail;
	}
	return TRUE;

fail:
	{
		libreswan_log("setup_half_ipsec_sa() hit fail:");
		/* undo the done SPIs */
		while (said_next-- != said) {
			if (said_next->proto != 0) {
				(void) del_spi(said_next->spi,
					said_next->proto,
					&src, said_next->dst.address);
			}
		}
		return FALSE;
	}
}

static bool teardown_half_ipsec_sa(struct state *st, bool inbound)
{
	/* Delete any AH, ESP, and IP in IP SPIs. */

	struct connection *const c = st->st_connection;

	/*
	 * If we have a new address in c->spd.that.host_addr,
	 * we are the initiator, have been redirected,
	 * and yet this routine must use the old address.
	 *
	 * We point effective_that_host_address to the appropriate address.
	 */

	const ip_address *effective_that_host_addr = &c->spd.that.host_addr;

	if (!sameaddr(&st->st_remote_endpoint, effective_that_host_addr) &&
	    address_is_specified(&c->temp_vars.redirect_ip)) {
		effective_that_host_addr = &st->st_remote_endpoint;
	}

	/* ??? CLANG 3.5 thinks that c might be NULL */
	if (inbound && c->spd.eroute_owner == SOS_NOBODY &&
	    !raw_eroute(effective_that_host_addr,
			&c->spd.that.client,
			&c->spd.this.host_addr,
			&c->spd.this.client,
			SPI_PASS, SPI_PASS,
			c->ipsec_mode == ENCAPSULATION_MODE_TRANSPORT ?
				&ip_protocol_esp : NULL,
			c->spd.this.protocol,
			c->ipsec_mode == ENCAPSULATION_MODE_TRANSPORT ?
				ET_ESP : ET_UNSPEC,
			null_proto_info,
			deltatime(0),
			calculate_sa_prio(c, FALSE),
			&c->sa_marks,
			0, /* xfrm_if_id. needed to tear down? */
			ERO_DEL_INBOUND,
			"delete inbound",
			c->policy_label))
	{
		libreswan_log("raw_eroute in teardown_half_ipsec_sa() failed to delete inbound");
	}

	/* collect each proto SA that needs deleting */

	struct {
		const struct ip_protocol *proto;
		const struct ipsec_proto_info *info;
	} protos[4];	/* at most 3 entries + terminator */
	int i = 0;

	if (st->st_ah.present) {
		protos[i].proto = &ip_protocol_ah;
		protos[i].info = &st->st_ah;
		i++;
	}

	if (st->st_esp.present) {
		protos[i].proto = &ip_protocol_esp;
		protos[i].info = &st->st_esp;
		i++;
	}

	if (st->st_ipcomp.present) {
		protos[i].proto = &ip_protocol_comp;
		protos[i].info = &st->st_ipcomp;
		i++;
	}

	/*
	 * If the SAs have been grouped, deleting any one will do:
	 * we just delete the first one found (protos[0]).
	 */
	if (kernel_ops->grp_sa != NULL && i > 0)
		i = 1;

	protos[i].proto = NULL;

	/* delete each proto that needs deleting */
	bool result = TRUE;

	for (i = 0; protos[i].proto != NULL; i++) {
		const struct ip_protocol *proto = protos[i].proto;
		ipsec_spi_t spi;
		const ip_address *src, *dst;

		if (inbound) {
			spi = protos[i].info->our_spi;
			src = effective_that_host_addr;
			dst = &c->spd.this.host_addr;
		} else {
			spi = protos[i].info->attrs.spi;
			src = &c->spd.this.host_addr;
			dst = effective_that_host_addr;
		}

		result &= del_spi(spi, proto, src, dst);
	}

	return result;
}

static event_callback_routine kernel_process_msg_cb;

static void kernel_process_msg_cb(evutil_socket_t fd,
		const short event UNUSED, void *arg)
{
	const struct kernel_ops *kernel_ops = arg;

	dbg(" %s process netlink message", __func__);
	threadtime_t start = threadtime_start();
	kernel_ops->process_msg(fd);
	threadtime_stop(&start, SOS_NOBODY, "kernel message");
	pexpect_reset_globals();
}

static global_timer_cb kernel_process_queue_cb;

static void kernel_process_queue_cb(struct fd *unused_whackfd UNUSED)
{
	if (pexpect(kernel_ops->process_queue != NULL)) {
		kernel_ops->process_queue();
	}
	pexpect_reset_globals();
}

/* keep track of kernel version  */
static char kversion[256];

const struct kernel_ops *kernel_ops =
#ifdef XFRM_SUPPORT
	&xfrm_kernel_ops
#endif
#ifdef BSD_KAME
	&bsdkame_kernel_ops
#endif
	;

deltatime_t bare_shunt_interval = DELTATIME_INIT(SHUNT_SCAN_INTERVAL);

static void kernel_scan_shunts(struct fd *unused_whackfd UNUSED)
{
	kernel_ops->scan_shunts();
}

void init_kernel(void)
{
	struct utsname un;

	/* get kernel version */
	uname(&un);
	jam_str(kversion, sizeof(kversion), un.release);

	switch (kernel_ops->type) {
#if defined(XFRM_SUPPORT)
	case USE_XFRM:
	{
		struct stat buf;
		if (stat("/proc/sys/net/core/xfrm_acq_expires", &buf) != 0) {
			libreswan_log("No XFRM kernel support detected, missing /proc/sys/net/core/xfrm_acq_expires");
			exit_pluto(PLUTO_EXIT_KERNEL_FAIL);
		}
		libreswan_log("Using Linux XFRM/NETKEY IPsec kernel support code on %s",
			      kversion);
		break;
	}
#endif

#if defined(BSD_KAME)
	case USE_BSDKAME:
		libreswan_log("Using BSD/KAME IPsec interface code on %s",
			kversion);
		break;
#endif

	default:
		libreswan_log("FATAL: kernel interface '%s' not available",
			enum_name(&kern_interface_names,
				kernel_ops->type));
		exit_pluto(PLUTO_EXIT_KERNEL_FAIL);
	}

	if (kernel_ops->init != NULL)
		kernel_ops->init();

	/* Add the port bypass polcies */

	if (kernel_ops->v6holes != NULL) {
		if (!kernel_ops->v6holes()) {
			libreswan_log("Could not add the ICMP bypass policies");
			exit_pluto(PLUTO_EXIT_KERNEL_FAIL);
		}
	}

	/* register SA types that we can negotiate */
	if (kernel_ops->pfkey_register != NULL)
		kernel_ops->pfkey_register();

	enable_periodic_timer(EVENT_SHUNT_SCAN, kernel_scan_shunts,
			      bare_shunt_interval);

	dbg("setup kernel fd callback");

	if (kernel_ops->async_fdp != NULL)
		/* Note: kernel_ops is const but pluto_event_add cannot know that */
		add_fd_read_event_handler(*kernel_ops->async_fdp, kernel_process_msg_cb,
				  (void *)kernel_ops, "KERNEL_XRM_FD");

	if (kernel_ops->route_fdp != NULL && *kernel_ops->route_fdp  > NULL_FD) {
		add_fd_read_event_handler(*kernel_ops->route_fdp, kernel_process_msg_cb,
					  (void *)kernel_ops, "KERNEL_ROUTE_FD");
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
			     kernel_ops->kern_name);
	}
}

/*
 * see if the attached connection refers to an older state.
 * if it does, then initiate this state with the appropriate outgoing
 * references, such that we won't break any userland applications
 * that are using the conn with REFINFO.
 */
static void look_for_replacement_state(struct state *st)
{
	struct connection *c = st->st_connection;
	struct state *ost = state_with_serialno(c->newest_ipsec_sa);

	if (DBGP(DBG_BASE)) {
		DBG_log("checking if this is a replacement state");
		DBG_log("  st=%p ost=%p st->serialno=#%lu ost->serialno=#%lu",
			st, ost, st->st_serialno,
			ost == NULL ? 0 : ost->st_serialno);
	}

	if (ost != NULL && ost != st && ost->st_serialno != st->st_serialno) {
		/*
		 * then there is an old state associated, and it is
		 * different then the new one.
		 */
		dbg("keeping ref_peer=%" PRIu32 " during rekey", ost->st_ref_peer);
		st->st_ref_peer = ost->st_ref_peer;
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
			if (sameaddr(&o->spd.that.host_addr,
					&c->spd.that.host_addr) &&
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
				  str_address_sensitive(&o->spd.that.host_addr, &b));
			/*
			 * XXX: Assume this call shouldn't log to
			 * whack(?).  While ST has an attached whack,
			 * the global whack, which this code would
			 * have been using, detached long-ago.
			 */
			release_connection(o, false, null_fd);
		}
	}

	dbg("install_inbound_ipsec_sa() checking if we can route");
	/* check that we will be able to route and eroute */
	switch (could_route(c, st->st_logger)) {
	case route_easy:
	case route_nearconflict:
		dbg("   routing is easy, or has resolvable near-conflict");
		break;

	case route_unnecessary:
		/*
		 * in this situation, we should look and see if there is
		 * a state that our connection references, that we are
		 * in fact replacing.
		 */
		break;

	default:
		return FALSE;
	}

	look_for_replacement_state(st);

	/*
	 * we now have to set up the outgoing SA first, so that
	 * we can refer to it in the incoming SA.
	 */
	if (st->st_ref_peer == IPSEC_SAREF_NULL && !st->st_outbound_done) {
		dbg("installing outgoing SA now as ref_peer=%u", st->st_ref_peer);
		if (!setup_half_ipsec_sa(st, FALSE)) {
			DBG_log("failed to install outgoing SA: %u",
				st->st_ref_peer);
			return FALSE;
		}

		st->st_outbound_done = TRUE;
	}
	dbg("outgoing SA has ref_peer=%u", st->st_ref_peer);

	/* (attempt to) actually set up the SAs */

	return setup_half_ipsec_sa(st, TRUE);
}

/* Install a route and then a prospective shunt eroute or an SA group eroute.
 * Assumption: could_route gave a go-ahead.
 * Any SA Group must have already been created.
 * On failure, steps will be unwound.
 */
bool route_and_eroute(struct connection *c,
		struct spd_route *sr,
		struct state *st)
{
	dbg("route_and_eroute() for proto %d, and source port %d dest port %d",
	    sr->this.protocol, sr->this.port, sr->that.port);
	setportof(htons(sr->this.port), &sr->this.client.addr);
	setportof(htons(sr->that.port), &sr->that.client.addr);

	struct spd_route *esr, *rosr;
	struct connection *ero,
		*ro = route_owner(c, sr, &rosr, &ero, &esr);	/* who, if anyone, owns our eroute? */

	dbg("route_and_eroute with c: %s (next: %s) ero:%s esr:{%p} ro:%s rosr:{%p} and state: #%lu",
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
	struct bare_shunt **bspp = (ero == NULL) ?
		bare_shunt_ptr(&sr->this.client, &sr->that.client, sr->this.protocol) :
		NULL;

	/* install the eroute */

	bool eroute_installed = FALSE;

#ifdef IPSEC_CONNECTION_LIMIT
	bool new_eroute = FALSE;
#endif

	passert(bspp == NULL || ero == NULL);   /* only one non-NULL */

	if (bspp != NULL || ero != NULL) {
		dbg("we are replacing an eroute");
		/* if no state provided, then install a shunt for later */
		if (st == NULL) {
			eroute_installed = shunt_eroute(c, sr,
							RT_ROUTED_PROSPECTIVE,
							ERO_REPLACE,
							"replace");
		} else {
			eroute_installed = sag_eroute(st, sr, ERO_REPLACE,
						"replace");
		}

		/* remember to free bspp if we make it out of here alive */
	} else {
		/* we're adding an eroute */
#ifdef IPSEC_CONNECTION_LIMIT
		if (num_ipsec_eroute == IPSEC_CONNECTION_LIMIT) {
			loglog(RC_LOG_SERIOUS,
				"Maximum number of IPsec connections reached (%d)",
				IPSEC_CONNECTION_LIMIT);
			return FALSE;
		}
		new_eroute = TRUE;
#endif

		/* if no state provided, then install a shunt for later */
		if (st == NULL) {
			eroute_installed = shunt_eroute(c, sr,
							RT_ROUTED_PROSPECTIVE,
							ERO_ADD, "add");
		} else {
			eroute_installed = sag_eroute(st, sr, ERO_ADD, "add");
		}
	}

	/* notify the firewall of a new tunnel */

	bool firewall_notified = FALSE;

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
			do_command(c, sr, "up", st); /* go ahead and notify */
	}

	/* install the route */

	bool route_installed = FALSE;

	dbg("route_and_eroute: firewall_notified: %s",
	    firewall_notified ? "true" : "false");
	if (!firewall_notified) {
		/* we're in trouble -- don't do routing */
	} else if (ro == NULL) {
		/* a new route: no deletion required, but preparation is */
		if (!do_command(c, sr, "prepare", st))
			dbg("prepare command returned an error");
		route_installed = do_command(c, sr, "route", st);
		if (!route_installed)
			dbg("route command returned an error");
	} else if (routed(sr->routing) ||
		routes_agree(ro, c)) {
		route_installed = TRUE; /* nothing to be done */
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
		if (sameaddr(&sr->this.host_nexthop,
				&esr->this.host_nexthop)) {
			if (!do_command(ro, sr, "unroute", st)) {
				dbg("unroute command returned an error");
			}
			route_installed = do_command(c, sr, "route", st);
			if (!route_installed)
				dbg("route command returned an error");
		} else {
			route_installed = do_command(c, sr, "route", st);
			if (!route_installed)
				dbg("route command returned an error");

			if (!do_command(ro, sr, "unroute", st)) {
				dbg("unroute command returned an error");
			}
		}

		/* record unrouting */
		if (route_installed) {
			do {
				dbg("installed route: ro name=%s, rosr->routing=%d", ro->name,
					rosr->routing);
				pexpect(!erouted(rosr->routing)); /* warn for now - requires fixing */
				rosr->routing = RT_UNROUTED;

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
		} else if (ero != NULL && ero != c) {
			/* check if ero is an ancestor of c. */
			struct connection *ero2;

			for (ero2 = c; ero2 != NULL && ero2 != c;
				ero2 = ero2->policy_next)
				;

			if (ero2 == NULL) {
				/*
				 * By elimination, we must be eclipsing ero.
				 * Checked above.
				 */
				if (ero->spd.routing != RT_ROUTED_ECLIPSED) {
					ero->spd.routing = RT_ROUTED_ECLIPSED;
					eclipse_count++;
				}
			}
		}

		if (st == NULL) {
			passert(sr->eroute_owner == SOS_NOBODY);
			sr->routing = RT_ROUTED_PROSPECTIVE;
		} else {
			sr->routing = RT_ROUTED_TUNNEL;
			connection_buf cib;
			dbg("route_and_eroute: instance "PRI_CONNECTION", setting eroute_owner {spd=%p,sr=%p} to #%lu (was #%lu) (newest_ipsec_sa=#%lu)",
			    pri_connection(st->st_connection, &cib),
			    &st->st_connection->spd, sr,
			    st->st_serialno,
			    sr->eroute_owner,
			    st->st_connection->newest_ipsec_sa);
			sr->eroute_owner = st->st_serialno;
			/* clear host shunts that clash with freshly installed route */
			clear_narrow_holds(&sr->this.client, &sr->that.client,
					sr->this.protocol);
		}

#ifdef IPSEC_CONNECTION_LIMIT
		if (new_eroute) {
			num_ipsec_eroute++;
			loglog(RC_COMMENT,
				"%d IPsec connections are currently being managed",
				num_ipsec_eroute);
		}
#endif

		return TRUE;
	} else {
		/* Failure!  Unwind our work. */
		if (firewall_notified && sr->eroute_owner == SOS_NOBODY) {
			if (!do_command(c, sr, "down", st))
				dbg("down command returned an error");
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

				if (!raw_eroute(&bs->said.dst,        /* should be useless */
						&bs->our_client,
						&bs->said.dst,        /* should be useless */
						&bs->peer_client,
						bs->said.spi,         /* unused? network order */
						bs->said.spi,         /* network order */
						&ip_protocol_internal,               /* proto */
						sr->this.protocol,    /* transport_proto */
						ET_INT,
						null_proto_info,
						deltatime(SHUNT_PATIENCE),
						calculate_sa_prio(c, FALSE),
						NULL,
						0,
						ERO_REPLACE,
						"restore",
						NULL)) /* bare shunt are not associated with any connection so no security label */
				{
					libreswan_log("raw_eroute() in route_and_eroute() failed to restore/replace SA");
				}
			} else if (ero != NULL) {
				passert(esr != NULL);
				/* restore ero's former glory */
				if (esr->eroute_owner == SOS_NOBODY) {
					/* note: normal or eclipse case */
					if (!shunt_eroute(ero, esr,
								esr->routing,
								ERO_REPLACE,
								"restore")) {
						libreswan_log("shunt_eroute() in route_and_eroute() failed restore/replace");
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
						state_with_serialno(
							esr->eroute_owner);

					if (ost != NULL) {
						if (!sag_eroute(ost, esr,
							ERO_REPLACE,
							"restore"))
							libreswan_log("sag_eroute() in route_and_eroute() failed restore/replace");
					}
				}
			} else {
				/* there was no previous eroute: delete whatever we installed */
				if (st == NULL) {
					if (!shunt_eroute(c, sr,
								sr->routing,
								ERO_DELETE,
								"delete")) {
						libreswan_log("shunt_eroute() in route_and_eroute() failed in !st case for delete");
					}
				} else {
					if (!sag_eroute(st, sr,
								ERO_DELETE,
								"delete")) {
						libreswan_log("shunt_eroute() in route_and_eroute() failed in st case for delete");
					}
				}
			}
		}

		return FALSE;
	}
}

bool install_ipsec_sa(struct state *st, bool inbound_also)
{
	dbg("install_ipsec_sa() for #%lu: %s", st->st_serialno,
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
		if (!setup_half_ipsec_sa(st, FALSE)) {
			return FALSE;
		}

		dbg("set up outgoing SA, ref=%u/%u", st->st_ref,
		    st->st_ref_peer);
		st->st_outbound_done = TRUE;
	}

	/* now setup inbound SA */
	if (st->st_ref == IPSEC_SAREF_NULL && inbound_also) {
		if (!setup_half_ipsec_sa(st, TRUE))
			return FALSE;

		dbg("set up incoming SA, ref=%u/%u", st->st_ref,
		    st->st_ref_peer);

		/*
		 * We successfully installed an IPsec SA, meaning it is safe
		 * to clear our revival back-off delay. This is based on the
		 * assumption that an unwilling partner might complete an IKE
		 * SA to us, but won't complete an IPsec SA to us.
		 */
		st->st_connection->temp_vars.revive_delay = 0;
	}

	if (rb == route_unnecessary)
		return TRUE;

	struct spd_route *sr = &st->st_connection->spd;

	if (st->st_connection->remotepeertype == CISCO && sr->spd_next != NULL)
		sr = sr->spd_next;

	/* for (sr = &st->st_connection->spd; sr != NULL; sr = sr->next) */
	for (; sr != NULL; sr = sr->spd_next) {
		dbg("sr for #%lu: %s", st->st_serialno,
		    enum_name(&routing_story, sr->routing));

		/*
		 * if the eroute owner is not us, then make it us.
		 * See test co-terminal-02, pluto-rekey-01,
		 * pluto-unit-02/oppo-twice
		 */
		pexpect(sr->eroute_owner == SOS_NOBODY ||
			sr->routing >= RT_ROUTED_TUNNEL);

		if (sr->eroute_owner != st->st_serialno &&
			sr->routing != RT_UNROUTED_KEYED) {
			if (!route_and_eroute(st->st_connection, sr, st)) {
				delete_ipsec_sa(st);
				/*
				 * XXX go and unroute any SRs that were
				 * successfully routed already.
				 */
				return false;
			}
		}
	}

	/* XXX why is this needed? Skip the bogus original conn? */
	if (st->st_connection->remotepeertype == CISCO) {
		struct spd_route *srcisco = st->st_connection->spd.spd_next;

		if (srcisco != NULL) {
			st->st_connection->spd.eroute_owner = srcisco->eroute_owner;
			st->st_connection->spd.routing = srcisco->routing;
		}
	}

	if (inbound_also)
		linux_audit_conn(st, LAK_CHILD_START);
	return true;
}

bool migrate_ipsec_sa(struct state *st)
{
	switch (kernel_ops->type) {
	case USE_XFRM:
		/* support ah? if(!st->st_esp.present && !st->st_ah.present)) */
		if (!st->st_esp.present) {
			libreswan_log("mobike SA migration only support ESP SA");
			return FALSE;
		}

		if (!kernel_ops->migrate_sa(st))
			return FALSE;

		return TRUE;

	default:
		dbg("Usupported kernel stack in migrate_ipsec_sa");
		return FALSE;
	}
}

/*
 * Delete an IPSEC SA.
 * we may not succeed, but we bull ahead anyway because
 * we cannot do anything better by recognizing failure
 * This used to have a parameter bool inbound_only, but
 * the saref code changed to always install inbound before
 * outbound so this it was always false, and thus removed
 *
 */
void delete_ipsec_sa(struct state *st)
{
	/* XXX in IKEv2 we get a spurious call with a parent st :( */
	if (IS_CHILD_SA(st)) {
		if (st->st_esp.present || st->st_ah.present) {
			/* ESP or AH means this was an established IPsec SA */
			linux_audit_conn(st, LAK_CHILD_DESTROY);
		}
	} else {
		libreswan_log("delete_ipsec_sa() called with (wrong?) parent state %s",
				st->st_state->name);
	}

	switch (kernel_ops->type) {
	case USE_XFRM:
		{
			/*
			 * If the state is the eroute owner, we must adjust
			 * the routing for the connection.
			 */
			struct connection *c = st->st_connection;
			struct spd_route *sr;

			for (sr = &c->spd; sr; sr = sr->spd_next) {
				if (sr->eroute_owner == st->st_serialno &&
					sr->routing == RT_ROUTED_TUNNEL) {
					sr->eroute_owner = SOS_NOBODY;

					/*
					 * Routing should become
					 * RT_ROUTED_FAILURE,
					 * but if POLICY_FAIL_NONE, then we
					 * just go right back to
					 * RT_ROUTED_PROSPECTIVE as if no
					 * failure happened.
					 */
					sr->routing =
						(c->policy &
							POLICY_FAIL_MASK) ==
						POLICY_FAIL_NONE ?
						RT_ROUTED_PROSPECTIVE :
						RT_ROUTED_FAILURE;

					if (sr == &c->spd &&
						c->remotepeertype == CISCO)
						continue;

					(void) do_command(c, sr, "down", st);
					if ((c->policy & POLICY_OPPORTUNISTIC) &&
							c->kind == CK_INSTANCE) {
						/*
						 * in this case we get rid of
						 * the IPSEC SA
						 */
						unroute_connection(c);
					} else if ((c->policy & POLICY_DONT_REKEY) &&
						c->kind == CK_INSTANCE) {
						/*
						 * in this special case,
						 * even if the connection
						 * is still alive (due to
						 * an ISAKMP SA),
						 * we get rid of routing.
						 * Even though there is still
						 * an eroute, the c->routing
						 * setting will convince
						 * unroute_connection to
						 * delete it.
						 * unroute_connection
						 * would be upset
						 * if c->routing ==
						 * RT_ROUTED_TUNNEL
						 */
						unroute_connection(c);
					} else {
						if (!shunt_eroute(c, sr,
									sr->routing,
									ERO_REPLACE,
									"replace with shunt")) {
							libreswan_log("shunt_eroute() failed replace with shunt in delete_ipsec_sa()");
						}
					}
				}
			}
			(void) teardown_half_ipsec_sa(st, FALSE);
		}
		(void) teardown_half_ipsec_sa(st, TRUE);

		break;
	default:
		dbg("unknown kernel stack in delete_ipsec_sa");
		break;
	} /* switch kernel_ops->type */
}

bool was_eroute_idle(struct state *st, deltatime_t since_when)
{
	if (kernel_ops->eroute_idle != NULL)
		return kernel_ops->eroute_idle(st, since_when);

	/* it is never idle if we can't check */
	return FALSE;
}

/*
 * get information about a given sa - needs merging with was_eroute_idle
 *
 * Note: this mutates *st.
 */
bool get_sa_info(struct state *st, bool inbound, deltatime_t *ago /* OUTPUT */)
{
	struct connection *const c = st->st_connection;

	if (kernel_ops->get_sa == NULL || (!st->st_esp.present && !st->st_ah.present)) {
		return FALSE;
	}

	const struct ip_protocol *proto;
	struct ipsec_proto_info *p2;

	if (st->st_esp.present) {
		proto = &ip_protocol_esp;
		p2 = &st->st_esp;
	} else if (st->st_ah.present) {
		proto = &ip_protocol_ah;
		p2 = &st->st_ah;
	} else {
		return FALSE;
	}

	const ip_address *src, *dst;
	ipsec_spi_t spi;
	bool redirected = FALSE;
	ip_address tmp_ip;

	/*
	 * if we were redirected (using the REDIRECT
	 * mechanism), change
	 * spd.that.host_addr temporarily, we reset
	 * it back later
	 */
	if (!sameaddr(&st->st_remote_endpoint, &c->spd.that.host_addr) &&
	    address_is_specified(&c->temp_vars.redirect_ip)) {
		redirected = TRUE;
		tmp_ip = c->spd.that.host_addr;
		tmp_ip.version = c->spd.that.host_addr.version;
		tmp_ip.hport = c->spd.that.host_addr.hport;
		c->spd.that.host_addr = st->st_remote_endpoint;
	}

	if (inbound) {
		src = &c->spd.that.host_addr;
		dst = &c->spd.this.host_addr;
		spi = p2->our_spi;
	} else {
		src = &c->spd.this.host_addr;
		dst = &c->spd.that.host_addr;
		spi = p2->attrs.spi;
	}

	char text_said[SATOT_BUF];

	set_text_said(text_said, dst, spi, proto);

	struct kernel_sa sa = {
		.spi = spi,
		.proto = proto,
		.src.address = src,
		.dst.address = dst,
		.text_said = text_said,
	};

	dbg("get_sa_info %s", text_said);

	uint64_t bytes;
	uint64_t add_time;

	if (!kernel_ops->get_sa(&sa, &bytes, &add_time))
		return FALSE;

	p2->add_time = add_time;

	/* field has been set? */
	passert(!is_monotime_epoch(p2->our_lastused));
	passert(!is_monotime_epoch(p2->peer_lastused));

	if (inbound) {
		if (bytes > p2->our_bytes) {
			p2->our_bytes = bytes;
			p2->our_lastused = mononow();
		}
		if (ago != NULL)
			*ago = monotimediff(mononow(), p2->our_lastused);
	} else {
		if (bytes > p2->peer_bytes) {
			p2->peer_bytes = bytes;
			p2->peer_lastused = mononow();
		}
		if (ago != NULL)
			*ago = monotimediff(mononow(), p2->peer_lastused);
	}

	if (redirected)
		c->spd.that.host_addr = tmp_ip;

	return TRUE;
}

bool orphan_holdpass(const struct connection *c, struct spd_route *sr,
		int transport_proto, ipsec_spi_t failure_shunt)
{
	enum routing_t ro = sr->routing,        /* routing, old */
			rn = ro;                 /* routing, new */
	ipsec_spi_t negotiation_shunt = (c->policy & POLICY_NEGO_PASS) ? SPI_PASS : SPI_DROP;

	if (negotiation_shunt != failure_shunt ) {
		dbg("failureshunt != negotiationshunt, needs replacing");
	} else {
		dbg("failureshunt == negotiationshunt, no replace needed");
	}

	dbg("orphan_holdpass() called for %s with transport_proto '%d' and sport %d and dport %d",
	    c->name, transport_proto, sr->this.port, sr->that.port);

	passert(LHAS(LELEM(CK_PERMANENT) | LELEM(CK_INSTANCE) |
				LELEM(CK_GOING_AWAY), c->kind));

	switch (ro) {
	case RT_UNROUTED_HOLD:
		rn = RT_UNROUTED;
		dbg("orphan_holdpass unrouted: hold -> pass");
		break;
	case RT_UNROUTED:
		rn = RT_UNROUTED_HOLD;
		dbg("orphan_holdpass unrouted: pass -> hold");
		break;
	case RT_ROUTED_HOLD:
		rn = RT_ROUTED_PROSPECTIVE;
		dbg("orphan_holdpass routed: hold -> trap (?)");
		break;
	default:
		dbg("no routing change needed for ro=%s - negotiation shunt matched failure shunt?",
		    enum_name(&routing_story, ro));
		break;
	}

	dbg("orphaning holdpass for connection '%s', routing was %s, needs to be %s",
	    c->name,
	    enum_name(&routing_story, ro),
	    enum_name(&routing_story, rn));

	{
		/* are we replacing a bare shunt ? */
		setportof(htons(sr->this.port), &sr->this.client.addr);
		setportof(htons(sr->that.port), &sr->that.client.addr);
		struct bare_shunt **old = bare_shunt_ptr(&sr->this.client, &sr->that.client, sr->this.protocol);

		if (old != NULL) {
			free_bare_shunt(old);
		}
	}

	/* create the bare shunt and update kernel policy if needed */
	{
		struct bare_shunt *bs = alloc_thing(struct bare_shunt, "orphan shunt");

		bs->why = "oe-failing";
		bs->our_client = sr->this.client;
		bs->peer_client = sr->that.client;
		bs->transport_proto = sr->this.protocol;
		bs->policy_prio = BOTTOM_PRIO;

		bs->said = said3(&subnet_type(&sr->this.client)->any_address,
				 htonl(negotiation_shunt), &ip_protocol_internal);

		bs->count = 0;
		bs->last_activity = mononow();
		if (strstr(c->name, "/32") != NULL || strstr(c->name, "/128") != NULL) {
			bs->from_cn = clone_str(c->name, "conn name in bare shunt");
		}

		bs->next = bare_shunts;
		bare_shunts = bs;
		dbg_bare_shunt("add", bs);

		/* update kernel policy if needed */
		/* This really causes the name to remain "oe-failing", we should be able to update only only the name of the shunt */
		if (negotiation_shunt != failure_shunt ) {
			dbg("replacing negotiation_shunt with failure_shunt");
			if (!replace_bare_shunt(&sr->this.host_addr, &sr->that.host_addr, bs->policy_prio,
						negotiation_shunt, failure_shunt, bs->transport_proto,
						"oe-failed")) {
				libreswan_log("assign_holdpass() failed to update shunt policy");
			}
		} else {
			dbg("No need to replace negotiation_shunt with failure_shunt - they are the same");
		}
	}

	/* change routing so we don't get cleared out when state/connection dies */
	sr->routing = rn;
	dbg("orphan_holdpas() done - returning success");
	return TRUE;
}

/* XXX move to proper kernel_ops in kernel_netlink */
void expire_bare_shunts(void)
{
	dbg("checking for aged bare shunts from shunt table to expire");
	for (struct bare_shunt **bspp = &bare_shunts; *bspp != NULL; ) {
		struct bare_shunt *bsp = *bspp;
		time_t age = deltasecs(monotimediff(mononow(), bsp->last_activity));
		struct connection *c = NULL;

		if (age > deltasecs(pluto_shunt_lifetime)) {
			dbg_bare_shunt("expiring old", bsp);
			if (bsp->from_cn != NULL) {
				c = conn_by_name(bsp->from_cn, FALSE);
				if (c != NULL) {
					if (!shunt_eroute(c, &c->spd, RT_ROUTED_PROSPECTIVE, ERO_ADD, "add")) {
						libreswan_log("trap shunt install failed ");
					}
				}
			}
			if (!delete_bare_shunt(&bsp->our_client.addr, &bsp->peer_client.addr,
					       bsp->transport_proto,
					       ntohl(bsp->said.spi),
					       (bsp->from_cn == NULL ? "expire_bare_shunt" :
						"IGNORE_ON_XFRM: expire_bare_shunt"))) {
				    log_global(RC_LOG_SERIOUS, null_fd, "failed to delete bare shunt");
			}
			passert(bsp != *bspp);
		} else {
			dbg_bare_shunt("keeping recent", bsp);
			bspp = &bsp->next;
		}
	}
}
