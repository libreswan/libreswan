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
 * Copyright (C) 2010,2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2015 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2016, Andrew Cagney <cagney@gnu.org>
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
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
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

#include <libreswan.h>

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
#include "kernel_netlink.h"
#include "kernel_pfkey.h"
#include "kernel_noklips.h"
#include "kernel_bsdkame.h"
#include "packet.h"
#include "x509.h"
#include "pluto_x509.h"
#include "certs.h"
#include "secrets.h"
#include "log.h"
#include "server.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "keys.h"

#include "packet.h"  /* for pb_stream in nat_traversal.h */
#include "nat_traversal.h"

#include "lswfips.h" /* for libreswan_fipsmode() */

bool can_do_IPcomp = TRUE;  /* can system actually perform IPCOMP? */

/* test if the routes required for two different connections agree
 * It is assumed that the destination subnets agree; we are only
 * testing that the interfaces and nexthops match.
 */
#define routes_agree(c, d) ((c)->interface->ip_dev == (d)->interface->ip_dev \
			    && sameaddr(&(c)->spd.this.host_nexthop, \
					&(d)->spd.this.host_nexthop))

/* forward declaration */
static void set_text_said(char *text_said,
			  const ip_address *dst,
			  ipsec_spi_t spi,
			  int proto);

const struct pfkey_proto_info null_proto_info[2] = {
	{
		.proto = IPPROTO_ESP,
		.encapsulation = ENCAPSULATION_MODE_TRANSPORT,
		.reqid = 0
	},
	{
		.proto = 0,
		.encapsulation = 0,
		.reqid = 0
	}
};

static struct bare_shunt *bare_shunts = NULL;

#ifdef IPSEC_CONNECTION_LIMIT
static int num_ipsec_eroute = 0;
#endif


static struct event *ev_fd = NULL; /* could these two go in kernel_ops AA_2015 ??? */
static struct event *ev_pq = NULL;

static void DBG_bare_shunt(const char *op, const struct bare_shunt *bs)
{
	DBG(DBG_KERNEL,
	    {
		    int ourport = ntohs(portof(&bs->ours.addr));
		    int hisport = ntohs(portof(&bs->his.addr));
		    char ourst[SUBNETTOT_BUF];
		    char hist[SUBNETTOT_BUF];
		    char sat[SATOT_BUF];
		    char prio[POLICY_PRIO_BUF];

		    subnettot(&bs->ours, 0, ourst, sizeof(ourst));
		    subnettot(&bs->his, 0, hist, sizeof(hist));
		    satot(&bs->said, 0, sat, sizeof(sat));
		    fmt_policy_prio(bs->policy_prio, prio);
		    DBG_log("%s bare shunt %p %s:%d --%d--> %s:%d => %s %s    %s",
			    op, (const void *)bs, ourst, ourport,
			    bs->transport_proto, hist, hisport,
			    sat, prio, bs->why);
	    });
}

/*
 * Note: "why" must be in stable storage (not auto, not heap)
 * because we use it indefinitely without copying or pfreeing.
 * Simple rule: use a string literal.
 */
void add_bare_shunt(const ip_subnet *ours, const ip_subnet *his,
	int transport_proto, ipsec_spi_t shunt_spi,
	const char *why)
{
	struct bare_shunt *bs = alloc_thing(struct bare_shunt,
					    "bare shunt");

	bs->why = why;
	bs->ours = *ours;
	bs->his = *his;
	bs->transport_proto = transport_proto;
	bs->policy_prio = BOTTOM_PRIO;

	bs->said.proto = SA_INT;
	bs->said.spi = htonl(shunt_spi);
	bs->said.dst = *aftoinfo(subnettypeof(ours))->any;

	bs->count = 0;
	bs->last_activity = mononow();

	bs->next = bare_shunts;
	bare_shunts = bs;
	DBG_bare_shunt("add", bs);
}


/*
 * Note: "why" must be in stable storage (not auto, not heap)
 * because we use it indefinitely without copying or pfreeing.
 * Simple rule: use a string literal.
 */
void record_and_initiate_opportunistic(const ip_subnet *ours,
				       const ip_subnet *his,
				       int transport_proto
#ifdef HAVE_LABELED_IPSEC
				       , struct xfrm_user_sec_ctx_ike *uctx
#endif
				       , const char *why)
{
	passert(samesubnettype(ours, his));

	/* Add the kernel shunt to the pluto bare shunt list.
	 * We need to do this because the %hold shunt was installed by kernel
	 * and we want to keep track of it inside pluto.
	 */
	add_bare_shunt(ours, his, transport_proto, SPI_HOLD, why);

	/* actually initiate opportunism / ondemand */
	{
		ip_address src, dst;

		networkof(ours, &src);
		networkof(his, &dst);
		initiate_ondemand(&src, &dst, transport_proto,
				      TRUE, NULL_FD,
#ifdef HAVE_LABELED_IPSEC
				      uctx,
#endif
				      "acquire");
	}

	if (kernel_ops->remove_orphaned_holds != NULL) {
		/* remove from KLIPS's list */
		DBG(DBG_OPPO, DBG_log("record_and_initiate_opportunistic(): tell kernel to remove orphan hold for our bare shunt"));
		(*kernel_ops->remove_orphaned_holds)(transport_proto, ours,
						     his);
	}
}

static reqid_t get_proto_reqid(reqid_t base, int proto)
{
	switch (proto) {
	case IPPROTO_COMP:
		return reqid_ipcomp(base);

	case IPPROTO_ESP:
		return reqid_esp(base);

	case IPPROTO_AH:
		return reqid_ah(base);

	default:
		bad_case(proto);
	}
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
ipsec_spi_t get_ipsec_spi(ipsec_spi_t avoid, int proto, const struct spd_route *sr,
			  bool tunnel)
{
	static ipsec_spi_t spi = 0; /* host order, so not returned directly! */
	char text_said[SATOT_BUF];

	passert(proto == IPPROTO_AH || proto == IPPROTO_ESP);
	set_text_said(text_said, &sr->this.host_addr, 0, proto);

	if (kernel_ops->get_spi != NULL) {
		return kernel_ops->get_spi(&sr->that.host_addr,
					   &sr->this.host_addr, proto, tunnel,
					   get_proto_reqid(sr->reqid, proto),
					   IPSEC_DOI_SPI_OUR_MIN, 0xffffffff,
					   text_said);
	}

	spi++;
	while (spi < IPSEC_DOI_SPI_OUR_MIN || spi == ntohl(avoid))
		get_rnd_bytes((u_char *)&spi, sizeof(spi));

	DBG(DBG_CONTROL,
	    {
		    ipsec_spi_t spi_net = htonl(spi);

		    DBG_dump("generate SPI:", (u_char *)&spi_net,
			     sizeof(spi_net));
	    });

	return htonl(spi);
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
	static cpi_t
		first_busy_cpi = 0,
		latest_cpi;
	char text_said[SATOT_BUF];

	set_text_said(text_said, &sr->this.host_addr, 0, IPPROTO_COMP);

	if (kernel_ops->get_spi != NULL) {
		return kernel_ops->get_spi(&sr->that.host_addr,
					   &sr->this.host_addr, IPPROTO_COMP,
					   tunnel,
					   get_proto_reqid(sr->reqid,
							   IPPROTO_COMP),
					   IPCOMP_FIRST_NEGOTIATED, IPCOMP_LAST_NEGOTIATED,
					   text_said);
	}

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

/* note: this mutates *st by calling get_sa_info */
static void fmt_traffic_str(struct state *st, char *istr, size_t istr_len, char *ostr, size_t ostr_len)
{
	passert(istr_len > 0 && ostr_len > 0);
	istr[0] = '\0';
	ostr[0] = '\0';
	if (st == NULL || IS_IKE_SA(st))
		return;

	if (get_sa_info(st, FALSE, NULL)) { /* our_bytes = out going bytes */
		snprintf(ostr, ostr_len, "PLUTO_OUTBYTES='%u' ",
			 st->st_esp.present ? st->st_esp.peer_bytes :
			 st->st_ah.present ? st->st_ah.peer_bytes :
			 st->st_ipcomp.present ? st->st_ipcomp.peer_bytes :
			 0);
	}
	if (get_sa_info(st, TRUE, NULL)) {
		snprintf(istr, istr_len, "PLUTO_INBYTES='%u' ",
			 st->st_esp.present ? st->st_esp.our_bytes :
			 st->st_ah.present ? st->st_ah.our_bytes :
			 st->st_ipcomp.present ? st->st_ipcomp.our_bytes :
			 0);
	}
}

/*
 * form the command string
 *
 * note: this mutates *st by calling fmt_traffic_str
 */
int fmt_common_shell_out(char *buf, int blen, const struct connection *c,
			 const struct spd_route *sr, struct state *st)
{
#define MAX_DISPLAY_BYTES 13
	int result;
	char
		myid_str2[IDTOA_BUF],
		srcip_str[sizeof("PLUTO_MY_SOURCEIP='' ") + ADDRTOT_BUF],
		myclient_str[SUBNETTOT_BUF],
		myclientnet_str[ADDRTOT_BUF],
		myclientmask_str[ADDRTOT_BUF],
		peerid_str[IDTOA_BUF],
		metric_str[sizeof("PLUTO_METRIC= ") + 4],
		connmtu_str[sizeof("PLUTO_MTU= ") + 4],
		peerclient_str[SUBNETTOT_BUF],
		peerclientnet_str[ADDRTOT_BUF],
		peerclientmask_str[ADDRTOT_BUF],
		secure_myid_str[IDTOA_BUF] = "",
		secure_peerid_str[IDTOA_BUF] = "",
		secure_peerca_str[IDTOA_BUF] = "",
		nexthop_str[sizeof("PLUTO_NEXT_HOP='' ") + ADDRTOT_BUF],
		secure_xauth_username_str[IDTOA_BUF] = "",
		traffic_in_str[sizeof("PLUTO_IN_BYTES='' ") + MAX_DISPLAY_BYTES] = "",
		traffic_out_str[sizeof("PLUTO_OUT_BYTES='' ") + MAX_DISPLAY_BYTES] = "",
		nflogstr[sizeof("NFLOG='' ") + MAX_DISPLAY_BYTES] = "",
		connmarkstr[2 * (sizeof("CONNMARK_XXX='' ") +  2 * sizeof("0xffffffff")+1) + sizeof(", ")] = "",
		catstr[] = "CAT='YES' ";
#undef MAX_DISPLAY_BYTES

	ipstr_buf bme, bpeer;
	ip_address ta;

	nexthop_str[0] = '\0';
	if (addrbytesptr(&sr->this.host_nexthop, NULL) &&
	    !isanyaddr(&sr->this.host_nexthop)) {
		char *n = jam_str(nexthop_str, sizeof(nexthop_str),
				"PLUTO_NEXT_HOP='");

		addrtot(&sr->this.host_nexthop, 0,
			n, sizeof(nexthop_str) - (n - nexthop_str));
		add_str(nexthop_str, sizeof(nexthop_str), n, "' ");
	}

	idtoa(&sr->this.id, myid_str2, sizeof(myid_str2));
	escape_metachar(myid_str2, secure_myid_str, sizeof(secure_myid_str));
	subnettot(&sr->this.client, 0, myclient_str, sizeof(myclientnet_str));
	networkof(&sr->this.client, &ta);
	addrtot(&ta, 0, myclientnet_str, sizeof(myclientnet_str));
	maskof(&sr->this.client, &ta);
	addrtot(&ta, 0, myclientmask_str, sizeof(myclientmask_str));

	idtoa(&sr->that.id, peerid_str, sizeof(peerid_str));
	escape_metachar(peerid_str, secure_peerid_str,
			sizeof(secure_peerid_str));
	subnettot(&sr->that.client, 0, peerclient_str,
		sizeof(peerclientnet_str));
	networkof(&sr->that.client, &ta);
	addrtot(&ta, 0, peerclientnet_str, sizeof(peerclientnet_str));
	maskof(&sr->that.client, &ta);
	addrtot(&ta, 0, peerclientmask_str, sizeof(peerclientmask_str));

	metric_str[0] = '\0';
	if (c->metric != 0)
		snprintf(metric_str, sizeof(metric_str), "PLUTO_METRIC=%d ",
			c->metric);

	connmtu_str[0] = '\0';
	if (c->connmtu != 0)
		snprintf(connmtu_str, sizeof(connmtu_str), "PLUTO_MTU=%d ",
			c->connmtu);

	secure_xauth_username_str[0] = '\0';

	if (st != NULL && st->st_username[0] != '\0') {
		char *p = jam_str(secure_xauth_username_str,
				sizeof(secure_xauth_username_str),
				"PLUTO_USERNAME='");

		remove_metachar(st->st_username,
				p,
				sizeof(secure_xauth_username_str) -
				(p - secure_xauth_username_str) - 2);
		add_str(secure_xauth_username_str,
			sizeof(secure_xauth_username_str), p, "' ");
	}
	fmt_traffic_str(st, traffic_in_str, sizeof(traffic_in_str), traffic_out_str, sizeof(traffic_out_str));

	nflogstr[0] = '\0';
	if (c->nflog_group != 0) {
		snprintf(nflogstr, sizeof(nflogstr), "NFLOG=%d ",
			c->nflog_group);
	}

	if (!sr->this.has_cat)
		catstr[0] = '\0';

	connmarkstr[0] = '\0';
	if (c->sa_marks.in.val != 0) {
		snprintf(connmarkstr, sizeof(connmarkstr), "CONNMARK_IN=%"PRIu32"/%#010x ",
			c->sa_marks.in.val, c->sa_marks.in.mask);
	}
	if (c->sa_marks.out.val != 0) {
		size_t inend = strlen(connmarkstr);
		snprintf(connmarkstr+inend, sizeof(connmarkstr)-inend, "CONNMARK_OUT=%"PRIu32"/%#010x ",
			c->sa_marks.out.val, c->sa_marks.out.mask);
	}

	srcip_str[0] = '\0';
	if (addrbytesptr(&sr->this.host_srcip, NULL) != 0 &&
	    !isanyaddr(&sr->this.host_srcip)) {
		char *p = jam_str(srcip_str, sizeof(srcip_str),
				"PLUTO_MY_SOURCEIP='");

		addrtot(&sr->this.host_srcip, 0, p,
			sizeof(srcip_str) - (p - srcip_str));
		add_str(srcip_str, sizeof(srcip_str), p, "' ");
	}

	{
		struct pubkey_list *p;
		char peerca_str[IDTOA_BUF];

		for (p = pluto_pubkeys; p != NULL; p = p->next) {
			struct pubkey *key = p->key;
			int pathlen;

			if (key->alg == PUBKEY_ALG_RSA &&
			    same_id(&sr->that.id, &key->id) &&
			    trusted_ca_nss(key->issuer, sr->that.ca, &pathlen)) {
				dntoa_or_null(peerca_str, IDTOA_BUF,
					key->issuer, "");
				escape_metachar(peerca_str, secure_peerca_str,
						sizeof(secure_peerca_str));
				break;
			}
		}
	}

	result = snprintf(
		buf, blen,
		/* change VERSION when interface spec changes */
		"PLUTO_VERSION='2.0' "
		"PLUTO_CONNECTION='%s' "
		"PLUTO_INTERFACE='%s' "
		"%s" /* possible PLUTO_NEXT_HOP */
		"PLUTO_ME='%s' "
		"PLUTO_MY_ID='%s' "		/* 5 */
		"PLUTO_MY_CLIENT='%s' "
		"PLUTO_MY_CLIENT_NET='%s' "
		"PLUTO_MY_CLIENT_MASK='%s' "
		"PLUTO_MY_PORT='%u' "
		"PLUTO_MY_PROTOCOL='%u' "	/* 10 */
		"PLUTO_SA_REQID='%u' "
		"PLUTO_SA_TYPE='%s' "
		"PLUTO_PEER='%s' "
		"PLUTO_PEER_ID='%s' "
		"PLUTO_PEER_CLIENT='%s' "	/* 15 */
		"PLUTO_PEER_CLIENT_NET='%s' "
		"PLUTO_PEER_CLIENT_MASK='%s' "
		"PLUTO_PEER_PORT='%u' "
		"PLUTO_PEER_PROTOCOL='%u' "
		"PLUTO_PEER_CA='%s' "		/* 20 */
		"PLUTO_STACK='%s' "
		"%s"		/* optional metric */
		"%s"		/* optional mtu */
		"PLUTO_ADDTIME='%" PRIu64 "' "
		"PLUTO_CONN_POLICY='%s' "	/* 25 */
		"PLUTO_CONN_KIND='%s' "
		"PLUTO_CONN_ADDRFAMILY='ipv%d' "
		"XAUTH_FAILED=%d "
		"%s"		/* XAUTH username - if any */
		"%s"		/* PLUTO_MY_SRCIP - if any */
		"PLUTO_IS_PEER_CISCO='%u' "
		"PLUTO_PEER_DNS_INFO='%s' "
		"PLUTO_PEER_DOMAIN_INFO='%s' "
		"PLUTO_PEER_BANNER='%s' "
#ifdef HAVE_NM
		"PLUTO_NM_CONFIGURED='%u' "
#endif
			"%s" /* traffic in stats - if any */
			"%s" /* traffic out stats - if any */
			"%s" /* nflog-group - if any */
			"%s" /* conn-mark - if any */
			"VTI_IFACE='%s' VTI_ROUTING='%s' VTI_SHARED='%s' "
			"%s" /* CAT=yes if set */
			"SPI_IN=0x%x SPI_OUT=0x%x " /* SPI_IN SPI_OUT */

		, c->name,
		c->interface == NULL ? "NULL" : c->interface->ip_dev->id_vname,
		nexthop_str,
		ipstr(&sr->this.host_addr, &bme),
		secure_myid_str,		/* 5 */
		myclient_str,
		myclientnet_str,
		myclientmask_str,
		sr->this.port,
		sr->this.protocol,		/* 10 */
		sr->reqid,
		(st == NULL ? "none" :
			st->st_esp.present ? "ESP" :
			st->st_ah.present ? "AH" :
			st->st_ipcomp.present ? "IPCOMP" :
			"unknown?"),
		ipstr(&sr->that.host_addr, &bpeer),
		secure_peerid_str,
		peerclient_str,			/* 15 */
		peerclientnet_str,
		peerclientmask_str,
		sr->that.port,
		sr->that.protocol,
		secure_peerca_str,		/* 20 */
		kernel_ops->kern_name,
		metric_str,
		connmtu_str,
		st == NULL ? (u_int64_t)0 : st->st_esp.add_time,
		prettypolicy(c->policy),	/* 25 */
		enum_show(&connection_kind_names, c->kind),
		(c->addr_family == AF_INET) ? 4 : 6,
		(st != NULL && st->st_xauth_soft) ? 1 : 0,
		secure_xauth_username_str,
		srcip_str,
		c->remotepeertype,
		c->cisco_dns_info ? c->cisco_dns_info : "",
		c->modecfg_domain ? c->modecfg_domain : "",
		c->modecfg_banner ? c->modecfg_banner : "",
#ifdef HAVE_NM
		c->nmconfigured,
#endif
		traffic_in_str,
		traffic_out_str,
		nflogstr,
		connmarkstr,
		c->vti_iface ? c->vti_iface : "",
		c->vti_routing ? "yes" : "no",
		c->vti_shared ? "yes" : "no",
		catstr,
		st == NULL ? 0 : st->st_esp.present ? st->st_esp.attrs.spi :
			st->st_ah.present ? st->st_ah.attrs.spi :
			st->st_ipcomp.present ? st->st_ipcomp.attrs.spi : 0,
		st == NULL ? 0 : st->st_esp.present ? st->st_esp.our_spi :
			st->st_ah.present ? st->st_ah.our_spi :
			st->st_ipcomp.present ? st->st_ipcomp.our_spi : 0
		);
	/*
	 * works for both old and new way of snprintf() returning
	 * eiter -1 or the output length  -- by Carsten Schlote
	 */
	return (result >= blen || result < 0) ? -1 : result;
}

bool do_command(const struct connection *c, const struct spd_route *sr, const char *verb,
		struct state *st)
{
	const char *verb_suffix;

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

	DBG(DBG_CONTROL, DBG_log("command executing %s%s",
				 verb, verb_suffix));

	if (kernel_ops->docommand == NULL) {
		DBG(DBG_CONTROL, DBG_log("no do_command for method %s",
					 kernel_ops->kern_name));
	} else {
		return (*kernel_ops->docommand)(c, sr, verb, verb_suffix, st);
	}
	return TRUE;
}

#include <signal.h>
typedef void (*sighandler_t)(int);	/* GNU extension would define this */

bool invoke_command(const char *verb, const char *verb_suffix, const char *cmd)
{
#	define CHUNK_WIDTH	80	/* units for cmd logging */
	DBG(DBG_CONTROL, {
		int slen = strlen(cmd);
		int i;

		DBG_log("executing %s%s: %s",
			 verb, verb_suffix, cmd);
		DBG_log("popen cmd is %d chars long", slen);
		for (i = 0; i < slen; i += CHUNK_WIDTH)
			DBG_log("cmd(%4d):%.*s:", i,
				slen-i < CHUNK_WIDTH? slen-i : CHUNK_WIDTH,
				&cmd[i]);
	});
#	undef CHUNK_WIDTH


	{
		/* invoke the script, catching stderr and stdout
		 * It may be of concern that some file descriptors will
		 * be inherited.  For the ones under our control, we
		 * have done fcntl(fd, F_SETFD, FD_CLOEXEC) to prevent this.
		 * Any used by library routines (perhaps the resolver or syslog)
		 * will remain.
		 */
		sighandler_t savesig = signal(SIGCHLD, SIG_DFL);
		FILE *f = popen(cmd, "r");

		if (f == NULL) {
#ifdef HAVE_BROKEN_POPEN
			/* See bug #1067  Angstrom Linux on a arm7 has no popen() */
			if (errno == ENOSYS) {
				/* Try system(), though it will not give us output */
				DBG_log("unable to popen(), falling back to system()");
				system(cmd);
				return TRUE;
			}
#endif
			loglog(RC_LOG_SERIOUS, "unable to popen %s%s command",
			       verb, verb_suffix);
			signal(SIGCHLD, savesig);
			return FALSE;
		}

		/* log any output */
		for (;; ) {
			/* if response doesn't fit in this buffer, it will be folded */
			char resp[256];

			if (fgets(resp, sizeof(resp), f) == NULL) {
				if (ferror(f)) {
					log_errno((e,
						   "fgets failed on output of %s%s command",
						   verb, verb_suffix));
					signal(SIGCHLD, savesig);
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
			signal(SIGCHLD, savesig);

			if (r == -1) {
				log_errno((e, "pclose failed for %s%s command",
					   verb, verb_suffix));
				return FALSE;
			} else if (WIFEXITED(r)) {
				if (WEXITSTATUS(r) != 0) {
					loglog(RC_LOG_SERIOUS,
					       "%s%s command exited with status %d",
					       verb, verb_suffix, WEXITSTATUS(
						       r));
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

	/* this is a co-terminal attempt of the "near" kind. */
	/* when chaining, we chain from inside to outside */

	/* XXX permit multiple deep connections? */
	passert(inside->policy_next == NULL);

	inside->policy_next = outside;

	/* since we are going to steal the eroute from the secondary
	 * policy, we need to make sure that it no longer thinks that
	 * it owns the eroute.
	 */
	outside->spd.eroute_owner = SOS_NOBODY;
	outside->spd.routing = RT_UNROUTED_KEYED;

	/* set the priority of the new eroute owner to be higher
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
static enum routability could_route(struct connection *c)
{
	DBG(DBG_CONTROL,
	    DBG_log("could_route called for %s (kind=%s)",
		    c->name,
		    enum_show(&connection_kind_names, c->kind)));

	/* it makes no sense to route a connection that is ISAKMP-only */
	if (!NEVER_NEGOTIATE(c->policy) && !HAS_IPSEC_POLICY(c->policy)) {
		loglog(RC_ROUTE, "cannot route an ISAKMP-only connection");
		return route_impossible;
	}

	/*
	 * if this is a transport SA, and overlapping SAs are supported, then
	 * this route is not necessary at all.
	 */
	if (kernel_ops->overlap_supported && !LIN(POLICY_TUNNEL, c->policy))
		return route_unnecessary;

	/* if this is a Road Warrior template, we cannot route.
	 * Opportunistic template is OK.
	 */
	if (!c->spd.that.has_client &&
	    c->kind == CK_TEMPLATE &&
	    !(c->policy & POLICY_OPPORTUNISTIC)) {
		loglog(RC_ROUTE, "cannot route template policy of %s",
		       prettypolicy(c->policy));
		return route_impossible;
	}

#if 0
	/* if we don't know nexthop, we cannot route */
	if (isanyaddr(&c->spd.this.host_nexthop)) {
		loglog(RC_ROUTE,
		       "cannot route connection without knowing our nexthop");
		return route_impossible;
	}
#endif

	/* if routing would affect IKE messages, reject */
	if (kern_interface != NO_KERNEL
	    && c->spd.this.host_port != pluto_nat_port
	    && c->spd.this.host_port != pluto_port &&
	    addrinsubnet(&c->spd.that.host_addr, &c->spd.that.client)) {
		loglog(RC_LOG_SERIOUS,
		       "cannot install route: peer is within its client");
		return route_impossible;
	}

	struct spd_route *esr, *rosr;
	struct connection *ero,		/* who, if anyone, owns our eroute? */
		*ro = route_owner(c, &c->spd, &rosr, &ero, &esr);	/* who owns our route? */

	/* If there is already a route for peer's client subnet
	 * and it disagrees about interface or nexthop, we cannot steal it.
	 * Note: if this connection is already routed (perhaps for another
	 * state object), the route will agree.
	 * This is as it should be -- it will arise during rekeying.
	 */
	if (ro != NULL && !routes_agree(ro, c)) {
		char cib[CONN_INST_BUF];
		loglog(RC_LOG_SERIOUS,
		       "cannot route -- route already in use for \"%s\"%s",
		       ro->name, fmt_conn_instance(ro, cib));
		/* We ignore this if the stack supports overlapping, and this
		 * connection was marked that overlapping is OK.  Below we will
		 * check the other eroute, ero.
		 */
		if (!compatible_overlapping_connections(c, ero)) {
			/*
			 * Another connection is already using the eroute.
			 * TODO: NETKEY can do this?
			 */
			return route_impossible;
		}
	}

	/* if there is an eroute for another connection, there is a problem */
	if (ero != NULL && ero != c) {
		/*
		 * note, wavesec (PERMANENT) goes *outside* and
		 * OE goes *inside* (TEMPLATE)
		 */
		char inst[CONN_INST_BUF];
		struct connection *ep;

		if (ero->kind == CK_PERMANENT &&
		    c->kind == CK_TEMPLATE) {
			return note_nearconflict(ero, c);
		} else if (c->kind == CK_PERMANENT &&
			   ero->kind == CK_TEMPLATE) {
			return note_nearconflict(c, ero);
		}

		/* look along the chain of policies for one with the same name */

		for (ep = ero; ep != NULL; ep = ero->policy_next) {
			if (ep->kind == CK_TEMPLATE &&
			    streq(ep->name, c->name))
				return route_easy;
		}

		/* If we fell off the end of the list, then we found no TEMPLATE
		 * so there must be a conflict that we can't resolve.
		 * As the names are not equal, then we aren't replacing/rekeying.
		 *
		 * ??? should there not be a conflict if ANYTHING in the list,
		 * other than c, conflicts with c?
		 */

		fmt_conn_instance(ero, inst);

		if (LDISJOINT(POLICY_OVERLAPIP, c->policy | ero->policy)) {
			/*
			 * another connection is already using the eroute,
			 * TODO: NETKEY apparently can do this though
			 */
			loglog(RC_LOG_SERIOUS,
			       "cannot install eroute -- it is in use for \"%s\"%s #%lu",
			       ero->name, inst, esr->eroute_owner);
			return route_impossible;
		}

		DBG(DBG_CONTROL,
		    DBG_log("overlapping permitted with \"%s\"%s #%lu",
			    ero->name, inst, esr->eroute_owner));
	}
	return route_easy;
}

bool trap_connection(struct connection *c)
{
	enum routability r = could_route(c);

	switch (r) {
	case route_impossible:
		return FALSE;

	case route_easy:
	case route_nearconflict:
		/* RT_ROUTED_TUNNEL is treated specially: we don't override
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
	DBG(DBG_CONTROL, DBG_log("shunt_eroute() called for connection '%s' to '%s' for rt_kind '%s'",
			c->name, opname, enum_name(&routing_story, rt_kind)));
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

/* delete any eroute for a connection and unroute it if route isn't shared */
void unroute_connection(struct connection *c)
{
	struct spd_route *sr;

	for (sr = &c->spd; sr; sr = sr->spd_next) {
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

#include "alg_info.h"
#include "kernel_alg.h"

static void set_text_said(char *text_said, const ip_address *dst,
			  ipsec_spi_t spi, int sa_proto)
{
	ip_said said;

	initsaid(dst, spi, sa_proto, &said);
	satot(&said, 0, text_said, SATOT_BUF);
}

/* find an entry in the bare_shunt table.
 * Trick: return a pointer to the pointer to the entry;
 * this allows the entry to be deleted.
 */
struct bare_shunt **bare_shunt_ptr(const ip_subnet *ours, const ip_subnet *his,
				   int transport_proto)
{
	struct bare_shunt *p, **pp;

	for (pp = &bare_shunts; (p = *pp) != NULL; pp = &p->next) {
		if (samesubnet(ours, &p->ours) &&
		    samesubnet(his, &p->his) &&
		    transport_proto == p->transport_proto &&
		    portof(&ours->addr) == portof(&p->ours.addr) &&
		    portof(&his->addr) == portof(&p->his.addr))
			return pp;
	}
	return NULL;
}

/* free a bare_shunt entry, given a pointer to the pointer */
static void free_bare_shunt(struct bare_shunt **pp)
{
	struct bare_shunt *p;

	/* ??? the following 3 lines are embarassing */
	pexpect(pp != NULL);
	if (pp == NULL)
		return;

	p = *pp;

	*pp = p->next;
	DBG_bare_shunt("delete", p);
	pfree(p);
}

int show_shunt_count(void)
{
	int i = 0;
	const struct bare_shunt *bs;

	for (bs = bare_shunts; bs != NULL; bs = bs->next)
	{
		i++;
	}

	return i;
}

void show_shunt_status(void)
{
	const struct bare_shunt *bs;

	whack_log(RC_COMMENT, "Bare Shunt list:"); /* spacer */
	whack_log(RC_COMMENT, " "); /* spacer */
	for (bs = bare_shunts; bs != NULL; bs = bs->next) {
		/* Print interesting fields.  Ignore count and last_active. */

		int ourport = ntohs(portof(&bs->ours.addr));
		int hisport = ntohs(portof(&bs->his.addr));
		char ourst[SUBNETTOT_BUF];
		char hist[SUBNETTOT_BUF];
		char sat[SATOT_BUF];
		char prio[POLICY_PRIO_BUF];

		subnettot(&(bs)->ours, 0, ourst, sizeof(ourst));
		subnettot(&(bs)->his, 0, hist, sizeof(hist));
		satot(&(bs)->said, 0, sat, sizeof(sat));
		fmt_policy_prio(bs->policy_prio, prio);

		whack_log(RC_COMMENT, "%s:%d -%d-> %s:%d => %s %s    %s",
			  ourst, ourport, bs->transport_proto, hist, hisport,
			  sat,
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
		       int sa_proto,
		       unsigned int transport_proto,
		       enum eroute_type esatype,
		       const struct pfkey_proto_info *proto_info,
		       deltatime_t use_lifetime,
		       uint32_t sa_priority,
		       const struct sa_marks *sa_marks,
		       enum pluto_sadb_operations op,
		       const char *opname
#ifdef HAVE_LABELED_IPSEC
		       , const char *policy_label
#endif
		       )
{
	char text_said[SATOT_BUF + SATOT_BUF];
	bool result;

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

	DBG(DBG_CONTROL | DBG_KERNEL,
	    {
		    int sport = ntohs(portof(&this_client->addr));
		    int dport = ntohs(portof(&that_client->addr));
		    char mybuf[SUBNETTOT_BUF];
		    char peerbuf[SUBNETTOT_BUF];

		    subnettot(this_client, 0, mybuf, sizeof(mybuf));
		    subnettot(that_client, 0, peerbuf, sizeof(peerbuf));
		    DBG_log("%s eroute %s:%d --%d-> %s:%d => %s (raw_eroute)",
			    opname, mybuf, sport, transport_proto, peerbuf,
			    dport,
			    text_said);
#ifdef HAVE_LABELED_IPSEC
		    if (policy_label != NULL)
			    DBG_log("policy security label %s", policy_label);
#endif
	    });

	result = kernel_ops->raw_eroute(this_host, this_client,
					that_host, that_client,
					cur_spi, new_spi, sa_proto,
					transport_proto,
					esatype, proto_info,
					use_lifetime, sa_priority, sa_marks, op, text_said
#ifdef HAVE_LABELED_IPSEC
					, policy_label
#endif
					);

	DBG(DBG_CONTROL | DBG_KERNEL, DBG_log("raw_eroute result=%s",
		result ? "success" : "failed"));

	return result;
}

/* test to see if %hold remains */
bool has_bare_hold(const ip_address *src, const ip_address *dst,
		   int transport_proto)
{
	ip_subnet this_client, that_client;

	passert(addrtypeof(src) == addrtypeof(dst));
	happy(addrtosubnet(src, &this_client));
	happy(addrtosubnet(dst, &that_client));

	/*const*/ struct bare_shunt **bspp =
		bare_shunt_ptr(&this_client, &that_client, transport_proto);

	return bspp != NULL &&
	       (*bspp)->said.proto == SA_INT && (*bspp)->said.spi == htonl(
		SPI_HOLD);
}

/*
 * clear any bare shunt holds that overlap with the network we have just
 * routed
 */
static void clear_narrow_holds(const ip_subnet *ours,
			       const ip_subnet *his,
			       int transport_proto)
{
	struct bare_shunt *p, **pp;

	for (pp = &bare_shunts; (p = *pp) != NULL; ) {
		ip_subnet po, ph;

		/* for now we only care about host-host narrow holds specifically */
		if (p->ours.maskbits != 32 || p->his.maskbits != 32) {
			pp = &p->next;
			continue;
		}

		if (p->said.spi != htonl(SPI_HOLD)) {
			pp = &p->next;
			continue;
		}

		initsubnet(&p->ours.addr, ours->maskbits, '0', &po);
		initsubnet(&p->his.addr, his->maskbits, '0', &ph);

		if (samesubnet(ours, &po) && samesubnet(his, &ph) &&
		    transport_proto == p->transport_proto &&
		    portof(&ours->addr) == portof(&p->ours.addr) &&
		    portof(&his->addr) == portof(&p->his.addr)) {

			if (!delete_bare_shunt(&p->ours.addr, &p->his.addr,
					transport_proto, SPI_HOLD,
					"removing clashing narrow hold"))
			{
				libreswan_log("delete_bare_shunt() in clear_narrow_holds() failed removing clashing narrow hold");
			}

			/* restart from beginning as we just removed an entry */
			pp = &bare_shunts;
			continue;
		}
		pp = &p->next;
	}
}

/* Replace (or delete) a shunt that is in the bare_shunts table.
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
	const ip_address *null_host = aftoinfo(addrtypeof(src))->any;

	DBG(DBG_CONTROL, DBG_log("fiddle_bare_shunt called"));

	passert(addrtypeof(src) == addrtypeof(dst));
	happy(addrtosubnet(src, &this_client));
	happy(addrtosubnet(dst, &that_client));

	/* ??? this comment might be obsolete.
	 * if the transport protocol is not the wildcard (0), then we need
	 * to look for a host<->host shunt, and replace that with the
	 * shunt spi, and then we add a %HOLD for what was there before.
	 *
	 * this is at odds with !repl, which should delete things.
	 *
	 */

	if (transport_proto != 0) {
		DBG(DBG_CONTROL, DBG_log("fiddle_bare_shunt with transport_proto %d", transport_proto));
	}

	{
		enum pluto_sadb_operations op = repl ? ERO_REPLACE : ERO_DELETE;

		DBG(DBG_KERNEL,
		    DBG_log("%s specific host-to-host bare shunt",
			    repl ? "replacing" : "removing"));
		if (raw_eroute(null_host, &this_client,
				null_host, &that_client,
			       htonl(cur_shunt_spi),
			       htonl(new_shunt_spi),
			       SA_INT, transport_proto,
			       ET_INT, null_proto_info,
			       deltatime(SHUNT_PATIENCE),
			       DEFAULT_IPSEC_SA_PRIORITY,
			       NULL, /* sa_marks */
			       op, why
#ifdef HAVE_LABELED_IPSEC
			       , NULL
#endif
			       )) {
			struct bare_shunt **bs_pp = bare_shunt_ptr(
				&this_client,
				&that_client,
				transport_proto);

			DBG(DBG_CONTROL, DBG_log("raw_eroute with op='%s' for transport_proto='%d' kernel shunt succeeded, bare shunt lookup %s",
				repl ? "replace" : "delete",
				transport_proto,
				(bs_pp == NULL) ? "failed" : "succeeded"));

			/* we can have proto mismatching acquires with netkey - this is a bad workaround */
			/* passert(bs_pp != NULL); */
			if (bs_pp == NULL) {
				DBG(DBG_CONTROL, DBG_log("not deleting bare (port) shunt - letting kernel expire it"));
				return TRUE;
			}
			if (repl) {
				/* change over to new bare eroute
				 * ours, his, transport_proto are the same.
				 */
				struct bare_shunt *bs = *bs_pp;

				bs->why = why;
				bs->policy_prio = policy_prio;
				bs->said.spi = htonl(new_shunt_spi);
				bs->said.proto = SA_INT;
				bs->said.dst = *null_host;
				bs->count = 0;
				bs->last_activity = mononow();
				DBG_bare_shunt("change", bs);
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
		       int sa_proto, enum eroute_type esatype,
		       const struct pfkey_proto_info *proto_info,
		       uint32_t sa_priority,
		       const struct sa_marks *sa_marks,
		       unsigned int op, const char *opname
#ifdef HAVE_LABELED_IPSEC
		       , const char *policy_label
#endif
		       )
{
	const ip_address *peer = &sr->that.host_addr;
	char buf2[256];
	ip_subnet client;

	snprintf(buf2, sizeof(buf2),
		 "eroute_connection %s", opname);

	if (sa_proto == SA_INT)
		peer = aftoinfo(addrtypeof(peer))->any;

	if (sr->this.has_cat) {
		addrtosubnet(&sr->this.host_addr, &client);
		bool t = raw_eroute(&sr->this.host_addr, &client,
				peer, &sr->that.client,
				cur_spi,
				new_spi,
				sa_proto,
				sr->this.protocol,
				esatype,
				proto_info,
				deltatime(0),
				sa_priority, sa_marks, op, buf2
#ifdef HAVE_LABELED_IPSEC
				, policy_label
#endif
				);
		if (!t)
			libreswan_log("CAT: failed to eroute additional Client Address Translation policy");

	DBG(DBG_CONTROL, DBG_log("%s CAT extra route added return=%d", __func__, t));
	}

	return raw_eroute(&sr->this.host_addr, &sr->this.client,
			  peer, &sr->that.client,
			  cur_spi,
			  new_spi,
			  sa_proto,
			  sr->this.protocol,
			  esatype,
			  proto_info,
			  deltatime(0),
			  sa_priority, sa_marks, op, buf2
#ifdef HAVE_LABELED_IPSEC
			  , policy_label
#endif
			  );
}

/* assign a bare hold or pass to a connection */

bool assign_holdpass(const struct connection *c,
		struct spd_route *sr,
		int transport_proto, ipsec_spi_t negotiation_shunt,
		const ip_address *src, const ip_address *dst)
{
	/* either the automatically installed %hold eroute is broad enough
	 * or we try to add a broader one and delete the automatic one.
	 * Beware: this %hold might be already handled, but still squeak
	 * through because of a race.
	 */
	enum routing_t ro = sr->routing,        /* routing, old */
		       rn = ro;                 /* routing, new */

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

	DBG(DBG_CONTROL,
	    DBG_log("assign hold, routing was %s, needs to be %s",
		    enum_name(&routing_story, ro),
		    enum_name(&routing_story, rn)));

	if (eclipsable(sr)) {
		/*
		 * Although %hold or %pass is appropriately broad, it will
		 * no longer be bare so we must ditch it from the bare table
		 */
		struct bare_shunt **old = bare_shunt_ptr(&sr->this.client, &sr->that.client, sr->this.protocol);

		if (old == NULL) {
			/* ??? should this happen?  It does. */
			DBG(DBG_CONTROL,
				DBG_log("assign_holdpass() no bare shunt to remove"));
		} else {
			/* ??? should this happen? */
			DBG(DBG_CONTROL,
				DBG_log("assign_holdpass() removing bare shunt"));
			free_bare_shunt(old);
		}
	} else {
		DBG(DBG_CONTROL,
			DBG_log("assign_holdpass() need broad(er) shunt"));
		/* we need a broad %hold, not the narrow one.
		 * First we ensure that there is a broad %hold.
		 * There may already be one (race condition): no need to create one.
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

			if (eroute_connection(sr, htonl(SPI_HOLD) /* kernel induced */, htonl(negotiation_shunt),
					       SA_INT, ET_INT,
					       null_proto_info,
					       DEFAULT_IPSEC_SA_PRIORITY,
					       NULL,
					       op,
					       reason
#ifdef HAVE_LABELED_IPSEC
					       , c->policy_label
#endif
					       )) {
				DBG(DBG_CONTROL, DBG_log("assign_holdpass() eroute_connection() done"));
			} else {
				libreswan_log("assign_holdpass() eroute_connection() failed");
				return FALSE;
			}
		}

		if (!delete_bare_shunt(src, dst,
					transport_proto,
					(c->policy & POLICY_NEGO_PASS) ? SPI_PASS : SPI_HOLD,
					(c->policy & POLICY_NEGO_PASS) ? "delete narrow %pass" :
						"delete narrow %hold"))
		{

			 DBG(DBG_CONTROL, DBG_log("assign_holdpass() delete_bare_shunt() succeeded"));
		} else {
			libreswan_log("assign_holdpass() delete_bare_shunt() failed");
				return FALSE;
		}
	}
	sr->routing = rn;
	DBG(DBG_CONTROL, DBG_log(" assign_holdpass() done - returning success"));
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
	       shunt_spi[(c->policy &
			  POLICY_SHUNT_MASK) >> POLICY_SHUNT_SHIFT] :
	       fail_spi[(c->policy & POLICY_FAIL_MASK) >> POLICY_FAIL_SHIFT];
}

static bool del_spi(ipsec_spi_t spi, int proto,
		    const ip_address *src, const ip_address *dest)
{
	char text_said[SATOT_BUF];
	struct kernel_sa sa;

	set_text_said(text_said, dest, spi, proto);

	DBG(DBG_KERNEL, DBG_log("delete %s", text_said));

	zero(&sa);
	sa.spi = spi;
	sa.proto = proto;
	sa.src = src;
	sa.dst = dest;
	sa.text_said = text_said;

	passert(kernel_ops->del_sa != NULL);
	return kernel_ops->del_sa(&sa);
}

/*
 * Set up one direction of the SA bundle
 */
static bool setup_half_ipsec_sa(struct state *st, bool inbound)
{
	/* Build an inbound or outbound SA */

	struct connection *c = st->st_connection;
	ip_subnet src, dst;
	ip_subnet src_client, dst_client;
	ipsec_spi_t inner_spi = 0;
	unsigned int proto = 0;
	enum eroute_type esatype = ET_UNSPEC;
	bool replace = inbound && (kernel_ops->get_spi != NULL);
	bool outgoing_ref_set = FALSE;
	bool incoming_ref_set = FALSE;
	IPsecSAref_t refhim = st->st_refhim;
	IPsecSAref_t new_refhim = IPSEC_SAREF_NULL;

	/* SPIs, saved for spigrouping or undoing, if necessary */
	struct kernel_sa said[EM_MAXRELSPIS];
	struct kernel_sa *said_next = said;
	struct kernel_sa said_boilerplate;

	char text_ipip[SATOT_BUF];
	char text_ipcomp[SATOT_BUF];
	char text_esp[SATOT_BUF];
	char text_ah[SATOT_BUF];

	/*
	 * encapsulation: encapsulation mode called for
	 * encap_oneshot: copy of "encapsultion" but reset to
	 *	ENCAPSULATION_MODE_TRANSPORT after use.
	 */
	int encapsulation = ENCAPSULATION_MODE_TRANSPORT;
	int encap_oneshot;

	bool add_selector;

	src.maskbits = 0;
	dst.maskbits = 0;

	if (inbound) {
		src.addr = c->spd.that.host_addr;
		dst.addr = c->spd.this.host_addr;
		src_client = c->spd.that.client;
		dst_client = c->spd.this.client;
	} else {
		src.addr = c->spd.this.host_addr,
		dst.addr = c->spd.that.host_addr;
		src_client = c->spd.this.client;
		dst_client = c->spd.that.client;
	}

	if (st->st_ah.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL ||
	    st->st_esp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL ||
	    st->st_ipcomp.attrs.encapsulation == ENCAPSULATION_MODE_TUNNEL) {
		encapsulation = ENCAPSULATION_MODE_TUNNEL;
		add_selector = FALSE; /* Don't add selectors for tunnel mode */
	} else {
		/* RFC 4301, Section 5.2 Requires traffic selectors to be set on
		 * transport mode
		 */
		add_selector = TRUE;
	}
	c->encapsulation = encapsulation;
	encap_oneshot = encapsulation;

	zero(&said_boilerplate);
	said_boilerplate.src = &src.addr;
	said_boilerplate.dst = &dst.addr;
	said_boilerplate.src_client = &src_client;
	said_boilerplate.dst_client = &dst_client;
	said_boilerplate.inbound = inbound;
	said_boilerplate.add_selector = add_selector;
	said_boilerplate.transport_proto = c->spd.this.protocol;
	said_boilerplate.sa_lifetime = c->sa_ipsec_life_seconds;
	said_boilerplate.outif = -1;
#ifdef HAVE_LABELED_IPSEC
	said_boilerplate.sec_ctx = st->sec_ctx;
#endif

	if (kernel_ops->inbound_eroute) {
		inner_spi = SPI_PASS;
		if (encapsulation == ENCAPSULATION_MODE_TUNNEL) {
			/* If we are tunnelling, set up IP in IP pseudo SA */
			proto = SA_IPIP;
			esatype = ET_IPIP;
		} else {
			/* For transport mode set ESP */
			/* ??? why are we sure that this isn't AH? */
			proto = SA_ESP;
			esatype = ET_ESP;
		}
	} else if (encapsulation == ENCAPSULATION_MODE_TUNNEL) {
		/* XXX hack alert -- we SHOULD NOT HAVE TO HAVE A DIFFERENT SPI
		 * XXX FOR IP-in-IP ENCAPSULATION!
		 */

		ipsec_spi_t ipip_spi;

		/* Allocate an SPI for the tunnel.
		 * Since our peer will never see this,
		 * and it comes from its own number space,
		 * it is purely a local implementation wart.
		 */
		{
			static ipsec_spi_t last_tunnel_spi =
				IPSEC_DOI_SPI_OUR_MIN;

			ipip_spi = htonl(last_tunnel_spi);
			last_tunnel_spi++;
			/* ??? what should we do on wrap-around? */
			passert(last_tunnel_spi >= IPSEC_DOI_SPI_OUR_MIN);
			if (inbound)
				st->st_tunnel_in_spi = ipip_spi;
			else
				st->st_tunnel_out_spi = ipip_spi;
		}

		set_text_said(text_ipip,
			      &c->spd.that.host_addr, ipip_spi, SA_IPIP);

		*said_next = said_boilerplate;
		said_next->spi = ipip_spi;
		said_next->esatype = ET_IPIP;
		said_next->text_said = text_ipip;

		if (inbound) {
			/*
			 * set corresponding outbound SA. We can do this on
			 * each SA in the bundle without harm.
			 */
			said_next->refhim = refhim;
		} else if (!outgoing_ref_set) {
			/* on outbound, pick up the SAref if not already done */
			said_next->ref    = refhim;
			outgoing_ref_set  = TRUE;
		}

		if (!kernel_ops->add_sa(said_next, replace)) {
			DBG(DBG_KERNEL, DBG_log("add_sa tunnel failed"));
			goto fail;
		}

		if (inbound) {
			st->st_esp.our_lastused = mononow();
		} else {
			st->st_esp.peer_lastused = mononow();
		}

		DBG(DBG_KERNEL,
		    DBG_log("added tunnel with ref=%u", said_next->ref));

		/*
		 * SA refs will have been allocated for this SA.
		 * The inner most one is interesting for the outgoing SA,
		 * since we refer to it in the policy that we instantiate.
		 */
		if (new_refhim == IPSEC_SAREF_NULL && !inbound) {
			DBG(DBG_KERNEL,
			    DBG_log("recorded ref=%u as refhim",
				    said_next->ref));
			new_refhim = said_next->ref;
			if (kern_interface != USE_NETKEY && new_refhim == IPSEC_SAREF_NULL)
				new_refhim = IPSEC_SAREF_NA;
		}
		if (!incoming_ref_set && inbound) {
			st->st_ref = said_next->ref;
			incoming_ref_set = TRUE;
		}
		said_next++;

		inner_spi = ipip_spi;
		proto = SA_IPIP;
		esatype = ET_IPIP;
	}

	/* set up IPCOMP SA, if any */

	if (st->st_ipcomp.present) {
		ipsec_spi_t ipcomp_spi =
			inbound ? st->st_ipcomp.our_spi : st->st_ipcomp.attrs.
			spi;
		unsigned compalg;

		switch (st->st_ipcomp.attrs.transattrs.encrypt) {
		case IPCOMP_DEFLATE:
			compalg = SADB_X_CALG_DEFLATE;
			break;

		default:
			loglog(RC_LOG_SERIOUS,
			       "IPCOMP transform %s not implemented",
			       enum_name(&ipcomp_transformid_names,
					 st->st_ipcomp.attrs.transattrs.encrypt));
			goto fail;
		}

		set_text_said(text_ipcomp, &dst.addr, ipcomp_spi, SA_COMP);

		*said_next = said_boilerplate;
		said_next->spi = ipcomp_spi;
		said_next->esatype = ET_IPCOMP;
		said_next->encalg = compalg;
		said_next->encapsulation = encap_oneshot;
		said_next->reqid = reqid_ipcomp(c->spd.reqid);
		said_next->text_said = text_ipcomp;

		if (inbound) {
			/*
			 * set corresponding outbound SA. We can do this on
			 * each SA in the bundle without harm.
			 */
			said_next->refhim = refhim;
		} else if (!outgoing_ref_set) {
			/* on outbound, pick up the SAref if not already done */
			said_next->ref    = refhim;
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
		if (new_refhim == IPSEC_SAREF_NULL && !inbound) {
			new_refhim = said_next->ref;
			if (kern_interface != USE_NETKEY && new_refhim == IPSEC_SAREF_NULL)
				new_refhim = IPSEC_SAREF_NA;
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
		const struct esp_info *ei;

		/* ??? table of non-registered algorithms? */
		static const struct esp_info esp_info[] = {
			{ FALSE, ESP_NULL, AUTH_ALGORITHM_HMAC_MD5,
			  0,
			  SADB_EALG_NULL, SADB_AALG_MD5HMAC },
			{ FALSE, ESP_NULL, AUTH_ALGORITHM_HMAC_SHA1,
			  0,
			  SADB_EALG_NULL, SADB_AALG_SHA1HMAC },
#if 0
			{ FALSE, ESP_DES, AUTH_ALGORITHM_NONE,
			  DES_CBC_BLOCK_SIZE,
			  SADB_EALG_DESCBC, SADB_AALG_NONE },
			{ FALSE, ESP_DES, AUTH_ALGORITHM_HMAC_MD5,
			  DES_CBC_BLOCK_SIZE,
			  SADB_EALG_DESCBC, SADB_AALG_MD5HMAC },
			{ FALSE, ESP_DES, AUTH_ALGORITHM_HMAC_SHA1,
			  DES_CBC_BLOCK_SIZE,
			  SADB_EALG_DESCBC,
			  SADB_AALG_SHA1HMAC },
#endif
			{ FALSE, ESP_3DES, AUTH_ALGORITHM_NONE,
			  DES_CBC_BLOCK_SIZE * 3,
			  SADB_EALG_3DESCBC, SADB_AALG_NONE },
			{ FALSE, ESP_3DES, AUTH_ALGORITHM_HMAC_MD5,
			  DES_CBC_BLOCK_SIZE * 3,
			  SADB_EALG_3DESCBC, SADB_AALG_MD5HMAC },
			{ FALSE, ESP_3DES, AUTH_ALGORITHM_HMAC_SHA1,
			  DES_CBC_BLOCK_SIZE * 3,
			  SADB_EALG_3DESCBC, SADB_AALG_SHA1HMAC },

			{ FALSE, ESP_AES, AUTH_ALGORITHM_NONE,
			  AES_CBC_BLOCK_SIZE,
			  SADB_X_EALG_AESCBC, SADB_AALG_NONE },
			{ FALSE, ESP_AES, AUTH_ALGORITHM_HMAC_MD5,
			  AES_CBC_BLOCK_SIZE,
			  SADB_X_EALG_AESCBC, SADB_AALG_MD5HMAC },
			{ FALSE, ESP_AES, AUTH_ALGORITHM_HMAC_SHA1,
			  AES_CBC_BLOCK_SIZE,
			  SADB_X_EALG_AESCBC, SADB_AALG_SHA1HMAC },

			{ FALSE, ESP_CAST, AUTH_ALGORITHM_NONE,
			  CAST_CBC_BLOCK_SIZE,
			  SADB_X_EALG_CASTCBC, SADB_AALG_NONE },
			{ FALSE, ESP_CAST, AUTH_ALGORITHM_HMAC_MD5,
			  CAST_CBC_BLOCK_SIZE,
			  SADB_X_EALG_CASTCBC, SADB_AALG_MD5HMAC },
			{ FALSE, ESP_CAST, AUTH_ALGORITHM_HMAC_SHA1,
			  CAST_CBC_BLOCK_SIZE,
			  SADB_X_EALG_CASTCBC, SADB_AALG_SHA1HMAC },
		};

		u_int8_t natt_type = 0;
		u_int16_t natt_sport = 0, natt_dport = 0;
		ip_address natt_oa;

		if (st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) {
			natt_type = ESPINUDP_WITH_NON_ESP;
			if (inbound) {
				natt_sport = st->st_remoteport;
				natt_dport = st->st_localport;
			} else {
				natt_sport = st->st_localport;
				natt_dport = st->st_remoteport;
			}
			natt_oa = st->hidden_variables.st_nat_oa;
		}

		DBG(DBG_CONTROL,
		    DBG_log("looking for alg with transid: %d keylen: %d auth: %d",
			    ta->encrypt, ta->enckeylen, ta->integ_hash));

		for (ei = esp_info; ; ei++) {

			/* if it is the last key entry, then ask algo */
			if (ei == &esp_info[elemsof(esp_info)]) {
				/*
				 * Check for additional kernel alg
				 * Note: result will be in a static buffer!
				 */
				struct esb_buf buftn, bufan;

				ei = kernel_alg_esp_info(ta->encrypt,
							ta->enckeylen,
							ta->integ_hash);
				if (ei != NULL)
					break;

				loglog(RC_LOG_SERIOUS,
				       "ESP transform %s(%d) / auth %s not implemented or allowed",
				       enum_showb(&esp_transformid_names,
						ta->encrypt,
						&buftn),
				       ta->enckeylen,
				       enum_showb(&auth_alg_names,
						ta->integ_hash,
						&bufan));
				goto fail;
			}

			DBG(DBG_CRYPT,
			    DBG_log("checking transid: %d keylen: %d auth: %d",
				    ei->transid, ei->enckeylen, ei->auth));

			if (ta->encrypt == ei->transid &&
			    (ta->enckeylen == 0 ||
			     ta->enckeylen == ei->enckeylen * BITS_PER_BYTE) &&
			    ta->integ_hash == ei->auth)
				break;
		}

		u_int16_t enc_key_len = ta->enckeylen / BITS_PER_BYTE;

		if (enc_key_len != 0) {
			/* XXX: must change to check valid _range_ enc_key_len */
			if (enc_key_len > ei->enckeylen) {
				loglog(RC_LOG_SERIOUS,
				       "ESP transform %s passed encryption key length %u; we expected %u or less",
				       enum_name(&esp_transformid_names,
						 ta->encrypt),
				       (unsigned)enc_key_len,
				       (unsigned)ei->enckeylen);
				goto fail;
			}
			/* ??? why would we have a different length? */
			pexpect(enc_key_len == ei->enckeylen);
		} else {
			enc_key_len = ei->enckeylen;
		}

		/* Fixup key lengths for special cases */
		switch (ei->transid) {
		case ESP_3DES:
			/* Grrrrr.... f*cking 7 bits jurassic algos  */
			/* 168 bits in kernel, need 192 bits for keymat_len */
			if (enc_key_len == 21)
				enc_key_len = 24;
			break;
		case ESP_DES:
			/* Grrrrr.... f*cking 7 bits jurassic algos  */
			/* 56 bits in kernel, need 64 bits for keymat_len */
			if (enc_key_len == 7)
				enc_key_len = 8;
			break;

		case IKEv2_ENCR_AES_CTR:
			/* keymat contains 4 bytes of salt */
			enc_key_len += AES_CTR_SALT_BYTES;
			break;

		case IKEv2_ENCR_AES_GCM_8:
		case IKEv2_ENCR_AES_GCM_12:
		case IKEv2_ENCR_AES_GCM_16:
			/* keymat contains 4 bytes of salt */
			enc_key_len += AES_GCM_SALT_BYTES;
			break;
		case IKEv2_ENCR_AES_CCM_8:
		case IKEv2_ENCR_AES_CCM_12:
		case IKEv2_ENCR_AES_CCM_16:
			/* keymat contains 3 bytes of salt */
			enc_key_len += AES_CCM_SALT_BYTES;
			break;
		}

		/* ??? why authkeylen but enc_key_len?  Spelling seems inconsistent. */
		unsigned authkeylen = ikev1_auth_kernel_attrs(ei->auth, NULL);

		DBG(DBG_KERNEL, DBG_log(
			"st->st_esp.keymat_len=%" PRIu16 " is key_len=%" PRIu16 " + authkeylen=%u",
			st->st_esp.keymat_len, enc_key_len, authkeylen));

		passert(st->st_esp.keymat_len == enc_key_len + authkeylen);

		set_text_said(text_esp, &dst.addr, esp_spi, SA_ESP);

		*said_next = said_boilerplate;
		said_next->spi = esp_spi;
		said_next->esatype = ET_ESP;
		said_next->replay_window = c->sa_replay_window;
		DBG(DBG_KERNEL, DBG_log("setting IPsec SA replay-window to %d",
			c->sa_replay_window));

		if (!inbound && c->sa_tfcpad != 0 && !st->st_seen_no_tfc) {
			DBG(DBG_KERNEL, DBG_log("Enabling TFC at %d bytes (up to PMTU)", c->sa_tfcpad));
			said_next->tfcpad = c->sa_tfcpad;
		}
		said_next->authalg = ei->authalg;
		if (said_next->authalg == AUTH_ALGORITHM_HMAC_SHA2_256 &&
		    st->st_connection->sha2_truncbug) {
			if (kernel_ops->sha2_truncbug_support) {
#ifdef FIPS_CHECK
				if (libreswan_fipsmode() == 1) {
					loglog(RC_LOG_SERIOUS,
						"Error: sha2-truncbug=yes is not allowed in FIPS mode");
					goto fail;
				}
#endif
				DBG(DBG_KERNEL, DBG_log(" authalg converted for sha2 truncation at 96bits instead of IETF's mandated 128bits"));
				/* We need to tell the kernel to mangle the sha2_256, as instructed by the user */
				said_next->authalg =
					AUTH_ALGORITHM_HMAC_SHA2_256_TRUNCBUG;
			} else {
				loglog(RC_LOG_SERIOUS,
				       "Error: %s stack does not support sha2_truncbug=yes",
				       kernel_ops->kern_name);
				goto fail;
			}
		}

		if (st->st_esp.attrs.transattrs.esn_enabled == TRUE) {
			DBG(DBG_KERNEL, DBG_log("Enabling ESN "));
			said_next->esn = TRUE;
		}

		/* divide up keying material */
		said_next->enckey = esp_dst_keymat;
		said_next->enckeylen = enc_key_len;
		said_next->encalg = ei->encryptalg;

		said_next->authkey = esp_dst_keymat + enc_key_len;
		said_next->authkeylen = authkeylen;
		/* said_next->authkey = esp_dst_keymat + ei->enckeylen; */
		/* said_next->enckeylen = ei->enckeylen; */

		said_next->encapsulation = encap_oneshot;
		said_next->reqid = reqid_esp(c->spd.reqid);

		said_next->natt_sport = natt_sport;
		said_next->natt_dport = natt_dport;
		said_next->transid = ta->encrypt;
		said_next->natt_type = natt_type;
		said_next->natt_oa = &natt_oa;
#ifdef KLIPS_MAST
		if (st->st_esp.attrs.encapsulation ==
		      ENCAPSULATION_MODE_TRANSPORT &&
		    useful_mastno != -1)
			said_next->outif = MASTTRANSPORT_OFFSET +
					   useful_mastno;

#endif
		said_next->text_said = text_esp;

		DBG(DBG_CRYPT, {
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
			said_next->refhim = refhim;
		} else if (!outgoing_ref_set) {
			/* on outbound, pick up the SAref if not already done */
			said_next->ref = refhim;
			outgoing_ref_set = TRUE;
		}

		if (!kernel_ops->add_sa(said_next, replace)) {
			/* scrub keys from memory */
			memset(said_next->enckey, 0, said_next->enckeylen);
			memset(said_next->authkey, 0, said_next->authkeylen);
			goto fail;
		}
		/* scrub keys from memory */
		memset(said_next->enckey, 0, said_next->enckeylen);
		memset(said_next->authkey, 0, said_next->authkeylen);

		/*
		 * SA refs will have been allocated for this SA.
		 * The inner most one is interesting for the outgoing SA,
		 * since we refer to it in the policy that we instantiate.
		 */
		if (new_refhim == IPSEC_SAREF_NULL && !inbound) {
			new_refhim = said_next->ref;
			if (kern_interface != USE_NETKEY && new_refhim == IPSEC_SAREF_NULL)
				new_refhim = IPSEC_SAREF_NA;
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


	        /*
		 * INTEG_HASH has type oakley_hash_t (a.k.a., "enum
		 * ikev1_hash_attribute") yet here it is being treated
		 * as ae "enum ikev1_auth_attribute".
		 */
		int authalg;
		enum ikev1_auth_attribute auth = st->st_ah.attrs.transattrs.integ_hash;
		unsigned key_len = ikev1_auth_kernel_attrs(auth, &authalg);
		if (authalg <= 0) {
			loglog(RC_LOG_SERIOUS, "%s not implemented",
			       enum_show(&auth_alg_names, auth));
			goto fail;
		}

		passert(st->st_ah.keymat_len == key_len);

		set_text_said(text_ah, &dst.addr, ah_spi, SA_AH);

		*said_next = said_boilerplate;
		said_next->spi = ah_spi;
		said_next->esatype = ET_AH;
		said_next->authalg = authalg;
		said_next->authkeylen = st->st_ah.keymat_len;
		said_next->authkey = ah_dst_keymat;
		said_next->encapsulation = encap_oneshot;
		said_next->reqid = reqid_ah(c->spd.reqid);
		said_next->text_said = text_ah;
		said_next->replay_window = c->sa_replay_window;
		DBG(DBG_KERNEL, DBG_log("setting IPsec SA replay-window to %d",
			c->sa_replay_window));

		if (st->st_ah.attrs.transattrs.esn_enabled == TRUE) {
			DBG(DBG_KERNEL, DBG_log("Enabling ESN "));
			said_next->esn = TRUE;
		}

		DBG(DBG_CRYPT, {
			DBG_dump("AH authkey:", said_next->authkey,
				said_next->authkeylen);
		    });

		if (inbound) {
			/*
			 * set corresponding outbound SA. We can do this on
			 * each SA in the bundle without harm.
			 */
			said_next->refhim = refhim;
		} else if (!outgoing_ref_set) {
			/* on outbound, pick up the SAref if not already done */
			said_next->ref = refhim;
			outgoing_ref_set = TRUE;	/* not currently used */
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
		if (new_refhim == IPSEC_SAREF_NULL && !inbound) {
			new_refhim = said_next->ref;
			if (kern_interface != USE_NETKEY && new_refhim == IPSEC_SAREF_NULL)
				new_refhim = IPSEC_SAREF_NA;
		}
		if (!incoming_ref_set && inbound) {
			st->st_ref = said_next->ref;
			incoming_ref_set = TRUE;	/* not currently used */
		}
		said_next++;

		encap_oneshot = ENCAPSULATION_MODE_TRANSPORT;	/* not currently used */
	}

	/*
	 * Add an inbound eroute to enforce an arrival check.
	 *
	 * If inbound, and policy does not specify DISABLEARRIVALCHECK,
	 * ??? and some more mysterious conditions,
	 * tell KLIPS to enforce the IP addresses appropriate for this tunnel.
	 * Note reversed ends.
	 * Not much to be done on failure.
	 */
	if (inbound && (c->policy & POLICY_DISABLEARRIVALCHECK) == 0 &&
	    (kernel_ops->inbound_eroute ? c->spd.eroute_owner == SOS_NOBODY :
	     encapsulation == ENCAPSULATION_MODE_TUNNEL))
	     {
		struct pfkey_proto_info proto_info[4];
		int i = 0;

		/*
		 * ??? why does this code care about
		 * st->st_*.attrs.encapsulation?
		 * We have gone do some trouble to compute
		 * "encapsulation".  And later code uses
		 * "encapsulation".
		 */
		if (st->st_ipcomp.present) {
			proto_info[i].proto = IPPROTO_COMP;
			proto_info[i].encapsulation =
				st->st_ipcomp.attrs.encapsulation;
			proto_info[i].reqid = reqid_ipcomp(c->spd.reqid);
			i++;
		}

		if (st->st_esp.present) {
			proto_info[i].proto = IPPROTO_ESP;
			proto_info[i].encapsulation =
				st->st_esp.attrs.encapsulation;
			proto_info[i].reqid = reqid_esp(c->spd.reqid);
			i++;
		}

		if (st->st_ah.present) {
			proto_info[i].proto = IPPROTO_AH;
			proto_info[i].encapsulation =
				st->st_ah.attrs.encapsulation;
			proto_info[i].reqid = reqid_ah(c->spd.reqid);
			i++;
		}

		proto_info[i].proto = 0;

		/*
		 * ??? why is encapsulation overwitten ONLY if
		 * kernel_ops->inbound_eroute?
		 */
		if (kernel_ops->inbound_eroute &&
		    encapsulation == ENCAPSULATION_MODE_TUNNEL) {
			proto_info[0].encapsulation =
				ENCAPSULATION_MODE_TUNNEL;
			for (i = 1; proto_info[i].proto; i++)
				proto_info[i].encapsulation =
					ENCAPSULATION_MODE_TRANSPORT;
		}

		/* MCR - should be passed a spd_eroute structure here */
		/* note: this and that are intentionally reversed */
		if (!raw_eroute(&c->spd.that.host_addr,		/* this_host */
				  &c->spd.that.client,		/* this_client */
				  &c->spd.this.host_addr,	/* that_host */
				  &c->spd.this.client,		/* that_client */
				  inner_spi,			/* current spi - might not be used? */
				  inner_spi,			/* new spi */
				  proto,			/* SA proto */
				  c->spd.this.protocol,		/* transport_proto */
				  esatype,			/* esatype */
				  proto_info,			/* " */
				  deltatime(0),			/* lifetime */
				  c->sa_priority,		/* IPsec SA prio */
				  &c->sa_marks,			/* IPsec SA marks */
				  ERO_ADD_INBOUND,		/* op */
				  "add inbound"			/* opname */
#ifdef HAVE_LABELED_IPSEC
				  , st->st_connection->policy_label
#endif
				  )) {
			libreswan_log("raw_eroute() in setup_half_ipsec_sa() failed to add inbound");
		}
	}

	/* If there are multiple SPIs, group them. */

	if (kernel_ops->grp_sa != NULL && said_next > &said[1]) {
		struct kernel_sa *s;

		/* group SAs, two at a time, inner to outer (backwards in said[])
		 * The grouping is by pairs.  So if said[] contains ah esp ipip,
		 * the grouping would be ipip:esp, esp:ah.
		 */
		for (s = said; s < said_next - 1; s++) {
			DBG(DBG_KERNEL,
			    DBG_log("grouping %s (ref=%u) and %s (ref=%u)",
				    s[0].text_said, s[0].ref,
				    s[1].text_said, s[1].ref));
			if (!kernel_ops->grp_sa(s + 1, s)) {
				libreswan_log("grp_sa failed");
				goto fail;
			}
		}
		/* could update said, but it will not be used */
	}

	if (new_refhim != IPSEC_SAREF_NULL)
		st->st_refhim = new_refhim;

	/* if the impaired is set, pretend this fails */
	if (st->st_connection->extra_debugging & IMPAIR_SA_CREATION) {
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
					       &src.addr, said_next->dst);
			}
		}
		return FALSE;
	}
}

/* teardown_ipsec_sa is a canibalized version of setup_ipsec_sa */
static bool teardown_half_ipsec_sa(struct state *st, bool inbound)
{
	/* We need to delete AH, ESP, and IP in IP SPIs.
	 * But if there is more than one, they have been grouped
	 * so deleting any one will do.  So we just delete the
	 * first one found.  It may or may not be the only one.
	 */
	struct connection *const c = st->st_connection;

	struct {
		unsigned proto;
		struct ipsec_proto_info *info;
	} protos[4];
	int i = 0;
	bool result;

	/* ??? CLANG 3.5 thinks that c might be NULL */
	if (kernel_ops->inbound_eroute && inbound &&
	    c->spd.eroute_owner == SOS_NOBODY) {
		if (!raw_eroute(&c->spd.that.host_addr, &c->spd.that.client,
				  &c->spd.this.host_addr, &c->spd.this.client,
				  SPI_PASS, SPI_PASS,
				  c->encapsulation == ENCAPSULATION_MODE_TRANSPORT ? SA_ESP : IPSEC_PROTO_ANY,
				  c->spd.this.protocol,
				  c->encapsulation == ENCAPSULATION_MODE_TRANSPORT ? ET_ESP : ET_UNSPEC,
				  null_proto_info,
				  deltatime(0),
				  c->sa_priority, &c->sa_marks,
				  ERO_DEL_INBOUND, "delete inbound"
#ifdef HAVE_LABELED_IPSEC
				  , c->policy_label
#endif
				  )) {
			 libreswan_log("raw_eroute in teardown_half_ipsec_sa() failed to delete inbound");
		}
	}

	if (kernel_ops->grp_sa == NULL) {
		if (st->st_ah.present) {
			protos[i].info = &st->st_ah;
			protos[i].proto = SA_AH;
			i++;
		}

		if (st->st_esp.present) {
			protos[i].info = &st->st_esp;
			protos[i].proto = SA_ESP;
			i++;
		}

		if (st->st_ipcomp.present) {
			protos[i].info = &st->st_ipcomp;
			protos[i].proto = SA_COMP;
			i++;
		}
	} else if (st->st_ah.present) {
		protos[i].info = &st->st_ah;
		protos[i].proto = SA_AH;
		i++;
	} else if (st->st_esp.present) {
		protos[i].info = &st->st_esp;
		protos[i].proto = SA_ESP;
		i++;
	} else {
		return TRUE;
	}
	protos[i].proto = 0;

	result = TRUE;
	for (i = 0; protos[i].proto; i++) {
		unsigned proto = protos[i].proto;
		ipsec_spi_t spi;
		const ip_address *src, *dst;

		if (inbound) {
			spi = protos[i].info->our_spi;
			src = &c->spd.that.host_addr;
			dst = &c->spd.this.host_addr;
		} else {
			spi = protos[i].info->attrs.spi;
			src = &c->spd.this.host_addr;
			dst = &c->spd.that.host_addr;
		}

		result &= del_spi(spi, proto, src, dst);
	}
	return result;
}

static event_callback_routine kernel_process_msg_cb;

static void kernel_process_msg_cb(evutil_socket_t fd UNUSED,
		const short event UNUSED, void *arg)
{
	const struct kernel_ops *kernel_ops = arg;

	DBG(DBG_KERNEL, DBG_log(" %s process netlink message", __func__));
	kernel_ops->process_msg();
	passert(GLOBALS_ARE_RESET());
}

static event_callback_routine kernel_process_queue_cb;

static void kernel_process_queue_cb(evutil_socket_t fd UNUSED,
		const short event UNUSED, void *arg)
{
	const struct kernel_ops *kernel_ops = arg;

	kernel_ops->process_queue();
	passert(GLOBALS_ARE_RESET());

}

/* keep track of kernel version  */
static char kversion[256];

const struct kernel_ops *kernel_ops = NULL;
int bare_shunt_interval = SHUNT_SCAN_INTERVAL;


void init_kernel(void)
{
	struct utsname un;

#if defined(NETKEY_SUPPORT) || defined(KLIPS) || defined(KLIPS_MAST)
	struct stat buf;
#endif

	/* get kernel version */
	uname(&un);
	jam_str(kversion, sizeof(kversion), un.release);

	switch (kern_interface) {
#if defined(NETKEY_SUPPORT)
	case USE_NETKEY:
		if (stat("/proc/net/pfkey", &buf) != 0) {
			libreswan_log(
				"No XFRM/NETKEY kernel interface detected");
			exit_pluto(PLUTO_EXIT_KERNEL_FAIL);
		}
		libreswan_log(
			"Using Linux XFRM/NETKEY IPsec interface code on %s",
			kversion);
		kernel_ops = &netkey_kernel_ops;
		break;
#endif

#if defined(KLIPS)
	case USE_KLIPS:
		if (stat("/proc/net/pf_key", &buf) != 0) {
			libreswan_log("No KLIPS kernel interface detected");
			exit_pluto(PLUTO_EXIT_KERNEL_FAIL);
		}
		libreswan_log("Using KLIPS IPsec interface code on %s",
			      kversion);
		kernel_ops = &klips_kernel_ops;
		break;
#endif

#if defined(KLIPS_MAST)
	case USE_MASTKLIPS:
		if (stat("/proc/sys/net/ipsec/debug_mast", &buf) != 0) {
			libreswan_log("No MASTKLIPS kernel interface detected");
			exit_pluto(PLUTO_EXIT_KERNEL_FAIL);
		}
		libreswan_log("Using KLIPSng (mast) IPsec interface code on %s",
			kversion);
		kernel_ops = &mast_kernel_ops;
		break;
#endif

#if defined(BSD_KAME)
	case USE_BSDKAME:
		libreswan_log("Using BSD/KAME IPsec interface code on %s",
			      kversion);
		kernel_ops = &bsdkame_kernel_ops;
		break;
#endif

#if defined(WIN32) && defined(WIN32_NATIVE)
	case USE_WIN32_NATIVE:
		libreswan_log("Using Win2K native IPsec interface code on %s",
			      kversion);
		kernel_ops = &win2k_kernel_ops;
		break;
#endif

	case NO_KERNEL:
		libreswan_log("Using 'no_kernel' interface code on %s",
			      kversion);
		kernel_ops = &noklips_kernel_ops;
		break;

	default:
		libreswan_log("FATAL: kernel interface '%s' not available",
			      enum_name(&kern_interface_names,
					kern_interface));
		exit_pluto(PLUTO_EXIT_KERNEL_FAIL);
	}

	if (kernel_ops->init != NULL)
		kernel_ops->init();

	/* register SA types that we can negotiate */
	can_do_IPcomp = FALSE; /* until we get a response from KLIPS */
	if (kernel_ops->pfkey_register != NULL)
		kernel_ops->pfkey_register();

	event_schedule(EVENT_SHUNT_SCAN, SHUNT_SCAN_INTERVAL, NULL);

	DBG(DBG_KERNEL, DBG_log("setup kernel fd callback"));

	/* Note: kernel_ops is const but pluto_event_new cannot know that */
	ev_fd = pluto_event_new(*kernel_ops->async_fdp, EV_READ | EV_PERSIST,
			kernel_process_msg_cb, (void *)kernel_ops, NULL);

	if (kernel_ops->process_queue != NULL) {
		/*
		 * AA_2015 this is untested code. only for non netkey ???
		 * It seems in klips we should, besides kernel_process_msg,
		 * call process_queue periodically.  Does the order
		 * matter?
		 */
		static const struct timeval delay = {KERNEL_PROCESS_Q_PERIOD, 0};

		/* Note: kernel_ops is read-only but pluto_event_new cannot know that */
		ev_pq = pluto_event_new(NULL_FD, EV_TIMEOUT | EV_PERSIST,
				kernel_process_queue_cb, (void *)kernel_ops, &delay);
	}
}

void show_kernel_interface(void)
{
	if (kernel_ops != NULL) {
		whack_log(RC_COMMENT, "using kernel interface: %s",
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

	DBG(DBG_CONTROL, {
		    DBG_log("checking if this is a replacement state");
		    DBG_log("  st=%p ost=%p st->serialno=#%lu ost->serialno=#%lu",
			    st, ost, st->st_serialno,
			    ost == NULL ? 0 : ost->st_serialno);
	    });

	if (ost != NULL && ost != st && ost->st_serialno != st->st_serialno) {
		/*
		 * then there is an old state associated, and it is
		 * different then the new one.
		 */
		libreswan_log("keeping refhim=%lu during rekey",
			      (unsigned long)ost->st_refhim);
		st->st_refhim = ost->st_refhim;
	}
}

/* Note: install_inbound_ipsec_sa is only used by the Responder.
 * The Responder will subsequently use install_ipsec_sa for the outbound.
 * The Initiator uses install_ipsec_sa to install both at once.
 */
bool install_inbound_ipsec_sa(struct state *st)
{
	struct connection *const c = st->st_connection;

	/* If our peer has a fixed-address client, check if we already
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

#if 0                                   /* this stops us removing certain RW routes, and later we fail */
			if (o->kind == CK_TEMPLATE && streq(o->name, c->name))
				break;  /* ??? is this good enough?? */
#endif

			if (kernel_ops->overlap_supported) {
				/* Both are transport mode, allow overlapping.
				 * [bart] not sure if this is actually intended, but am
				 *        leaving it in to make it behave like before
				 */
				if (!LIN(POLICY_TUNNEL, c->policy) &&
				    !LIN(POLICY_TUNNEL, o->policy))
					break;
				/* Both declared that overlapping is OK. */
				if (LIN(POLICY_OVERLAPIP, c->policy) &&
				    LIN(POLICY_OVERLAPIP, o->policy))
					break;
			}

			ipstr_buf b;
			char cib[CONN_INST_BUF];
			loglog(RC_LOG_SERIOUS,
			       "route to peer's client conflicts with \"%s\"%s %s; releasing old connection to free the route",
			       o->name, fmt_conn_instance(o, cib),
			       ipstr(&o->spd.that.host_addr, &b));
			release_connection(o, FALSE);
		}
	}

	DBG(DBG_CONTROL,
	    DBG_log("install_inbound_ipsec_sa() checking if we can route"));
	/* check that we will be able to route and eroute */
	switch (could_route(c)) {
	case route_easy:
	case route_nearconflict:
		DBG(DBG_CONTROL,
		    DBG_log("   routing is easy, or has resolvable near-conflict"));
		break;

	case route_unnecessary:
		/*
		 * in this situation, we should look and see if there is a state
		 * that our connection references, that we are in fact replacing.
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
	if (st->st_refhim == IPSEC_SAREF_NULL && !st->st_outbound_done) {

		DBG(DBG_CONTROL,
		    DBG_log("installing outgoing SA now as refhim=%u",
			    st->st_refhim));
		if (!setup_half_ipsec_sa(st, FALSE)) {
			DBG_log("failed to install outgoing SA: %u",
				st->st_refhim);
			return FALSE;
		}

		st->st_outbound_done = TRUE;
	}
	DBG(DBG_CONTROL, DBG_log("outgoing SA has refhim=%u", st->st_refhim));

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
	bool eroute_installed = FALSE,
	     firewall_notified = FALSE,
	     route_installed = FALSE;

#ifdef IPSEC_CONNECTION_LIMIT
	bool new_eroute = FALSE;
#endif

	struct spd_route *esr, *rosr;
	struct connection *ero,
		*ro = route_owner(c, sr, &rosr, &ero, &esr);	/* who, if anyone, owns our eroute? */

	DBG(DBG_CONTROLMORE,
	    DBG_log("route_and_eroute with c: %s (next: %s) ero:%s esr:{%p} ro:%s rosr:{%p} and state: #%lu",
		    c->name,
		    (c->policy_next ? c->policy_next->name : "none"),
		    ero == NULL ? "null" : ero->name,
		    esr,
		    ro == NULL ? "null" : ro->name,
		    rosr,
		    st == NULL ? 0 : st->st_serialno));

	/* look along the chain of policies for one with the same name */

#if 0
	/* XXX - mcr this made sense before, and likely will make sense
	 * again, so I'l leaving this to remind me what is up
	 */
	if (ero != NULL && ero->routing == RT_UNROUTED_KEYED)
		ero = NULL;

	for (ero2 = ero; ero2 != NULL; ero2 = ero->policy_next)
		if ((ero2->kind == CK_TEMPLATE ||
		     ero2->kind == CK_SECONDARY) &&
		    streq(ero2->name, c->name))
			break;
#endif

	struct bare_shunt **bspp = (ero == NULL) ?
	       bare_shunt_ptr(&sr->this.client, &sr->that.client,
			      sr->this.protocol) :
	       NULL;

	/* install the eroute */

	passert(bspp == NULL || ero == NULL);   /* only one non-NULL */

	if (bspp != NULL || ero != NULL) {
		/* We're replacing an eroute */

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

#if 0
		/* XXX - MCR. I previously felt that this was a bogus check */
		if (ero != NULL && ero != c && esr != sr) {
			/* By elimination, we must be eclipsing ero.  Check. */
			passert(ero->kind == CK_TEMPLATE &&
				streq(ero->name, c->name));
			passert(LHAS(LELEM(RT_ROUTED_PROSPECTIVE) |
				     LELEM(RT_ROUTED_ECLIPSED),
				     esr->routing));
			passert(samesubnet(&esr->this.client,
					   &sr->this.client) &&
				samesubnet(&esr->that.client,
					   &sr->that.client));
		}
#endif
		/* remember to free bspp iff we make it out of here alive */
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

	if (eroute_installed) {
		/* do we have to notify the firewall?  Yes, if we are installing
		 * a tunnel eroute and the firewall wasn't notified
		 * for a previous tunnel with the same clients.  Any Previous
		 * tunnel would have to be for our connection, so the actual
		 * test is simple.
		 */
		firewall_notified = st == NULL ||                       /* not a tunnel eroute */
				    sr->eroute_owner != SOS_NOBODY ||   /* already notified */
				    do_command(c, sr, "up", st);        /* go ahead and notify */
	}

	/* install the route */

	DBG(DBG_CONTROL,
	    DBG_log("route_and_eroute: firewall_notified: %s",
		    firewall_notified ? "true" : "false"));
	if (!firewall_notified) {
		/* we're in trouble -- don't do routing */
	} else if (ro == NULL) {
		/* a new route: no deletion required, but preparation is */
		if (!do_command(c, sr, "prepare", st))
			DBG(DBG_CONTROL,
			    DBG_log("prepare command returned an error"));
		route_installed = do_command(c, sr, "route", st);
		if (!route_installed)
			DBG(DBG_CONTROL,
			    DBG_log("route command returned an error"));
	} else if (routed(sr->routing) ||
		   routes_agree(ro, c)) {
		route_installed = TRUE; /* nothing to be done */
	} else {
		/* Some other connection must own the route
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
				DBG(DBG_CONTROL,
				    DBG_log("unroute command returned an error"));
			}
			route_installed = do_command(c, sr, "route", st);
			if (!route_installed)
				DBG(DBG_CONTROL,
				    DBG_log("route command returned an error"));


		} else {
			route_installed = do_command(c, sr, "route", st);
			if (!route_installed)
				DBG(DBG_CONTROL,
				    DBG_log("route command returned an error"));


			if (!do_command(ro, sr, "unroute", st)) {
				DBG(DBG_CONTROL,
				    DBG_log("unroute command returned an error"));
			}
		}

		/* record unrouting */
		if (route_installed) {
			do {
				passert(!erouted(rosr->routing));
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
				/* By elimination, we must be eclipsing ero.  Checked above. */
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

			DBG(DBG_CONTROL, {
				    char cib[CONN_INST_BUF];
				    DBG_log("route_and_eroute: instance \"%s\"%s, setting eroute_owner {spd=%p,sr=%p} to #%lu (was #%lu) (newest_ipsec_sa=#%lu)",
					    st->st_connection->name,
					    fmt_conn_instance(st->st_connection,
							      cib),
					    &st->st_connection->spd, sr,
					    st->st_serialno,
					    sr->eroute_owner,
					    st->st_connection->newest_ipsec_sa);
			    });
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
				DBG(DBG_CONTROL,
				    DBG_log("down command returned an error"));


		}

		if (eroute_installed) {
			/* Restore original eroute, if we can.
			 * Since there is nothing much to be done if the restoration
			 * fails, ignore success or failure.
			 */
			if (bspp != NULL) {
				/* Restore old bare_shunt.
				 * I don't think that this case is very likely.
				 * Normally a bare shunt would have been assigned
				 * to a connection before we've gotten this far.
				 */
				struct bare_shunt *bs = *bspp;

				if (!raw_eroute(&bs->said.dst,        /* should be useless */
						  &bs->ours,
						  &bs->said.dst,        /* should be useless */
						  &bs->his,
						  bs->said.spi,         /* unused? network order */
						  bs->said.spi,         /* network order */
						  SA_INT,               /* proto */
						  0,                    /* transport_proto */
						  ET_INT,
						  null_proto_info,
						  deltatime(SHUNT_PATIENCE),
						  DEFAULT_IPSEC_SA_PRIORITY,
						  NULL,
						  ERO_REPLACE, "restore"
#ifdef HAVE_LABELED_IPSEC
						  , NULL /* bare shunt are not associated with any connection so no security label*/
#endif
						  )) {
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
					/* Try to find state that owned eroute.
					 * Don't do anything if it cannot be found.
					 * This case isn't likely since we don't run
					 * the updown script when replacing a SA group
					 * with its successor (for the same conn).
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
	DBG(DBG_CONTROL, DBG_log("install_ipsec_sa() for #%lu: %s",
				 st->st_serialno,
				 inbound_also ?
				 "inbound and outbound" : "outbound only"));

	enum routability rb = could_route(st->st_connection);

	switch (rb) {
	case route_easy:
	case route_unnecessary:
	case route_nearconflict:
		break;

	default:
		return FALSE;
	}

	/* (attempt to) actually set up the SA group */

	/* setup outgoing SA if we haven't already */
	if (!st->st_outbound_done) {
		if (!setup_half_ipsec_sa(st, FALSE))
			return FALSE;

		DBG(DBG_KERNEL,
		    DBG_log("set up outgoing SA, ref=%u/%u", st->st_ref,
			    st->st_refhim));
		st->st_outbound_done = TRUE;
	}

	/* now setup inbound SA */
	if (st->st_ref == IPSEC_SAREF_NULL && inbound_also) {
		if (!setup_half_ipsec_sa(st, TRUE))
			return FALSE;

		DBG(DBG_KERNEL,
		    DBG_log("set up incoming SA, ref=%u/%u", st->st_ref,
			    st->st_refhim));
	}

	if (rb == route_unnecessary)
		return TRUE;

	struct spd_route *sr = &st->st_connection->spd;

	if (st->st_connection->remotepeertype == CISCO && sr->spd_next != NULL)
		sr = sr->spd_next;

	/* for (sr = &st->st_connection->spd; sr != NULL; sr = sr->next) */
	for (; sr != NULL; sr = sr->spd_next) {
		DBG(DBG_CONTROL, DBG_log("sr for #%lu: %s",
					 st->st_serialno,
					 enum_name(&routing_story,
						   sr->routing)));

		/*
		 * if the eroute owner is not us, then make it us.
		 * See test co-terminal-02, pluto-rekey-01, pluto-unit-02/oppo-twice
		 */
		pexpect(sr->eroute_owner == SOS_NOBODY ||
			sr->routing >= RT_ROUTED_TUNNEL);

		if (sr->eroute_owner != st->st_serialno &&
		    sr->routing != RT_UNROUTED_KEYED) {
			if (!route_and_eroute(st->st_connection, sr, st)) {
				delete_ipsec_sa(st);
				/* XXX go and unroute any SRs that were successfully
				 * routed already.
				 */
				return FALSE;
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

#ifdef USE_LINUX_AUDIT
	linux_audit_conn(st, LAK_CHILD_START);
#endif

	return TRUE;
}

/* delete an IPSEC SA.
 * we may not succeed, but we bull ahead anyway because
 * we cannot do anything better by recognizing failure
 * This used to have a parameter bool inbound_only, but
 * the saref code changed to always install inbound before
 * outbound so this it was always false, and thus removed
 */
void delete_ipsec_sa(struct state *st)
{
#ifdef USE_LINUX_AUDIT
	/* XXX in IKEv2 we get a spurious call with a parent st :( */
	if (IS_CHILD_SA(st))
		linux_audit_conn(st, LAK_CHILD_DESTROY);
#endif
	switch (kern_interface) {
	case USE_MASTKLIPS:
	case USE_KLIPS:
	case USE_NETKEY:
		{
			/* If the state is the eroute owner, we must adjust
			 * the routing for the connection.
			 */
			struct connection *c = st->st_connection;
			struct spd_route *sr;

			for (sr = &c->spd; sr; sr = sr->spd_next) {
				if (sr->eroute_owner == st->st_serialno &&
				    sr->routing == RT_ROUTED_TUNNEL) {
					sr->eroute_owner = SOS_NOBODY;

					/* Routing should become RT_ROUTED_FAILURE,
					 * but if POLICY_FAIL_NONE, then we just go
					 * right back to RT_ROUTED_PROSPECTIVE as if no
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
						/* in this special case, even if the connection
						 * is still alive (due to an ISAKMP SA),
						 * we get rid of routing.
						 * Even though there is still an eroute, the c->routing
						 * setting will convince unroute_connection to delete it.
						 * unroute_connection would be upset if c->routing == RT_ROUTED_TUNNEL
						 */
						unroute_connection(c);
					} else {
						if (!shunt_eroute(c, sr,
								    sr->routing, ERO_REPLACE,
								    "replace with shunt")) {
							libreswan_log("shunt_eroute() failed replace with shunt in delete_ipsec_sa()");
						}
					}

#ifdef KLIPS_MAST
					/* in mast mode we must also delete the iptables rule */
					if (kern_interface == USE_MASTKLIPS)
						if (!sag_eroute(st, sr,
								  ERO_DELETE,
								  "delete")) {
							libreswan_log("sag_eroute() failed delete in delete_ipsec_sa()");
						}
#endif
				}
			}
			(void) teardown_half_ipsec_sa(st, FALSE);
		}
		(void) teardown_half_ipsec_sa(st, TRUE);

		break;
#if defined(WIN32) && defined(WIN32_NATIVE)
	case USE_WIN32_NATIVE:
		DBG(DBG_CONTROL,
		    DBG_log("No support (required?) to delete_ipsec_sa with Win2k"));
		break;
#endif
	case NO_KERNEL:
		DBG(DBG_CONTROL,
		    DBG_log("No support required to delete_ipsec_sa with NoKernel support"));
		break;
	default:
		DBG(DBG_CONTROL,
		    DBG_log("Unknown kernel stack in delete_ipsec_sa"));
		break;
	} /* switch kern_interface */
}

bool was_eroute_idle(struct state *st, deltatime_t since_when)
{
	if (kernel_ops->eroute_idle != NULL)
		return kernel_ops->eroute_idle(st, since_when);

	/* it is never idle if we can't check */
	return FALSE;
}

/* This wrapper is to make the seam_* files in testing/ easier */
bool kernel_overlap_supported(void)
{
	return kernel_ops->overlap_supported;
}

const char *kernel_if_name(void)
{
	return kernel_ops->kern_name;
}

/*
 * get information about a given sa - needs merging with was_eroute_idle
 *
 * Note: this mutates *st.
 */
bool get_sa_info(struct state *st, bool inbound, deltatime_t *ago /* OUTPUT */)
{
	char text_said[SATOT_BUF];
	u_int proto;
	u_int bytes;
	uint64_t add_time;
	ipsec_spi_t spi;
	const ip_address *src, *dst;
	struct kernel_sa sa;
	struct ipsec_proto_info *p2;

	const struct connection *c = st->st_connection;

	if (kernel_ops->get_sa == NULL || (!st->st_esp.present && !st->st_ah.present)) {
		return FALSE;
	}

	if (st->st_esp.present) {
		proto = SA_ESP;
		p2 = &st->st_esp;
	} else if (st->st_ah.present) {
		proto = SA_AH;
		p2 = &st->st_ah;
	} else {
		return FALSE;
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
	set_text_said(text_said, dst, spi, proto);

	zero(&sa);
	sa.spi = spi;
	sa.proto = proto;
	sa.src = src;
	sa.dst = dst;
	sa.text_said = text_said;

	DBG(DBG_KERNEL,
	    DBG_log("get %s", text_said));
	if (!kernel_ops->get_sa(&sa, &bytes, &add_time))
		return FALSE;

	p2->add_time = add_time;

	passert(p2->our_lastused.mono_secs != 0);
	passert(p2->peer_lastused.mono_secs != 0);

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
	return TRUE;
}

void free_kernelfd(void)
{
	if (ev_fd != NULL) {
		event_free(ev_fd);
		ev_fd = NULL;
	}
	if (ev_pq != NULL) {
		event_free(ev_pq);
		ev_pq = NULL;
	}

}

bool orphan_holdpass(const struct connection *c, struct spd_route *sr,
		int transport_proto, ipsec_spi_t failure_shunt)
{
	enum routing_t ro = sr->routing,        /* routing, old */
			rn = ro;                 /* routing, new */
	ipsec_spi_t negotiation_shunt = (c->policy & POLICY_NEGO_PASS) ? SPI_PASS : SPI_DROP;

	if (negotiation_shunt != failure_shunt ) {
		DBG(DBG_CONTROL, DBG_log("failureshunt != negotiationshunt, needs replacing"));
	} else {
		DBG(DBG_CONTROL, DBG_log("failureshunt == negotiationshunt, no replace needed"));
	}

	DBG(DBG_CONTROL, DBG_log("orphan_holdpass() called for %s with transport_proto '%d'",
		 c->name, transport_proto));

	passert(LHAS(LELEM(CK_PERMANENT) | LELEM(CK_INSTANCE) |
				LELEM(CK_GOING_AWAY), c->kind));

	switch (ro) {
	case RT_UNROUTED_HOLD:
		rn = RT_UNROUTED;
		DBG(DBG_CONTROL, DBG_log("orphan_holdpass unrouted: hold -> pass"));
		break;
	case RT_UNROUTED:
		rn = RT_UNROUTED_HOLD;
		DBG(DBG_CONTROL, DBG_log("orphan_holdpass unrouted: pass -> hold"));
		break;
	case RT_ROUTED_HOLD:
		rn = RT_ROUTED_PROSPECTIVE;
		DBG(DBG_CONTROL, DBG_log("orphan_holdpass routed: hold -> trap (?)"));
		break;
	default:
		DBG(DBG_CONTROL, DBG_log(
			"no routing change needed for ro=%s - negotiation shunt matched failure shunt?",
			enum_name(&routing_story, ro)));
		break;
	}

	DBG(DBG_CONTROL,
		DBG_log("orphaning holdpass for connection '%s', routing was %s, needs to be %s",
			c->name,
			enum_name(&routing_story, ro),
			enum_name(&routing_story, rn)));

	{
		/* are we replacing a bare shunt ? */
		struct bare_shunt **old = bare_shunt_ptr(&sr->this.client, &sr->that.client, sr->this.protocol);

		if (old != NULL) {
			free_bare_shunt(old);
		}
	}

	/* create the bare shunt and update kernel policy if needed */
	{
		struct bare_shunt *bs = alloc_thing(struct bare_shunt, "orphan shunt");

		bs->why = "oe-failing";
		bs->ours = sr->this.client;
		bs->his = sr->that.client;
		bs->transport_proto = sr->this.protocol;
		bs->policy_prio = BOTTOM_PRIO;

		bs->said.proto = SA_INT;
		bs->said.spi = htonl(negotiation_shunt);
		bs->said.dst = *aftoinfo(subnettypeof(&sr->this.client))->any;

		bs->count = 0;
		bs->last_activity = mononow();

		bs->next = bare_shunts;
		bare_shunts = bs;
		DBG_bare_shunt("add", bs);

		/* update kernel policy if needed */
		if (negotiation_shunt != failure_shunt ) {
			if (!replace_bare_shunt(&sr->this.host_addr, &sr->that.host_addr, bs->policy_prio,
				negotiation_shunt, failure_shunt, bs->transport_proto,
				"oe-failed"))
			{
				libreswan_log("assign_holdpass() failed to update shunt policy");
			}
		}
	}

	/* change routing so we don't get cleared out when state/connection dies */
	sr->routing = rn;
	DBG(DBG_CONTROL, DBG_log("orphan_holdpas() done - returning success"));
	return TRUE;
}

/* XXX move to proper kernel_ops in kernel_netlink */
void expire_bare_shunts(void)
{
	struct bare_shunt **bspp;

	DBG(DBG_OPPO, DBG_log("expiring aged bare shunts"));
	for (bspp = &bare_shunts; *bspp != NULL; ) {
		struct bare_shunt *bsp = *bspp;
		time_t age = deltasecs(monotimediff(mononow(), bsp->last_activity));

		if (age > deltasecs(pluto_shunt_lifetime)) {
			DBG(DBG_OPPO, DBG_bare_shunt("expiring old", bsp));
			delete_bare_shunt(&bsp->ours.addr, &bsp->his.addr,
				bsp->transport_proto, ntohl(bsp->said.spi),
				"expire_bare_shunt");
			passert(bsp != *bspp);
		} else {
			DBG(DBG_OPPO, DBG_bare_shunt("keeping recent", bsp));
			bspp = &bsp->next;
		}
	}

	event_schedule(EVENT_SHUNT_SCAN, bare_shunt_interval, NULL);
}

unsigned
ikev1_auth_kernel_attrs(enum ikev1_auth_attribute auth, int *alg)
{
	int authalg;
	unsigned key_len;

	switch (auth) {

	case AUTH_ALGORITHM_NONE:
		authalg = 0;
		key_len = 0;
		break;

	case AUTH_ALGORITHM_HMAC_MD5:
		authalg = SADB_AALG_MD5HMAC;
		key_len = HMAC_MD5_KEY_LEN;
		break;

	case AUTH_ALGORITHM_HMAC_SHA1:
		authalg = SADB_AALG_SHA1HMAC;
		key_len = HMAC_SHA1_KEY_LEN;
		break;

		/* RFC 4868 */
	case AUTH_ALGORITHM_HMAC_SHA2_256:
		authalg = SADB_X_AALG_SHA2_256HMAC;
		key_len = BYTES_FOR_BITS(256);
		break;

		/* RFC 4868 */
	case AUTH_ALGORITHM_HMAC_SHA2_384:
		authalg = SADB_X_AALG_SHA2_384HMAC;
		key_len = BYTES_FOR_BITS(384);
		break;

		/* RFC 4868 */
	case AUTH_ALGORITHM_HMAC_SHA2_512:
		authalg = SADB_X_AALG_SHA2_512HMAC;
		key_len = BYTES_FOR_BITS(512);
		break;

		/* RFC 2857 Section 3 */
	case AUTH_ALGORITHM_HMAC_RIPEMD:
		authalg = SADB_X_AALG_RIPEMD160HMAC;
		key_len = BYTES_FOR_BITS(160);
		break;

		/* RFC 3566 Section 4.1 */
	case AUTH_ALGORITHM_AES_XCBC:
		authalg = SADB_X_AALG_AES_XCBC_MAC;
		key_len = BYTES_FOR_BITS(128);
		break;

		/* RFC 4543 Section 5.3 */
	case AUTH_ALGORITHM_AES_128_GMAC:
		authalg = SADB_X_AALG_AH_AES_128_GMAC;
		key_len = BYTES_FOR_BITS(128);
		break;

		/* RFC 4543 Section 5.3 */
	case AUTH_ALGORITHM_AES_192_GMAC:
		authalg = SADB_X_AALG_AH_AES_192_GMAC;
		key_len = BYTES_FOR_BITS(192);
		break;

		/* RFC 4543 Section 5.3 */
	case AUTH_ALGORITHM_AES_256_GMAC:
		authalg = SADB_X_AALG_AH_AES_256_GMAC;
		key_len = BYTES_FOR_BITS(256);
		break;

	case AUTH_ALGORITHM_NULL_KAME: /* Should we support this? */
	case AUTH_ALGORITHM_SIG_RSA: /* RFC 4359 */
	case AUTH_ALGORITHM_KPDK:
	case AUTH_ALGORITHM_DES_MAC:
	default:
		key_len = 0;
		authalg = -1;
	}

	if (alg != NULL)
		*alg = authalg;
	return key_len;
}
