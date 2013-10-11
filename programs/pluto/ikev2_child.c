/* IKEv2 - CHILD SA - calculations
 *
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2009-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2011-2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Antony Antony <appu@phenome.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"
#include "libswan.h"

#include "defs.h"
#include "cookie.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "packet.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "ike_alg.h"
#include "log.h"
#include "demux.h"      /* needs packet.h */
#include "ikev2.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "timer.h"
#include "whack.h"      /* requires connections.h */
#include "server.h"
#include "vendor.h"
#include "dpd.h"
#include "udpfromto.h"
#include "kernel.h"
#include "virtual.h"	/* needs connections.h */
#include "hostpair.h"

void ikev2_print_ts(struct traffic_selector *ts)
{
	char lbx[ADDRTOT_BUF];
	char hbx[ADDRTOT_BUF];

	DBG_log("printing contents struct traffic_selector");
	DBG_log("  ts_type: %s", enum_name(&ikev2_ts_type_names, ts->ts_type));
	DBG_log("  ipprotoid: %d", ts->ipprotoid);
	DBG_log("  startport: %d", ts->startport);
	DBG_log("  endport: %d", ts->endport);
	addrtot(&ts->low,  0, lbx, sizeof(lbx));
	addrtot(&ts->high, 0, hbx, sizeof(hbx));
	DBG_log("  ip low: %s", lbx);
	DBG_log("  ip high: %s", hbx);
}

/* rewrite me with addrbytesptr() */
struct traffic_selector ikev2_end_to_ts(struct end *e)
{
	struct traffic_selector ts;
	struct in6_addr v6mask;

	memset(&ts, 0, sizeof(ts));

	switch (e->client.addr.u.v4.sin_family) {
	case AF_INET:
		ts.ts_type = IKEv2_TS_IPV4_ADDR_RANGE;
		ts.low   = e->client.addr;
		ts.low.u.v4.sin_addr.s_addr  &=
			bitstomask(e->client.maskbits).s_addr;
		ts.high  = e->client.addr;
		ts.high.u.v4.sin_addr.s_addr |=
			~bitstomask(e->client.maskbits).s_addr;
		break;

	case AF_INET6:
		ts.ts_type = IKEv2_TS_IPV6_ADDR_RANGE;
		v6mask = bitstomask6(e->client.maskbits);

		ts.low   = e->client.addr;
		ts.low.u.v6.sin6_addr.s6_addr32[0] &= v6mask.s6_addr32[0];
		ts.low.u.v6.sin6_addr.s6_addr32[1] &= v6mask.s6_addr32[1];
		ts.low.u.v6.sin6_addr.s6_addr32[2] &= v6mask.s6_addr32[2];
		ts.low.u.v6.sin6_addr.s6_addr32[3] &= v6mask.s6_addr32[3];

		ts.high  = e->client.addr;
		ts.high.u.v6.sin6_addr.s6_addr32[0] |= ~v6mask.s6_addr32[0];
		ts.high.u.v6.sin6_addr.s6_addr32[1] |= ~v6mask.s6_addr32[1];
		ts.high.u.v6.sin6_addr.s6_addr32[2] |= ~v6mask.s6_addr32[2];
		ts.high.u.v6.sin6_addr.s6_addr32[3] |= ~v6mask.s6_addr32[3];
		break;

		/* Setting ts_type IKEv2_TS_FC_ADDR_RANGE (RFC-4595) not yet supproted */
	}

	ts.ipprotoid = e->protocol;

	/*
	 * if port is %any or 0 we mean all ports (or all iccmp/icmpv6
	 * See RFC-5996 Section 3.13.1 handling for ICMP(1) and ICMPv6(58)
	 *   we only support providing Type, not Code, eg protoport=1/1
	 */
	if (e->port == 0 || e->has_port_wildcard) {
		ts.startport = 0;
		ts.endport = 65535;
	} else {
		ts.startport = e->port;
		ts.endport = e->port;
	}

	return ts;
}

stf_status ikev2_emit_ts(struct msg_digest *md UNUSED,
			 pb_stream *outpbs,
			 unsigned int np,
			 struct traffic_selector *ts,
			 enum phase1_role role UNUSED)
{
	struct ikev2_ts its;
	struct ikev2_ts1 its1;
	pb_stream ts_pbs;
	pb_stream ts_pbs2;

	its.isat_np = np;
	its.isat_critical = ISAKMP_PAYLOAD_NONCRITICAL;
	its.isat_num = 1;

	if (!out_struct(&its, &ikev2_ts_desc, outpbs, &ts_pbs))
		return STF_INTERNAL_ERROR;

	switch (ts->ts_type) {
	case IKEv2_TS_IPV4_ADDR_RANGE:
		its1.isat1_type = IKEv2_TS_IPV4_ADDR_RANGE;
		its1.isat1_sellen = 2 * 4 + 8; /* See RFC 5669 SEction 13.3.1, 8 octet header plus 2 ip addresses */
		break;
	case IKEv2_TS_IPV6_ADDR_RANGE:
		its1.isat1_type = IKEv2_TS_IPV6_ADDR_RANGE;
		its1.isat1_sellen = 2 * 16 + 8; /* See RFC 5669 SEction 13.3.1, 8 octet header plus 2 ip addresses */
		break;
	case IKEv2_TS_FC_ADDR_RANGE:
		DBG_log(
			"IKEv2 Traffic Selector IKEv2_TS_FC_ADDR_RANGE not yet supported");
		return STF_INTERNAL_ERROR;

	default:
		DBG_log("IKEv2 Traffic Selector type '%d' not supported",
			ts->ts_type);
	}

	its1.isat1_ipprotoid = ts->ipprotoid;   /* protocol as per local policy*/
	its1.isat1_startport = ts->startport;   /* ports as per local policy*/
	its1.isat1_endport = ts->endport;
	if (!out_struct(&its1, &ikev2_ts1_desc, &ts_pbs, &ts_pbs2))
		return STF_INTERNAL_ERROR;

	/* now do IP addresses */
	switch (ts->ts_type) {
	case IKEv2_TS_IPV4_ADDR_RANGE:
		if (!out_raw(&ts->low.u.v4.sin_addr.s_addr, 4, &ts_pbs2,
			     "ipv4 low") ||
		    !out_raw(&ts->high.u.v4.sin_addr.s_addr, 4, &ts_pbs2,
			     "ipv4 high"))
			return STF_INTERNAL_ERROR;

		break;
	case IKEv2_TS_IPV6_ADDR_RANGE:
		if (!out_raw(&ts->low.u.v6.sin6_addr.s6_addr, 16, &ts_pbs2,
			     "ipv6 low") ||
		    !out_raw(&ts->high.u.v6.sin6_addr.s6_addr, 16, &ts_pbs2,
			     "ipv6 high"))
			return STF_INTERNAL_ERROR;

		break;
	case IKEv2_TS_FC_ADDR_RANGE:
		DBG_log("Traffic Selector IKEv2_TS_FC_ADDR_RANGE not supported");
		return STF_FAIL;

	default:
		DBG_log(
			"Failed to create unknown IKEv2 Traffic Selector payload '%d'",
			ts->ts_type);
		return STF_FAIL;
	}

	close_output_pbs(&ts_pbs2);
	close_output_pbs(&ts_pbs);

	return STF_OK;
}

stf_status ikev2_calc_emit_ts(struct msg_digest *md,
			      pb_stream *outpbs,
			      enum phase1_role role,
			      struct connection *c0,
			      lset_t policy UNUSED)
{
	struct state *st = md->st;
	struct traffic_selector *ts_i, *ts_r;
	struct spd_route *sr;
	stf_status ret;

	st->st_childsa = c0;

	if (role == INITIATOR) {
		ts_i = &st->st_ts_this;
		ts_r = &st->st_ts_that;
	} else {
		ts_i = &st->st_ts_that;
		ts_r = &st->st_ts_this;
	}

	for (sr = &c0->spd; sr != NULL; sr = sr->next) {
		ret = ikev2_emit_ts(md, outpbs, ISAKMP_NEXT_v2TSr,
				    ts_i, INITIATOR);
		if (ret != STF_OK)
			return ret;

		if (role == INITIATOR) {
			ret = ikev2_emit_ts(md, outpbs,
					    st->st_connection->policy & POLICY_TUNNEL ? ISAKMP_NEXT_v2NONE : ISAKMP_NEXT_v2N,
					    ts_r, RESPONDER);
		} else {
			struct payload_digest *p;
			for (p = md->chain[ISAKMP_NEXT_v2N]; p != NULL;
			     p = p->next) {
				if ( p->payload.v2n.isan_type ==
				     v2N_USE_TRANSPORT_MODE ) {
					DBG_log(
						"Received v2N_USE_TRANSPORT_MODE from the other end, next payload is v2N_USE_TRANSPORT_MODE notification");
					ret = ikev2_emit_ts(md, outpbs,
							    ISAKMP_NEXT_v2N,
							    ts_r, RESPONDER);
					break;
				}
			}
			if (!p) {
				ret = ikev2_emit_ts(md, outpbs,
						    ISAKMP_NEXT_v2NONE,
						    ts_r, RESPONDER);
			}
		}

		if (ret != STF_OK)
			return ret;
	}

	return STF_OK;
}

/* return number of traffic selectors found */
int ikev2_parse_ts(struct payload_digest *const ts_pd,
		   struct traffic_selector *array,
		   unsigned int array_max)
{
	struct ikev2_ts1 ts1;
	unsigned int i;

	for (i = 0; i < ts_pd->payload.v2ts.isat_num; i++) {
		pb_stream addr;
		if (!in_struct(&ts1, &ikev2_ts1_desc, &ts_pd->pbs, &addr))
			return -1;

		if (i < array_max) {
			memset(&array[i], 0, sizeof(*array));
			switch (ts1.isat1_type) {
			case IKEv2_TS_IPV4_ADDR_RANGE:
				array[i].ts_type = IKEv2_TS_IPV4_ADDR_RANGE;
				array[i].low.u.v4.sin_family  = AF_INET;
#ifdef NEED_SIN_LEN
				array[i].low.u.v4.sin_len =
					sizeof( struct sockaddr_in);
#endif
				if (!in_raw(&array[i].low.u.v4.sin_addr.s_addr,
					    4, &addr, "ipv4 ts"))
					return -1;

				array[i].high.u.v4.sin_family = AF_INET;
#ifdef NEED_SIN_LEN
				array[i].high.u.v4.sin_len =
					sizeof( struct sockaddr_in);
#endif

				if (!in_raw(&array[i].high.u.v4.sin_addr.s_addr,
					    4, &addr, "ipv4 ts"))
					return -1;

				break;

			case IKEv2_TS_IPV6_ADDR_RANGE:
				array[i].ts_type = IKEv2_TS_IPV6_ADDR_RANGE;
				array[i].low.u.v6.sin6_family  = AF_INET6;
#ifdef NEED_SIN_LEN
				array[i].low.u.v6.sin6_len =
					sizeof( struct sockaddr_in6);
#endif

				if (!in_raw(&array[i].low.u.v6.sin6_addr.
					    s6_addr, 16, &addr, "ipv6 ts"))
					return -1;

				array[i].high.u.v6.sin6_family = AF_INET6;
#ifdef NEED_SIN_LEN
				array[i].high.u.v6.sin6_len =
					sizeof( struct sockaddr_in6);
#endif

				if (!in_raw(&array[i].high.u.v6.sin6_addr.
					    s6_addr, 16, &addr, "ipv6 ts"))
					return -1;

				break;

			default:
				return -1;
			}

			array[i].ipprotoid = ts1.isat1_ipprotoid;
			/*should be converted to host byte order for local processing*/
			array[i].startport = ts1.isat1_startport;
			array[i].endport   = ts1.isat1_endport;
		}
	}

	return i;
}

int ikev2_evaluate_connection_protocol_fit(struct connection *d,
					   struct spd_route *sr,
					   enum phase1_role role,
					   struct traffic_selector *tsi,
					   struct traffic_selector *tsr,
					   unsigned int tsi_n,
					   unsigned int tsr_n,
					   unsigned int *best_tsi_i,
					   unsigned int *best_tsr_i)
{
	unsigned int tsi_ni, tsr_ni;
	int bestfit_pr = -1;
	struct end *ei, *er;
	int narrowing = (d->policy & POLICY_IKEV2_ALLOW_NARROWING);

	if (role == INITIATOR) {
		ei = &sr->this;
		er = &sr->that;
	} else {
		ei = &sr->that;
		er = &sr->this;
	}
	/* compare tsi/r array to this/that, evaluating port ranges how well it fits */
	for (tsi_ni = 0; tsi_ni < tsi_n; tsi_ni++) {
		for (tsr_ni = 0; tsr_ni < tsr_n; tsr_ni++) {
			int fitrange1 = 0;
			int fitrange2 = 0;
			DBG(DBG_CONTROL,
			    DBG_log(
				    "ei->protocol %d  tsi[tsi_ni].ipprotoid %d narrowing=%s",
				    ei->protocol,
				    tsi[tsi_ni].ipprotoid,
				    (narrowing ? "yes" : "no")));
			if (ei->protocol == tsi[tsi_ni].ipprotoid) {
				fitrange1 = 255;
				DBG(DBG_CONTROL,
				    DBG_log(
					    "   tsi[%d] %d  ==  ei->protocol %d exact match  fitrange1 %d",
					    tsi_ni,
					    tsi[tsi_ni].ipprotoid,
					    ei->protocol,
					    fitrange1));

			} else if ( (role == INITIATOR) && narrowing &&
				    (!ei->protocol)) {
				DBG(DBG_CONTROL,
				    DBG_log(
					    "  INITIATOR narrowing=yes, want to narrow ei->protocol 0(all) to tsi[%d] protocol %d",
					    tsi_ni,
					    tsi[tsi_ni].ipprotoid));
				fitrange1 = 1;
				DBG(DBG_CONTROL,
				    DBG_log(
					    "  tsi[%d] protocol %d >= ei->protocol 0(all) can be narrowed  fitrange1 %d",
					    tsi_ni,
					    tsi[tsi_ni].ipprotoid, fitrange1));
			} else if ( (role == RESPONDER) && narrowing &&
				    (ei->protocol)) {
				DBG(DBG_CONTROL,
				    DBG_log(
					    "  RESPONDER narrowing=yes, want to narrow ei->protocol %d to tsi[%d] protocol %d",
					    ei->protocol, tsi_ni,
					    tsi[tsi_ni].ipprotoid));
				fitrange1 = 1;
			} else {
				DBG(DBG_CONTROL,
				    DBG_log(
					    "  mismatch tsi[%d] %d to ei->protocol %d",
					    tsi_ni,
					    tsi[tsi_ni].ipprotoid,
					    ei->protocol));
			}

			if (er->protocol == tsr[tsr_ni].ipprotoid) {
				fitrange2 = 255;
				DBG(DBG_CONTROL,
				    DBG_log(
					    "   tsr[%d] %d  ==  er->protocol %d exact match  fitrange2 %d",
					    tsr_ni,
					    tsr[tsr_ni].ipprotoid,
					    er->protocol,
					    fitrange2));

			} else if ( (role == INITIATOR) && narrowing &&
				    (!er->protocol)) {
				DBG(DBG_CONTROL,
				    DBG_log(
					    "  INITIATOR narrowing=yes, want to narrow er->protocol 0(all) to tsr[%d] protocol %d",
					    tsr_ni,
					    tsr[tsr_ni].ipprotoid));
				fitrange2 = 1;
				DBG(DBG_CONTROL,
				    DBG_log(
					    "  tsr[%d] protocol %d >= er->protocol 0(all) can be narrowed  fitrange1 %d",
					    tsr_ni,
					    tsr[tsr_ni].ipprotoid, fitrange1));
			} else if ( (role == RESPONDER) && narrowing &&
				    (er->protocol)) {
				DBG(DBG_CONTROL,
				    DBG_log(
					    "  RESPONDER narrowing=yes, want to narrow er->protocol %d to tsr[%d] protocol %d",
					    er->protocol, tsr_ni,
					    tsr[tsr_ni].ipprotoid));
				fitrange2 = 1;
			} else {
				DBG(DBG_CONTROL,
				    DBG_log(
					    "  mismatch tsr[%d] %d to er->protocol %d",
					    tsr_ni,
					    tsr[tsr_ni].ipprotoid,
					    er->protocol));
			}

			int fitbits  = 0;
			if (fitrange1 && fitrange2) {
				fitbits = (fitrange1 << 8) + fitrange2;
				DBG(DBG_CONTROL, DBG_log("    is a match"));
				if (fitbits > bestfit_pr) {
					*best_tsi_i = tsi_ni;
					*best_tsr_i = tsr_ni;
					bestfit_pr = fitbits;
					DBG(DBG_CONTROL,
					    DBG_log(
						    "    and is a better fit tsi[%d] fitrange1 %d tsr[%d] fitrange2 %d fitbits %d",
						    *best_tsi_i,
						    fitrange1, *best_tsr_i,
						    fitrange2,
						    fitbits));
				} else {
					DBG(DBG_CONTROL,
					    DBG_log(
						    "    and is not a better fit tsi[%d] fitrange %d tsr[%d] fitrange2 %d fitbits %d",
						    *best_tsi_i,
						    fitrange1, *best_tsr_i,
						    fitrange2,
						    fitbits));
				}
			} else {
				DBG(DBG_CONTROL,
				    DBG_log("    is not a match"));
			}
		}
	}
	DBG(DBG_CONTROL, DBG_log("    protocol_fitnes  %d", bestfit_pr));
	return bestfit_pr;

}

int ikev2_evaluate_connection_port_fit(struct connection *d,
				       struct spd_route *sr,
				       enum phase1_role role,
				       struct traffic_selector *tsi,
				       struct traffic_selector *tsr,
				       unsigned int tsi_n,
				       unsigned int tsr_n,
				       unsigned int *best_tsi_i,
				       unsigned int *best_tsr_i)
{
	unsigned int tsi_ni, tsr_ni;
	int bestfit_p = -1;
	struct end *ei, *er;
	int narrowing = (d->policy & POLICY_IKEV2_ALLOW_NARROWING);

	if (role == INITIATOR) {
		ei = &sr->this;
		er = &sr->that;
	} else {
		ei = &sr->that;
		er = &sr->this;
	}
	/* compare tsi/r array to this/that, evaluating port ranges how well it fits */
	for (tsi_ni = 0; tsi_ni < tsi_n; tsi_ni++) {
		for (tsr_ni = 0; tsr_ni < tsr_n; tsr_ni++) {
			int fitrange1 = 0;
			int fitrange2 = 0;

			DBG(DBG_CONTROL,
			    DBG_log(
				    "ei->port %d  tsi[tsi_ni].startport %d  tsi[tsi_ni].endport %d narrowing=%s",
				    ei->port,
				    tsi[tsi_ni].startport, tsi[tsi_ni].endport,
				    (narrowing ? "yes" : "no")));

			if ((ei->port) &&
			    (( ei->port == tsi[tsi_ni].startport ) &&
			     (ei->port == tsi[tsi_ni].endport))) {
				fitrange1 = 1;
				DBG(DBG_CONTROL,
				    DBG_log(
					    "   tsi[%d] %d  ==  ei->port %d exact match single port  fitrange1 %d",
					    tsi_ni,
					    tsi[tsi_ni].startport, ei->port,
					    fitrange1));

			} else if ((!ei->port) &&
				   ( ( tsi[tsi_ni].startport == ei->port ) &&
				     (tsi[tsi_ni].endport == 65535 ))) {
				/* we are on range 0 - 64K  will alloow  only the same  with our without narrowing */
				fitrange1 =  65535;
				DBG(DBG_CONTROL,
				    DBG_log(
					    "   tsi[%d] %d-%d  ==  ei 0-65535 exact match all ports  fitrange1 %d",
					    tsi_ni,
					    tsi[tsi_ni].startport,
					    tsi[tsi_ni].endport,
					    fitrange1));
			} else if ( (role == INITIATOR) && narrowing &&
				    (!ei->port)) {
				DBG(DBG_CONTROL,
				    DBG_log(
					    "   narrowing=yes want to narrow ei->port 0-65355 to tsi[%d] %d-%d",
					    tsi_ni,
					    tsi[tsi_ni].startport,
					    tsi[tsi_ni].endport));
				if ( tsi[tsi_ni].startport <=
				     tsi[tsi_ni].endport ) {
					fitrange1 = 1 + tsi[tsi_ni].endport -
						    tsi[tsi_ni].startport;
					DBG(DBG_CONTROL,
					    DBG_log(
						    "  tsi[%d] %d-%d >= ei->port 0-65535 can be narrowed  fitrange1 %d",
						    tsi_ni,
						    tsi[tsi_ni].startport,
						    tsi[tsi_ni].endport,
						    fitrange1));
				} else {
					DBG(DBG_CONTROL,
					    DBG_log(
						    "   cant narrow tsi[%d] %d-%d to ei->port %d",
						    tsi_ni,
						    tsi[tsi_ni].startport,
						    tsi[tsi_ni].endport,
						    ei->port));
				}

			} else if ((role == RESPONDER) &&
				   ( narrowing  && ei->port) ) {
				DBG(DBG_CONTROL,
				    DBG_log(
					    "   narrowing=yes want to narrow ei->port %d to tsi[%d] %d-%d to",
					    ei->port, tsi_ni,
					    tsi[tsi_ni].startport,
					    tsi[tsi_ni].endport));
				if (( ei->port >= tsi[tsi_ni].startport ) &&
				    (ei->port <= tsi[tsi_ni].endport)) {
					fitrange1 = 1;
					DBG(DBG_CONTROL,
					    DBG_log(
						    "  tsi[%d] %d-%d >= ei->port 0-65535. can be narrowed  fitrange1 %d",
						    tsi_ni,
						    tsi[tsi_ni].startport,
						    tsi[tsi_ni].endport,
						    fitrange1));
				} else {
					DBG(DBG_CONTROL,
					    DBG_log(
						    "   cant narrow tsi[%d] %d-%d to ei->port %d",
						    tsi_ni,
						    tsi[tsi_ni].startport,
						    tsi[tsi_ni].endport,
						    ei->port));
				}

			} else {
				DBG(DBG_CONTROL,
				    DBG_log(
					    "  mismatch tsi[%d] %d-%d to ei->port %d",
					    tsi_ni,
					    tsi[tsi_ni].startport,
					    tsi[tsi_ni].endport,
					    ei->port));
			}

			if ((er->port) &&
			    (( er->port == tsr[tsr_ni].startport ) &&
			     (er->port == tsr[tsr_ni].endport))) {
				fitrange2 = 1;
				DBG(DBG_CONTROL,
				    DBG_log(
					    "   tsr[%d] %d  ==  er->port %d exact match single port fitrange2 %d",
					    tsr_ni,
					    tsr[tsr_ni].startport, er->port,
					    fitrange2));

			} else if ((!er->port) &&
				   ( ( tsr[tsr_ni].startport == er->port ) &&
				     (tsr[tsr_ni].endport == 65535 ))) {
				/* we are on range 0 - 64K  will alloow  only the same  with our without narrowing */
				fitrange2 =  65535;
				DBG(DBG_CONTROL,
				    DBG_log(
					    "   tsr[%d] %d-%d  ==  ei 0-65535 exact match all ports fitrange2 %d",
					    tsr_ni,
					    tsr[tsr_ni].startport,
					    tsr[tsr_ni].endport,
					    fitrange2));
			} else if ( (role == INITIATOR) && narrowing &&
				    (!er->port)) {
				DBG(DBG_CONTROL,
				    DBG_log(
					    "   narrowing=yes want to narrow ei->port 0-65355 to tsi[%d] %d-%d",
					    tsr_ni,
					    tsr[tsr_ni].startport,
					    tsr[tsr_ni].endport));
				if ( tsr[tsr_ni].startport <=
				     tsi[tsr_ni].endport ) {
					fitrange2 = 1 + tsr[tsr_ni].endport -
						    tsr[tsr_ni].startport;
					DBG(DBG_CONTROL,
					    DBG_log(
						    "  tsr[%d] %d-%d <= er->port 0-65535 can be narrowed  fitrange2 %d",
						    tsr_ni,
						    tsr[tsr_ni].startport,
						    tsr[tsr_ni].endport,
						    fitrange2));
				} else {
					DBG(DBG_CONTROL,
					    DBG_log(
						    "   cant narrow tsr[%d] %d-%d to er->port 0-65535",
						    tsr_ni,
						    tsr[tsr_ni].startport,
						    tsr[tsr_ni].endport));
				}

			} else if ((role == RESPONDER) &&  narrowing  &&
				   (er->port)) {
				DBG(DBG_CONTROL,
				    DBG_log(
					    "   narrowing=yes want to narrow ei->port 0-65535 to tsi[%d] %d-%d",
					    tsr_ni,
					    tsr[tsr_ni].startport,
					    tsr[tsr_ni].endport));
				if ((  er->port >= tsr[tsr_ni].startport ) &&
				    (er->port <= tsr[tsr_ni].endport)) {
					fitrange2 = 1;
					DBG(DBG_CONTROL,
					    DBG_log(
						    "  tsr[%d] %d-%d <= er->port %d can be narrowed fitrange2 %d",
						    tsr_ni,
						    tsr[tsr_ni].startport,
						    tsr[tsr_ni].endport,
						    er->port,
						    fitrange2));
				} else {
					DBG(DBG_CONTROL,
					    DBG_log(
						    "   can't narrow tsr[%d] %d-%d to er->port %d",
						    tsr_ni,
						    tsr[tsr_ni].startport,
						    tsr[tsr_ni].endport,
						    er->port));
				}
			} else {
				DBG(DBG_CONTROL,
				    DBG_log(
					    "  mismatch tsr[%d] %d-%d to er->port %d",
					    tsr_ni,
					    tsr[tsr_ni].startport,
					    tsr[tsr_ni].endport,
					    er->port));
			}

			int fitbits  = 0;
			if (fitrange1 && fitrange2) {
				fitbits = (fitrange1 << 8) + fitrange2;
				DBG(DBG_CONTROL, DBG_log("    is a match"));
				if (fitbits > bestfit_p) {
					*best_tsi_i = tsi_ni;
					*best_tsr_i = tsr_ni;
					bestfit_p = fitbits;
					DBG(DBG_CONTROL,
					    DBG_log(
						    "    and is a better fit tsi[%d] fitrange1 %d tsr[%d] fitrange2 %d fitbits %d",
						    *best_tsi_i,
						    fitrange1, *best_tsr_i,
						    fitrange2,
						    fitbits));
				} else {
					DBG(DBG_CONTROL,
					    DBG_log(
						    "    and is not a better fit tsi[%d] fitrange %d tsr[%d] fitrange2 %d fitbits %d",
						    *best_tsi_i,
						    fitrange1, *best_tsr_i,
						    fitrange2,
						    fitbits));
				}
			} else {
				DBG(DBG_CONTROL,
				    DBG_log("    is not a match"));
			}

		}
	}
	DBG(DBG_CONTROL, DBG_log("    port_fitness  %d", bestfit_p));
	return bestfit_p;
}

int ikev2_evaluate_connection_fit(struct connection *d,
				  struct spd_route *sr,
				  enum phase1_role role,
				  struct traffic_selector *tsi,
				  struct traffic_selector *tsr,
				  unsigned int tsi_n,
				  unsigned int tsr_n)
{
	unsigned int tsi_ni, tsr_ni;
	int bestfit = -1;
	struct end *ei, *er;

	if (role == INITIATOR) {
		ei = &sr->this;
		er = &sr->that;
	} else {
		ei = &sr->that;
		er = &sr->this;
	}

	DBG(DBG_CONTROLMORE,
	    {
		    char ei3[SUBNETTOT_BUF];
		    char er3[SUBNETTOT_BUF];
		    subnettot(&ei->client,  0, ei3, sizeof(ei3));
		    subnettot(&er->client,  0, er3, sizeof(er3));
		    DBG_log("  ikev2_evaluate_connection_fit evaluating our "
			    "I=%s:%s:%d/%d R=%s:%d/%d %s to their:",
			    d->name, ei3, ei->protocol, ei->port,
			    er3, er->protocol, er->port,
			    is_virtual_connection(d) ? "(virt)" : "");
	    }
	    );

	/* compare tsi/r array to this/that, evaluating how well it fits */
	for (tsi_ni = 0; tsi_ni < tsi_n; tsi_ni++) {
		for (tsr_ni = 0; tsr_ni < tsr_n; tsr_ni++) {
			/* does it fit at all? */

			DBG(DBG_CONTROLMORE,
			    {
				    char lbi[ADDRTOT_BUF];
				    char hbi[ADDRTOT_BUF];
				    char lbr[ADDRTOT_BUF];
				    char hbr[ADDRTOT_BUF];
				    addrtot(&tsi[tsi_ni].low,  0, lbi,
					    sizeof(lbi));
				    addrtot(&tsi[tsi_ni].high, 0, hbi,
					    sizeof(hbi));
				    addrtot(&tsr[tsr_ni].low,  0, lbr,
					    sizeof(lbr));
				    addrtot(&tsr[tsr_ni].high, 0, hbr,
					    sizeof(hbr));

				    DBG_log(
					    "    tsi[%u]=%s/%s proto=%d portrange %d-%d, tsr[%u]=%s/%s proto=%d portrange %d-%d",
					    tsi_ni, lbi, hbi,
					    tsi[tsi_ni].ipprotoid,
					    tsi[tsi_ni].startport,
					    tsi[tsi_ni].endport,
					    tsr_ni, lbr, hbr,
					    tsr[tsr_ni].ipprotoid,
					    tsr[tsr_ni].startport,
					    tsr[tsr_ni].endport);
			    }
			    );
			/* do addresses fit into the policy? */

			/*
			 * NOTE: Our parser/config only allows 1 CIDR, however IKEv2 ranges can be non-CIDR
			 *       for now we really support/limit ourselves to a single CIDR
			 */
			if (addrinsubnet(&tsi[tsi_ni].low, &ei->client) &&
			    addrinsubnet(&tsi[tsi_ni].high, &ei->client) &&
			    addrinsubnet(&tsr[tsr_ni].low,  &er->client) &&
			    addrinsubnet(&tsr[tsr_ni].high, &er->client)
			    ) {
				/*
				 * now, how good a fit is it? --- sum of bits gives
				 * how good a fit this is.
				 */
				int ts_range1 =
					ikev2_calc_iprangediff(tsi[tsi_ni].low,
							       tsi[
								       tsi_ni].high);
				int maskbits1 = ei->client.maskbits;
				int fitbits1  = maskbits1 + ts_range1;

				int ts_range2 =
					ikev2_calc_iprangediff(tsr[tsr_ni].low,
							       tsr[
								       tsr_ni].high);
				int maskbits2 = er->client.maskbits;
				int fitbits2  = maskbits2 + ts_range2;
				int fitbits = (fitbits1 << 8) + fitbits2;

				/*
				 * comparing for ports
				 * for finding better local polcy
				 */
				DBG(DBG_CONTROL,
				    DBG_log(
					    "ei->port %d  tsi[tsi_ni].startport %d  tsi[tsi_ni].endport %d",
					    ei->port,
					    tsi[tsi_ni].startport,
					    tsi[tsi_ni].endport));
				if ( ei->port &&
				     (tsi[tsi_ni].startport == ei->port &&
				      tsi[tsi_ni].endport == ei->port))
					fitbits = fitbits << 1;

				if ( er->port &&
				     (tsr[tsr_ni].startport == er->port &&
				      tsr[tsr_ni].endport == er->port))
					fitbits = fitbits << 1;

				DBG(DBG_CONTROLMORE,
				    {
					    DBG_log(
						    "      has ts_range1=%u maskbits1=%u ts_range2=%u maskbits2=%u fitbits=%d <> %d",
						    ts_range1, maskbits1,
						    ts_range2, maskbits2,
						    fitbits, bestfit);
				    }
				    );

				if (fitbits > bestfit)
					bestfit = fitbits;
			}
		}
	}

	return bestfit;
}

stf_status ikev2_child_sa_respond(struct msg_digest *md,
				  enum phase1_role role,
				  pb_stream *outpbs)
{
	struct state      *st = md->st;
	struct state      *st1;
	struct connection *c  = st->st_connection;
	/* struct connection *cb; */
	struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_v2SA];
	stf_status ret;
	struct payload_digest *const tsi_pd = md->chain[ISAKMP_NEXT_v2TSi];
	struct payload_digest *const tsr_pd = md->chain[ISAKMP_NEXT_v2TSr];
	struct traffic_selector tsi[16], tsr[16];
	unsigned int tsi_n, tsr_n;

	/*
	 * now look at provided TSx, and see if these fit the connection
	 * that we have, and narrow them if necessary.
	 */
	tsi_n = ikev2_parse_ts(tsi_pd, tsi, 16);
	tsr_n = ikev2_parse_ts(tsr_pd, tsr, 16);

	/*
	 * now walk through all connections and see if this connection
	 * was in fact the best.
	 *
	 * similar to find_client_connection/fc_try.
	 */
	{
		struct connection *b = c;
		struct connection *d;
		int bestfit_n, newfit, bestfit_p, bestfit_pr;
		struct spd_route *sra, *bsr;
		struct host_pair *hp = NULL;
		unsigned int best_tsi_i,  best_tsr_i;

		bsr = NULL;
		bestfit_n = -1;
		bestfit_p = -1;
		bestfit_pr = -1,
		best_tsi_i =  best_tsr_i = -1;

		for (sra = &c->spd; sra != NULL; sra = sra->next) {
			int bfit_n = ikev2_evaluate_connection_fit(c, sra,
								   role, tsi,
								   tsr, tsi_n,
								   tsr_n);
			if (bfit_n > bestfit_n) {
				DBG(DBG_CONTROLMORE,
				    DBG_log(
					    "bfit_n=ikev2_evaluate_connection_fit found better fit c %s",
					    c->name));
				int bfit_p =
					ikev2_evaluate_connection_port_fit(c,
									   sra,
									   role, tsi,
									   tsr,
									   tsi_n, tsr_n, &best_tsi_i,
									   &best_tsr_i);
				if (bfit_p > bestfit_p) {
					DBG(DBG_CONTROLMORE,
					    DBG_log(
						    "ikev2_evaluate_connection_port_fit found better fit c %s, tsi[%d],tsr[%d]",
						    c->name,
						    best_tsi_i, best_tsr_i));
					int bfit_pr =
						ikev2_evaluate_connection_protocol_fit(
							c, sra, role, tsi, tsr,
							tsi_n,
							tsr_n, &best_tsi_i,
							&best_tsr_i);
					if (bfit_pr > bestfit_pr ) {
						DBG(DBG_CONTROLMORE,
						    DBG_log(
							    "ikev2_evaluate_connection_protocol_fit found better fit c %s, tsi[%d],tsr[%d]",
							    c
							    ->name, best_tsi_i,
							    best_tsr_i));

						bestfit_p = bfit_p;
						bestfit_n = bfit_n;
						b = c;
						bsr = sra;
					} else {
						DBG(DBG_CONTROLMORE,
						    DBG_log(
							    "protocol range fit c %s c->name was rejected by protocol matching",
							    c
							    ->name));
					}
				}
			} else {
				DBG(DBG_CONTROLMORE,
				    DBG_log(
					    "prefix range fit c %s c->name was rejected by port matching",
					    c->name));
			}
		}

		for (sra = &c->spd; hp == NULL && sra != NULL; sra =
			     sra->next) {
			hp = find_host_pair(&sra->this.host_addr,
					    sra->this.host_port,
					    &sra->that.host_addr,
					    sra->that.host_port);

#ifdef DEBUG
			if (DBGP(DBG_CONTROLMORE)) {
				char s2[SUBNETTOT_BUF], d2[SUBNETTOT_BUF];

				subnettot(&sra->this.client, 0, s2,
					  sizeof(s2));
				subnettot(&sra->that.client, 0, d2,
					  sizeof(d2));

				DBG_log("  checking hostpair %s -> %s is %s",
					s2, d2,
					(hp ? "found" : "not found"));
			}
#endif                  /* DEBUG */

			if (!hp)
				continue;

			for (d = hp->connections; d != NULL; d = d->hp_next) {
				struct spd_route *sr;
				int wildcards, pathlen; /* XXX */

				if (d->policy & POLICY_GROUP)
					continue;

				if (!(same_id(&c->spd.this.id,
					      &d->spd.this.id) &&
				      match_id(&c->spd.that.id,
					       &d->spd.that.id, &wildcards) &&
				      trusted_ca(c->spd.that.ca,
						 d->spd.that.ca, &pathlen)))
					continue;
				for (sr = &d->spd; sr != NULL; sr = sr->next) {
					newfit = ikev2_evaluate_connection_fit(
						d, sr, role,
						tsi, tsr, tsi_n,
						tsr_n);
					if (newfit > bestfit_n) { /* will complicated this with narrowing */
						DBG(DBG_CONTROLMORE,
						    DBG_log(
							    "bfit=ikev2_evaluate_connection_fit found better fit d %s",
							    d->name));
						int bfit_p =
							ikev2_evaluate_connection_port_fit(
								d, sra, role,
								tsi, tsr,
								tsi_n, tsr_n,
								&best_tsi_i,
								&best_tsr_i);
						if (bfit_p > bestfit_p) {
							DBG(DBG_CONTROLMORE, DBG_log(
								    "ikev2_evaluate_connection_port_fit found better fit d %s, tsi[%d],tsr[%d]",
								    d
								    ->name,
								    best_tsi_i,
								    best_tsr_i));
							int bfit_pr =
								ikev2_evaluate_connection_protocol_fit(
									d, sra,
									role,
									tsi,
									tsr,
									tsi_n,
									tsr_n,
									&best_tsi_i,
									&best_tsr_i);
							if (bfit_pr >
							    bestfit_pr ) {
								DBG(
									DBG_CONTROLMORE,
									DBG_log(
										"ikev2_evaluate_connection_protocol_fit found better fit d %s, tsi[%d],tsr[%d]",
										d
										->
										name,
										best_tsi_i,
										best_tsr_i));

								bestfit_p =
									bfit_p;
								bestfit_n =
									newfit;
								b = d;
								bsr = sr;
							} else {
								DBG(
									DBG_CONTROLMORE,
									DBG_log(
										"protocol range fit d %s c->name was rejected by protocol matching",
										d
										->
										name));
							}
						}
					} else {
						DBG(DBG_CONTROLMORE,
						    DBG_log(
							    "prefix range fit d %s d->name was rejected by port matching",
							    d->name));
					}
				}
			}
		}

		/*
		 * now that we have found the best connection, copy the data into
		 * the state structure as the tsi/tsr
		 *
		 */

		/*better connection*/
		c = b;

		/* Paul: should we STF_FAIL here instead of checking for NULL */
		if (bsr != NULL) {
			st1 = duplicate_state(st);
			insert_state(st1); /* needed for delete - we should never have duplicated before we were sure */

			if (role == INITIATOR) {
				memcpy(&st1->st_ts_this, &tsi[best_tsi_i],
				       sizeof(struct traffic_selector));
				memcpy(&st1->st_ts_that, &tsr[best_tsr_i],
				       sizeof(struct traffic_selector));
			} else {
				st1->st_ts_this = ikev2_end_to_ts(&bsr->this);
				st1->st_ts_that = ikev2_end_to_ts(&bsr->that);
			}
			ikev2_print_ts(&st1->st_ts_this);
			ikev2_print_ts(&st1->st_ts_that);
		} else {
			if (role == INITIATOR)
				return STF_FAIL;
			else
				return STF_FAIL + v2N_NO_PROPOSAL_CHOSEN;
		}
	}

	st1->st_connection = c;
	md->st = st1;
	md->pst = st;

	/* start of SA out */
	{
		struct isakmp_sa r_sa = sa_pd->payload.sa;
		notification_t rn;
		pb_stream r_sa_pbs;

		r_sa.isasa_np = ISAKMP_NEXT_v2TSi;
		if (!out_struct(&r_sa, &ikev2_sa_desc, outpbs, &r_sa_pbs))
			return STF_INTERNAL_ERROR;

		/* SA body in and out */
		rn = ikev2_parse_child_sa_body(&sa_pd->pbs,
					       &sa_pd->payload.v2sa,
					       &r_sa_pbs, st1, FALSE);

		if (rn != NOTHING_WRONG)
			return STF_FAIL + rn; /* should we delete_state st1? */
	}

	ret = ikev2_calc_emit_ts(md, outpbs, role,
				 c, c->policy);
	if (ret != STF_OK)
		return ret;           /* should we delete_state st1? */

	if ( role == RESPONDER ) {
		chunk_t child_spi, notifiy_data;
		struct payload_digest *p;
		for (p = md->chain[ISAKMP_NEXT_v2N]; p != NULL; p = p->next) {
			if ( p->payload.v2n.isan_type ==
			     v2N_USE_TRANSPORT_MODE ) {

				if (st1->st_connection->policy &
				    POLICY_TUNNEL) {
					DBG_log(
						"Although local policy is tunnel, received USE_TRANSPORT_MODE");
					DBG_log(
						"So switching to transport mode, and responding with USE_TRANSPORT_MODE notify");
				} else {
					DBG_log(
						"Local policy is transport, received USE_TRANSPORT_MODE");
					DBG_log(
						"Now responding with USE_TRANSPORT_MODE notify");
				}

				memset(&child_spi, 0, sizeof(child_spi));
				memset(&notifiy_data, 0, sizeof(notifiy_data));
				ship_v2N(ISAKMP_NEXT_v2NONE,
					 ISAKMP_PAYLOAD_NONCRITICAL,
				         /*PROTO_ISAKMP*/ 0,
					 &child_spi,
					 v2N_USE_TRANSPORT_MODE, &notifiy_data,
					 outpbs);

				if (st1->st_esp.present == TRUE) {
					/*libreswan supports only "esp" with ikev2 it seems, look at ikev2_parse_child_sa_body handling*/
					st1->st_esp.attrs.encapsulation =
						ENCAPSULATION_MODE_TRANSPORT;
				}
				break;
			}
		}
	}

	ikev2_derive_child_keys(st1, role);
	/* install inbound and outbound SPI info */
	if (!install_ipsec_sa(st1, TRUE))
		return STF_FATAL;

	/* mark the connection as now having an IPsec SA associated with it. */
	st1->st_connection->newest_ipsec_sa = st1->st_serialno;

	return STF_OK;
}
