/* Libreswan NAT-Traversal
 *
 * Copyright (C) 2002-2003 Mathieu Lafon - Arkoon Network Security
 * Copyright (C) 2005-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2005 Ken Bantoft <ken@xelerance.com>
 * Copyright (C) 2006 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2007-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2009 Gilles Espinasse <g.esp@free.fr>
 * Copyright (C) 2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2011 Shinichi Furuso <Shinichi.Furuso@jp.sony.com>
 * Copyright (C) 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2014 Antony Antony <antony@phenome.org>
 * Copyright (C) 2019 Andrew Cagney <cagney@gnu.org>
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

#include "defs.h"
#include "log.h"
#include "state.h"
#include "nat_traversal.h"
#include "connections.h"
#include "ike_alg.h"
#include "ike_alg_hash.h"
#include "crypt_hash.h"
#include "ip_info.h"
#include "send.h"
#include "iface.h"
#include "state_db.h"

/* As per https://tools.ietf.org/html/rfc3948#section-4 */
#define DEFAULT_KEEP_ALIVE_SECS  20

bool nat_traversal_enabled = TRUE; /* can get disabled if kernel lacks support */

static deltatime_t nat_kap = DELTATIME_INIT(DEFAULT_KEEP_ALIVE_SECS);	/* keep-alive period */
static bool nat_kap_event = FALSE;

void init_nat_traversal(deltatime_t keep_alive_period, struct logger *logger)
{
	if (deltamillisecs(keep_alive_period) != 0)
		nat_kap = keep_alive_period;

	dbg("init_nat_traversal() initialized with keep_alive=%jds",
	    deltasecs(keep_alive_period));
	llog(RC_LOG, logger, "NAT-Traversal support %s",
		    nat_traversal_enabled ? " [enabled]" : " [disabled]");

	init_oneshot_timer(EVENT_NAT_T_KEEPALIVE, nat_traversal_ka_event);
}

struct crypt_mac natd_hash(const struct hash_desc *hasher,
			   const ike_spis_t *spis,
			   const ip_endpoint endpoint,
			   struct logger *logger)
{
	/* only responder's IKE SPI can be zero */
	if (ike_spi_is_zero(&spis->initiator)) {
		dbg("nat: IKE.SPIi is unexpectedly zero");
		pexpect(impair.ike_initiator_spi-1/*1-bias*/ == 0);
	}
	if (ike_spi_is_zero(&spis->responder)) {
		/* IKE_SA_INIT exchange */
		dbg("nat: IKE.SPIr is zero");
	}

	/*
	 * RFC 3947
	 *
	 *   HASH = HASH(IKE.SPIi | IKE.SPIr | IP | Port)
	 *
	 * All values in network order
	 */
	struct crypt_hash *ctx = crypt_hash_init("NATD", hasher, logger);

	crypt_hash_digest_thing(ctx, "IKE SPIi", spis->initiator);
	crypt_hash_digest_thing(ctx, "IKE SPIr", spis->responder);

	ip_address ip = endpoint_address(endpoint);
	shunk_t ap = address_as_shunk(&ip);
	crypt_hash_digest_hunk(ctx, "IP addr", ap);

	uint16_t np = nport(endpoint_port(endpoint));
	crypt_hash_digest_thing(ctx, "PORT", np);
	struct crypt_mac hash = crypt_hash_final_mac(&ctx);

	if (DBGP(DBG_BASE)) {
		DBG_log("natd_hash: hasher=%p(%d)", hasher,
			(int)hasher->hash_digest_size);
		DBG_dump_thing("natd_hash: icookie=", spis->initiator);
		DBG_dump_thing("natd_hash: rcookie=", spis->responder);
		DBG_dump_hunk("natd_hash: ip=", ap);
		DBG_dump_thing("natd_hash: port=", np);
		DBG_dump_hunk("natd_hash: hash=", hash);
	}
	return hash;
}

void natd_lookup_common(struct state *st,
			const ip_endpoint sender,
			bool found_me, bool found_peer)
{
	st->hidden_variables.st_natd = ipv4_info.address.any;

	/* update NAT-T settings for local policy */
	switch (st->st_connection->encaps) {
	case yna_auto:
		dbg("NAT_TRAVERSAL encaps using auto-detect");
		if (!found_me) {
			dbg("NAT_TRAVERSAL this end is behind NAT");
			st->hidden_variables.st_nat_traversal |= LELEM(NATED_HOST);
			st->hidden_variables.st_natd = endpoint_address(sender);
		} else {
			dbg("NAT_TRAVERSAL this end is NOT behind NAT");
		}

		if (!found_peer) {
			endpoint_buf b;
			dbg("NAT_TRAVERSAL that end is behind NAT %s",
			    str_endpoint(&sender, &b));
			st->hidden_variables.st_nat_traversal |= LELEM(NATED_PEER);
			st->hidden_variables.st_natd = endpoint_address(sender);
		} else {
			dbg("NAT_TRAVERSAL that end is NOT behind NAT");
		}
		break;

	case yna_no:
		st->hidden_variables.st_nat_traversal |= LEMPTY;
		dbg("NAT_TRAVERSAL local policy prohibits encapsulation");
		break;

	case yna_yes:
		dbg("NAT_TRAVERSAL local policy enforces encapsulation");
		dbg("NAT_TRAVERSAL forceencaps enabled");
		st->hidden_variables.st_nat_traversal |=
			LELEM(NATED_PEER) | LELEM(NATED_HOST);
		st->hidden_variables.st_natd = endpoint_address(sender);
		break;
	}

	if (st->st_connection->nat_keepalive) {
		endpoint_buf b;
		dbg("NAT_TRAVERSAL nat-keepalive enabled %s", str_endpoint(&sender, &b));
	}
}

void nat_traversal_new_ka_event(void)
{
	if (nat_kap_event)
		return;	/* Event already schedule */

	schedule_oneshot_timer(EVENT_NAT_T_KEEPALIVE, nat_kap);
	nat_kap_event = TRUE;
}

static void nat_traversal_send_ka(struct state *st)
{
	endpoint_buf b;
	dbg("ka_event: send NAT-KA to %s (state=#%lu)",
	    str_endpoint(&st->st_remote_endpoint, &b),
	    st->st_serialno);

	/* send keep alive */
	dbg("sending NAT-T Keep Alive");
	send_keepalive_using_state(st, "NAT-T Keep Alive");
}

/*
 * Find ISAKMP States with NAT-T and send keep-alive
 */
static void nat_traversal_ka_event_state(struct state *st, void *data)
{
	unsigned int *nat_kap_st = (unsigned int *)data;
	const struct connection *c = st->st_connection;

	if (!LHAS(st->hidden_variables.st_nat_traversal, NATED_HOST)) {
		dbg("not behind NAT: no NAT-T KEEP-ALIVE required for conn %s",
		    c->name);
		return;
	}

	if (!c->nat_keepalive) {
		dbg("Suppressing sending of NAT-T KEEP-ALIVE for conn %s (nat-keepalive=no)",
		    c->name);
		return;
	}
	/* XXX: .st_interface, not c.interface - can be different */
	if (!st->st_interface->io->send_keepalive) {
		dbg("skipping NAT-T KEEP-ALIVE: #%lu does not need it for %s protocol",
		    st->st_serialno, st->st_interface->protocol->name);
		return;
	}
	if (c->newest_ike_sa != st->st_serialno) {
		dbg("skipping NAT-T KEEP-ALIVE: #%lu is not current IKE SA", st->st_serialno);
		return;
	}

	/*
	 * As long as we don't check get_sa_info() in IPsec SA's, and for
	 * IKEv1 IPsec SA's always send a keepalive, we might as well
	 * _not_ send keepalives for IKEv1 IKE SA's.
	 *
	 * XXX: IKEv2?
	 */

	switch (st->st_ike_version) {
	case IKEv2:
		/*
		 * - IKE SA established
		 * - we are behind NAT
		 * - NAT-KeepAlive needed (we are NATed)
		 */
		if (!IS_IKE_SA_ESTABLISHED(st)) {
			dbg("skipping NAT-T KEEP-ALIVE: #%lu is not established", st->st_serialno);
			return;
		}

		/*
		 * If this IKE SA sent a packet recently, no need for
		 * anything eg, if short DPD timers are used we can
		 * skip this.
		 */
		if (!is_monotime_epoch(st->st_last_liveness) &&
		    deltasecs(monotimediff(mononow(), st->st_last_liveness)) < DEFAULT_KEEP_ALIVE_SECS)
		{
			dbg("NAT-T KEEP-ALIVE packet not required as recent DPD event used the IKE SA on conn %s",
			    c->name);
			return;
		}

		/*
		 * TODO or not?
		 *
		 * We could also check If there is IPsec SA
		 * encapsulation traffic, since then we also do not
		 * need to send keepalives, but that check is a little
		 * expensive as we have to find some/all IPsec states
		 * and ask the kernel, every 20s.
		 */
		dbg("we are behind NAT: sending of NAT-T KEEP-ALIVE for conn %s",
		    c->name);

		(*nat_kap_st)++;
		nat_traversal_send_ka(st);
		return;

#ifdef USE_IKEv1
	case IKEv1:
		/*
		 * IKE SA and IPsec SA keepalives happen over the same port/NAT mapping.
		 * If the IKE SA is idle and triggers keepalives, we don't need to check
		 * IPsec SA's being idle. If we were to check IPsec SA, we could then
		 * also update the IKE SA st->st_last_liveness, but we think this is
		 * too expensive (call get_sa_info() to kernel _and_ find IKE SA.
		 *
		 * For IKEv2, just use the one IKE SA instead of the one or more IPsec SA's
		 * (and ignore whether IPsec SA was active or not)
		 *
		 * for IKEv1, there can be orphan IPsec SA's. We still are not checking
		 * the kernel, so we just have to always send the keepalive.
		 */
		if (!IS_IPSEC_SA_ESTABLISHED(st)) {
			dbg("skipping NAT-T KEEP-ALIVE: #%lu is not established", st->st_serialno);
			return;
		}
		nat_traversal_send_ka(st);
		(*nat_kap_st)++;
		return;
#endif
	default:
		bad_case(st->st_ike_version);
	}
}

void nat_traversal_ka_event(struct logger *unused_logger UNUSED)
{
	unsigned int nat_kap_st = 0;

	nat_kap_event = FALSE;  /* ready to be reschedule */

	for_each_state(nat_traversal_ka_event_state, &nat_kap_st, __func__);

	if (nat_kap_st != 0) {
		/*
		 * If there are still states who needs Keep-Alive,
		 * schedule new event
		 */
		nat_traversal_new_ka_event();
	}
}

/*
 * Re-map entire family.
 *
 * In IKEv1 this code needs to handle orphans - the children are
 * around but the IKE (ISAKMP) SA is gone.
 */

struct new_mapp_nfo {
	so_serial_t clonedfrom;
	const ip_endpoint new_remote_endpoint;
};

static bool nat_traversal_update_family_mapp_state(struct state *st, void *data)
{
	struct new_mapp_nfo *nfo = data;
	if (pexpect(st->st_serialno == nfo->clonedfrom /*parent*/ ||
		    st->st_clonedfrom == nfo->clonedfrom /*sibling*/)) {
		endpoint_buf b1;
		endpoint_buf b2;
		ip_endpoint st_remote_endpoint = st->st_remote_endpoint;
		dbg("new NAT mapping for #%lu, was %s, now %s",
		    st->st_serialno,
		    str_endpoint(&st_remote_endpoint, &b1),
		    str_endpoint(&nfo->new_remote_endpoint, &b2));

		/* update it */
		st->st_remote_endpoint = nfo->new_remote_endpoint;
		st->hidden_variables.st_natd = endpoint_address(nfo->new_remote_endpoint);
		struct connection *c = st->st_connection;
		if (c->kind == CK_INSTANCE)
			c->spd.that.host_addr = endpoint_address(nfo->new_remote_endpoint);
	}
	return false; /* search for more */
}

/*
 * this should only be called after packet has been
 * verified/authenticated! (XXX: IKEv1?)
 *
 * XXX: Is this solving an IKEv1 only problem?  IKEv2 only needs to
 * update the IKE SA and seems to do it using update_ike_endpoints().
 */

void nat_traversal_change_port_lookup(struct msg_digest *md, struct state *st)
{
	pexpect_st_local_endpoint(st);

	if (st == NULL)
		return;

	if (st->st_interface->protocol == &ip_protocol_tcp ||
	    (md != NULL && md->iface->protocol == &ip_protocol_tcp)) {
		/* XXX: when is MD NULL? */
		return;
	}

	if (md != NULL) {

		/*
		 * If source port/address has changed, update the family.
		 *
		 * Since IKEv1 allows orphans - parent deleted but
		 * children live on.
		 */
		if (!endpoint_eq_endpoint(md->sender, st->st_remote_endpoint)) {
			struct new_mapp_nfo nfo = {
				.clonedfrom = (st->st_clonedfrom != SOS_NOBODY ? st->st_clonedfrom : st->st_serialno),
				.new_remote_endpoint = md->sender,
			};
			state_by_ike_spis(st->st_ike_version,
					  NULL /* clonedfrom */,
					  NULL /* v1_msgid */,
					  NULL /* role */,
					  &st->st_ike_spis,
					  nat_traversal_update_family_mapp_state,
					  &nfo,
					  __func__);
		}

		/*
		 * If interface type has changed, update local port (500/4500)
		 */
		if (md->iface != st->st_interface) {
			endpoint_buf b1, b2;
			dbg("NAT-T: #%lu updating local interface from %s to %s (using md->iface in %s())",
			    st->st_serialno,
			    str_endpoint(&st->st_interface->local_endpoint, &b1),
			    str_endpoint(&md->iface->local_endpoint, &b2), __func__);
			st->st_interface = md->iface;
		}
	}
	pexpect_st_local_endpoint(st);
}

void show_setup_natt(struct show *s)
{
	show_separator(s);
	show_comment(s, "nat-traversal=%s, keep-alive=%ld, nat-ikeport=%d",
		     bool_str(nat_traversal_enabled),
		     (long) deltasecs(nat_kap),
		     NAT_IKE_UDP_PORT);
}
