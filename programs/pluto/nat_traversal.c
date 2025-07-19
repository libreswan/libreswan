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
#include "state_db.h"		/* for state_by_ike_spis() */
#include "show.h"

/* As per https://tools.ietf.org/html/rfc3948#section-4 */
#define DEFAULT_KEEP_ALIVE_SECS  20

deltatime_t nat_keepalive_period = DELTATIME_INIT(DEFAULT_KEEP_ALIVE_SECS);

void init_nat_traversal_timer(deltatime_t keep_alive, struct logger *logger)
{
	if (keep_alive.is_set) {
		/* truncate */
		if (deltatime_cmp(keep_alive, <, one_second)) {
			deltatime_buf db;
			llog(RC_LOG, logger,
			     "NAT-Traversal: ignoring too small keep-alive period %s (less than 1 second)",
			     str_deltatime(keep_alive, &db));
		} else if (deltatime_cmp(keep_alive, >, one_day)) {
			deltatime_buf db;
			llog(RC_LOG, logger,
			     "NAT-Traversal: ignoring too big keep-alive period %s (more than 1 day)",
			     str_deltatime(keep_alive, &db));
		} else {
			nat_keepalive_period = keep_alive;
		}
	}

	deltatime_buf db;
	llog(RC_LOG, logger, "NAT-Traversal: keep-alive period %ss",
	     str_deltatime(nat_keepalive_period, &db));
}

struct crypt_mac natd_hash(const struct hash_desc *hasher,
			   const ike_spis_t *spis,
			   const ip_endpoint endpoint,
			   struct logger *logger)
{
	/* only responder's IKE SPI can be zero */
	if (ike_spi_is_zero(&spis->initiator)) {
		dbg("nat: IKE.SPIi is unexpectedly zero");
		/* presumably because it was impaired?!? */
		pexpect(impair.ike_initiator_spi.enabled &&
			impair.ike_initiator_spi.value == 0);
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

	if (LDBGP(DBG_BASE, logger)) {
		LDBG_log(logger, "natd_hash: hasher=%p(%d)", hasher,
			 (int)hasher->hash_digest_size);
		LDBG_log(logger, "icookie:"); LDBG_thing(logger, spis->initiator);
		LDBG_log(logger, "rcookie:"); LDBG_thing(logger, spis->responder);
		LDBG_log(logger, "ip:"); LDBG_thing(logger, ap);
		LDBG_log(logger, "port:"); LDBG_thing(logger, np);
		LDBG_log(logger, "hash:"); LDBG_thing(logger, hash);
	}
	return hash;
}

void natd_lookup_common(struct state *st,
			const ip_endpoint sender,
			bool found_me, bool found_peer)
{
	st->hidden_variables.st_natd = ipv4_info.address.zero;

	/* update NAT-T settings for local policy */
	switch (st->st_connection->config->encapsulation) {
	case YNA_UNSET:
	case YNA_AUTO:
		dbg("NAT_TRAVERSAL encaps using auto-detect");
		if (!found_me) {
			dbg("NAT_TRAVERSAL this end is behind NAT");
			st->hidden_variables.st_nated_host = true;
			st->hidden_variables.st_natd = endpoint_address(sender);
		} else {
			dbg("NAT_TRAVERSAL this end is NOT behind NAT");
		}

		if (!found_peer) {
			endpoint_buf b;
			dbg("NAT_TRAVERSAL that end is behind NAT %s",
			    str_endpoint(&sender, &b));
			st->hidden_variables.st_nated_peer = true;
			st->hidden_variables.st_natd = endpoint_address(sender);
		} else {
			dbg("NAT_TRAVERSAL that end is NOT behind NAT");
		}
		break;

	case YNA_NO:
		st->hidden_variables.st_nat_traversal |= LEMPTY;
		dbg("NAT_TRAVERSAL local policy prohibits encapsulation");
		break;

	case YNA_YES:
		ldbg(st->logger, "NAT_TRAVERSAL local policy enforces encapsulation");
		st->hidden_variables.st_nated_peer = true;
		st->hidden_variables.st_nated_host = true;
		st->hidden_variables.st_natd = endpoint_address(sender);
		break;
	}

	if (st->st_connection->config->nat_keepalive) {
		endpoint_buf b;
		dbg("NAT_TRAVERSAL nat-keepalive enabled %s", str_endpoint(&sender, &b));
	}
}

bool nat_traversal_detected(struct state *st)
{
	return (st->hidden_variables.st_nated_host ||
		st->hidden_variables.st_nated_peer);
}

static void nat_traversal_send_ka(struct state *st)
{
	endpoint_buf b;
	ldbg(st->logger, "ka_event: send NAT-KA to %s (state="PRI_SO")",
	     str_endpoint(&st->st_remote_endpoint, &b),
	     pri_so(st->st_serialno));

	/* send keep alive */
	ldbg(st->logger, "sending NAT-T Keep Alive");
	send_keepalive_using_state(st, "NAT-T Keep Alive");
}

/*
 * Find ISAKMP States with NAT-T and send keep-alive
 */

static bool need_nat_keepalive(struct state *st)
{
	const struct connection *c = st->st_connection;

	if (!c->config->nat_keepalive) {
		pdbg(st->logger, "NAT-keep-alive: not scheduled, nat-keepalive=no)");
		return false;
	}

	if (!st->hidden_variables.st_nated_host) {
		pdbg(st->logger, "NAT-keep-alive: not scheduled, not behind NAT");
		return false;
	}

	/* XXX: .st_iface_endpoint, not c.interface - can be different */
	if (!st->st_iface_endpoint->io->send_keepalive) {
		pdbg(st->logger, "NAT-keep-alive: not scheduled, needed by %s protocol",
		     st->st_iface_endpoint->io->protocol->name);
		return false;
	}

	return true;
}

void schedule_v1_nat_keepalive(struct state *st)
{
	if (!need_nat_keepalive(st)) {
		return;
	}

	pdbg(st->logger, "NAT-keep-alive: scheduled, period %jds",
	     deltasecs(nat_keepalive_period));
	event_schedule(EVENT_v1_NAT_KEEPALIVE, nat_keepalive_period, st);
}


void schedule_v2_nat_keepalive(struct ike_sa *ike, where_t where)
{
	if (!need_nat_keepalive(&ike->sa)) {
		/* already logged */
		return;
	}

	/*
	 * In IKEv2 all messages go through the established IKE SA.
	 * Hence, expect this to be established, at least when first
	 * scheduling the timer.
	 *
	 * However, the responder calls this code early (before
	 * processing child payloads), which means it is not
	 * established.
	 */
	if (!IS_IKE_SA_ESTABLISHED(&ike->sa)) {
		pdbg(ike->sa.logger, "NAT-keep-alive: allowing non-established IKE SA when scheduling (responder yet to process Child payloads?) "PRI_WHERE,
		     pri_where(where));
	}

	/*
	 * crossing-streams can result in this established IKE SA is
	 * not being the most current.  That's OK.  Need to still keep
	 * NAT open so it can later shutdown.
	 */
	if (ike->sa.st_connection->established_ike_sa != ike->sa.st_serialno) {
		pdbg(ike->sa.logger, "NAT-keep-alive: allowing IKE SA crossing-stream with "PRI_SO" when scheduling "PRI_WHERE,
		     pri_so(ike->sa.st_connection->established_ike_sa),
		     pri_where(where));
	}

	pdbg(ike->sa.logger, "NAT-keep-alive: scheduled, period %jds",
	     deltasecs(nat_keepalive_period));
	event_schedule(EVENT_v2_NAT_KEEPALIVE, nat_keepalive_period, &ike->sa);
}

#ifdef USE_IKEv1
void event_v1_nat_keepalive(struct state *st)
{
	const struct connection *c = st->st_connection;
	/*
	 * For IKEv1, there can be orphaned IPsec SA's.  Since we are
	 * not checking the kernel we just have to always send the
	 * keepalive for all IPsec SAs.
	 *
	 * Older comment providing some backstory:
	 *
	 * ISAKMP SA and IPsec SA keepalives happen over the same
	 * port/NAT mapping.  If the ISAKMP SA is idle and triggers
	 * keepalives, we don't need to check IPsec SA's being idle.
	 * If we were to check IPsec SA, we could then also update the
	 * ISAKMP SA, but we think this is too expensive (call
	 * get_sa_bundle_info() to kernel _and_ find ISAKMP SA.
	 */
	if (!IS_IPSEC_SA_ESTABLISHED(st)) {
		pdbg(st->logger, "NAT-keep-alive: IPsec SA is not established");
		return;
	}

	if (c->established_child_sa != st->st_serialno) {
		pdbg(st->logger, "NAT-keep-alive: IPsec SA is not the current SA ("PRI_SO")",
		     pri_so(c->established_child_sa));
		return;
	}

	pdbg(st->logger, "NAT-keep-alive: sending keep-alive");
	nat_traversal_send_ka(st);
}
#endif

void event_v2_nat_keepalive(struct ike_sa *ike)
{
	const struct connection *c = ike->sa.st_connection;

	/*
	 * In IKEv2 all messages go through the IKE SA.  Hence check
	 * its timers.
	 */
	if (!IS_IKE_SA_ESTABLISHED(&ike->sa)) {
		pdbg(ike->sa.logger, "NAT-keep-alive: skipping send, as IKE SA is not established");
		return;
	}

	if (c->established_ike_sa != ike->sa.st_serialno) {
		pdbg(ike->sa.logger, "NAT-keep-alive: skipping send, IKE SA is not current ("PRI_SO")",
		     pri_so(c->established_ike_sa));
		return;
	}

	/*
	 * If this IKE SA sent a packet recently, no need for anything
	 * eg, if short LIVENESS timers are used we can skip this.
	 */
	if (!is_monotime_epoch(ike->sa.st_v2_msgid_windows.last_sent) &&
	    deltasecs(monotime_diff(mononow(), ike->sa.st_v2_msgid_windows.last_sent)) < DEFAULT_KEEP_ALIVE_SECS) {
		pdbg(ike->sa.logger, "NAT-keep-alive: skipping send, IKE SA recently sent a request");
		return;
	}

	/*
	 * TODO or not?
	 *
	 * We could also check If there is IPsec SA encapsulation
	 * traffic, since then we also do not need to send keepalives,
	 * but that check is a little expensive as we have to find
	 * some/all IPsec states and ask the kernel, every 20s.
	 *
	 * XXX:
	 *
	 * But that call is being made every minute or so for
	 * LIVENESS, and it's NAT so probably not that many SAs, and
	 * finding the IKE SA is cheap.
	 */

	pdbg(ike->sa.logger, "NAT-keep-alive: sending keep-alive");
	nat_traversal_send_ka(&ike->sa);
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
		ldbg(st->logger, "new NAT mapping for "PRI_SO", was %s, now %s",
		     pri_so(st->st_serialno),
		     str_endpoint(&st_remote_endpoint, &b1),
		     str_endpoint(&nfo->new_remote_endpoint, &b2));

		/* update it */
		st->st_remote_endpoint = nfo->new_remote_endpoint;
		st->hidden_variables.st_natd = endpoint_address(nfo->new_remote_endpoint);
		struct connection *c = st->st_connection;
		if (is_instance(c)) {
			/* update remote */
			c->remote->host.addr = endpoint_address(nfo->new_remote_endpoint);
			/* then rebuild local<>remote host-pair */
		}
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

	if (st == NULL)
		return;

	if (st->st_iface_endpoint->io->protocol == &ip_protocol_tcp ||
	    (md != NULL && md->iface->io->protocol == &ip_protocol_tcp)) {
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
		if (md->iface != st->st_iface_endpoint) {
			endpoint_buf b1, b2;
			dbg("NAT-T: "PRI_SO" updating local interface from %s to %s (using md->iface in %s())",
			    pri_so(st->st_serialno),
			    str_endpoint(&st->st_iface_endpoint->local_endpoint, &b1),
			    str_endpoint(&md->iface->local_endpoint, &b2), __func__);
			iface_endpoint_delref(&st->st_iface_endpoint);
			st->st_iface_endpoint = iface_endpoint_addref(md->iface);
		}
	}
}

void show_setup_natt(struct show *s)
{
	show_separator(s);
	show(s, "nat-traversal: keep-alive=%jd, nat-ikeport=%d",
	     deltasecs(nat_keepalive_period), NAT_IKE_UDP_PORT);
}
