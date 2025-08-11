/* information about connections between hosts and clients
 *
 * Copyright (C) 1998-2002,2010,2013,2018 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009-2011 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2010 Shinichi Furuso <Shinichi.Furuso@jp.sony.com>
 * Copyright (C) 2010,2013 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2017 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2012 Philippe Vouters <Philippe.Vouters@laposte.net>
 * Copyright (C) 2012 Bram <bram-bcrafjna-erqzvar@spam.wizbit.be>
 * Copyright (C) 2013 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2013,2017 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013,2018 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2013 Florian Weimer <fweimer@redhat.com>
 * Copyright (C) 2015-2020 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2016-2020 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 * Copyright (C) 20212-2022 Paul Wouters <paul.wouters@aiven.io>
 * Copyright (C) 2020 Nupur Agrawal <nupur202000@gmail.com>
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

#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <errno.h>
#include <limits.h>

#include "sysdep.h"
#include "constants.h"
#include "lswalloc.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "secrets.h"
#include "lswnss.h"
#include "authby.h"
#include "ipsecconf/interfaces.h"

#include "kernel_info.h"
#include "defs.h"
#include "connections.h" /* needs id.h */
#include "connection_db.h"
#include "spd_db.h"
#include "pending.h"
#include "foodgroups.h"
#include "demux.h" /* needs packet.h */
#include "state.h"
#include "timer.h"
#include "ipsec_doi.h" /* needs demux.h and state.h */
#include "server.h"
#include "kernel.h" /* needs connections.h */
#include "log.h"
#include "keys.h"
#include "whack.h"
#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"
#include "ikev1_xauth.h"
#include "addresspool.h"
#include "nat_traversal.h"
#include "pluto_x509.h"
#include "nss_cert_verify.h" /* for cert_VerifySubjectAltName() */
#include "nss_cert_load.h"
#include "ikev2.h"
#include "virtual_ip.h"	/* needs connections.h */
#include "fips_mode.h"
#include "crypto.h"
#include "kernel_xfrm.h"
#include "ip_address.h"
#include "ip_info.h"
#include "keyhi.h" /* for SECKEY_DestroyPublicKey */
#include "state_db.h"		/* for state_db_rehash_connection_serialno */
#include "ipsec_interface.h"
#include "iface.h"
#include "ip_selector.h"
#include "labeled_ipsec.h"		/* for vet_seclabel() */
#include "orient.h"
#include "ikev2_proposals.h"
#include "lswnss.h"
#include "show.h"
#include "routing.h"
#include "timescale.h"
#include "connection_event.h"
#include "ike_alg_kem.h"		/* for ike_alg_kem_none; */
#include "sparse_names.h"
#include "ikev2_ike_session_resume.h"	/* for pfree_session() */
#include "whack_pubkey.h"
#include "binaryscale-iec-60027-2.h"
#include "addr_lookup.h"
#include "config_setup.h"
#include "extract.h"

static void discard_connection(struct connection **cp, bool connection_valid, where_t where);

void vdbg_connection(const struct connection *c,
		     struct verbose verbose, where_t where,
		     const char *message, ...)
{
	if (!LDBGP(DBG_BASE, c->logger)) {
		return;
	}
	verbose.stream = DEBUG_STREAM;
	/* MESSAGE ... */
	LLOG_JAMBUF(verbose.stream, verbose.logger, buf) {
		jam(buf, PRI_VERBOSE, pri_verbose);
		va_list ap;
		va_start(ap, message);
		jam_va_list(buf, message, ap);
		va_end(ap);
		jam_string(buf, " ");
		jam_where(buf, where);
	}
	verbose.level++;
	/* connection ... */
	LLOG_JAMBUF(verbose.stream, verbose.logger, buf) {
		jam(buf, PRI_VERBOSE, pri_verbose);
		jam_string(buf, "connection ");
		jam_co(buf, c->serialno);
		if (c->clonedfrom != NULL) {
			jam_string(buf, " clonedfrom ");
			jam_co(buf, c->clonedfrom->serialno);
		}
		jam_string(buf, ": ");
		jam_connection(buf, c);
	}
	verbose.level++;
	/* host local->remote */
	LLOG_JAMBUF(verbose.stream, verbose.logger, buf) {
		jam(buf, PRI_VERBOSE, pri_verbose);
		jam_string(buf, "host: ");
		jam_address(buf, &c->local->host.addr);
		jam_string(buf, "->");
		jam_address(buf, &c->remote->host.addr);
	}
	/* host id */
	LLOG_JAMBUF(verbose.stream, verbose.logger, buf) {
		jam(buf, PRI_VERBOSE, pri_verbose);
		jam_string(buf, "id: ");
		jam_id(buf, &c->local->host.id);
		jam_string(buf, " -> ");
		jam_id(buf, &c->remote->host.id);
	}
	/* routing+kind ... */
	LLOG_JAMBUF(verbose.stream, verbose.logger, buf) {
		jam(buf, PRI_VERBOSE, pri_verbose);
		jam_string(buf, "routing+kind: ");
		jam_enum_short(buf, &routing_names, c->routing.state);
		jam_string(buf, " ");
		jam_enum_short(buf, &connection_kind_names, c->local->kind);
	}
	/* selectors local->remote */
	LLOG_JAMBUF(verbose.stream, verbose.logger, buf) {
		jam(buf, PRI_VERBOSE, pri_verbose);
		jam_string(buf, "selectors");
		jam_string(buf, " proposed:");
		FOR_EACH_THING(end, &c->local->child, &c->remote->child) {
			FOR_EACH_ITEM(selector, &end->selectors.proposed) {
				jam_string(buf, " ");
				jam_selector(buf, selector);
			}
			jam_string(buf, " ->");
		}
		jam_string(buf, " accepted:");
		FOR_EACH_THING(end, &c->local->child, &c->remote->child) {
			FOR_EACH_ITEM(selector, &end->selectors.accepted) {
				jam_string(buf, " ");
				jam_selector(buf, selector);
			}
			jam_string(buf, " ->");
		}
		jam_string(buf, "; leases:");
		FOR_EACH_THING(end, &c->local->child, &c->remote->child) {
			FOR_EACH_ELEMENT(lease, end->lease) {
				if (lease->ip.is_set) {
					jam_string(buf, " ");
					jam_address(buf, lease);
				}
			}
			jam_string(buf, " ->");
		}
	}
	/* SPDs local->remote */
	LLOG_JAMBUF(verbose.stream, verbose.logger, buf) {
		jam(buf, PRI_VERBOSE, pri_verbose);
		jam_string(buf, "spds:");
		FOR_EACH_ITEM(spd, &c->child.spds) {
			jam_string(buf, " ");
			jam_selector_pair(buf, &spd->local->client, &spd->remote->client);
		}
	}
	/* policy */
	LLOG_JAMBUF(verbose.stream, verbose.logger, buf) {
		jam(buf, PRI_VERBOSE, pri_verbose);
		jam_string(buf, "policy: ");
		jam_connection_policies(buf, c);
	}
	/* sec-label */
	if (c->config->sec_label.len > 0) {
		LLOG_JAMBUF(verbose.stream, verbose.logger, buf) {
			jam(buf, PRI_VERBOSE, pri_verbose);
			jam_string(buf, "sec_label: ");
			if (c->child.sec_label.len > 0) {
				jam(buf, PRI_SHUNK, pri_shunk(c->child.sec_label));
				jam_string(buf, " <= ");
			}
			jam(buf, PRI_SHUNK, pri_shunk(c->config->sec_label));
		}
	}
	connection_db_check(verbose.logger, where);
}

/*
 * Is there an existing connection with NAME?
 */

bool connection_with_name_exists(const char *name)
{
	struct connection_filter cq = {
		.base_name = name,
		.search = {
			.order = NEW2OLD,
			.verbose.logger = &global_logger,
			.where = HERE,
		},
	};
	while (next_connection(&cq)) {
		return true;
	}
	return false;
}

/* Delete a connection */
static void discard_spd_end_content(struct spd_end *e)
{
	virtual_ip_delref(&e->virt);
}

static void discard_spd_content(struct spd *spd)
{
	spd_db_del(spd);
	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		discard_spd_end_content(&spd->end[end]);
	}
}

void discard_connection_spds(struct connection *c)
{
	FOR_EACH_ITEM(spd, &c->child.spds) {
		discard_spd_content(spd);
	}
	pfree_list(&c->child.spds);
	c->child.spds = (struct spds) {0};
}


/*
 * delete_connection -- removes a connection by pointer
 *
 * @c - the connection pointer
 * @relations - whether to delete any instances as well.
 * @connection_valid - apply sanity checks
 *
 * Compat hack for code that thinks it knows the connection is
 * finished with - it passerts() that it is delref()ing the last
 * reference.
 */

static void llog_delete_connection_when_instance(const struct connection *c)
{
	if (is_labeled_parent(c)) {
		/* XXX: pointless log? */
		address_buf b;
		llog(RC_LOG, c->logger,
		     "deleting labeled parent connection with peer %s sec_label:"PRI_SHUNK,
		     str_address_sensitive(&c->remote->host.addr, &b),
		     pri_shunk(c->config->sec_label));
	} else if (is_labeled_child(c)) {
		/* XXX: pointless log? */
		address_buf b;
		llog(RC_LOG, c->logger,
		     "deleting labeled child connection with peer %s sec_label:"PRI_SHUNK,
		     str_address_sensitive(&c->remote->host.addr, &b),
		     pri_shunk(c->child.sec_label));
	} else if (is_instance(c)) {
		/* XXX: pointless check? */
		if (!is_opportunistic(c)) {
			/* XXX: pointless log? */
			address_buf b;
			llog(RC_LOG, c->logger,
			     "deleting connection instance with peer %s",
			     str_address_sensitive(&c->remote->host.addr, &b));
		}
	}
}

void delete_connection_where(struct connection **cp, where_t where)
{
	struct connection *c = *cp;
	llog_delete_connection_when_instance(c);
	delref_where(cp, c->logger, where); /* should leave 0 references */
	discard_connection(&c, true/*connection_valid*/, where);
}

struct connection *connection_addref_where(struct connection *c, const struct logger *owner, where_t where)
{
	return refcnt_addref(c, owner, where);
}

void connection_delref_where(struct connection **cp, const struct logger *owner, where_t where)
{
	struct connection *c = refcnt_delref(cp, owner, where);
	if (c == NULL) {
		return;
	}
	llog_delete_connection_when_instance(c);
	discard_connection(&c, true/*connection_valid*/, where);
}

static bool connection_ok_to_delete(struct connection *c, where_t where)
{
	bool ok_to_delete = true;
	struct logger *logger = c->logger;

	unsigned refcnt = refcnt_peek(c);
	if (refcnt != 0) {
		llog_pexpect(logger, where,
			     "connection "PRI_CO" [%p] still has %u references",
			     pri_connection_co(c), c, refcnt);
		ok_to_delete = false;
	}

	/*
	 * Must not be pending (i.e., not on a queue waiting for an
	 * IKE SA to establish).
	 */
	if (connection_is_pending(c)) {
		llog_pexpect(logger, where,
			     "connection "PRI_CO" [%p] is still pending",
			     pri_connection_co(c), c);
		ok_to_delete = false;
	}

	/*
	 * Must have all routing and all owners cleared.
	 */
	if (!pexpect_connection_is_unrouted(c, logger, where)) {
		ok_to_delete = false;
	}
	if (!pexpect_connection_is_disowned(c, logger, where)) {
		ok_to_delete = false;
	}

	/*
	 * Must not have instances (i.e., all instantiations are gone).
	 */
	struct connection_filter instance = {
		.clonedfrom = c,
		.search = {
			.order = OLD2NEW,
			.verbose = VERBOSE(DEBUG_STREAM, logger, NULL),
			.where = HERE,
		},
	};
	while (next_connection(&instance)) {
		llog_pexpect(logger, where,
			     "connection "PRI_CO" [%p] still instantiated as %s [%p]",
			     pri_connection_co(c), c,
			     instance.c->name,
			     instance.c);
		connection_ok_to_delete(instance.c, where);
		ok_to_delete = false;
	}

	/*
	 * Must not have states (i.e., no states are referring to this
	 * connection).
	 */
	struct state_filter state = {
		.connection_serialno = c->serialno,
		.search = {
			.order = NEW2OLD,
			.verbose = VERBOSE(DEBUG_STREAM, logger, NULL),
			.where = HERE,
		},
	};
	while (next_state(&state)) {
		state_buf sb;
		llog_pexpect(logger, where,
			     "connection "PRI_CO" [%p] is still being used by %s "PRI_STATE,
			     pri_connection_co(c), c,
			     state_sa_name(state.st),
			     pri_state(state.st, &sb));
		ok_to_delete = false;
	}

	/*
	 * There can't be any outstanding events.
	 */
	if (connection_event_is_scheduled(c, CONNECTION_REVIVAL)) {
		llog_pexpect(logger, where,
			     "connection "PRI_CO" [%p] has REVVIAL pending",
			     pri_connection_co(c), c);
		ok_to_delete = false;
	}

	return ok_to_delete;
}

static void discard_connection(struct connection **cp, bool connection_valid, where_t where)
{
	struct connection *c = *cp;
	*cp = NULL;

	/*
	 * Preserve the original logger's text.  Things like
	 * delref(.clonedfrom) affect the prefix.
	 */
	struct logger *logger = clone_logger(c->logger, where);  /* must free */

	/*
	 * XXX: don't use "@%p".  The refcnt tracker will see it and
	 * report a use-after-free (since refcnt loggs the pointer as
	 * free before calling this code).
	 */
	ldbg(logger, "%s() %s "PRI_CO" [%p] cloned from "PRI_CO,
	     __func__, c->name,
	     pri_connection_co(c), c,
	     pri_connection_co(c->clonedfrom));

	if (!connection_ok_to_delete(c, where)) {
		llog_passert(logger, where,
			     "connection "PRI_CO" [%p] still in use",
			     pri_connection_co(c), c);
	}

	/*
	 * Finally start cleanup.
	 */

	FOR_EACH_ELEMENT(afi, ip_families) {
		if (c->pool[afi->ip.version] != NULL) {
			free_that_address_lease(c, afi, logger);
			addresspool_delref(&c->pool[afi->ip.version], logger);
		}
	}

	/* find and delete c from the host pair list */
#if 0
	PEXPECT(logger, !oriented(c));
#endif
	disorient(c);

	/*
	 * Disorienting should have released .ipsec_interface, and
	 * unrouting should have released the
	 * .ipsec_interface_address.
	 */
	PEXPECT(logger, c->ipsec_interface == NULL);
	PEXPECT(logger, c->ipsec_interface_address == NULL);

	remove_from_group(c);

	if (connection_valid) {
		connection_db_del(c);
	}
	discard_connection_spds(c);

	/*
	 * Freeing .clonedfrom breaks the logger's message.
	 */

	free_logger(&c->logger, where);

	FOR_EACH_ELEMENT(end, c->end) {
		free_id_content(&end->host.id);
		pfree_list(&end->child.selectors.accepted);
	}

	connection_delref(&c->clonedfrom, logger);

	iface_endpoint_delref(&c->revival.local);

	free_chunk_content(&c->child.sec_label);

	pfree_session(&c->session);

	/*
	 * Only free config when the root connection.  Non-root
	 * connections have .root_config==NULL.
	 */
	struct config *config = c->root_config;
	if (config != NULL) {
		PASSERT(logger, c->clonedfrom == NULL); /*i.e., root */
		pfreeany(config->vti.interface);
		free_chunk_content(&config->sec_label);
		free_proposals(&config->ike_proposals.p);
		free_proposals(&config->child.proposals.p);
		free_ikev2_proposals(&config->v2_ike_proposals);
		free_ikev2_proposals(&config->child.v2_ike_auth_proposals);
		pfreeany(config->connalias);
		pfree_list(&config->modecfg.dns);
		pfreeany(config->modecfg.domains);
		pfreeany(config->modecfg.banner);
		pfreeany(config->ppk_ids);
		if (config->ppk_ids_shunks != NULL) {
			pfree(config->ppk_ids_shunks);
		}
		pfreeany(config->redirect.to);
		pfreeany(config->redirect.accept_to);
		FOR_EACH_ELEMENT(end, config->end) {
			if (end->host.cert.nss_cert != NULL) {
				CERT_DestroyCertificate(end->host.cert.nss_cert);
			}
			/* ike/host */
			free_chunk_content(&end->host.ca);
			pfreeany(end->host.ckaid);
			pfreeany(end->host.xauth.username);
			pfreeany(end->host.host.name);
			pfreeany(end->host.nexthop.name);
			free_id_content(&end->host.id);
			/* child */
			pfreeany(end->child.updown);
			pfree_list(&end->child.selectors);
			pfree_list(&end->child.sourceip);
			virtual_ip_delref(&end->child.virt);
			pfree_list(&end->child.addresspools);
			FOR_EACH_ELEMENT(pool, end->child.addresspool) {
				addresspool_delref(pool, logger);
			}
		}
		pfree(config->name);
		pfree(c->root_config);
	}

	/* connection's final gasp; need's c->name */
	pfreeany(c->base_name);
	pfreeany(c->name);
	free_logger(&logger, where);
	pfree(c);
}

ip_port end_host_port(const struct host_end *this, const struct host_end *that)
{
	ip_port port;
	if (port_is_specified(this->config->ikeport)) {
		/*
		 * The END's IKEPORT was specified in the config file.
		 * Use that.
		 */
		port = this->config->ikeport;
	} else if (port_is_specified(that->config->ikeport)) {
		/*
		 * The other end's IKEPORT was specified in the config
		 * file.  Since specifying an IKEPORT implies ESP
		 * encapsulation (i.e. IKE packets must include the
		 * ESP=0 prefix), send packets from the encapsulating
		 * NAT_IKE_UDP_PORT.
		 */
		port = ip_hport(NAT_IKE_UDP_PORT);
	} else if (that->encap) {
		/*
		 * See above.  Presumably an instance which previously
		 * had a natted port and is being revived.
		 */
		port = ip_hport(NAT_IKE_UDP_PORT);
	} else if (this->config->iketcp == IKE_TCP_ONLY) {
		/*
		 * RFC 8229: Implementations MUST support TCP
		 * encapsulation on TCP port 4500, which is reserved
		 * for IPsec NAT traversal.
		*/
		port = ip_hport(NAT_IKE_UDP_PORT);
	} else {
		port = ip_hport(IKE_UDP_PORT);
	}
	return port;
}

ip_port local_host_port(const struct connection *c)
{
	return end_host_port(&c->local->host, &c->remote->host);
}

void update_hosts_from_end_host_addr(struct connection *c,
				     enum end end,
				     ip_address host_addr,
				     ip_address peer_nexthop,
				     where_t where)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, c->logger, "ehr");
	struct host_end *host = &c->end[end].host;
	struct host_end *peer = &c->end[!end].host;

	address_buf hab, pb;
	vdbg("updating %s host ends from host.addr %s and peer.nexthop %s",
	     host->config->leftright,
	     str_address(&host_addr, &hab),
	     str_address(&peer_nexthop, &pb));
	verbose.level++;

#if 0
	/* could be %any but can't be an address */
	vassert_where(where, !address_is_specified(host->addr));
#endif

	/* can't be unset; but could be %any[46] */
	const struct ip_info *afi = address_info(host_addr);
	vassert_where(where, afi != NULL); /* since specified */

	address_buf old_ha, new_ha;
	vdbg("updated %s.host.addr %s to %s",
	     host->config->leftright,
	     str_address(&host->addr, &old_ha),
	     str_address(&host_addr, &new_ha));

	host->addr = host_addr;
	host->first_addr = host_addr;

	/*
	 * Update the %any ID to HOST_ADDR, but only when it set to a
	 * proper address, i.e., is set and not %any aka 0.0.0 --
	 * WildCard.
	 */
	if (address_is_specified(host_addr) &&
	    host->id.kind == ID_NONE) {
		struct id id = {
			.kind = afi->id_ip_addr,
			.ip_addr = host->addr,
		};
		id_buf hid, cid, nid;
		vdbg("updated %s.id from %s (config=%s) to %s",
		     host->config->leftright,
		     str_id(&host->id, &hid),
		     str_id(&host->config->id, &cid),
		     str_id(&id, &nid));
		host->id = id;
	}

	/*
	 * If END has an IKEPORT (which means messages are ESP=0
	 * prefixed), then END must send from either IKEPORT or the
	 * NAT port (and also ESP=0 prefix messages).
	 */
	if (address_is_specified(host_addr)) {
		unsigned host_port = hport(end_host_port(host, peer));
		vdbg("updated %s.host.port from %u to %u",
		    host->config->leftright,
		    host->port, host_port);
		host->port = host_port;
	}

	/*
	 * Set the peer's NEXTHOP when necessary.
	 *
	 * When not supplied, use this end's HOST_ADDR, as in:
	 *
	 *   peer.ADDR -> peer.NEXTHOP=host.ADDR -> host.ADDR.
	 */
	if (address_is_specified(host_addr) &&
	    !address_is_specified(peer_nexthop)) {
		peer_nexthop = host_addr;
	}

	address_buf old_nh, new_nh;
	vdbg("updated peer %s.nexthop from %s to %s",
	    peer->config->leftright,
	    str_address(&peer->nexthop, &old_nh),
	    str_address(&peer_nexthop, &new_nh));
	peer->nexthop = peer_nexthop;
}

bool resolve_connection_hosts_from_configs(struct connection *c,
					   struct verbose verbose)
{
	const struct config *config = c->config;

	struct resolve_end resolve[END_ROOF] = {0};

	bool can_resolve = true;
	FOR_EACH_THING(lr, LEFT_END, RIGHT_END) {
		const struct host_end_config *src = &config->end[lr].host;
 		struct resolve_end *dst = &resolve[lr];
 		const char *leftright = config->end[lr].leftright;

		/* leftright */
		dst->leftright = leftright;

		/* nexthop */
		dst->nexthop.name = src->nexthop.name;
		dst->nexthop.addr = src->nexthop.addr;
		dst->nexthop.type = src->nexthop.type;

		/* host */
		ip_address host_addr;
		if (src->host.type == KH_IPHOSTNAME) {
			err_t e = ttoaddress_dns(shunk1(src->host.name),
						 config->host.afi, &host_addr);
			if (e != NULL) {
				/*
				 * XXX: failing ttoaddress*() sets
				 * host_addr to unset but want
				 * src.host.addr.
				 */
				vlog("failed to resolve '%s%s=%s' at load time: %s",
				     leftright, "", src->host.name, e);
				can_resolve = false;
				host_addr = src->host.addr;
			}
		} else {
			host_addr = src->host.addr;
		}
		dst->host.name = src->host.name;
		dst->host.addr = host_addr;
		dst->host.type = src->host.type;
	}

	if (can_resolve) {
		resolve_default_route(&resolve[LEFT_END],
				      &resolve[RIGHT_END],
				      config->host.afi,
				      verbose);
		resolve_default_route(&resolve[RIGHT_END],
				      &resolve[LEFT_END],
				      config->host.afi,
				      verbose);
	}

	FOR_EACH_THING(lr, LEFT_END, RIGHT_END) {
		update_hosts_from_end_host_addr(c, lr,
						resolve[lr].host.addr,
						resolve[!lr].nexthop.addr,
						HERE); /* from add */
	}

	/*
	 * Since above updated HOST_PAIR, and possibly ID, must
	 * re-hash.
	 */
	connection_db_rehash_that_id(c);
	connection_db_rehash_host_pair(c);
	if (VDBGP()) {
		connection_db_check(verbose.logger, HERE);
	}

	return can_resolve;
}

diag_t add_end_cert_and_preload_private_key(CERTCertificate *cert,
					    struct host_end_config *host_end_config,
					    bool preserve_ca,
					    const struct logger *logger)
{
	PASSERT(logger, cert != NULL);
	const char *nickname = cert->nickname;
	const char *leftright = host_end_config->leftright;

	/*
	 * A copy of this code lives in nss_cert_verify.c :/
	 * Currently only a check for RSA is needed, as the only ECDSA
	 * key size not allowed in FIPS mode (p192 curve), is not implemented
	 * by NSS.
	 * See also RSA_secret_sane() and ECDSA_secret_sane()
	 */
	if (is_fips_mode()) {
		SECKEYPublicKey *pk = CERT_ExtractPublicKey(cert);
		PASSERT(logger, pk != NULL);
		if (pk->keyType == rsaKey &&
		    ((pk->u.rsa.modulus.len * BITS_IN_BYTE) < FIPS_MIN_RSA_KEY_SIZE)) {
			SECKEY_DestroyPublicKey(pk);
			return diag("FIPS: rejecting %s certificate '%s' with key size %d which is under %d",
				    leftright, nickname,
				    pk->u.rsa.modulus.len * BITS_IN_BYTE,
				    FIPS_MIN_RSA_KEY_SIZE);
		}
		/* TODO FORCE MINIMUM SIZE ECDSA KEY */
		SECKEY_DestroyPublicKey(pk);
	}

	/* check validity of cert */
	SECCertTimeValidity validity = CERT_CheckCertValidTimes(cert, PR_Now(), false);
	switch (validity) {
	case secCertTimeValid:
		ldbg(logger, "%s certificate '%s' time is valid", leftright, nickname);
		break;
	case secCertTimeExpired:
		if (!host_end_config->groundhog) {
			return diag("%s certificate '%s' has expired",
				    leftright, nickname);
		}
		llog(RC_LOG, logger,
		     "WARNING: groundhog %s certificate '%s' has expired",
		     leftright, nickname);
		break;
	case secCertTimeNotValidYet:
		if (!host_end_config->groundhog) {
			return diag("%s certificate '%s' is not yet valid",
				    leftright, nickname);
		}
		llog(RC_LOG, logger,
		     "WARNING: groundhog %s certificate '%s' is not yet valid",
		     leftright, nickname);
		break;
	default:
	case secCertTimeUndetermined:
		if (!host_end_config->groundhog) {
			return diag("%s certificate '%s' has undetermined time",
				    leftright, nickname);
		}
		llog(RC_LOG, logger,
		     "WARNING: groundhog %s certificate '%s' has undetermined time",
		     leftright, nickname);
		break;
	}

	/*
	 * Note: this is passing in the pre-%fromcert updated ID.
	 *
	 * add_pubkey_from_nss_cert() adds pubkeys under: the cert's
	 * subject name, and cert's subject alt names (SAN).  It then,
	 * when ID isn't %fromcert, or DN (i.e., subject name making
	 * it redundant), adds a further pubkey under the ID's name
	 * (for instance @east?).
	 *
	 * Hence, using the non-updated ID from config is fine.
	 */
	ldbg(logger, "adding %s certificate \'%s\' pubkey", leftright, cert->nickname);
	if (!add_pubkey_from_nss_cert(&pluto_pubkeys, &host_end_config->id, cert, logger)) {
		/* XXX: push diag_t into add_pubkey_from_nss_cert()? */
		return diag("%s certificate \'%s\' pubkey could not be loaded", leftright, cert->nickname);
	}

	host_end_config->cert.nss_cert = cert;

	/*
	 * If no CA is defined, use issuer as default; but only when
	 * update is ok (when reloading certs it is never ok).
	 */
	if (preserve_ca || host_end_config->ca.ptr != NULL) {
		ldbg(logger, "preserving existing %s ca", leftright);
	} else {
		host_end_config->ca = clone_secitem_as_chunk(cert->derIssuer, "issuer ca");
	}

	/*
	 * Try to pre-load the certificate's secret (private key) into
	 * the local cache (see keys.c).
	 *
	 * This can fail.  For instance, this end may only have the
	 * peer's certificate
	 *
	 * This could also fail because a needed secret is missing.
	 * That case is handled by refine_host_connection /
	 * get_psk.
	 */
	ldbg(logger, "preload cert/secret for connection: %s", cert->nickname);
	bool load_needed;
	err_t ugh = preload_private_key_by_cert(&host_end_config->cert, &load_needed, logger);
	if (ugh != NULL) {
		ldbg(logger, "no private key matching %s certificate %s: %s",
		     leftright, nickname, ugh);
	} else if (load_needed) {
		llog(LOG_STREAM/*not-whack-for-now*/, logger,
		     "loaded private key matching %s certificate '%s'",
		     leftright, nickname);
	}
	return NULL;
}

/*
 * Turn the config's selectors / addresspool / host-addr into
 * proposals.
 */

void build_connection_proposals_from_hosts_and_configs(struct connection *d,
						       struct verbose verbose)
{
	vdbg("%s() ...", __func__);
	verbose.level++;

	FOR_EACH_ELEMENT(end, d->end) {
		const char *leftright = end->config->leftright;

		vexpect(end->child.selectors.proposed.list == NULL);
		vexpect(end->child.selectors.proposed.len == 0);
		vexpect(end->child.has_client == false);

		/* {left,right}subnet=... */
		if (end->child.config->selectors.len > 0) {
			VDBG_JAMBUF(buf) {
				jam_string(buf, leftright);
				jam_string(buf, " proposals from child config selectors");
				FOR_EACH_ITEM(selector, &end->child.config->selectors) {
					jam_string(buf, " ");
					jam_selector(buf, selector);
				}
			}
			end->child.selectors.proposed = end->child.config->selectors;
			/*
			 * This is important, but why?
			 *
			 * IKEv1: the initiator should send the client
			 * ID during quick mode.
			 */
			set_end_child_has_client(d, end->config->index, true);
			continue;
		}

		/* {left,right}addresspool= */
		if (end->child.config->addresspools.len > 0) {
			/*
			 * Set the selectors to the pool range:
			 *
			 * IKEv2: addresspool implies narrowing so
			 * peer sending ::/0 will be allowed to narrow
			 * down to the addresspool range.
			 *
			 * IKEv1: peer is expected to send the lease
			 * it obtained earlier (either during
			 * MODE_CFG, or hard-wired in the config
			 * file).
			 */
			FOR_EACH_ITEM(range, &end->child.config->addresspools) {
				ip_selector selector = selector_from_range((*range));
				selector_buf sb;
				vdbg("%s proposals formed from address pool %s",
				     leftright, str_selector(&selector, &sb));
				append_end_selector(end, selector, verbose);
			}
			continue;
		}

		/* {left,right}= and non-zero */
		if (address_is_specified(end->host.addr)) {
			/*
			 * When there's no subnet=, and the host.addr
			 * is known, default the selector to the
			 * host's addr (with protoport added).
			 *
			 * Code will update_end_selector() to
			 * host.addr once host.addr is (for instance
			 * during orient()); or to a lease (for
			 * instance because the peer assigned an
			 * address using IKEv2 CP, or IKEv1 MODE_CFG);
			 * or?
			 */
			address_buf ab;
			protoport_buf pb;
			vdbg("%s proposals from host address+protoport %s %s",
			     leftright,
			     str_address(&end->host.addr, &ab),
			     str_protoport(&end->child.config->protoport, &pb));
			ip_selector selector =
				selector_from_address_protoport(end->host.addr,
								end->child.config->protoport);
			append_end_selector(end, selector, verbose);
			continue;
		}

		/*
		 * Instances, since they are oriented, should have
		 * been handled by the above.
		 */
		if (!vexpect(is_permanent(d) || is_group(d) || is_template(d))) {
			return;
		}

		/*
		 * Either %any, or an unresolved address.
		 *
		 * Make space in the proposal for the value; and
		 * preserve the expected address family.  Use the
		 * .selector.unset as which has .ip.is_set=false so it
		 * looks unset; yet has .version=IPv[46] so that is
		 * available.
		 *
		 * Can't use .selector.zero as all zeros is a valid
		 * selector value.
		 *
		 * Be forgiving of the extract code - accept either
		 * .address.zero, or .address.unset.  Just log source.
		 */

		const struct ip_info *host_afi;
		if (end->host.addr.ip.is_set) {
			host_afi = address_info(end->host.addr);
			vdbg("%s proposals from zero host family %s",
			     leftright, host_afi->ip_name);
		} else if (end->host.addr.ip.version != 0) {
			host_afi = ip_version_info(end->host.addr.ip.version);
			vdbg("%s proposals from unset host family %s",
			     leftright, host_afi->ip_name);
		} else {
			vlog_pexpect(HERE, "%s host address is unknown", leftright);
			return;
		}

		/*
		 * Note: NOT afi->selector.all.  It needs to
		 * differentiate so it knows it is to be updated.
		 *
		 * selector.unset has .ip.is_set=false so looks unset;
		 * but has .version=IPv[46].
		 */
		append_end_selector(end, host_afi->selector.unset, verbose);
	}
}

void delete_connection_proposals(struct connection *c)
{
	FOR_EACH_THING(lr, LEFT_END, RIGHT_END) {
		struct child_end *child = &c->end[lr].child;

		pfreeany(child->selectors.accepted.list);
		zero(&child->selectors.accepted);
		zero(&child->selectors.proposed);
		child->has_client = false;
	}
}

void init_connection_spd(struct connection *c, struct spd *spd)
{
	/* back link */
	spd->connection = c;
	/* local link */
	spd->local = &spd->end[c->local->config->index];	/*clone must update*/
	spd->remote = &spd->end[c->remote->config->index];	/*clone must update*/
	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		spd->end[end].config = c->end[end].config;
		spd->end[end].host = &c->end[end].host;		/*clone must update*/
		spd->end[end].child = &c->end[end].child;	/*clone must update*/
	}
	/* db; will be updated */
	spd_db_init_spd(spd);
}

void alloc_connection_spds(struct connection *c, unsigned nr_spds,
			   struct verbose verbose)
{
	vassert(c->child.spds.len == 0);
	vdbg("allocating %u SPDs", nr_spds);
	c->child.spds = (struct spds) {
		.len = nr_spds,
		.list = alloc_things(struct spd, nr_spds, "spds"),
	};
	FOR_EACH_ITEM(spd, &c->child.spds) {
		init_connection_spd(c, spd);
	}
}

void build_connection_spds_from_proposals(struct connection *c)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, c->logger, NULL);
	vdbg("adding connection spds using proposed");
	verbose.level++;

	const ip_selectors *left_proposals = &c->end[LEFT_END].child.selectors.proposed;
	const ip_selectors *right_proposals = &c->end[RIGHT_END].child.selectors.proposed;
	vdbg("left=%u right=%u", left_proposals->len, right_proposals->len);

	/*
	 * Pass 1: Calculate the total number of SPDs.
	 *
	 * Note: All selectors in the proposal, even unset selectors,
	 * have .version set.  When there's no subnet= and the
	 * host-addr isn't known it is set to selector.unset (aka
	 * .ip.is_set=false, .version=..., )
	 */

	unsigned nr_spds = 0;
	FOR_EACH_ITEM(left_selector, left_proposals) {
		vexpect(left_selector->ip.version != 0);
		FOR_EACH_ITEM(right_selector, right_proposals) {
			vexpect(right_selector->ip.version != 0);
			if (left_selector->ip.version == right_selector->ip.version) {
				nr_spds ++;
			}
		}
	}

	/* Allocate the SPDs. */
	alloc_connection_spds(c, nr_spds, verbose);

	/*
	 * Pass 2: fill them in, hashing each as it is added.
	 */

	unsigned spd_nr = 0;
	FOR_EACH_ITEM(left_selector, left_proposals) {
		FOR_EACH_ITEM(right_selector, right_proposals) {
			verbose.level = 2;
			if (left_selector->ip.version == right_selector->ip.version) {
				selector_pair_buf spb;
				vdbg("%s", str_selector_pair(left_selector, right_selector, &spb));
				verbose.level = 3;
				struct spd *spd = &c->child.spds.list[spd_nr++];
				vassert(spd < c->child.spds.list + c->child.spds.len);
				ip_selector *selectors[] = {
					[LEFT_END] = left_selector,
					[RIGHT_END] = right_selector,
				};
				FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
					const struct child_end_config *child_end =
						&c->end[end].config->child;
					struct spd_end *spd_end = &spd->end[end];
					const char *leftright = child_end->leftright;
					spd_end->client = (*selectors[end]);
					spd_end->virt = virtual_ip_addref(child_end->virt);
					selector_buf sb;
					vdbg("%s child spd from selector %s %s.spd.has_client=%s virt=%s",
					     spd_end->config->leftright,
					     str_selector(&spd_end->client, &sb),
					     leftright,
					     bool_str(spd_end->child->has_client),
					     bool_str(spd_end->virt != NULL));
				}
				spd_db_add(spd);
			}
		}
	}
}

static char *alloc_connection_prefix(const char *name, const struct connection *t/*could be NULL*/)
{
	if (t == NULL || t->next_instance_serial == 0) {
		/* permanent; group; ... */
		return alloc_printf("\"%s\"", name);
	}

	/*
	 * Form new prefix by appending next serial to existing
	 * prefix.
	 */
	return alloc_printf("%s[%lu]", t->name, t->next_instance_serial);
}

static struct config *alloc_config(const char *name)
{
	struct config *config = alloc_thing(struct config, "root config");
	config->name = clone_str(name, "config");
	FOR_EACH_THING(lr, LEFT_END, RIGHT_END) {
		/* "left" or "right" */
		const char *leftright =
			(lr == LEFT_END ? "left" :
			 lr == RIGHT_END ? "right" :
			 NULL);
		passert(leftright != NULL);
		struct end_config *end_config = &config->end[lr];
		end_config->leftright = leftright;
		end_config->index = lr;
		end_config->host.leftright = leftright;
		end_config->child.leftright = leftright;
	}
	return config;
}

struct connection *alloc_connection(const char *name,
				    struct connection *t,
				    struct config *root_config,
				    lset_t debugging,
				    struct logger *logger,
				    where_t where)
{
	struct connection *c = refcnt_alloc(struct connection, logger, where);
	const struct config *config = (t != NULL ? t->config : root_config);

	/* before alloc_logger(); can't use C */
	c->base_name = clone_str(name, __func__);

	/* before alloc_logger(); can't use C */
	c->name = alloc_connection_prefix(name, t);

	/* after .name and .name_prefix are set; needed by logger */
	c->logger = alloc_logger(c, &logger_connection_vec,
				 debugging, where);

	/* after alloc_logger(); connection's first gasp */
	connection_attach(c, logger);

	/*
	 *  Update the .instance_serial.
	 */
	if (t != NULL && t->next_instance_serial > 0) {
		/* restart count in instance */
		c->next_instance_serial = 1;
		c->instance_serial = t->next_instance_serial;
		t->next_instance_serial++;
		ldbg(t->logger, "template .instance_serial_next updated to %lu; instance %lu",
		     t->next_instance_serial,
		     c->instance_serial);
	}

	/*
	 * Determine left/right vs local/remote.
	 *
	 * When there's no template, LOCAL and REMOTE are disoriented
	 * so the decision is arbitrary.  Keep with the historic
	 * convention:
	 *
	 *    LEFT == LOCAL / THIS
	 *    RIGHT == REMOTE / THAT
	 *
	 * Needed by the hash table code that expects .that->host.id
	 * to work.
	 */

	enum end local = (t == NULL ? LEFT_END : t->local->config->index);
	enum end remote = (t == NULL ? RIGHT_END : t->remote->config->index);

	c->local = &c->end[local];	/* this; clone must update */
	c->remote = &c->end[remote];	/* that; clone must update */

	/*
	 * Point connection's end's config at corresponding entries in
	 * config.
	 *
	 * Needed by the connection_db code when it tries to log.
	 */
	c->config = config;
	c->root_config = root_config; /* possibly NULL */
	FOR_EACH_THING(lr, LEFT_END, RIGHT_END) {
		/* "left" or "right" */
		struct connection_end *end = &c->end[lr];
		const struct end_config *end_config = &c->config->end[lr];
		end->config = end_config;
		end->host.config = &end_config->host;
		end->child.config = &end_config->child;
	}

	/* somewhat oriented can start hashing */
	connection_db_init_connection(c);

	connection_routing_init(c);

	/*
	 * Update counter, set serialno and add to serialno list.
	 *
	 * The connection will be hashed after the caller has finished
	 * populating it.
	 */
	static co_serial_t connection_serialno;
	connection_serialno++;
	PASSERT(logger, connection_serialno > 0); /* can't overflow */
	c->serialno = connection_serialno;
	c->clonedfrom = connection_addref(t, c->logger);

	return c;
}

const struct ike_info ikev1_info = {
	.version = IKEv1,
	.version_name = "IKEv1",
	.parent_name = "ISAKMP",
	.child_name = "IPsec",
	.parent_sa_name = "ISAKMP SA",
	.child_sa_name = "IPsec SA",
	.expire_event[SA_HARD_EXPIRED] = EVENT_v1_EXPIRE,
	.expire_event[SA_SOFT_EXPIRED] = EVENT_v1_REPLACE,
	.replace_event = EVENT_v1_REPLACE,
	.retransmit_event = EVENT_v1_RETRANSMIT,
};

const struct ike_info ikev2_info = {
	.version = IKEv2,
	.version_name = "IKEv2",
	.parent_name = "IKE",
	.child_name = "Child",
	.parent_sa_name = "IKE SA",
	.child_sa_name = "Child SA",
	.expire_event[SA_HARD_EXPIRED] = EVENT_v2_EXPIRE,
	.expire_event[SA_SOFT_EXPIRED] = EVENT_v2_REKEY,
	.replace_event = EVENT_v2_REPLACE,
	.retransmit_event = EVENT_v2_RETRANSMIT,
};

diag_t add_connection(const struct whack_message *wm, struct logger *logger)
{
	/*
	 * For instance ipsec add --debug.
	 */
	lset_t debugging = lmod(LEMPTY, wm->whack_debugging);

	/*
	 * Use lmod_args() since it both knows how to parse a comma
	 * separated list and can handle no-XXX (ex: all,no-xauth).
	 * The final set of enabled bits is returned in .set.
	 *
	 * Delay complaining about a lack of set bits until there's a
	 * connection to log against.
	 */
	lmod_t debug = {0};
	if (wm->debug != NULL) {
		/* failure handled below */
		ttolmod(shunk1(wm->debug), &debug, &debug_lmod_info, true/*enable*/);
	}

	/*
	 * Allocate the configuration - only allocated on root
	 * connection; connection instances (clones) inherit these
	 * pointers.
	 */

	struct config *root_config = alloc_config(wm->name);
	struct connection *c = alloc_connection(root_config->name, NULL, root_config,
						debugging | debug.set,
						logger, HERE);
	struct verbose verbose = VERBOSE(DEBUG_STREAM, c->logger, c->name);

	/*
	 * Now that there's a connection to log against, complain
	 * about broken debug=.
	 */
	if (wm->debug != NULL && debug.set == LEMPTY) {
		vwarning("debug=%s invalid, ignored", wm->debug);
	}

	diag_t d = extract_connection(wm, c, root_config, verbose);
	if (d != NULL) {
		struct connection *cp = c;
		vassert(delref_where(&cp, c->logger, HERE) == c);
		discard_connection(&c, false/*not-valid*/, HERE);
		return d;
	}

	/* log all about this connection */

	/* connection is good-to-go: log against it */

	err_t tss = connection_requires_tss(c);
	if (tss != NULL) {
		llog(RC_LOG, c->logger, "connection is using multiple %s", tss);
	}

	LLOG_JAMBUF(RC_LOG, c->logger, buf) {
		jam_string(buf, "added");
		jam_string(buf, " ");
		jam_orientation(buf, c, /*oriented_details*/false);
	}

	policy_buf pb;
	ldbg(c->logger,
	     "ike_life: %jd; ipsec_life: %jds; rekey_margin: %jds; rekey_fuzz: %lu%%; replay_window: %ju; policy: %s ipsec_max_bytes: %ju ipsec_max_packets %ju",
	     deltasecs(c->config->sa_ike_max_lifetime),
	     deltasecs(c->config->sa_ipsec_max_lifetime),
	     deltasecs(c->config->sa_rekey_margin),
	     c->config->sa_rekey_fuzz,
	     c->config->child.replay_window,
	     str_connection_policies(c, &pb),
	     c->config->sa_ipsec_max_bytes,
	     c->config->sa_ipsec_max_packets);
	release_whack(c->logger, HERE);
	return NULL;
}

static connection_priority_t max_prefix_len(struct connection_end *end)
{
	int len = 0;
	FOR_EACH_ITEM(selector, &end->child.selectors.proposed) {
		int prefix_len = selector_prefix_len((*selector));
		if (prefix_len >= 0) {
			len = max(len, prefix_len);
		}
	}
	return len;
}

connection_priority_t connection_priority(const struct connection *c)
{
	connection_priority_t pp = 0;
	/* space for IPv6 mask which is /128 */
	pp |= max_prefix_len(c->local);
	pp <<= 8;
	pp |= max_prefix_len(c->remote);
	pp <<= 1;
	pp |= is_instance(c);
	pp <<= 1;
	pp |= 1; /* never return zero aka BOTTOM_PRIORITY */
	return pp;
}

void jam_connection_priority(struct jambuf *buf, const struct connection *c)
{
	connection_priority_t pp = connection_priority(c);
	/* reverse the above */

	/* 1-bit never zero */
	pp >>= 1;
	/* 1-bit instance */
	unsigned instance = pp & 1;
	pp >>= 1;
	/* 8-bit remote */
	unsigned remote = pp & 0xff;
	pp >>= 8;
	/* 8-bit local */
	unsigned local = pp & 0xff;
	pp >>= 8;

	jam(buf, "%u,%u,%u", local, remote, instance);
}

/*
 * Format any information needed to identify an instance of a connection.
 * Fills any needed information into buf which MUST be big enough.
 * Road Warrior: peer's IP address
 * Opportunistic: [" " myclient "==="] " ..." peer ["===" peer_client] '\0'
 */

static size_t jam_connection_child(struct jambuf *b,
				   const char *prefix, const char *suffix,
				   const struct child_end *child,
				   const ip_address host_addr)
{
	const ip_selectors *selectors =
		(child->selectors.accepted.len > 0 ? &child->selectors.accepted :
		 child->selectors.proposed.len > 0 ? &child->selectors.proposed :
		 NULL);
	size_t s = 0;
	if (selectors == NULL) {
		/* no point */
	} else if (selectors->len == 1 &&
		   /* i.e., selector==host.addr[+protoport] */
		   range_eq_address(selector_range(selectors->list[0]), host_addr)) {
		/* compact denotation for "self" */
	} else {
		s += jam_string(b, prefix);
		if (child->config->addresspools.len > 0) {
			s += jam_string(b, "{");
		}
		const char *sep = "";
		FOR_EACH_ITEM(selector, selectors) {
			if (pexpect(selector->ip.is_set)) {
				s += jam_selector_range(b, selector);
				if (selector_is_zero(*selector)) {
					s += jam_string(b, "?");
				}
			} else {
				s += jam_string(b, "?");
			}
			jam_string(b, sep); sep = ",";
		}
		if (child->config->addresspools.len > 0) {
			s += jam_string(b, "}");
		}
		s += jam_string(b, suffix);
	}
	return s;
}

static size_t jam_connection_suffix(struct jambuf *buf, const struct connection *c)
{
	size_t s = 0;
	if (is_opportunistic(c)) {
		/*
		 * XXX: print proposed or accepted selectors?
		 */
		s += jam_connection_child(buf, " ", "===", &c->local->child,
					  c->local->host.addr);
		s += jam_string(buf, " ...");
		s += jam_address_sensitive(buf, &c->remote->host.addr);
		s += jam_connection_child(buf, "===", "", &c->remote->child,
					  c->remote->host.addr);
	} else {
		s += jam_string(buf, " ");
		s += jam_address_sensitive(buf, &c->remote->host.addr);
	}
	return s;
}

size_t jam_connection(struct jambuf *buf, const struct connection *c)
{
	size_t s = 0;
	s += jam_string(buf, c->name);
	if (c->instance_serial > 0) {
		s += jam_connection_suffix(buf, c);
	}
	return s;
}

const char *str_connection_suffix(const struct connection *c, connection_buf *buf)
{
	struct jambuf p = ARRAY_AS_JAMBUF(buf->buf);
	if (c->instance_serial > 0) {
		jam_connection_suffix(&p, c);
	}
	return buf->buf;
}

size_t jam_connection_policies(struct jambuf *buf, const struct connection *c)
{
	const char *sep = "";
	size_t s = 0;
	enum shunt_policy shunt;

	/* Show [S]tring */
#define CS(S)					\
	{					\
		s += jam_string(buf, sep);	\
		s += jam_string(buf, S);	\
		sep = "+";			\
	}
	/* Show when True (and negotiate) */
#define CT(C, N)				\
	if (!never_negotiate(c) &&		\
	    c->config->C) {			\
		/* show when true */		\
		CS(#N);				\
	}
	/* Show when False (and negotiate) */
#define CF(C, N)				\
	if (!never_negotiate(c) &&		\
	    !c->config->C) {			\
		/* show when false */		\
		CS(#N);				\
	}
	/* Show when [P]redicate (and negotiate) */
#define CP(P, N)				\
	if (!never_negotiate(c) &&		\
	    P) {				\
		/* show when true */		\
		CS(#N);				\
	}
	/* Show when Predicate */
#define CNN(P,N)				\
	if (P) {				\
		/* show when never-negotiate */	\
		CS(#N);				\
	}

	if (c->config->ike_version > 0) {
		CS(c->config->ike_info->version_name);
	}

	struct authby authby = c->local->host.config->authby;
	if (authby_is_set(authby)) {
		s += jam_string(buf, sep);
		s += jam_authby(buf, authby);
		sep = "+";
	}

	switch (c->config->child.encap_proto) {
	case ENCAP_PROTO_ESP:
		CS("ENCRYPT");
		break;
	case ENCAP_PROTO_AH:
		CS("AUTHENTICATE");
		break;
	default:
		break;
	}

	CT(child.ipcomp, COMPRESS);
	if (!never_negotiate(c) &&
	    c->config->child.encap_mode != ENCAP_MODE_UNSET) {
		name_buf eb;
		CS(str_enum_short(&encap_mode_names, c->config->child.encap_mode, &eb));
	}
	CT(child.pfs, PFS);
	CT(decap_dscp, DECAP_DSCP);
	CF(encap_dscp, DONT_ENCAP_DSCP);
	CT(nopmtudisc, NOPMTUDISC);
	CT(ms_dh_downgrade, MS_DH_DOWNGRADE);
	CT(pfs_rekey_workaround, PFS_REKEY_WORKAROUND);

	/* note reverse logic */
	CF(require_id_on_certificate, ALLOW_NO_SAN);

	CT(dns_match_id, DNS_MATCH_ID);
	CT(sha2_truncbug, SHA2_TRUNCBUG);

	/* note reversed logic */
	CF(rekey, DONT_REKEY);
	CF(share_lease, DONT_SHARE_LEASE);

	CT(reauth, REAUTH);

	CNN(is_opportunistic(c), OPPORTUNISTIC);
	CNN(is_from_group(c), GROUPINSTANCE);
	CNN(c->policy.route, ROUTE);
	CP(c->policy.up, UP);
	CP(c->policy.keep, KEEP);

	CP(is_xauth(c), XAUTH);
	CT(modecfg.pull, MODECFG_PULL);

	CT(aggressive, AGGRESSIVE);
	CT(overlapip, OVERLAPIP);

	CT(narrowing, IKEV2_ALLOW_NARROWING);

	CT(ikev2_pam_authorize, IKEV2_PAM_AUTHORIZE);

	CT(redirect.send_always, SEND_REDIRECT_ALWAYS);
	CT(redirect.send_never, SEND_REDIRECT_NEVER);
	CT(redirect.accept, ACCEPT_REDIRECT_YES);

	CT(ike_frag.allow, IKE_FRAG_ALLOW);
	CT(ike_frag.v1_force, IKE_FRAG_FORCE);

	/* need to reconstruct */
	if (c->config->v1_ikepad.message) {
		if (c->config->v1_ikepad.modecfg) {
			CS("IKEPAD_YES");
		}
		/* else is RFC */
	} else if (c->config->v1_ikepad.modecfg) {
		CS("IKEPAD_MODECFG"); /* can't happen!?! */
	} else {
		CS("IKEPAD_NO");
	}

	CT(mobike, MOBIKE);
	CT(ppk.allow, PPK_ALLOW);
	CT(ppk.insist, PPK_INSIST);
	CT(esn.no, ESN_NO);
	CT(esn.yes, ESN_YES);
	CT(intermediate, INTERMEDIATE);
	CT(ignore_peer_dns, IGNORE_PEER_DNS);
	CT(session_resumption, RESUME);

	CNN(is_group(c), GROUP);

	shunt = c->config->never_negotiate_shunt;
	if (shunt != SHUNT_UNSET) {
		s += jam_string(buf, sep);
		/*
		 * Keep tests happy, this needs a re-think.
		 */
#if 0
		s += jam_sparse_short(buf, &never_negotiate_shunt_names, shunt);
#else
		s += jam_enum_short(buf, &shunt_policy_names, shunt);
#endif
		sep = "+";
	}

	shunt = c->config->negotiation_shunt;
	if (shunt != SHUNT_DROP) {
		s += jam_string(buf, sep);
		s += jam_string(buf, "NEGO_");
		/*
		 * Keep tests happy, this needs a re-think.
		 */
#if 0
		s += jam_sparse_short(buf, &negotiation_shunt_names, shunt);
#else
		s += jam_enum_short(buf, &shunt_policy_names, shunt);
#endif
		sep = "+";
	}

	shunt = c->config->failure_shunt;
	if (shunt != SHUNT_NONE) {
		s += jam_string(buf, sep);
		s += jam_string(buf, "failure");
		/*
		 * Keep tests happy, this needs a re-think.
		 */
#if 0
		s += jam_sparse_short(buf, &failure_shunt_names, shunt);
#else
		s += jam_enum_short(buf, &shunt_policy_names, shunt);
#endif
		sep = "+";
	}

	CNN(never_negotiate(c), NEVER_NEGOTIATE);

	return s;
}

const char *str_connection_policies(const struct connection *c, policy_buf *buf)
{
	struct jambuf p = ARRAY_AS_JAMBUF(buf->buf);
	jam_connection_policies(&p, c);
	return buf->buf;
}

/*
 * Find an existing connection for a trapped outbound packet.
 *
 * This is attempted before we bother with gateway discovery.
 *
 *   + the connection is routed or instance_of_routed_template
 *     (i.e. approved for on-demand)
 *
 *   + local subnet contains src address (or we are our_client)
 *
 *   + remote subnet contains dst address (or peer is peer_client)
 *
 *   + don't care about Phase 1 IDs (we don't know)
 *
 * Note: result may still need to be instantiated.  The winner has the
 * highest policy priority.
 *
 * If there are several with that priority, we give preference to the
 * first one that is an instance.
 *
 * See also find_outgoing_opportunistic_template().
 */

struct connection *find_connection_for_packet(const ip_packet packet,
					      shunk_t sec_label,
					      const struct logger *logger)
{
	packet_buf pb;
	ldbg(logger, "%s() looking for an out-going connection that matches packet %s sec_label="PRI_SHUNK,
	     __func__, str_packet(&packet, &pb), pri_shunk(sec_label));

	const ip_selector packet_src = packet_src_selector(packet);
	const ip_endpoint packet_dst = packet_dst_endpoint(packet);

	struct connection *best_connection = NULL;
	connection_priority_t best_priority = BOTTOM_PRIORITY;

	struct connection_filter cq = {
		.search = {
			.order = NEW2OLD,
			.verbose.logger = logger,
			.where = HERE,
		},
	};
	while (next_connection(&cq)) {
		struct connection *c = cq.c;

		if (!oriented(c)) {
			ldbg(logger, "    skipping %s; not oriented",
			     c->name);
			continue;
		}

		if (is_group(c)) {
			ldbg(logger, "    skipping %s; a food group",
			     c->name);
			continue;
		}

		/*
		 * Don't try to mix 'n' match acquire sec_label with
		 * non-sec_label connections.
		 */
		if (sec_label.len == 0 && is_labeled(c)) {
			ldbg(logger, "    skipping %s; has unwanted label",
			     c->name);
			continue;
		}
		if (sec_label.len > 0 && !is_labeled(c)) {
			ldbg(logger, "    skipping %s; doesn't have label",
			     c->name);
			continue;
		}

		/*
		 * Labeled IPsec, always start with the either the
		 * template or the parent - assume the kernel won't
		 * send a duplicate child request.
		 */
		if (is_labeled_child(c)) {
			ldbg(logger, "    skipping %s; IKEv2 sec_label connection is a child",
			     c->name);
			continue;
		}

		/*
		 * When there is a sec_label, it needs to be within
		 * the configuration's range.
		 */
		if (sec_label.len > 0 /*implies c->config->sec_label > 0 */ &&
		    !sec_label_within_range("acquire", sec_label,
					    c->config->sec_label, logger)) {
			ldbg(logger,
			     "    skipping %s; packet sec_label="PRI_SHUNK" not within connection sec_label="PRI_SHUNK,
			     c->name, pri_shunk(sec_label),
			     pri_shunk(c->config->sec_label));
			continue;
		}

		/*
		 * Old comment from the dawn of time:
		 *
		 * Remember if the template is routed: if so, this
		 * instance applies for initiation even if it is
		 * created for responding.
		 *
		 * XXX: So, if the instance is routed, and so to is
		 * its template, then let it be reused for an outgoing
		 * connection?!?
		 */
		bool instance_initiation_ok =
			(is_opportunistic(c) &&
			 is_instance(c) &&
			 PEXPECT(logger, c->clonedfrom != NULL) /* because instance */ &&
			 kernel_route_installed(c->clonedfrom));
		if (!kernel_route_installed(c) &&
		    !instance_initiation_ok &&
		    c->config->sec_label.len == 0) {
			ldbg(logger, "    skipping %s; !routed,!instance_initiation_ok,!sec_label",
			     c->name);
			continue;
		}

		/*
		 * The triggering packet needs to be within
		 * the client.
		 */

		connection_priority_t src = 0;
		FOR_EACH_ITEM(local, &c->local->child.selectors.proposed) {
			/*
			 * The packet source address is a selector, and not endpoint.
			 *
			 * If the triggering source port passed into
			 * the kernel is ephemeral (i.e., passed in
			 * with the value zero) that same ephemeral
			 * (zero) port is passed on to pluto.  A zero
			 * (unknown) port is not valid for an
			 * endpoint.
			 */
			if (selector_in_selector(packet_src, *local)) {
				/* add one so always non-zero */
				unsigned score =
					(((local->hport == packet_src.hport) << 2) |
					 ((local->ipproto == packet_src.ipproto) << 1) |
					 1);
				src = max(score, src);
			}
		}

		if (src == 0) {
			LDBGP_JAMBUF(DBG_BASE, logger, buf) {
				jam_string(buf, "    skipping ");
				jam_connection(buf, c);
				jam_string(buf, "; packet dst ");
				jam_selector(buf, &packet_src);
				jam_string(buf, " not in selectors ");
				jam_selectors(buf, c->local->child.selectors.proposed);
			}
			continue;
		}

		connection_priority_t dst = 0;
		FOR_EACH_ITEM(remote, &c->remote->child.selectors.proposed) {
			/*
			 * The packet destination address is always a
			 * proper endpoint.
			 */
			if (endpoint_in_selector(packet_dst, *remote)) {
				/* add one so always non-zero */
				unsigned score =
					(((remote->hport == packet_dst.hport) << 2) | 1);
				dst = max(score, dst);
			}
		}

		if (dst == 0) {
			LDBGP_JAMBUF(DBG_BASE, logger, buf) {
				jam_string(buf, "    skipping ");
				jam_connection(buf, c);
				jam_string(buf, "; packet dst ");
				jam_endpoint(buf, &packet_dst);
				jam_string(buf, " not in selectors ");
				jam_selectors(buf, c->remote->child.selectors.proposed);
			}
			continue;
		}

		/*
		 * More exact is better and bigger
		 *
		 * Instance score better than the template.  Exact
		 * protocol or exact port gets more points (see
		 * above).
		 */
		connection_priority_t priority =
			((connection_priority(c) << 3)/*space-for-2-bits+overflow*/ +
			 (src - 1/*2-bits, strip 1 added above*/) +
			 (dst - 1/*2-bits, strip 1 added above*/));

		if (best_connection != NULL &&
		    priority <= best_priority) {
			ldbg(logger,
			     "    skipping %s priority %"PRIu32"; doesn't best %s priority %"PRIu32,
			     c->name,
			     priority,
			     best_connection->name,
			     best_priority);
			continue;
		}

		/* current is best; log why */
		if (best_connection == NULL) {
			ldbg(logger,
			     "    choosing %s priority %"PRIu32"; as first best",
			     c->name,
			     priority);
		} else {
			ldbg(logger,
			     "    choosing %s priority %"PRIu32"; as bests %s priority %"PRIu32,
			     c->name,
			     priority,
			     best_connection->name,
			     best_priority);
		}

		best_connection = c;
		best_priority = priority;
	}

	if (best_connection == NULL) {
		ldbg(logger, "  concluding with empty; no match");
		return NULL;
	}

	/*
	 * XXX: So that the best connection can prevent negotiation?
	 */
	if (never_negotiate(best_connection)) {
		ldbg(logger, "  concluding with empty; best connection %s was NEVER_NEGOTIATE",
		     best_connection->name);
		return NULL;
	}

	name_buf kb;
	ldbg(logger, "  concluding with %s priority %" PRIu32 " kind=%s",
	     best_connection->name,
	     best_priority,
	     str_enum_short(&connection_kind_names, best_connection->local->kind, &kb));
	return best_connection;
}

/*
 * Recursively order instances.
 */

static int connection_instance_compare(const struct connection *cl,
				       const struct connection *cr)
{
	if (cl->clonedfrom != NULL && cr->clonedfrom != NULL) {
		int ret = connection_instance_compare(cl->clonedfrom,
						      cr->clonedfrom);
		if (ret != 0) {
			return ret;
		}
	}

	return (cl->instance_serial < cr->instance_serial ? -1 :
		cl->instance_serial > cr->instance_serial ? 1 :
		0);
}

/* signed result suitable for quicksort */
int connection_compare(const struct connection *cl,
		       const struct connection *cr)
{
	int ret;

	ret = strcmp(cl->base_name, cr->base_name);
	if (ret != 0) {
		return ret;
	}

	/* note: enum connection_kind behaves like int */
	ret = (long)cl->local->kind - (long)cr->local->kind;
	if (ret != 0) {
		return ret;
	}

	/* same name, and same type */
	ret = connection_instance_compare(cl, cr);
	if (ret != 0) {
		return ret;
	}

	connection_priority_t pl = connection_priority(cl);
	connection_priority_t pr = connection_priority(cr);
	return (pl < pr ? -1 :
		pl > pr ? 1 :
		0);
}

static int connection_compare_qsort(const void *l, const void *r)
{
	return connection_compare(*(const struct connection *const *)l,
				  *(const struct connection *const *)r);
}

/*
 * Return a sorted array of connections.  Caller must free.
 *
 * See also sort_states().
 */

struct connections *sort_connections(void)
{
	/* count up the connections */
	unsigned nr_connections = 0;
	{
		struct connection_filter cq = {
			.search = {
				.order = OLD2NEW,
				.verbose.logger = &global_logger,
				.where = HERE,
			},
		};
		while (next_connection(&cq)) {
			nr_connections++;
		}
	}

	struct connections *connections = alloc_items(struct connections,
						      nr_connections);

	{
		unsigned i = 0;
		struct connection_filter cq = {
			.search = {
				.order = OLD2NEW,
				.verbose.logger = &global_logger,
				.where = HERE,
			},
		};
		while (next_connection(&cq)) {
			connections->item[i++] = cq.c;
		}
		passert(i == nr_connections);
	}

	/* sort it! */
	qsort(connections->item, nr_connections, sizeof(struct connection *),
	      connection_compare_qsort);

	return connections;
}

/*
 * Find a sourceip for the address family.
 */
ip_address config_end_sourceip(const ip_selector client, const struct child_end_config *end)
{
	const struct ip_info *afi = selector_info(client);
	FOR_EACH_ITEM(sourceip, &end->sourceip) {
		if (afi == address_type(sourceip)) {
			return *sourceip;
		}
	}

	return unset_address;
}

ip_address spd_end_sourceip(const struct spd_end *spde)
{
	/*
	 * Find a configured sourceip within the SPD's client.
	 */
	ip_address sourceip = config_end_sourceip(spde->client, spde->child->config);
	if (sourceip.ip.is_set) {
		return sourceip;
	}

	/*
	 * Failing that see if CP is involved.  IKEv1 always leaves
	 * client_address_translation false.
	 */
	const struct ip_info *afi = selector_info(spde->client);
	if (afi != NULL &&
	    spde->child->lease[afi->ip.version].ip.is_set &&
	    !spde->child->config->has_client_address_translation) {
		/* XXX: same as .lease[]? */
		ip_address a = selector_prefix(spde->client);
		pexpect(address_eq_address(a, spde->child->lease[afi->ip.version]));
		return selector_prefix(spde->client);
	}

	/* or give up */
	return unset_address;
}

/*
 * If the connection contains a newer SA, return it.
 */
so_serial_t get_newer_sa_from_connection(struct state *st)
{
	struct connection *c = st->st_connection;
	so_serial_t newest;

	if (IS_IKE_SA(st)) {
		newest = c->established_ike_sa;
		ldbg(st->logger, "picked established_ike_sa "PRI_SO" for "PRI_SO"",
		     pri_so(newest), pri_so(st->st_serialno));
	} else {
		newest = c->established_child_sa;
		ldbg(st->logger, "picked established_child_sa "PRI_SO" for "PRI_SO"",
		     pri_so(newest), pri_so(st->st_serialno));
	}

	if (newest != SOS_NOBODY && newest != st->st_serialno) {
		return newest;
	} else {
		return SOS_NOBODY;
	}
}

/* check to see that Ids of peers match */
bool same_peer_ids(const struct connection *c, const struct connection *d)
{
	return (same_id(&c->local->host.id, &d->local->host.id) &&
		same_id(&c->remote->host.id, &d->remote->host.id));
}

/* seems to be a good spot for now */
bool dpd_active_locally(const struct connection *c)
{
	return deltasecs(c->config->dpd.delay) != 0;
}

void append_end_selector(struct connection_end *end,
			 ip_selector selector/*can be unset!*/,
			 struct verbose verbose)
{
	/* space? */
	vassert(end->child.selectors.proposed.len < elemsof(end->child.selectors.assigned));

	/*
	 * Ensure proposed is pointing at assigned aka scratch.
	 */
	if (end->child.selectors.proposed.list == NULL) {
		vassert(end->child.selectors.proposed.len == 0);
		end->child.selectors.proposed.list = end->child.selectors.assigned;
	} else {
		vassert(end->child.selectors.proposed.len > 0);
		vassert(end->child.selectors.proposed.list == end->child.selectors.assigned);
	}

	/* append the selector to assigned */
	unsigned i = end->child.selectors.proposed.len++;
	end->child.selectors.assigned[i] = selector;

	selector_buf nb;
	vdbg("%s.child.selectors.proposed[%d] %s "PRI_WHERE,
	     end->config->leftright,
	     i, str_selector(&selector, &nb),
	     pri_where(verbose.where));
}

void update_end_selector_where(struct connection *c, enum end lr,
			       ip_selector new_selector,
			       const char *excuse, where_t where)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, c->logger, NULL);
	verbose.where = where;

	struct connection_end *end = &c->end[lr];
	struct child_end *child = &end->child;
	struct child_end_selectors *end_selectors = &end->child.selectors;
	const char *leftright = end->config->leftright;

	vexpect(end_selectors->proposed.len == 1);
	ip_selector old_selector = end_selectors->proposed.list[0];
	selector_buf ob, nb;
	vdbg("%s() update %s.child.selector %s -> %s "PRI_WHERE,
	     __func__, leftright,
	     str_selector(&old_selector, &ob),
	     str_selector(&new_selector, &nb),
	     pri_where(where));
	verbose.level++;

	/*
	 * Point the selectors list at and UPDATE the scratch value.
	 *
	 * Is the assumption that this is only applied when there is a
	 * single selector.  Reasonable?  Certainly don't want to
	 * truncate the selector list.
	 */
	zero(&end->child.selectors.proposed);
	append_end_selector(end, new_selector, verbose);

	/*
	 * If needed, also update the SPD.  It's assumed for this code
	 * path there is only one (just like there is only one
	 * selector).
	 */
	if (c->child.spds.len == 1) {
		ip_selector old_client = c->child.spds.list->end[lr].client;
		if (!selector_eq_selector(old_selector, old_client)) {
			selector_buf sb, cb;
			vlog_pexpect(where,
				     "%s() %s.child.selector %s does not match %s.spd.client %s",
				     __func__, leftright,
				     str_selector(&old_selector, &sb),
				     end->config->leftright,
				     str_selector(&old_client, &cb));
		}
		c->child.spds.list->end[lr].client = new_selector;
	}

	/*
	 * When there's a selectors.list, any update to the first
	 * selector should be a no-op?  Lets find out.
	 *
	 * XXX: the CP payload code violoates this.
	 *
	 * It stomps on the child.selector without even looking at the
	 * traffic selectors.
	 *
	 * XXX: the TS code violates this.
	 *
	 * It scribbles the result of the TS negotiation on the
	 * child.selector.
	 */
	if (child->config->selectors.len > 0) {
		ip_selector selector = child->config->selectors.list[0];
		if (selector_eq_selector(new_selector, selector)) {
			selector_buf sb;
			vdbg("%s.child.selector %s matches selectors[0] "PRI_WHERE,
			     leftright,
			     str_selector(&new_selector, &sb),
			     pri_where(where));
		} else if (excuse != NULL) {
			selector_buf sb, cb;
			vdbg("%s.child.selector %s does not match %s.selectors[0] %s but %s "PRI_WHERE,
			     leftright, str_selector(&new_selector, &sb),
			     leftright, str_selector(&selector, &cb),
			     excuse, pri_where(where));
		} else {
			selector_buf sb, cb;
			vlog_pexpect(where, "%s() %s.child.selector %s does not match %s.selectors[0] %s",
				     __func__, leftright, str_selector(&new_selector, &sb),
				     leftright, str_selector(&selector, &cb));
		}
	}
}

err_t connection_requires_tss(const struct connection *c)
{
	if (c->config->ike_version == IKEv1) {
		return NULL;
	}
	FOR_EACH_ELEMENT(end, c->end) {
		if (end->config->child.addresspools.len > 1) {
			return "addresspools";
		}
		if (end->config->child.selectors.len > 1) {
			return "subnets";
		}
		if (end->config->child.sourceip.len > 1) {
			return "sourceips";
		}
	}
	return NULL;
}

bool never_negotiate(const struct connection *c)
{
	if (c == NULL) {
		return false;
	}
	return (c->config->never_negotiate_shunt != SHUNT_UNSET);
}

bool is_opportunistic(const struct connection *c)
{
	return (c != NULL && c->config->opportunistic);
}

bool is_instance(const struct connection *c)
{
	if (c == NULL) {
		return false;
	}
	switch (c->local->kind) {
	case CK_INVALID:
		break;
	case CK_PERMANENT:
	case CK_TEMPLATE:
	case CK_GROUP:
	case CK_LABELED_TEMPLATE:
		return false;
	case CK_INSTANCE:
	case CK_LABELED_PARENT:
	case CK_LABELED_CHILD:
		return true;
	}
	bad_case(c->local->kind);
}

bool is_template(const struct connection *c)
{
	if (c == NULL) {
		return false;
	}
	switch (c->local->kind) {
	case CK_INVALID:
		break;
	case CK_TEMPLATE:
	case CK_LABELED_TEMPLATE:
		return true;
	case CK_PERMANENT:
	case CK_GROUP:
	case CK_INSTANCE:
	case CK_LABELED_PARENT:
	case CK_LABELED_CHILD:
		return false;
	}
	bad_case(c->local->kind);
}

bool is_opportunistic_template(const struct connection *c)
{
	if (c == NULL) {
		return false;
	}
	switch (c->local->kind) {
	case CK_INVALID:
		break;
	case CK_TEMPLATE:
		return is_opportunistic(c);
	case CK_LABELED_TEMPLATE:
	case CK_PERMANENT:
	case CK_GROUP:
	case CK_INSTANCE:
	case CK_LABELED_PARENT:
	case CK_LABELED_CHILD:
		return false;
	}
	bad_case(c->local->kind);
}

bool is_permanent(const struct connection *c)
{
	if (c == NULL) {
		return false;
	}
	switch (c->local->kind) {
	case CK_INVALID:
		break;
	case CK_PERMANENT:
		return true;
	case CK_TEMPLATE:
	case CK_LABELED_TEMPLATE:
	case CK_GROUP:
	case CK_INSTANCE:
	case CK_LABELED_PARENT:
	case CK_LABELED_CHILD:
		return false;
	}
	bad_case(c->local->kind);
}

bool is_group(const struct connection *c)
{
	if (c == NULL) {
		return false;
	}
	switch (c->local->kind) {
	case CK_INVALID:
		break;
	case CK_GROUP:
		return true;
	case CK_PERMANENT:
	case CK_TEMPLATE:
	case CK_LABELED_TEMPLATE:
	case CK_INSTANCE:
	case CK_LABELED_PARENT:
	case CK_LABELED_CHILD:
		return false;
	}
	bad_case(c->local->kind);
}

bool is_from_group(const struct connection *c)
{
	if (c == NULL) {
		return false;
	}
	switch (c->local->kind) {
	case CK_INVALID:
		break;
	case CK_GROUP:
	case CK_PERMANENT:
	case CK_LABELED_TEMPLATE:
	case CK_LABELED_PARENT:
	case CK_LABELED_CHILD:
		return false;
	case CK_TEMPLATE:
		/* cloned from could be null; is_group() handles
		 * that */
		return is_group(c->clonedfrom);
	case CK_INSTANCE:
		/* cloned from could be null; is_group() handles
		 * that */
		return is_group(c->clonedfrom->clonedfrom);
	}
	bad_enum(c->logger, &connection_kind_names, c->local->kind);
}

bool is_labeled_where(const struct connection *c, where_t where)
{
	if (c == NULL) {
		return false;
	}
	switch (c->local->kind) {
	case CK_INVALID:
		break;
	case CK_LABELED_PARENT:
	case CK_LABELED_CHILD:
	case CK_LABELED_TEMPLATE:
		PASSERT_WHERE(c->logger, where, c->config->sec_label.len > 0);
		return true;
	case CK_TEMPLATE:
	case CK_PERMANENT:
	case CK_GROUP:
	case CK_INSTANCE:
		PASSERT_WHERE(c->logger, where, c->config->sec_label.len == 0);
		return false;
	}
	bad_case(c->local->kind);
}

bool is_labeled_template_where(const struct connection *c, where_t where)
{
	if (c == NULL) {
		return false;
	}
	switch (c->local->kind) {
	case CK_INVALID:
		break;
	case CK_LABELED_TEMPLATE:
		PASSERT_WHERE(c->logger, where, (c->config->sec_label.len > 0 &&
						 c->child.sec_label.len == 0));
		return true;
	case CK_LABELED_PARENT:
	case CK_LABELED_CHILD:
	case CK_TEMPLATE:
	case CK_PERMANENT:
	case CK_GROUP:
	case CK_INSTANCE:
		return false;
	}
	bad_case(c->local->kind);
}

bool is_labeled_parent_where(const struct connection *c, where_t where)
{
	if (c == NULL) {
		return false;
	}
	switch (c->local->kind) {
	case CK_INVALID:
		break;
	case CK_LABELED_PARENT:
		PASSERT_WHERE(c->logger, where, (c->config->sec_label.len > 0 &&
						 c->child.sec_label.len == 0));
		return true;
	case CK_LABELED_TEMPLATE:
	case CK_LABELED_CHILD:
	case CK_TEMPLATE:
	case CK_PERMANENT:
	case CK_GROUP:
	case CK_INSTANCE:
		return false;
	}
	bad_case(c->local->kind);
}

bool is_labeled_child_where(const struct connection *c, where_t where)
{
	if (c == NULL) {
		return false;
	}
	switch (c->local->kind) {
	case CK_INVALID:
		break;
	case CK_LABELED_CHILD:
		PASSERT_WHERE(c->logger, where, (c->config->sec_label.len > 0 &&
						 c->child.sec_label.len > 0));
		return true;
	case CK_LABELED_TEMPLATE:
	case CK_LABELED_PARENT:
	case CK_TEMPLATE:
	case CK_PERMANENT:
	case CK_GROUP:
	case CK_INSTANCE:
		return false;
	}
	bad_case(c->local->kind);
}

bool can_have_sa(const struct connection *c, 
		 enum sa_kind sa_kind)
{
	if (c == NULL) {
		return false;
	}
	switch (sa_kind) {
	case IKE_SA:
		switch (c->local->kind) {
		case CK_INVALID:
			break;
		case CK_LABELED_CHILD:
		case CK_GROUP:
		case CK_LABELED_TEMPLATE:
		case CK_TEMPLATE:
			return false;
		case CK_LABELED_PARENT:
		case CK_PERMANENT:
		case CK_INSTANCE:
			return true;
		}
		bad_enum(c->logger, &connection_kind_names, c->local->kind);
	case CHILD_SA:
		switch (c->local->kind) {
		case CK_INVALID:
			break;
		case CK_LABELED_TEMPLATE:
		case CK_LABELED_PARENT:
		case CK_TEMPLATE:
		case CK_GROUP:
			return false;
		case CK_PERMANENT:
		case CK_INSTANCE:
		case CK_LABELED_CHILD:
			return true;
		}
		bad_enum(c->logger, &connection_kind_names, c->local->kind);
	}
	bad_case(sa_kind);
}

/*
 * XXX: is this too strict?
 *
 * addconn was setting XAUTH when either of SERVER or CLIENT was set,
 * but the below only considers SERVER.
 */
 
bool is_xauth(const struct connection *c)
{
	return (c->local->host.config->xauth.server || c->remote->host.config->xauth.server ||
		c->local->host.config->xauth.client || c->remote->host.config->xauth.client);
}

/* IKE SA | ISAKMP SA || Child SA | IPsec SA */
const char *connection_sa_name(const struct connection *c, enum sa_kind sa_kind)
{
	switch (sa_kind) {
	case IKE_SA:
		return c->config->ike_info->parent_sa_name;
	case CHILD_SA:
		return c->config->ike_info->child_sa_name;
	}
	bad_case(sa_kind);
}

/* IKE | ISAKMP || Child | IPsec */
const char *connection_sa_short_name(const struct connection *c, enum sa_kind sa_kind)
{
	switch (sa_kind) {
	case IKE_SA:
		return c->config->ike_info->parent_name;
	case CHILD_SA:
		return c->config->ike_info->child_name;
	}
	bad_case(sa_kind);
}

struct child_policy child_sa_policy(const struct connection *c)
{
	if (c->config->child.encap_proto == ENCAP_PROTO_ESP ||
	    c->config->child.encap_proto == ENCAP_PROTO_AH) {
		return (struct child_policy) {
			.is_set = true,
			.transport = (c->config->child.encap_mode == ENCAP_MODE_TRANSPORT),
			.compress = c->config->child.ipcomp,
		};
	}

	return (struct child_policy) {0};
}

/*
 * Find newest Phase 1 negotiation state object for suitable for
 * connection c.
 *
 * Also used to find an IKEv1 ISAKMP SA suitable for sending a delete.
 */

bool connections_can_share_parent(const struct connection *c, const struct connection *d)
{
	/*
	 * Need matching version and parent for starters!
	 */
	if (c->config->ike_version != d->config->ike_version) {
		return false;
	}

	/*
	 * Check the initial host-pair.  Do these two mean that a much
	 * faster host-pair search could be used?
	 *
	 * Not really, it's called when searching for an IKE SA, and
	 * not a connection.  However, a connection search that uses
	 * .negotiating_ike_sa and/or .established_ike_sa, might?
	 */
	if (!address_eq_address(c->local->host.addr, d->local->host.addr)) {
		return false;
	}
	if (!address_eq_address(c->remote->host.first_addr, d->remote->host.first_addr)) {
		return false;
	}

	/*
	 * Also check any redirection.
	 */
	if (!address_eq_address(c->remote->host.addr, d->remote->host.addr)) {
		return false;
	}

	/*
	 * i.e., connection and IKE SA have the same authentication.
	 */
	if (!same_peer_ids(c, d)) {
		return false;
	}

	return true;
}

reqid_t child_reqid(const struct config *config, const struct logger *logger)
{
	reqid_t reqid = (config->sa_reqid != 0 ? config->sa_reqid :
			 gen_reqid());
	ldbg(logger, "child.reqid="PRI_REQID" because c->sa_reqid="PRI_REQID" (%s)",
	     pri_reqid(reqid),
	     pri_reqid(config->sa_reqid),
	     (config->sa_reqid == 0 ? "generate" : "use"));
	return reqid;
}

size_t jam_co(struct jambuf *buf, co_serial_t co)
{
	return jam(buf, PRI_CO, co);
}
