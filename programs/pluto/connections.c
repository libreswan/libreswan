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
#include "lswconf.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "secrets.h"
#include "lswnss.h"
#include "authby.h"

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
#include "ike_alg_dh.h"		/* for ike_alg_dh_none; */
#include "sparse_names.h"
#include "ikev2_ike_session_resume.h"	/* for pfree_session() */
#include "whack_pubkey.h"
#include "binaryscale-iec-60027-2.h"

static void discard_connection(struct connection **cp, bool connection_valid, where_t where);

void vdbg_connection(const struct connection *c,
		     struct verbose verbose, where_t where,
		     const char *message, ...)
{
	if (!LDBGP(DBG_BASE, c->logger)) {
		return;
	}
	verbose.rc_flags = DEBUG_STREAM;
	/* MESSAGE ... */
	LLOG_JAMBUF(verbose.rc_flags, verbose.logger, buf) {
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
	LLOG_JAMBUF(verbose.rc_flags, verbose.logger, buf) {
		jam(buf, PRI_VERBOSE, pri_verbose);
		jam_string(buf, "connection ");
		jam_connection_co(buf, c);
		if (c->clonedfrom != 0) {
			jam_string(buf, " clonedfrom ");
			jam_connection_co(buf, c->clonedfrom);
		}
		jam_string(buf, ": ");
		jam_connection(buf, c);
	}
	verbose.level++;
	/* host local->remote */
	LLOG_JAMBUF(verbose.rc_flags, verbose.logger, buf) {
		jam(buf, PRI_VERBOSE, pri_verbose);
		jam_string(buf, "host: ");
		jam_address(buf, &c->local->host.addr);
		jam_string(buf, "->");
		jam_address(buf, &c->remote->host.addr);
	}
	/* host id */
	LLOG_JAMBUF(verbose.rc_flags, verbose.logger, buf) {
		jam(buf, PRI_VERBOSE, pri_verbose);
		jam_string(buf, "id: ");
		jam_id(buf, &c->local->host.id);
		jam_string(buf, " -> ");
		jam_id(buf, &c->remote->host.id);
	}
	/* routing+kind ... */
	LLOG_JAMBUF(verbose.rc_flags, verbose.logger, buf) {
		jam(buf, PRI_VERBOSE, pri_verbose);
		jam_string(buf, "routing+kind: ");
		jam_enum_short(buf, &routing_names, c->routing.state);
		jam_string(buf, " ");
		jam_enum_short(buf, &connection_kind_names, c->local->kind);
	}
	/* selectors local->remote */
	LLOG_JAMBUF(verbose.rc_flags, verbose.logger, buf) {
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
				if (lease->is_set) {
					jam_string(buf, " ");
					jam_address(buf, lease);
				}
			}
			jam_string(buf, " ->");
		}
	}
	/* SPDs local->remote */
	LLOG_JAMBUF(verbose.rc_flags, verbose.logger, buf) {
		jam(buf, PRI_VERBOSE, pri_verbose);
		jam_string(buf, "spds:");
		FOR_EACH_ITEM(spd, &c->child.spds) {
			jam_string(buf, " ");
			jam_selector_pair(buf, &spd->local->client, &spd->remote->client);
		}
	}
	/* policy */
	LLOG_JAMBUF(verbose.rc_flags, verbose.logger, buf) {
		jam(buf, PRI_VERBOSE, pri_verbose);
		jam_string(buf, "policy: ");
		jam_connection_policies(buf, c);
	}
	/* sec-label */
	if (c->config->sec_label.len > 0) {
		LLOG_JAMBUF(verbose.rc_flags, verbose.logger, buf) {
			jam(buf, PRI_VERBOSE, pri_verbose);
			jam_string(buf, "sec_label: ");
			if (c->child.sec_label.len > 0) {
				jam(buf, PRI_SHUNK, pri_shunk(c->child.sec_label));
				jam_string(buf, " <= ");
			}
			jam(buf, PRI_SHUNK, pri_shunk(c->config->sec_label));
		}
	}
}

static bool never_negotiate_wm(const struct whack_message *wm)
{
	/* with no never-negotiate shunt, things must negotiate */
	return (wm->never_negotiate_shunt != SHUNT_UNSET);
}

static bool is_opportunistic_wm_end(const struct whack_end *end)
{
	return (end->host_type == KH_OPPO ||
		end->host_type == KH_OPPOGROUP);
}

static bool is_opportunistic_wm(const struct whack_message *wm)
{
	return (is_opportunistic_wm_end(&wm->end[LEFT_END]) ||
		is_opportunistic_wm_end(&wm->end[RIGHT_END]));
}

static bool is_group_wm_end(const struct whack_end *end)
{
	return (end->host_type == KH_GROUP ||
		end->host_type == KH_OPPOGROUP);
}

static bool is_group_wm(const struct whack_message *wm)
{
	return (is_group_wm_end(&wm->end[LEFT_END]) ||
		is_group_wm_end(&wm->end[RIGHT_END]));
}

/*
 * Is there an existing connection with NAME?
 */

bool connection_with_name_exists(const char *name)
{
	struct connection_filter cq = {
		.name = name,
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
	return laddref_where(c, owner, where);
}

void connection_delref_where(struct connection **cp, const struct logger *owner, where_t where)
{
	struct connection *c = ldelref_where(cp, owner, where);
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

	unsigned refcnt = refcnt_peek(c, logger);
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
		.ike_version = c->config->ike_version,
		.search = {
			.order = OLD2NEW,
			.verbose.logger = logger,
			.where = HERE,
		},
	};
	while (next_connection(&instance)) {
		connection_buf cb;
		llog_pexpect(logger, where,
			     "connection "PRI_CO" [%p] still instantiated as "PRI_CONNECTION" [%p]",
			     pri_connection_co(c), c,
			     pri_connection(instance.c, &cb),
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
			.verbose.logger = &global_logger,
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
		if (c->pool[afi->ip_index] != NULL) {
			free_that_address_lease(c, afi, c->logger);
			addresspool_delref(&c->pool[afi->ip_index], c->logger);
		}
	}

	/* find and delete c from the host pair list */
#if 0
	PEXPECT(c->logger, !oriented(c));
#endif
	disorient(c);

	/*
	 * Disorienting should have released .ipsec_interface, and
	 * unrouting should have released the
	 * .ipsec_interface_address.
	 */
	PEXPECT(c->logger, c->ipsec_interface == NULL);
	PEXPECT(c->logger, c->ipsec_interface_address == NULL);

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
		passert(c->clonedfrom == NULL); /*i.e., root */
		pfreeany(config->vti.interface);
		free_chunk_content(&config->sec_label);
		free_proposals(&config->ike_proposals.p);
		free_proposals(&config->child_sa.proposals.p);
		free_ikev2_proposals(&config->v2_ike_proposals);
		free_ikev2_proposals(&config->child_sa.v2_ike_auth_proposals);
		pfreeany(config->connalias);
		pfreeany(config->dnshostname);
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
			pfreeany(end->host.addr_name);
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
		pfree(c->root_config);
	}

	/* connection's final gasp; need's c->name */
	pfreeany(c->name);
	pfreeany(c->prefix);
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
				     where_t where)
{
	struct host_end *host = &c->end[end].host;
	struct host_end *other_host = &c->end[!end].host;

	address_buf hab;
	ldbg(c->logger, "updating host ends from %s.host.addr %s",
	     host->config->leftright, str_address(&host_addr, &hab));

	/* could be %any but can't be an address */
	PASSERT_WHERE(c->logger, where, !address_is_specified(host->addr));

	/* can't be unset; but could be %any[46] */
	const struct ip_info *afi = address_info(host_addr);
	PASSERT_WHERE(c->logger, where, afi != NULL); /* since specified */

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
		dbg("  updated %s.id from %s (config=%s) to %s",
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
		unsigned host_port = hport(end_host_port(host, other_host));
		dbg("  updated %s.host_port from %u to %u",
		    host->config->leftright,
		    host->port, host_port);
		host->port = host_port;
	}

	/*
	 * Set the other end's NEXTHOP.
	 *
	 * When not specified by the config, use this end's HOST_ADDR,
	 * as in:
	 *
	 *   other_host.ADDR -> other_host.NEXTHOP -> ADDR.
	 */
	other_host->nexthop = other_host->config->nexthop;
	if (address_is_specified(host_addr) &&
	    !address_is_specified(other_host->nexthop)) {
		other_host->nexthop = host_addr;
	}
	address_buf old, new;
	dbg("  updated %s.host_nexthop from %s to %s",
	    other_host->config->leftright,
	    str_address(&other_host->config->nexthop, &old),
	    str_address(&other_host->nexthop, &new));
}

/*
 * Figure out the host / client address family.
 *
 * Returns diag() when there's a conflict.  leaves *AFI NULL if could
 * not be determined.
 */

#define EXTRACT_AFI(NAME, FIELD)					\
	{								\
		const struct ip_info *wfi = address_info(FIELD);	\
		if (*afi == NULL) {					\
			*afi = wfi;					\
			leftright = w->leftright;			\
			name = NAME;					\
			struct jambuf buf = ARRAY_AS_JAMBUF(value);	\
			jam_address(&buf, &FIELD);			\
		} else if (wfi != NULL && wfi != *afi) {		\
			address_buf tb;					\
			return diag("host address family %s from %s%s=%s conflicts with %s%s=%s", \
				    (*afi)->ip_name, leftright, name, value, \
				    w->leftright, NAME, str_address(&FIELD, &tb)); \
		}							\
	}

static diag_t extract_host_afi(const struct whack_message *wm,
			       const struct ip_info **afi)
{
	*afi = NULL;
	const char *leftright;
	const char *name;
	char value[sizeof(selector_buf)];
	FOR_EACH_THING(w, &wm->end[LEFT_END], &wm->end[RIGHT_END]) {
		EXTRACT_AFI(""/*left""=,right""=*/, w->host_addr);
		EXTRACT_AFI("nexthop", w->nexthop);
	}
	return NULL;
}

/* assume 0 is unset */

static unsigned extract_sparse(const char *leftright, const char *name,
			       unsigned value,
			       unsigned value_when_unset /*i.e., 0*/,
			       unsigned value_when_never_negotiate,
			       const struct sparse_names *names,
			       const struct whack_message *wm,
			       struct logger *logger)
{
	if (never_negotiate_wm(wm)) {
		if (value != 0) {
			sparse_buf sb;
			llog(RC_LOG, logger,
			     "warning: %s%s=%s ignored for never-negotiate connection",
			     leftright, name, str_sparse(names, value, &sb));
		}
		return value_when_never_negotiate;
	}

	if (value == 0) {
		return value_when_unset;
	}

	return value;
}

static bool extract_yn(const char *leftright, const char *name,
		       enum yn_options value, enum yn_options value_when_unset,
		       const struct whack_message *wm, struct logger *logger)
{
	enum yn_options yn = extract_sparse(leftright, name, value,
					    value_when_unset, /*never*/YN_NO,
					    &yn_option_names, wm, logger);

	switch (yn) {
	case YN_NO: return false;
	case YN_YES: return true;
	default:
		bad_sparse(logger, &yn_option_names, yn);
	}
}

/*
 * YN option that is only used when P is enabled.  When P is disabled a
 * warning is issued but the value is saved regardless:
 *
 * This is to stop:
 *   iptfs=no; iptfs-fragmentation=yes
 * showing as:
 *   iptfs: no; fragmentation: no;
 */

static bool extract_yn_p(const char *leftright, const char *name, enum yn_options yn,
			 enum yn_options value_when_unset,
			 const struct whack_message *wm, struct logger *logger,
			 const char *p_leftright, const char *p_name, enum yn_options p)
{
	const struct sparse_names *names = &yn_option_names;

	if (yn == 0) {
		/* no argument */
		return value_when_unset;
	}

	bool value;
	switch (yn) {
	case YN_NO: value = false; break;
	case YN_YES: value = true; break;
	default:
		bad_sparse(logger, &yn_option_names, yn);
	}

	/* complain? */
	if (never_negotiate_wm(wm)) {
		name_buf sb;
		llog(RC_LOG, logger,
		     "warning: %s%s=%s ignored for never-negotiate connection",
		     leftright, name, str_sparse(names, value, &sb));
	} else if (p == YN_UNSET) {
		name_buf sb;
		llog(RC_LOG, logger,
		     "warning: %s%s=%s ignored without %s%s=yes",
		     leftright, name, str_sparse(names, value, &sb),
		     p_leftright, p_name);
	} else if (p == YN_NO) {
		name_buf sb;
		llog(RC_LOG, logger,
		     "warning: %s%s=%s ignored when %s%s=no",
		     leftright, name, str_sparse(names, value, &sb),
		     p_leftright, p_name);
	}

	return value;
}

static enum yna_options extract_yna(const char *leftright, const char *name,
				    enum yna_options yna,
				    enum yna_options value_when_unset,
				    enum yna_options value_when_never_negotiate,
				    const struct whack_message *wm,
				    struct logger *logger)
{
	return extract_sparse(leftright, name, yna,
			      value_when_unset,
			      value_when_never_negotiate,
			      &yna_option_names, wm, logger);
}

/* terrible name */

static bool can_extract_string(const char *leftright,
			       const char *name,
			       const char *value,
			       const struct whack_message *wm,
			       struct logger *logger)
{
	if (value == NULL) {
		return false;
	}

	if (never_negotiate_wm(wm)) {
		llog(RC_LOG, logger,
		     "warning: %s%s=%s ignored for never-negotiate connection",
		     leftright, name, value);
		return false;
	}

	return true;
}

static char *extract_string(const char *leftright, const char *name,
			    const char *string,
			    const struct whack_message *wm,
			    struct logger *logger)
{
	if (!can_extract_string(leftright, name, string, wm, logger)) {
		return NULL;
	}

	return clone_str(string, name);
}

static unsigned extract_enum_name(const char *leftright,
				  const char *name,
				  const char *value, unsigned unset,
				  const struct enum_names *names,
				  const struct whack_message *wm,
				  diag_t *d,
				  struct logger *logger)
{
	(*d) = NULL;

	if (never_negotiate_wm(wm)) {
		if (value != NULL) {
			llog(RC_LOG, logger,
			     "warning: %s%s=%s ignored for never-negotiate connection",
			     leftright, name, value);
		}
		return unset;
	}

	if (value == NULL) {
		return unset;
	}

	int match = enum_match(names, shunk1(value));
	if (match < 0) {
		/* include allowed names? */
		(*d) = diag("%s%s=%s invalid, '%s' unrecognized",
			    leftright, name, value, value);
		return 0;
	}

	return match;
}

static unsigned extract_sparse_name(const char *leftright,
				    const char *name,
				    const char *value, unsigned unset,
				    const struct sparse_names *names,
				    const struct whack_message *wm,
				    diag_t *d,
				    struct logger *logger)
{
	(*d) = NULL;

	if (never_negotiate_wm(wm)) {
		if (value != NULL) {
			llog(RC_LOG, logger,
			     "warning: %s%s=%s ignored for never-negotiate connection",
			     leftright, name, value);
		}
		return unset;
	}

	if (value == NULL) {
		return unset;
	}

	const struct sparse_name *sparse = sparse_lookup_by_name(names, shunk1(value));
	if (sparse == NULL) {
		/* include allowed names? */
		(*d) = diag("%s%s=%s invalid, '%s' unrecognized",
			    leftright, name, value, value);
		return 0;
	}

	return sparse->value;
}

static uintmax_t extract_uintmax(const char *leftright,
				 const char *name,
				 const char *value,
				 uintmax_t value_when_unset,
				 uintmax_t min, uintmax_t max,
				 const struct whack_message *wm,
				 diag_t *d,
				 struct logger *logger)
{
	(*d) = NULL;
	if (!can_extract_string(leftright, name, value, wm, logger)) {
		return value_when_unset;
	}

	uintmax_t uintmax;
	err_t err = shunk_to_uintmax(shunk1(value), NULL/*all*/, 0, &uintmax);
	if (err != NULL) {
		(*d) = diag("%s%s=%s invalid, %s", leftright, name, value, err);
		return value_when_unset;
	}
	if (uintmax < min || uintmax > max) {
		(*d) = diag("%s%s=%ju invalid, must be in the range %ju-%ju",
			    leftright, name, uintmax, min, max);
		return value_when_unset;
	}
	return uintmax;
}

static uintmax_t extract_scaled_uintmax(const char *leftright,
					const char *name,
					const char *value,
					const struct scales *scales,
					uintmax_t max,
					const char *what,
					const struct whack_message *wm,
					diag_t *d,
					struct logger *logger)
{
	(*d) = NULL;

	if (!can_extract_string(leftright, name, value, wm, logger)) {
		return max;
	}

	uintmax_t number;
	diag_t diag = tto_scaled_uintmax(shunk1(value), &number, scales);
	if ((*d) != NULL) {
		(*d) = diag_diag(&diag, "%s%s=%s invalid, ", leftright, name, value);
		return max;
	}
	if (number > max) {
		humber_buf hb;
		llog(RC_LOG, logger, "%s limited to the max allowed %s",
		     what, str_humber(max, &hb));
		return max;
	}
	return number;
}

static uintmax_t extract_percent(const char *leftright, const char *name, const char *value,
				 uintmax_t value_when_unset,
				 const struct whack_message *wm,
				 diag_t *d,
				 struct logger *logger)
{
	(*d) = NULL;

	if (!can_extract_string(leftright, name, value, wm, logger)) {
		return value_when_unset;
	}

	/* NUMBER% */

	uintmax_t percent;
	shunk_t cursor = shunk1(value);
	err_t err = shunk_to_uintmax(cursor, &cursor, /*base*/10, &percent);
	if (err != NULL) {
		(*d) = diag("%s%s=%s invalid, %s", leftright, name, value, err);
		return value_when_unset;
	}

	if (!hunk_streq(cursor, "%")) {
		(*d) = diag("%s%s=%s invalid, expecting %% character", leftright, name, value);
		return value_when_unset;
	}

	if (percent > INT_MAX - 100) {
		llog(RC_LOG, logger, "%s%s=%s is way to large, using %ju%%",
		     leftright, name, value, value_when_unset);
		return value_when_unset;
	}

	return percent;
}


static ip_cidr extract_cidr_num(const char *leftright,
				const char *name,
				const char *value,
				const struct whack_message *wm,
				diag_t *d,
				struct logger *logger)
{
	err_t err;
	(*d) = NULL;

	if (!can_extract_string(leftright, name, value, wm, logger)) {
		return unset_cidr;
	}

	ip_cidr cidr;
	err = ttocidr_num(shunk1(value), NULL, &cidr);
	if (err != NULL) {
		(*d) = diag("%s%s=%s invalid, %s", leftright, name, value, err);
		return unset_cidr;
	}

	err = cidr_check(cidr);
	if (err != NULL) {
		(*d) = diag("%s%s=%s invalid, %s", leftright, name, value, err);
	}

	return cidr;
}

static diag_t extract_host_ckaid(struct host_end_config *host_config,
				 const struct whack_end *src,
				 bool *same_ca,
				 struct logger *logger/*connection "..."*/)
{
	const char *leftright = src->leftright;
	ckaid_t ckaid;
	err_t err = string_to_ckaid(src->ckaid, &ckaid);
	if (err != NULL) {
		return diag("%s-ckaid='%s' invalid: %s",
			    leftright, src->ckaid, err);
	}

	/*
	 * Always save the CKAID so that a delayed load of the private
	 * key can work.
	 */
	host_config->ckaid = clone_thing(ckaid, "end ckaid");

	/*
	 * See if there's a certificate matching the CKAID, if not
	 * assume things will later find the private key (or cert on a
	 * later attempt).
	 */
	CERTCertificate *cert = get_cert_by_ckaid_from_nss(&ckaid, logger);
	if (cert != NULL) {
		diag_t diag = add_end_cert_and_preload_private_key(cert, host_config,
								   *same_ca/*preserve_ca*/,
								   logger);
		if (diag != NULL) {
			CERT_DestroyCertificate(cert);
			return diag;
		}
		return NULL;
	}

	ldbg(logger, "%s-ckaid=%s did not match a certificate in the NSS database",
	     leftright, src->ckaid);

	/* try to pre-load the private key */
	bool load_needed;
	err = preload_private_key_by_ckaid(&ckaid, &load_needed, logger);
	if (err != NULL) {
		ckaid_buf ckb;
		ldbg(logger, "no private key matching %s-ckaid=%s: %s",
		     leftright, str_ckaid(host_config->ckaid, &ckb), err);
		return NULL;
	}

	ckaid_buf ckb;
	llog(LOG_STREAM/*not-whack-for-now*/, logger,
	     "loaded private key matching %s-ckaid=%s",
	     leftright,
	     str_ckaid(host_config->ckaid, &ckb));
	return NULL;
}


static diag_t extract_host_end(struct host_end *host,
			       struct host_end_config *host_config,
			       struct host_end_config *other_host_config,
			       const struct whack_message *wm,
			       const struct whack_end *src,
			       const struct whack_end *other_src,
			       bool *same_ca,
			       struct logger *logger/*connection "..."*/)
{
	err_t err;
	diag_t d;
	const char *leftright = host_config->leftright;

	bool groundhog = extract_yn(leftright, "groundhog", src->groundhog,
				    /*value_when_unset*/YN_NO, wm, logger);
	if (groundhog) {
		if (is_fips_mode()) {
			return diag("%sgroundhog=yes is invalid in FIPS mode",
				    leftright);
		}
		host_config->groundhog = groundhog;
		groundhogday |= groundhog;
		llog(RC_LOG, logger, "WARNING: %s is a groundhog", leftright);
	} else {
		ldbg(logger, "connection is not a groundhog");
	}

	/*
	 * Save the whack value, update_hosts_from_end_host_addr()
	 * will set the actual .nexthop value for the connection.
	 * Either now, during extraction, or later, during
	 * instantiation.
	 */
	host_config->nexthop = src->nexthop;

	/*
	 * Decode id, if any.
	 *
	 * For %fromcert, the load_end_cert*() call will update it.
	 *
	 * For unset, update_hosts_from_end_host_addr(), will fill it
	 * on from the HOST address (assuming it can be resolved).
	 *
	 * Else it remains unset and acts like a wildcard.
	 */
	pexpect(host_config->id.kind == ID_NONE);
	if (src->id != NULL) { /*can_extract_str()*/
		/*
		 * Treat any atoid() failure as fatal.  One wart is
		 * something like id=foo.  ttoaddress_dns() fails
		 * when, perhaps, the code should instead return FQDN?
		 *
		 * In 4.x the error was ignored and ID=<HOST_IP> was
		 * used.
		 */
		err_t e = atoid(src->id, &host_config->id);
		if (e != NULL) {
			return diag("%sid=%s invalid: %s",
				    leftright, src->id, e);
		}
	}

	/* decode CA distinguished name, if any */
	host_config->ca = empty_chunk;
	if (src->ca != NULL) {
		if (streq(src->ca, "%same")) {
			*same_ca = true;
		} else if (!streq(src->ca, "%any")) {
			err_t ugh;

			/* convert the CA into a DN blob */
			ugh = atodn(src->ca, &host_config->ca);
			if (ugh != NULL) {
				llog(RC_LOG, logger,
				     "bad %s CA string '%s': %s (ignored)",
				     leftright, src->ca, ugh);
			} else {
				/* now try converting it back; isn't failing this a bug? */
				ugh = parse_dn(ASN1(host_config->ca));
				if (ugh != NULL) {
					llog(RC_LOG, logger,
					     "error parsing %s CA converted to DN: %s",
					     leftright, ugh);
					LDBG_hunk(logger, host_config->ca);
				}
			}

		}
	}

	/*
	 * Try to find the cert / private key.
	 *
	 * XXX: Be lazy and simply warn about combinations such as
	 * cert+ckaid.
	 *
	 * Should this instead cross check?
	 */
	if (src->cert != NULL) {

		if (src->ckaid != NULL) {
			llog(RC_LOG, logger,
				    "warning: ignoring %s ckaid '%s' and using %s certificate '%s'",
				    leftright, src->cert,
				    leftright, src->cert);
		}

		if (src->pubkey != NULL) {
			enum_buf pkb;
			llog(RC_LOG, logger,
			     "warning: ignoring %s %s '%s' and using %s certificate '%s'",
			     leftright,
			     str_enum(&ipseckey_algorithm_config_names, src->pubkey_alg, &pkb),
			     src->pubkey,
			     leftright, src->cert);
		}

		CERTCertificate *cert = get_cert_by_nickname_from_nss(src->cert, logger);
		if (cert == NULL) {
			return diag("%s certificate '%s' not found in the NSS database",
				    leftright, src->cert);
		}
		diag_t diag = add_end_cert_and_preload_private_key(cert, host_config,
								   *same_ca/*preserve_ca*/,
								   logger);
		if (diag != NULL) {
			CERT_DestroyCertificate(cert);
			return diag;
		}

	} else if (src->pubkey != NULL) {

		/*
		 * Extract the CKAID from the PUBKEY.  When there's an
		 * ID, also save the pubkey under that name (later,
		 * during oritentation, the the missing ID will be
		 * filled in with HOST or left alone and treated like
		 * "null").
		 *
		 * Not adding the PUBKEY when there's no ID is very
		 * old behaviour.
		 *
		 * Extracting the CKAID from the PUBKEY and using that
		 * to find the private key is a somewhat more recent
		 * behaviour.
		 *
		 * There are OE tests where the missing ID is treated
		 * like "null".  Since the private key isn't needed,
		 * missing key is ignored.
		 *
		 * Are there tests where the ID defaults to HOST?
		 * Presumably the saved CKAID would be used to find
		 * the host key?
		 */

		if (src->ckaid != NULL) {
			enum_buf pkb;
			llog(RC_LOG, logger,
			     "warning: ignoring %sckaid=%s and using %s%s",
			     leftright, src->ckaid,
			     leftright, str_enum(&ipseckey_algorithm_config_names, src->pubkey_alg, &pkb));
		}

		chunk_t keyspace = NULL_HUNK; /* must free_chunk_content() */
		err = whack_pubkey_to_chunk(src->pubkey_alg, src->pubkey, &keyspace);
		if (err != NULL) {
			enum_buf pkb;
			return diag("%s%s invalid: %s",
				    leftright, str_enum(&ipseckey_algorithm_config_names, src->pubkey_alg, &pkb),
				    err);
		}

		/* must-free keyspace */

		if (src->id == NULL) {

			struct pubkey_content pubkey_content; /* must free_pubkey_content() */
			d = unpack_dns_pubkey_content(src->pubkey_alg, HUNK_AS_SHUNK(keyspace),
						      &pubkey_content, logger);
			if (d != NULL) {
				free_chunk_content(&keyspace);
				enum_buf pkb;
				return diag_diag(&d, "%s%s invalid, ",
						 leftright, str_enum(&ipseckey_algorithm_config_names, src->pubkey_alg, &pkb));
			}

			/* must free keyspace pubkey_content */
			passert(pubkey_content.type != NULL);

			ckaid_buf ckb;
			enum_buf pkb;
			ldbg(logger, "saving CKAID %s extracted from %s%s",
			     str_ckaid(&pubkey_content.ckaid, &ckb),
			     leftright, str_enum(&ipseckey_algorithm_config_names, src->pubkey_alg, &pkb));
			host_config->ckaid = clone_const_thing(pubkey_content.ckaid, "raw pubkey's ckaid");

			free_chunk_content(&keyspace);
			free_pubkey_content(&pubkey_content, logger);

			/* must-free keyspace */

		} else {

			/* must-free keyspace */

			struct id keyid; /* must free_id_content() */
			err = atoid(src->id, &keyid);
			if (err != NULL) {
				free_chunk_content(&keyspace);
				return diag("%sid=\"%s\": %s", leftright, src->id, err);
			}

			/* must-free keyspace keyid */

			/* add the public key */
			struct pubkey *pubkey = NULL; /* must pubkey_delref() */
			diag_t d = unpack_dns_pubkey(&keyid, PUBKEY_LOCAL,
						     src->pubkey_alg,
						     /*install_time*/realnow(),
						     /*until_time*/realtime_epoch,
						     /*ttl*/0,
						     HUNK_AS_SHUNK(keyspace),
						     &pubkey, logger);
			if (d != NULL) {
				free_chunk_content(&keyspace);
				free_id_content(&keyid);
				return d;
			}

			/* must-free keyspace keyid pubkey */

			replace_pubkey(pubkey, &pluto_pubkeys);
			const ckaid_t *ckaid = pubkey_ckaid(pubkey);
			host_config->ckaid = clone_const_thing(*ckaid, "pubkey ckaid");
			pubkey_delref(&pubkey);
			free_id_content(&keyid);

			/* must-free keyspace */
		}

		/* saved */
		PEXPECT(logger, host_config->ckaid != NULL);

		/* must-free keyspace */

		/* try to pre-load the private key */
		bool load_needed;
		err = preload_private_key_by_ckaid(host_config->ckaid, &load_needed, logger);
		if (err != NULL) {
			ckaid_buf ckb;
			dbg("no private key matching %s CKAID %s: %s",
			    leftright, str_ckaid(host_config->ckaid, &ckb), err);
		} else if (load_needed) {
			ckaid_buf ckb;
			enum_buf pkb;
			llog(LOG_STREAM/*not-whack-for-now*/, logger,
			     "loaded private key matching %s%s CKAID %s",
			     leftright, str_enum(&ipseckey_algorithm_config_names, src->pubkey_alg, &pkb),
			     str_ckaid(host_config->ckaid, &ckb));
		}

		free_chunk_content(&keyspace);

	} else if (src->ckaid != NULL) {
		diag_t d = extract_host_ckaid(host_config, src, same_ca, logger);
		if (d != NULL) {
			return d;
		}
	}

	if (host_config->id.kind == ID_FROMCERT &&
	    host_config->cert.nss_cert != NULL) {
		host->id = id_from_cert(&host_config->cert);
		id_buf idb;
		ldbg(logger, "setting %s-id to '%s' as host->config->id=%%fromcert",
		     leftright, str_id(&host->id, &idb));
	} else {
		id_buf idb;
		ldbg(logger, "setting %s-id to '%s' as host->config->id)",
		     leftright, str_id(&host_config->id, &idb));
		host->id = clone_id(&host_config->id, __func__);
	}

	/* the rest is simple copying of corresponding fields */
	host_config->type = src->host_type;
	host_config->addr_name = clone_str(src->host_addr_name, "host ip");
	host_config->xauth.server = extract_yn(leftright, "xauthserver", src->xauthserver,
					       YN_NO, wm, logger);
	host_config->xauth.client = extract_yn(leftright, "xauthclient", src->xauthclient,
					       YN_NO, wm, logger);
	host_config->xauth.username = extract_string(leftright, "xauthusername",
						     src->xauthusername,
						     wm, logger);
	host_config->eap = src->eap;

	if (src->eap == IKE_EAP_NONE && src->auth == AUTH_EAPONLY) {
		return diag("leftauth/rightauth can only be 'eaponly' when using leftautheap/rightautheap is not 'none'");
	}

	/*
	 * Determine the authentication from auth= and authby=.
	 */

	if (never_negotiate_wm(wm) && src->auth != AUTH_UNSET && src->auth != AUTH_NEVER) {
		/* AUTH_UNSET is updated below */
		enum_buf ab;
		return diag("%sauth=%s option is invalid for type=passthrough connection",
			    leftright, str_enum_short(&keyword_auth_names, src->auth, &ab));
	}

	/*
	 * Note: this checks the whack message (WM), and not the
	 * connection (C) being construct - it could be done before
	 * extract_end(), but do it here.
	 *
	 * XXX: why not allow this?
	 */
	if ((src->auth == AUTH_UNSET) != (other_src->auth == AUTH_UNSET)) {
		return diag("leftauth= and rightauth= must both be set or both be unset");
	}

	/* value starting points */
	struct authby authby = (never_negotiate_wm(wm) ? AUTHBY_NEVER :
				!authby_is_set(wm->authby) ? AUTHBY_DEFAULTS :
				wm->authby);
	enum keyword_auth auth = src->auth;

	/*
	 * IKEv1 determines AUTH from authby= (it ignores auth= and
	 * bonus bits in authby=foo,bar).
	 *
	 * This logic still applies when NEVER_NEGOTIATE() - it turns
	 * above AUTHBY_NEVER into AUTH_NEVER.
	 */
	if (wm->ike_version == IKEv1) {
		/* override auth= using above authby= */
		if (auth != AUTH_UNSET) {
			return diag("%sauth= is not supported by IKEv1", leftright);
		}
		auth = auth_from_authby(authby);
		/* Force authby= to be consistent with selected AUTH */
		authby = authby_from_auth(auth);
		authby.ecdsa = false;
		authby.rsasig_v1_5 = false;
		if (!authby_is_set(authby)) {
			/* just striped ECDSA say */
			authby_buf ab;
			return diag("authby=%s is invalid for IKEv1",
				    str_authby(wm->authby, &ab));
		}
		/* ignore bonus wm->authby (not authby) bits */
		struct authby exclude = authby_not(authby);
		struct authby supplied = wm->authby;
		supplied.rsasig_v1_5 = false;
		supplied.ecdsa = false;
		struct authby unexpected = authby_and(supplied, exclude);
		if (authby_is_set(unexpected)) {
			authby_buf wb, ub;
			return diag("additional %s in authby=%s is not supported by IKEv1",
				    str_authby(unexpected, &ub),
				    str_authby(supplied, &wb));
		}
	}

	struct authby authby_mask = {0};
	switch (auth) {
	case AUTH_RSASIG:
		authby_mask = AUTHBY_RSASIG;
		break;
	case AUTH_ECDSA:
		authby_mask = AUTHBY_ECDSA;
		break;
	case AUTH_PSK:
		/* force only bit (not on by default) */
		authby = (struct authby) { .psk = true, };
		break;
	case AUTH_NULL:
		/* force only bit (not on by default) */
		authby = (struct authby) { .null = true, };
		break;
	case AUTH_UNSET:
		auth = auth_from_authby(authby);
		break;
	case AUTH_EAPONLY:
		break;
	case AUTH_NEVER:
		break;
	}

	if (authby_is_set(authby_mask)) {
		authby = authby_and(authby, authby_mask);
		if (!authby_is_set(authby)) {
			enum_buf ab;
			authby_buf pb;
			return diag("%sauth=%s expects authby=%s",
				    leftright,
				    str_enum_short(&keyword_auth_names, auth, &ab),
				    str_authby(authby_mask, &pb));
		}
	}

	enum_buf eab;
	authby_buf wabb;
	authby_buf eabb;
	dbg("fake %sauth=%s %sauthby=%s from whack authby %s",
	    src->leftright, str_enum_short(&keyword_auth_names, auth, &eab),
	    src->leftright, str_authby(authby, &eabb),
	    str_authby(wm->authby, &wabb));
	host_config->auth = auth;
	host_config->authby = authby;

	if (src->id != NULL && streq(src->id, "%fromcert")) {
		if (auth == AUTH_PSK || auth == AUTH_NULL) {
			return diag("ID cannot be specified as %%fromcert if PSK or AUTH-NULL is used");
		}
	}

	host_config->key_from_DNS_on_demand = src->key_from_DNS_on_demand;

	host_config->sendcert = extract_sparse_name(leftright, "sendcert", src->sendcert,
						    cert_defaultcertpolicy, &sendcert_policy_names,
						    wm, &d, logger);
	if (d != NULL) {
		return d;
	}

	if (can_extract_string(leftright, "ikeport", src->ikeport, wm, logger)) {
		err = ttoport(shunk1(src->ikeport), &host_config->ikeport);
		if (err != NULL) {
			return diag("%sikeport=%s invalid, %s", leftright, src->ikeport, err);
		}
		if (!port_is_specified(host_config->ikeport)) {
			return diag("%sikeport=%s invalid, must be in range 1-65535",
				    leftright, src->ikeport);
		}
	}

	/*
	 * Check for consistency between modecfgclient=,
	 * modecfgserver=, cat= and addresspool=.
	 *
	 * Danger:
	 *
	 * Since OE configurations can be both the client and the
	 * server they allow contradictions such as both
	 * leftmodecfgclient=yes leftmodecfgserver=yes.
	 *
	 * Danger:
	 *
	 * It's common practice to specify leftmodecfgclient=yes
	 * rightmodecfgserver=yes even though "right" isn't properly
	 * configured (for instance expecting leftaddresspool).
	 */

	if (src->modecfgserver == YN_YES && src->modecfgclient == YN_YES) {
		diag_t d = diag("both %smodecfgserver=yes and %smodecfgclient=yes defined",
				leftright, leftright);
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		llog(RC_LOG, logger, "opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}

	if (src->modecfgserver == YN_YES && src->cat == YN_YES) {
		diag_t d = diag("both %smodecfgserver=yes and %scat=yes defined",
				leftright, leftright);
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		llog(RC_LOG, logger, "opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}

	if (src->modecfgclient == YN_YES && other_src->cat == YN_YES) {
		diag_t d = diag("both %smodecfgclient=yes and %scat=yes defined",
				leftright, other_src->leftright);
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		llog(RC_LOG, logger, "opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}

	if (src->modecfgserver == YN_YES && src->addresspool != NULL) {
		diag_t d = diag("%smodecfgserver=yes does not expect %saddresspool=",
				leftright, src->leftright);
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		llog(RC_LOG, logger, "opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}

	/*
	 * XXX: this can't be rejected.  For instance, in
	 * ikev1-psk-dual-behind-nat-01, road has
	 * <east>modecfgserver=yes, but doesn't specify the address
	 * pool.  Arguably modecfgserver= should be ignored?
	 */
#if 0
	if (src->modecfgserver == YN_YES && other_src->addresspool == NULL) {
		diag_t d = diag("%smodecfgserver=yes expects %saddresspool=",
				leftright, other_src->leftright);
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		llog(RC_LOG, logger, "opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}
#endif

	if (src->modecfgclient == YN_YES && other_src->addresspool != NULL) {
		diag_t d = diag("%smodecfgclient=yes does not expect %saddresspool=",
				leftright, other_src->leftright);
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		llog(RC_LOG, logger, "opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}

	if (src->cat == YN_YES && other_src->addresspool != NULL) {
		diag_t d = diag("both %scat=yes and %saddresspool= defined",
				leftright, other_src->leftright);
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		llog(RC_LOG, logger, "opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}

	/*
	 * Update client/server based on config and addresspool
	 *
	 * The update uses OR so that the truth is blended with both
	 * the ADDRESSPOOL code's truth (see further down) and the
	 * reverse calls sense of truth.
	 *
	 * Unfortunately, no!
	 *
	 * This end having an addresspool should imply that this host
	 * is the client and the other host is the server.  Right?
	 *
	 * OE configurations have leftmodecfgclient=yes
	 * rightaddresspool= which creates a the connection that is
	 * both a client and a server.
	 */

	host_config->modecfg.server |= (src->modecfgserver == YN_YES);
	host_config->modecfg.client |= (src->modecfgclient == YN_YES);

	if (src->addresspool != NULL) {
		other_host_config->modecfg.server = true;
		host_config->modecfg.client = true;
		dbg("forced %s modecfg client=%s %s modecfg server=%s",
		    host_config->leftright, bool_str(host_config->modecfg.client),
		    other_host_config->leftright, bool_str(other_host_config->modecfg.server));
	}

	return NULL;
}

static diag_t extract_child_end_config(const struct whack_message *wm,
				       const struct whack_end *src,
				       struct connection *c,
				       struct child_end_config *child_config,
				       struct logger *logger)
{
	diag_t d = NULL;
	const char *leftright = src->leftright;

	switch (wm->ike_version) {
	case IKEv2:
#ifdef USE_CAT
		child_config->has_client_address_translation = (src->cat == YN_YES);
#endif
		break;
	case IKEv1:
		if (src->cat != YN_UNSET) {
			name_buf nb;
			llog(RC_LOG, logger,
			     "warning: IKEv1, ignoring %scat=%s (client address translation)",
			     leftright, str_sparse(&yn_option_names, src->cat, &nb));
		}
		break;
	default:
		bad_case(wm->ike_version);
	}

	child_config->vti_ip =
		extract_cidr_num(leftright, "vti", src->vti, wm, &d, logger);
	if (d != NULL) {
		return d;
	}

	child_config->ipsec_interface_ip =
		extract_cidr_num(leftright, "interface-ip", src->interface_ip, wm, &d, logger);
	if (d != NULL) {
		return d;
	}

	/* save some defaults */
	child_config->protoport = src->protoport;

	/*
	 * Support for skipping updown, eg leftupdown="" or %disabled.
	 *
	 * Useful on busy servers that do not need to use updown for
	 * anything.
	 */
	if (never_negotiate_wm(wm)) {
		if (src->updown != NULL) {
			llog(RC_LOG, logger,
			     "warning: %supdown=%s ignored when never negotiate",
			     leftright, src->updown);
		}
	} else {
		/* Note: "" disables updown; but no updown gets default */
		child_config->updown =
			(src->updown == NULL ? clone_str(DEFAULT_UPDOWN, "default_updown") :
			 streq(src->updown, UPDOWN_DISABLED) ? NULL :
			 streq(src->updown, "") ? NULL :
			 clone_str(src->updown, "child_config.updown"));
	}


	ip_selectors *child_selectors = &child_config->selectors;

	/*
	 * Figure out the end's child selectors.
	 */
	if (src->addresspool != NULL) {

		/*
		 * Both ends can't add an address pool (cross
		 * checked).
		 */
		FOR_EACH_ELEMENT(pool, c->pool) {
			PASSERT(logger, (*pool) == NULL);
		}

		if (src->subnets != NULL) {
			/* XXX: why? */
			return diag("cannot specify both %saddresspool= and %ssubnets=",
				    leftright, leftright);
		}

		if (src->subnet != NULL) {
			/* XXX: why? */
			return diag("cannot specify both %saddresspool= and %ssubnet=",
				    leftright, leftright);
		}

		diag_t d = ttoranges_num(shunk1(src->addresspool), ", ", NULL,
					 &child_config->addresspools);
		if (d != NULL) {
			return diag_diag(&d, "%saddresspool=%s invalid, ", leftright, src->addresspool);
		}

		FOR_EACH_ITEM(range, &child_config->addresspools) {

			const struct ip_info *afi = range_type(range);

			if (wm->ike_version == IKEv1 && afi == &ipv6_info) {
				return diag("%saddresspool=%s invalid, IKEv1 does not support IPv6 address pool",
					    leftright, src->addresspool);
			}

			if (afi == &ipv6_info && !range_is_cidr((*range))) {
				range_buf rb;
				return diag("%saddresspool=%s invalid, IPv6 range %s is not a subnet",
					    leftright, src->addresspool,
					    str_range(range, &rb));
			}

			/*
			 * Create the address pool regardless of
			 * orientation.  Orienting will then add a
			 * reference as needed.
			 *
			 * This way, conflicting addresspools are
			 * detected early (OTOH, they may be detected
			 * when they don't matter).
			 *
			 * This also detetects and rejects multiple
			 * pools with the same address family.
			 */
			diag_t d = install_addresspool((*range), child_config->addresspool, logger);
			if (d != NULL) {
				return diag_diag(&d, "%saddresspool=%s invalid, ",
						 leftright, src->addresspool);
			}

		}

	} else if (src->subnet != NULL) {

		/*
		 * Parse new syntax (protoport= is not used).
		 *
		 * Of course if NARROWING is allowed, this can be
		 * refined regardless of .has_client.
		 */
		ldbg(logger, "%s child selectors from %ssubnet (selector); %s.config.has_client=true",
		     leftright, leftright, leftright);
		ip_address nonzero_host;
		diag_t d = ttoselectors_num(shunk1(src->subnet), ", ", NULL,
					    &child_config->selectors, &nonzero_host);
		if (d != NULL) {
			return diag_diag(&d, "%ssubnet=%s invalid, ",
					 leftright, src->subnet);
		}

		if (wm->ike_version == IKEv1) {
			if (child_config->selectors.len > 1) {
				return diag("IKEv1 does not support %ssubnet= with multiple selectors", leftright);
			}
		}

		if (src->protoport.is_set) {
			if (child_config->selectors.len > 1) {
				return diag("%ssubnet= must be a single subnet when combined with %sprotoport=",
					    leftright, leftright);
			}
			if (!selector_is_subnet(child_config->selectors.list[0])) {
				return diag("%ssubnet= cannot be a selector when combined with %sprotoport=",
					    leftright, leftright);
			}
			ip_subnet subnet = selector_subnet(child_config->selectors.list[0]);
			ldbg(logger, "%s child selectors from %ssubnet + %sprotoport; %s.config.has_client=true",
			     leftright, leftright, leftright, leftright);
			child_selectors->list[0] =
				selector_from_subnet_protoport(subnet, src->protoport);
		}

		if (nonzero_host.is_set) {
			address_buf hb;
			llog(RC_LOG, logger,
			     "zeroing non-sero address identifier %s in %ssubnet=%s",
			     str_address(&nonzero_host, &hb), leftright, src->subnet);
		}

	} else {
		ldbg(logger, "%s child selectors unknown; probably derived from host?!?",
		     leftright);
	}

	/*
	 * Also extract .virt.
	 *
	 * While subnet= can only specify .virt XOR .client, the end
	 * result can be that both .virt and .client are set.
	 *
	 * XXX: don't set .has_client as update_child_ends*() will see
	 * it and skip updating the client address from the host.
	 */
	if (src->virt != NULL) {
		if (wm->ike_version > IKEv1) {
			return diag("IKEv%d does not support virtual subnets",
				    wm->ike_version);
		}
		dbg("%s %s child has a virt-end", wm->name, leftright);
		diag_t d = create_virtual(leftright, src->virt,
					  &child_config->virt);
		if (d != NULL) {
			return d;
		}
	}

	/*
	 * Get the SOURCEIPs and check that they all fit within at
	 * least one selector determined above (remember, when the
	 * selector isn't specified (i.e., subnet=), the selector is
	 * set to the .host_addr).
	 */

	if (src->sourceip != NULL) {
		if (src->interface_ip != NULL) {
			return diag("cannot specify %sinterface-ip=%s and %sssourceip=%s",
				    leftright, src->interface_ip,
				    leftright, src->sourceip);
		}

		diag_t d = ttoaddresses_num(shunk1(src->sourceip), ", ",
					    NULL/*UNSPEC*/, &child_config->sourceip);
		if (d != NULL) {
			return diag_diag(&d, "%ssourceip=%s invalid, ",
					 src->leftright, src->sourceip);
		}
		/* valid? */
		ip_address seen[IP_INDEX_ROOF] = {0};
		FOR_EACH_ITEM(sourceip, &child_config->sourceip) {

			/* i.e., not :: and not 0.0.0.0 */
			if (!address_is_specified(*sourceip)) {
				return diag("%ssourceip=%s invalid, must be a valid address",
					    leftright, src->sourceip);
			}

			/* i.e., not 1::1,1::2 */
			const struct ip_info *afi = address_type(sourceip);
			PASSERT(logger, afi != NULL); /* since specified */
			if (seen[afi->ip_index].is_set) {
				address_buf sb, ipb;
				return diag("%ssourceip=%s invalid, multiple %s addresses (%s and %s) specified",
					    leftright, src->sourceip, afi->ip_name,
					    str_address(&seen[afi->ip_index], &sb),
					    str_address(sourceip, &ipb));
			}
			seen[afi->ip_index] = (*sourceip);

			if (child_config->selectors.len > 0) {
				/* skip aliases; they hide the selectors list */
				if (wm->connalias != NULL) {
					continue;
				}
				bool within = false;
				FOR_EACH_ITEM(sel, &child_config->selectors) {
					/*
					 * Only compare the address
					 * against the selector's
					 * address range (not the
					 * /protocol/port).
					 *
					 * For instance when the
					 * selector is:
					 *
					 *   1::/128/tcp/22
					 *
					 * the sourceip=1:: is still
					 * ok.
					 */
					if (address_in_selector_range(*sourceip, *sel)) {
						within = true;
						break;
					}
				}
				if (!within) {
					address_buf sipb;
					return diag("%ssourceip=%s invalid, address %s is not within %ssubnet=%s",
						    leftright, src->sourceip,
						    str_address(sourceip, &sipb),
						    leftright, src->subnet);
				}
			} else if (src->host_addr.is_set) {
				if (!address_eq_address(*sourceip, src->host_addr)) {
					address_buf sipb;
					address_buf hab;
					return diag("%ssourceip=%s invalid, address %s does not match %s=%s and %ssubnet= was not specified",
						    leftright, src->sourceip,
						    str_address(sourceip, &sipb),
						    leftright, str_address(&src->host_addr, &hab),
						    leftright);
				}
			} else {
				return diag("%ssourceip=%s invalid, %ssubnet= unspecified and %s IP address unknown",
					    leftright, src->sourceip,
					    leftright/*subnet=*/, leftright/*host=*/);
			}
		}
	}
	return NULL;
}

diag_t add_end_cert_and_preload_private_key(CERTCertificate *cert,
					    struct host_end_config *host_end_config,
					    bool preserve_ca,
					    struct logger *logger)
{
	passert(cert != NULL);
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
		passert(pk != NULL);
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
		dbg("preserving existing %s ca", leftright);
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
	dbg("preload cert/secret for connection: %s", cert->nickname);
	bool load_needed;
	err_t ugh = preload_private_key_by_cert(&host_end_config->cert, &load_needed, logger);
	if (ugh != NULL) {
		dbg("no private key matching %s certificate %s: %s",
		    leftright, nickname, ugh);
	} else if (load_needed) {
		llog(LOG_STREAM/*not-whack-for-now*/, logger,
		     "loaded private key matching %s certificate '%s'",
		     leftright, nickname);
	}
	return NULL;
}

/* only used by add_connection() */

static diag_t mark_parse(const char *leftright, const char *name, const char *mark,
			 struct sa_mark *sa_mark)
{
	(*sa_mark) = (struct sa_mark) {
		.unique = false,
		.val = UINT32_MAX,
		.mask = UINT32_MAX,
	};

	shunk_t cursor = shunk1(mark);
	intmax_t value;
	err_t e = shunk_to_intmax(cursor, &cursor, 0, &value);
	if (e != NULL) {
		return diag("%s%s=\"%s\" value invalid, %s",
			    leftright, name, mark, e);
	}
	if (value > UINT32_MAX) {
		return diag("%s%s=\"%s\" value invalid, %jd is larger than %#08"PRIx32,
			    leftright, name, mark,
			    value, UINT32_MAX);
	}
	if (value < -1) {
		return diag("%s%s=\"%s\" value invalid, %jd is less than -1",
			    leftright, name, mark, value);
	}
	if (cursor.len > 0 && hunk_char(cursor, 0) != '/') {
		return diag("%s%s=\"%s\" value invalid, contains trailing junk \""PRI_SHUNK"\"",
			    leftright, name, mark, pri_shunk(cursor));
	}
	sa_mark->val = value;

	if (hunk_streat(&cursor, "/")) {
		uintmax_t mask;
		err_t e = shunk_to_uintmax(cursor, &cursor, 0, &mask);
		if (e != NULL) {
			return diag("%s%s=\"%s\" mask invalid, %s",
				    leftright, name, mark, e);
		}
		if (mask > UINT32_MAX) {
			return diag("%s%s=\"%s\" mask invalid, %jd is larger than %#08"PRIx32,
				    leftright, name, mark,
				    mask, UINT32_MAX);
		}
		if (cursor.len > 0) {
			return diag("%s%s=\"%s\" mask invalid, contains trailing junk \""PRI_SHUNK"\"",
				    leftright, name, mark, pri_shunk(cursor));
		}
		sa_mark->mask = mask;
	}
	if ((sa_mark->val & ~sa_mark->mask) != 0) {
		return diag("%s%s=\"%s\" invalid, value %#08"PRIx32" has bits outside mask %#08"PRIx32,
			    leftright, name, mark, sa_mark->val, sa_mark->mask);
	}
	return NULL;
}

/*
 * Turn the config's selectors / addresspool / host-addr into
 * proposals.
 */

void build_connection_proposals_from_configs(struct connection *d,
					     const struct ip_info *host_afi,
					     struct verbose verbose)
{
	vdbg("%s() host-afi=%s", __func__, (host_afi == NULL ? "N/A" : host_afi->ip_name));
	verbose.level++;

	FOR_EACH_ELEMENT(end, d->end) {
		const char *leftright = end->config->leftright;

		vassert(end->child.selectors.proposed.list == NULL);
		vassert(end->child.selectors.proposed.len == 0);
		vexpect(end->child.has_client == false);

		/* {left,right}subnet=... */
		if (end->child.config->selectors.len > 0) {
			vdbg("%s selectors from %d child.selectors",
			     leftright, end->child.config->selectors.len);
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
				vdbg("%s selector formed from address pool %s",
				     leftright, str_selector(&selector, &sb));
				append_end_selector(end, selector, verbose.logger, HERE);
			}
			continue;
		}

		/* {left,right}= */
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
			vdbg("%s selector proposals from host address+protoport %s %s",
			     leftright,
			     str_address(&end->host.addr, &ab),
			     str_protoport(&end->child.config->protoport, &pb));
			ip_selector selector =
				selector_from_address_protoport(end->host.addr,
								end->child.config->protoport);
			append_end_selector(end, selector, verbose.logger, HERE);
			continue;
		}

		/*
		 * Make space for the to-be-determined selector so
		 * that there's something to iterate over and
		 * something containing the intended address family.
		 *
		 * When called by instantiate() and HOST_AFI==NULL,
		 * this code isn't reached.  This is because both the
		 * local (connection is oriented) and remote (the
		 * packet from the peer triggering the instantiate)
		 * host.addr are known.
		 */
		if (vbad(host_afi == NULL)) {
			return;
		}

		vexpect(is_permanent(d) || is_group(d) || is_template(d));
		vdbg("%s selector proposals from host family %s",
		     leftright, host_afi->ip_name);
		/*
		 * Note: NOT afi->selector.all.  It needs to
		 * differentiate so it knows it is to be updated.
		 *
		 * selector.unset has .is_set=false so looks unset;
		 * but has .version=IPv[46].
		 */
		append_end_selector(end, host_afi->selector.unset, verbose.logger, HERE);
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

void alloc_connection_spds(struct connection *c, unsigned nr_spds)
{
	PASSERT(c->logger, c->child.spds.len == 0);
	ldbg(c->logger, "allocating %u SPDs", nr_spds);
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
	struct verbose verbose = VERBOSE(DEBUG_STREAM, c->logger, "");
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
	 * .is_set=false, .version=..., )
	 */

	unsigned nr_spds = 0;
	FOR_EACH_ITEM(left_selector, left_proposals) {
		vexpect(left_selector->ip_version != 0);
		FOR_EACH_ITEM(right_selector, right_proposals) {
			vexpect(right_selector->ip_version != 0);
			if (left_selector->ip_version == right_selector->ip_version) {
				nr_spds ++;
			}
		}
	}

	/* Allocate the SPDs. */
	alloc_connection_spds(c, nr_spds);

	/*
	 * Pass 2: fill them in, hashing each as it is added.
	 */

	unsigned spd_nr = 0;
	FOR_EACH_ITEM(left_selector, left_proposals) {
		FOR_EACH_ITEM(right_selector, right_proposals) {
			verbose.level = 2;
			if (left_selector->ip_version == right_selector->ip_version) {
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

/*
 * Extract the connection detail from the whack message WM and store
 * them in the connection C.
 *
 * This code is responsible for cloning strings and other structures
 * so that they out live the whack message.  When things go wrong,
 * return false, the caller will then use discard_connection() to free
 * the partially constructed connection.
 *
 * Checks from confread/whack should be moved here so it is similar
 * for all methods of loading a connection.
 *
 * XXX: at one point this code was populating the connection with
 * pointer's to the whack message's strings and then trying to use
 * unshare_connection() to create local copies.  Bad idea.  For
 * instance, it duplicated the proposal pointers yet here the pointer
 * was freshy allocated so no duplication should be needed (or at
 * least shouldn't be) (look for strange free() vs delref() sequence).
 */

static diag_t extract_lifetime(deltatime_t *lifetime,
			       const char *lifetime_name,
			       deltatime_t whack_lifetime,
			       deltatime_t default_lifetime,
			       deltatime_t lifetime_max,
			       deltatime_t lifetime_fips,
			       deltatime_t rekeymargin,
			       uintmax_t rekeyfuzz_percent,
			       struct logger *logger,
			       const struct whack_message *wm)
{
	const char *source;
	if (whack_lifetime.is_set) {
		source = "whack";
		*lifetime = whack_lifetime;
	} else {
		source = "default";
		*lifetime = default_lifetime;
	}

	/*
	 * Determine the MAX lifetime
	 *
	 * http://csrc.nist.gov/publications/nistpubs/800-77/sp800-77.pdf
	 */
	const char *fips;
	deltatime_t max_lifetime;
	if (is_fips_mode()) {
		fips = "FIPS: ";
		max_lifetime = lifetime_fips;
	} else {
		fips = "";
		max_lifetime = lifetime_max;
	}

	if (impair.lifetime) {
		llog(RC_LOG, logger, "IMPAIR: skipping %s=%jd checks",
		     lifetime_name, deltasecs(*lifetime));
		return NULL;
	}

	/*
	 * Determine the minimum lifetime.  Use:
	 *
	 *    rekeymargin*(100+rekeyfuzz)/100
	 *
	 * which is the maximum possible rekey margin.  INT_MAX is
	 * arbitrary as an upper bound - anything to stop overflow.
	 */

	deltatime_t min_lifetime = deltatime_scale(rekeymargin,
						   100 + rekeyfuzz_percent,
						   100);

	if (deltatime_cmp(max_lifetime, <, min_lifetime)) {
		return diag("%s%s=%jd must be greater than rekeymargin=%jus + rekeyfuzz=%jd%% yet less than the maximum allowed %ju",
			    fips, 
			    lifetime_name, deltasecs(*lifetime),
			    deltasecs(rekeymargin), rekeyfuzz_percent,
			    deltasecs(min_lifetime));
	}

	if (deltatime_cmp(*lifetime, >, max_lifetime)) {
		llog(RC_LOG, logger,
		     "%s%s=%ju seconds exceeds maximum of %ju seconds, setting to the maximum allowed",
		     fips,
		     lifetime_name, deltasecs(*lifetime),
		     deltasecs(max_lifetime));
		source = "max";
		*lifetime = max_lifetime;
	} else if (deltatime_cmp(*lifetime, <, min_lifetime)) {
		llog(RC_LOG, logger,
		     "%s=%jd must be greater than rekeymargin=%jus + rekeyfuzz=%jd%%, setting to %jd seconds",
		     lifetime_name, deltasecs(*lifetime),
		     deltasecs(wm->rekeymargin),
		     rekeyfuzz_percent,
		     deltasecs(min_lifetime));
		source = "min";
		*lifetime = min_lifetime;
	}

	deltatime_buf db;
	ldbg(logger, "%s=%s (%s)", lifetime_name, source, str_deltatime(*lifetime, &db));
	return NULL;
}

static enum connection_kind extract_connection_end_kind(const struct whack_message *wm,
							const struct whack_end *this,
							const struct whack_end *that,
							struct logger *logger)
{
	if (is_group_wm(wm)) {
		ldbg(logger, "%s connection is CK_GROUP: by is_group_wm()",
		     this->leftright);
		return CK_GROUP;
	}
	if (wm->sec_label != NULL) {
		ldbg(logger, "%s connection is CK_LABELED_TEMPLATE: has security label: %s",
		     this->leftright, wm->sec_label);
		return CK_LABELED_TEMPLATE;
	}
	if(wm->narrowing == YN_YES) {
		ldbg(logger, "%s connection is CK_TEMPLATE: narrowing=yes",
		     this->leftright);
		return CK_TEMPLATE;
	}
	if (that->virt != NULL) {
		/*
		 * A peer with subnet=vnet:.. needs instantiation so
		 * we can accept multiple subnets from that peer.
		 */
		ldbg(logger, "%s connection is CK_TEMPLATE: %s has vnets at play",
		     this->leftright, that->leftright);
		return CK_TEMPLATE;
	}
	if (that->addresspool != NULL) {
		ldbg(logger, "%s connection is CK_TEMPLATE: %s has an address pool",
		     this->leftright, that->leftright);
		return CK_TEMPLATE;
	}
	if (that->protoport.is_set /*technically-redundant*/ &&
	    that->protoport.has_port_wildcard) {
		ldbg(logger, "%s connection is CK_TEMPLATE: %s child has protoport wildcard port",
		     this->leftright, that->leftright);
		return CK_TEMPLATE;
	}
	FOR_EACH_THING(we, this, that) {
		if (!never_negotiate_wm(wm) &&
		    !address_is_specified(we->host_addr) &&
		    we->host_type != KH_IPHOSTNAME) {
			ldbg(logger, "%s connection is CK_TEMPLATE: unspecified %s address yet policy negotiate",
			     this->leftright, we->leftright);
			return CK_TEMPLATE;
		}
	}
	ldbg(logger, "%s connection is CK_PERMANENT: by default",
	     this->leftright);
	return CK_PERMANENT;
}

static bool shunt_ok(enum shunt_kind shunt_kind, enum shunt_policy shunt_policy)
{
	static const bool ok[SHUNT_KIND_ROOF][SHUNT_POLICY_ROOF] = {
		[SHUNT_KIND_NONE] = {
			[SHUNT_UNSET] = true,
		},
		[SHUNT_KIND_NEVER_NEGOTIATE] = {
			[SHUNT_UNSET] = true,
			[SHUNT_NONE] = false, [SHUNT_TRAP] = false, [SHUNT_PASS] = true,  [SHUNT_DROP] = true,
		},
		[SHUNT_KIND_NEGOTIATION] = {
			[SHUNT_NONE] = false, [SHUNT_TRAP] = false, [SHUNT_PASS] = true,  [SHUNT_DROP] = true,
		},
		[SHUNT_KIND_FAILURE] = {
			[SHUNT_NONE] = true,  [SHUNT_TRAP] = false, [SHUNT_PASS] = true,  [SHUNT_DROP] = true,
		},
		/* hard-wired */
		[SHUNT_KIND_IPSEC] = { [SHUNT_IPSEC] = true, },
		[SHUNT_KIND_BLOCK] = { [SHUNT_DROP] = true, },
		[SHUNT_KIND_ONDEMAND] = { [SHUNT_TRAP] = true, },
	};
	return ok[shunt_kind][shunt_policy];
}

static diag_t extract_shunt(struct config *config,
			    const struct whack_message *wm,
			    enum shunt_kind shunt_kind,
			    const struct sparse_names *shunt_names,
			    enum shunt_policy unset_shunt)
{
	enum shunt_policy shunt_policy = wm->shunt[shunt_kind];
	if (shunt_policy == SHUNT_UNSET) {
		shunt_policy = unset_shunt;
	}
	if (!shunt_ok(shunt_kind, shunt_policy)) {
		JAMBUF(buf) {
			jam_enum_human(buf, &shunt_kind_names, shunt_kind);
			jam_string(buf, "shunt=");
			jam_sparse_long(buf, shunt_names, shunt_policy);
			jam_string(buf, " invalid");
			return diag_jambuf(buf);
		}
	}
	config->shunt[shunt_kind] = shunt_policy;
	return NULL;
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
	return alloc_printf("%s[%lu]", t->prefix, t->next_instance_serial);
}

static struct config *alloc_config(enum ike_version ike_version)
{
	struct config *config = alloc_thing(struct config, "root config");
	/* stuff that can't fail! */
	config->ike_version = ike_version;
	FOR_EACH_THING(lr, LEFT_END, RIGHT_END) {
		/* "left" or "right" */
		const char *leftright =
			(lr == LEFT_END ? "left" :
			 lr == RIGHT_END ? "right" :
			 NULL);
		passert(leftright != NULL);
		struct config_end *end_config = &config->end[lr];
		end_config->leftright = leftright;
		end_config->index = lr;
		end_config->host.leftright = leftright;
		end_config->child.leftright = leftright;
	}
	return config;
}

struct connection *alloc_connection(const char *name,
				    struct connection *t,
				    const struct config *config,
				    lset_t debugging,
				    struct logger *logger,
				    where_t where)
{
	struct connection *c = refcnt_alloc(struct connection, where);

	/* before alloc_logger(); can't use C */
	c->name = clone_str(name, __func__);

	/* before alloc_logger(); can't use C */
	c->prefix = alloc_connection_prefix(name, t);

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
		pdbg(t->logger, "template .instance_serial_next updated to %lu; instance %lu",
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
	FOR_EACH_THING(lr, LEFT_END, RIGHT_END) {
		/* "left" or "right" */
		struct connection_end *end = &c->end[lr];
		const struct config_end *end_config = &c->config->end[lr];
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
	passert(connection_serialno > 0); /* can't overflow */
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

static const struct ike_info *const ike_info[] = {
	[IKEv1] = &ikev1_info,
	[IKEv2] = &ikev2_info,
};

static diag_t extract_connection(const struct whack_message *wm,
				 struct connection *c,
				 struct config *config)
{
	diag_t d;

	const struct whack_end *whack_ends[] = {
		[LEFT_END] = &wm->end[LEFT_END],
		[RIGHT_END] = &wm->end[RIGHT_END],
	};

	/*
	 * Determine the Host's address family.
	 */
	const struct ip_info *host_afi = NULL;
	d = extract_host_afi(wm, &host_afi);
	if (d != NULL) {
		return d;
	}

	if (host_afi == NULL) {
		return diag("host address family unknown");
	}

	/*
	 * Determine the host topology.
	 *
	 * Needs two passes: first pass extracts tentative
	 * host/nexthop; scecond propagates that to other dependent
	 * fields.
	 *
	 * XXX: the host lookup is blocking; should instead do it
	 * asynchronously using unbound.
	 */
	ip_address host_addr[END_ROOF];
	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		const struct whack_end *we = whack_ends[end];
		host_addr[end] = host_afi->address.unspec;
		if (address_is_specified(we->host_addr)) {
			host_addr[end] = we->host_addr;
		} else if (we->host_type == KH_IPHOSTNAME) {
			ip_address addr;
			err_t er = ttoaddress_dns(shunk1(we->host_addr_name),
						  host_afi, &addr);
			if (er != NULL) {
				llog(RC_LOG, c->logger,
				     "failed to resolve '%s=%s' at load time: %s",
				     we->leftright, we->host_addr_name, er);
			} else {
				host_addr[end] = addr;
			}
		}
	}

	/*
	 * Unpack and verify the ends.
	 */

	bool same_ca[END_ROOF] = { false, };

	FOR_EACH_THING(this, LEFT_END, RIGHT_END) {
		diag_t d;
		int that = (this + 1) % END_ROOF;
		d = extract_host_end(&c->end[this].host,
				     &config->end[this].host,
				     &config->end[that].host,
				     wm,
				     whack_ends[this],
				     whack_ends[that],
				     &same_ca[this],
				     c->logger);
		if (d != NULL) {
			return d;
		}
	}

	/*
	 * Determine the connection KIND from the wm.
	 *
	 * Save it in a local variable so code can use that (and be
	 * forced to only use value after it's been determined).  Yea,
	 * hack.
	 */
	FOR_EACH_THING(this, LEFT_END, RIGHT_END) {
		enum end that = (this + 1) % END_ROOF;
		c->end[this].kind =
			extract_connection_end_kind(wm,
						    whack_ends[this],
						    whack_ends[that],
						    c->logger);
	}

	passert(c->name != NULL); /* see alloc_connection() */

	/*
	 * Extract policy bits.
	 */

	bool pfs = extract_yn("", "pfs", wm->pfs,
			      /*value_when_unset*/YN_YES,
			      wm, c->logger);
	config->child_sa.pfs = pfs;

	bool compress = extract_yn("", "compress", wm->compress,
				   /*value_when_unset*/YN_NO,
				   wm, c->logger);
	config->child_sa.ipcomp = compress;

	/* sanity check?  done below */
	enum encap_proto encap_proto;
	if (never_negotiate_wm(wm)) {
		if (wm->phase2 != ENCAP_PROTO_UNSET) {
			enum_buf sb;
			llog(RC_LOG, c->logger,
			     "warning: phase2=%s ignored for never-negotiate connection",
			     str_enum(&encap_proto_story, wm->phase2, &sb));
		}
		encap_proto = ENCAP_PROTO_UNSET;
	} else {
		encap_proto = (wm->phase2 == ENCAP_PROTO_UNSET ? ENCAP_PROTO_ESP :
			       wm->phase2);
	}
	config->child_sa.encap_proto = encap_proto;

	enum encap_mode encap_mode;
	if (wm->type == KS_UNSET) {
		encap_mode = ENCAP_MODE_TUNNEL;
	} else if (wm->type == KS_TUNNEL) {
		encap_mode = ENCAP_MODE_TUNNEL;
	} else if (wm->type == KS_TRANSPORT) {
		encap_mode = ENCAP_MODE_TRANSPORT;
	} else {
		if (!never_negotiate_wm(wm)) {
			sparse_buf sb;
			llog_pexpect(c->logger, HERE,
				     "type=%s should be never-negotiate",
				     str_sparse(&type_option_names, wm->type, &sb));
		}
		encap_mode = ENCAP_MODE_UNSET;
	}
	config->child_sa.encap_mode = encap_mode;

	if (encap_mode == ENCAP_MODE_TRANSPORT) {
		if (wm->vti_interface != NULL) {
			return diag("VTI requires tunnel mode but connection specifies type=transport");
		}
	}

	if (wm->authby.never) {
		if (wm->never_negotiate_shunt == SHUNT_UNSET) {
			return diag("connection with authby=never must specify shunt type via type=");
		}
	}
	if (wm->never_negotiate_shunt != SHUNT_UNSET) {
		if (!authby_eq(wm->authby, AUTHBY_NONE) &&
		    !authby_eq(wm->authby, AUTHBY_NEVER)) {
			authby_buf ab;
			enum_buf sb;
			return diag("kind=%s shunt connection cannot have authby=%s authentication",
				    str_sparse_short(&never_negotiate_shunt_names, wm->never_negotiate_shunt, &sb),
				    str_authby(wm->authby, &ab));
		}
	}

	if (wm->ike_version == IKEv1) {
#ifdef USE_IKEv1
		if (pluto_ikev1_pol != GLOBAL_IKEv1_ACCEPT) {
			return diag("global ikev1-policy does not allow IKEv1 connections");
		}
#else
		return diag("IKEv1 support not compiled in");
#endif
	}

	if ((wm->ike_version == IKEv1 && wm->ikev2 == YN_YES) ||
	    (wm->ike_version == IKEv2 && wm->ikev2 == YN_NO)) {
		enum_buf vn;
		llog(RC_LOG, c->logger,
		     "ignoring ikev2=%s which conflicts with keyexchange=%s",
		     (wm->ikev2 == YN_YES ? "yes" :
		      wm->ikev2 == YN_NO ? "no" :
		      "???"),
		     str_enum(&ike_version_names, wm->ike_version, &vn));
	} else if (wm->ikev2 != 0) {
		llog(RC_LOG, c->logger,
		     "ikev2=%s has been replaced by keyexchange=%s",
		     (wm->ikev2 == YN_YES ? "yes" :
		      wm->ikev2 == YN_NO ? "no" :
		      "???"),
		     (wm->ikev2 == YN_YES ? "ikev2" :
		      wm->ikev2 == YN_NO ? "ikev1" :
		      "???"));
	}

	config->ike_version = wm->ike_version;
	PASSERT(c->logger, wm->ike_version < elemsof(ike_info));
	PASSERT(c->logger, ike_info[wm->ike_version] != NULL);
	config->ike_info = ike_info[wm->ike_version];
	PASSERT(c->logger, config->ike_info->version > 0);

#if 0
	PASSERT(c->logger,
		is_opportunistic_wm(wm) == ((wm->policy & POLICY_OPPORTUNISTIC) != LEMPTY));
	PASSERT(c->logger, is_group_wm(wm) == wm->is_connection_group);
#endif

	if (is_opportunistic_wm(wm) && c->config->ike_version < IKEv2) {
		return diag("opportunistic connection MUST have IKEv2");
	}
	config->opportunistic = is_opportunistic_wm(wm);

#if 0
	if (is_opportunistic_wm(wm)) {
		if (wm->authby.psk) {
			return diag("PSK is not supported for opportunism");
		}
		if (!authby_has_digsig(wm->authby)) {
			return diag("only Digital Signatures are supported for opportunism");
		}
		if (!pfs) {
			return diag("PFS required for opportunism");
		}
	}
#endif

	config->intermediate = extract_yn("", "intermediate", wm->intermediate,
					  /*value_when_unset*/YN_NO,
					  wm, c->logger);
	if (config->intermediate) {
		if (wm->ike_version < IKEv2) {
			return diag("intermediate requires IKEv2");
		}
	}

	config->session_resumption = extract_yn("", "session_resumption", wm->session_resumption,
						/*value_when_unset*/YN_NO,
						wm, c->logger);
	if (config->session_resumption) {
		if (wm->ike_version < IKEv2) {
			return diag("session resumption requires IKEv2");
		}
	}

	config->sha2_truncbug = extract_yn("", "sha2-truncbug", wm->sha2_truncbug,
					   /*value_when_unset*/YN_NO,
					   wm, c->logger);
	config->overlapip = extract_yn("", "overlapip", wm->overlapip,
				       /*value_when_unset*/YN_NO, wm, c->logger);

	bool ms_dh_downgrade = extract_yn("", "ms-dh-downgrade", wm->ms_dh_downgrade,
					  /*value_when_unset*/YN_NO, wm, c->logger);
	bool pfs_rekey_workaround = extract_yn("", "pfs-rekey-workaround", wm->pfs_rekey_workaround,
					       /*value_when_unset*/YN_NO, wm, c->logger);
	if (ms_dh_downgrade && pfs_rekey_workaround) {
		return diag("cannot specify both ms-dh-downgrade=yes and pfs-rekey-workaround=yes");
	}
	config->ms_dh_downgrade = ms_dh_downgrade;
	config->pfs_rekey_workaround = pfs_rekey_workaround;

	config->dns_match_id = extract_yn("", "dns-match-id", wm->dns_match_id,
					  /*value_when_unset*/YN_NO, wm, c->logger);
	/* IKEv2 only; IKEv1 uses xauth=pam */
	config->ikev2_pam_authorize = extract_yn("", "pam-authorize", wm->pam_authorize,
						 /*value_when_unset*/YN_NO, wm, c->logger);

	if (wm->ike_version >= IKEv2) {
		if (wm->ikepad != YNA_UNSET) {
			name_buf vn, pn;
			llog(RC_LOG, c->logger, "warning: %s connection ignores ikepad=%s",
			     str_enum(&ike_version_names, wm->ike_version, &vn),
			     str_sparse(&yna_option_names, wm->ikepad, &pn));
		}
		/* default */
		config->v1_ikepad.message = true;
		config->v1_ikepad.modecfg = false;
	} else {
		config->v1_ikepad.modecfg = (wm->ikepad == YNA_YES);
		config->v1_ikepad.message = (wm->ikepad != YNA_NO);
	}

	config->require_id_on_certificate = extract_yn("", "require-id-on-certificate", wm->require_id_on_certificate,
						       /*value_when_unset*/YN_YES,wm, c->logger);

	if (wm->aggressive == YN_YES && wm->ike_version >= IKEv2) {
		return diag("cannot specify aggressive mode with IKEv2");
	}
	if (wm->aggressive == YN_YES && wm->ike == NULL) {
		return diag("cannot specify aggressive mode without ike= to set algorithm");
	}
	config->aggressive = extract_yn("", "aggressive", wm->aggressive,
					/*value_when_unset*/YN_NO,
					wm, c->logger);

	config->decap_dscp = extract_yn("", "decap-dscp", wm->decap_dscp,
					/*value_when_unset*/YN_NO,
					wm, c->logger);

	config->encap_dscp = extract_yn("", "encap-dscp", wm->encap_dscp,
					/*value_when_unset*/YN_YES,
					wm, c->logger);

	config->nopmtudisc = extract_yn("", "nopmtudisc", wm->nopmtudisc,
					/*value_when_unset*/YN_NO,
					wm, c->logger);

	bool mobike = extract_yn("", "mobike", wm->mobike,
				 /*value_when_unset*/YN_NO,
				 wm, c->logger);
	config->mobike = mobike;
	if (mobike) {
		if (wm->ike_version < IKEv2) {
			return diag("MOBIKE requires IKEv2");
		}
		if (encap_mode != ENCAP_MODE_TUNNEL) {
			return diag("MOBIKE requires tunnel mode");
		}
		if (kernel_ops->migrate_ipsec_sa_is_enabled == NULL) {
			return diag("MOBIKE is not supported by %s kernel interface",
				    kernel_ops->interface_name);
		}
		/* probe the interface */
		err_t err = kernel_ops->migrate_ipsec_sa_is_enabled(c->logger);
		if (err != NULL) {
			return diag("MOBIKE support is not enabled for %s kernel interface: %s",
				    kernel_ops->interface_name, err);
		}
	}

	/* this warns when never_negotiate() */
	bool iptfs = extract_yn("", "iptfs", wm->iptfs,
				/*value_when_unset*/YN_NO,
				wm, c->logger);
	if (iptfs) {
		/* lots of incompatibility */
		if (wm->ike_version < IKEv2) {
			return diag("IPTFS requires IKEv2");
		}
		if (encap_mode != ENCAP_MODE_TUNNEL) {
			name_buf sb;
			return diag("type=%s must be transport",
				    str_sparse(&type_option_names, wm->type, &sb));
		}
		if (wm->tfc > 0) {
			return diag("IPTFS is not compatible with tfc=%ju", wm->tfc);
		}
		if (compress) {
			return diag("IPTFS is not compatible with compress=yes");
		}
		if (encap_mode == ENCAP_MODE_TRANSPORT) {
			return diag("IPTFS is not compatible with type=transport");
		}
		if (encap_proto != ENCAP_PROTO_ESP) {
			name_buf sb;
			return diag("IPTFS is not compatible with phase2=%s",
				    str_enum(&encap_proto_story, wm->phase2, &sb));
		}

		err_t err = kernel_ops->iptfs_ipsec_sa_is_enabled(c->logger);
		if (err != NULL) {
			return diag("IPTFS is not supported by the kernel: %s", err);
		}

		deltatime_t uint32_max = deltatime_from_microseconds(UINT32_MAX);

		config->child_sa.iptfs.enabled = true;
		config->child_sa.iptfs.packet_size = wm->iptfs_packet_size;
		config->child_sa.iptfs.max_queue_size = wm->iptfs_max_queue_size;

		if (deltatime_cmp(wm->iptfs_drop_time, >=, uint32_max)) {
			deltatime_buf tb;
			return diag("iptfs-drop-time cannot larger than %s",
				    str_deltatime(uint32_max, &tb));
		}
		config->child_sa.iptfs.drop_time = wm->iptfs_drop_time;

			if (deltatime_cmp(wm->iptfs_init_delay, >=, uint32_max)) {
			deltatime_buf tb;
			return diag("iptfs-init-delay cannot larger than %s",
				    str_deltatime(uint32_max, &tb));
		}
		config->child_sa.iptfs.init_delay = wm->iptfs_init_delay;

		if (wm->iptfs_reorder_window > 65535) {
			return diag("iptfs reorder window cannot be larger than 65535");
		}
		config->child_sa.iptfs.reorder_window = wm->iptfs_reorder_window;
	}

	/*
	 * Extract iptfs parameters regardless; so that the default is
	 * consistent and toggling iptfs= doesn't seem to change the
	 * field.  Could warn about this but meh.
	 */
	config->child_sa.iptfs.fragmentation =
		extract_yn_p("", "iptfs-fragmentation", wm->iptfs_fragmentation,
			     /*value_when_unset*/YN_YES,
			     wm, c->logger,
			     "", "iptfs", wm->iptfs);

	/*
	 * RFC 5685 - IKEv2 Redirect mechanism.
	 */
	config->redirect.to = clone_str(wm->redirect_to, "connection redirect_to");
	config->redirect.accept_to = clone_str(wm->accept_redirect_to, "connection accept_redirect_to");
	if (wm->ike_version == IKEv1) {
		if (wm->send_redirect != YNA_UNSET) {
			llog(RC_LOG, c->logger,
			     "warning: IKEv1 connection ignores send-redirect=");
		}
	} else {
		switch (wm->send_redirect) {
		case YNA_YES:
			if (wm->redirect_to == NULL) {
				llog(RC_LOG, c->logger,
				     "warning: send-redirect=yes ignored, redirect-to= was not specified");
			}
			/* set it anyway!?!  the code checking it
			 * issues a second warning */
			config->redirect.send_always = true;
			break;

		case YNA_NO:
			if (wm->redirect_to != NULL) {
				llog(RC_LOG, c->logger,
				     "warning: send-redirect=no, redirect-to= is ignored");
			}
			config->redirect.send_never = true;
			break;

		case YNA_UNSET:
		case YNA_AUTO:
			break;
		}
	}

	if (wm->ike_version == IKEv1) {
		if (wm->accept_redirect != YN_UNSET) {
			llog(RC_LOG, c->logger,
			     "warning: IKEv1 connection ignores accept-redirect=");
		}
	} else {
		config->redirect.accept =
			extract_yn("", "acceept-redirect", wm->accept_redirect,
				   /*value_when_unset*/YN_NO,
				   wm, c->logger);
	}

	/* fragmentation */

	/*
	 * some options are set as part of our default, but
	 * some make no sense for shunts, so remove those again
	 */
	if (never_negotiate_wm(wm)) {
		if (wm->fragmentation != YNF_UNSET) {
			name_buf fb;
			llog(RC_LOG, c->logger,
			     "warning: never-negotiate connection ignores fragmentation=%s",
			     str_sparse(&ynf_option_names, wm->fragmentation, &fb));
		}
	} else if (wm->ike_version >= IKEv2 && wm->fragmentation == YNF_FORCE) {
		name_buf fb;
		llog(RC_LOG, c->logger,
		     "warning: IKEv1 only fragmentation=%s ignored; using fragmentation=yes",
		     str_sparse(&ynf_option_names, wm->fragmentation, &fb));
		config->ike_frag.allow = true;
	} else {
		switch (wm->fragmentation) {
		case YNF_UNSET: /*default*/
		case YNF_YES:
			config->ike_frag.allow = true;
			break;
		case YNF_NO:
			break;
		case YNF_FORCE:
			config->ike_frag.allow = true;
			config->ike_frag.v1_force = true;
		}
	}

	/* RFC 8229 TCP encap*/

	enum tcp_options iketcp;
	if (never_negotiate_wm(wm)) {
		if (wm->enable_tcp != 0) {
			sparse_buf eb;
			llog(RC_LOG, c->logger,
			     "warning: enable-tcp=%s ignored for type=passthrough connection",
			     str_sparse(&tcp_option_names, wm->enable_tcp, &eb));
		}
		/* cleanup inherited default; XXX: ? */
		iketcp = IKE_TCP_NO;
	} else if (c->config->ike_version < IKEv2) {
		if (wm->enable_tcp != 0 &&
		    wm->enable_tcp != IKE_TCP_NO) {
			return diag("enable-tcp= requires IKEv2");
		}
		iketcp = IKE_TCP_NO;
	} else if (wm->enable_tcp == 0) {
		iketcp = IKE_TCP_NO; /* default */
	} else {
		iketcp = wm->enable_tcp;
	}
	config->end[LEFT_END].host.iketcp = config->end[RIGHT_END].host.iketcp = iketcp;

	switch (iketcp) {
	case IKE_TCP_NO:
		if (wm->tcp_remoteport != 0) {
			llog(RC_LOG, c->logger,
			     "warning: tcp-remoteport=%ju ignored for non-TCP connections",
			     wm->tcp_remoteport);
		}
		/* keep tests happy, value ignored */
		config->remote_tcpport = ip_hport(NAT_IKE_UDP_PORT);
		break;
	case IKE_TCP_ONLY:
	case IKE_TCP_FALLBACK:
		if (wm->tcp_remoteport == 500) {
			return diag("tcp-remoteport cannot be 500");
		}
		if (wm->tcp_remoteport > 65535/*magic?*/) {
			return diag("tcp-remoteport=%ju is too big", wm->tcp_remoteport);
		}
		config->remote_tcpport =
			ip_hport(wm->tcp_remoteport == 0 ? NAT_IKE_UDP_PORT:
				 wm->tcp_remoteport);
		break;
	default:
		/* must  have been set */
		bad_sparse(c->logger, &tcp_option_names, iketcp);
	}


	/* authentication (proof of identity) */

	if (never_negotiate_wm(wm)) {
		dbg("ignore sighash, never negotiate");
	} else if (c->config->ike_version == IKEv1) {
		dbg("ignore sighash, IKEv1");
	} else {
		config->sighash_policy = wm->sighash_policy;
	}

	/* some port stuff */

	if (wm->end[RIGHT_END].protoport.has_port_wildcard && wm->end[LEFT_END].protoport.has_port_wildcard) {
		return diag("cannot have protoports with wildcard (%%any) ports on both sides");
	}

	/*
	 * When the other side is wildcard: we must check if other
	 * conditions met.
	 *
	 * MAKE this more sane in the face of unresolved IP
	 * addresses.
	 */
	if (wm->end[LEFT_END].host_type != KH_IPHOSTNAME && !address_is_specified(wm->end[LEFT_END].host_addr) &&
	    wm->end[RIGHT_END].host_type != KH_IPHOSTNAME && !address_is_specified(wm->end[RIGHT_END].host_addr)) {
		return diag("must specify host IP address for our side");
	}

	/* duplicate any alias, adding spaces to the beginning and end */
	config->connalias = clone_str(wm->connalias, "connection alias");

	config->dnshostname = clone_str(wm->dnshostname, "connection dnshostname");

	/*
	 * narrowing=?
	 *
	 * In addition to explicit narrowing=yes, seeing any sort of
	 * port wildcard (tcp/%any) implies narrowing.  This is
	 * largely IKEv1 and L2TP (it's the only test) but nothing
	 * implies that they can't.
	 */

	if (wm->narrowing == YN_NO && wm->ike_version < IKEv2) {
		return diag("narrowing=yes requires IKEv2");
	}
	if (wm->narrowing == YN_NO) {
		FOR_EACH_THING(end, &wm->end[LEFT_END], &wm->end[RIGHT_END]) {
			if (end->addresspool != NULL) {
				return diag("narrowing=no conflicts with %saddresspool=%s",
					    end->leftright,
					    end->addresspool);
			}
		}
	}
	bool narrowing =
		extract_yn("", "narrowing", wm->narrowing,
			   /*value_when_unset*/(wm->ike_version < IKEv2 ? YN_NO :
						wm->end[LEFT_END].addresspool != NULL ? YN_YES :
						wm->end[RIGHT_END].addresspool != NULL ? YN_YES :
						YN_NO),
			   wm, c->logger);
#if 0
	/*
	 * Not yet: tcp/%any means narrow past the selector and down
	 * to a single port; while narrwing means narrow down to the
	 * selector.
	 */
	FOR_EACH_THING(end, &wm->end[LEFT_END], &wm->end[RIGHT_END]) {
		narrowing |= (end->protoport.is_set &&
			      end->protoport.has_port_wildcard);
	}
#endif
	config->narrowing = narrowing;

	config->rekey = extract_yn("", "rekey", wm->rekey,
				   /*value_when_unset*/YN_YES,
				   wm, c->logger);
	config->reauth = extract_yn("", "reauth", wm->reauth,
				    /*value_when_unset*/YN_NO,
				    wm, c->logger);

	switch (wm->autostart) {
	case AUTOSTART_UP:
	case AUTOSTART_START:
	{
		name_buf nb;
		ldbg(c->logger, "autostart=%s implies +UP",
		     str_sparse(&autostart_names, wm->autostart, &nb));
		add_policy(c, policy.up);
		break;
	}
	case AUTOSTART_ROUTE:
	case AUTOSTART_ONDEMAND:
	{
		name_buf nb;
		ldbg(c->logger, "autostart=%s implies +ROUTE",
		     str_sparse(&autostart_names, wm->autostart, &nb));
		add_policy(c, policy.route);
		break;
	}
	case AUTOSTART_KEEP:
	{
		name_buf nb;
		ldbg(c->logger, "autostart=%s implies +KEEP",
		     str_sparse(&autostart_names, wm->autostart, &nb));
		add_policy(c, policy.keep);
		break;
	}
	case AUTOSTART_IGNORE:
	case AUTOSTART_ADD:
	case AUTOSTART_UNSET:
		break;
	}

	/*
	 * Extract configurable shunts, set hardwired shunts.
	 */

	d = extract_shunt(config, wm, SHUNT_KIND_NEVER_NEGOTIATE,
			  &never_negotiate_shunt_names, /*unset*/SHUNT_UNSET);
	if (d != NULL) {
		return d;
	}

	d = extract_shunt(config, wm, SHUNT_KIND_NEGOTIATION,
			  &negotiation_shunt_names, /*unset*/SHUNT_DROP);
	if (d != NULL) {
		return d;
	}

	if (is_fips_mode() && config->negotiation_shunt == SHUNT_PASS) {
		enum_buf sb;
		llog(RC_LOG, c->logger,
		     "FIPS: ignored negotiationshunt=%s - packets MUST be blocked in FIPS mode",
		     str_sparse_short(&negotiation_shunt_names, config->negotiation_shunt, &sb));
		config->negotiation_shunt = SHUNT_DROP;
	}

	d = extract_shunt(config, wm, SHUNT_KIND_FAILURE,
			  &failure_shunt_names, /*unset*/SHUNT_NONE);
	if (d != NULL) {
		return d;
	}

	/* make kernel code easier */
	config->shunt[SHUNT_KIND_BLOCK] = SHUNT_DROP;
	config->shunt[SHUNT_KIND_ONDEMAND] = SHUNT_TRAP;
	config->shunt[SHUNT_KIND_IPSEC] = SHUNT_IPSEC;

	if (is_fips_mode() && config->failure_shunt != SHUNT_NONE) {
		enum_buf eb;
		llog(RC_LOG, c->logger,
		     "FIPS: ignored failureshunt=%s - packets MUST be blocked in FIPS mode",
		     str_sparse_short(&failure_shunt_names, config->failure_shunt, &eb));
		config->failure_shunt = SHUNT_NONE;
	}

	for (enum shunt_kind sk = SHUNT_KIND_FLOOR; sk < SHUNT_KIND_ROOF; sk++) {
		PASSERT(c->logger, sk < elemsof(config->shunt));
		PASSERT(c->logger, shunt_ok(sk, config->shunt[sk]));
	}

	/*
	 * Should ESN be disabled?
	 *
	 * Order things so that a lack of kernel support is the last
	 * resort (fixing the kernel will break less tests).
	 */

	uintmax_t replay_window =
		extract_uintmax("", "replay-window", wm->replay_window,
				/*value_when_unset*/IPSEC_SA_DEFAULT_REPLAY_WINDOW,
				0, kernel_ops->max_replay_window,
				wm, &d, c->logger);
	if (d != NULL) {
		return d;
	}
	config->child_sa.replay_window = replay_window;

	if (never_negotiate_wm(wm)) {
		if (wm->esn != YNE_UNSET) {
			name_buf nb;
			llog(RC_LOG, c->logger,
			     "warning: ignoring esn=%s as connection is never-negotiate",
			     str_sparse(&yne_option_names, wm->esn, &nb));
		}
	} else if (replay_window == 0) {
		/*
		 * RFC 4303 states:
		 *
		 * Note: If a receiver chooses to not enable
		 * anti-replay for an SA, then the receiver SHOULD NOT
		 * negotiate ESN in an SA management protocol.  Use of
		 * ESN creates a need for the receiver to manage the
		 * anti-replay window (in order to determine the
		 * correct value for the high-order bits of the ESN,
		 * which are employed in the ICV computation), which
		 * is generally contrary to the notion of disabling
		 * anti-replay for an SA.
		 */
		if (wm->esn != YNE_UNSET && wm->esn != YNE_NO) {
			llog(RC_LOG, c->logger,
			     "warning: forcing esn=no as replay-window=0");
		} else {
			dbg("ESN: disabled as replay-window=0"); /* XXX: log? */
		}
		config->esn.no = true;
	} else if (!kernel_ops->esn_supported) {
		/*
		 * Only warn when there's an explicit esn=yes.
		 */
		if (wm->esn == YNE_YES ||
		    wm->esn == YNE_EITHER) {
			name_buf nb;
			llog(RC_LOG, c->logger,
			     "warning: %s kernel interface does not support ESN, ignoring esn=%s",
			     kernel_ops->interface_name,
			     str_sparse(&yne_option_names, wm->esn, &nb));
		}
		config->esn.no = true;
#ifdef USE_IKEv1
	} else if (wm->ike_version == IKEv1) {
		/*
		 * Ignore ESN when IKEv1.
		 *
		 * XXX: except it isn't; it still gets decoded and
		 * stuffed into the config.  It just isn't acted on.
		 */
		dbg("ESN: ignored as not implemented with IKEv1");
#if 0
		if (wm->esn != YNE_UNSET) {
			name_buf nb;
			llog(RC_LOG, c->logger,
			     "warning: ignoring esn=%s as not implemented with IKEv1",
			     str_sparse(yne_option_names, wm->esn, &nb));
		}
#endif
		switch (wm->esn) {
		case YNE_UNSET:
		case YNE_EITHER:
			config->esn.no = true;
			config->esn.yes = true;
			break;
		case YNE_NO:
			config->esn.no = true;
			break;
		case YNE_YES:
			config->esn.yes = true;
			break;
		}
#endif
	} else {
		switch (wm->esn) {
		case YNE_UNSET:
		case YNE_EITHER:
			config->esn.no = true;
			config->esn.yes = true;
			break;
		case YNE_NO:
			config->esn.no = true;
			break;
		case YNE_YES:
			config->esn.yes = true;
			break;
		}
	}

	if (wm->ike_version == IKEv1) {
		if (wm->ppk != NPPI_UNSET) {
			sparse_buf sb;
			llog(RC_LOG, c->logger,
			     "warning: ignoring ppk=%s as IKEv1",
			     str_sparse(&nppi_option_names, wm->ppk, &sb));
		}
	} else {
		switch (wm->ppk) {
		case NPPI_UNSET:
		case NPPI_NEVER:
			break;
		case NPPI_PERMIT:
		case NPPI_PROPOSE:
			config->ppk.allow = true;
			break;
		case NPPI_INSIST:
			config->ppk.allow = true;
			config->ppk.insist = true;
			break;
		}
	}

	connection_buf cb;
	policy_buf pb;
	dbg("added new %s connection "PRI_CONNECTION" with policy %s",
	    c->config->ike_info->version_name,
	    pri_connection(c, &cb), str_connection_policies(c, &pb));

	/* IKE cipher suites */

	if (never_negotiate_wm(wm)) {
		if (wm->ike != NULL) {
			llog(RC_LOG, c->logger,
			     "ignored ike= option for type=passthrough connection");
		}
	} else {
		const struct proposal_policy proposal_policy = {
			/* logic needs to match pick_initiator() */
			.version = c->config->ike_version,
			.alg_is_ok = ike_alg_is_ike,
			.pfs = pfs,
			.check_pfs_vs_dh = false,
			.logger_rc_flags = ALL_STREAMS,
			.logger = c->logger, /* on-stack */
			/* let defaults stumble on regardless */
			.ignore_parser_errors = (wm->ike == NULL),
		};

		struct proposal_parser *parser = ike_proposal_parser(&proposal_policy);
		config->ike_proposals.p = proposals_from_str(parser, wm->ike);

		if (c->config->ike_proposals.p == NULL) {
			pexpect(parser->diag != NULL); /* something */
			diag_t d = parser->diag; parser->diag = NULL;
			free_proposal_parser(&parser);
			return d;
		}
		free_proposal_parser(&parser);

		LDBGP_JAMBUF(DBG_BASE, c->logger, buf) {
			jam_string(buf, "ike (phase1) algorithm values: ");
			jam_proposals(buf, c->config->ike_proposals.p);
		}

		if (c->config->ike_version == IKEv2) {
			connection_buf cb;
			dbg("constructing local IKE proposals for "PRI_CONNECTION,
			    pri_connection(c, &cb));
			config->v2_ike_proposals =
				ikev2_proposals_from_proposals(IKEv2_SEC_PROTO_IKE,
							       config->ike_proposals.p,
							       c->logger);
			llog_v2_proposals(LOG_STREAM/*not-whack*/, c->logger,
					  config->v2_ike_proposals,
					  "IKE SA proposals (connection add)");
		}
	}

	/* ESP or AH cipher suites (but not both) */

	if (never_negotiate_wm(wm)) {
		if (wm->esp != NULL) {
			llog(RC_LOG, c->logger,
			     "ignored esp= option for type=passthrough connection");
		}
	} else  {
		PEXPECT(c->logger, encap_proto != ENCAP_PROTO_UNSET);

		const struct proposal_policy proposal_policy = {
			/*
			 * logic needs to match pick_initiator()
			 *
			 * XXX: Once pluto is changed to IKEv1 XOR
			 * IKEv2 it should be possible to move this
			 * magic into pluto proper and instead pass a
			 * simple boolean.
			 */
			.version = c->config->ike_version,
			.alg_is_ok = kernel_alg_is_ok,
			.pfs = pfs,
			.check_pfs_vs_dh = true,
			.logger_rc_flags = ALL_STREAMS,
			.logger = c->logger, /* on-stack */
			/* let defaults stumble on regardless */
			.ignore_parser_errors = (wm->esp == NULL),
		};

		/*
		 * We checked above that exactly one of POLICY_ENCRYPT
		 * and POLICY_AUTHENTICATE is on.  The only difference
		 * in processing is which function is called (and
		 * those functions are almost identical).
		 */
		struct proposal_parser *(*fn)(const struct proposal_policy *policy) =
			(encap_proto == ENCAP_PROTO_ESP) ? esp_proposal_parser :
			(encap_proto == ENCAP_PROTO_AH) ? ah_proposal_parser :
			NULL;
		passert(fn != NULL);
		struct proposal_parser *parser = fn(&proposal_policy);
		config->child_sa.proposals.p = proposals_from_str(parser, wm->esp);
		if (c->config->child_sa.proposals.p == NULL) {
			pexpect(parser->diag != NULL);
			diag_t d = parser->diag; parser->diag = NULL;
			free_proposal_parser(&parser);
			return d;
		}
		free_proposal_parser(&parser);

		LDBGP_JAMBUF(DBG_BASE, c->logger, buf) {
			jam_string(buf, "ESP/AH string values: ");
			jam_proposals(buf, c->config->child_sa.proposals.p);
		};

		/*
		 * For IKEv2, also generate the Child proposal that
		 * will be used during IKE AUTH.
		 *
		 * Since a Child SA established during an IKE_AUTH
		 * exchange does not propose DH (keying material is
		 * taken from the IKE SA's SKEYSEED), DH is stripped
		 * from the proposals.
		 *
		 * Since only things that affect this proposal suite
		 * are the connection's .policy bits and the contents
		 * .child_proposals, and modifying those triggers the
		 * creation of a new connection (true?), the
		 * connection can be cached.
		 */
		if (c->config->ike_version == IKEv2) {
			config->child_sa.v2_ike_auth_proposals =
				get_v2_IKE_AUTH_new_child_proposals(c);
			llog_v2_proposals(LOG_STREAM/*not-whack*/, c->logger,
					  config->child_sa.v2_ike_auth_proposals,
					  "Child SA proposals (connection add)");
		}
	}

	config->encapsulation = extract_yna("", "encapsulation", wm->encapsulation,
					    /*value_when_unset*/YNA_AUTO,
					    /*value_when_never_negotiate*/YNA_NO,
					    wm, c->logger);

	config->vti.shared = extract_yn("", "vti-shared", wm->vti_shared,
					/*value_when_unset*/YN_NO, wm, c->logger);
	config->vti.routing = extract_yn("", "vti-routing", wm->vti_routing,
					 /*value_when_unset*/YN_NO, wm, c->logger);
	if (wm->vti_interface != NULL && strlen(wm->vti_interface) >= IFNAMSIZ) {
		llog(RC_LOG, c->logger,
		     "warning: length of vti-interface '%s' exceeds IFNAMSIZ (%u)",
		     wm->vti_interface, (unsigned) IFNAMSIZ);
	}
	config->vti.interface = extract_string("",  "vti-interface", wm->vti_interface,
					       wm, c->logger);

	if (never_negotiate_wm(wm)) {
		if (wm->nic_offload != NIC_OFFLOAD_UNSET) {
			name_buf nb;
			llog(RC_LOG, c->logger, "nic-offload=%s ignored for never-negotiate connection",
			     str_sparse(&nic_offload_option_names, wm->nic_offload, &nb));
		}
		/* keep <<ipsec connectionstatus>> simple */
		config->nic_offload = NIC_OFFLOAD_NO;
	} else {
		switch (wm->nic_offload) {
		case NIC_OFFLOAD_UNSET:
		case NIC_OFFLOAD_NO:
			config->nic_offload = NIC_OFFLOAD_NO; /* default */
			break;
		case NIC_OFFLOAD_PACKET:
		case NIC_OFFLOAD_CRYPTO:
			if (kernel_ops->detect_nic_offload == NULL) {
				name_buf nb;
				return diag("no kernel support for nic-offload[=%s]",
					    str_sparse(&nic_offload_option_names, wm->nic_offload, &nb));
			}
			config->nic_offload = wm->nic_offload;
		}

		if (wm->nic_offload == NIC_OFFLOAD_PACKET) {
			if (encap_mode != ENCAP_MODE_TRANSPORT) {
				return diag("nic-offload=packet restricted to type=transport");
			}
			if (encap_proto != ENCAP_PROTO_ESP) {
				return diag("nic-offload=packet restricted to phase2=esp");
			}
			if (compress) {
				return diag("nic-offload=packet restricted to compression=no");
			}
			if (config->encapsulation == YNA_YES) {
				return diag("nic-offload=packet cannot specify encapsulation=yes");
			}

			/* byte/packet counters for packet offload on linux requires >= 6.7 */
			if (wm->ipsec_max_bytes != NULL ||
			    wm->ipsec_max_packets != NULL) {
				if (!kernel_ge(KINFO_LINUX, 6, 7, 0)) {
					return diag("Linux kernel 6.7+ required for byte/packet counters and hardware offload");
				}
				ldbg(c->logger, "kernel >= 6.7 is GTG for h/w offload");
			}

			/* limited replay windows supported for packet offload */
			switch (replay_window) {
			case 32:
			case 64:
			case 128:
			case 256:
				ldbg(c->logger, "packet offload replay-window compatible with all known hardware and Linux kernels");
				break;
			default:
				return diag("current packet offload hardware only supports replay-window of 32, 64, 128 or 256");
			}
			/* check if we need checks for tfcpad= , encap-dscp, nopmtudisc, ikepad, encapsulation, etc? */
		}

	}

	uintmax_t rekeyfuzz_percent = extract_percent("", "rekeyfuzz", wm->rekeyfuzz,
						      SA_REPLACEMENT_FUZZ_DEFAULT,
						      wm, &d, c->logger);

	if (never_negotiate_wm(wm)) {
		dbg("skipping over misc settings as NEVER_NEGOTIATE");
	} else {

		if (d != NULL) {
			return d;
		}

		deltatime_t rekeymargin;
		if (wm->rekeymargin.is_set) {
			if (deltasecs(wm->rekeymargin) > (INT_MAX / (100 + (intmax_t)rekeyfuzz_percent))) {
				return diag("rekeymargin=%jd is so large it causes overflow",
					    deltasecs(wm->rekeymargin));
			}
			rekeymargin = wm->rekeymargin;
		} else {
			rekeymargin = deltatime(SA_REPLACEMENT_MARGIN_DEFAULT);
		};
		config->sa_rekey_margin = rekeymargin;

		d = extract_lifetime(&config->sa_ike_max_lifetime,
				     "ikelifetime", wm->ikelifetime,
				     IKE_SA_LIFETIME_DEFAULT,
				     IKE_SA_LIFETIME_MAXIMUM,
				     FIPS_IKE_SA_LIFETIME_MAXIMUM,
				     rekeymargin, rekeyfuzz_percent,
				     c->logger, wm);
		if (d != NULL) {
			return d;
		}
		d = extract_lifetime(&config->sa_ipsec_max_lifetime,
				     "ipsec-lifetime", wm->ipsec_lifetime,
				     IPSEC_SA_LIFETIME_DEFAULT,
				     IPSEC_SA_LIFETIME_MAXIMUM,
				     FIPS_IPSEC_SA_LIFETIME_MAXIMUM,
				     rekeymargin, rekeyfuzz_percent,
				     c->logger, wm);
		if (d != NULL) {
			return d;
		}

		config->sa_rekey_fuzz = rekeyfuzz_percent;

		config->retransmit_timeout =
			(wm->retransmit_timeout.is_set ? wm->retransmit_timeout :
			 deltatime_from_milliseconds(RETRANSMIT_TIMEOUT_DEFAULT * 1000));
		config->retransmit_interval =
			(wm->retransmit_interval.is_set ? wm->retransmit_interval :
			 deltatime_from_milliseconds(RETRANSMIT_INTERVAL_DEFAULT_MS));

		/*
		 * A 1500 mtu packet requires 1500/16 ~= 90 crypto
		 * operations.  Always use NIST maximums for
		 * bytes/packets.
		 *
		 * https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
		 * "The total number of invocations of the
		 * authenticated encryption function shall not exceed
		 * 2^32 , including all IV lengths and all instances
		 * of the authenticated encryption function with the
		 * given key."
		 *
		 * Note "invocations" is not "bytes" or "packets", but
		 * the safest assumption is the most wasteful
		 * invocations which is 1 byte per packet.
		 *
		 * XXX: this code isn't yet doing this.
		 */

		config->sa_ipsec_max_bytes =
			extract_scaled_uintmax("", "ipsec-max-bytes", wm->ipsec_max_bytes,
					       &binary_byte_scales,
					       IPSEC_SA_MAX_OPERATIONS,
					       "IPsec max bytes",
					       wm, &d, c->logger);
		if (d != NULL) {
			return d;
		}

		config->sa_ipsec_max_packets =
			extract_scaled_uintmax("", "ipsec-max-packets", wm->ipsec_max_packets,
					       &binary_scales,
					       IPSEC_SA_MAX_OPERATIONS,
					       "IPsec max packets",
					       wm, &d, c->logger);
		if (d != NULL) {
			return d;
		}

		if (deltatime_cmp(config->sa_rekey_margin, >=, config->sa_ipsec_max_lifetime)) {
			deltatime_t new_rkm = deltatime_scale(config->sa_ipsec_max_lifetime, 1, 2);

			llog(RC_LOG, c->logger,
			     "rekeymargin (%jds) >= salifetime (%jds); reducing rekeymargin to %jds seconds",
			     deltasecs(config->sa_rekey_margin),
			     deltasecs(config->sa_ipsec_max_lifetime),
			     deltasecs(new_rkm));

			config->sa_rekey_margin = new_rkm;
		}

		const enum timescale dpd_timescale = TIMESCALE_SECONDS;
		switch (wm->ike_version) {
		case IKEv1:
			/* IKEv1's RFC 3706 DPD */
			if (wm->dpddelay != NULL &&
			    wm->dpdtimeout != NULL) {
				diag_t d;
				d = ttodeltatime(shunk1(wm->dpddelay),
						 &config->dpd.delay,
						 dpd_timescale);
				if (d != NULL) {
					return diag_diag(&d, "dpddelay=%s invalid, ",
							 wm->dpddelay);
				}
				d = ttodeltatime(shunk1(wm->dpdtimeout),
						 &config->dpd.timeout,
						 dpd_timescale);
				if (d != NULL) {
					return diag_diag(&d, "dpdtimeout=%s invalid, ",
							 wm->dpdtimeout);
				}
				deltatime_buf db, tb;
				ldbg(c->logger, "IKEv1 dpd.timeout=%s dpd.delay=%s",
				     str_deltatime(config->dpd.timeout, &db),
				     str_deltatime(config->dpd.delay, &tb));
			} else if (wm->dpddelay != NULL  ||
				   wm->dpdtimeout != NULL) {
				llog(RC_LOG, c->logger,
				     "warning: IKEv1 dpd settings are ignored unless both dpdtimeout= and dpddelay= are set");
			}
			break;
		case IKEv2:
			if (wm->dpddelay != NULL) {
				diag_t d;
				d = ttodeltatime(shunk1(wm->dpddelay),
						 &config->dpd.delay,
						 dpd_timescale);
				if (d != NULL) {
					return diag_diag(&d, "dpddelay=%s invalid, ",
							 wm->dpddelay);
				}
			}
			if (wm->dpdtimeout != NULL) {
				/* actual values don't matter */
				llog(RC_LOG, c->logger,
				     "warning: IKEv2 ignores dpdtimeout==; use dpddelay= and retransmit-timeout=");
			}
			break;
		}

		/* Cisco interop: remote peer type */
		enum remote_peer_type remote_peer_type =
			extract_sparse_name("", "remote-peer-type",
					    wm->remote_peer_type,
					    REMOTE_PEER_IETF,
					    &remote_peer_type_names,
					    wm, &d, c->logger);
		if (d != NULL) {
			return d;
		}
		/* just blat both ends */
		FOR_EACH_ELEMENT(end, config->end) {
			end->host.xauth.cisco = (remote_peer_type == REMOTE_PEER_CISCO);
		}

		config->child_sa.metric = wm->metric;
		config->child_sa.mtu = wm->mtu;
		config->nat_keepalive = extract_yn("", "nat-keepalive", wm->nat_keepalive,
						   /*value_when_unset*/YN_YES,
						   wm, c->logger);
		if (wm->nat_ikev1_method == 0) {
			config->ikev1_natt = NATT_BOTH;
		} else {
			config->ikev1_natt = wm->nat_ikev1_method;
		}
		config->send_initial_contact = extract_yn("", "initial-contact", wm->initial_contact,
							  /*value_when_unset*/YN_NO,
							  wm, c->logger);
		config->send_vid_cisco_unity = extract_yn("", "cisco-unity", wm->cisco_unity,
							  /*value_when_unset*/YN_NO,
							  wm, c->logger);
		config->send_vid_fake_strongswan = extract_yn("", "fake-strongswan", wm->fake_strongswan,
							      /*value_when_unset*/YN_NO,
							      wm, c->logger);
		config->send_vendorid = extract_yn("", "send-vendorid", wm->send_vendorid,
						   /*value_when_unset*/YN_NO,
						   wm, c->logger);
		if (d != NULL) {
			return d;
		}

		config->send_ca = extract_enum_name("", "sendca", wm->sendca,
						    CA_SEND_ALL,
						    &send_ca_policy_names,
						    wm, &d, c->logger);
		if (d != NULL) {
			return d;
		}

		config->xauthby = extract_sparse("", "xauthby", wm->xauthby,
						 /*value_when_unset*/XAUTHBY_FILE,
						 /*value_when_never_negotiate*/XAUTHBY_FILE,
						 &xauthby_names, wm, c->logger);
		config->xauthfail = extract_sparse("", "xauthfail", wm->xauthfail,
						   /*value_when_unset*/XAUTHFAIL_HARD,
						   /*value_when_never_negotiate*/XAUTHFAIL_HARD,
						   &xauthfail_names, wm, c->logger);

		/* RFC 8784 and draft-ietf-ipsecme-ikev2-qr-alt-04 */
		config->ppk_ids = clone_str(wm->ppk_ids, "connection ppk_ids");
		if (config->ppk_ids != NULL) {
			config->ppk_ids_shunks = ttoshunks(shunk1(config->ppk_ids),
							   ", ",
							   EAT_EMPTY_SHUNKS); /* process into shunks once */
		}
	}

	/*
	 * modecfg/cp
	 */

	config->modecfg.pull = extract_yn("", "modecfgpull", wm->modecfgpull,
					  /*value_when_unset*/YN_NO,
					  wm, c->logger);

	if (can_extract_string("", "modecfgdns", wm->modecfgdns, wm, c->logger)) {
		diag_t d = ttoaddresses_num(shunk1(wm->modecfgdns), ", ",
					    /* IKEv1 doesn't do IPv6 */
					    (wm->ike_version == IKEv1 ? &ipv4_info : NULL),
					    &config->modecfg.dns);
		if (d != NULL) {
			return diag_diag(&d, "modecfgdns=%s invalid: ", wm->modecfgdns);
		}
	}

	if (can_extract_string("", "modecfgdomains", wm->modecfgdomains, wm, c->logger)) {
		config->modecfg.domains = clone_shunk_tokens(shunk1(wm->modecfgdomains),
							     ", ", HERE);
		if (wm->ike_version == IKEv1 &&
		    config->modecfg.domains != NULL &&
		    config->modecfg.domains[1].ptr != NULL) {
			llog(RC_LOG, c->logger,
			     "IKEv1 only uses the first domain in modecfgdomain=%s",
			     wm->modecfgdomains);
			config->modecfg.domains[1] = null_shunk;
		}
	}

	config->modecfg.banner = extract_string("", "modecfgbanner", wm->modecfgbanner,
						wm, c->logger);

	/*
	 * Marks.
	 *
	 * parse mark and mask values form the mark/mask string
	 * acceptable string formats are
	 * ( -1 | <nat> | <hex> ) [ / ( <nat> | <hex> ) ]
	 * examples:
	 *   10
	 *   10/0xffffffff
	 *   0xA/0xFFFFFFFF
	 *
	 * defaults:
	 *  if mark is provided and mask is not mask will default to 0xFFFFFFFF
	 *  if nothing is provided mark and mask are set to 0;
	 *
	 * mark-in= and mark-out= overwrite mark=
	 */

	if (can_extract_string("", "mark", wm->mark, wm, c->logger)) {
		d = mark_parse("", "mark", wm->mark, &c->sa_marks.in);
		if (d != NULL) {
			return d;
		}
		d = mark_parse("", "mark", wm->mark, &c->sa_marks.out);
		if (d != NULL) {
			return d;
		}
	}

	if (can_extract_string("", "mark-in", wm->mark_in, wm, c->logger)) {
		if (wm->mark != NULL) {
			llog(RC_LOG, c->logger, "warning: mark-in=%s overrides mark=%s",
			     wm->mark_in, wm->mark);
		}
		d = mark_parse("", "mark-in", wm->mark_in, &c->sa_marks.in);
		if (d != NULL) {
			return d;
		}
	}

	if (can_extract_string("", "mark-out", wm->mark_out, wm, c->logger)) {
		if (wm->mark != NULL) {
			llog(RC_LOG, c->logger, "warning: mark-out=%s overrides mark=%s",
			     wm->mark_out, wm->mark);
		}
		d = mark_parse("", "mark-out", wm->mark_out, &c->sa_marks.out);
		if (d != NULL) {
			return d;
		}
	}

	/*
	 * ipsec-interface
	 */

	struct ipsec_interface_config ipsec_interface = {0};
	if (can_extract_string("", "ipsec-interface", wm->ipsec_interface, wm, c->logger)) {
		diag_t d;
		d = parse_ipsec_interface(wm->ipsec_interface, &ipsec_interface, c->logger);
		if (d != NULL) {
			return d;
		}
		config->ipsec_interface = ipsec_interface;
	}

	enum yn_options nm_configured = extract_sparse_name("", "nm-configured", wm->nm_configured,
							    /*value_when_unset*/YN_NO,
							    &yn_option_names,
							    wm, &d, c->logger);
	if (d != NULL) {
		return d;
	}
	config->nm_configured = (nm_configured == YN_YES);

#ifdef USE_NFLOG
	c->nflog_group = extract_uintmax("", "nflog-group", wm->nflog_group,
					 /*value_when_unset*/0,
					 1, 65535, wm, &d, c->logger);
	if (d != NULL) {
		return d;
	}
#endif

	if (wm->priority > UINT32_MAX) {
		return diag("priority=%ju exceeds upper bound of %"PRIu32,
			    wm->priority, UINT32_MAX);
	}
	config->child_sa.priority = wm->priority;

	if (wm->tfc != 0) {
		if (encap_mode == ENCAP_MODE_TRANSPORT) {
			return diag("connection with type=transport cannot specify tfc=");
		}
		if (encap_proto == ENCAP_PROTO_AH) {
			return diag("connection with encap_proto=ah cannot specify tfc=");
		}
		if (wm->tfc > UINT32_MAX) {
			return diag("tfc=%ju exceeds upper bound of %"PRIu32,
				    wm->tfc, UINT32_MAX);
		}
		config->child_sa.tfcpad = wm->tfc;
	}

	config->child.send.esp_tfc_padding_not_supported =
		extract_yn("", "send-esp-tfc-padding-not-supported",
			   wm->send_esp_tfc_padding_not_supported,
			   YN_NO, wm, c->logger);

	/*
	 * Since security labels use the same REQID for everything,
	 * pre-assign it.
	 *
	 * HACK; extract_uintmax() returns 0, when there's no reqid.
	 */

	uintmax_t reqid = extract_uintmax("", "reqid", wm->reqid,
					  /*value_when_unset*/0,
					  1, IPSEC_MANUAL_REQID_MAX,
					  wm, &d, c->logger);
	if (d != NULL) {
		return d;
	}

	config->sa_reqid = (reqid != 0 ? reqid :
			    wm->sec_label != NULL ? gen_reqid() :
			    ipsec_interface.enabled ? ipsec_interface_reqid(ipsec_interface.id, c->logger) :
			    /*generated later*/0);

	ldbg(c->logger,
	     "c->sa_reqid="PRI_REQID" because wm->reqid=%s and sec-label=%s",
	     pri_reqid(config->sa_reqid),
	     (wm->reqid != NULL ? wm->reqid : "n/a"),
	     (wm->sec_label != NULL ? wm->sec_label : "n/a"));

	/*
	 * Set both end's sec_label to the same value.
	 */

	if (wm->sec_label != NULL) {
		ldbg(c->logger, "received sec_label '%s' from whack", wm->sec_label);
		if (wm->ike_version == IKEv1) {
			return diag("IKEv1 does not support Labeled IPsec");
		}
		/* include NUL! */
		shunk_t sec_label = shunk2(wm->sec_label, strlen(wm->sec_label)+1);
		err_t ugh = vet_seclabel(sec_label);
		if (ugh != NULL) {
			return diag("%s: policy-label=%s", ugh, wm->sec_label);
		}
		config->sec_label = clone_hunk(sec_label, "struct config sec_label");
	}

	/*
	 * Look for contradictions.
	 */

	if (wm->end[LEFT_END].addresspool != NULL &&
	    wm->end[RIGHT_END].addresspool != NULL) {
		return diag("both leftaddresspool= and rightaddresspool= defined");
	}

	if (wm->end[LEFT_END].modecfgserver == YN_YES &&
	    wm->end[RIGHT_END].modecfgserver == YN_YES) {
		diag_t d = diag("both leftmodecfgserver=yes and rightmodecfgserver=yes defined");
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		llog(RC_LOG, c->logger, "opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}

	if (wm->end[LEFT_END].modecfgclient == YN_YES &&
	    wm->end[RIGHT_END].modecfgclient == YN_YES) {
		diag_t d = diag("both leftmodecfgclient=yes and rightmodecfgclient=yes defined");
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		llog(RC_LOG, c->logger, "opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}

	if (wm->end[LEFT_END].cat == YN_YES && wm->end[RIGHT_END].cat == YN_YES) {
		diag_t d = diag("both leftcat=yes and rightcat=yes defined");
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		llog(RC_LOG, c->logger, "opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}

	if (wm->end[LEFT_END].virt != NULL && wm->end[RIGHT_END].virt != NULL) {
		return diag("both leftvirt= and rightvirt= defined");
	}

	if (is_group_wm(wm) && (wm->end[LEFT_END].virt != NULL ||
				wm->end[RIGHT_END].virt != NULL)) {
		return diag("connection groups do not support virtual subnets");
	}

	FOR_EACH_THING(this, LEFT_END, RIGHT_END) {
		int that = (this + 1) % END_ROOF;
		if (same_ca[that]) {
			config->end[that].host.ca = clone_hunk(config->end[this].host.ca,
							       "same ca");
			break;
		}
	}

	/*
	 * Connections can't be both client and server right?
	 *
	 * Unfortunately, no!
	 *
	 * OE configurations have configurations such as
	 * leftmodecfgclient=yes rightaddresspool= and
	 * leftmodeconfigclient=yes leftmodeconfigserver=yes which
	 * create a connection that is both a client and a server.
	 */

	if (config->end[LEFT_END].host.modecfg.server &&
	    config->end[RIGHT_END].host.modecfg.server) {
		diag_t d = diag("both left and right are configured as a server");
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		llog(RC_LOG, c->logger, "opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}

	if (config->end[LEFT_END].host.modecfg.client &&
	    config->end[RIGHT_END].host.modecfg.client) {
		diag_t d = diag("both left and right are configured as a client");
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		llog(RC_LOG, c->logger, "opportunistic: %s", str_diag(d));
		pfree_diag(&d);
	}

	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		update_hosts_from_end_host_addr(c, end, host_addr[end], HERE); /* from add */
	}

	/*
	 * Cross-check the auth= vs authby= results.
	 */

	if (never_negotiate(c)) {
		if (!PEXPECT(c->logger,
			     c->local->host.config->auth == AUTH_NEVER &&
			     c->remote->host.config->auth == AUTH_NEVER)) {
			return diag("internal error");
		}
	} else {
		if (c->local->host.config->auth == AUTH_UNSET ||
		    c->remote->host.config->auth == AUTH_UNSET) {
			/*
			 * Since an unset auth is set from authby,
			 * authby= must have somehow been blanked out
			 * or left with something useless (such as
			 * never).
			 */
			return diag("no authentication (auth=, authby=) was set");
		}

		if ((c->local->host.config->auth == AUTH_PSK && c->remote->host.config->auth == AUTH_NULL) ||
		    (c->local->host.config->auth == AUTH_NULL && c->remote->host.config->auth == AUTH_PSK)) {
			enum_buf lab, rab;
			return diag("cannot mix PSK and NULL authentication (%sauth=%s and %sauth=%s)",
				    c->local->config->leftright,
				    str_enum(&keyword_auth_names, c->local->host.config->auth, &lab),
				    c->remote->config->leftright,
				    str_enum(&keyword_auth_names, c->remote->host.config->auth, &rab));
		}
	}

	/*
	 * For templates; start the instance counter.  Each time the
	 * connection is instantiated this is updated; ditto for
	 * instantiated instantiations such as is_labeled_child().
	 */
	c->instance_serial = 0;
	c->next_instance_serial = (is_template(c) ? 1 : 0);

	/* set internal fields */
	c->iface = NULL; /* initializing */

	c->redirect.attempt = 0;

	/* non configurable */
	config->ike_window = IKE_V2_OVERLAPPING_WINDOW_SIZE;

	/*
	 * We cannot have unlimited keyingtries for Opportunistic, or
	 * else we gain infinite partial IKE SA's. But also, more than
	 * one makes no sense, since it will be installing a
	 * failureshunt (not negotiationshunt) on the 2nd keyingtry,
	 * and try to re-install another negotiation or failure shunt.
	 */
	if (wm->keyingtries.set) {
		if (never_negotiate_wm(wm)) {
			llog(RC_LOG, c->logger,
			     "warning: keyingtries=%ju ignored, connection will never negotiate",
			     wm->keyingtries.value);
		} else if (is_opportunistic_wm(wm) &&
			   wm->keyingtries.value != 1) {
			llog(RC_LOG, c->logger,
			     "warning: keyingtries=%ju ignored, Opportunistic connections do not retry",
			     wm->keyingtries.value);
		} else {
			llog(RC_LOG, c->logger,
			     "warning: keyingtries=%ju ignored, UP connection will attempt to establish until marked DOWN",
			     wm->keyingtries.value);
		}
	}

	/*
	 * Extract the child configuration and save it.
	 */

	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		d = extract_child_end_config(wm, whack_ends[end],
					     c, &config->end[end].child,
					     c->logger);
		if (d != NULL) {
			return d;
		}
	}

	/*
	 * Now cross check the configuration looking for IP version
	 * conflicts.
	 *
	 * First build a table of the IP address families that each
	 * end's child is using and then cross check it with the other
	 * end.  Either both ends use a AFI or both don't.
	 */

	struct end_family {
		bool used;
		const char *field;
		const char *value;
	} end_family[END_ROOF][IP_INDEX_ROOF] = {0};
	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		const ip_selectors *const selectors = &c->end[end].config->child.selectors;
		const ip_ranges *const pools = &c->end[end].config->child.addresspools;
		if (selectors->len > 0) {
			FOR_EACH_ITEM(selector, selectors) {
				const struct ip_info *afi = selector_type(selector);
				struct end_family *family = &end_family[end][afi->ip_index];
				if (!family->used) {
					family->used = true;
					family->field = "subnet";
					family->value = whack_ends[end]->subnet;
				}
			}
		} else if (pools->len > 0) {
			FOR_EACH_ITEM(range, pools) {
				const struct ip_info *afi = range_type(range);
				/* only one for now */
				struct end_family *family = &end_family[end][afi->ip_index];
				passert(family->used == false);
				family->used = true;
				family->field = "addresspool";
				family->value = whack_ends[end]->addresspool;
			}
		} else {
			struct end_family *family = &end_family[end][host_afi->ip_index];
			family->used = true;
			family->field = "";
			family->value = whack_ends[end]->host_addr_name;
		}
	}

	/* legacy; check against clientaddrfamily */
	if (wm->child_afi != NULL) {
		/* is other ip version being used? */
		enum ip_index j = (wm->child_afi == &ipv4_info ? IPv6_INDEX :
				   IPv4_INDEX);
		FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
			if (end_family[end][j].used) {
				return diag("\"childaddrfamily=%s\" conflicts with \"%s%s=%s\"",
					    wm->child_afi->ip_name,
					    config->end[end].leftright,
					    end_family[end][j].field,
					    end_family[end][j].value);
			}
		}
	}

	/* now check there's a match */
	FOR_EACH_ELEMENT(afi, ip_families) {
		enum ip_index i = afi->ip_index;

		/* both ends do; or both ends don't */
		if (end_family[LEFT_END][i].used == end_family[RIGHT_END][i].used) {
			continue;
		}
		/*
		 * Flip the AFI for RIGHT.  Presumably it being
		 * non-zero is the reason for the conflict?
		 */
		enum ip_index j = (i == IPv4_INDEX ? IPv6_INDEX : IPv4_INDEX);
		if (end_family[LEFT_END][i].used) {
			/* oops, no winner */
			pexpect(end_family[RIGHT_END][j].used);
		} else {
			swap(i, j);
			pexpect(end_family[LEFT_END][i].used);
			pexpect(end_family[RIGHT_END][j].used);
		}
		/*
		 * Both ends used child AFIs.
		 *
		 * Since no permutation was valid one end must
		 * be pure IPv4 and the other end pure IPv6
		 * say.
		 *
		 * Use the first list entry to get the AFI.
		 */
		return diag("address family of left%s=%s conflicts with right%s=%s",
			    end_family[LEFT_END][i].field,
			    end_family[LEFT_END][i].value,
			    end_family[RIGHT_END][j].field,
			    end_family[RIGHT_END][j].value);
	}

	/*
	 * Is spd.reqid necessary for all c?  CK_INSTANCE or
	 * CK_PERMANENT need one.  Does CK_TEMPLATE need one?
	 */
	c->child.reqid = child_reqid(c->config, c->logger);

	/*
	 * Fill in the child's selector proposals from the config.  It
	 * might use subnet or host or addresspool.
	 */

	VERBOSE_DBGP(DBG_BASE, c->logger, "%s() ...", __func__);
	build_connection_proposals_from_configs(c, host_afi, verbose);

	/*
	 * All done, enter it into the databases.  Since orient() may
	 * switch ends, triggering an spd rehash, insert things into
	 * the database first.
	 */
	connection_db_add(c);

	/*
	 * Force orientation (currently kind of unoriented?).
	 *
	 * If the connection orients,the SPDs and host-pair hash
	 * tables are updated.
	 *
	 * This function holds the just allocated reference.
	 */
	PASSERT(c->logger, !oriented(c));
	orient(c, c->logger);

	return NULL;
}

diag_t add_connection(const struct whack_message *wm, struct logger *logger)
{
	/* will inherit defaults */
	lset_t debugging = lmod(LEMPTY, wm->debugging);

	/*
	 * Allocate the configuration - only allocated on root
	 * connection; connection instances (clones) inherit these
	 * pointers.
	 */
	struct config *root_config = alloc_config(wm->ike_version);
	struct connection *c = alloc_connection(wm->name, NULL, root_config,
						debugging | wm->conn_debug,
						logger, HERE);
	c->root_config = root_config;

	diag_t d = extract_connection(wm, c, root_config);
	if (d != NULL) {
		struct connection *cp = c;
		PASSERT(c->logger, delref_where(&cp, c->logger, HERE) == c);
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
	     c->config->child_sa.replay_window,
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
			if (pexpect(selector->is_set)) {
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
	s += jam_connection_short(buf, c);
	if (c->instance_serial > 0) {
		s += jam_connection_suffix(buf, c);
	}
	return s;
}

size_t jam_connection_short(struct jambuf *buf, const struct connection *c)
{
	return jam_string(buf, c->prefix);
}

const char *str_connection_short(const struct connection *c)
{
	return c->prefix;
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

	switch (c->config->child_sa.encap_proto) {
	case ENCAP_PROTO_ESP:
		CS("ENCRYPT");
		break;
	case ENCAP_PROTO_AH:
		CS("AUTHENTICATE");
		break;
	default:
		break;
	}

	CT(child_sa.ipcomp, COMPRESS);
	if (!never_negotiate(c) &&
	    c->config->child_sa.encap_mode != ENCAP_MODE_UNSET) {
		enum_buf eb;
		CS(str_enum_short(&encap_mode_names, c->config->child_sa.encap_mode, &eb));
	}
	CT(child_sa.pfs, PFS);
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

	CT(reauth, REAUTH);

	CNN(is_opportunistic(c), OPPORTUNISTIC);
	CNN(is_group_instance(c), GROUPINSTANCE);
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
			connection_buf cb;
			ldbg(logger, "    skipping "PRI_CONNECTION"; not oriented",
			     pri_connection(c, &cb));
			continue;
		}

		if (is_group(c)) {
			connection_buf cb;
			ldbg(logger, "    skipping "PRI_CONNECTION"; a food group",
			     pri_connection(c, &cb));
			continue;
		}

		/*
		 * Don't try to mix 'n' match acquire sec_label with
		 * non-sec_label connections.
		 */
		if (sec_label.len == 0 && is_labeled(c)) {
			connection_buf cb;
			ldbg(logger, "    skipping "PRI_CONNECTION"; has unwanted label",
			     pri_connection(c, &cb));
			continue;
		}
		if (sec_label.len > 0 && !is_labeled(c)) {
			connection_buf cb;
			ldbg(logger, "    skipping "PRI_CONNECTION"; doesn't have label",
			     pri_connection(c, &cb));
			continue;
		}

		/*
		 * Labeled IPsec, always start with the either the
		 * template or the parent - assume the kernel won't
		 * send a duplicate child request.
		 */
		if (is_labeled_child(c)) {
			connection_buf cb;
			ldbg(logger, "    skipping "PRI_CONNECTION"; IKEv2 sec_label connection is a child",
			     pri_connection(c, &cb));
			continue;
		}

		/*
		 * When there is a sec_label, it needs to be within
		 * the configuration's range.
		 */
		if (sec_label.len > 0 /*implies c->config->sec_label > 0 */ &&
		    !sec_label_within_range("acquire", sec_label,
					    c->config->sec_label, logger)) {
			connection_buf cb;
			ldbg(logger, "    skipping "PRI_CONNECTION"; packet sec_label="PRI_SHUNK" not within connection sec_label="PRI_SHUNK,
			     pri_connection(c, &cb), pri_shunk(sec_label),
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
			 pexpect(c->clonedfrom != NULL) /* because instance */ &&
			 kernel_route_installed(c->clonedfrom));
		if (!kernel_route_installed(c) &&
		    !instance_initiation_ok &&
		    c->config->sec_label.len == 0) {
			connection_buf cb;
			ldbg(logger, "    skipping "PRI_CONNECTION"; !routed,!instance_initiation_ok,!sec_label",
			     pri_connection(c, &cb));
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
			connection_buf cb, bcb;
			ldbg(logger,
			     "    skipping "PRI_CONNECTION" priority %"PRIu32"; doesn't best "PRI_CONNECTION" priority %"PRIu32,
			     pri_connection(c, &cb),
			     priority,
			     pri_connection(best_connection, &bcb),
			     best_priority);
			continue;
		}

		/* current is best; log why */
		if (best_connection == NULL) {
			connection_buf cb;
			ldbg(logger,
			     "    choosing "PRI_CONNECTION" priority %"PRIu32"; as first best",
			     pri_connection(c, &cb),
			     priority);
		} else {
			connection_buf cb, bcb;
			ldbg(logger,
			     "    choosing "PRI_CONNECTION" priority %"PRIu32"; as bests "PRI_CONNECTION" priority %"PRIu32,
			     pri_connection(c, &cb),
			     priority,
			     pri_connection(best_connection, &bcb),
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
		connection_buf cb;
		ldbg(logger, "  concluding with empty; best connection "PRI_CONNECTION" was NEVER_NEGOTIATE",
		     pri_connection(best_connection, &cb));
		return NULL;
	}

	connection_buf cib;
	enum_buf kb;
	dbg("  concluding with "PRI_CONNECTION" priority %" PRIu32 " kind=%s",
	    pri_connection(best_connection, &cib),
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

	ret = strcmp(cl->name, cr->name);
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
	if (sourceip.is_set) {
		return sourceip;
	}

	/*
	 * Failing that see if CP is involved.  IKEv1 always leaves
	 * client_address_translation false.
	 */
	const struct ip_info *afi = selector_info(spde->client);
	if (afi != NULL &&
	    spde->child->lease[afi->ip_index].is_set &&
	    !spde->child->config->has_client_address_translation) {
		/* XXX: same as .lease[]? */
		ip_address a = selector_prefix(spde->client);
		pexpect(address_eq_address(a, spde->child->lease[afi->ip_index]));
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
		dbg("picked established_ike_sa #%lu for #%lu",
		    newest, st->st_serialno);
	} else {
		newest = c->established_child_sa;
		dbg("picked established_child_sa #%lu for #%lu",
		    newest, st->st_serialno);
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
			 const struct logger *logger, where_t where)
{
	/* space? */
	PASSERT_WHERE(logger, where, end->child.selectors.proposed.len < elemsof(end->child.selectors.assigned));

	/*
	 * Ensure proposed is pointing at assigned aka scratch.
	 */
	if (end->child.selectors.proposed.list == NULL) {
		PASSERT_WHERE(logger, where, end->child.selectors.proposed.len == 0);
		end->child.selectors.proposed.list = end->child.selectors.assigned;
	} else {
		PASSERT_WHERE(logger, where, end->child.selectors.proposed.len > 0);
		PASSERT_WHERE(logger, where, end->child.selectors.proposed.list == end->child.selectors.assigned);
	}

	/* append the selector to assigned */
	unsigned i = end->child.selectors.proposed.len++;
	end->child.selectors.assigned[i] = selector;

	selector_buf nb;
	ldbg(logger, "%s() %s.child.selectors.proposed[%d] %s "PRI_WHERE,
	     __func__,
	     end->config->leftright,
	     i, str_selector(&selector, &nb),
	     pri_where(where));
}

void update_end_selector_where(struct connection *c, enum end lr,
			       ip_selector new_selector,
			       const char *excuse, where_t where)
{
	struct connection_end *end = &c->end[lr];
	struct child_end *child = &end->child;
	struct child_end_selectors *end_selectors = &end->child.selectors;
	const char *leftright = end->config->leftright;

	PEXPECT_WHERE(c->logger, where, end_selectors->proposed.len == 1);
	ip_selector old_selector = end_selectors->proposed.list[0];
	selector_buf ob, nb;
	ldbg(c->logger, "%s() update %s.child.selector %s -> %s "PRI_WHERE,
	     __func__, leftright,
	     str_selector(&old_selector, &ob),
	     str_selector(&new_selector, &nb),
	     pri_where(where));

	/*
	 * Point the selectors list at and UPDATE the scratch value.
	 *
	 * Is the assumption that this is only applied when there is a
	 * single selector.  Reasonable?  Certainly don't want to
	 * truncate the selector list.
	 */
	zero(&end->child.selectors.proposed);
	append_end_selector(end, new_selector, c->logger, where);

	/*
	 * If needed, also update the SPD.  It's assumed for this code
	 * path there is only one (just like there is only one
	 * selector).
	 */
	if (c->child.spds.len == 1) {
		ip_selector old_client = c->child.spds.list->end[lr].client;
		if (!selector_eq_selector(old_selector, old_client)) {
			selector_buf sb, cb;
			llog_pexpect(c->logger, where,
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
			ldbg(c->logger,
			     "%s() %s.child.selector %s matches selectors[0] "PRI_WHERE,
			     __func__, leftright,
			     str_selector(&new_selector, &sb),
			     pri_where(where));
		} else if (excuse != NULL) {
			selector_buf sb, cb;
			ldbg(c->logger,
			     "%s() %s.child.selector %s does not match %s.selectors[0] %s but %s "PRI_WHERE,
			     __func__, leftright, str_selector(&new_selector, &sb),
			     leftright, str_selector(&selector, &cb),
			     excuse, pri_where(where));
		} else {
			selector_buf sb, cb;
			llog_pexpect(c->logger, where,
				     "%s() %s.child.selector %s does not match %s.selectors[0] %s",
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

bool is_group_instance(const struct connection *c)
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
	if (c->config->child_sa.encap_proto == ENCAP_PROTO_ESP ||
	    c->config->child_sa.encap_proto == ENCAP_PROTO_AH) {
		return (struct child_policy) {
			.is_set = true,
			.transport = (c->config->child_sa.encap_mode == ENCAP_MODE_TRANSPORT),
			.compress = c->config->child_sa.ipcomp,
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

reqid_t child_reqid(const struct config *config, struct logger *logger)
{
	reqid_t reqid = (config->sa_reqid != 0 ? config->sa_reqid :
			 gen_reqid());
	ldbg(logger, "child.reqid="PRI_REQID" because c->sa_reqid="PRI_REQID" (%s)",
	     pri_reqid(reqid),
	     pri_reqid(config->sa_reqid),
	     (config->sa_reqid == 0 ? "generate" : "use"));
	return reqid;
}
