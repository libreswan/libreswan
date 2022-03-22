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

#include "defs.h"
#include "connections.h" /* needs id.h */
#include "connection_db.h"
#include "pending.h"
#include "foodgroups.h"
#include "packet.h"
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
#include "host_pair.h"
#include "lswfips.h"
#include "crypto.h"
#include "kernel_xfrm.h"
#include "ip_address.h"
#include "ip_info.h"
#include "keyhi.h" /* for SECKEY_DestroyPublicKey */
#include "state_db.h"		/* for rehash_state_connection */
# include "kernel_xfrm_interface.h"
#include "iface.h"
#include "ip_selector.h"
#include "labeled_ipsec.h"		/* for vet_seclabel() */
#include "orient.h"
#include "ikev2_proposals.h"
#include "lswnss.h"

#define MINIMUM_IPSEC_SA_RANDOM_MARK 65536
static uint32_t global_marks = MINIMUM_IPSEC_SA_RANDOM_MARK;

static void hash_connection(struct connection *c)
{
	add_db_connection(c);
	passert(c->spd.spd_next == NULL);
	add_db_spd_route(&c->spd);
}

/*
 * Find a connection by name.
 *
 * no_inst: don't accept a CK_INSTANCE.
 */

struct connection *conn_by_name(const char *nm, bool no_inst)
{
	dbg("FOR_EACH_CONNECTION_... in %s", __func__);
	struct connection_filter cq = {
		.name = nm,
		.where = HERE,
	};
	while (next_connection_new2old(&cq)) {
		struct connection *c = cq.c;
		if (no_inst && c->kind == CK_INSTANCE) {
			continue;
		}
		return c;
	}
	return NULL;
}

void release_connection(struct connection *c)
{
	pexpect(c->kind != CK_INSTANCE);
	flush_pending_by_connection(c);
	delete_states_by_connection(&c);
	passert(c != NULL);
	unroute_connection(c);
}

/* Delete a connection */
static void delete_end(struct end *e)
{
	free_chunk_content(&e->sec_label);
	virtual_ip_delref(&e->virt, HERE);
}

static void delete_spd_route(struct spd_route **sr, bool first, bool valid)
{
	del_db_spd_route(*sr, valid);
	delete_end(&(*sr)->this);
	delete_end(&(*sr)->that);
	if (!first) {
		pfreeany(*sr);
	}
}

/*
 * delete_connection -- removes a connection by pointer
 *
 * @c - the connection pointer
 * @relations - whether to delete any instances as well.
 * @connection_valid - apply sanity checks
 *
 */

static void discard_connection(struct connection **cp, bool connection_valid);

void delete_connection(struct connection **cp)
{
	struct connection *c = *cp;
	*cp = NULL;

	/*
	 * Must be careful to avoid circularity:
	 * we mark c as going away so it won't get deleted recursively.
	 */
	passert(c->kind != CK_GOING_AWAY);
	if (c->kind == CK_INSTANCE) {
		if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
			address_buf b;
			llog(RC_LOG, c->logger,
			     "deleting connection instance with peer %s {isakmp=#%lu/ipsec=#%lu}",
			     str_address_sensitive(&c->remote->host.addr, &b),
			     c->newest_ike_sa, c->newest_ipsec_sa);
		}
		c->kind = CK_GOING_AWAY;
		if (c->pool != NULL) {
			free_that_address_lease(c);
		}
	}
	release_connection(c);
	discard_connection(&c, true/*connection_valid*/);
}

static void discard_connection(struct connection **cp, bool connection_valid)
{
	struct connection *c = *cp;
	*cp = NULL;

	if (c->kind == CK_GROUP)
		delete_group(c);

	if (c->pool != NULL)
		unreference_addresspool(c);

	if (IS_XFRMI && c->xfrmi != NULL)
		unreference_xfrmi(c);

	/* find and delete c from the host pair list */
	host_pair_remove_connection(c, connection_valid);

	flush_revival(c);

	del_db_connection(c, connection_valid);

	passert(c->spd.this.virt == NULL);
	for (struct spd_route *sr = &c->spd, *next = NULL; sr != NULL; sr = next) {
		next = sr->spd_next;

		delete_spd_route(&sr, /*first?*/sr == &c->spd, connection_valid);
	}

	FOR_EACH_ELEMENT(c->end, end) {
		free_id_content(&end->host.id);
	}

	/*
	 * Logging no longer valid.  Can this be delayed further?
	 */
#if 0
	struct logger *connection_logger = clone_logger(c->logger, HERE);
#endif
	free_logger(&c->logger, HERE);

	pfreeany(c->foodgroup);
	pfreeany(c->connalias);
	pfreeany(c->vti_iface);
	pfreeany(c->modecfg_dns);
	pfreeany(c->modecfg_domains);
	pfreeany(c->modecfg_banner);
	pfreeany(c->dnshostname);
	pfreeany(c->redirect_to);
	pfreeany(c->accept_redirect_to);
	iface_endpoint_delref(&c->interface);

	struct config *config = c->root_config;
	if (config != NULL) {
		passert(co_serial_is_unset(c->serial_from));
		free_chunk_content(&config->sec_label);
		free_proposals(&config->ike_proposals.p);
		free_proposals(&config->child_proposals.p);
		free_ikev2_proposals(&config->v2_ike_proposals);
		free_ikev2_proposals(&config->v2_ike_auth_child_proposals);
		FOR_EACH_ELEMENT(config->end, end) {
			pfreeany(end->client.updown);
			if (end->host.cert.nss_cert != NULL) {
				CERT_DestroyCertificate(end->host.cert.nss_cert);
			}
			free_chunk_content(&end->host.ca);
			pfreeany(end->host.ckaid);
			pfreeany(end->host.xauth.username);
			pfreeany(end->host.addr_name);
		}
		pfree(c->root_config);
	}

	/* connection's final gasp; need's c->name */
	dbg_free(c->name, c, HERE);
	pfreeany(c->name);
	pfree(c);
}

int foreach_connection_by_alias(const char *alias,
				int (*f)(struct connection *c,
					 void *arg, struct logger *logger),
				void *arg, struct logger *logger)
{
	int count = 0;

	struct connection_filter cq = { .where = HERE, };
	while (next_connection_new2old(&cq)) {
		struct connection *p = cq.c;

		if (lsw_alias_cmp(alias, p->connalias))
			count += (*f)(p, arg, logger);
	}
	return count;
}

/*
 * return -1 if nothing was found at all; else total from f()
 */

int foreach_concrete_connection_by_name(const char *name,
					int (*f)(struct connection *c,
						 void *arg, struct logger *logger),
					void *arg, struct logger *logger)
{
	/*
	 * Find the first non-CK_INSTANCE connection matching NAME;
	 * that is CK_GROUP, CK_TEMPLATE, CK_PERMENANT, CK_GOING_AWAY.
	 *
	 * If this search succeeds, then the function also succeeds.
	 *
	 * But here's the kicker:
	 *
	 * The original conn_by_name() call also moved the connection
	 * to the front of the connections list.  For CK_GROUP and
	 * CK_TEMPLATE this put any CK_INSTANCES after it in the list
	 * so continuing the search would find them (without this the
	 * list is new-to-old so instances would have been skipped).
	 *
	 * This code achieves the same effect by searching old2new.
	 */
	struct connection_filter cq = {
		.name = name,
		.where = HERE,
	};
	bool found = false;
	while (next_connection_old2new(&cq)) {
		struct connection *c = cq.c;
		if (c->kind == CK_INSTANCE) {
			continue;
		}
		found = true;
		break;
	}
	if (!found) {
		/* nothing matched at all */
		return -1;
	}
	/*
	 * Now continue with the connection list looking for
	 * CK_PERMENANT and/or CK_INSTANCE connections with the name.
	 */
	int total = 0;
	do {
		struct connection *c = cq.c;
		if (c->kind >= CK_PERMANENT &&
		    !NEVER_NEGOTIATE(c->policy) &&
		    streq(c->name, name)) {
			total += f(c, arg, logger);
		}
	} while (next_connection_old2new(&cq));
	return total;
}

static int delete_connection_wrap(struct connection *c, void *arg UNUSED, struct logger *logger)
{
	/* XXX: something better? */
	fd_delref(&c->logger->global_whackfd);
	c->logger->global_whackfd = fd_addref(logger->global_whackfd); /* freed by discard_conection() */

	delete_connection(&c);
	return 1;
}

/* Delete connections with the specified name */
void delete_connections_by_name(const char *name, bool strict, struct logger *logger)
{
	passert(name != NULL);
	struct connection *c = conn_by_name(name, strict);
	if (c != NULL) {
		do {
			/* XXX: something better? */
			delete_connection_wrap(c, NULL, logger);
			c = conn_by_name(name, false/*!strict*/);
		} while (c != NULL);
	} else {
		foreach_connection_by_alias(name, delete_connection_wrap, NULL, logger);
	}
}

void delete_every_connection(void)
{
	struct connection_filter cq = { .where = HERE, };
	/* Delete instances before templates. */
	while (next_connection_new2old(&cq)) {
		struct connection *c = cq.c;
		delete_connection(&c);
	}
}

ip_port end_host_port(const struct end *end, const struct end *other)
{
	unsigned port;
	if (end->config->host.ikeport != 0) {
		/*
		 * The END's IKEPORT was specified in the config file.
		 * Use that.
		 */
		port = end->config->host.ikeport;
	} else if (other->config->host.ikeport != 0) {
		/*
		 * The other end's IKEPORT was specified in the config
		 * file.  Since specifying an IKEPORT implies ESP
		 * encapsulation (i.e. IKE packets must include the
		 * ESP=0 prefix), send packets from the encapsulating
		 * NAT_IKE_UDP_PORT.
		 */
		port = NAT_IKE_UDP_PORT;
	} else if (other->host->encap) {
		/*
		 * See above.  Presumably an instance which previously
		 * had a natted port and is being revived.
		 */
		port = NAT_IKE_UDP_PORT;
	} else {
		port = IKE_UDP_PORT;
	}
	return ip_hport(port);
}

void update_ends_from_this_host_addr(struct end *this, struct end *that)
{
	address_buf hab;
	dbg("updating ends from %s.host_addr %s",
	    this->config->leftright, str_address(&this->host->addr, &hab));

	if (!address_is_specified(this->host->addr)) {
		dbg("  %s.host_addr's is unspecified (unset, ::, or 0.0.0.0); skipping",
		    this->config->leftright);
		return;
	}

	const struct ip_info *afi = address_type(&this->host->addr);
	passert(afi != NULL); /* since specified */

	/*
	 * Default ID to IP (but only if not NO_IP -- WildCard).
	 */
	if (this->host->id.kind == ID_NONE) {
		struct id id = {
			.kind = afi->id_ip_addr,
			.ip_addr = this->host->addr,
		};
		id_buf old, new;
		dbg("  updated %s.id from %s to %s",
		    this->config->leftright,
		    str_id(&this->host->id, &old),
		    str_id(&id, &new));
		this->host->id = id;
	}

	/*
	 * If THAT has an IKEPORT (which means messages are ESP=0
	 * prefixed), then THIS must send from either IKEPORT or the
	 * NAT port (and also ESP=0 prefix messages).
	 */
	unsigned host_port = hport(end_host_port(this, that));
	dbg("  updated %s.host_port from %u to %u",
	    this->config->leftright,
	    this->host->port, host_port);
	this->host->port = host_port;

	/*
	 * Default client to subnet containing only self.
	 *
	 * XXX: This gets OPPO wrong when instantiating a template
	 * that has proto/port: it scribbles on the proto/port stored
	 * in the .client field.  oppo_instantiate() fixes this up
	 * after instantiate() returns.
	 */
	if (!this->has_client) {
		/*
		 * Default client to a subnet containing only self.
		 *
		 * For instance, the config file omitted subnet, but
		 * specified protoport; merge that.
		 */
		ip_selector client = selector_from_address_protoport(this->host->addr,
								     this->config->client.protoport);
		selector_buf old, new;
		dbg("  updated %s.client from %s to %s",
		    this->config->leftright,
		    str_selector_subnet_port(&this->client, &old),
		    str_selector_subnet_port(&client, &new));
		this->client = client;
	}

	/*
	 * Propagate this.HOST_ADDR to that.NEXTHOP.
	 * As in: THAT -> that.NEXTHOP -> THIS.
	 */
	if (!address_is_specified(that->host->nexthop)) {
		address_buf old, new;
		dbg("  updated %s.host_nexthop from %s to %s",
		    that->config->leftright,
		    str_address(&that->host->nexthop, &old),
		    str_address(&this->host->addr, &new));
		that->host->nexthop = this->host->addr;
	}

	/*
	 * Propagate this.HOST_ADDR's address family to
	 * that.HOST_ADDR.
	 */
	if (!address_is_specified(that->host->addr)) {
		address_buf old, new;
		dbg("  updated %s.host_addr from %s to %s",
		    that->config->leftright,
		    str_address(&that->host->addr, &old),
		    str_address(&afi->address.unspec, &new));
		that->host->addr = afi->address.unspec;
	}
}

/*
 * Format the topology of a connection end, leaving out defaults.
 * Used to construct strings of the form:
 *
 *      [this]LOCAL_END ...END_REMOTE[that]
 *
 * where END_REMOTE is roughly formatted as the mirror image of
 * LOCAL_END.  LEFT_RIGHT is used to determine if the LHS or RHS
 * string is being emitted (however, note that the LHS here is _not_
 * the configuration file's left*=).
 *
 * LOCAL_END's longest string is:
 *
 *    client === host : port [ host_id ] --- HOP
 *
 * Note: if that == NULL, skip nexthop Returns strlen of formatted
 * result (length excludes NUL at end).
 */

static void jam_end_host(struct jambuf *buf, const struct end *this, lset_t policy)
{
	/* HOST */
	if (!address_is_specified(this->host->addr)) {
		if (this->config->host.type == KH_IPHOSTNAME) {
			jam_string(buf, "%dns");
			jam(buf, "<%s>", this->config->host.addr_name);
		} else {
			switch (policy & (POLICY_GROUP | POLICY_OPPORTUNISTIC)) {
			case POLICY_GROUP:
				jam_string(buf, "%group");
				break;
			case POLICY_OPPORTUNISTIC:
				jam_string(buf, "%opportunistic");
				break;
			case POLICY_GROUP | POLICY_OPPORTUNISTIC:
				jam_string(buf, "%opportunisticgroup");
				break;
			default:
				jam_string(buf, "%any");
				break;
			}
		}
		/*
		 * XXX: only print anomalies: since the host address
		 * is zero, so too should be the port.
		 */
		if (this->host->port != 0) {
			jam(buf, ":%u", this->host->port);
		}
	} else if (is_virtual_end(this)) {
		jam_string(buf, "%virtual");
		/*
		 * XXX: only print anomalies: the host is %virtual
		 * (what ever that means), so too should be the port.
		 */
		if (this->host->port != 0) {
			jam(buf, ":%u", this->host->port);
		}
	} else {
		/* ADDRESS[:PORT][<HOSTNAME>] */
		/*
		 * XXX: only print anomalies: when the host address is
		 * valid, any hardwired IKEPORT or a port other than
		 * IKE_UDP_PORT.
		 */
		bool include_port = (this->config->host.ikeport != 0 ||
				     this->host->port != IKE_UDP_PORT);
		if (!log_ip) {
			/* ADDRESS(SENSITIVE) */
			jam_string(buf, "<address>");
		} else if (include_port) {
			/* ADDRESS:PORT */
			const struct ip_info *afi = address_type(&this->host->addr);
			/* XXX: jam_address_wrapped()? */
			afi->address.jam_wrapped(buf, afi, &this->host->addr.bytes);
			jam(buf, ":%u", this->host->port);
		} else {
			/* ADDRESS */
			jam_address(buf, &this->host->addr);
		}
		/* [<HOSTNAME>] */
		address_buf ab;
		if (this->config->host.addr_name != NULL &&
		    !streq(str_address(&this->host->addr, &ab),
			   this->config->host.addr_name)) {
			jam(buf, "<%s>", this->config->host.addr_name);
		}
	}
}

static void jam_end_client(struct jambuf *buf, const struct end *this,
			   lset_t policy, enum left_right left_right)
{
	/* left: [CLIENT/PROTOCOL:PORT===] or right: [===CLIENT/PROTOCOL:PORT] */

	if (!this->client.is_set) {
		return;
	}

	if (selector_eq_address(this->client, this->host->addr)) {
		return;
	}

	if (selector_is_all(this->client) &&
	    (policy & (POLICY_GROUP | POLICY_OPPORTUNISTIC))) {
		/* booring */
		return;
	}

	if (left_right == RIGHT_END) {
		jam_string(buf, "===");
	}

	if (is_virtual_end(this)) {
		if (is_virtual_vhost(this))
			jam_string(buf, "vhost:?");
		else
			jam_string(buf,  "vnet:?");
	} else {
		jam_selector(buf, &this->client);
		if (selector_is_zero(this->client)) {
			jam_string(buf, "?");
		}
	}

	if (left_right == LEFT_END) {
		jam_string(buf, "===");
	}
}

static void jam_end_id(struct jambuf *buf, const struct end *this)
{
	/* id, if different from host */
	bool open_paren = false;
	if (!(this->host->id.kind == ID_NONE ||
	      (id_is_ipaddr(&this->host->id) &&
	       sameaddr(&this->host->id.ip_addr, &this->host->addr)))) {
		open_paren = true;
		jam_string(buf, "[");
		jam_id_bytes(buf, &this->host->id, jam_sanitized_bytes);
	}

	if (this->modecfg_server ||
	    this->modecfg_client ||
	    this->config->host.xauth.server ||
	    this->config->host.xauth.client ||
	    this->config->host.sendcert != cert_defaultcertpolicy) {

		if (open_paren) {
			jam_string(buf, ",");
		} else {
			open_paren = true;
			jam_string(buf, "[");
		}

		if (this->modecfg_server)
			jam_string(buf, "MS");
		if (this->modecfg_client)
			jam_string(buf, "+MC");
		if (this->cat)
			jam_string(buf, "+CAT");
		if (this->config->host.xauth.server)
			jam_string(buf, "+XS");
		if (this->config->host.xauth.client)
			jam_string(buf, "+XC");

		switch (this->config->host.sendcert) {
		case CERT_NEVERSEND:
			jam(buf, "+S-C");
			break;
		case CERT_SENDIFASKED:
			jam(buf, "+S?C");
			break;
		case CERT_ALWAYSSEND:
			jam(buf, "+S=C");
			break;
		default:
			jam(buf, "+UNKNOWN");
		}
	}

	if (open_paren) {
		jam_string(buf, "]");
	}
}

static void jam_end_nexthop(struct jambuf *buf, const struct end *this,
			    const struct end *that, bool skip_next_hop,
			    enum left_right left_right)
{
	/* [---hop] */
	if (!skip_next_hop &&
	    address_is_specified(this->host->nexthop) &&
	    !address_eq_address(this->host->nexthop, that->host->addr)) {
		if (left_right == LEFT_END) {
			jam_string(buf, "---");
		}
		jam_address(buf, &this->host->nexthop);
		if (left_right == RIGHT_END) {
			jam_string(buf, "---");
		}
	}
}

void jam_end(struct jambuf *buf, const struct end *this, const struct end *that,
	     enum left_right left_right, lset_t policy, bool skip_next_hop)
{
	switch (left_right) {
	case LEFT_END:
		/* CLIENT/PROTOCOL:PORT=== */
		jam_end_client(buf, this, policy, left_right);
		/* HOST */
		jam_end_host(buf, this, policy);
		/* [ID+OPTS] */
		jam_end_id(buf, this);
		/* ---NEXTHOP */
		jam_end_nexthop(buf, this, that, skip_next_hop, left_right);
		break;
	case RIGHT_END:
		/* HOPNEXT--- */
		jam_end_nexthop(buf, this, that, skip_next_hop, left_right);
		/* HOST */
		jam_end_host(buf, this, policy);
		/* [ID+OPTS] */
		jam_end_id(buf, this);
		/* ===CLIENT/PROTOCOL:PORT */
		jam_end_client(buf, this, policy, left_right);
		break;
	}
}

/*
 * format topology of a connection.
 * Two symmetric ends separated by ...
 */

#define END_BUF (sizeof(subnet_buf) + sizeof(address_buf) + sizeof(id_buf) + sizeof(subnet_buf) + 10)
#define CONN_BUF_LEN    (2 * (END_BUF - 1) + 4)

static char *format_connection(char *buf, size_t buf_len,
			       const struct connection *c,
			       const struct spd_route *sr)
{
	struct jambuf b = array_as_jambuf(buf, buf_len);
	jam_end(&b, &sr->this, &sr->that, LEFT_END, LEMPTY, false);
	jam(&b, "...");
	jam_end(&b, &sr->that, &sr->this, RIGHT_END, c->policy, oriented(c));
	return buf;
}

/* spd_route's with end's get copied in xauth.c */
void unshare_connection_end(struct connection *c, struct end *e)
{
	e->virt = virtual_ip_addref(e->virt, HERE);
	pexpect(e->sec_label.ptr == NULL);
	e->host = &c->end[e->config->index].host;
}

/*
 * unshare_connection: after a struct connection has been copied,
 * duplicate anything it references so that unshareable resources
 * are no longer shared.  Typically strings, but some other things too.
 *
 * Think of this as converting a shallow copy to a deep copy
 *
 * XXX: unshare_connection() and the shallow clone should be merged
 * into a routine that allocates a new connection and then explicitly
 * copy over the data.  Cloning pointers and then trying to fix them
 * up after the event is a guaranteed way to create use-after-free
 * problems.
 */
static void unshare_connection(struct connection *c, struct connection *t/*emplate*/)
{
	c->root_config = NULL;

	c->foodgroup = clone_str(c->foodgroup, "connection foodgroup");

	c->modecfg_dns = clone_str(c->modecfg_dns,
				"connection modecfg_dns");
	c->modecfg_domains = clone_str(c->modecfg_domains,
				"connection modecfg_domains");
	c->modecfg_banner = clone_str(c->modecfg_banner,
				"connection modecfg_banner");
	c->dnshostname = clone_str(c->dnshostname, "connection dnshostname");

	/* duplicate any alias, adding spaces to the beginning and end */
	c->connalias = clone_str(c->connalias, "connection alias");

	c->vti_iface = clone_str(c->vti_iface, "connection vti_iface");

	c->redirect_to = clone_str(c->redirect_to,\
					"connection redirect_to");
	c->accept_redirect_to = clone_str(c->accept_redirect_to,\
					"connection accept_redirect_to");

	c->interface = iface_endpoint_addref(t->interface);

	for (struct spd_route *sr = &c->spd; sr != NULL; sr = sr->spd_next) {
		unshare_connection_end(c, &sr->this);
		unshare_connection_end(c, &sr->that);
		sr->connection = c;
		if (sr->spd_next != NULL) {
			sr->spd_next = clone_thing(*sr->spd_next, "spd clone");
		}
	}

	FOR_EACH_THING(end, c->local, c->remote) {
		end->host.id = clone_id(&end->host.id, "unshare connection id");
	}

	if (c->pool !=  NULL)
		reference_addresspool(c);

	if (IS_XFRMI && c->xfrmi != NULL)
		reference_xfrmi(c);
}

/*
 * Figure out the host / client address family.
 *
 * Returns diag() when there's a conflict.  leaves *AFI NULL if could
 * not be determined.
 */

#define EXTRACT_AFI(LEVEL, NAME, TYPE, FIELD)				\
	{								\
		const struct ip_info *wfi = TYPE##_type(&FIELD);	\
		if (*afi == NULL) {					\
			*afi = wfi;					\
			leftright = w->leftright;			\
			name = NAME;					\
			struct jambuf buf = ARRAY_AS_JAMBUF(value);	\
			jam_##TYPE(&buf, &FIELD);			\
		} else if (wfi != NULL && wfi != *afi) {		\
			TYPE##_buf tb;					\
			return diag(LEVEL" address family %s from %s%s=%s conflicts with %s%s=%s", \
				    (*afi)->ip_name, leftright, name, value, \
				    w->leftright, NAME, str_##TYPE(&FIELD, &tb)); \
		}							\
	}

static diag_t extract_host_afi(const struct whack_message *wm,
			       const struct ip_info **afi)
{
	*afi = NULL;
	const char *leftright;
	const char *name;
	char value[sizeof(selector_buf)];
	FOR_EACH_THING(w, &wm->left, &wm->right) {
		EXTRACT_AFI("host", "", address, w->host_addr);
		EXTRACT_AFI("host", "nexthop", address, w->host_nexthop);
	}
	return NULL;
}

static diag_t extract_client_afi(const struct whack_message *wm,
				 const struct ip_info **afi)
{
	*afi = NULL;
	const char *leftright;
	const char *name;
	char value[sizeof(selector_buf)];
	FOR_EACH_THING(w, &wm->left, &wm->right) {
		EXTRACT_AFI("client", "subnet", subnet, w->client);
	}
	return NULL;
}

static int extract_end(struct connection *c,
		       struct end *dst,
		       struct config_end *config_end,
		       const struct whack_message *wm,
		       const struct whack_end *src,
		       struct end *other_end,
		       const struct ip_info *host_afi,
		       const struct ip_info *client_afi,
		       struct logger *logger/*connection "..."*/)
{
	passert(dst->config == config_end);
	const char *leftright = dst->config->leftright;
	bool same_ca = 0;

	/*
	 * decode id, if any
	 *
	 * For %fromcert, the load_end_cert*() call will update it.
	 */
	if (src->id == NULL) {
		dst->host->id.kind = ID_NONE;
	} else {
		/*
		 * Cannot report errors due to low level nesting of functions,
		 * since it will try literal IP string conversions first. But
		 * atoid() will log real failures like illegal DNS chars already,
		 * and for @string ID's all chars are valid without processing.
		 */
		atoid(src->id, &dst->host->id);
	}

	/* decode CA distinguished name, if any */
	config_end->host.ca = empty_chunk;
	if (src->ca != NULL) {
		if (streq(src->ca, "%same")) {
			same_ca = 1;
		} else if (!streq(src->ca, "%any")) {
			err_t ugh;

			/* convert the CA into a DN blob */
			ugh = atodn(src->ca, &config_end->host.ca);
			if (ugh != NULL) {
				llog(RC_LOG, logger,
				     "bad %s CA string '%s': %s (ignored)",
				     leftright, src->ca, ugh);
			} else {
				/* now try converting it back; isn't failing this a bug? */
				ugh = parse_dn(ASN1(config_end->host.ca));
				if (ugh != NULL) {
					llog(RC_LOG, logger,
					     "error parsing %s CA converted to DN: %s",
					     leftright, ugh);
					DBG_dump_hunk(NULL, config_end->host.ca);
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
		if (src->rsasigkey != NULL) {
			llog(RC_LOG, logger,
				    "warning: ignoring %s rsasigkey '%s' and using %s certificate '%s'",
				    leftright, src->cert,
				    leftright, src->cert);
		}
		CERTCertificate *cert = get_cert_by_nickname_from_nss(src->cert, logger);
		if (cert == NULL) {
			llog(RC_FATAL, logger,
				    "failed to add connection: %s certificate '%s' not found in the NSS database",
				    leftright, src->cert);
			return -1; /* fatal */
		}
		diag_t diag = add_end_cert_and_preload_private_key(cert,
								   dst, config_end,
								   same_ca/*preserve_ca*/,
								   logger);
		if (diag != NULL) {
			llog_diag(RC_FATAL, logger, &diag, "failed to add connection: ");
			CERT_DestroyCertificate(cert);
			return -1;
		}
	} else if (src->rsasigkey != NULL) {
		if (src->ckaid != NULL) {
			llog(RC_LOG, logger,
				    "warning: ignoring %s ckaid '%s' and using %s rsasigkey",
				    leftright, src->ckaid, leftright);
		}
		/*
		 * XXX: hack: whack will load the rsasigkey in a
		 * second message, this code just extracts the ckaid.
		 */
		const struct pubkey_type *type = &pubkey_type_rsa;
		/* XXX: lifted from starter_whack_add_pubkey() */
		char err_buf[TTODATAV_BUF];
		char keyspace[1024 + 4];
		size_t keylen;

		/* ??? this value of err isn't used */
		err_t err = ttodatav(src->rsasigkey, 0, 0,
				     keyspace, sizeof(keyspace), &keylen,
				     err_buf, sizeof(err_buf), 0);
		union pubkey_content pkc;
		keyid_t pubkey;
		ckaid_t ckaid;
		size_t size;
		err = type->unpack_pubkey_content(&pkc, &pubkey, &ckaid, &size,
						  chunk2(keyspace, keylen));
		if (err != NULL) {
			llog(RC_FATAL, logger,
				    "failed to add connection: %s raw public key invalid: %s",
				    leftright, err);
			return -1;
		}
		ckaid_buf ckb;
		dbg("saving %s CKAID %s extracted from raw %s public key",
		    leftright, str_ckaid(&ckaid, &ckb), type->name);
		config_end->host.ckaid = clone_const_thing(ckaid, "raw pubkey's ckaid");
		type->free_pubkey_content(&pkc);
		/* try to pre-load the private key */
		bool load_needed;
		err = preload_private_key_by_ckaid(&ckaid, &load_needed, logger);
		if (err != NULL) {
			ckaid_buf ckb;
			dbg("no private key matching %s CKAID %s: %s",
			    leftright, str_ckaid(config_end->host.ckaid, &ckb), err);
		} else if (load_needed) {
			ckaid_buf ckb;
			llog(RC_LOG|LOG_STREAM/*not-whack-for-now*/, logger,
				    "loaded private key matching %s CKAID %s",
				    leftright, str_ckaid(config_end->host.ckaid, &ckb));
		}
	} else if (src->ckaid != NULL) {
		ckaid_t ckaid;
		err_t err = string_to_ckaid(src->ckaid, &ckaid);
		if (err != NULL) {
			/* should have been rejected by whack? */
			/* XXX: don't trust whack */
			llog(RC_FATAL, logger,
				    "failed to add connection: %s CKAID '%s' invalid: %s",
				    leftright, src->ckaid, err);
			return -1; /* fatal */
		}
		/*
		 * Always save the CKAID so lazy load of the private
		 * key will work.
		 */
		config_end->host.ckaid = clone_thing(ckaid, "end ckaid");
		/*
		 * See if there's a certificate matching the CKAID, if
		 * not assume things will later find the private key.
		 */
		CERTCertificate *cert = get_cert_by_ckaid_from_nss(&ckaid, logger);
		if (cert != NULL) {
			diag_t diag = add_end_cert_and_preload_private_key(cert,
									   dst, config_end,
									   same_ca/*preserve_ca*/,
									   logger);
			if (diag != NULL) {
				llog_diag(RC_FATAL, logger, &diag, "failed to add connection: ");
				CERT_DestroyCertificate(cert);
				return -1;
			}
		} else {
			dbg("%s CKAID '%s' did not match a certificate in the NSS database",
			    leftright, src->ckaid);
			/* try to pre-load the private key */
			bool load_needed;
			err_t err = preload_private_key_by_ckaid(&ckaid, &load_needed, logger);
			if (err != NULL) {
				ckaid_buf ckb;
				dbg("no private key matching %s CKAID %s: %s",
				    leftright,
				    str_ckaid(config_end->host.ckaid, &ckb), err);
			} else {
				ckaid_buf ckb;
				llog(RC_LOG|LOG_STREAM/*not-whack-for-now*/, logger,
				     "loaded private key matching %s CKAID %s",
				     leftright,
				     str_ckaid(config_end->host.ckaid, &ckb));
			}
		}
	}

	/* the rest is simple copying of corresponding fields */
	config_end->host.type = src->host_type;
	dst->host->addr = src->host_addr;
	config_end->host.addr_name = clone_str(src->host_addr_name, "host ip");
	dst->host->nexthop = src->host_nexthop;
	dst->host_srcip = src->host_srcip;
	config_end->client.host_vtiip = src->host_vtiip;
	config_end->client.ifaceip = src->ifaceip;
	dst->cat = src->cat;
	dst->pool_range = src->pool_range;

	config_end->host.xauth.server = src->xauth_server;
	config_end->host.xauth.client = src->xauth_client;
	config_end->host.xauth.username = clone_str(src->xauth_username, "xauth username");
	config_end->host.eap = src->eap;

	if (src->eap == IKE_EAP_NONE && src->auth == AUTH_EAPONLY) {
		llog(RC_LOG_SERIOUS, logger, "failed to add connection: leftauth/rightauth can only be 'eaponly' when using leftautheap/rightautheap is not 'none'");
		return -1;
	}

	config_end->host.auth = src->auth;
	lset_t policy_authby = LEMPTY;
	switch (src->auth) {
	case AUTH_RSASIG:
		policy_authby = (wm->policy & POLICY_AUTHBY_RSASIG_MASK);
		break;
	case AUTH_ECDSA:
		policy_authby = (wm->policy & POLICY_AUTHBY_ECDSA_MASK);
		break;
	case AUTH_PSK:
		/* force only bit */
		policy_authby = POLICY_PSK;
		break;
	case AUTH_NULL:
		/* force only bit */
		policy_authby = POLICY_AUTH_NULL;
		break;
	case AUTH_EAPONLY:
	case AUTH_UNSET:
		policy_authby = (wm->policy & POLICY_AUTHBY_MASK); /* ??? */
	case AUTH_NEVER:
		break;
	}
	if (wm->ike_version == IKEv1) {
		/* strip stuff IKEv1 ignores */
		policy_authby &= ~POLICY_ECDSA;
		policy_authby &= ~POLICY_RSASIG_v1_5;
	}
	lset_buf pab;
	dbg("fake %sauthby=%s", src->leftright,
	    str_lset_short(&sa_policy_bit_names, "+", policy_authby, &pab));
	config_end->host.policy_authby = policy_authby;

	/* save some defaults */
	config_end->client.subnet = src->client;
	config_end->client.protoport = src->protoport;

	if (src->protoport.ipproto == 0 && src->protoport.hport != 0) {
		llog(RC_LOG_SERIOUS, logger,
		     "failed to add connection: %sprotoport cannot specify non-zero port %d for prototcol 0",
		     src->leftright, src->protoport.hport);
		return -1;
	}

	if (src->client.is_set) {
		/*
		 * end.has_client seems to mean that the .client
		 * selector is pinned (when false .client can be
		 * refined).
		 *
		 * Of course if NARROWING is allowed, this can be
		 * refined regardless of .has_client.
		 */
		dst->has_client = true;
		dst->client = selector_from_subnet_protoport(src->client,
							     src->protoport);
	} else if (host_afi != client_afi) {
		/*
		 * If {left,right}subnet isn't specified in the
		 * configuration file then it defaults to the HOST's
		 * address.
		 *
		 * Except at this point the host's address may not be
		 * known (DNS, %any).  This is "fixed" by
		 * update_ends().  Fortunately (if nothing else, by
		 * forcing it), at least the host address family is
		 * known.
		 */
		llog(RC_LOG_SERIOUS, logger,
		     "failed to add connection: host protocol %s conflicts with client protocol %s",
		     host_afi->ip_name, client_afi->ip_name);
		return -1;
	} else if (src->protoport.is_set) {
		/*
		 * There's no client subnet _yet_ there is a client
		 * protoport.  There must be a client.
		 *
		 * Per above, the client will be formed from
		 * HOST+PROTOPORT.  Problem is, HOST probably isn't
		 * yet known, use host family's .all as a stand in.
		 * Calling update_ends*() will then try to fix it.
		 */
		dst->client = selector_from_subnet_protoport(host_afi->subnet.all,
							     src->protoport);
	}

	dst->key_from_DNS_on_demand = src->key_from_DNS_on_demand;
	config_end->client.updown = clone_str(src->updown, "config_end.client.updown");
	config_end->host.sendcert = src->sendcert == 0 ? CERT_SENDIFASKED : src->sendcert;
	config_end->host.ikeport = src->host_ikeport;
	if (src->host_ikeport > 65535) {
		llog(RC_BADID, logger,
			    "%sikeport=%u must be between 1..65535, ignored",
			    leftright, src->host_ikeport);
		config_end->host.ikeport = 0;
	}

	/*
	 * see if we can resolve the DNS name right now
	 * XXX this is WRONG, we should do this asynchronously, as part of
	 * the normal loading process
	 */
	switch (dst->config->host.type) {
	case KH_IPHOSTNAME:
	{
		err_t er = ttoaddress_dns(shunk1(config_end->host.addr_name),
					  address_type(&dst->host->addr),
					  &dst->host->addr);
		if (er != NULL) {
			llog(RC_COMMENT, logger,
			     "failed to convert '%s' at load time: %s",
			     config_end->host.addr_name, er);
		}
		break;
	}

	default:
		break;
	}

	/*
	 * How to add addresspool only for responder?  It is not
	 * necessary on the initiator
	 *
	 * Note that, possibly confusingly, it is the client's end
	 * that has the address pool.  I.e., set OTHER_END to server.
	 *
	 * Need to also merge in the client/server options provided by
	 * whack - sometimes they are set, sometimes they are not.
	 */

	dst->modecfg_server = dst->modecfg_server || src->modecfg_server;
	dst->modecfg_client = dst->modecfg_client || src->modecfg_client;

	if (range_size(src->pool_range) > 0) {
		if (c->pool != NULL) {
			llog(RC_LOG_SERIOUS, logger, "both left and right define address pools");
			return -1;
		}
		diag_t d = install_addresspool(src->pool_range, &c->pool);
		if (d != NULL) {
			llog_diag(RC_LOG_SERIOUS, c->logger, &d,
				 "invalid %saddresspool: ", leftright);
			return -1;
		}
		other_end->modecfg_server = true;
		dst->modecfg_client = true;
	}

	return same_ca;
}

static diag_t check_connection_end(const struct whack_end *this,
				   const struct whack_end *that,
				   const struct whack_message *wm)
{
	/* ??? seems like a nasty test (in-band, low-level) */
	/* XXX: still nasty; just less low-level */
	if (range_size(this->pool_range) > 0) {
		struct ip_pool *pool; /* ignore */
		diag_t d = find_addresspool(this->pool_range, &pool);
		if (d != NULL) {
			return d;
		}
	}

	/* MAKE this more sane in the face of unresolved IP addresses */
	if (that->host_type != KH_IPHOSTNAME &&
	    !address_is_specified(that->host_addr)) {
		/*
		 * Other side is wildcard: we must check if other conditions
		 * met.
		 */
		if (this->host_type != KH_IPHOSTNAME &&
		    !address_is_specified(this->host_addr)) {
			return diag("connection %s must specify host IP address for our side",
				    wm->name);
		}
	}

	if (this->id != NULL && streq(this->id, "%fromcert")) {
		lset_t auth_pol = (wm->policy & POLICY_ID_AUTH_MASK);

		if (this->auth == AUTH_PSK ||
		    this->auth == AUTH_NULL ||
		    auth_pol == POLICY_PSK ||
		    auth_pol == POLICY_AUTH_NULL) {
			return diag("ID cannot be specified as %%fromcert if PSK or AUTH-NULL is used");
		}
	}

	return NULL; /* happy */
}

diag_t add_end_cert_and_preload_private_key(CERTCertificate *cert,
					    struct end *end,
					    struct config_end *config_end,
					    bool preserve_ca,
					    struct logger *logger)
{
	passert(cert != NULL);
	const char *nickname = cert->nickname;
	const char *leftright = end->config->leftright;

	/*
	 * A copy of this code lives in nss_cert_verify.c :/
	 * Currently only a check for RSA is needed, as the only ECDSA
	 * key size not allowed in FIPS mode (p192 curve), is not implemented
	 * by NSS.
	 * See also RSA_secret_sane() and ECDSA_secret_sane()
	 */
	if (libreswan_fipsmode()) {
		SECKEYPublicKey *pk = CERT_ExtractPublicKey(cert);
		passert(pk != NULL);
		if (pk->keyType == rsaKey &&
		    ((pk->u.rsa.modulus.len * BITS_PER_BYTE) < FIPS_MIN_RSA_KEY_SIZE)) {
			SECKEY_DestroyPublicKey(pk);
			return diag("FIPS: rejecting %s certificate '%s' with key size %d which is under %d",
				    leftright, nickname,
				    pk->u.rsa.modulus.len * BITS_PER_BYTE,
				    FIPS_MIN_RSA_KEY_SIZE);
		}
		/* TODO FORCE MINIMUM SIZE ECDSA KEY */
		SECKEY_DestroyPublicKey(pk);
	}

	/* XXX: should this be after validity check? */
	select_nss_cert_id(cert, &end->host->id);

	/* check validity of cert */
	if (CERT_CheckCertValidTimes(cert, PR_Now(), false) !=
			secCertTimeValid) {
		return diag("%s certificate '%s' is expired or not yet valid",
			    leftright, nickname);
	}

	dbg("loading %s certificate \'%s\' pubkey", leftright, nickname);
	if (!add_pubkey_from_nss_cert(&pluto_pubkeys, &end->host->id, cert, logger)) {
		/* XXX: push diag_t into add_pubkey_from_nss_cert()? */
		return diag("%s certificate \'%s\' pubkey could not be loaded",
			    leftright, nickname);
	}

	config_end->host.cert.nss_cert = cert;

	/*
	 * If no CA is defined, use issuer as default; but only when
	 * update is ok.
	 *
	 */
	if (preserve_ca || config_end->host.ca.ptr != NULL) {
		dbg("preserving existing %s ca", leftright);
	} else {
		config_end->host.ca = clone_secitem_as_chunk(cert->derIssuer, "issuer ca");
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
	err_t ugh = preload_private_key_by_cert(&config_end->host.cert, &load_needed, logger);
	if (ugh != NULL) {
		dbg("no private key matching %s certificate %s: %s",
		    leftright, nickname, ugh);
	} else if (load_needed) {
		llog(RC_LOG|LOG_STREAM/*not-whack-for-now*/, logger,
		     "loaded private key matching %s certificate '%s'",
		     leftright, nickname);
	}
	return NULL;
}

/* only used by add_connection() */
static void mark_parse(/*const*/ char *wmmark,
		       struct sa_mark *sa_mark,
		       struct logger *logger/*connection "...":*/)
{
	/*const*/ char *val_end;

	sa_mark->unique = false;
	sa_mark->val = 0xffffffff;
	sa_mark->mask = 0xffffffff;
	if (streq(wmmark, "-1") || startswith(wmmark, "-1/")) {
		sa_mark->unique = true;
		val_end = wmmark + strlen("-1");
	} else {
		errno = 0;
		unsigned long v = strtoul(wmmark, &val_end, 0);
		if (errno != 0 || v > 0xffffffff ||
		    (*val_end != '\0' && *val_end != '/'))
		{
			/* ??? should be detected and reported by confread and whack */
			/* XXX: don't trust whack */
			llog(RC_LOG_SERIOUS, logger,
				    "bad mark value \"%s\"", wmmark);
		} else {
			sa_mark->val = v;
		}
	}

	if (*val_end == '/') {
		/*const*/ char *mask_end;
		errno = 0;
		unsigned long v = strtoul(val_end+1, &mask_end, 0);
		if (errno != 0 || v > 0xffffffff || *mask_end != '\0') {
			/* ??? should be detected and reported by confread and whack */
			/* XXX: don't trust whack */
			llog(RC_LOG_SERIOUS, logger,
				   "bad mark mask \"%s\"", mask_end);
		} else {
			sa_mark->mask = v;
		}
	}
	if ((sa_mark->val & ~sa_mark->mask) != 0) {
		/* ??? should be detected and reported by confread and whack */
		/* XXX: don't trust whack */
		llog(RC_LOG_SERIOUS, logger,
			    "mark value %#08" PRIx32 " has bits outside mask %#08" PRIx32,
			    sa_mark->val, sa_mark->mask);
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

static bool extract_connection(const struct whack_message *wm,
			       struct connection *c)
{
	diag_t d;
	struct config *config = c->root_config; /* writeable; root only */
	passert(c->name != NULL); /* see alloc_connection() */

	if ((wm->policy & POLICY_TUNNEL) == LEMPTY) {
		if (wm->sa_tfcpad != 0) {
			llog(RC_FATAL, c->logger,
			     "failed to add connection: connection with type=transport cannot specify tfc=");
			return false;
		}
		if (wm->vti_iface != NULL) {
			llog(RC_FATAL, c->logger,
			     "failed to add connection: VTI requires tunnel mode but connection specifies type=transport");
			return false;
		}
	}
	if (LIN(POLICY_AUTHENTICATE, wm->policy)) {
		if (wm->sa_tfcpad != 0) {
			llog(RC_FATAL, c->logger,
			     "failed to add connection: connection with phase2=ah cannot specify tfc=");
			return false;
		}
	}

	if (LIN(POLICY_AUTH_NEVER, wm->policy)) {
		if (wm->prospective_shunt == SHUNT_UNSET ||
		    wm->prospective_shunt == SHUNT_TRAP) {
			llog(RC_FATAL, c->logger,
			     "failed to add connection: connection with authby=never must specify shunt type via type=");
			return false;
		}
	}
	if (wm->prospective_shunt != SHUNT_UNSET && wm->prospective_shunt != SHUNT_TRAP) {
		if ((wm->policy & (POLICY_ID_AUTH_MASK & ~POLICY_AUTH_NEVER)) != LEMPTY) {
			llog(RC_FATAL, c->logger,
				    "failed to add connection: shunt connection cannot have authentication method other then authby=never");
			return false;
		}
	} else {
		switch (wm->policy & (POLICY_AUTHENTICATE | POLICY_ENCRYPT)) {
		case LEMPTY:
			if (!LIN(POLICY_AUTH_NEVER, wm->policy)) {
				llog(RC_FATAL, c->logger,
					    "failed to add connection: non-shunt connection must have AH or ESP");
				return false;
			}
			break;
		case POLICY_AUTHENTICATE | POLICY_ENCRYPT:
			llog(RC_FATAL, c->logger,
				    "failed to add connection: non-shunt connection must not specify both AH and ESP");
			return false;
		}
	}

	if (wm->ike_version == IKEv1) {
#ifdef USE_IKEv1
		if (pluto_ikev1_pol != GLOBAL_IKEv1_ACCEPT) {
			llog(RC_FATAL, c->logger,
				    "failed to add IKEv1 connection: global ikev1-policy does not allow IKEv1 connections");
			return false;
		}
#else
		llog(RC_FATAL, c->logger, "failed to add IKEv1 connection: IKEv1 support not compiled in");
		return false;
#endif
	}
	config->ike_version = wm->ike_version;

	if (wm->policy & POLICY_OPPORTUNISTIC &&
	    c->config->ike_version < IKEv2) {
		llog(RC_FATAL, c->logger,
		     "failed to add connection: opportunistic connection MUST have IKEv2");
		return false;
	}

	if (wm->policy & POLICY_MOBIKE &&
	    c->config->ike_version < IKEv2) {
		llog(RC_FATAL, c->logger,
		     "failed to add connection: MOBIKE requires IKEv2");
		return false;
	}

	if (wm->policy & POLICY_IKEV2_ALLOW_NARROWING &&
	    c->config->ike_version < IKEv2) {
		llog(RC_FATAL, c->logger,
		     "failed to add connection: narrowing=yes requires IKEv2");
		return false;
	}

	if (wm->iketcp != IKE_TCP_NO &&
	    c->config->ike_version < IKEv2) {
		llog(RC_FATAL, c->logger,
		     "failed to add connection: enable-tcp= requires IKEv2");
		return false;
	}

	if (wm->policy & POLICY_MOBIKE) {
		if (kernel_ops->migrate_sa_check == NULL) {
			llog(RC_FATAL, c->logger,
			     "failed to add connection: MOBIKE not supported by %s interface",
			     kernel_ops->interface_name);
			return false;
		}
		/* probe the interface */
		err_t err = kernel_ops->migrate_sa_check(c->logger);
		if (err != NULL) {
			llog(RC_FATAL, c->logger,
			     "failed to add connection: MOBIKE kernel support missing for %s interface: %s",
			     kernel_ops->interface_name, err);
			return false;
		}
	}

	if (wm->iketcp != IKE_TCP_NO && (wm->remote_tcpport == 0 || wm->remote_tcpport == 500)) {
		llog(RC_FATAL, c->logger,
			    "failed to add connection: tcp-remoteport cannot be 0 or 500");
		return false;
	}

	/* we could complain about a lot more whack strings */
	if (NEVER_NEGOTIATE(wm->policy)) {
		if (wm->ike != NULL) {
			llog(RC_INFORMATIONAL, c->logger,
				    "ignored ike= option for type=passthrough connection");
		}
		if (wm->esp != NULL) {
			llog(RC_INFORMATIONAL, c->logger,
				    "ignored esp= option for type=passthrough connection");
		}
		if (wm->iketcp != IKE_TCP_NO) {
			llog(RC_INFORMATIONAL, c->logger,
				    "ignored enable-tcp= option for type=passthrough connection");
		}
		if (wm->left.auth != AUTH_UNSET ||
		    wm->right.auth != AUTH_UNSET) {
			llog(RC_FATAL, c->logger,
				    "failed to add connection: leftauth= / rightauth= options are invalid for type=passthrough connection");
			return false;
		}
	} else {
		/* reject all bad combinations of authby with leftauth=/rightauth= */
		if (wm->left.auth != AUTH_UNSET ||
		    wm->right.auth != AUTH_UNSET) {
			if (c->config->ike_version == IKEv1) {
				llog(RC_FATAL, c->logger,
					    "failed to add connection: leftauth= and rightauth= require ikev2");
				return false;
			}
			if (wm->left.auth == AUTH_UNSET ||
			    wm->right.auth == AUTH_UNSET) {
				llog(RC_FATAL, c->logger,
					    "failed to add connection: leftauth= and rightauth= must both be set or both be unset");
				return false;
			}
			/* ensure no conflicts of set left/rightauth with (set or unset) authby= */
			if (wm->left.auth == wm->right.auth) {

				lset_t auth_pol = (wm->policy & POLICY_ID_AUTH_MASK);
				const char *conflict = NULL;
				switch (wm->left.auth) {
				case AUTH_PSK:
					if (auth_pol != POLICY_PSK && auth_pol != LEMPTY) {
						conflict = "leftauthby=secret but authby= is not secret";
					}
					break;
				case AUTH_NULL:
					if (auth_pol != POLICY_AUTH_NULL && auth_pol != LEMPTY) {
						conflict = "leftauthby=null but authby= is not null";
					}
					break;
				case AUTH_NEVER:
					if ((wm->policy & POLICY_ID_AUTH_MASK) != LEMPTY) {
						conflict = "leftauthby=never but authby= is not never - double huh?";
					}
					break;
				case AUTH_RSASIG:
				case AUTH_ECDSA:
					/* will be fixed later below */
					break;
				case AUTH_EAPONLY:
					/* no conflict possible with symmetric POLICY flags */
					break;
				default:
					bad_case(wm->left.auth);
				}
				if (conflict != NULL) {
					policy_buf pb;
					llog(RC_FATAL, c->logger,
					     "failed to add connection: leftauth=%s and rightauth=%s conflict with authby=%s, %s",
					     enum_name(&keyword_auth_names, wm->left.auth),
					     enum_name(&keyword_auth_names, wm->right.auth),
					     str_policy(wm->policy & POLICY_ID_AUTH_MASK, &pb),
					     conflict);
					return false;
				}
			} else {
				if ((wm->left.auth == AUTH_PSK && wm->right.auth == AUTH_NULL) ||
				    (wm->left.auth == AUTH_NULL && wm->right.auth == AUTH_PSK)) {
					llog(RC_FATAL, c->logger,
						    "failed to add connection: cannot mix PSK and NULL authentication (leftauth=%s and rightauth=%s)",
						    enum_name(&keyword_auth_names, wm->left.auth),
						    enum_name(&keyword_auth_names, wm->right.auth));
					return false;
				}
			}
		}
	}

	if (wm->right.protoport.has_port_wildcard && wm->left.protoport.has_port_wildcard) {
		llog(RC_FATAL, c->logger,
		     "failed to add connection: cannot have protoports with wildcard (%%any) ports on both sides");
		return false;
	}

	/*
	 * Determine the host/client's family.
	 *
	 * XXX: idle speculation: if traffic selectors with different
	 * address families are to be supported then these will need
	 * to be nested within some sort of loop.  One for host, one
	 * for client, one for IPv4, and one for IPv6.
	 */
	const struct ip_info *host_afi = NULL;
	d = extract_host_afi(wm, &host_afi);
	if (d != NULL) {
		llog_diag(RC_FATAL, c->logger, &d, "failed to add connection: ");
		return false;
	}
	if (host_afi == NULL) {
		llog(RC_FATAL, c->logger,
		     "failed to add connection: host address family unknown");
		return false;
	}

	const struct ip_info *client_afi = NULL;
	d = extract_client_afi(wm, &client_afi);
	if (d != NULL) {
		llog_diag(RC_FATAL, c->logger, &d, "failed to add connection: ");
		return false;
	}
	if (client_afi == NULL) {
		dbg("defaulting client afi to host afi");
		client_afi = host_afi;
	}

	d = check_connection_end(&wm->right, &wm->left, wm);
	if (d != NULL) {
		llog_diag(RC_FATAL, c->logger, &d, "failed to add connection: ");
		return false;
	}
	d = check_connection_end(&wm->left, &wm->right, wm);
	if (d != NULL) {
		llog_diag(RC_FATAL, c->logger, &d, "failed to add connection: ");
		return false;
	}

	/* duplicate any alias, adding spaces to the beginning and end */
	c->connalias = clone_str(wm->connalias, "connection alias");

	c->dnshostname = clone_str(wm->dnshostname, "connection dnshostname");
	c->policy = wm->policy;

	switch (wm->prospective_shunt) {
	case SHUNT_UNSET:
		config->prospective_shunt = SHUNT_TRAP;
		break;
	case SHUNT_TRAP:
	case SHUNT_PASS:
	case SHUNT_DROP:
	case SHUNT_REJECT:
		config->prospective_shunt = wm->prospective_shunt;
		break;
	case SHUNT_NONE: /* XXX: no default */
	case SHUNT_HOLD:
	{
		enum_buf sb;
		llog(RC_FATAL, c->logger, "prospective shunt %s invalid",
		     str_enum_short(&shunt_policy_names, wm->prospective_shunt, &sb));
		return false;
	}
	}

	switch (wm->negotiation_shunt) {
	case SHUNT_UNSET:
		config->negotiation_shunt = SHUNT_HOLD;
		break;
	case SHUNT_PASS:
	case SHUNT_HOLD:
		config->negotiation_shunt = wm->negotiation_shunt;
		break;
	case SHUNT_TRAP: /* XXX: no default */
	case SHUNT_DROP:
	case SHUNT_REJECT:
	case SHUNT_NONE:
	{
		enum_buf sb;
		llog(RC_FATAL, c->logger, "negotiation shunt %s invalid",
		     str_enum_short(&shunt_policy_names, wm->negotiation_shunt, &sb));
		return false;
	}
	}
	if (libreswan_fipsmode() && config->negotiation_shunt == SHUNT_PASS) {
		enum_buf sb;
		llog(RC_LOG_SERIOUS, c->logger,
		     "FIPS: ignored negotiationshunt=%s - packets MUST be blocked in FIPS mode",
		     str_enum_short(&shunt_policy_names, config->negotiation_shunt, &sb));
		config->negotiation_shunt = SHUNT_HOLD;
	}

	switch (wm->failure_shunt) {
	case SHUNT_UNSET:
		config->failure_shunt = SHUNT_NONE;
		break;
	case SHUNT_NONE:
	case SHUNT_PASS:
	case SHUNT_DROP:
	case SHUNT_REJECT:
		config->failure_shunt = wm->failure_shunt;
		break;
	case SHUNT_TRAP: /* XXX: no default */
	case SHUNT_HOLD:
	{
		enum_buf sb;
		llog(RC_FATAL, c->logger, "failure shunt %s invalid",
		     str_enum_short(&shunt_policy_names, wm->failure_shunt, &sb));
		return false;
	}
	}
	if (libreswan_fipsmode() && config->failure_shunt != SHUNT_NONE) {
		enum_buf eb;
		llog(RC_LOG_SERIOUS, c->logger,
		     "FIPS: ignored failureshunt=%s - packets MUST be blocked in FIPS mode",
		     str_enum_short(&shunt_policy_names, config->failure_shunt, &eb));
		config->failure_shunt = SHUNT_NONE;
	}

	/* ignore IKEv2 ECDSA and legacy RSA policies for IKEv1 connections */
	if (c->config->ike_version == IKEv1)
		c->policy = (c->policy & ~(POLICY_ECDSA | POLICY_RSASIG_v1_5));
	/* ignore symmetrical defaults if we got left/rightauth */
	if (wm->left.auth != wm->right.auth)
		c->policy = c->policy & ~POLICY_ID_AUTH_MASK;
	/* remove default pubkey policy if left/rightauth is specified */
	if (wm->left.auth == wm->right.auth) {
		if (wm->left.auth == AUTH_RSASIG)
			c->policy = (c->policy & ~(POLICY_ECDSA));
		if (wm->left.auth == AUTH_ECDSA)
			c->policy = (c->policy & ~(POLICY_RSASIG | POLICY_RSASIG_v1_5));
	}

	/* ignore supplied sighash and ECDSA (from defaults) for IKEv1 */
	if (c->config->ike_version == IKEv2) {
		config->sighash_policy = wm->sighash_policy;
	}

	if (NEVER_NEGOTIATE(c->policy)) {
		/* cleanup inherited default */
		c->iketcp = IKE_TCP_NO;
		c->remote_tcpport = 0;
	}

	/*
	 * Should ESN be disabled?
	 *
	 * Order things so that a lack of kernel support is the last
	 * resort (fixing the kernel will break less tests).
	 */

	if (NEVER_NEGOTIATE(wm->policy)) {
		dbg("ESN: never negotiating so ESN unchanged");
	} else if ((c->policy & POLICY_ESN_YES) == LEMPTY) {
		dbg("ESN: already disabled so nothing to do");
	} else if (wm->sa_replay_window == 0) {
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
		dbg("ESN: disabled as replay-window=0"); /* XXX: log? */
		c->policy &= ~POLICY_ESN_YES;
		c->policy |= POLICY_ESN_NO;
#ifdef USE_IKEv1
	} else if (wm->ike_version == IKEv1) {
#if 0
		dbg("ESN: disabled as not implemented with IKEv1");
		c->policy &= ~POLICY_ESN_YES;
		c->policy |= POLICY_ESN_NO;
#else
		dbg("ESN: ignored as not implemented with IKEv1");
#endif
#endif
	} else if (!kernel_ops->esn_supported) {
		llog(RC_LOG, c->logger,
		     "kernel interface does not support ESN so disabling");
		c->policy &= ~POLICY_ESN_YES;
		c->policy |= POLICY_ESN_NO;
	}

	connection_buf cb;
	policy_buf pb;
	dbg("added new %s connection "PRI_CONNECTION" with policy %s",
	    enum_name(&ike_version_names, c->config->ike_version),
	    pri_connection(c, &cb), str_connection_policies(c, &pb));

	if (NEVER_NEGOTIATE(wm->policy)) {
		/* set default to AUTH_NEVER if unset and we do not expect to do IKE */
		if (wm->left.auth == AUTH_UNSET &&
		    wm->right.auth == AUTH_UNSET) {
			if ((c->policy & POLICY_ID_AUTH_MASK) == LEMPTY) {
				/* authby= was also not specified - fill in default */
				c->policy |= POLICY_AUTH_NEVER;
				policy_buf pb;
				dbg("no AUTH policy was set for type=passthrough - defaulting to %s",
				    str_policy(c->policy & POLICY_ID_AUTH_MASK, &pb));
			}
		}
	} else {
		/* set default to RSASIG if unset and we expect to do IKE */
		if (wm->left.auth == AUTH_UNSET &&
		    wm->right.auth == AUTH_UNSET) {
			 if ((c->policy & POLICY_ID_AUTH_MASK) == LEMPTY) {
				/* authby= was also not specified - fill in default */
				c->policy |= POLICY_DEFAULT;
				policy_buf pb;
				dbg("no AUTH policy was set - defaulting to %s",
				    str_policy(c->policy & POLICY_ID_AUTH_MASK, &pb));
			}
		}

		/* fixup symmetric policy flags based on asymmetric ones */
		if ((wm->left.auth == AUTH_NULL && wm->right.auth == AUTH_RSASIG) ||
		    (wm->left.auth == AUTH_RSASIG && wm->right.auth == AUTH_NULL)) {
			c->policy |= POLICY_RSASIG;
		}
		if ((wm->left.auth == AUTH_NULL && wm->right.auth == AUTH_ECDSA) ||
		    (wm->left.auth == AUTH_ECDSA && wm->right.auth == AUTH_NULL)) {
			c->policy |= POLICY_ECDSA;
		}

		/* IKE cipher suites */

		if (!LIN(POLICY_AUTH_NEVER, wm->policy) &&
		    (wm->ike != NULL || c->config->ike_version == IKEv2)) {
			const struct proposal_policy proposal_policy = {
				/* logic needs to match pick_initiator() */
				.version = c->config->ike_version,
				.alg_is_ok = ike_alg_is_ike,
				.pfs = LIN(POLICY_PFS, wm->policy),
				.check_pfs_vs_dh = false,
				.logger_rc_flags = ALL_STREAMS|RC_LOG,
				.logger = c->logger, /* on-stack */
				/* let defaults stumble on regardless */
				.ignore_parser_errors = (wm->ike == NULL),
			};

			struct proposal_parser *parser = ike_proposal_parser(&proposal_policy);
			config->ike_proposals.p = proposals_from_str(parser, wm->ike);

			if (c->config->ike_proposals.p == NULL) {
				pexpect(parser->diag != NULL); /* something */
				llog_diag(RC_FATAL, c->logger, &parser->diag,
					 "failed to add connection: ");
				free_proposal_parser(&parser);
				/* caller will free C */
				return false;
			}
			free_proposal_parser(&parser);

			/* from here on, error returns should alg_info_free(&c->ike_proposals->ai); */

			LSWDBGP(DBG_BASE, buf) {
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
				llog_v2_proposals(LOG_STREAM/*not-whack*/|RC_LOG, c->logger,
						  config->v2_ike_proposals,
						  "IKE SA proposals");
			}
		}

		/* ESP or AH cipher suites (but not both) */

		if (wm->esp != NULL ||
		    (c->config->ike_version == IKEv2 &&
		     (c->policy & (POLICY_ENCRYPT|POLICY_AUTHENTICATE)))) {
			const char *esp = wm->esp != NULL ? wm->esp : "";
			dbg("from whack: got --esp=%s", esp);

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
				.pfs = LIN(POLICY_PFS, wm->policy),
				.check_pfs_vs_dh = true,
				.logger_rc_flags = ALL_STREAMS|RC_LOG,
				.logger = c->logger, /* on-stack */
				/* let defaults stumble on regardless */
				.ignore_parser_errors = (wm->esp == NULL),
			};

			/*
			 * We checked above that exactly one of
			 * POLICY_ENCRYPT and POLICY_AUTHENTICATE is on.
			 * The only difference in processing is which
			 * function is called (and those functions are
			 * almost identical).
			 */
			struct proposal_parser *(*fn)(const struct proposal_policy *policy) =
				(c->policy & POLICY_ENCRYPT) ? esp_proposal_parser :
				(c->policy & POLICY_AUTHENTICATE) ? ah_proposal_parser :
				NULL;
			passert(fn != NULL);
			struct proposal_parser *parser = fn(&proposal_policy);
			config->child_proposals.p = proposals_from_str(parser, wm->esp);
			if (c->config->child_proposals.p == NULL) {
				pexpect(parser->diag != NULL);
				llog_diag(RC_FATAL, c->logger, &parser->diag,
					 "failed to add connection: ");
				free_proposal_parser(&parser);
				/* caller will free C */
				return false;
			}
			free_proposal_parser(&parser);

			/* from here on, error returns should alg_info_free(&c->child_proposals->ai); */

			LSWDBGP(DBG_BASE, buf) {
				jam_string(buf, "ESP/AH string values: ");
				jam_proposals(buf, c->config->child_proposals.p);
			};

			/*
			 * For IKEv2, also generate the Child proposal
			 * that will be used during IKE AUTH.
			 *
			 * Since a Child SA established during an
			 * IKE_AUTH exchange does not propose DH
			 * (keying material is taken from the IKE SA's
			 * SKEYSEED), DH is stripped from the
			 * proposals.
			 *
			 * Since only things that affect this proposal
			 * suite are the connection's .policy bits and
			 * the contents .child_proposals, and
			 * modifiying those triggers the creation of a
			 * new connection (true?), the connection can
			 * be cached.
			 */
			if (c->config->ike_version == IKEv2) {
				/* UNSET_GROUP means strip DH from the proposal. */
				config->v2_ike_auth_child_proposals =
					get_v2_child_proposals(c, "loading config", &unset_group,
							       c->logger);
				llog_v2_proposals(LOG_STREAM/*not-whack*/|RC_LOG, c->logger,
						  config->v2_ike_auth_child_proposals,
						  "Child SA proposals");
			}
		}

		config->nic_offload = wm->nic_offload;
		c->sa_ike_life_seconds = wm->sa_ike_life_seconds;
		c->sa_ipsec_life_seconds = wm->sa_ipsec_life_seconds;
		c->sa_rekey_margin = wm->sa_rekey_margin;
		c->sa_rekey_fuzz = wm->sa_rekey_fuzz;
		c->sa_keying_tries = wm->sa_keying_tries;

		c->sa_replay_window = wm->sa_replay_window;

		config->retransmit_timeout = wm->retransmit_timeout;
		config->retransmit_interval = wm->retransmit_interval;

		if (deltatime_cmp(c->sa_rekey_margin, >=, c->sa_ipsec_life_seconds)) {
			deltatime_t new_rkm = deltatimescale(1, 2, c->sa_ipsec_life_seconds);

			llog(RC_LOG, c->logger,
			     "rekeymargin (%jds) >= salifetime (%jds); reducing rekeymargin to %jds seconds",
			     deltasecs(c->sa_rekey_margin),
			     deltasecs(c->sa_ipsec_life_seconds),
			     deltasecs(new_rkm));

			c->sa_rekey_margin = new_rkm;
		}

		{
			/* http://csrc.nist.gov/publications/nistpubs/800-77/sp800-77.pdf */
			time_t max_ike = libreswan_fipsmode() ? FIPS_IKE_SA_LIFETIME_MAXIMUM : IKE_SA_LIFETIME_MAXIMUM;
			time_t max_ipsec = libreswan_fipsmode() ? FIPS_IPSEC_SA_LIFETIME_MAXIMUM : IPSEC_SA_LIFETIME_MAXIMUM;

			if (deltasecs(c->sa_ike_life_seconds) > max_ike) {
				llog(RC_LOG_SERIOUS, c->logger,
				     "IKE lifetime limited to the maximum allowed %jds",
				     (intmax_t) max_ike);
				c->sa_ike_life_seconds = deltatime(max_ike);
			}
			if (deltasecs(c->sa_ipsec_life_seconds) > max_ipsec) {
				llog(RC_LOG_SERIOUS, c->logger,
				     "IPsec lifetime limited to the maximum allowed %jds",
				     (intmax_t) max_ipsec);
				c->sa_ipsec_life_seconds = deltatime(max_ipsec);
			}
		}

		/* IKEv1's RFC 3706 DPD */
		config->dpd.action = wm->dpd_action;
		switch (wm->ike_version) {
		case IKEv1:
			if (deltasecs(wm->dpd_delay) > 0 &&
			    deltasecs(wm->dpd_timeout) > 0) {
				config->dpd.delay = wm->dpd_delay;
				config->dpd.timeout = wm->dpd_timeout;
			} else if (deltasecs(wm->dpd_delay) > 0 ||
				   deltasecs(wm->dpd_timeout) > 0) {
				llog(RC_LOG_SERIOUS, c->logger,
				     "IKEv1 DPD requres both dpddelay and dpdtimeout");
			}
			break;
		case IKEv2:
			config->dpd.delay = wm->dpd_delay;
			config->dpd.timeout = wm->dpd_timeout; /* XXX: to-be-deleted */
			break;
		}

		/* Cisco interop: remote peer type */
		c->remotepeertype = wm->remotepeertype;

		c->metric = wm->metric;
		c->connmtu = wm->connmtu;
		c->encaps = wm->encaps;
		c->nat_keepalive = wm->nat_keepalive;
		c->ikev1_natt = wm->ikev1_natt;
		c->initial_contact = wm->initial_contact;
		c->cisco_unity = wm->cisco_unity;
		c->fake_strongswan = wm->fake_strongswan;
		c->send_vendorid = wm->send_vendorid;
		c->send_ca = wm->send_ca;
		c->xauthby = wm->xauthby;
		c->xauthfail = wm->xauthfail;

		c->modecfg_dns = clone_str(wm->modecfg_dns, "connection modecfg_dns");
		c->modecfg_domains = clone_str(wm->modecfg_domains, "connection modecfg_domains");
		c->modecfg_banner = clone_str(wm->modecfg_banner, "connection modecfg_banner");

		/* RFC 5685 - IKEv2 Redirect mechanism */
		c->redirect_to = clone_str(wm->redirect_to, "connection redirect_to");
		c->accept_redirect_to = clone_str(wm->accept_redirect_to, "connection accept_redirect_to");

		/* RFC 8229 TCP encap*/
		c->remote_tcpport = wm->remote_tcpport;
		c->iketcp = wm->iketcp;

		/*
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
		 */

		/* mark-in= and mark-out= overwrite mark= */
		if (wm->conn_mark_both != NULL) {
			mark_parse(wm->conn_mark_both, &c->sa_marks.in, c->logger);
			mark_parse(wm->conn_mark_both, &c->sa_marks.out, c->logger);
			if (wm->conn_mark_in != NULL || wm->conn_mark_out != NULL) {
				llog(RC_LOG_SERIOUS, c->logger,
				     "conflicting mark specifications");
			}
		}
		if (wm->conn_mark_in != NULL)
			mark_parse(wm->conn_mark_in, &c->sa_marks.in, c->logger);
		if (wm->conn_mark_out != NULL)
			mark_parse(wm->conn_mark_out, &c->sa_marks.out, c->logger);

		c->vti_iface = clone_str(wm->vti_iface, "connection vti_iface");
		c->vti_routing = wm->vti_routing;
		c->vti_shared = wm->vti_shared;
#ifdef USE_XFRM_INTERFACE
		if (wm->xfrm_if_id != UINT32_MAX) {
			err_t err = xfrm_iface_supported(c->logger);
			if (err == NULL) {
				if (!setup_xfrm_interface(c, wm->xfrm_if_id == 0 ?
					PLUTO_XFRMI_REMAP_IF_ID_ZERO : wm->xfrm_if_id ))
					return false;
			} else {
				llog(RC_FATAL, c->logger,
				     "failed to add connection: ipsec-interface=%u not supported. %s",
				     wm->xfrm_if_id, err);
				return false;
			}
		}
#endif
	}

#ifdef HAVE_NM
	c->nmconfigured = wm->nmconfigured;
#endif

	c->nflog_group = wm->nflog_group;
	c->sa_priority = wm->sa_priority;
	c->sa_tfcpad = wm->sa_tfcpad;
	c->send_no_esp_tfc = wm->send_no_esp_tfc;

	/*
	 * Since security labels use the same REQID for everything,
	 * pre-assign it.
	 */
	c->sa_reqid = (wm->sa_reqid != 0 ? wm->sa_reqid :
		       wm->ike_version != IKEv2 ? /*generated later*/0 :
		       wm->sec_label != NULL ? gen_reqid() :
		       /*generated later*/0);
	dbg(PRI_CONNECTION" c->sa_reqid=%d because wm->sa_reqid=%d and sec-label=%s",
	    pri_connection(c, &cb),
	    c->sa_reqid, wm->sa_reqid,
	    (wm->ike_version != IKEv2 ? "not-IKEv2" :
	     wm->sec_label != NULL ? wm->sec_label :
	     "n/a"));

	/*
	 * Set both end's sec_label to the same value.
	 */

	if (wm->sec_label != NULL) {
		dbg("received sec_label '%s' from whack", wm->sec_label);
		/* include NUL! */
		shunk_t sec_label = shunk2(wm->sec_label, strlen(wm->sec_label)+1);
		err_t ugh = vet_seclabel(sec_label);
		if (ugh != NULL) {
			llog(RC_LOG_SERIOUS, c->logger, "failed to add connection: %s: policy-label=%s",
			     ugh, wm->sec_label);
			return false;
		}
		config->sec_label = clone_hunk(sec_label, "struct config sec_label");
	}

	/*
	 * Unpack the ends.
	 *
	 * This choice of left/right must match alloc_connection().
	 */

	struct end *client_spd[] = {
		[LEFT_END] = c->end[LEFT_END].client.spd,
		[RIGHT_END] = c->end[RIGHT_END].client.spd,
	};

	const struct whack_end *whack_ends[] = {
		[LEFT_END] = &wm->left,
		[RIGHT_END] = &wm->right,
	};

	int same_ca[LEFT_RIGHT_ROOF] = { 0, };

	FOR_EACH_THING(lr, LEFT_END, RIGHT_END) {
		int opp = (lr + 1) % LEFT_RIGHT_ROOF;
		same_ca[lr] = extract_end(c,
					  client_spd[lr],
					  &config->end[lr],
					  wm, whack_ends[lr],
					  client_spd[opp],
					  host_afi, client_afi,
					  c->logger);
		if (same_ca[lr] < 0) {
			return false;
		}
	}

	FOR_EACH_THING(lr, LEFT_END, RIGHT_END) {
		int opp = (lr + 1) % LEFT_RIGHT_ROOF;
		if (same_ca[opp] == 1) {
			config->end[opp].host.ca = clone_hunk(config->end[lr].host.ca,
							     "same ca");
			break;
		}
	}

	if (c->local->config->host.xauth.server || c->remote->config->host.xauth.server)
		c->policy |= POLICY_XAUTH;

	update_ends_from_this_host_addr(&c->spd.this, &c->spd.that);
	update_ends_from_this_host_addr(&c->spd.that, &c->spd.this);

	/*
	 * If both left/rightauth is unset, fill it in with
	 * (preferred) symmetric policy.
	 */
	if (wm->left.auth == AUTH_UNSET &&
	    wm->right.auth == AUTH_UNSET) {
		enum keyword_auth authby;
		if (c->policy & POLICY_RSASIG)
			authby = AUTH_RSASIG;
		else if (c->policy & POLICY_ECDSA)
			authby = AUTH_ECDSA;
		else if (c->policy & POLICY_PSK)
			authby = AUTH_PSK;
		else if (c->policy & POLICY_AUTH_NULL)
			authby = AUTH_NULL;
		else
			authby = AUTH_UNSET;
		config->end[LEFT_END].host.auth = authby;
		config->end[RIGHT_END].host.auth = authby;
	}

	/* if left/rightauth are set, but symmetric policy is not, fill it in */
	if (wm->left.auth == wm->right.auth ||
	    wm->right.auth == AUTH_EAPONLY) {
		switch (wm->left.auth) {
		case AUTH_RSASIG:
			c->policy |= POLICY_RSASIG;
			break;
		case AUTH_ECDSA:
			c->policy |= POLICY_ECDSA;
			break;
		case AUTH_PSK:
			c->policy |= POLICY_PSK;
			break;
		case AUTH_NULL:
			c->policy |= POLICY_AUTH_NULL;
			break;
		default:
			break;
		}
	}

	c->spd.spd_next = NULL;
	c->spd.connection = c;

	/* set internal fields */
	c->instance_serial = 0;
	c->interface = NULL; /* initializing */
	c->spd.routing = RT_UNROUTED;
	c->newest_ike_sa = SOS_NOBODY;
	c->newest_ipsec_sa = SOS_NOBODY;
	c->spd.eroute_owner = SOS_NOBODY;
	c->temp_vars.num_redirects = 0;
	/*
	 * is spd.reqid necessary for all c? CK_INSTANCE or CK_PERMANENT
	 * need one. Does CK_TEMPLATE need one?
	 */
	c->spd.reqid = c->sa_reqid == 0 ? gen_reqid() : c->sa_reqid;
	dbg(PRI_CONNECTION" c->spd.reqid=%d because c->sa_reqid=%d",
	    pri_connection(c, &cb),
	    c->spd.reqid, c->sa_reqid);

	/*
	 * determine the wild side (the side that likely won't
	 * orient).
	 */
	struct end *wild_side =
		(!address_is_specified(c->local->host.addr) ||
		 c->spd.this.config->client.protoport.has_port_wildcard ||
		 id_has_wildcards(&c->local->host.id) ? &c->spd.this : &c->spd.that);

	/* force all oppo connections to have a client */
	if (c->policy & POLICY_OPPORTUNISTIC) {
		wild_side->has_client = true;
		wild_side->client.maskbits = 0; /* ??? shouldn't this be 32 for v4? */
		/*
		 * We cannot have unlimited keyingtries for Opportunistic, or else
		 * we gain infinite partial IKE SA's. But also, more than one makes
		 * no sense, since it will be installing a failureshunt (not
		 * negotiationshunt) on the 2nd keyingtry, and try to re-install another
		 * negotiation or failure shunt
		 */
		if (c->sa_keying_tries == 0) {
			c->sa_keying_tries = 1;
			llog(RC_LOG, c->logger,
			     "the connection is Opportunistic, but used keyingtries=0. The specified value was changed to 1");
		}
	}

	if (c->policy & POLICY_GROUP) {
		dbg("connection is group: by policy");
		c->kind = CK_GROUP;
		add_group(c);
	} else if (!NEVER_NEGOTIATE(c->policy) &&
		   !address_is_specified(wild_side->host->addr)) {
		dbg("connection is template: no remote address yet policy negotiate");
		c->kind = CK_TEMPLATE;
	} else if (wild_side->config->client.protoport.has_port_wildcard) {
		dbg("connection is template: remote has wildcard port");
		c->kind = CK_TEMPLATE;
	} else if (c->config->ike_version == IKEv2 && c->config->sec_label.len > 0) {
		dbg("connection is template: has security label: "PRI_SHUNK,
		    pri_shunk(c->config->sec_label));
		c->kind = CK_TEMPLATE;
	} else if (wm->left.virt != NULL || wm->right.virt != NULL) {
		/*
		 * If we have a subnet=vnet: needing instantiation
		 * so we can accept multiple subnets from
		 * the remote peer.
		 */
		dbg("connection is template: there are vnets at play");
		c->kind = CK_TEMPLATE;
	} else if (c->policy & POLICY_IKEV2_ALLOW_NARROWING) {
		dbg("connection is template: POLICY_IKEV2_ALLOW_NARROWING");
		c->kind = CK_TEMPLATE;
	} else {
		dbg("connection is permanent: by default");
		c->kind = CK_PERMANENT;
	}

	set_policy_prio(c); /* must be after kind is set */

	c->extra_debugging = wm->debugging;

	/* at most one virt can be present */
	passert(wm->left.virt == NULL || wm->right.virt == NULL);

	if (wm->left.virt != NULL || wm->right.virt != NULL) {
		/*
		 * This now happens with wildcards on
		 * non-instantiations, such as rightsubnet=vnet:%priv
		 * or rightprotoport=17/%any
		 *
		 * passert(!address_is_specified(wild_side->host->addr))
		 */
		passert(wild_side->virt == NULL);
		wild_side->virt =
			create_virtual(wm->left.virt != NULL ? wm->left.virt : wm->right.virt,
				       c->logger);
		if (wild_side->virt != NULL)
			wild_side->has_client = true;
	}

	if (c->pool !=  NULL)
		reference_addresspool(c);

	/* non configurable */
	c->ike_window = IKE_V2_OVERLAPPING_WINDOW_SIZE;

	/*
	 * All done, enter it into the databases.  Since orient() may
	 * switch ends, triggering an spd rehash, insert things into
	 * the database first.
	 */
	hash_connection(c);

	/* this triggers a rehash of the SPDs */
	orient(c, c->logger);

	connect_to_host_pair(c);

	return true;
}

void add_connection(const struct whack_message *wm, struct logger *logger)
{
	/*
	 * Check for duplicate before allocating; otherwise the lookup
	 * will return the just allocated connection missing the
	 * original.
	 */
	if (conn_by_name(wm->name, false/*!strict*/) != NULL) {
		llog(RC_DUPNAME, logger,
		     "attempt to redefine connection \"%s\"", wm->name);
		return;
	}

	struct connection *c = alloc_connection(wm->name, HERE);
	/* XXX: something better? */
	fd_delref(&c->logger->global_whackfd);
	c->logger->global_whackfd = fd_addref(logger->global_whackfd);

	if (!extract_connection(wm, c)) {
		/* already logged */
		discard_connection(&c, false/*not-valid*/);
		return;
	}

	/* log all about this connection */

	/* slightly different names compared to pluto_constants.c */
	static const char *const policy_shunt_names[SHUNT_POLICY_ROOF] = {
		[SHUNT_UNSET] = "[should not happen]",
		[SHUNT_TRAP] = "trap[should not happen]",
		[SHUNT_NONE] = "none",
		[SHUNT_PASS] = "passthrough",
		[SHUNT_DROP] = "drop",
		[SHUNT_REJECT] = "reject",
	};

	const char *what = (NEVER_NEGOTIATE(c->policy) ? policy_shunt_names[c->config->prospective_shunt] :
			    c->config->ike_version == IKEv1 ? "IKEv1" :
			    c->config->ike_version == IKEv2 ? "IKEv2" :
			    "IKEv?");
	/* connection is good-to-go: log against it */
	llog(RC_LOG, c->logger, "added %s connection", what);
	policy_buf pb;
	dbg("ike_life: %jd; ipsec_life: %jds; rekey_margin: %jds; rekey_fuzz: %lu%%; keyingtries: %lu; replay_window: %u; policy: %s",
	    deltasecs(c->sa_ike_life_seconds),
	    deltasecs(c->sa_ipsec_life_seconds),
	    deltasecs(c->sa_rekey_margin),
	    c->sa_rekey_fuzz,
	    c->sa_keying_tries,
	    c->sa_replay_window,
	    str_connection_policies(c, &pb));
	char topo[CONN_BUF_LEN];
	dbg("%s", format_connection(topo, sizeof(topo), c, &c->spd));
	/* XXX: something better? */
	fd_delref(&c->logger->global_whackfd);
}

/*
 * Derive a template connection from a group connection and target.
 * Similar to instantiate().  Happens at whack --listen.  Returns name
 * of new connection.  NULL on failure (duplicated name).  Caller is
 * responsible for pfreeing name.
 */
struct connection *add_group_instance(struct connection *group,
				      const ip_selector *target,
				      uint8_t proto, uint16_t sport , uint16_t dport)
{
	passert(group->kind == CK_GROUP);
	passert(oriented(group));

	/*
	 * Manufacture a unique name for this template.
	 */
	char *namebuf; /* must free */

	subnet_buf targetbuf;
	str_selector_subnet(target, &targetbuf);

	if (proto == 0) {
		namebuf = alloc_printf("%s#%s", group->name, targetbuf.buf);
	} else {
		namebuf = alloc_printf("%s#%s-(%d--%d--%d)", group->name,
				       targetbuf.buf, sport, proto, dport);
	}

	if (conn_by_name(namebuf, false/*!strict*/) != NULL) {
		llog(RC_DUPNAME, group->logger,
		     "group name + target yields duplicate name \"%s\"", namebuf);
		pfreeany(namebuf);
		return NULL;
	}

	struct connection *t = clone_connection(namebuf, group, HERE);
	passert(namebuf != t->name); /* see clone_connection() */
	pfreeany(namebuf);
	t->foodgroup = t->name; /* XXX: DANGER: unshare_connection() will clone this */

	/* suppress virt before unsharing */
	passert(t->spd.this.virt == NULL);

	pexpect(t->spd.spd_next == NULL);	/* we only handle top spd */

	if (t->spd.that.virt != NULL) {
		DBG_log("virtual_ip not supported in group instance; ignored");
		virtual_ip_delref(&t->spd.that.virt, HERE);
	}

	unshare_connection(t, group);
	passert(t->foodgroup != t->name); /* XXX: see DANGER above */

	t->spd.that.client = *target;	/* hashed below */
	if (proto != 0) {
		/* if foodgroup entry specifies protoport, override protoport= settings */
		update_selector_ipproto(&t->spd.this.client, proto);
		update_selector_ipproto(&t->spd.that.client, proto);
		update_selector_hport(&t->spd.this.client, sport);
		update_selector_hport(&t->spd.that.client, dport);
	}
	t->policy &= ~(POLICY_GROUP | POLICY_GROUTED);
	t->policy |= POLICY_GROUPINSTANCE; /* mark as group instance for later */
	t->kind = (!address_is_specified(t->remote->host.addr) &&
		   !NEVER_NEGOTIATE(t->policy)) ? CK_TEMPLATE : CK_INSTANCE;

	/* reset log file info */
	t->log_file_name = NULL;
	t->log_file = NULL;
	t->log_file_err = false;

	t->spd.reqid = group->sa_reqid == 0 ? gen_reqid() : group->sa_reqid;
	dbg("%s t->spd.reqid=%d because group->sa_reqid=%d",
	    t->name, t->spd.reqid, group->sa_reqid);

	/* same host_pair as parent: stick after parent on list */
	/* t->hp_next = group->hp_next; */	/* done by clone_thing */
	group->hp_next = t;

	/* all done */
	hash_connection(t);

	/* route if group is routed */
	if (group->policy & POLICY_GROUTED) {
		/* XXX: something better? */
		fd_delref(&t->logger->global_whackfd);
		t->logger->global_whackfd = fd_addref(group->logger->global_whackfd);
		if (!trap_connection(t)) {
			llog(WHACK_STREAM|RC_ROUTE, group->logger,
			     "could not route");
		}
		/* XXX: something better? */
		fd_delref(&t->logger->global_whackfd);
	}
	return t;
}

/*
 * Common part of instantiating a Road Warrior or Opportunistic connection.
 * peers_id can be used to carry over an ID discovered in Phase 1.
 * It must not disagree with the one in c, but if that is unspecified,
 * the new connection will use peers_id.
 * If peers_id is NULL, and c.that.id is uninstantiated (ID_NONE), the
 * new connection will continue to have an uninstantiated that.id.
 * Note: instantiation does not affect port numbers.
 *
 * Note that instantiate can only deal with a single SPD/eroute.
 */
struct connection *instantiate(struct connection *c,
			       const ip_address *peer_addr,
			       const struct id *peer_id,
			       shunk_t sec_label)
{
	passert(c->kind == CK_TEMPLATE);
	passert(c->spd.spd_next == NULL);

	/*
	 * Is the new connection still a template?
	 *
	 * For instance, a responder with a template connection T with
	 * both remote=%any and configuration sec_label will:
	 *
	 * - during IKE_SA_INIT, instantiate T with the remote
         *   address; creating a new template T.IKE (since the
         *   negotiated sec_label isn't known it is still a template)
	 *
	 * - during IKE_AUTH (or CREATE_CHILD_SA), instantiate T.IKE
	 *   with the Child SA's negotiated SEC_LABEL creating the
	 *   connection instance C.CHILD
	 */
	enum connection_kind kind;
	if (c->config->sec_label.len > 0) {
		/*
		 * Either:
		 *
		 * - C is T, and D is T.IKE (the remote address is
		 *   updated below) -> CK_TEMPLATE
		 *
		 * Or:
		 *
		 * - or C is T.IKE and D is C.CHILD (the sec_label is
		 *   updated below) -> CK_INSTANCE
		 */
		pexpect(address_is_specified(c->remote->host.addr) || peer_addr != NULL);
		if (sec_label.len == 0) {
			kind = CK_TEMPLATE;
		} else {
			kind = CK_INSTANCE;
		}
	} else {
		/* pexpect(address_is_specified(c->remote->host.addr) || peer_addr != NULL); true??? */
		kind = CK_INSTANCE;
	}

	c->instance_serial++;
	struct connection *d = clone_connection(c->name, c, HERE);
	passert(c->name != d->name); /* see clone_connection() */
	if (peer_id != NULL) {
		int wildcards;	/* value ignored */

		passert(d->remote->host.id.kind == ID_FROMCERT ||
			match_id("", peer_id, &d->remote->host.id, &wildcards));
		d->remote->host.id = *peer_id;
	}
	unshare_connection(d, c);
	d->kind = kind;
	passert(oriented(d));
	if (peer_addr != NULL) {
		d->remote->host.addr = *peer_addr;
	}
	update_ends_from_this_host_addr(&d->spd.that, &d->spd.this);

	/*
	 * We cannot guess what our next_hop should be, but if it was
	 * explicitly specified as 0.0.0.0, we set it to be peer.
	 * (whack will not allow nexthop to be elided in RW case.)
	 */
	update_ends_from_this_host_addr(&d->spd.this, &d->spd.that);
	d->spd.spd_next = NULL;

	d->spd.reqid = c->sa_reqid == 0 ? gen_reqid() : c->sa_reqid;
	dbg("%s d->spd.reqid=%d because c->sa_reqid=%d",
	    d->name, d->spd.reqid, c->sa_reqid);

	/* since both ends updated; presumably already oriented? */
	set_policy_prio(d);

	/* set internal fields */
	d->spd.routing = RT_UNROUTED;
	d->newest_ike_sa = SOS_NOBODY;
	d->newest_ipsec_sa = SOS_NOBODY;
	d->spd.eroute_owner = SOS_NOBODY;

	/* reset log file info */
	d->log_file_name = NULL;
	d->log_file = NULL;
	d->log_file_err = false;

	if (c->sa_marks.in.unique) {
		d->sa_marks.in.val = global_marks;
		d->sa_marks.out.val = global_marks;
		global_marks++;
		if (global_marks == UINT_MAX - 1) {
			/* we hope 2^32 connections ago are no longer around */
			global_marks = MINIMUM_IPSEC_SA_RANDOM_MARK;
		}
	}

	/* assumption: orientation is the same as c's */
	connect_to_host_pair(d);

	if (sec_label.len > 0) {
		/*
		 * Install the sec_label from either an acquire or
		 * child payload into both ends.
		 */
		FOR_EACH_THING(end, &d->spd.this, &d->spd.that) {
			pexpect(end->sec_label.ptr == NULL);
			end->sec_label = clone_hunk(sec_label, "instantiate() sec_label");
		}
	}

	/* all done */
	hash_connection(d);

	connection_buf cb, db;
	address_buf pab;
	id_buf pib;
	dbg("instantiated "PRI_CO" "PRI_CONNECTION" as "PRI_CO" "PRI_CONNECTION" using kind=%s remote_address=%s remote_id=%s sec_label="PRI_SHUNK,
	    pri_co(c->serialno), pri_connection(c, &cb),
	    pri_co(d->serialno), pri_connection(d, &db),
	    enum_name(&connection_kind_names, d->kind),
	    peer_addr != NULL ? str_address(peer_addr, &pab) : "N/A",
	    peer_id != NULL ? str_id(peer_id, &pib) : "N/A",
	    pri_shunk(d->spd.this.sec_label));

	return d;
}

struct connection *rw_instantiate(struct connection *c,
				  const ip_address *peer_addr,
				  const ip_selector *peer_subnet,
				  const struct id *peer_id)
{
	struct connection *d = instantiate(c, peer_addr, peer_id, null_shunk);

	if (peer_subnet != NULL && is_virtual_connection(c)) {
		d->spd.that.client = *peer_subnet;
		rehash_db_spd_route_remote_client(&d->spd);
		if (selector_eq_address(*peer_subnet, *peer_addr))
			d->spd.that.has_client = false;
	}

	if (d->policy & POLICY_OPPORTUNISTIC) {
		/*
		 * This must be before we know the client addresses.
		 * Fill in one that is impossible. This prevents anyone else
		 * from trying to use this connection to get to a particular
		 * client
		 */
		d->spd.that.client = selector_type(&d->spd.that.client)->selector.zero;
		rehash_db_spd_route_remote_client(&d->spd);
	}
	connection_buf inst;
	address_buf b;
	dbg("rw_instantiate() instantiated "PRI_CONNECTION" for %s",
	    pri_connection(d, &inst),
	    str_address(peer_addr, &b));
	return d;
}

/* priority formatting */
size_t jam_policy_prio(struct jambuf *buf, policy_prio_t pp)
{
	if (pp == BOTTOM_PRIO) {
		return jam_string(buf, "0");
	}

	return jam(buf, "%" PRIu32 ",%" PRIu32,
		   pp >> 17, (pp & ~(~(policy_prio_t)0 << 17)) >> 8);
}

const char *str_policy_prio(policy_prio_t pp, policy_prio_buf *buf)
{
	struct jambuf jb = ARRAY_AS_JAMBUF(buf->buf);
	jam_policy_prio(&jb, pp);
	return buf->buf;
}

void set_policy_prio(struct connection *c)
{
	c->policy_prio = (((policy_prio_t)c->spd.this.client.maskbits << 17) |
			  ((policy_prio_t)c->spd.that.client.maskbits << 8) |
			  ((policy_prio_t)1));
}

/*
 * Format any information needed to identify an instance of a connection.
 * Fills any needed information into buf which MUST be big enough.
 * Road Warrior: peer's IP address
 * Opportunistic: [" " myclient "==="] " ..." peer ["===" peer_client] '\0'
 */

static size_t jam_connection_client(struct jambuf *b,
				    const char *prefix, const char *suffix,
				    const ip_selector client,
				    const ip_address host_addr)
{
	size_t s = 0;
	if (selector_range_eq_address(client, host_addr)) {
		/* compact denotation for "self" */
	} else {
		s += jam_string(b, prefix);
		if (client.is_set) {
			s += jam_selector_subnet(b, &client);
			if (selector_is_zero(client)) {
				s += jam_string(b, "?");
			}
		} else {
			s += jam_string(b, "?");
		}
		s += jam_string(b, suffix);
	}
	return s;
}

size_t jam_connection_instance(struct jambuf *buf, const struct connection *c)
{
	if (!pexpect(c->kind == CK_INSTANCE ||
		     c->kind == CK_GOING_AWAY)) {
		return 0;
	}
	size_t s = 0;
	if (c->instance_serial != 0) {
		s += jam(buf, "[%lu]", c->instance_serial);
	}
	if (c->policy & POLICY_OPPORTUNISTIC) {
		s += jam_connection_client(buf, " ", "===",
					   c->spd.this.client,
					   c->local->host.addr);
		s += jam_string(buf, " ...");
		s += jam_address(buf, &c->remote->host.addr);
		s += jam_connection_client(buf, "===", "",
					   c->spd.that.client,
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
	s += jam(buf, "\"%s\"", c->name);
	if (c->kind == CK_INSTANCE || c->kind == CK_GOING_AWAY) {
		s += jam_connection_instance(buf, c);
	}
	return s;
}

const char *str_connection_instance(const struct connection *c, connection_buf *buf)
{
	struct jambuf p = ARRAY_AS_JAMBUF(buf->buf);
	if (c->kind == CK_INSTANCE) {
		jam_connection_instance(&p, c);
	}
	return buf->buf;
}

size_t jam_connection_policies(struct jambuf *buf, const struct connection *c)
{
	const char *sep = "";
	size_t s = 0;
	lset_t shunt;

	if (c->config->ike_version > 0) {
		s += jam_enum(buf, &ike_version_names, c->config->ike_version);
		sep = "+";
	}

	lset_t other = c->policy;
	if (other != LEMPTY) {
		s += jam_string(buf, sep);
		s += jam_lset_short(buf, &sa_policy_bit_names, "+", other);
		sep = "+";
	}

	shunt = c->config->prospective_shunt;
	if (shunt != SHUNT_TRAP) {
		s += jam_string(buf, sep);
		s += jam_enum_short(buf, &shunt_policy_names, shunt);
		sep = "+";
	}

	shunt = c->config->negotiation_shunt;
	if (shunt != SHUNT_HOLD) {
		s += jam_string(buf, sep);
		s += jam_string(buf, "NEGO_");
		s += jam_enum_short(buf, &shunt_policy_names, shunt);
		sep = "+";
	}

	shunt = c->config->failure_shunt;
	if (shunt != SHUNT_NONE) {
		s += jam_string(buf, sep);
		s += jam_string(buf, "failure");
		s += jam_enum_short(buf, &shunt_policy_names, shunt);
		sep = "+";
	}

	if (NEVER_NEGOTIATE(c->policy)) {
		jam(buf, "%sNEVER_NEGOTIATE", sep);
		sep = "+";
	}

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
 *   + this connection is routed or instance_of_routed_template
 *     (i.e. approved for on-demand)
 *   + this subnet contains our_client (or we are our_client)
 *   + that subnet contains peer_client (or peer is peer_client)
 *   + don't care about Phase 1 IDs (we don't know)
 * Note: result may still need to be instantiated.
 * The winner has the highest policy priority.
 *
 * If there are several with that priority, we give preference to the
 * first one that is an instance.
 *
 * See also find_outgoing_opportunistic_template().
 */

struct connection *find_connection_for_packet(struct spd_route **srp,
					      const ip_packet packet,
					      shunk_t sec_label,
					      struct logger *logger)
{
	packet_buf pb;
	dbg("%s() looking for an out-going connection that matches packet %s sec_label="PRI_SHUNK,
	    __func__, str_packet(&packet, &pb), pri_shunk(sec_label));

	const ip_selector packet_src = packet_src_selector(packet);
	const ip_endpoint packet_dst = packet_dst_endpoint(packet);

	struct connection *best_connection = NULL;
	policy_prio_t best_priority = BOTTOM_PRIO;
	struct spd_route *best_sr = NULL;

	struct connection_filter cq = { .where = HERE, };
	while (next_connection_new2old(&cq)) {
		struct connection *c = cq.c;

		if (c->kind == CK_GROUP) {
			connection_buf cb;
			dbg("    skipping "PRI_CONNECTION"; a food group",
			    pri_connection(c, &cb));
			continue;
		}

		/*
		 * For both IKEv1 and IKEv2 labeled IPsec, don't try
		 * to mix 'n' match acquire sec_label with
		 * non-sec_label connection.
		 */
		if ((sec_label.len > 0) != (c->config->sec_label.len > 0)) {
			connection_buf cb;
			dbg("    skipping "PRI_CONNECTION"; %s have a sec_label",
			    pri_connection(c, &cb),
			    (sec_label.len > 0 ? "must" : "must not"));
			continue;
		}

		/*
		 * For IKEv2 labeled IPsec, always start with the
		 * template.  Who are we to argue if the kernel asks
		 * for a new SA with, seemingly, a security label that
		 * matches an existing connection instance.
		 */
		if (c->config->ike_version == IKEv2 &&
		    c->config->sec_label.len > 0 &&
		    c->kind != CK_TEMPLATE) {
			pexpect(c->kind == CK_INSTANCE);
			connection_buf cb;
			dbg("    skipping "PRI_CONNECTION"; IKEv2 sec_label connection is not a template",
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
			dbg("    skipping "PRI_CONNECTION"; packet sec_label="PRI_SHUNK" not within connection sec_label="PRI_SHUNK,
			    pri_connection(c, &cb), pri_shunk(sec_label),
			    pri_shunk(c->config->sec_label));
			continue;
		}

		for (struct spd_route *sr = &c->spd;
		     /* bail if below sets BEST_CONECTION to C */
		     best_connection != c && sr != NULL;
		     sr = sr->spd_next) {

			/*
			 * XXX: is the !sec_label an IKEv1 thing?  An
			 * IKEv2 sec-labeled connection should have
			 * been routed by now?
			 */
			if (!routed(sr->routing) &&
			    !c->instance_initiation_ok &&
			    c->config->sec_label.len == 0) {
				connection_buf cb;
				selectors_buf sb;
				dbg("    skipping "PRI_CONNECTION" %s; !routed,!instance_initiation_ok,!sec_label",
				    pri_connection(c, &cb),
				    str_selectors(&c->spd.this.client, &c->spd.that.client, &sb));
				continue;
			}

			/*
			 * The triggering packet needs to be within
			 * the client.
			 *
			 * SRC is a selector, and not endpoint.  When
			 * the source port passed into the kernel is
			 * ephemeral (i.e., passed in as zero) that
			 * same ephemeral (zero) port is passed on to
			 * pluto, and a zero (unknown) port is not
			 * valid for an endpoint.
			 *
			 * DST, OTOH, is a proper endpoint.
			 */

			if (!selector_in_selector(packet_src, sr->this.client)) {
				connection_buf cb;
				selectors_buf sb;
				selector_buf psb;
				dbg("    skipping "PRI_CONNECTION" %s; packet src %s not in range",
				    pri_connection(c, &cb),
				    str_selectors(&c->spd.this.client, &c->spd.that.client, &sb),
				    str_selector(&packet_src, &psb));
				continue;
			}

			if (!endpoint_in_selector(packet_dst, sr->that.client)) {
				connection_buf cb;
				selectors_buf sb;
				endpoint_buf eb;
				dbg("    skipping "PRI_CONNECTION" %s; packet dst %s not in range",
				    pri_connection(c, &cb),
				    str_selectors(&c->spd.this.client, &c->spd.that.client, &sb),
				    str_endpoint(&packet_dst, &eb));
				continue;
			}

			/*
			 * More exact is better and bigger
			 *
			 * For instance, exact protocol or exact port
			 * gets more points.
			 */
			policy_prio_t priority =
				(8 * (c->policy_prio + (c->kind == CK_INSTANCE)) +
				 2 * (sr->this.client.hport == packet.src.hport) +
				 2 * (sr->that.client.hport == packet.dst.hport) +
				 1 * (sr->this.client.ipproto == packet.protocol->ipproto));

			if (best_connection != NULL &&
			    priority <= best_priority) {
				connection_buf cb, bcb;
				selectors_buf sb, bsb;
				dbg("    skipping "PRI_CONNECTION" %s priority %"PRIu32"; doesn't best "PRI_CONNECTION" %s priority %"PRIu32,
				    pri_connection(c, &cb),
				    str_selectors(&c->spd.this.client, &c->spd.that.client, &sb),
				    priority,
				    pri_connection(best_connection, &bcb),
				    str_selectors(&best_sr->this.client, &best_sr->that.client, &bsb),
				    best_priority);
				continue;
			}

			/* current is best; log why */
			if (best_connection == NULL) {
				connection_buf cb;
				selectors_buf sb;
				dbg("    choosing "PRI_CONNECTION" %s priority %"PRIu32" child %s; as first best",
				    pri_connection(c, &cb),
				    str_selectors(&c->spd.this.client, &c->spd.that.client, &sb),
				    priority,
				    (c->policy_next != NULL ? c->policy_next->name : "none"));
			} else {
				connection_buf cb, bcb;
				selectors_buf sb, bsb;
				dbg("    choosing "PRI_CONNECTION" %s priority %"PRIu32" child %s; as bests "PRI_CONNECTION" %s priority %"PRIu32,
				    pri_connection(c, &cb),
				    str_selectors(&c->spd.this.client, &c->spd.that.client, &sb),
				    priority,
				    (c->policy_next != NULL ? c->policy_next->name : "none"),
				    pri_connection(best_connection, &bcb),
				    str_selectors(&best_sr->this.client, &best_sr->that.client, &bsb),
				    best_priority);
			}

			best_connection = c;
			best_sr = sr;
			best_priority = priority;
		}
	}

	/*
	 * XXX: So that the best connection can prevent negotiation?
	 */
	if (best_connection != NULL && NEVER_NEGOTIATE(best_connection->policy)) {
		best_connection = NULL;
	}

	if (best_connection != NULL) {
		connection_buf cib;
		selectors_buf sb;
		enum_buf kb;
		dbg("  concluding with "PRI_CONNECTION" %s priority %" PRIu32 " kind=%s",
		    pri_connection(best_connection, &cib),
		    str_selectors(&best_sr->this.client, &best_sr->that.client, &sb),
		    best_priority,
		    str_enum_short(&connection_kind_names, best_connection->kind, &kb));
	} else {
		dbg("  concluding with empty");
	}

	if (srp != NULL && best_connection != NULL) {
		*srp = best_sr;
	}
	return best_connection;
}

struct connection *oppo_instantiate(struct connection *c,
				    const struct id *remote_id,
				    /* both host and client */
				    const ip_address *local_address,
				    const ip_address *remote_address)
{
	passert(local_address != NULL);
	passert(remote_address != NULL);
	address_buf lb, rb;
	connection_buf cb;
	dbg("oppo instantiating "PRI_CONNECTION" with routing %s between %s -> %s",
	    pri_connection(c, &cb), enum_name(&routing_story, c->spd.routing),
	    str_address(local_address, &lb), str_address(remote_address, &rb));

	struct connection *d = instantiate(c, remote_address, remote_id, null_shunk);

	passert(d->spd.spd_next == NULL);

	/*
	 * Fill in (or fix up) our client side.
	 */

	const struct ip_protocol *local_protocol = selector_protocol(c->spd.this.client);
	ip_port local_port = selector_port(c->spd.this.client);
	dbg("oppo local(c) protocol %s port %d",
	    local_protocol->name,
	    local_port.hport);

	if (d->spd.this.has_client) {
		/*
		 * There was a client in the abstract connection so we
		 * demand that either ...
		 */

		/* opportunistic connections do not use port selectors */
		if (address_in_selector_range(*local_address, d->spd.this.client)) {
			/*
			 * the required client is within that subnet
			 * narrow it(?), ...
			*/
			d->spd.this.client =
				selector_from_address_protocol_port(*local_address,
								    local_protocol,
								    local_port);
		} else if (address_eq_address(*local_address, d->local->host.addr)) {
			/*
			 * or that it is our private ip in case we are
			 * behind a port forward.
			 */
			update_selector_hport(&d->spd.this.client, 0);
		} else {
			llog_passert(c->logger, HERE,
				     "local address does not match the host or client");
		}
	} else {
		/*
		 * There was no client in the abstract connection so
		 * we demand that the required client be the host.
		 *
		 * Because instantiate(), when !has_client, updates
		 * client using config->protoport, any proto/port
		 * added to the template is lost.
		 *
		 * XXX: it's all a bit weird.  Should the oppo group
		 * just set the selector and work with that?
		 */
		dbg("oppo local has no client; patching damage by instantiate()");
		passert(address_eq_address(*local_address, d->local->host.addr));
		d->spd.this.client =
			selector_from_address_protocol_port(*local_address,
							    local_protocol,
							    local_port);
	}

	dbg("oppo local(d) protocol %s port %d",
	    selector_protocol(d->spd.this.client)->name,
	    selector_port(d->spd.this.client).hport);

	/*
	 * Fill in peer's client side.
	 * If the client is the peer, excise the client from the connection.
	 */

	dbg("oppo remote(c) protocol %s port %d",
	    selector_protocol(c->spd.that.client)->name,
	    selector_port(c->spd.that.client).hport);

	const struct ip_protocol *remote_protocol = selector_protocol(c->spd.that.client);
	ip_port remote_port = selector_port(c->spd.that.client);
	passert(d->policy & POLICY_OPPORTUNISTIC);
	passert(address_in_selector_range(*remote_address, d->spd.that.client));
	d->spd.that.client = selector_from_address_protocol_port(*remote_address,
								 remote_protocol,
								 remote_port);
	rehash_db_spd_route_remote_client(&d->spd);

	dbg("oppo remote(d) protocol %s port %d",
	    selector_protocol(d->spd.that.client)->name,
	    selector_port(d->spd.that.client).hport);

	if (address_eq_address(*remote_address, d->remote->host.addr))
		d->spd.that.has_client = false;

	/*
	 * Adjust routing if something is eclipsing c.
	 * It must be a %hold for us (hard to passert this).
	 * If there was another instance eclipsing, we'd be using it.
	 */
	if (c->spd.routing == RT_ROUTED_ECLIPSED)
		d->spd.routing = RT_ROUTED_PROSPECTIVE;

	/*
	 * Remember if the template is routed:
	 * if so, this instance applies for initiation
	 * even if it is created for responding.
	 */
	if (routed(c->spd.routing))
		d->instance_initiation_ok = true;

	if (DBGP(DBG_BASE)) {
		char topo[CONN_BUF_LEN];
		connection_buf inst;
		DBG_log("oppo_instantiate() instantiated "PRI_CONNECTION" with routing %s: %s",
			pri_connection(d, &inst),
			enum_name(&routing_story, d->spd.routing),
			format_connection(topo, sizeof(topo), d, &d->spd));
	}
	return d;
}

/*
 * Outgoing opportunistic connection.
 *
 * Find and instantiate a connection for an outgoing Opportunistic connection.
 * We've already discovered its gateway.
 * We look for a connection such that:
 *   + this is one of our interfaces
 *   + this subnet contains our_client (or we are our_client)
 *     (we will specialize the client). We prefer the smallest such subnet.
 *   + that subnet contains peer_clent (we will specialize the client).
 *     We prefer the smallest such subnet.
 *   + is opportunistic
 *   + that peer is NO_IP
 *   + don't care about Phase 1 IDs (probably should be default)
 * We could look for a connection that already had the desired peer
 * (rather than NO_IP) specified, but it doesn't seem worth the
 * bother.
 *
 * We look for the routed policy applying to the narrowest subnets.
 * We only succeed if we find such a policy AND it is satisfactory.
 *
 * The body of the inner loop is a lot like that in
 * find_connection_for_clients. In this case, we know the gateways
 * that we need to instantiate an opportunistic connection.
 */

struct connection *find_outgoing_opportunistic_template(const ip_packet packet)
{
	/*
	 * Go through all the "half" oriented connections (remote
	 * address is unset) looking for client that matches the
	 * local/remote endpoint.
	 *
	 * Unfortunately there's no good data structure for doing
	 * this, so ...
	 *
	 * Big hack: get the list of local addresses by iterating over
	 * the interface endpoints, and then feed the endpoint's
	 * address into FOR_EACH_HOST_PAIR_CONNECTION(LOCAL,UNSET).
	 */
	struct connection *best = NULL;
	struct spd_route *best_spd_route = NULL;
	struct iface_dev *last_iface_device = NULL;
	for (struct iface_endpoint *p = interfaces; p != NULL; p = p->next) {
		/*
		 * Bigger hack: assume the interface endpoints
		 * (ADDRESS:500 ADDRESS:4500) for a device are grouped
		 * (mostly true, TCP, custom port?) and only search
		 * when a new interface device is found.
		 */
		if (p->ip_dev == last_iface_device) {
			continue;
		}
		last_iface_device = p->ip_dev;
		/*
		 * Go through those connections with our address and
		 * NO_IP as hosts.
		 *
		 * We cannot know what port the peer would use, so we
		 * assume that it is pluto_port (makes debugging
		 * easier).
		 *
		 * XXX: the port doesn't matter!
		 */
		FOR_EACH_HOST_PAIR_CONNECTION(p->ip_dev->id_address, unset_address, c) {

			connection_buf cb;
			dbg("checking "PRI_CONNECTION, pri_connection(c, &cb));

#if 0
			/* REMOTE==%any so d can never be an instance */
			if (c->kind == CK_INSTANCE && c->remote->host.id.kind == ID_NULL) {
				connection_buf cb;
				dbg("skipping unauthenticated "PRI_CONNECTION" with ID_NULL",
				    pri_connection(c, &cb));
				continue;
			}
#endif

			if (c->kind == CK_GROUP)
				continue;

			/*
			 * for each sr of c, see if we have a new best
			 *
			 * Paul: while this code can reject unmatched
			 * conns, it does not find the most narrow
			 * match!
			 */
			for (struct spd_route *sr = &c->spd; sr != NULL; sr = sr->spd_next) {
				if (!routed(sr->routing)) {
					continue;
				}

				/*
				 * The triggering packet needs to be
				 * within the client.
				 *
				 * SRC is a selector, and not
				 * endpoint, as the port can be zero
				 * (aka wild-card).  For instance, a
				 * connect where the src port is
				 * ephemeral is passed to the kernel
				 * as zero and on to pluto as zero.
				 *
				 * DST, OTOH, is a proper endpoint.
				 */
				ip_selector src = packet_src_selector(packet);
				ip_endpoint dst = packet_dst_endpoint(packet);
				if (!selector_in_selector(src, sr->this.client) ||
				    !endpoint_in_selector(dst, sr->that.client)) {
					continue;
				}

				/*
				 * First or better solution.
				 *
				 * The test for better is:
				 *   sr's .this is narrower, or
				 *   sr's .this is same and sr's .that is narrower.
				 * ??? not elegant, not symmetric.
				 * Possible replacement test:
				 *   best_spd_route->this.client.maskbits + best_spd_route->that.client.maskbits >
				 *   sr->this.client.maskbits + sr->that.client.maskbits
				 * but this knows too much about the representation of ip_subnet.
				 * What is the correct semantics?
				 *
				 * XXX: selector_in_selector() is
				 * exclusive - it excludes
				 * selector_eq().
				 */

				if (best_spd_route != NULL &&
				    selector_in_selector(best_spd_route->this.client, sr->this.client)) {
					/*
					 * BEST_SPD_ROUTE is better.
					 *
					 * BEST_SPD_ROUTE's .this is
					 * narrower than .SR's.
					 */
					continue;
				}
				if (best_spd_route != NULL &&
				    selector_eq_selector(best_spd_route->this.client, sr->this.client) &&
				    selector_in_selector(best_spd_route->that.client, sr->that.client)) {
					/*
					 * BEST_SPD_ROUTE is better.
					 *
					 * Since BEST_SPD_ROUTE's
					 * .this matches SR's,
					 * tie-break with
					 * BEST_SPD_ROUTE's .that
					 * being narrower than .SR's.
					 */
					continue;
				}
				best = c;
				best_spd_route = sr;
			}
		}
	}

	if (best == NULL ||
	    NEVER_NEGOTIATE(best->policy) ||
	    (best->policy & POLICY_OPPORTUNISTIC) == LEMPTY ||
	    best->kind != CK_TEMPLATE) {
		return NULL;
	}

	return best;
}

/*
 * Find the connection to connection c's peer's client with the
 * largest value of .routing.  All other things being equal,
 * preference is given to c.  If none is routed, return NULL.
 *
 * If erop is non-null, set *erop to a connection sharing both
 * our client subnet and peer's client subnet with the largest value
 * of .routing.  If none is erouted, set *erop to NULL.
 *
 * The return value is used to find other connections sharing a route.
 * *erop is used to find other connections sharing an eroute.
 */
struct connection *route_owner(struct connection *c,
			       const struct spd_route *cur_spd,
			       struct spd_route **srp,
			       struct connection **erop,
			       struct spd_route **esrp)
{
	if (!oriented(c)) {
		llog(RC_LOG, c->logger,
		     "route_owner: connection no longer oriented - system interface change?");
		return NULL;
	}

	struct connection *best_routing_connection = c;
	struct spd_route *best_routing_spd = NULL;
	enum routing_t best_routing = cur_spd->routing;

	struct connection *best_ero = c;
	struct spd_route *best_esr = NULL;
	enum routing_t best_erouting = best_routing;

	for (const struct spd_route *c_spd = &c->spd;
	     c_spd != NULL; c_spd = c_spd->spd_next) {

		struct spd_route_filter srf = {
			.remote_client_range = &c_spd->that.client,
			.where = HERE,
		};
		while (next_spd_route(NEW2OLD, &srf)) {
			struct spd_route *d_spd = srf.spd;
			struct connection *d = d_spd->connection;

			if (c_spd == d_spd)
				continue;

			if (!oriented(d))
				continue;

			if (d_spd->routing == RT_UNROUTED)
				continue;

			pexpect(selector_range_eq_selector_range(c_spd->that.client, d_spd->that.client));
			if (c_spd->that.client.ipproto != d_spd->that.client.ipproto)
				continue;
			if (c_spd->that.client.hport != d_spd->that.client.hport)
				continue;
			if (!sameaddr(&c_spd->this.host->addr, &d_spd->this.host->addr))
				continue;

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

			if (d_spd->routing > best_routing) {
				best_routing_connection = d;
				best_routing_spd = d_spd;
				best_routing = d_spd->routing;
			}

			if (selector_range_eq_selector_range(c_spd->this.client, d_spd->this.client) &&
			    c_spd->this.client.ipproto == d_spd->this.client.ipproto &&
			    c_spd->this.client.hport == d_spd->this.client.hport &&
			    d_spd->routing > best_erouting) {
				best_ero = d;
				best_esr = d_spd;
				best_erouting = d_spd->routing;
			}

		}
	}

	LSWDBGP(DBG_BASE, buf) {
		connection_buf cib;
		jam(buf, "route owner of \"%s\"%s %s: ",
		    pri_connection(c, &cib),
		    enum_name(&routing_story, cur_spd->routing));

		if (!routed(best_routing)) {
			jam(buf, "NULL");
		} else if (best_routing_connection == c) {
			jam(buf, "self");
		} else {
			connection_buf cib;
			jam(buf, ""PRI_CONNECTION" %s",
			    pri_connection(best_routing_connection, &cib),
			    enum_name(&routing_story, best_routing));
		}

		if (erop != NULL) {
			jam(buf, "; eroute owner: ");
			if (!erouted(best_ero->spd.routing)) {
				jam(buf, "NULL");
			} else if (best_ero == c) {
				jam(buf, "self");
			} else {
				connection_buf cib;
				jam(buf, ""PRI_CONNECTION" %s",
				    pri_connection(best_ero, &cib),
				    enum_name(&routing_story, best_ero->spd.routing));
			}
		}
	}

	if (erop != NULL)
		*erop = erouted(best_erouting) ? best_ero : NULL;

	if (srp != NULL ) {
		*srp = best_routing_spd;
		if (esrp != NULL )
			*esrp = best_esr;
	}

	return routed(best_routing) ? best_routing_connection : NULL;
}

/* signed result suitable for quicksort */
int connection_compare(const struct connection *ca,
		const struct connection *cb)
{
	int ret;

	ret = strcmp(ca->name, cb->name);
	if (ret != 0)
		return ret;

	/* note: enum connection_kind behaves like int */
	ret = ca->kind - cb->kind;
	if (ret != 0)
		return ret;

	/* same name, and same type */
	switch (ca->kind) {
	case CK_INSTANCE:
		return ca->instance_serial < cb->instance_serial ? -1 :
		ca->instance_serial > cb-> instance_serial ? 1 : 0;

	default:
		return (ca->policy_prio < cb->policy_prio ? -1 :
			ca->policy_prio > cb->policy_prio ? 1 : 0);
	}
}

static int connection_compare_qsort(const void *a, const void *b)
{
	return connection_compare(*(const struct connection *const *)a,
				*(const struct connection *const *)b);
}

static void show_one_sr(struct show *s,
			const struct connection *c,
			const struct spd_route *sr,
			const char *instance)
{
	char topo[CONN_BUF_LEN];
	ipstr_buf thisipb, thatipb;

	show_comment(s, PRI_CONNECTION": %s; %s; eroute owner: #%lu",
		     c->name, instance,
		     format_connection(topo, sizeof(topo), c, sr),
		     enum_name(&routing_story, sr->routing),
		     sr->eroute_owner);

#define OPT_HOST(h, ipb)  (address_is_specified(h) ? str_address(&h, &ipb) : "unset")

		/* note: this macro generates a pair of arguments */
#define OPT_PREFIX_STR(pre, s) (s) == NULL ? "" : (pre), (s) == NULL? "" : (s)

	show_comment(s, PRI_CONNECTION":     %s; my_ip=%s; their_ip=%s%s%s%s%s; my_updown=%s;",
		     c->name, instance,
		     oriented(c) ? "oriented" : "unoriented",
		     OPT_HOST(c->spd.this.host_srcip, thisipb),
		     OPT_HOST(c->spd.that.host_srcip, thatipb),
		     OPT_PREFIX_STR("; mycert=", cert_nickname(&c->local->config->host.cert)),
		     OPT_PREFIX_STR("; peercert=", cert_nickname(&c->remote->config->host.cert)),
		     ((sr->this.config->client.updown == NULL ||
		       streq(sr->this.config->client.updown, "%disabled")) ? "<disabled>"
		      : sr->this.config->client.updown));

#undef OPT_HOST
#undef OPT_PREFIX_STR

	/*
	 * Both should not be set, but if they are, we want
	 * to know
	 */
#define COMBO(END, SERVER, CLIENT) \
	((END).SERVER ? \
		((END).CLIENT ? "BOTH??" : "server") : \
		((END).CLIENT ? "client" : "none"))

	show_comment(s, PRI_CONNECTION":   xauth us:%s, xauth them:%s, %s my_username=%s; their_username=%s",
		     c->name, instance,
		     /*
		      * Both should not be set, but if they are, we
		      * want to know.
		      */
		     COMBO(sr->this, config->host.xauth.server, config->host.xauth.client),
		     COMBO(sr->that, config->host.xauth.server, config->host.xauth.client),
		     /* should really be an enum name */
		     (sr->this.config->host.xauth.server ?
		      c->xauthby == XAUTHBY_FILE ?
		      "xauthby:file;" :
		      c->xauthby == XAUTHBY_PAM ?
		      "xauthby:pam;" :
		      "xauthby:alwaysok;" :
		      ""),
		     (sr->this.config->host.xauth.username == NULL ? "[any]" :
		      sr->this.config->host.xauth.username),
		     (sr->that.config->host.xauth.username == NULL ? "[any]" :
		      sr->that.config->host.xauth.username));

	enum_buf auth1, auth2;
	show_comment(s, PRI_CONNECTION":   our auth:%s, their auth:%s, our autheap:%s, their autheap:%s;",
		     c->name, instance,
		     str_enum_short(&keyword_auth_names, sr->this.config->host.auth, &auth1),
		     str_enum_short(&keyword_auth_names, sr->that.config->host.auth, &auth2),
		     c->local->config->host.eap == IKE_EAP_NONE ? "none" : "tls",
		     c->remote->config->host.eap == IKE_EAP_NONE ? "none" : "tls"
	);

	show_comment(s, PRI_CONNECTION":   modecfg info: us:%s, them:%s, modecfg policy:%s, dns:%s, domains:%s, cat:%s;",
		     c->name, instance,
		     COMBO(sr->this, modecfg_server, modecfg_client),
		     COMBO(sr->that, modecfg_server, modecfg_client),

		     (c->policy & POLICY_MODECFG_PULL) ? "pull" : "push",
		     (c->modecfg_dns == NULL) ? "unset" : c->modecfg_dns,
		     (c->modecfg_domains == NULL) ? "unset" : c->modecfg_domains,
		     sr->this.cat ? "set" : "unset");

#undef COMBO

	if (c->modecfg_banner != NULL) {
		show_comment(s, PRI_CONNECTION": banner:%s;",
			     c->name, instance, c->modecfg_banner);
	}

	/*
	 * Show the first valid sec_label.
	 *
	 * We only support symmetric labels, but store it in struct
	 * end - pick one.
	 *
	 * XXX: IKEv1 stores the negotiated sec_label in the state.
	 */
	if (sr->this.sec_label.len > 0) {
		/* negotiated (IKEv2) */
		show_comment(s, PRI_CONNECTION":   sec_label:"PRI_SHUNK,
			     c->name, instance,
			     pri_shunk(sr->this.sec_label));
	} else if (c->config->sec_label.len > 0) {
		/* configured */
		show_comment(s, "\"%s\"%s:   sec_label:"PRI_SHUNK,
			     c->name, instance, pri_shunk(c->config->sec_label));
	} else {
		show_comment(s, PRI_CONNECTION":   sec_label:unset;",
			     c->name, instance);
	}
}

void show_one_connection(struct show *s,
			 const struct connection *c)
{
	const char *ifn;
	char ifnstr[2 *  IFNAMSIZ + 2];  /* id_rname@id_vname\0 */
	char instance[32];
	char mtustr[8];
	char sapriostr[13];
	char satfcstr[13];
	char nflogstr[8];
	char markstr[2 * (2 * strlen("0xffffffff") + strlen("/")) + strlen(", ") ];

	if (oriented(c)) {
		if (c->xfrmi != NULL && c->xfrmi->name != NULL) {
			char *n = jam_str(ifnstr, sizeof(ifnstr),
					c->xfrmi->name);
			add_str(ifnstr, sizeof(ifnstr), n, "@");
			add_str(ifnstr, sizeof(ifnstr), n,
					c->interface->ip_dev->id_rname);
			ifn = ifnstr;
		} else {
			ifn = c->interface->ip_dev->id_rname;
		}
	} else {
		ifn = "";
	};

	instance[0] = '\0';
	if (c->kind == CK_INSTANCE && c->instance_serial != 0)
		snprintf(instance, sizeof(instance), "[%lu]",
			c->instance_serial);

	/* Show topology. */
	{
		const struct spd_route *sr = &c->spd;

		while (sr != NULL) {
			show_one_sr(s, c, sr, instance);
			sr = sr->spd_next;
		}
	}

	/* Show CAs */
	if (c->local->config->host.ca.ptr != NULL || c->remote->config->host.ca.ptr != NULL) {
		dn_buf this_ca, that_ca;
		show_comment(s, PRI_CONNECTION":   CAs: '%s'...'%s'",
			     c->name, instance,
			     str_dn_or_null(ASN1(c->local->config->host.ca), "%any", &this_ca),
			     str_dn_or_null(ASN1(c->remote->config->host.ca), "%any", &that_ca));
	}

	show_comment(s, PRI_CONNECTION":   ike_life: %jds; ipsec_life: %jds; replay_window: %u; rekey_margin: %jds; rekey_fuzz: %lu%%; keyingtries: %lu;",
		     c->name, instance,
		     deltasecs(c->sa_ike_life_seconds),
		     deltasecs(c->sa_ipsec_life_seconds),
		     c->sa_replay_window,
		     deltasecs(c->sa_rekey_margin),
		     c->sa_rekey_fuzz,
		     c->sa_keying_tries);

	show_comment(s, PRI_CONNECTION":   retransmit-interval: %jdms; retransmit-timeout: %jds; iketcp:%s; iketcp-port:%d;",
		     c->name, instance,
		     deltamillisecs(c->config->retransmit_interval),
		     deltasecs(c->config->retransmit_timeout),
		     c->iketcp == IKE_TCP_NO ? "no" : c->iketcp == IKE_TCP_ONLY ? "yes" :
		     c->iketcp == IKE_TCP_FALLBACK ? "fallback" : "<BAD VALUE>",
		     c->remote_tcpport);

	show_comment(s, PRI_CONNECTION":   initial-contact:%s; cisco-unity:%s; fake-strongswan:%s; send-vendorid:%s; send-no-esp-tfc:%s;",
		     c->name, instance,
		     bool_str(c->initial_contact),
		     bool_str(c->cisco_unity),
		     bool_str(c->fake_strongswan),
		     bool_str(c->send_vendorid),
		     bool_str(c->send_no_esp_tfc));

	if (c->policy_next != NULL) {
		show_comment(s, PRI_CONNECTION":   policy_next: %s",
			     c->name, instance, c->policy_next->name);
	}

	policy_buf pb;
	show_comment(s, PRI_CONNECTION":   policy: %s%s%s%s;",
		     c->name, instance,
		     str_connection_policies(c, &pb),
		     (c->spd.this.key_from_DNS_on_demand ||
		      c->spd.that.key_from_DNS_on_demand) ? "; " : "",
		     (c->spd.this.key_from_DNS_on_demand ? "+lKOD" : ""),
		     (c->spd.that.key_from_DNS_on_demand ? "+rKOD" : ""));

	if (c->config->ike_version == IKEv2) {
		lset_buf hashpolbuf;
		show_comment(s, PRI_CONNECTION":   v2-auth-hash-policy: %s;",
			     c->name, instance,
			     str_lset_short(&ikev2_hash_algorithm_names, "+",
					    c->config->sighash_policy, &hashpolbuf));
	}

	if (c->connmtu != 0)
		snprintf(mtustr, sizeof(mtustr), "%d", c->connmtu);
	else
		strcpy(mtustr, "unset");

	if (c->sa_priority != 0)
		snprintf(sapriostr, sizeof(sapriostr), "%" PRIu32, c->sa_priority);
	else
		strcpy(sapriostr, "auto");

	if (c->sa_tfcpad != 0)
		snprintf(satfcstr, sizeof(satfcstr), "%u", c->sa_tfcpad);
	else
		strcpy(satfcstr, "none");

	policy_prio_buf prio;
	show_comment(s, PRI_CONNECTION":   conn_prio: %s; interface: %s; metric: %u; mtu: %s; sa_prio:%s; sa_tfc:%s;",
		     c->name, instance,
		     str_policy_prio(c->policy_prio, &prio),
		     ifn,
		     c->metric,
		     mtustr, sapriostr, satfcstr);

	if (c->nflog_group != 0)
		snprintf(nflogstr, sizeof(nflogstr), "%d", c->nflog_group);
	else
		strcpy(nflogstr, "unset");

	if (c->sa_marks.in.val != 0 || c->sa_marks.out.val != 0 ) {
		snprintf(markstr, sizeof(markstr), "%" PRIu32 "/%#08" PRIx32 ", %" PRIu32 "/%#08" PRIx32,
			c->sa_marks.in.val, c->sa_marks.in.mask,
			c->sa_marks.out.val, c->sa_marks.out.mask);
	} else {
		strcpy(markstr, "unset");
	}

	show_comment(s, PRI_CONNECTION":   nflog-group: %s; mark: %s; vti-iface:%s; vti-routing:%s; vti-shared:%s; nic-offload:%s;",
		     c->name, instance,
		     nflogstr, markstr,
		     c->vti_iface == NULL ? "unset" : c->vti_iface,
		     bool_str(c->vti_routing),
		     bool_str(c->vti_shared),
		     (c->config->nic_offload == yna_auto ? "auto" :
		      bool_str(c->config->nic_offload == yna_yes)));

	{
		id_buf thisidb;
		id_buf thatidb;

		show_comment(s, PRI_CONNECTION":   our idtype: %s; our id=%s; their idtype: %s; their id=%s",
			     c->name, instance,
			     enum_name(&ike_id_type_names, c->local->host.id.kind),
			     str_id(&c->local->host.id, &thisidb),
			     enum_name(&ike_id_type_names, c->remote->host.id.kind),
			     str_id(&c->remote->host.id, &thatidb));
	}

	switch (c->config->ike_version) {
	case IKEv1:
	{
		enum_buf eb;
		show_comment(s, PRI_CONNECTION":   dpd: %s; action:%s; delay:%jds; timeout:%jds",
			     c->name, instance,
			     (deltasecs(c->config->dpd.delay) > 0 &&
			      deltasecs(c->config->dpd.timeout) > 0 ? "active" : "passive"),
			     str_enum_short(&dpd_action_names, c->config->dpd.action, &eb),
			     deltasecs(c->config->dpd.delay),
			     deltasecs(c->config->dpd.timeout));
		break;
	}
	case IKEv2:
	{
		enum_buf eb;
		show_comment(s, PRI_CONNECTION":   liveness: %s; dpdaction:%s; dpddelay:%jds; retransmit-timeout:%jds",
			     c->name, instance,
			     deltasecs(c->config->dpd.delay) > 0 ? "active" : "passive",
			     str_enum_short(&dpd_action_names, c->config->dpd.action, &eb),
			     deltasecs(c->config->dpd.delay),
			     deltasecs(c->config->retransmit_timeout));
		break;
	}
	}

	SHOW_JAMBUF(RC_COMMENT, s, buf) {
		jam(buf, PRI_CONNECTION":   nat-traversal: encaps:%s",
		    c->name, instance,
		    (c->encaps == yna_auto ? "auto" :
		     bool_str(c->encaps == yna_yes)));
		jam_string(buf, "; keepalive:");
		if (c->nat_keepalive) {
			jam(buf, "%jds", deltasecs(nat_keepalive_period));
		} else {
			jam_string(buf, bool_str(false));
		}
		if (c->config->ike_version == IKEv1) {
			jam_string(buf, "; ikev1-method:");
			switch (c->ikev1_natt) {
			case NATT_BOTH: jam_string(buf, "rfc+drafts"); break;
			case NATT_RFC: jam_string(buf, "rfc"); break;
			case NATT_DRAFTS: jam_string(buf, "drafts"); break;
			case NATT_NONE: jam_string(buf, "none"); break;
			default: bad_case(c->ikev1_natt);
			}
		}
	}

	if (!lmod_empty(c->extra_debugging)) {
		SHOW_JAMBUF(RC_COMMENT, s, buf) {
			jam(buf, PRI_CONNECTION":   debug: ",
			    c->name, instance);
			jam_lmod(buf, &debug_names, "+", c->extra_debugging);
		}
	}

	SHOW_JAMBUF(RC_COMMENT, s, buf) {
		jam(buf, PRI_CONNECTION":   newest ISAKMP SA: #%lu; newest IPsec SA: #%lu; conn serial: "PRI_CO"",
		    c->name, instance,
		    c->newest_ike_sa,
		    c->newest_ipsec_sa,
		    pri_co(c->serialno));
		if (c->serial_from != UNSET_CO_SERIAL) {
			jam(buf, ", instantiated from: "PRI_CO";",
			    pri_co(c->serial_from));
		} else {
			jam(buf, ";");
		}
	}

	if (c->connalias != NULL) {
		show_comment(s, PRI_CONNECTION":   aliases: %s",
			     c->name, instance,
			     c->connalias);
	}

	show_ike_alg_connection(s, c, instance);
	show_kernel_alg_connection(s, c, instance);
}

void show_connections_status(struct show *s)
{
	int count = 0;
	int active = 0;

	show_separator(s);
	show_comment(s, "Connection list:");
	show_separator(s);

	struct connection_filter cq = { .where = HERE, };
	while (next_connection_new2old(&cq)) {
		struct connection *c = cq.c;
		count++;
		if (c->spd.routing == RT_ROUTED_TUNNEL)
			active++;
	}

	if (count != 0) {
		/* make an array of connections, sort it, and report it */

		struct connection **array =
			alloc_bytes(sizeof(struct connection *) * count,
				"connection array");
		int i = 0;


		struct connection_filter cq = { .where = HERE, };
		while (next_connection_new2old(&cq)) {
			array[i++] = cq.c;
		}

		/* sort it! */
		qsort(array, count, sizeof(struct connection *),
			connection_compare_qsort);

		for (i = 0; i < count; i++)
			show_one_connection(s, array[i]);

		pfree(array);
		show_separator(s);
	}

	show_comment(s, "Total IPsec connections: loaded %d, active %d",
		     count, active);
}

/*
 * Delete a connection if
 * - it is an instance and it is no longer in use.
 * - the ike state is not shared with another connection
 * We must be careful to avoid circularity:
 * we don't touch it if it is CK_GOING_AWAY.
 */
void connection_delete_unused_instance(struct connection **cp,
				       struct state *old_state,
				       struct fd *whackfd)
{
	struct connection *c = (*cp);
	*cp = NULL;

	if (c->kind != CK_INSTANCE) {
		connection_buf cb;
		dbg("connection "PRI_CONNECTION" is not an instance, skipping delete-unused",
		    pri_connection(c, &cb));
		return;
	}

	if (connection_is_pending(c)) {
		connection_buf cb;
		dbg("connection "PRI_CONNECTION" is pending, skipping delete-unused",
		    pri_connection(c, &cb));
		return;
	}

	if (LIN(POLICY_UP, c->policy) &&
	    old_state != NULL && (IS_IKE_SA_ESTABLISHED(old_state) ||
				  IS_V1_ISAKMP_SA_ESTABLISHED(old_state))) {
		/*
		 * If this connection instance was previously for an
		 * established sa planning to revive, don't delete.
		 */
		connection_buf cb;
		dbg("connection "PRI_CONNECTION" with serial "PRI_CO" is being revived, skipping delete-unused",
		    pri_connection(c, &cb), pri_co(c->serialno));
		return;
	}

	/* see of a state, any state, is using the connection */
	struct state_filter sf = {
		.connection_serialno = c->serialno,
		.where = HERE,
	};
	if (next_state_new2old(&sf)) {
		connection_buf cb;
		dbg("connection "PRI_CONNECTION" in use by #%lu, skipping delete-unused",
		    pri_connection(c, &cb), sf.st->st_serialno);
		return;
	}

	connection_buf cb;
	dbg("connection "PRI_CONNECTION" is not being used, deleting",
	    pri_connection(c, &cb));
	/* XXX: something better? */
	fd_delref(&c->logger->global_whackfd);
	c->logger->global_whackfd = fd_addref(whackfd);
	delete_connection(&c);
}

/*
 * A template connection's eroute can be eclipsed by
 * either a %hold or an eroute for an instance iff
 * the template is a /32 -> /32. This requires some special casing.
 */
long eclipse_count = 0;

struct connection *eclipsed(const struct connection *c, struct spd_route **esrp /*OUT*/)
{
	/*
	 * This function was changed in freeswan 2.02 and since
	 * then has never worked because it always returned NULL.
	 * It should be caught by the testing/pluto/co-terminal test cases.
	 * ??? DHR doesn't know how much of this is true.
	 */

	/* ??? this logic seems broken: it doesn't try all spd_routes of c */

	/* XXX This logic also predates support for protoports, which isn't handled below */

	struct connection_filter cq = { .where = HERE, };
	while (next_connection_new2old(&cq)) {
		struct connection *ue = cq.c;

		for (struct spd_route *srue = &ue->spd; srue != NULL; srue =srue->spd_next) {
			for (const struct spd_route *src = &c->spd; src != NULL; src = src->spd_next) {
				if (srue->routing == RT_ROUTED_ECLIPSED &&
				    selector_range_eq_selector_range(src->this.client, srue->this.client) &&
				    selector_range_eq_selector_range(src->that.client, srue->that.client)) {
					connection_buf cb, ub;
					dbg(PRI_CONNECTION" eclipsed "PRI_CONNECTION,
					    pri_connection(c, &cb), pri_connection(ue, &ub));
					*esrp = srue;
					return ue;
				}
			}
		}
	}
	*esrp = NULL;
	return NULL;
}

/*
 * sa priority and type should really go into kernel_sa
 *
 * Danger! While the priority used by the kernel is lowest-wins this
 * code computes the reverse, only to then subtract that from some
 * magic constant.
 */
uint32_t calculate_sa_prio(const struct connection *c, bool oe_shunt)
{
	connection_buf cib;

	if (c->sa_priority != 0) {
		dbg("priority calculation of connection "PRI_CONNECTION" overruled by connection specification of %"PRIu32" (%#"PRIx32")",
		    pri_connection(c, &cib), c->sa_priority, c->sa_priority);
		return c->sa_priority;
	}

	if (LIN(POLICY_GROUP, c->policy)) {
		dbg("priority calculation of connection "PRI_CONNECTION" skipped - group template does not install SPDs",
		    pri_connection(c, &cib));
		return 0;
	}

	/* XXX: assume unsigned >= 32-bits */
	passert(sizeof(unsigned) >= sizeof(uint32_t));

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
		if (LIN(POLICY_AUTH_NULL, c->policy)) {
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
		((c->spd.this.client.hport == 0 ? 1 : 0) +
		 (c->spd.that.client.hport == 0 ? 1 : 0));
	prio = (prio << 2) | portsw;

	/* Penalize wildcard protocol (1 bit). */
	unsigned protow = c->spd.this.client.ipproto == 0 ? 1 : 0;
	prio = (prio << 1) | protow;

	/*
	 * For transport mode or /32 to /32, the client mask bits are
	 * set based on the host_addr parameters.
	 *
	 * A longer prefix wins over a shorter prefix, hence the
	 * reversal.  Value needs to fit 0-128, hence 8 bits.
	 */
	unsigned srcw = 128 - c->spd.this.client.maskbits;
	prio = (prio << 8) | srcw;

	/* if opportunistic, dial up dstw TO THE MAX aka 0 */
	unsigned dstw = 128 - c->spd.that.client.maskbits;
	if (oe_shunt) {
		dstw = 0;
	}
	prio = (prio << 8) | dstw;

	/*
	 * Penalize template (1 bit).
	 *
	 * "Ensure an instance always has preference over it's
	 * template/OE-group always has preference."
	 */
	unsigned instw = (c->kind == CK_INSTANCE ? 0 : 1);
	prio = (prio << 1) | instw;

	dbg("priority calculation of connection "PRI_CONNECTION" is %u (%#x) base=%u portsw=%u protow=%u, srcw=%u dstw=%u instw=%u",
	    pri_connection(c, &cib), prio, prio,
	    base, portsw, protow, srcw, dstw, instw);
	return prio;
}

/*
 * If the connection contains a newer SA, return it.
 */
so_serial_t get_newer_sa_from_connection(struct state *st)
{
	struct connection *c = st->st_connection;
	so_serial_t newest;

	if (IS_IKE_SA(st)) {
		newest = c->newest_ike_sa;
		dbg("picked newest_ike_sa #%lu for #%lu",
		    newest, st->st_serialno);
	} else {
		newest = c->newest_ipsec_sa;
		dbg("picked newest_ipsec_sa #%lu for #%lu",
		    newest, st->st_serialno);
	}

	if (newest != SOS_NOBODY && newest != st->st_serialno) {
		return newest;
	} else {
		return SOS_NOBODY;
	}
}

/* check to see that Ids of peers match */
bool same_peer_ids(const struct connection *c, const struct connection *d,
		   const struct id *peer_id)
{
	return same_id(&c->local->host.id, &d->local->host.id) &&
	       same_id(peer_id == NULL ? &c->remote->host.id : peer_id,
		       &d->remote->host.id);
}

void check_connection(struct connection *c, where_t where)
{
	check_db_connection(c, c->logger, where);
	for (struct spd_route *sr = &c->spd; sr != NULL; sr = sr->spd_next) {
		check_db_spd_route(sr, c->logger, where);
	}
}

/* seems to be a good spot for now */
bool dpd_active_locally(const struct connection *c)
{
	return deltasecs(c->config->dpd.delay) != 0;
}
