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
#include "show.h"

static struct connection *clone_connection(const char *name, struct connection *t,
					   const struct id *peer_id, where_t where);
static void clone_connection_spd(struct connection *d, struct connection *t);

#define MINIMUM_IPSEC_SA_RANDOM_MARK 65536
static uint32_t global_marks = MINIMUM_IPSEC_SA_RANDOM_MARK;

void ldbg_connection(const struct connection *c, where_t where,
		     const char *message, ...)
{
	if (DBGP(DBG_BASE)) {
		LLOG_JAMBUF(DEBUG_STREAM, c->logger, buf) {
			va_list ap;
			va_start(ap, message);
			jam_va_list(buf, message, ap);
			va_end(ap);
			jam(buf, " "PRI_WHERE, pri_where(where));
		}
		connection_buf cb;
		LDBG_log(c->logger, "  connection: "PRI_CONNECTION,
			 pri_connection(c, &cb));
		LDBG_log(c->logger, "    routing: %s",
			 enum_name_short(&routing_story, c->child.routing));
		address_buf lb, rb;
		LDBG_log(c->logger, "    host: %s->%s",
			 str_address(&c->local->host.addr, &lb),
			 str_address(&c->remote->host.addr, &rb));
		LDBG_log(c->logger, "    kind: %s",
			 enum_name_short(&connection_kind_names, c->kind));
		LLOG_JAMBUF(DEBUG_STREAM, c->logger, buf) {
			jam_string(buf, "    selectors:");
			const char *sep = " ->";
			FOR_EACH_THING(end, &c->local->child, &c->remote->child) {
				const ip_selectors *selectors = &end->selectors.proposed;
				for (const ip_selector *selector = selectors->list;
				     selector < selectors->list + selectors->len;
				     selector++) {
					jam_string(buf, " ");
					jam_selector(buf, selector);
				}
				jam_string(buf, sep); sep = "";
			}
		}
		LLOG_JAMBUF(DEBUG_STREAM, c->logger, buf) {
			jam_string(buf, "    spds:");
			for (const struct spd_route *spd = c->spd; spd != NULL; spd = spd->spd_next) {
				jam_string(buf, " ");
				jam_selector_pair(buf, &spd->local->client, &spd->remote->client);
			}
		}
	}

}

/*
 * Find a connection by name.
 *
 * no_inst: don't accept a CK_INSTANCE.
 */

struct connection *conn_by_name(const char *nm, bool no_inst)
{
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
static void discard_spd_end(struct spd_end *e)
{
	virtual_ip_delref(&e->virt);
}

static void discard_spd(struct spd_route **spd, bool valid)
{
	spd_route_db_del(*spd, valid);
	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		discard_spd_end(&(*spd)->end[end]);
	}
	pfreeany(*spd);
}

void discard_connection_spds(struct connection *c, bool connection_valid)
{
	for (struct spd_route *spd = c->spd, *next = NULL; spd != NULL; spd = next) {
		next = spd->spd_next; /*step-off*/
		discard_spd(&spd, connection_valid);
	}
	c->spd = NULL;
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
		for (enum ip_index i = IP_INDEX_FLOOR; i < IP_INDEX_ROOF; i++) {
			if (c->pool[i] != NULL) {
				free_that_address_lease(c, &ip_info[i]);
			}
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

	for (enum ip_index i = IP_INDEX_FLOOR; i < IP_INDEX_ROOF; i++) {
		addresspool_delref(&c->pool[i]);
	}

	if (IS_XFRMI && c->xfrmi != NULL)
		unreference_xfrmi(c);

	/* find and delete c from the host pair list */
	host_pair_remove_connection(c, connection_valid);

	flush_revival(c);

	connection_db_del(c, connection_valid);

	discard_connection_spds(c, connection_valid);

	FOR_EACH_ELEMENT(end, c->end) {
		free_id_content(&end->host.id);
		pfreeany(end->child.selectors.accepted.list);
	}

	/*
	 * Logging no longer valid.  Can this be delayed further?
	 */
#if 0
	struct logger *connection_logger = clone_logger(c->logger, HERE);
#endif
	free_logger(&c->logger, HERE);

	pfreeany(c->foodgroup);
	pfreeany(c->vti_iface);
	iface_endpoint_delref(&c->interface);

	free_chunk_content(&c->child.sec_label);

	struct config *config = c->root_config;
	if (config != NULL) {
		passert(co_serial_is_unset(c->serial_from));
		free_chunk_content(&config->sec_label);
		free_proposals(&config->ike_proposals.p);
		free_proposals(&config->child_proposals.p);
		free_ikev2_proposals(&config->v2_ike_proposals);
		free_ikev2_proposals(&config->v2_ike_auth_child_proposals);
		pfreeany(config->connalias);
		pfreeany(config->dnshostname);
		pfreeany(config->modecfg.dns.list);
		pfreeany(config->modecfg.domains);
		pfreeany(config->modecfg.banner);
		pfreeany(config->redirect.to);
		pfreeany(config->redirect.accept);
		FOR_EACH_ELEMENT(end, config->end) {
			if (end->host.cert.nss_cert != NULL) {
				CERT_DestroyCertificate(end->host.cert.nss_cert);
			}
			/* ike/host */
			free_chunk_content(&end->host.ca);
			pfreeany(end->host.ckaid);
			pfreeany(end->host.xauth.username);
			pfreeany(end->host.addr_name);
			pfreeany(end->host.pool_ranges.list);
			/* child */
			pfreeany(end->child.updown);
			pfreeany(end->child.selectors.list);
			pfreeany(end->child.sourceip.list);
			virtual_ip_delref(&end->child.virt);
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

		if (lsw_alias_cmp(alias, p->config->connalias))
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

ip_port end_host_port(const struct host_end *this, const struct host_end *that)
{
	unsigned port;
	if (this->config->ikeport != 0) {
		/*
		 * The END's IKEPORT was specified in the config file.
		 * Use that.
		 */
		port = this->config->ikeport;
	} else if (that->config->ikeport != 0) {
		/*
		 * The other end's IKEPORT was specified in the config
		 * file.  Since specifying an IKEPORT implies ESP
		 * encapsulation (i.e. IKE packets must include the
		 * ESP=0 prefix), send packets from the encapsulating
		 * NAT_IKE_UDP_PORT.
		 */
		port = NAT_IKE_UDP_PORT;
	} else if (that->encap) {
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

void update_hosts_from_end_host_addr(struct connection *c, enum left_right e,
				     ip_address host_addr, where_t where)
{
	struct host_end *end = &c->end[e].host;
	struct host_end *other_end = &c->end[!e].host;

	address_buf hab;
	ldbg(c->logger, "updating host ends from %s.host.addr %s",
	     end->config->leftright, str_address(&host_addr, &hab));

	/* could be %any but can't be an address */
	PASSERT_WHERE(c->logger, where, !address_is_specified(end->addr));

	/* can't be unset; but could be %any[46] */
	const struct ip_info *afi = address_info(host_addr);
	PASSERT_WHERE(c->logger, where, afi != NULL); /* since specified */

	end->addr = host_addr;
	if (!address_is_specified(host_addr)) {
		return;
	}

	/*
	 * Default ID to IP (but only if not NO_IP -- WildCard).
	 */
	if (end->id.kind == ID_NONE) {
		struct id id = {
			.kind = afi->id_ip_addr,
			.ip_addr = end->addr,
		};
		id_buf old, new;
		dbg("  updated %s.id from %s to %s",
		    end->config->leftright,
		    str_id(&end->id, &old),
		    str_id(&id, &new));
		end->id = id;
	}

	/*
	 * If END has an IKEPORT (which means messages are ESP=0
	 * prefixed), then END must send from either IKEPORT or the
	 * NAT port (and also ESP=0 prefix messages).
	 */
	unsigned host_port = hport(end_host_port(end, other_end));
	dbg("  updated %s.host_port from %u to %u",
	    end->config->leftright,
	    end->port, host_port);
	end->port = host_port;

	/*
	 * Propagate end.HOST_ADDR to other_end.NEXTHOP.
	 * As in: other_end.addr -> other_end.NEXTHOP -> END.
	 */
	if (!address_is_specified(other_end->nexthop)) {
		address_buf old, new;
		dbg("  updated %s.host_nexthop from %s to %s",
		    other_end->config->leftright,
		    str_address(&other_end->nexthop, &old),
		    str_address(&end->addr, &new));
		other_end->nexthop = end->addr;
	}
}

void update_spds_from_end_host_addr(struct connection *c, enum left_right end, ip_address host_addr,
				    where_t where)
{
	const char *leftright = c->end[end].config->leftright;
	const struct child_end *child = &c->end[end].child;
	address_buf hab;
	ldbg(c->logger, "updating %s.spd client(selector) from %s.host.addr %s "PRI_WHERE,
	     leftright, leftright, str_address(&host_addr, &hab), pri_where(where));

	if (!PEXPECT_WHERE(c->logger, where, address_is_specified(host_addr))) {
		return;
	}

	if (child->config->selectors.len > 0) {
		ldbg(c->logger, "  %s.child already has a hard-wired selectors; skipping",
		     leftright);
		return;
	}

	for (struct spd_route *spd = c->spd; spd != NULL; spd = spd->spd_next) {
		struct spd_end *spde = &spd->end[end];

		if (spde->child->has_client) {
			pexpect(c->policy & POLICY_OPPORTUNISTIC);
			ldbg(c->logger, "  %s.child.has_client yet no selectors; skipping magic",
			     leftright);
			continue;
		}

		/* per-above */
		if (!pexpect(address_is_specified(host_addr))) {
			continue;
		}

		/*
		 * Default the end's child selector (client) to a
		 * subnet containing only the end's host address.
		 *
		 * If the other end has multiple child subnets then
		 * the SPD will be a list.
		 */
		ip_selector selector =
			selector_from_address_protoport(host_addr, child->config->protoport);

		selector_buf old, new;
		dbg("  updated %s.spd client(selector) from %s to %s",
		    leftright,
		    str_selector_subnet_port(&spde->client, &old),
		    str_selector_subnet_port(&selector, &new));
		if (spd == c->spd) {
			update_end_selector(c, end, selector, NULL);
		} else {
			spde->client = selector; /*set_end_selector()*/
		}
	}
}

/*
 * unshare_connection: after a struct connection has been copied,
 * duplicate anything it references so that unshareable resources are
 * no longer shared.  Typically strings, but some other things too.
 *
 * Think of this as converting a shallow copy to a deep copy
 *
 * XXX: unshare_connection() and the shallow clone should be merged
 * into a routine that allocates a new connection and then explicitly
 * copy over the data.  Cloning pointers and then trying to fix them
 * up after the event is a guaranteed way to create use-after-free
 * problems.
 */

struct connection *clone_connection(const char *name, struct connection *t,
				    const struct id *peer_id, where_t where)
{
	struct connection *c = clone_thing(*t, where->func);
	zero_thing(c->hash_table_entries); /* keep init_list_entry() happy */
	finish_connection(c, name, t,
			  t->logger->debugging,
			  t->logger->object_whackfd,
			  where);

	/* caller responsible for cloning this */
	c->spd = NULL;

	c->log_file_name = NULL;
	c->log_file = NULL;
	c->log_file_err = false;

	c->root_config = NULL; /* block write access */
	c->foodgroup = clone_str(t->foodgroup, "food groups");
	c->vti_iface = clone_str(t->vti_iface, "connection vti_iface");
	c->interface = iface_endpoint_addref(t->interface);

	/* can't yet have an assigned SEC_LABEL */
	PASSERT(c->logger, c->child.sec_label.len == 0);

	c->local->host.id = clone_id(&t->local->host.id, "unshare local connection id");
	c->remote->host.id = clone_id((peer_id != NULL ? peer_id : &t->remote->host.id),
				      "unshare remote connection id");

	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		zero(&c->end[end].child.selectors);
	}

	for (enum ip_index i = IP_INDEX_FLOOR; i < IP_INDEX_ROOF; i++) {
		c->pool[i] = addresspool_addref(t->pool[i]);
	}

	if (IS_XFRMI && c->xfrmi != NULL) {
		reference_xfrmi(c);
	}

	return c;
}

/*
 * Figure out the host / client address family.
 *
 * Returns diag() when there's a conflict.  leaves *AFI NULL if could
 * not be determined.
 */

#define EXTRACT_AFI(NAME, TYPE, FIELD)				\
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
			return diag("host address family %s from %s%s=%s conflicts with %s%s=%s", \
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
		EXTRACT_AFI(""/*left""=,right""=*/, address, w->host_addr);
		EXTRACT_AFI("nexthop", address, w->host_nexthop);
	}
	return NULL;
}

#define ADD_FAILED_PREFIX "failed to add connection: "

static diag_t extract_host_end(struct connection *c, /* for POOL */
			       struct host_end *host,
			       struct host_end_config *host_config,
			       struct host_end_config *other_host_config,
			       const struct whack_message *wm,
			       const struct whack_end *src,
			       const struct whack_end *other_src,
			       bool *same_ca,
			       struct logger *logger/*connection "..."*/)
{
	err_t err;
	const char *leftright = host_config->leftright;

	/*
	 * decode id, if any
	 *
	 * For %fromcert, the load_end_cert*() call will update it.
	 */
	if (src->id == NULL) {
		host->id.kind = ID_NONE;
	} else {
		/*
		 * Cannot report errors due to low level nesting of functions,
		 * since it will try literal IP string conversions first. But
		 * atoid() will log real failures like illegal DNS chars already,
		 * and for @string ID's all chars are valid without processing.
		 */
		atoid(src->id, &host->id);
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
					DBG_dump_hunk(NULL, host_config->ca);
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
		diag_t diag = add_end_cert_and_preload_private_key(cert, host, host_config,
								   *same_ca/*preserve_ca*/,
								   logger);
		if (diag != NULL) {
			CERT_DestroyCertificate(cert);
			return diag;
		}
	} else if (src->pubkey != NULL) {

		/*
		 * XXX: hack: whack will load the actual key in a
		 * second message, this code just extracts the ckaid.
		 */

		if (src->ckaid != NULL) {
			enum_buf pkb;
			llog(RC_LOG, logger,
			     "warning: ignoring %sckaid=%s and using %s%s",
			     leftright, src->ckaid,
			     leftright, str_enum(&ipseckey_algorithm_config_names, src->pubkey_alg, &pkb));
		}

		chunk_t keyspace = NULL_HUNK; /* must free */
		struct pubkey_content pkc;
		if (src->pubkey_alg == IPSECKEY_ALGORITHM_X_PUBKEY) {
			/* XXX: lifted from starter_whack_add_pubkey() */
			err = ttochunk(shunk1(src->pubkey), 64/*damit*/, &keyspace);
			if (err != NULL) {
				enum_buf pkb;
				return diag("%s%s invalid: %s",
					    leftright, str_enum(&ipseckey_algorithm_config_names, src->pubkey_alg, &pkb),
					    err);
			}
			diag_t d = pubkey_der_to_pubkey_content(HUNK_AS_SHUNK(keyspace), &pkc);
			if (d != NULL) {
				free_chunk_content(&keyspace);
				enum_buf pkb;
				return diag_diag(&d, "%s%s invalid, ",
						 leftright, str_enum(&ipseckey_algorithm_config_names, src->pubkey_alg, &pkb));
			}
		} else {
			/* XXX: lifted from starter_whack_add_pubkey() */
			err = ttochunk(shunk1(src->pubkey), 0/*figure-it-out*/, &keyspace);
			if (err != NULL) {
				enum_buf pkb;
				return diag("%s%s invalid: %s",
					    leftright, str_enum(&ipseckey_algorithm_config_names, src->pubkey_alg, &pkb),
					    err);
			}
			const struct pubkey_type *type;
			switch (src->pubkey_alg) {
			case IPSECKEY_ALGORITHM_RSA:
				type = &pubkey_type_rsa;
				break;
			case IPSECKEY_ALGORITHM_ECDSA:
				type = &pubkey_type_ecdsa;
				break;
			default:
				bad_case(src->pubkey_alg);
			}

			diag_t d = type->ipseckey_rdata_to_pubkey_content(HUNK_AS_SHUNK(keyspace), &pkc);
			if (d != NULL) {
				free_chunk_content(&keyspace);
				enum_buf pkb;
				return diag_diag(&d, "%s%s invalid, ",
						 leftright, str_enum(&ipseckey_algorithm_config_names, src->pubkey_alg, &pkb));
			}
		}

		passert(pkc.type != NULL);

		ckaid_buf ckb;
		enum_buf pkb;
		dbg("saving CKAID %s extracted from %s%s",
		    str_ckaid(&pkc.ckaid, &ckb),
		    leftright, str_enum(&ipseckey_algorithm_config_names, src->pubkey_alg, &pkb));
		host_config->ckaid = clone_const_thing(pkc.ckaid, "raw pubkey's ckaid");
		free_chunk_content(&keyspace);
		pkc.type->free_pubkey_content(&pkc);

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
			llog(RC_LOG|LOG_STREAM/*not-whack-for-now*/, logger,
			     "loaded private key matching %s%s CKAID %s",
			     leftright, str_enum(&ipseckey_algorithm_config_names, src->pubkey_alg, &pkb),
			     str_ckaid(host_config->ckaid, &ckb));
		}
	} else if (src->ckaid != NULL) {
		ckaid_t ckaid;
		err_t err = string_to_ckaid(src->ckaid, &ckaid);
		if (err != NULL) {
			/* should have been rejected by whack? */
			/* XXX: don't trust whack */
			return diag("%s CKAID '%s' invalid: %s",
				    leftright, src->ckaid, err);
		}
		/*
		 * Always save the CKAID so lazy load of the private
		 * key will work.
		 */
		host_config->ckaid = clone_thing(ckaid, "end ckaid");
		/*
		 * See if there's a certificate matching the CKAID, if
		 * not assume things will later find the private key.
		 */
		CERTCertificate *cert = get_cert_by_ckaid_from_nss(&ckaid, logger);
		if (cert != NULL) {
			diag_t diag = add_end_cert_and_preload_private_key(cert, host, host_config,
									   *same_ca/*preserve_ca*/,
									   logger);
			if (diag != NULL) {
				CERT_DestroyCertificate(cert);
				return diag;
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
				    str_ckaid(host_config->ckaid, &ckb), err);
			} else {
				ckaid_buf ckb;
				llog(RC_LOG|LOG_STREAM/*not-whack-for-now*/, logger,
				     "loaded private key matching %s CKAID %s",
				     leftright,
				     str_ckaid(host_config->ckaid, &ckb));
			}
		}
	}

	/* the rest is simple copying of corresponding fields */
	host_config->type = src->host_type;
	host_config->addr_name = clone_str(src->host_addr_name, "host ip");
	host_config->xauth.server = src->xauth_server;
	host_config->xauth.client = src->xauth_client;
	host_config->xauth.username = clone_str(src->xauth_username, "xauth username");
	host_config->eap = src->eap;

	if (src->eap == IKE_EAP_NONE && src->auth == AUTH_EAPONLY) {
		return diag("leftauth/rightauth can only be 'eaponly' when using leftautheap/rightautheap is not 'none'");
	}

	/*
	 * Determine the authentication from auth= and authby=.
	 */

	if (NEVER_NEGOTIATE(wm->policy) && src->auth != AUTH_UNSET && src->auth != AUTH_NEVER) {
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
	struct authby authby = (NEVER_NEGOTIATE(wm->policy) ? AUTHBY_NEVER :
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

	if (src->protoport.ipproto == 0 && src->protoport.hport != 0) {
		return diag("%sprotoport cannot specify non-zero port %d for prototcol 0",
			    src->leftright, src->protoport.hport);
	}

	host_config->key_from_DNS_on_demand = src->key_from_DNS_on_demand;
	host_config->sendcert = src->sendcert == 0 ? CERT_SENDIFASKED : src->sendcert;
	host_config->ikeport = src->host_ikeport;
	if (src->host_ikeport > 65535) {
		llog(RC_BADID, logger,
			    "%sikeport=%u must be between 1..65535, ignored",
			    leftright, src->host_ikeport);
		host_config->ikeport = 0;
	}

	/*
	 * Should the address pool only be added to the modecfg
	 * .server?  Is it necessary on the initiator?
	 *
	 * OE orients things so that local modecfg is the client
	 * .client (presumably so that it can initiate connections
	 * on-demand), BUT also makes that same connection act like a
	 * server accepting incoming OE connections.
	 *
	 * Note that, possibly confusingly, in the config file the
	 * client end specifies the address pool (instead of being
	 * given a subnet).  Presumably it is saying this is where the
	 * ends addresses come from.
	 *
	 * Can a client also be a server, per above, OE seems to think
	 * so (but without actually setting the bits).
	 *
	 * Note: IKEv1's XAUTH code will replace this address pool
	 * with one based on the auth file.
	 *
	 * Note: The selector code will use the addresspool ranges to
	 * generate the selectors.
	 */

	/* only update, may already be set below */
	host_config->modecfg.server |= src->modecfg_server;
	host_config->modecfg.client |= src->modecfg_client;

	if (src->addresspool != NULL) {

		/* both ends can't add an address pool */
		passert(c->pool[IPv4_INDEX] == NULL &&
			c->pool[IPv6_INDEX] == NULL);

		diag_t d = ttoranges_num(shunk1(src->addresspool), ", ", NULL,
					 &host_config->pool_ranges);
		if (d != NULL) {
			return diag_diag(&d, "%saddresspool=%s invalid, ", leftright, src->addresspool);
		}

		for (const ip_range *pool_range = host_config->pool_ranges.list;
		     pool_range < host_config->pool_ranges.list + host_config->pool_ranges.len;
		     pool_range++) {
			const struct ip_info *pool_afi = range_type(pool_range);

			if (c->pool[pool_afi->ip_index] != NULL) {
				return diag("%saddresspool=%s invalid, multiple %s ranges",
					    leftright, src->addresspool, pool_afi->ip_name);
			}

			if (pool_afi == &ipv6_info && !pool_range->is_subnet) {
				range_buf rb;
				return diag("%saddresspool=%s invalid, IPv6 range %s is not a subnet",
					    leftright, src->addresspool,
					    str_range(pool_range, &rb));
			}

			/* Check for overlap with existing pools */
			diag_t d;
			struct addresspool *pool; /* ignore */
			d = find_addresspool(*pool_range, &pool);
			if (d != NULL) {
				return diag_diag(&d, "%saddresspool=%s invalid, ",
						 leftright, src->addresspool);
			}

			d = install_addresspool(*pool_range, c);
			if (d != NULL) {
				return diag_diag(&d, "%saddresspool=%s invalid, ",
						 leftright, src->addresspool);
			}
		}

		/*
		 * Addresspool implies the end is a client (and other
		 * is a server), force settings.
		 */
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
				       struct child_end_config *child_config,
				       struct logger *logger)
{
	const char *leftright = src->leftright;

	switch (wm->ike_version) {
	case IKEv2:
		child_config->has_client_address_translation = src->cat;
		break;
	case IKEv1:
		if (src->cat) {
			llog(RC_LOG, logger,
			     "warning: IKEv1, ignoring %scat=%s (client address translation)",
			     leftright, bool_str(src->cat));
		}
		break;
	default:
		bad_case(wm->ike_version);
	}

	child_config->host_vtiip = src->host_vtiip;
	child_config->ifaceip = src->ifaceip;

	/* save some defaults */
	child_config->protoport = src->protoport;

	/*
	 * Support for skipping updown, eg leftupdown="" or %disabled.
	 *
	 * Useful on busy servers that do not need to use updown for
	 * anything.
	 *
	 * XXX: Perhaps src->updown will some day be NULL.
	 */
	child_config->updown = (src->updown == NULL ? NULL :
				streq(src->updown, "%disabled") ? NULL :
				streq(src->updown, "") ? NULL :
				clone_str(src->updown, "child_config.updown"));

	/*
	 * Figure out the end's child selectors.
	 */
	if (src->subnet != NULL && (wm->ike_version == IKEv1 ||
				    src->protoport.is_set)) {
		/*
		 * Legacy syntax:
		 *
		 * - IKEv1
		 * - when protoport= was also specified
		 *
		 * Merge protoport into the selector.
		 */
		ip_subnet subnet;
		ip_address nonzero_host;
		err_t e = ttosubnet_num(shunk1(src->subnet), NULL,
					&subnet, &nonzero_host);
		if (nonzero_host.is_set) {
			address_buf hb;
			llog(RC_LOG, logger, "zeroing non-zero host identifier %s in %ssubnet=%s",
			     leftright, str_address(&nonzero_host, &hb), src->subnet);
		}
		if (e != NULL) {
			return diag("%ssubnet=%s invalid, %s",
				    leftright, src->subnet, e);
		}
		ldbg(logger, "%s child selectors from %ssubnet + %sprotoport; %s.config.has_client=true",
		     leftright, leftright, leftright, leftright);
		child_config->selectors.len = 1;
		child_config->selectors.list = alloc_things(ip_selector, 1, "subnet-selectors");
		child_config->selectors.list[0] =
			selector_from_subnet_protoport(subnet, src->protoport);
	} else if (src->subnet != NULL) {
		/*
		 * Parse new syntax (protoport= is not used).
		 *
		 * Of course if NARROWING is allowed, this can be
		 * refined regardless of .has_client.
		 */
		ldbg(logger, "%s child selectors from %ssubnet (selector); %s.config.has_client=true",
		     leftright, leftright, leftright);
		passert(wm->ike_version == IKEv2);
		ip_address nonzero_host;
		diag_t d = ttoselectors_num(shunk1(src->subnet), ", ", NULL,
					    &child_config->selectors, &nonzero_host);
		if (d != NULL) {
			return diag_diag(&d, "%ssubnet=%s invalid, ",
					 leftright, src->subnet);
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
	 * least one selector determined above.
	 */

	if (src->sourceip != NULL && src->subnet == NULL) {
		return diag("%ssourceip=%s invalid, requires %ssubnet",
			    leftright, src->sourceip, leftright);
	}

	if (src->sourceip != NULL) {
		pexpect(child_config->selectors.len > 0);
		diag_t d = ttoaddresses_num(shunk1(src->sourceip), ", ",
					    NULL/*UNSPEC*/, &child_config->sourceip);
		if (d != NULL) {
			return diag_diag(&d, "%ssourceip=%s invalid, ",
					 src->leftright, src->sourceip);
		}
		/* valid? */
		for (ip_address *sip = child_config->sourceip.list;
		     sip < child_config->sourceip.list + child_config->sourceip.len; sip++) {
			if (!address_is_specified(*sip)) {
				return diag("%ssourceip=%s invalid, must be a valid address",
					    leftright, src->sourceip);
			}
			/* skip aliases; they hide the selectors list */
			if (wm->connalias != NULL) {
				continue;
			}
			bool within = false;
			for (ip_selector *sel = child_config->selectors.list;
			     sel < child_config->selectors.list + child_config->selectors.len;
			     sel++) {
				if (address_in_selector(*sip, *sel)) {
					within = true;
					break;
				}
			}
			if (!within) {
				address_buf sipb;
				return diag("%ssourceip=%s address %s is not within %ssubnet=%s",
					    leftright, src->sourceip, str_address(sip, &sipb),
					    leftright, src->subnet);
			}
		}
	}

	return NULL;
}

diag_t add_end_cert_and_preload_private_key(CERTCertificate *cert,
					    struct host_end *host_end,
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
	select_nss_cert_id(cert, &host_end->id);

	/* check validity of cert */
	if (CERT_CheckCertValidTimes(cert, PR_Now(), false) !=
			secCertTimeValid) {
		return diag("%s certificate '%s' is expired or not yet valid",
			    leftright, nickname);
	}

	dbg("loading %s certificate \'%s\' pubkey", leftright, nickname);
	if (!add_pubkey_from_nss_cert(&pluto_pubkeys, &host_end->id, cert, logger)) {
		/* XXX: push diag_t into add_pubkey_from_nss_cert()? */
		return diag("%s certificate \'%s\' pubkey could not be loaded",
			    leftright, nickname);
	}

	host_end_config->cert.nss_cert = cert;

	/*
	 * If no CA is defined, use issuer as default; but only when
	 * update is ok.
	 *
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

static void set_connection_spds(struct connection *c, const struct ip_info *host_afi)
{
	ldbg(c->logger, "adding spds");
	struct spd_route *spd_list = NULL;
	struct spd_route **spd_tail = &spd_list;
	struct {
		const ip_selectors *selectors;
		const ip_selector *selector;
		const struct ip_info *afi;
	} selectors[END_ROOF] = {0};
	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		selectors[end].selectors = &c->end[end].config->child.selectors;
	}
	selectors[LEFT_END].selector = selectors[LEFT_END].selectors->list; /* could be NULL */
	while (true) /*LEFT*/ {
		unsigned indent = 1;
		selector_buf leftb;
		ldbg(c->logger, "%*s%s->...", indent, "", str_selector(selectors[LEFT_END].selector, &leftb));
		selectors[RIGHT_END].selector = selectors[RIGHT_END].selectors->list;  /* could be NULL */
		while (true) /*RIGHT*/ {
			indent = 2;
			selector_buf rightb;
			ldbg(c->logger, "%*s%s->%s", indent, "",
			     str_selector(selectors[LEFT_END].selector, &leftb),
			     str_selector(selectors[RIGHT_END].selector, &rightb));
			indent = 3;
			/*
			 * XXX: Try to filter out IPv4 vs IPv6.  When
			 * selector is NULL, the host's address family
			 * is used.
			 */
			FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
				if (selectors[end].selector == NULL) {
					selectors[end].afi = host_afi;
				} else {
					selectors[end].afi = selector_type(selectors[end].selector);
				}
			}
			if (selectors[LEFT_END].afi == selectors[RIGHT_END].afi) {
				indent = 6;
				struct spd_route *spd = append_spd(c, &spd_tail);
				FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
					const ip_selector *selector = selectors[end].selector; /* could be NULL */
					const struct child_end_config *child_end = &c->end[end].config->child;
					struct spd_end *spd_end = &spd->end[end];
					const char *leftright = child_end->leftright;
					/*
					 * Set things based both on
					 * virt and on selectors.
					 *
					 * XXX: don't set .has_client
					 * as update_child_ends*()
					 * will see it and skip
					 * updating the client address
					 * from the host.
					 */
					if (selector != NULL) {
						selector_buf sb;
						ldbg(c->logger,
						     "%*s%s %s child spd has selectors; setting client to %s",
						     indent, "", c->name, leftright, str_selector(selector, &sb));
						passert(selector->is_set); /* else pointless */
						if (spd == c->spd) {
							update_end_selector(c, end, *selector, NULL);
						} else {
							spd_end->client = *selector;/*update_end_selector()*/
						}
					}
					if (child_end->virt != NULL) {
						ldbg(c->logger,
						     "%*s%s child spd is virtual; adding virt",
						     indent, "", leftright);
						spd_end->virt = virtual_ip_addref(child_end->virt);
					}
					selector_buf sb;
					ldbg(c->logger,
					     "%*s%s child spd from selector %s %s.spd.has_client=%s virt=%s",
					     indent, "", spd_end->config->leftright,
					     str_selector(&spd_end->client, &sb),
					     leftright,
					     bool_str(spd_end->child->has_client),
					     bool_str(spd_end->virt != NULL));
				}
			}
			/* advance RIGHT (NULL+1>=NULL+0) */
			if (selectors[RIGHT_END].selector + 1 >= selectors[RIGHT_END].selectors->list + selectors[RIGHT_END].selectors->len) break;
			selectors[RIGHT_END].selector++;
		}
		/* advance LEFT (NULL+1>=NULL+0) */
		if (selectors[LEFT_END].selector + 1 >= selectors[LEFT_END].selectors->list + selectors[LEFT_END].selectors->len) break;
		selectors[LEFT_END].selector++;
	}

	c->spd = spd_list;

	/* leave a bread crumb */
	PEXPECT(c->logger, c->child.kernel_policy_owner == SOS_NOBODY);
	set_child_kernel_policy_owner(c, SOS_NOBODY);

	/* leave a bread crumb */
	passert(c->child.routing == RT_UNROUTED);
	set_child_routing(c, RT_UNROUTED);

	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		ip_address host_addr = c->end[end].host.addr;
		if (address_is_specified(host_addr)) {
			update_spds_from_end_host_addr(c, end, host_addr, HERE);
		}
	}

	set_connection_priority(c); /* must be after kind is set */
}

void add_connection_spds(struct connection *c)
{
	unsigned indent = 0;
	ldbg(c->logger, "%*sadding proposal spds", indent, "");

	struct spd_route *spd_list = NULL;
	struct spd_route **spd_end = &spd_list;
	struct {
		const ip_selectors *selectors;
		const ip_selector *selector;
		const struct ip_info *afi;
	} selectors[END_ROOF] = {0};
	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		const ip_selectors *s = &c->end[end].child.selectors.proposed;
		if (s->len == 0) {
			ldbg(c->logger, "%s has no selectors",
			     c->end[end].config->leftright);
			return;
		}
		selectors[end].selectors = s;
	}
	selectors[LEFT_END].selector = selectors[LEFT_END].selectors->list;
	for (selectors[LEFT_END].selector = selectors[LEFT_END].selectors->list;
	     selectors[LEFT_END].selector < selectors[LEFT_END].selectors->list + selectors[LEFT_END].selectors->len;
	     selectors[LEFT_END].selector++) {
		for (selectors[RIGHT_END].selector = selectors[RIGHT_END].selectors->list;
		     selectors[RIGHT_END].selector < selectors[RIGHT_END].selectors->list + selectors[RIGHT_END].selectors->len;
		     selectors[RIGHT_END].selector++) {
			indent = 1;
			selector_buf leftb, rightb;
			ldbg(c->logger, "%*s%s->%s", indent, "",
			     str_selector(selectors[LEFT_END].selector, &leftb),
			     str_selector(selectors[RIGHT_END].selector, &rightb));
			indent = 2;
			/*
			 * XXX: figure out the combination's IP
			 * family.
			 */
			FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
				selectors[end].afi = selector_type(selectors[end].selector);
			}
			if (selectors[LEFT_END].afi == selectors[RIGHT_END].afi) {
				indent = 6;
				struct spd_route *spd = append_spd(c, &spd_end);
				FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
					const ip_selector *selector = selectors[end].selector;
					const struct child_end_config *child_end = &c->end[end].config->child;
					struct spd_end *spd_end = &spd->end[end];
					const char *leftright = child_end->leftright;
					spd_end->client = *selector;/*NOT update_end_selector()*/
					spd_end->virt = virtual_ip_addref(child_end->virt);
					selector_buf sb;
					ldbg(c->logger,
					     "%*s%s child spd from selector %s %s.spd.has_client=%s virt=%s",
					     indent, "", spd_end->config->leftright,
					     str_selector(&spd_end->client, &sb),
					     leftright,
					     bool_str(spd_end->child->has_client),
					     bool_str(spd_end->virt != NULL));
				}
			}
		}
	}

	PEXPECT(c->logger, c->spd == NULL); /* leak? */
	c->spd = spd_list;

	set_connection_priority(c); /* must be after .kind and .spd are set */
	spd_route_db_add_connection(c);
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

static void extract_max_sa_lifetime(const char *sa_name,
				    deltatime_t *lifetime, deltatime_t whack_lifetime,
				    time_t fips_lifetime_max, time_t lifetime_max,
				    struct logger *logger)
{
	/* http://csrc.nist.gov/publications/nistpubs/800-77/sp800-77.pdf */
	deltatime_t max_lifetime =
		deltatime(libreswan_fipsmode() ? fips_lifetime_max : lifetime_max);

	if (deltatime_cmp(whack_lifetime, ==, deltatime_zero) ||
	    deltatime_cmp(whack_lifetime, >, max_lifetime)) {
		llog(RC_LOG, logger,
		     "%s lifetime set to the maximum allowed %jds",
		     sa_name, deltasecs(max_lifetime));
		*lifetime = max_lifetime;
	} else {
		*lifetime = whack_lifetime;
	}
}

static enum connection_kind extract_connection_kind(const struct whack_message *wm,
						    struct logger *logger)
{
	if (wm->policy & POLICY_GROUP) {
		ldbg(logger, "connection is group: by policy");
		return CK_GROUP;
	}
	if (wm->ike_version == IKEv2 && wm->sec_label != NULL) {
		ldbg(logger, "connection is template: IKEv2 and has security label: %s", wm->sec_label);
		return CK_TEMPLATE;
	}
	if(wm->policy & POLICY_IKEV2_ALLOW_NARROWING) {
		ldbg(logger, "connection is template: POLICY_IKEV2_ALLOW_NARROWING");
		return CK_TEMPLATE;
	}
	FOR_EACH_THING(we, &wm->left, &wm->right) {
		if (we->virt != NULL) {
			/*
			 * If we have a subnet=vnet: needing
			 * instantiation so we can accept
			 * multiple subnets from the remote
			 * peer.
			 */
			dbg("connection is template: %s has vnets at play",
			    we->leftright);
			return CK_TEMPLATE;
		}
		if (we->protoport.has_port_wildcard) {
			dbg("connection is template: %s child has wildcard protoport",
			    we->leftright);
			return CK_TEMPLATE;
		}
		if (!NEVER_NEGOTIATE(wm->policy) &&
		    !address_is_specified(we->host_addr) &&
		    we->host_type != KH_IPHOSTNAME) {
			dbg("connection is template: unspecified %s address yet policy negotiate",
			    we->leftright);
			return CK_TEMPLATE;
		}
	}
	dbg("connection is permanent: by default");
	return CK_PERMANENT;
}

static bool extract_shunt(const char *shunt_name,
			  enum shunt_policy *out,
			  enum shunt_policy shunt,
			  bool (*shunt_ok)(enum shunt_policy),
			  enum shunt_policy unset_shunt,
			  struct logger *logger)
{
	if (shunt == SHUNT_UNSET) {
		shunt = unset_shunt;
	}
	if (!shunt_ok(shunt)) {
		enum_buf sb;
		llog(RC_FATAL, logger,
		     ADD_FAILED_PREFIX"%s shunt %s invalid",
		     shunt_name, str_enum_short(&shunt_policy_names, shunt, &sb));
		return false;
	}
	*out = shunt;
	return true;
}

static bool extract_connection(const struct whack_message *wm,
			       struct connection *c)
{
	diag_t d;
	struct config *config = c->root_config; /* writeable; root only */
	passert(c->name != NULL); /* see alloc_connection() */

	if ((wm->policy & POLICY_TUNNEL) == LEMPTY) {
		if (wm->sa_tfcpad != 0) {
			llog(RC_FATAL, c->logger,
			     ADD_FAILED_PREFIX"connection with type=transport cannot specify tfc=");
			return false;
		}
		if (wm->vti_iface != NULL) {
			llog(RC_FATAL, c->logger,
			     ADD_FAILED_PREFIX"VTI requires tunnel mode but connection specifies type=transport");
			return false;
		}
	}
	if (LIN(POLICY_AUTHENTICATE, wm->policy)) {
		if (wm->sa_tfcpad != 0) {
			llog(RC_FATAL, c->logger,
			     ADD_FAILED_PREFIX"connection with phase2=ah cannot specify tfc=");
			return false;
		}
	}

	if (wm->authby.never) {
		if (wm->prospective_shunt == SHUNT_UNSET ||
		    wm->prospective_shunt == SHUNT_TRAP) {
			llog(RC_FATAL, c->logger,
			     ADD_FAILED_PREFIX"connection with authby=never must specify shunt type via type=");
			return false;
		}
	}
	if (wm->prospective_shunt != SHUNT_UNSET &&
	    wm->prospective_shunt != SHUNT_TRAP) {
		if (!authby_eq(wm->authby, (struct authby) { .never = true, })) {
			llog(RC_FATAL, c->logger,
			     ADD_FAILED_PREFIX"shunt connection cannot have authentication method other then authby=never");
			return false;
		}
	} else {
		switch (wm->policy & (POLICY_AUTHENTICATE | POLICY_ENCRYPT)) {
		case LEMPTY:
			if (!wm->authby.never) {
				llog(RC_FATAL, c->logger,
				     ADD_FAILED_PREFIX"non-shunt connection must have AH or ESP");
				return false;
			}
			break;
		case POLICY_AUTHENTICATE | POLICY_ENCRYPT:
			llog(RC_FATAL, c->logger,
				    ADD_FAILED_PREFIX"non-shunt connection must not specify both AH and ESP");
			return false;
		}
	}

	if (wm->ike_version == IKEv1) {
#ifdef USE_IKEv1
		if (pluto_ikev1_pol != GLOBAL_IKEv1_ACCEPT) {
			llog(RC_FATAL, c->logger,
			     ADD_FAILED_PREFIX"global ikev1-policy does not allow IKEv1 connections");
			return false;
		}
#else
		llog(RC_FATAL, c->logger, ADD_FAILED_PREFIX"IKEv1 support not compiled in");
		return false;
#endif
	}
	config->ike_version = wm->ike_version;
	static const struct ike_info ike_info[] = {
		[0] = {
			.version = 0,
			.version_name = "INVALID",
			.sa_type_name[IKE_SA] = "PARENT?!?",
			.sa_type_name[IPSEC_SA] = "CHILD?!?",
		},
		[IKEv1] = {
			.version = IKEv1,
			.version_name = "IKEv1",
			.sa_name[IKE_SA] = "ISAKMP",
			.sa_name[IPSEC_SA] = "IPsec",
			.sa_type_name[IKE_SA] = "ISAKMP SA",
			.sa_type_name[IPSEC_SA] = "IPsec SA",
		},
		[IKEv2] = {
			.version = IKEv2,
			.version_name = "IKEv2",
			.sa_name[IKE_SA] = "IKE",
			.sa_name[IPSEC_SA] = "Child",
			.sa_type_name[IKE_SA] = "IKE SA",
			.sa_type_name[IPSEC_SA] = "Child SA",
		},
	};
	passert(wm->ike_version < elemsof(ike_info));
	config->ike_info = &ike_info[wm->ike_version];

	if (wm->policy & POLICY_OPPORTUNISTIC &&
	    c->config->ike_version < IKEv2) {
		llog(RC_FATAL, c->logger,
		     ADD_FAILED_PREFIX"opportunistic connection MUST have IKEv2");
		return false;
	}

	if (wm->policy & POLICY_MOBIKE &&
	    c->config->ike_version < IKEv2) {
		llog(RC_FATAL, c->logger,
		     ADD_FAILED_PREFIX"MOBIKE requires IKEv2");
		return false;
	}

	if ((wm->policy & POLICY_MOBIKE) &&
	    (wm->policy & POLICY_TUNNEL) == LEMPTY) {
		llog(RC_FATAL, c->logger,
		     ADD_FAILED_PREFIX"MOBIKE requires tunnel mode");
		return false;
	}

	if (wm->policy & POLICY_IKEV2_ALLOW_NARROWING &&
	    c->config->ike_version < IKEv2) {
		llog(RC_FATAL, c->logger,
		     ADD_FAILED_PREFIX"narrowing=yes requires IKEv2");
		return false;
	}

	if (wm->iketcp != IKE_TCP_NO &&
	    c->config->ike_version < IKEv2) {
		llog(RC_FATAL, c->logger,
		     ADD_FAILED_PREFIX"enable-tcp= requires IKEv2");
		return false;
	}

	if (wm->policy & POLICY_MOBIKE) {
		if (kernel_ops->migrate_ipsec_sa_is_enabled == NULL) {
			llog(RC_FATAL, c->logger,
			     ADD_FAILED_PREFIX"MOBIKE is not supported by %s kernel interface",
			     kernel_ops->interface_name);
			return false;
		}
		/* probe the interface */
		err_t err = kernel_ops->migrate_ipsec_sa_is_enabled(c->logger);
		if (err != NULL) {
			llog(RC_FATAL, c->logger,
			     ADD_FAILED_PREFIX"MOBIKE support is not enabled for %s kernel interface: %s",
			     kernel_ops->interface_name, err);
			return false;
		}
	}

	/* RFC 8229 TCP encap*/

	if (NEVER_NEGOTIATE(wm->policy)) {
		if (wm->iketcp != IKE_TCP_NO) {
			llog(RC_INFORMATIONAL, c->logger,
			     "ignored enable-tcp= option for type=passthrough connection");
		}
		/* cleanup inherited default */
		c->iketcp = IKE_TCP_NO;
		c->remote_tcpport = 0;
	} else {
		if (wm->iketcp != IKE_TCP_NO && (wm->remote_tcpport == 0 || wm->remote_tcpport == 500)) {
			llog(RC_FATAL, c->logger,
			     ADD_FAILED_PREFIX"tcp-remoteport cannot be 0 or 500");
			return false;
		}
		c->remote_tcpport = wm->remote_tcpport;
		c->iketcp = wm->iketcp;
	}

	/* authentication (proof of identity) */

	if (NEVER_NEGOTIATE(wm->policy)) {
		dbg("ignore sighash, never negotiate");
	} else if (c->config->ike_version == IKEv1) {
		dbg("ignore sighash, IKEv1");
	} else {
		config->sighash_policy = wm->sighash_policy;
	}

	/* some port stuff */

	if (wm->right.protoport.has_port_wildcard && wm->left.protoport.has_port_wildcard) {
		llog(RC_FATAL, c->logger,
		     ADD_FAILED_PREFIX"cannot have protoports with wildcard (%%any) ports on both sides");
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
		llog_diag(RC_FATAL, c->logger, &d, ADD_FAILED_PREFIX);
		return false;
	}
	if (host_afi == NULL) {
		llog(RC_FATAL, c->logger,
		     ADD_FAILED_PREFIX"host address family unknown");
		return false;
	}

	/*
	 * When the other side is wildcard: we must check if other
	 * conditions met.
	 *
	 * MAKE this more sane in the face of unresolved IP
	 * addresses.
	 */
	if (wm->left.host_type != KH_IPHOSTNAME && !address_is_specified(wm->left.host_addr) &&
	    wm->right.host_type != KH_IPHOSTNAME && !address_is_specified(wm->right.host_addr)) {
		llog(RC_FATAL, c->logger,
		     ADD_FAILED_PREFIX"must specify host IP address for our side");
		return false;
	}

	/* duplicate any alias, adding spaces to the beginning and end */
	config->connalias = clone_str(wm->connalias, "connection alias");

	config->dnshostname = clone_str(wm->dnshostname, "connection dnshostname");
	c->policy = wm->policy;

	if (!extract_shunt("prospective", &config->prospective_shunt,
			   wm->prospective_shunt, prospective_shunt_ok,
			   /*unset*/SHUNT_TRAP, c->logger)) {
		return false;
	}

	if (!extract_shunt("negotiation", &config->negotiation_shunt,
			   wm->negotiation_shunt, negotiation_shunt_ok,
			   /*unset*/SHUNT_HOLD, c->logger)) {
		return false;
	}

	if (libreswan_fipsmode() && config->negotiation_shunt == SHUNT_PASS) {
		enum_buf sb;
		llog(RC_LOG_SERIOUS, c->logger,
		     "FIPS: ignored negotiationshunt=%s - packets MUST be blocked in FIPS mode",
		     str_enum_short(&shunt_policy_names, config->negotiation_shunt, &sb));
		config->negotiation_shunt = SHUNT_HOLD;
	}

	if (!extract_shunt("failure", &config->failure_shunt,
			   wm->failure_shunt, failure_shunt_ok,
			   /*unset*/SHUNT_NONE, c->logger)) {
		return false;
	}

	if (libreswan_fipsmode() && config->failure_shunt != SHUNT_NONE) {
		enum_buf eb;
		llog(RC_LOG_SERIOUS, c->logger,
		     "FIPS: ignored failureshunt=%s - packets MUST be blocked in FIPS mode",
		     str_enum_short(&shunt_policy_names, config->failure_shunt, &eb));
		config->failure_shunt = SHUNT_NONE;
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
	} else if (wm->sa_replay_window > kernel_ops->max_replay_window) {
		llog(RC_FATAL, c->logger,
		     ADD_FAILED_PREFIX"replay-window=%ju exceeds %s limit of %ju",
		     wm->sa_replay_window,
		     kernel_ops->interface_name, kernel_ops->max_replay_window);
		return false;
	}

	connection_buf cb;
	policy_buf pb;
	dbg("added new %s connection "PRI_CONNECTION" with policy %s",
	    c->config->ike_info->version_name,
	    pri_connection(c, &cb), str_connection_policies(c, &pb));

	/* IKE cipher suites */

	if (NEVER_NEGOTIATE(wm->policy)) {
		if (wm->ike != NULL) {
			llog(RC_INFORMATIONAL, c->logger,
			     "ignored ike= option for type=passthrough connection");
		}
	} else if (!wm->authby.never && (wm->ike != NULL ||
					 wm->ike_version == IKEv2)) {
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
				  ADD_FAILED_PREFIX);
			free_proposal_parser(&parser);
			/* caller will free C */
			return false;
		}
		free_proposal_parser(&parser);

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
					  "IKE SA proposals (connection add)");
		}
	}

	/* ESP or AH cipher suites (but not both) */

	if (NEVER_NEGOTIATE(wm->policy)) {
		if (wm->esp != NULL) {
			llog(RC_INFORMATIONAL, c->logger,
			     "ignored esp= option for type=passthrough connection");
		}
	} else if (wm->esp != NULL ||
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
		 * We checked above that exactly one of POLICY_ENCRYPT
		 * and POLICY_AUTHENTICATE is on.  The only difference
		 * in processing is which function is called (and
		 * those functions are almost identical).
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
				  ADD_FAILED_PREFIX);
			free_proposal_parser(&parser);
			/* caller will free C */
			return false;
		}
		free_proposal_parser(&parser);

		LSWDBGP(DBG_BASE, buf) {
			jam_string(buf, "ESP/AH string values: ");
			jam_proposals(buf, c->config->child_proposals.p);
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
		 * .child_proposals, and modifiying those triggers the
		 * creation of a new connection (true?), the
		 * connection can be cached.
		 */
		if (c->config->ike_version == IKEv2) {
			/* UNSET_GROUP means strip DH from the proposal. */
			config->v2_ike_auth_child_proposals =
				get_v2_child_proposals(c, "loading config", &unset_group,
						       c->logger);
			llog_v2_proposals(LOG_STREAM/*not-whack*/|RC_LOG, c->logger,
					  config->v2_ike_auth_child_proposals,
					  "Child SA proposals (connection add)");
		}
	}

	if (NEVER_NEGOTIATE(wm->policy)) {
		dbg("skipping over misc settings as NEVER_NEGOTIATE");
	} else {
		/* http://csrc.nist.gov/publications/nistpubs/800-77/sp800-77.pdf */
		extract_max_sa_lifetime("IKE", &config->sa_ike_max_lifetime, wm->sa_ike_max_lifetime,
					FIPS_IKE_SA_LIFETIME_MAXIMUM, IKE_SA_LIFETIME_MAXIMUM, c->logger);
		extract_max_sa_lifetime("IPsec", &config->sa_ipsec_max_lifetime, wm->sa_ipsec_max_lifetime,
					FIPS_IPSEC_SA_LIFETIME_MAXIMUM, IPSEC_SA_LIFETIME_MAXIMUM, c->logger);

		config->nic_offload = wm->nic_offload;
		config->sa_rekey_margin = wm->sa_rekey_margin;
		config->sa_rekey_fuzz = wm->sa_rekey_fuzz;
		c->sa_replay_window = wm->sa_replay_window;

		config->retransmit_timeout = wm->retransmit_timeout;
		config->retransmit_interval = wm->retransmit_interval;

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
		config->sa_ipsec_max_bytes = wm->sa_ipsec_max_bytes;
		if (wm->sa_ipsec_max_bytes > IPSEC_SA_MAX_OPERATIONS) {
			llog(RC_LOG_SERIOUS, c->logger,
			     "IPsec max bytes limited to the maximum allowed %s",
			     IPSEC_SA_MAX_OPERATIONS_STRING);
			config->sa_ipsec_max_bytes = IPSEC_SA_MAX_OPERATIONS;
		}
		config->sa_ipsec_max_packets = wm->sa_ipsec_max_packets;
		if (wm->sa_ipsec_max_packets > IPSEC_SA_MAX_OPERATIONS) {
			llog(RC_LOG_SERIOUS, c->logger,
			     "IPsec max packets limited to the maximum allowed %s",
			     IPSEC_SA_MAX_OPERATIONS_STRING);
			config->sa_ipsec_max_packets = IPSEC_SA_MAX_OPERATIONS;
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
		config->send_initial_contact = wm->initial_contact;
		config->send_vid_cisco_unity = wm->cisco_unity;
		config->send_vid_fake_strongswan = wm->fake_strongswan;
		config->send_vendorid = wm->send_vendorid;
		c->send_ca = wm->send_ca;
		config->xauthby = wm->xauthby;
		config->xauthfail = wm->xauthfail;

		diag_t d = ttoaddresses_num(shunk1(wm->modecfg_dns), ", ",
					    /* IKEv1 doesn't do IPv6 */
					    (wm->ike_version == IKEv1 ? &ipv4_info : NULL),
					    &config->modecfg.dns);
		if (d != NULL) {
			llog_diag(RC_FATAL, c->logger, &d,
				  ADD_FAILED_PREFIX"modecfgdns=%s invalid: ",
				  wm->modecfg_dns);
			/* caller will free C */
			return false;
		}

		config->modecfg.domains = clone_shunk_tokens(shunk1(wm->modecfg_domains),
							     ", ", HERE);
		if (wm->ike_version == IKEv1 &&
		    config->modecfg.domains != NULL &&
		    config->modecfg.domains[1].ptr != NULL) {
			llog(RC_LOG_SERIOUS, c->logger,
			     "IKEv1 only uses the first domain in modecfgdomain=%s",
			     wm->modecfg_domains);
			config->modecfg.domains[1] = null_shunk;
		}

		config->modecfg.banner = clone_str(wm->modecfg_banner, "connection modecfg_banner");


		/* RFC 5685 - IKEv2 Redirect mechanism */
		config->redirect.to = clone_str(wm->redirect_to, "connection redirect_to");
		config->redirect.accept = clone_str(wm->accept_redirect_to, "connection accept_redirect_to");

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
			if (err != NULL) {
				llog(RC_FATAL, c->logger,
				     ADD_FAILED_PREFIX"ipsec-interface=%u not supported. %s",
				     wm->xfrm_if_id, err);
				return false;
			}
			if (!setup_xfrm_interface(c, wm->xfrm_if_id == 0 ?
						  PLUTO_XFRMI_REMAP_IF_ID_ZERO : wm->xfrm_if_id )) {
				/* XXX: never happens?!? */
				llog(RC_FATAL, c->logger,
				     ADD_FAILED_PREFIX"setup xfrmi interface failed");
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
	config->send_no_esp_tfc = wm->send_no_esp_tfc;

	/*
	 * Since security labels use the same REQID for everything,
	 * pre-assign it.
	 */
	config->sa_reqid = (wm->sa_reqid != 0 ? wm->sa_reqid :
			    wm->ike_version != IKEv2 ? /*generated later*/0 :
			    wm->sec_label != NULL ? gen_reqid() :
			    /*generated later*/0);
	dbg(PRI_CONNECTION" c->sa_reqid=%d because wm->sa_reqid=%d and sec-label=%s",
	    pri_connection(c, &cb),
	    config->sa_reqid, wm->sa_reqid,
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
			llog(RC_LOG_SERIOUS, c->logger, ADD_FAILED_PREFIX"%s: policy-label=%s",
			     ugh, wm->sec_label);
			return false;
		}
		config->sec_label = clone_hunk(sec_label, "struct config sec_label");
	}

	if (wm->left.addresspool != NULL && wm->right.addresspool != NULL) {
		llog(RC_FATAL, c->logger, ADD_FAILED_PREFIX"both left and right define addresspool=");
		return false;
	}

	/*
	 * Determine the connection KIND from the wm.
	 *
	 * Save it in a local variable so code can use that (and be
	 * forced to only use value after it's been determined).  Yea,
	 * hack.
	 */
	const enum connection_kind connection_kind =
		c->kind = extract_connection_kind(wm, c->logger);

	if (connection_kind == CK_GROUP) {
		add_to_groups(c);
	}

	if (wm->left.virt != NULL && wm->right.virt != NULL) {
		llog(RC_FATAL, c->logger,
		     ADD_FAILED_PREFIX"both left and right define virtual subnets");
		return false;
	}

	if (connection_kind == CK_GROUP &&
	    (wm->left.virt != NULL || wm->right.virt != NULL)) {
		llog(RC_FATAL, c->logger,
		     ADD_FAILED_PREFIX"connection groups do not support virtual subnets");
		return false;
	}

	/*
	 * Unpack and verify the ends.
	 */

	const struct whack_end *whack_ends[] = {
		[LEFT_END] = &wm->left,
		[RIGHT_END] = &wm->right,
	};

	bool same_ca[END_ROOF] = { false, };

	FOR_EACH_THING(this, LEFT_END, RIGHT_END) {
		diag_t d;
		int that = (this + 1) % END_ROOF;
		d = extract_host_end(c, &c->end[this].host,
				     &config->end[this].host, &config->end[that].host,
				     wm, whack_ends[this], whack_ends[that],
				     &same_ca[this], c->logger);
		if (d != NULL) {
			llog_diag(RC_FATAL, c->logger, &d, ADD_FAILED_PREFIX);
			return false;
		}
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
	 * Determine the host topology.
	 *
	 * Needs two passes: first pass extracts tentative
	 * host/nexthop; scecond propogates that to other dependent
	 * fields.
	 *
	 * XXX: the host lookup is blocking; should instead do it
	 * asynchronously using unbound.
	 *
	 * XXX: move the find nexthop code to here?
	 */
	ip_address host_addr[END_ROOF];
	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		const struct whack_end *we = whack_ends[end];
		struct host_end *host = &c->end[end].host;
		host_addr[end] = host_afi->address.unspec;
		if (address_is_specified(we->host_addr)) {
			host_addr[end] = we->host_addr;
		} else if (we->host_type == KH_IPHOSTNAME) {
			ip_address addr;
			err_t er = ttoaddress_dns(shunk1(we->host_addr_name),
						  host_afi, &addr);
			if (er != NULL) {
				llog(RC_COMMENT, c->logger,
				     "failed to resolve '%s=%s' at load time: %s",
				     we->leftright, we->host_addr_name, er);
			} else {
				host_addr[end] = addr;
			}
		}
		host->nexthop = we->host_nexthop;
	}

	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		update_hosts_from_end_host_addr(c, end, host_addr[end], HERE); /* from add */
	}

	/*
	 * Cross-check the auth= vs authby= results.
	 */

	if (c->local->host.config->xauth.server || c->remote->host.config->xauth.server)
		c->policy |= POLICY_XAUTH;

	if (NEVER_NEGOTIATE(c->policy)) {
		if (!PEXPECT(c->logger,
			     c->local->host.config->auth == AUTH_NEVER &&
			     c->remote->host.config->auth == AUTH_NEVER)) {
			return false;
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
			llog(RC_FATAL, c->logger,
			     ADD_FAILED_PREFIX"no authentication (auth=, authby=) was set");
			return false;
		}

		if ((c->local->host.config->auth == AUTH_PSK && c->remote->host.config->auth == AUTH_NULL) ||
		    (c->local->host.config->auth == AUTH_NULL && c->remote->host.config->auth == AUTH_PSK)) {
			llog(RC_FATAL, c->logger,
			     ADD_FAILED_PREFIX"cannot mix PSK and NULL authentication (%sauth=%s and %sauth=%s)",
			     c->local->config->leftright,
			     enum_name(&keyword_auth_names, c->local->host.config->auth),
			     c->remote->config->leftright,
			     enum_name(&keyword_auth_names, c->remote->host.config->auth));
			return false;
		}
	}

	/* set internal fields */
	c->instance_serial = 0;
	c->interface = NULL; /* initializing */

	c->newest_ike_sa = SOS_NOBODY;
	c->newest_ipsec_sa = SOS_NOBODY;
	c->temp_vars.num_redirects = 0;

	/* non configurable */
	c->ike_window = IKE_V2_OVERLAPPING_WINDOW_SIZE;

	/*
	 * We cannot have unlimited keyingtries for Opportunistic, or
	 * else we gain infinite partial IKE SA's. But also, more than
	 * one makes no sense, since it will be installing a
	 * failureshunt (not negotiationshunt) on the 2nd keyingtry,
	 * and try to re-install another negotiation or failure shunt
	 */
	if (NEVER_NEGOTIATE(wm->policy)) {
		dbg("skipping sa_keying_tries as NEVER_NEGOTIATE");
	} else if ((wm->policy & POLICY_OPPORTUNISTIC) &&
		   wm->sa_keying_tries == 0) {
		c->sa_keying_tries = 1;
		llog(RC_LOG, c->logger,
		     "the connection is Opportunistic, but used keyingtries=0. The specified value was changed to 1");
	} else {
		c->sa_keying_tries = wm->sa_keying_tries;
	}

	/*
	 * Extract the child configuration and save it.
	 */

	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		d = extract_child_end_config(wm, whack_ends[end],
					     &config->end[end].child,
					     c->logger);
		if (d != NULL) {
			llog_diag(RC_FATAL, c->logger, &d, ADD_FAILED_PREFIX);
			return false;
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

	struct {
		bool used;
		const char *field;
		char *value;
	} end_family[END_ROOF][IP_INDEX_ROOF] = {0};
	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		const ip_selectors *const selectors = &c->end[end].config->child.selectors;
		const ip_ranges *const pools = &c->end[end].config->host.pool_ranges;
		if (selectors->len > 0) {
			for (const ip_selector *s = selectors->list;
			     s < selectors->list + selectors->len;
			     s++) {
				const struct ip_info *afi = selector_type(s);
				end_family[end][afi->ip_index].used = true;
				end_family[end][afi->ip_index].field = "subnet";
				end_family[end][afi->ip_index].value = whack_ends[end]->subnet;
			}
		} else if (pools->len > 0) {
			for (const ip_range *s = pools->list;
			     s < pools->list + pools->len;
			     s++) {
				const struct ip_info *afi = range_type(s);
				end_family[end][afi->ip_index].used = true;
				end_family[end][afi->ip_index].field = "addresspool";
				end_family[end][afi->ip_index].value = whack_ends[end]->addresspool;
			}
		} else {
			end_family[end][host_afi->ip_index].used = true;
			end_family[end][host_afi->ip_index].field = "";
			end_family[end][host_afi->ip_index].value = whack_ends[end]->host_addr_name;
		}
	}

	/* now check there's a match */
	FOR_EACH_THING(afi, &ipv4_info, &ipv6_info) {
		enum ip_index i = afi->ip_index;
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
		llog(RC_FATAL, c->logger,
		     ADD_FAILED_PREFIX"address family of left%s=%s conflicts with right%s=%s",
		     end_family[LEFT_END][i].field,
		     end_family[LEFT_END][i].value,
		     end_family[RIGHT_END][j].field,
		     end_family[RIGHT_END][j].value);
		return false;
	}

	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		const ip_selectors *const selectors = &c->end[end].config->child.selectors;
		if (selectors->len > 0) {
			c->end[end].child.selectors.proposed = *selectors;
		} else {
			/*
			 * to-be-determined from the host or the
			 * opportunistic group.
			 */
			c->end[end].child.selectors.assigned[0] = unset_selector;
			c->end[end].child.selectors.proposed.len = 1;
			c->end[end].child.selectors.proposed.list = c->end[end].child.selectors.assigned;
		}
		set_end_child_has_client(c, end, c->end[end].config->child.selectors.len > 0);
	}

	/*
	 * Is spd.reqid necessary for all c?  CK_INSTANCE or
	 * CK_PERMANENT need one.  Does CK_TEMPLATE need one?
	 */
	c->child.reqid = (c->config->sa_reqid == 0 ? gen_reqid() : c->config->sa_reqid);
	ldbg(c->logger, "child.reqid=%d because c->sa_reqid=%d (%s)",
	     c->child.reqid, c->config->sa_reqid,
	     (c->config->sa_reqid == 0 ? "generate" : "use"));

	/*
	 * Fill in the child SPDs using the previously parsed
	 * selectors.
	 */

	set_connection_spds(c, host_afi);
	if (!pexpect(c->spd != NULL)) {
		return false;
	}

	/*
	 * All done, enter it into the databases.  Since orient() may
	 * switch ends, triggering an spd rehash, insert things into
	 * the database first.
	 */
	connection_db_add(c);
	spd_route_db_add_connection(c);

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

	/* will inherit defaults */
	lset_t debugging = lmod(LEMPTY, wm->debugging);
	struct connection *c = alloc_connection(wm->name,
						debugging, logger->global_whackfd,
						HERE);

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
			    c->config->ike_info->version_name);
	/* connection is good-to-go: log against it */
	llog(RC_LOG, c->logger, "added %s connection", what);
	policy_buf pb;
	dbg("ike_life: %jd; ipsec_life: %jds; rekey_margin: %jds; rekey_fuzz: %lu%%; keyingtries: %lu; replay_window: %u; policy: %s ipsec_max_bytes: %" PRIu64 " ipsec_max_packets %" PRIu64,
	    deltasecs(c->config->sa_ike_max_lifetime),
	    deltasecs(c->config->sa_ipsec_max_lifetime),
	    deltasecs(c->config->sa_rekey_margin),
	    c->config->sa_rekey_fuzz,
	    c->sa_keying_tries,
	    c->sa_replay_window,
	    str_connection_policies(c, &pb),
	    c->config->sa_ipsec_max_bytes,
	    c->config->sa_ipsec_max_packets);
	char topo[CONN_BUF_LEN];
	dbg("%s", format_connection(topo, sizeof(topo), c, c->spd));
	release_whack(c->logger, HERE);
}

/*
 * Derive a template connection from a group connection and target.
 *
 * Similar to instantiate().  Happens at whack --listen.  Returns new
 * connection.  Null on failure (duplicated name).
 */

struct connection *group_instantiate(struct connection *group,
				     const ip_subnet remote_subnet,
				     const struct ip_protocol *protocol,
				     ip_port local_port,
				     ip_port remote_port)
{
	subnet_buf rsb;
	ldbg_connection(group, HERE, "instantiate: "PRI_HPORT" %s -> [%s]:"PRI_HPORT,
			pri_hport(local_port),
			protocol->name,
			str_subnet(&remote_subnet, &rsb),
			pri_hport(remote_port));
	PASSERT(group->logger, group->kind == CK_GROUP);
	PASSERT(group->logger, oriented(group));
	PASSERT(group->logger, protocol != NULL);
	PASSERT(group->logger, (group->spd == NULL ||
				group->spd->spd_next == NULL));
	PASSERT(group->logger, (group->spd == NULL ||
				group->spd->local->virt == NULL));

	/*
	 * Manufacture a unique name for this template.
	 */
	char *namebuf; /* must free */
	if (protocol == &ip_protocol_all) {
		/* all protocols implies all ports */
		pexpect(local_port.hport == 0);
		pexpect(remote_port.hport == 0);
		subnet_buf tb;
		namebuf = alloc_printf("%s#%s", group->name,
				       str_subnet(&remote_subnet, &tb));
	} else {
		subnet_buf tb;
		namebuf = alloc_printf("%s#%s-("PRI_HPORT"--%d--"PRI_HPORT")",
				       group->name,
				       str_subnet(&remote_subnet, &tb),
				       pri_hport(local_port),
				       protocol->ipproto,
				       pri_hport(remote_port));
	}

	if (conn_by_name(namebuf, false/*!strict*/) != NULL) {
		llog(RC_DUPNAME, group->logger,
		     "group name + target yields duplicate name \"%s\"", namebuf);
		pfreeany(namebuf);
		return NULL;
	}

	struct connection *t = clone_connection(namebuf, group, NULL/*id*/, HERE);

	passert(t->name != namebuf); /* see clone_connection() */
	PASSERT(group->logger, group->foodgroup == NULL);
	t->foodgroup = clone_str(namebuf, "foodgroups");
	pfreeany(namebuf);

	/*
	 * For the remote end, just use what ever the group specified
	 * (i.e., ignore protoport=).
	 */
	ip_selector remote_selector =
		selector_from_subnet_protocol_port(remote_subnet, protocol, remote_port);
	set_first_selector(t, remote, remote_selector);

	/*
	 * Figure out the local selector; it was either specified
	 * using subnet= or it needs to be derived from the host.
	 *
	 * XXX: this is looking like potential boiler plate code.
	 */

	ip_selector local_selector;
	if (t->local->child.config->selectors.len > 0) {
		/*
		 * Selector contains subnet= possibly already merged
		 * with protoport=.
		 */
		local_selector = t->local->child.config->selectors.list[0];
	} else {
		/*
		 * Need to mash protoport and local .host_addr
		 * together, and then combined with what was specified
		 * by the group.
		 */
		local_selector = selector_from_address_protoport(t->local->host.addr,
								 t->local->child.config->protoport);
	}

	/*
	 * If the group entry specifies a protoport, override those
	 * fields in the selector.
	 */

	if (protocol != &ip_protocol_all) {
		ip_subnet local_subnet = selector_subnet(local_selector);
		local_selector = selector_from_subnet_protocol_port(local_subnet,
								    protocol,
								    local_port);
	}

	set_first_selector(t, local, local_selector);

	t->policy &= ~(POLICY_GROUP | POLICY_GROUTED);
	t->policy |= POLICY_GROUPINSTANCE; /* mark as group instance for later */
	t->kind = (!address_is_specified(t->remote->host.addr) &&
		   !NEVER_NEGOTIATE(t->policy)) ? CK_TEMPLATE : CK_INSTANCE;

	/* leave a breadcrumb */
	PASSERT(t->logger, t->child.routing == RT_UNROUTED);
	set_child_routing(t, RT_UNROUTED);

	t->child.reqid = (t->config->sa_reqid == 0 ? gen_reqid() :
			  t->config->sa_reqid);
	ldbg(t->logger,
	     "%s t.child.reqid=%d because group->sa_reqid=%d (%s)",
	     t->name, t->child.reqid, t->config->sa_reqid,
	     (t->config->sa_reqid == 0 ? "generate" : "use"));

	/*
	 * Same host_pair as parent: stick after parent on list.
	 * t->hp_next = group->hp_next; // done by clone_connection
	 */
	group->hp_next = t;

	/* all done */
	connection_db_add(t);

	/* fill in the SPDs */
	add_connection_spds(t);

	connection_buf gb;
	ldbg_connection(t, HERE, "instantiated from "PRI_CONNECTION,
			pri_connection(group, &gb));
	return t;
}

/*
 * Common code for instantiating a Road Warrior or Opportunistic
 * connection.
 *
 * instantiate() doesn't generate SPDs from the selectors
 * spd_instantiate() does.
 *
 * peers_id can be used to carry over an ID discovered in Phase 1.  It
 * must not disagree with the one in c, but if that is unspecified,
 * the new connection will use peers_id.  If peers_id is NULL, and
 * c.that.id is uninstantiated (ID_NONE), the new connection will
 * continue to have an uninstantiated that.id.  Note: instantiation
 * does not affect port numbers.
 */

static struct connection *instantiate(struct connection *t,
				      const ip_address remote_addr,
				      const struct id *peer_id,
				      shunk_t sec_label,
				      const char *func, where_t where)
{
	address_buf ab;
	id_buf idb;
	ldbg_connection(t, where, "%s: remote=%s id=%s sec_label="PRI_SHUNK,
			func, str_address(&remote_addr, &ab),
			str_id(peer_id, &idb),
			pri_shunk(sec_label));

	PASSERT(t->logger, address_is_specified(remote_addr)); /* always */

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
	if (t->config->sec_label.len > 0) {
		/*
		 * Either:
		 *
		 * - T is the sec_label group template, and D is the
		 *   IKE connection (also treated like a template);
		 *   hence CK_TEMPLATE
		 *
		 *   The remote address is updated below.
		 *
		 * Or:
		 *
		 * - T is the IKE connection and and D is Child
		 *   connection; hence CK_INSTANCE
		 *
		 *   The sec_label is updated below.
		 *
		 * One problem is that, on the initiator, the child's
		 * connection is instantiated from the original
		 * template and not the hybrid.
		 */
		if (sec_label.len == 0) {
			PASSERT(t->logger, t->kind == CK_TEMPLATE);
			kind = CK_TEMPLATE; /*XXX:CK_HYBRID*/
		} else {
			PASSERT(t->logger, (t->kind == CK_HYBRID ||
					    t->kind == CK_TEMPLATE/*XXX:bug*/));
			kind = CK_INSTANCE;
		}
	} else {
		/* pexpect(address_is_specified(t->remote->host.addr) || peer_addr != NULL); true??? */
		PASSERT(t->logger, t->kind == CK_TEMPLATE);
		kind = CK_INSTANCE;
	}

	t->instance_serial++;	/* before clone */

	if (peer_id != NULL) {
		int wildcards;	/* value ignored */

		passert(t->remote->host.id.kind == ID_FROMCERT ||
			match_id("", peer_id, &t->remote->host.id, &wildcards));
	}

	struct connection *d = clone_connection(t->name, t, peer_id, HERE);
	passert(t->name != d->name); /* see clone_connection() */

	d->kind = kind;
	passert(oriented(d)); /*like parent like child*/

	/* propogate remote address when set */
	if (address_is_specified(d->remote->host.addr)) {
		/* can't change remote once set */
		PASSERT(d->logger, address_eq_address(remote_addr, d->remote->host.addr));
	} else {
		/* this updates ID NULL */
		update_hosts_from_end_host_addr(d, d->remote->config->index,
						remote_addr, HERE); /* from whack initiate */
	}

	d->child.reqid = (t->config->sa_reqid == 0 ? gen_reqid() : t->config->sa_reqid);
	dbg("%s .child.reqid=%d because t.config.sa_requid=%d (%s)",
	    d->name, d->child.reqid, t->config->sa_reqid,
	    (t->config->sa_reqid == 0 ? "generate" : "use"));

	/* which is true?  template could be prospective? */
#if 0
	pexpect(d->child.routing == RT_UNROUTED); /* CK_INSTANCE? */
	pexpect(d->child.routing == RT_PROSPECTIVE_EROUTED);  /* CK_GROUPINSTANCE? */
#endif
	set_child_routing(d, RT_UNROUTED);

	/*
	 * Reset; sec_label templates will have set this.
	 */
	d->newest_ike_sa = SOS_NOBODY;
	pexpect(d->newest_ipsec_sa == SOS_NOBODY);

	if (sec_label.len > 0) {
		/*
		 * Install the sec_label from either an acquire or
		 * child payload into both ends.
		 */
		pexpect(t->child.sec_label.ptr == NULL);
		d->child.sec_label = clone_hunk(sec_label, "instantiate() sec_label");
	}

	/* assumption: orientation is the same as c's */
	connect_to_host_pair(d);
	connection_db_add(d);

	/* XXX: could this use the connection number? */
	if (t->sa_marks.in.unique) {
		d->sa_marks.in.val = global_marks;
		d->sa_marks.out.val = global_marks;
		global_marks++;
		if (global_marks == UINT_MAX - 1) {
			/* we hope 2^32 connections ago are no longer around */
			global_marks = MINIMUM_IPSEC_SA_RANDOM_MARK;
		}
	}

	return d;
}

/*
 * In addition to instantiate() also clone the SPD entries.
 *
 * XXX: it's arguable that SPD entries are being created far too early
 * (currently during connection add).  The IKEv2 TS responder, for
 * instance, ends up throwing away the SPDs creating its own.
 */

static void clone_connection_spd(struct connection *d, struct connection *t)
{
	struct spd_route **dst = &d->spd;
	for (struct spd_route *old = t->spd; old != NULL; old = old->spd_next) {
		struct spd_route *new = clone_thing(*old, __func__);
		zero_thing(new->hash_table_entries); /* keep init_list_entry() happy */
		new->connection = d;
		new->spd_next = NULL; /* break old chain */
		/* cross-link */
		new->local = &new->end[d->local->config->index];
		new->remote = &new->end[d->remote->config->index];
		FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
			new->end[end].virt = virtual_ip_addref(old->end[end].virt);
			new->end[end].host = &d->end[end].host;
			new->end[end].child = &d->end[end].child;
		}
		/* add to c->spd list ... */
		*dst = new;
		dst = &new->spd_next;
		/* ... before first use */
		spd_route_db_init_spd_route(new);
	}
}

struct connection *spd_instantiate(struct connection *t,
				   const ip_address remote_addr,
				   where_t where)
{
	struct connection *d = instantiate(t, remote_addr, /*peer-id*/NULL,
					   /*sec_label*/null_shunk,
					   __func__, where);

	/*
	 * XXX: code in rw_responder_id_instantiate() is slightly
	 * different - that code also handles remote subnets.
	 *
	 * XXX: identical to code in rw_responder_instantiate().
	 */
	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		const char *leftright = d->end[end].config->leftright;
		struct host_end *host = &d->end[end].host;
		struct child_end *child = &d->end[end].child;
		if (child->config->selectors.len > 0) {
			ldbg(d->logger, "%s.child has %d configured selectors",
			     leftright, child->config->selectors.len > 0);
			child->selectors.proposed = child->config->selectors;
		} else {
			ldbg(d->logger, "%s.child selector formed from host", leftright);
			/*
			 * Default the end's child selector (client) to a
			 * subnet containing only the end's host address.
			 */
			ip_selector selector =
				selector_from_address_protoport(host->addr,
								child->config->protoport);
			set_end_selector(d, end, selector);
		}
	}

	add_connection_spds(d);

	/* leave breadcrumb */
	pexpect(d->child.kernel_policy_owner == SOS_NOBODY);
	set_child_kernel_policy_owner(d, SOS_NOBODY);

	connection_buf tb;
	ldbg_connection(d, HERE, "instantiated from "PRI_CONNECTION,
			pri_connection(t, &tb));

	return d;
}

struct connection *sec_label_instantiate(struct ike_sa *ike,
					 shunk_t sec_label,
					 where_t where)
{
	struct connection *t = ike->sa.st_connection;
	/*
	 * XXX: the IKE SA should always have a CK_HYBRID connection
	 * bit that is currently only true on the responder.
	 */
	PEXPECT_WHERE(t->logger, where, (t->kind == CK_HYBRID ||
					 t->kind == CK_TEMPLATE/*XXX:bug*/));
	PEXPECT_WHERE(t->logger, where, t->config->sec_label.len > 0);
	PEXPECT_WHERE(t->logger, where, sec_label.len > 0);

	ip_address remote_addr = endpoint_address(ike->sa.st_remote_endpoint);
	struct connection *d = instantiate(t, remote_addr, /*peer-id*/NULL, sec_label,
					   __func__, where);

	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		if (t->end[end].child.selectors.proposed.list == t->end[end].child.config->selectors.list) {
			d->end[end].child.selectors.proposed = t->end[end].child.config->selectors;
		} else {
			d->end[end].child.selectors.assigned[0] = t->end[end].child.selectors.assigned[0];
			d->end[end].child.selectors.proposed.len = 1;
			d->end[end].child.selectors.proposed.list = d->end[end].child.selectors.assigned;
		}
 	}

	clone_connection_spd(d, t);

	update_spds_from_end_host_addr(d, d->remote->config->index, remote_addr, HERE);

	set_connection_priority(d); /* re-compute; may have changed */

	/* leave breadcrumb */
	pexpect(d->child.kernel_policy_owner == SOS_NOBODY);
	set_child_kernel_policy_owner(d, SOS_NOBODY);

	/* all done */
	spd_route_db_add_connection(d);

	connection_buf cb, db;
	address_buf pab;
	dbg("instantiated "PRI_CO" "PRI_CONNECTION" as "PRI_CO" "PRI_CONNECTION" using kind=%s remote_address=%s sec_label="PRI_SHUNK,
	    pri_co(t->serialno), pri_connection(t, &cb),
	    pri_co(d->serialno), pri_connection(d, &db),
	    enum_name(&connection_kind_names, d->kind),
	    str_address(&remote_addr, &pab),
	    pri_shunk(d->child.sec_label));

	return d;
}

struct connection *rw_responder_instantiate(struct connection *t,
					    const ip_address peer_addr,
					    where_t where)
{
	if (!PEXPECT(t->logger, (t->policy & POLICY_OPPORTUNISTIC) == LEMPTY)) {
		return NULL;
	}

	struct connection *d = instantiate(t, peer_addr,
					   /*TBD peer_id*/NULL,
					   /*TBD sec_label*/null_shunk,
					   __func__, where);

	/*
	 * XXX: code in rw_responder_id_instantiate() is slightly
	 * different - that code also handles remote subnets.
	 *
	 * XXX: identical to code in spd_instantiate().
	 */
	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		const char *leftright = d->end[end].config->leftright;
		struct host_end *host = &d->end[end].host;
		struct child_end *child = &d->end[end].child;
		if (child->config->selectors.len > 0) {
			ldbg(d->logger, "%s.child has %d configured selectors",
			     leftright, child->config->selectors.len > 0);
			child->selectors.proposed = child->config->selectors;
		} else {
			ldbg(d->logger, "%s.child selector formed from host", leftright);
			/*
			 * Default the end's child selector (client) to a
			 * subnet containing only the end's host address.
			 */
			ip_selector selector =
				selector_from_address_protoport(host->addr,
								child->config->protoport);
			set_end_selector(d, end, selector);
		}
	}

	add_connection_spds(d);

	connection_buf tb;
	ldbg_connection(d, HERE, "instantiated from "PRI_CONNECTION,
			pri_connection(t, &tb));
	return d;
}

struct connection *rw_responder_id_instantiate(struct connection *t,
					       const ip_address remote_addr,
					       const ip_selector *remote_subnet,
					       const struct id *remote_id)
{
	PASSERT(t->logger, (t->policy & POLICY_OPPORTUNISTIC) == LEMPTY);

	/*
	 * XXX: this function is never called when there are
	 * sec_labels?
	 */
	struct connection *d = instantiate(t, remote_addr, remote_id,
					   /*TBD sec_label?!?*/null_shunk,
					   __func__, HERE);

	/*
	 * XXX: unlike rw_responder_id_instantiate(), this code has to
	 * handle the remote subnet
	 */
	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		const char *leftright = d->end[end].config->leftright;
		struct host_end *host = &d->end[end].host;
		struct child_end *child = &d->end[end].child;
		if (child->config->selectors.len > 0) {
			ldbg(d->logger, "%s.child has %d configured selectors",
			     leftright, child->config->selectors.len > 0);
			child->selectors.proposed = child->config->selectors;
		} else if (child == &d->remote->child &&
			   remote_subnet != NULL &&
			   d->remote->config->child.virt != NULL) {
			PASSERT(d->logger, host == &d->remote->host);
			set_end_selector(d, end, *remote_subnet);
			if (selector_eq_address(*remote_subnet, d->remote->host.addr)) {
				ldbg(t->logger, "forcing remote %s.spd.has_client=false",
				     d->spd->remote->config->leftright);
				set_child_has_client(d, remote, false);
			}
		} else {
			ldbg(d->logger, "%s.child selector formed from host", leftright);
			/*
			 * Default the end's child selector (client) to a
			 * subnet containing only the end's host address.
			 */
			ip_selector selector =
				selector_from_address_protoport(host->addr,
								child->config->protoport);
			set_end_selector(d, end, selector);
		}
	}

	add_connection_spds(d);

	connection_buf tb;
	ldbg_connection(d, HERE, "instantiated from "PRI_CONNECTION,
			pri_connection(t, &tb));
	return d;

}

/* priority formatting */
size_t jam_connection_priority(struct jambuf *buf, connection_priority_t pp)
{
	if (pp == BOTTOM_PRIORITY) {
		return jam_string(buf, "0");
	}

	return jam(buf, "%" PRIu32 ",%" PRIu32,
		   pp >> 17, (pp & ~(~(connection_priority_t)0 << 17)) >> 8);
}

const char *str_connection_priority(connection_priority_t pp, connection_priority_buf *buf)
{
	struct jambuf jb = ARRAY_AS_JAMBUF(buf->buf);
	jam_connection_priority(&jb, pp);
	return buf->buf;
}

void set_connection_priority(struct connection *c)
{
	c->priority = (((connection_priority_t)c->spd->local->client.maskbits << 17) |
		       ((connection_priority_t)c->spd->remote->client.maskbits << 8) |
		       ((connection_priority_t)1));
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
		   selector_range_eq_address(selectors->list[0], host_addr)) {
		/* compact denotation for "self" */
	} else {
		s += jam_string(b, prefix);
		for (const ip_selector *selector = selectors->list;
		     selector < selectors->list + selectors->len;
		     selector++) {
			if (pexpect(selector->is_set)) {
				s += jam_selector_subnet(b, selector);
				if (selector_is_zero(*selector)) {
					s += jam_string(b, "?");
				}
			} else {
				s += jam_string(b, "?");
			}
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
		s += jam_string(buf, c->config->ike_info->version_name);
		sep = "+";
	}

	lset_t policy = c->policy;

	struct authby authby = c->local->host.config->authby;
	if (authby_is_set(authby)) {
		s += jam_string(buf, sep);
		s += jam_authby(buf, authby);
		sep = "+";
	}

	if (policy != LEMPTY) {
		s += jam_string(buf, sep);
		s += jam_lset_short(buf, &sa_policy_bit_names, "+", policy);
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
	connection_priority_t best_priority = BOTTOM_PRIORITY;
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

		/*
		 * XXX: is the !sec_label an IKEv1 thing?  An IKEv2
		 * sec-labeled connection should have been routed by
		 * now?
		 */
		if (!routed(c->child.routing) &&
		    !c->instance_initiation_ok &&
		    c->config->sec_label.len == 0) {
			connection_buf cb;
			selector_pair_buf sb;
			dbg("    skipping "PRI_CONNECTION" %s; !routed,!instance_initiation_ok,!sec_label",
			    pri_connection(c, &cb),
			    str_selector_pair(&c->spd->local->client, &c->spd->remote->client, &sb));
			continue;
		}

		for (struct spd_route *sr = c->spd;
		     /* bail if below sets BEST_CONECTION to C */
		     best_connection != c && sr != NULL;
		     sr = sr->spd_next) {

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

			if (!selector_in_selector(packet_src, sr->local->client)) {
				connection_buf cb;
				selector_pair_buf sb;
				selector_buf psb;
				dbg("    skipping "PRI_CONNECTION" %s; packet src %s not in range",
				    pri_connection(c, &cb),
				    str_selector_pair(&c->spd->local->client, &c->spd->remote->client, &sb),
				    str_selector(&packet_src, &psb));
				continue;
			}

			if (!endpoint_in_selector(packet_dst, sr->remote->client)) {
				connection_buf cb;
				selector_pair_buf sb;
				endpoint_buf eb;
				dbg("    skipping "PRI_CONNECTION" %s; packet dst %s not in range",
				    pri_connection(c, &cb),
				    str_selector_pair(&c->spd->local->client, &c->spd->remote->client, &sb),
				    str_endpoint(&packet_dst, &eb));
				continue;
			}

			/*
			 * More exact is better and bigger
			 *
			 * For instance, exact protocol or exact port
			 * gets more points.
			 */
			connection_priority_t priority =
				(8 * (c->priority + (c->kind == CK_INSTANCE)) +
				 2 * (sr->local->client.hport == packet.src.hport) +
				 2 * (sr->remote->client.hport == packet.dst.hport) +
				 1 * (sr->local->client.ipproto == packet.protocol->ipproto));

			if (best_connection != NULL &&
			    priority <= best_priority) {
				connection_buf cb, bcb;
				selector_pair_buf sb, bsb;
				dbg("    skipping "PRI_CONNECTION" %s priority %"PRIu32"; doesn't best "PRI_CONNECTION" %s priority %"PRIu32,
				    pri_connection(c, &cb),
				    str_selector_pair(&c->spd->local->client, &c->spd->remote->client, &sb),
				    priority,
				    pri_connection(best_connection, &bcb),
				    str_selector_pair(&best_sr->local->client, &best_sr->remote->client, &bsb),
				    best_priority);
				continue;
			}

			/* current is best; log why */
			if (best_connection == NULL) {
				connection_buf cb;
				selector_pair_buf sb;
				ldbg(logger,
				     "    choosing "PRI_CONNECTION" %s priority %"PRIu32"; as first best",
				     pri_connection(c, &cb),
				     str_selector_pair(&c->spd->local->client, &c->spd->remote->client, &sb),
				     priority);
			} else {
				connection_buf cb, bcb;
				selector_pair_buf sb, bsb;
				ldbg(logger,
				     "    choosing "PRI_CONNECTION" %s priority %"PRIu32"; as bests "PRI_CONNECTION" %s priority %"PRIu32,
				     pri_connection(c, &cb),
				     str_selector_pair(&c->spd->local->client, &c->spd->remote->client, &sb),
				     priority,
				     pri_connection(best_connection, &bcb),
				     str_selector_pair(&best_sr->local->client, &best_sr->remote->client, &bsb),
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
		selector_pair_buf sb;
		enum_buf kb;
		dbg("  concluding with "PRI_CONNECTION" %s priority %" PRIu32 " kind=%s",
		    pri_connection(best_connection, &cib),
		    str_selector_pair(&best_sr->local->client, &best_sr->remote->client, &sb),
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

static struct connection *oppo_instantiate(struct connection *t,
					   const ip_address remote_address,
					   const char *func, where_t where)
{
	PASSERT(t->logger, t->kind == CK_TEMPLATE);
	PASSERT(t->logger, oriented(t)); /* else won't instantiate */
	PASSERT(t->logger, t->local->child.selectors.proposed.len == 1);
	PASSERT(t->logger, t->remote->child.selectors.proposed.len == 1);

	/*
	 * Instance inherits remote ID of child; exception being when
	 * ID is NONE when it is set to the remote address.
	 */

	struct connection *d = instantiate(t, remote_address,
					   /*peer_id*/NULL,
					   /*sec_label*/null_shunk,
					   func, where);

	PASSERT(d->logger, d->kind == CK_INSTANCE);
	PASSERT(d->logger, oriented(d)); /* else won't instantiate */
	PASSERT(d->logger, d->policy & POLICY_OPPORTUNISTIC);
	PASSERT(d->logger, address_eq_address(d->remote->host.addr, remote_address));

	/*
	 * Remember if the template is routed:
	 * if so, this instance applies for initiation
	 * even if it is created for responding.
	 *
	 * D will have had its routing reset.
	 *
	 * XXX: huh?
	 */
	if (routed(t->child.routing)) {
		d->instance_initiation_ok = true;
	}
	ldbg(d->logger, "template routing %s instance routing %s instance_initiation_ok %s",
	     enum_name_short(&routing_names, t->child.routing),
	     enum_name_short(&routing_names, d->child.routing),
	     bool_str(d->instance_initiation_ok));

	/*
	 * Fill in the local client - just inherit the parent's value.
	 */
	set_first_selector(d, local, t->local->child.selectors.proposed.list[0]);

	/*
	 * Fill in peer's client side.
	 */
	PASSERT(d->logger, t->remote->child.selectors.proposed.len == 1);
	ip_selector remote_template = t->remote->child.selectors.proposed.list[0];
	/* see also caller checks */
	PASSERT(d->logger, address_in_selector_range(remote_address, remote_template));
	ip_selector remote_selector =
		selector_from_address_protocol_port(remote_address,
						    selector_protocol(remote_template),
						    selector_port(remote_template));
	set_first_selector(d, remote, remote_selector);

	add_connection_spds(d);

	connection_buf tb;
	ldbg_connection(d, where, "instantiated from "PRI_CONNECTION,
			pri_connection(t, &tb));
	return d;
}

struct connection *oppo_responder_instantiate(struct connection *t,
					      const ip_address remote_address,
					      where_t where)
{
	/*
	 * Did find oppo connection do its job?
	 *
	 * On the responder all that is known is the address of the
	 * remote IKE daemon that initiated the exchange.  Hence check
	 * it falls within the selector's range (can't match port as
	 * not yet known).
	 */
	PASSERT(t->logger, t->remote->child.selectors.proposed.len == 1);
	ip_selector remote_template = t->remote->child.selectors.proposed.list[0];
	PASSERT(t->logger, address_in_selector_range(remote_address, remote_template));
	return oppo_instantiate(t, remote_address, __func__, where);
}

struct connection *oppo_initiator_instantiate(struct connection *t,
					      const struct kernel_acquire *b,
					      where_t where)
{
	/*
	 * Did find oppo connection do its job?
	 *
	 * On the initiator the triggering packet provides the exact
	 * endpoint that needs to be negotiated.  Hence this endpoint
	 * must be fully within the template's selector).
	 */
	PASSERT(t->logger, t->remote->child.selectors.proposed.len == 1);
	ip_selector remote_template = t->remote->child.selectors.proposed.list[0];
	ip_endpoint remote_endpoint = packet_dst_endpoint(b->packet);
	PASSERT(t->logger, endpoint_in_selector(remote_endpoint, remote_template));
	ip_address local_address = packet_src_address(b->packet);
	PEXPECT(t->logger, address_eq_address(local_address, t->local->host.addr));
	ip_address remote_address = endpoint_address(remote_endpoint);
	return oppo_instantiate(t, remote_address, __func__, where);
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

			if (c->kind == CK_GROUP) {
				continue;
			}

			if (!routed(c->child.routing)) {
				continue;
			}

			/*
			 * for each sr of c, see if we have a new best
			 *
			 * Paul: while this code can reject unmatched
			 * conns, it does not find the most narrow
			 * match!
			 */
			for (struct spd_route *sr = c->spd; sr != NULL; sr = sr->spd_next) {

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
				if (!selector_in_selector(src, sr->local->client) ||
				    !endpoint_in_selector(dst, sr->remote->client)) {
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
				 *   sr->local->client.maskbits + sr->remote->client.maskbits
				 * but this knows too much about the representation of ip_subnet.
				 * What is the correct semantics?
				 *
				 * XXX: selector_in_selector() is
				 * exclusive - it excludes
				 * selector_eq().
				 */

				if (best_spd_route != NULL &&
				    selector_in_selector(best_spd_route->local->client, sr->local->client)) {
					/*
					 * BEST_SPD_ROUTE is better.
					 *
					 * BEST_SPD_ROUTE's .this is
					 * narrower than .SR's.
					 */
					continue;
				}
				if (best_spd_route != NULL &&
				    selector_eq_selector(best_spd_route->local->client, sr->local->client) &&
				    selector_in_selector(best_spd_route->remote->client, sr->remote->client)) {
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
		return (ca->priority < cb->priority ? -1 :
			ca->priority > cb->priority ? 1 : 0);
	}
}

ip_address spd_end_sourceip(const struct spd_end *spde)
{
	/*
	 * Find a sourceip within the SPD selector.
	 */
	const ip_addresses *sourceip = &spde->child->config->sourceip;
	for (ip_address *s = sourceip->list; s < sourceip->list + sourceip->len; s++) {
		if (address_in_selector(*s, spde->client)) {
			return *s;
		}
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
	connection_db_check_connection(c, c->logger, where);
	for (struct spd_route *sr = c->spd; sr != NULL; sr = sr->spd_next) {
		spd_route_db_check_spd_route(sr, c->logger, where);
	}
}

/* seems to be a good spot for now */
bool dpd_active_locally(const struct connection *c)
{
	return deltasecs(c->config->dpd.delay) != 0;
}

void scribble_end_selector(struct connection *c, enum left_right end,
			   ip_selector selector, where_t where, bool first_time)
{
	struct child_end *child = &c->end[end].child;
	struct logger *logger = c->logger;
	if (first_time) {
		child->selectors.proposed.len = 0;
		child->selectors.proposed.list = child->selectors.assigned;
	}
	unsigned i = child->selectors.proposed.len++;
	if (!PEXPECT_WHERE(logger, where, i < elemsof(child->selectors.assigned))) {
		return;
	}
	child->selectors.assigned[i] = selector;
	selector_buf nb;
	ldbg(c->logger, "%s() %s.child.selector[%d] %s "PRI_WHERE,
	     __func__,
	     c->end[end].config->leftright,
	     i,
	     str_selector(&selector, &nb),
	     pri_where(where));
}

void set_end_selector_where(struct connection *c, enum left_right end,
			    ip_selector new_selector, bool first_time,
			    const char *excuse, where_t where)
{
	struct child_end *child = &c->end[end].child;
	const char *leftright = c->end[end].config->leftright;
	if (first_time) {
		PEXPECT_WHERE(c->logger, where, child->selectors.proposed.len == 0);
		selector_buf nb;
		ldbg(c->logger, "%s() set %s.child.selector %s "PRI_WHERE,
		     __func__, leftright,
		     str_selector(&new_selector, &nb),
		     pri_where(where));
		if (!PEXPECT_WHERE(c->logger, where, c->spd == NULL)) {
			c->spd->end[end].client = new_selector;
		}
	} else {
		PEXPECT_WHERE(c->logger, where, child->selectors.proposed.len == 1);
		ip_selector old_selector = child->selectors.proposed.list[0];
		selector_buf ob, nb;
		ldbg(c->logger, "%s() update %s.child.selector %s -> %s "PRI_WHERE,
		     __func__, leftright,
		     str_selector(&old_selector, &ob),
		     str_selector(&new_selector, &nb),
		     pri_where(where));
		if (c->spd != NULL) {
			PEXPECT_WHERE(c->logger, where, c->spd->spd_next == NULL);
			ip_selector old_client = c->spd->end[end].client;
			if (!selector_eq_selector(old_selector, old_client)) {
				selector_buf sb, cb;
				llog_pexpect(c->logger, where,
					     "%s() %s.child.selector %s does not match %s.spd.client %s",
					     __func__, leftright,
					     str_selector(&old_selector, &sb),
					     c->end[end].config->leftright,
					     str_selector(&old_client, &cb));
			}
			c->spd->end[end].client = new_selector;
		}
	}

	/*
	 * Point the selectors list at and UPDATE the scratch value.
	 *
	 * Is the assumption that this is only applied when there is a
	 * single selector reasonable?  Certainly don't want to
	 * truncate the selector list.
	 */
	child->selectors.assigned[0] = new_selector;
	child->selectors.proposed.list = child->selectors.assigned;
	child->selectors.proposed.len = 1;

	/*
	 * When there's a selectors.list, the child.selector is only
	 * allowed to update to the first selector in that list?
	 *
	 * XXX: the CP payload code violoates this.  It stomps on the
	 * child.selector without even looking at the traffic
	 * selectors.
	 *
	 * XXX: the TS code violates this.  It scribbles the result of
	 * the TS negotiation on the child.selector.
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
			     __func__, leftright,
			     str_selector(&new_selector, &sb),
			     c->end[end].config->leftright,
			     str_selector(&selector, &cb),
			     excuse,
			     pri_where(where));
		} else {
			selector_buf sb, cb;
			llog_pexpect(c->logger, where,
				     "%s() %s.child.selector %s does not match %s.selectors[0] %s",
				     __func__, leftright,
				     str_selector(&new_selector, &sb),
				     c->end[end].config->leftright,
				     str_selector(&selector, &cb));
		}
	}
}

void set_child_kernel_policy_owner_where(struct connection *c, so_serial_t nso, where_t where)
{
	so_serial_t oso = c->child.kernel_policy_owner;
	ldbg(c->logger,
	     "kernel: eroute_owner connection "PRI_SO"->"PRI_SO" "PRI_WHERE,
	     pri_so(oso), pri_so(nso),
	     pri_where(where));
	c->child.kernel_policy_owner = nso;
}

void set_child_routing_where(struct connection *c, enum routing routing, where_t where)
{
	enum_buf ob, nb;
	ldbg(c->logger, "kernel: routing connection %s->%s "PRI_WHERE,
	     str_enum(&routing_story, c->child.routing, &ob),
	     str_enum(&routing_story, routing, &nb),
	     pri_where(where));
	c->child.routing = routing;
}
