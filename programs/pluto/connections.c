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
# include "kernel_xfrm_interface.h"
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

static void discard_connection(struct connection **cp, bool connection_valid, where_t where);

void ldbg_connection(const struct connection *c, where_t where,
		     const char *message, ...)
{
	if (DBGP(DBG_BASE)) {
		LLOG_JAMBUF(DEBUG_STREAM|ADD_PREFIX, c->logger, buf) {
			va_list ap;
			va_start(ap, message);
			jam_va_list(buf, message, ap);
			va_end(ap);
			jam_string(buf, " ");
			jam_where(buf, where);
		}
		LLOG_JAMBUF(DEBUG_STREAM, c->logger, buf) {
			jam_string(buf, "  connection ");
			jam_connection_co(buf, c);
			if (c->clonedfrom != 0) {
				jam_string(buf, " clonedfrom ");
				jam_connection_co(buf, c->clonedfrom);
			}
			jam_string(buf, ": ");
			jam_connection(buf, c);
		}
		LDBG_log(c->logger, "    routing+kind: %s %s",
			 enum_name_short(&routing_names, c->routing.state),
			 enum_name_short(&connection_kind_names, c->local->kind));
		address_buf lb, rb;
		LDBG_log(c->logger, "    host: %s->%s",
			 str_address(&c->local->host.addr, &lb),
			 str_address(&c->remote->host.addr, &rb));
		LLOG_JAMBUF(DEBUG_STREAM, c->logger, buf) {
			jam_string(buf, "    selectors:");
			const char *sep = " ->";
			FOR_EACH_THING(end, &c->local->child, &c->remote->child) {
				FOR_EACH_ITEM(selector, &end->selectors.proposed) {
					jam_string(buf, " ");
					jam_selector(buf, selector);
				}
				jam_string(buf, sep); sep = "";
			}
		}
		LLOG_JAMBUF(DEBUG_STREAM, c->logger, buf) {
			jam_string(buf, "    spds:");
			FOR_EACH_ITEM(spd, &c->child.spds) {
				jam_string(buf, " ");
				jam_selector_pair(buf, &spd->local->client, &spd->remote->client);
			}
		}
		LLOG_JAMBUF(DEBUG_STREAM, c->logger, buf) {
			jam_string(buf, "    policy: ");
			jam_connection_policies(buf, c);
		}
		if (c->config->sec_label.len > 0) {
			LLOG_JAMBUF(DEBUG_STREAM, c->logger, buf) {
				jam_string(buf, "    sec_label: ");
				if (c->child.sec_label.len > 0) {
					jam(buf, PRI_SHUNK, pri_shunk(c->child.sec_label));
					jam_string(buf, " <= ");
				}
				jam(buf, PRI_SHUNK, pri_shunk(c->config->sec_label));
			}
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
	return (is_opportunistic_wm_end(&wm->left) ||
		is_opportunistic_wm_end(&wm->right));
}

static bool is_group_wm_end(const struct whack_end *end)
{
	return (end->host_type == KH_GROUP ||
		end->host_type == KH_OPPOGROUP);
}

static bool is_group_wm(const struct whack_message *wm)
{
	return (is_group_wm_end(&wm->left) ||
		is_group_wm_end(&wm->right));
}

/*
 * Is there an existing connection with NAME?
 */

bool connection_with_name_exists(const char *name)
{
	struct connection_filter cq = {
		.name = name,
		.where = HERE,
	};
	while (next_connection(NEW2OLD, &cq)) {
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
	c->spd = NULL;
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
		.where = HERE,
	};
	while (next_connection(OLD2NEW, &instance)) {
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
		.where = HERE,
	};
	while (next_state(NEW2OLD, &state)) {
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
			free_that_address_lease(c, afi);
			addresspool_delref(&c->pool[afi->ip_index]);
		}
	}

#ifdef USE_XFRM_INTERFACE
	if (c->xfrmi != NULL) {
		unreference_xfrmi(c);
	}
#endif

	/* find and delete c from the host pair list */
	disorient(c);

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
			pfree_list(&end->host.pool_ranges);
			/* child */
			pfreeany(end->child.updown);
			pfree_list(&end->child.selectors);
			pfree_list(&end->child.sourceip);
			virtual_ip_delref(&end->child.virt);
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
	} else if (this->config->iketcp == IKE_TCP_ONLY) {
		/*
		 * RFC 8229: Implementations MUST support TCP
		 * encapsulation on TCP port 4500, which is reserved
		 * for IPsec NAT traversal.
		*/
		port = NAT_IKE_UDP_PORT;
	} else {
		port = IKE_UDP_PORT;
	}
	return ip_hport(port);
}

ip_port local_host_port(const struct connection *c)
{
	return end_host_port(&c->local->host, &c->remote->host);
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
	end->first_addr = host_addr;
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

/* assume 0 is unset */

static unsigned extract_sparse(const char *leftright, const char *name,
			       unsigned value, unsigned unset, unsigned never,
			       const struct sparse_name *names,
			       const struct whack_message *wm,
			       struct logger *logger)
{
	if (never_negotiate_wm(wm)) {
		if (value != 0) {
			sparse_buf sb;
			llog(RC_INFORMATIONAL, logger,
			     "warning: %s%s=%s ignored for never-negotiate connection",
			     leftright, name, str_sparse(names, value, &sb));
		}
		return never;
	} else if (value == 0) {
		return unset;
	} else {
		return value;
	}
}

static bool extract_yn(const char *leftright, const char *name,
		       enum yn_options value, bool unset,
		       const struct whack_message *wm, struct logger *logger)
{
	/* note that 0 gets mapped to YN_UNSET(0) and then UNSET */
	enum yn_options yn = extract_sparse(leftright, name, value, YN_UNSET, YN_NO,
					    yn_option_names,
					    wm, logger);
	switch (yn) {
	case YN_NO: return false;
	case YN_YES: return true;
	case YN_UNSET: return unset;
	}
	bad_sparse(logger, yn_option_names, yn);
}

static enum yna_options extract_yna(const char *leftright, const char *name,
				    enum yna_options yna,
				    enum yna_options unset,
				    enum yna_options never,
				    const struct whack_message *wm,
				    struct logger *logger)
{
	return extract_sparse(leftright, name, yna, unset, never, yna_option_names, wm, logger);
}

static char *extract_str(const char *leftright, const char *name,
			 const char *str,
			 const struct whack_message *wm, struct logger *logger)
{
	if (never_negotiate_wm(wm)) {
		if (str != NULL) {
			llog(RC_LOG, logger,
			     "warning: %s%s=%s ignored for never-negotiate connection",
			     leftright, name, str);
		}
		return NULL;
	}
	return clone_str(str, name);
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
	 * Decode id, if any.
	 *
	 * For %fromcert, the load_end_cert*() call will update it.
	 */
	if (src->id == NULL) {
		/*
		 * The id will be set to the host by
		 * update_hosts_from_end_host_addr() which is after it
		 * has been resolved.
		 */
		host->id.kind = ID_NONE;
	} else {
		/*
		 * Treat any atoid() failure as fatal.  One wart is
		 * something like id=foo.  ttoaddress_dns() fails
		 * when, perhaps, the code should instead return FQDN?
		 *
		 * In 4.x the error was ignored and ID=<HOST_IP> was
		 * used.
		 */
		err_t e = atoid(src->id, &host->id);
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

	if (src->protoport.ipproto == 0 && src->protoport.hport != 0) {
		return diag("%sprotoport cannot specify non-zero port %d for prototcol 0",
			    src->leftright, src->protoport.hport);
	}

	if (src->groundhog != NULL) {
		err_t e = ttobool(src->groundhog, &host_config->groundhog);
		if (e != NULL) {
			return diag("%sgroundhog=%s, %s", leftright, src->groundhog, e);
		}
		if (host_config->groundhog && is_fips_mode()) {
			return diag("%sgroundhog=%s is invalid in FIPS mode",
				    leftright, src->groundhog);
		}
		groundhogday |= host_config->groundhog;
		llog(RC_LOG_SERIOUS, logger,
		     "WARNING: %s is a groundhog", leftright);
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
	 * Set client/server based on modecfg flags.
	 *
	 * And check that modecfg client, server, and CAT are all
	 * consistent.
	 *
	 * The update uses OR so that the truth is blended with the
	 * ADDRESSPOOL code's truth (see further down).
	 *
	 * Danger:
	 *
	 * OE configurations have leftmodecfgclient=yes
	 * leftmodecfgserver=yes which creates a the connection that
	 * is both a client and a server.
	 */

	if (src->modecfg_server && src->modecfg_client) {
		diag_t d = diag("both %smodecfgserver=yes and %smodecfgclient=yes defined",
				leftright, leftright);
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		llog_diag(RC_LOG, logger, &d, "opportunistic: ");
	}

	if (src->modecfg_server && src->cat) {
		diag_t d = diag("both %smodecfgserver=yes and %scat=yes defined",
				leftright, leftright);
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		llog_diag(RC_LOG, logger, &d, "opportunistic: ");
	}

	if (src->modecfg_client && other_src->cat) {
		diag_t d = diag("both %smodecfgclient=yes and %scat=yes defined",
				leftright, other_src->leftright);
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		llog_diag(RC_LOG, logger, &d, "opportunistic: ");
	}

	/* only update, may already be set below */
	host_config->modecfg.server |= src->modecfg_server;
	host_config->modecfg.client |= src->modecfg_client;

	/*
	 * Set client/server based on addresspool
	 *
	 * This end having an addresspool should imply that this host
	 * is the client and the other host is the server.  Right?
	 *
	 * Unfortunately, no!
	 *
	 * OE configurations have leftmodecfgclient=yes
	 * rightaddresspool= which creates a the connection that is
	 * both a client and a server.
	 */

	if (src->addresspool != NULL) {
		if (src->subnets != NULL) {
			return diag("cannot specify both %saddresspool= and %ssubnets=",
				    leftright, leftright);
		}
		if (src->subnet != NULL) {
			return diag("cannot specify both %saddresspool= and %ssubnet=",
				    leftright, leftright);
		}
	}

	if (src->addresspool != NULL) {
		/*
		 */
		other_host_config->modecfg.server = true;
		host_config->modecfg.client = true;
		dbg("forced %s modecfg client=%s %s modecfg server=%s",
		    host_config->leftright, bool_str(host_config->modecfg.client),
		    other_host_config->leftright, bool_str(other_host_config->modecfg.server));
	}

	if (src->modecfg_server && src->addresspool != NULL) {
		diag_t d = diag("%smodecfgserver=yes expects %saddresspool= and not %saddresspool=",
				leftright, other_src->leftright, leftright);
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		llog_diag(RC_LOG, logger, &d, "opportunistic: ");
	}

	if (src->cat && other_src->addresspool != NULL) {
		diag_t d = diag("both %scat=yes and %saddresspool= defined",
				leftright, other_src->leftright);
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		llog_diag(RC_LOG, logger, &d, "opportunistic: ");
	}

	if (src->modecfg_client && other_src->addresspool != NULL) {
		diag_t d = diag("both %smodecfgclient=yes and %saddresspool= defined",
				leftright, other_src->leftright);
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		llog_diag(RC_LOG, logger, &d, "opportunistic: ");
	}

	/*
	 * Note: IKEv1's XAUTH code will replace this address pool
	 * with one based on the auth file.
	 *
	 * Note: The selector code will use the addresspool ranges to
	 * generate the selectors.
	 */

	if (src->addresspool != NULL) {

		/* both ends can't add an address pool */
		passert(c->pool[IPv4_INDEX] == NULL &&
			c->pool[IPv6_INDEX] == NULL);

		diag_t d = ttoranges_num(shunk1(src->addresspool), ", ", NULL,
					 &host_config->pool_ranges);
		if (d != NULL) {
			return diag_diag(&d, "%saddresspool=%s invalid, ", leftright, src->addresspool);
		}

		FOR_EACH_ELEMENT(pool_afi, ip_families) {

			/* allow at most one */
			switch (host_config->pool_ranges.ip[pool_afi->ip_index].len) {
			case 0: continue;
			case 1: break;
			default:
				return diag("%saddresspool=%s invalid, multiple %s ranges",
					    leftright, src->addresspool, pool_afi->ip_name);
			}

			const ip_range *pool_range = host_config->pool_ranges.ip[pool_afi->ip_index].list;
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
#ifdef USE_CAT
		child_config->has_client_address_translation = src->cat;
#endif
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
	 */
	if (never_negotiate_wm(wm)) {
		if (src->updown != NULL) {
			llog(RC_LOG, logger,
			     "warning: %supdown=%s ignored when never negotiate",
			     leftright, src->updown);
		}
	} else {
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
		child_selectors->len = 1;
		child_selectors->list = alloc_things(ip_selector, 1, "subnet-selectors");
		child_selectors->list[0] =
			selector_from_subnet_protoport(subnet, src->protoport);
		const struct ip_info *afi = subnet_info(subnet);
		child_selectors->ip[afi->ip_index].len = 1;
		child_selectors->ip[afi->ip_index].list = child_selectors->list;
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

	if (src->sourceip != NULL) {
		if (src->subnet == NULL) {
			return diag("%ssourceip=%s invalid, requires %ssubnet",
				    leftright, src->sourceip, leftright);
		}
		if (src->ifaceip.is_set) {
			cidr_buf cb;
			return diag("cannot specify %sinterface-ip=%s and %sssourceip=%s",
				    leftright, str_cidr(&src->ifaceip, &cb),
				    leftright, src->sourceip);
		}
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
		FOR_EACH_ITEM(sip, &child_config->sourceip) {
			if (!address_is_specified(*sip)) {
				return diag("%ssourceip=%s invalid, must be a valid address",
					    leftright, src->sourceip);
			}
			/* skip aliases; they hide the selectors list */
			if (wm->connalias != NULL) {
				continue;
			}
			bool within = false;
			FOR_EACH_ITEM(sel, &child_config->selectors) {
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

static void set_connection_selector_proposals(struct connection *c, const struct ip_info *host_afi)
{
	/*
	 * Fill in selectors.
	 */
	FOR_EACH_ELEMENT(end, c->end) {
		const char *leftright = end->config->leftright;
		PASSERT(c->logger, end->child.selectors.proposed.list == NULL);
		PASSERT(c->logger, end->child.selectors.proposed.len == 0);
		if (end->child.config->selectors.len > 0) {
			ldbg(c->logger, "%s() %s selector from %d child.selectors",
			     __func__, leftright, end->child.config->selectors.len);
			end->child.selectors.proposed = end->child.config->selectors;
			/* see also clone_connection */
			set_end_child_has_client(c, end->config->index, true);
		} else if (end->host.config->pool_ranges.len > 0) {
			/*
			 * Make space for the selectors that will be
			 * assigned from the addresspool.
			 */
			ldbg(c->logger, "%s() %s selectors from unset address pool family",
			     __func__, leftright);
			FOR_EACH_ELEMENT(afi, ip_families) {
				if (end->host.config->pool_ranges.ip[afi->ip_index].len > 0) {
					append_end_selector(end, afi, afi->selector.all,
							    c->logger, HERE);
				}
			}
		} else if (address_is_specified(end->host.addr)) {
			/*
			 * Default the end's child selector (client)
			 * to a subnet containing only the end's host
			 * address.
			 *
			 * If the other end has multiple child
			 * selectors then the combination becomes a
			 * list.
			 */
			ldbg(c->logger, "%s() %s selector proposals from host address+protoport",
			     __func__, leftright);
			ip_selector selector =
				selector_from_address_protoport(end->host.addr,
								end->child.config->protoport);
			append_end_selector(end, host_afi, selector,
					    c->logger, HERE);
		} else {
			/*
			 * to-be-determined from the host or the
			 * opportunistic group but make space
			 * regardless.
			 */
			ldbg(c->logger, "%s() %s selector proposals from unset host family",
			     __func__, leftright);
			append_end_selector(end, host_afi, unset_selector,
					    c->logger, HERE);
		}
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
	c->spd = c->child.spds.list;
	FOR_EACH_ITEM(spd, &c->child.spds) {
		init_connection_spd(c, spd);
	}
}

void add_connection_spds(struct connection *c,
			 const struct ip_info *host_afi UNUSED /*XXX: suspect need to fudge up IPv[46] entry to match no-op selector entry, see above and unset_selector */)
{
	unsigned indent = 0;
	ldbg(c->logger, "%*sadding connection spds using proposed", indent, "");

	indent = 1;
	const ip_selectors *left = &c->end[LEFT_END].child.selectors.proposed;
	const ip_selectors *right = &c->end[RIGHT_END].child.selectors.proposed;
	ldbg(c->logger, "%*sleft=%u right=%u",
	     indent, "", left->len, right->len);

	/* Calculate the total number of SPDs. */
	unsigned nr_spds = 0;
	FOR_EACH_ELEMENT(afi, ip_families) {
		const ip_selectors *left = &c->end[LEFT_END].child.selectors.proposed;
		const ip_selectors *right = &c->end[RIGHT_END].child.selectors.proposed;
		ldbg(c->logger, "%*sleft[%s]=%u right[%s]=%u",
		     indent+1, "",
		     afi->ip_name, left->ip[afi->ip_index].len,
		     afi->ip_name, right->ip[afi->ip_index].len);
		nr_spds += (left->ip[afi->ip_index].len * right->ip[afi->ip_index].len);
	}

	/* Allocate the SPDs. */
	alloc_connection_spds(c, nr_spds);

	/* Now fill them in. */
	unsigned spds = 0;
	FOR_EACH_ELEMENT(afi, ip_families) {
		enum ip_index ip = afi->ip_index;
		const ip_selectors *left_selectors = &c->end[LEFT_END].child.selectors.proposed;
		FOR_EACH_ITEM(left_selector, &left_selectors->ip[ip]) {
			const ip_selectors *right_selectors = &c->end[RIGHT_END].child.selectors.proposed;
			FOR_EACH_ITEM(right_selector, &right_selectors->ip[ip]) {
				indent = 2;
				selector_pair_buf spb;
				ldbg(c->logger, "%*s%s", indent, "",
				     str_selector_pair(left_selector, right_selector, &spb));
				indent = 3;
				struct spd *spd = &c->child.spds.list[spds++];
				PASSERT(c->logger, spd < c->child.spds.list + c->child.spds.len);
				ip_selector *selectors[] = {
					[LEFT_END] = left_selector,
					[RIGHT_END] = right_selector,
				};
				FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
					const ip_selector *selector = selectors[end];
					const struct child_end_config *child_end = &c->end[end].config->child;
					struct spd_end *spd_end = &spd->end[end];
					const char *leftright = child_end->leftright;
					/* NOT set_end_selector() */
					spd_end->client = *selector;
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
	if (wm->sa_rekeyfuzz_percent > INT_MAX - 100) {
		return diag("rekeyfuzz=%jd%% is so large it causes overflow",
			    wm->sa_rekeyfuzz_percent);
	}
	if (deltasecs(wm->sa_rekey_margin) > (INT_MAX / (100 + (intmax_t)wm->sa_rekeyfuzz_percent))) {
		return diag("rekeymargin=%jd is so large it causes overflow",
			    deltasecs(wm->sa_rekey_margin));
	}
	deltatime_t min_lifetime = deltatime_scale(wm->sa_rekey_margin,
						   100 + wm->sa_rekeyfuzz_percent,
						   100);

	if (deltatime_cmp(max_lifetime, <, min_lifetime)) {
		return diag("%s%s=%jd must be greater than rekeymargin=%jus + rekeyfuzz=%jd%% yet less than the maximum allowed %ju",
			    fips, 
			    lifetime_name, deltasecs(*lifetime),
			    deltasecs(wm->sa_rekey_margin), wm->sa_rekeyfuzz_percent,
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
		     deltasecs(wm->sa_rekey_margin),
		     wm->sa_rekeyfuzz_percent,
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
	if(wm->ikev2_allow_narrowing == YN_YES) {
		ldbg(logger, "%s connection is CK_TEMPLATE: POLICY_IKEV2_ALLOW_NARROWING",
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
	FOR_EACH_THING(we, this, that) {
		if (we->protoport.has_port_wildcard) {
			ldbg(logger, "%s connection is CK_TEMPLATE: %s child has wildcard protoport",
			     this->leftright, we->leftright);
			return CK_TEMPLATE;
		}
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
			[SHUNT_NONE] = false, [SHUNT_HOLD] = false, [SHUNT_TRAP] = false, [SHUNT_PASS] = true,  [SHUNT_DROP] = true,  [SHUNT_REJECT] = true,
		},
		[SHUNT_KIND_NEGOTIATION] = {
			[SHUNT_NONE] = false, [SHUNT_HOLD] = true,  [SHUNT_TRAP] = false, [SHUNT_PASS] = true,  [SHUNT_DROP] = false, [SHUNT_REJECT] = false,
		},
		[SHUNT_KIND_FAILURE] = {
			[SHUNT_NONE] = true,  [SHUNT_HOLD] = false, [SHUNT_TRAP] = false, [SHUNT_PASS] = true,  [SHUNT_DROP] = true,  [SHUNT_REJECT] = true,
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
			jam_enum_human(buf, &shunt_policy_names, shunt_policy);
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

static struct config *alloc_config(void)
{
	struct config *config = alloc_thing(struct config, "root config");
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

	enum left_right local = (t == NULL ? LEFT_END : t->local->config->index);
	enum left_right remote = (t == NULL ? RIGHT_END : t->remote->config->index);

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

static diag_t extract_connection(const struct whack_message *wm,
				 struct connection *c,
				 struct config *config)
{
	const struct whack_end *whack_ends[] = {
		[LEFT_END] = &wm->left,
		[RIGHT_END] = &wm->right,
	};

	/*
	 * Determine the connection KIND from the wm.
	 *
	 * Save it in a local variable so code can use that (and be
	 * forced to only use value after it's been determined).  Yea,
	 * hack.
	 */
	FOR_EACH_THING(this, LEFT_END, RIGHT_END) {
		enum left_right that = (this + 1) % END_ROOF;
		c->end[this].kind =
			extract_connection_end_kind(wm,
						    whack_ends[this],
						    whack_ends[that],
						    c->logger);
	}

	diag_t d;
	passert(c->name != NULL); /* see alloc_connection() */

	/*
	 * Extract policy bits.
	 */

	bool pfs = extract_yn("", "pfs", wm->pfs, true, wm, c->logger);
	config->child_sa.pfs = pfs;

	bool compress = extract_yn("", "compress", wm->compress, false, wm, c->logger);
	config->child_sa.ipcomp = compress;

	/* sanity check?  done below */
	enum encap_proto encap_proto;
	if (never_negotiate_wm(wm)) {
		if (wm->phase2 != ENCAP_PROTO_UNSET) {
			enum_buf sb;
			llog(RC_INFORMATIONAL, c->logger,
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
				     str_sparse(type_option_names, wm->type, &sb));
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
				    str_enum_short(&shunt_policy_names, wm->never_negotiate_shunt, &sb),
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
		llog(RC_INFORMATIONAL, c->logger,
		     "ignoring ikev2=%s which conflicts with keyexchange=%s",
		     (wm->ikev2 == YN_YES ? "yes" :
		      wm->ikev2 == YN_NO ? "no" :
		      "???"),
		     enum_name(&ike_version_names, wm->ike_version));
	} else if (wm->ikev2 != 0) {
		llog(RC_INFORMATIONAL, c->logger,
		     "ikev2=%s has been replaced by keyexchange=%s",
		     (wm->ikev2 == YN_YES ? "yes" :
		      wm->ikev2 == YN_NO ? "no" :
		      "???"),
		     (wm->ikev2 == YN_YES ? "ikev2" :
		      wm->ikev2 == YN_NO ? "ikev1" :
		      "???"));
	}

	config->ike_version = wm->ike_version;
	static const struct ike_info ike_info[] = {
		[IKEv1] = {
			.version = IKEv1,
			.version_name = "IKEv1",
			.parent_name = "ISAKMP",
			.child_name = "IPsec",
			.parent_sa_name = "ISAKMP SA",
			.child_sa_name = "IPsec SA",
			.expire_event[SA_HARD_EXPIRED] = EVENT_v1_EXPIRE,
			.expire_event[SA_SOFT_EXPIRED] = EVENT_v1_REPLACE,
			.replace_event = EVENT_v1_REPLACE,
		},
		[IKEv2] = {
			.version = IKEv2,
			.version_name = "IKEv2",
			.parent_name = "IKE",
			.child_name = "Child",
			.parent_sa_name = "IKE SA",
			.child_sa_name = "Child SA",
			.expire_event[SA_HARD_EXPIRED] = EVENT_v2_EXPIRE,
			.expire_event[SA_SOFT_EXPIRED] = EVENT_v2_REKEY,
			.replace_event = EVENT_v2_REPLACE,
		},
	};
	PASSERT(c->logger, wm->ike_version < elemsof(ike_info));
	PASSERT(c->logger, ike_info[wm->ike_version].version > 0);
	config->ike_info = &ike_info[wm->ike_version];

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

	config->intermediate = extract_yn("", "intermediate", wm->intermediate, /*default*/false,wm, c->logger);
	if (config->intermediate) {
		if (wm->ike_version < IKEv2) {
			return diag("intermediate requires IKEv2");
		}
	}

	config->sha2_truncbug = extract_yn("", "sha2-truncbug", wm->sha2_truncbug, /*default*/false,wm, c->logger);
	config->overlapip = extract_yn("", "overlapip", wm->overlapip, /*default*/false,wm, c->logger);

	bool ms_dh_downgrade = extract_yn("", "ms-dh-downgrade", wm->ms_dh_downgrade, /*default*/false,wm, c->logger);
	bool pfs_rekey_workaround = extract_yn("", "pfs-rekey-workaround", wm->pfs_rekey_workaround, /*unset*/false, wm, c->logger);
	if (ms_dh_downgrade && pfs_rekey_workaround) {
		return diag("cannot specify both ms-dh-downgrade=yes and pfs-rekey-workaround=yes");
	}
	config->ms_dh_downgrade = ms_dh_downgrade;
	config->pfs_rekey_workaround = pfs_rekey_workaround;

	config->dns_match_id = extract_yn("", "dns-match-id", wm->dns_match_id, /*default*/false,wm, c->logger);
	config->ikev2_pam_authorize = extract_yn("", "ikev2-pam-authorize", wm->pam_authorize, /*default*/false,wm, c->logger);
	config->ikepad = extract_yn("", "ikepad", wm->ikepad, /*default*/true,wm, c->logger);
	config->require_id_on_certificate = extract_yn("", "require-id-on-certificate", wm->require_id_on_certificate,
						       /*default*/true/*YES-TRUE*/,wm, c->logger);
	config->modecfg.pull = extract_yn("", "modecfg", wm->modecfgpull, /*default*/false,wm, c->logger);

	if (wm->aggressive == YN_YES && wm->ike_version >= IKEv2) {
		return diag("cannot specify aggressive mode with IKEv2");
	}
	if (wm->aggressive == YN_YES && wm->ike == NULL) {
		return diag("cannot specify aggressive mode without ike= to set algorithm");
	}
	config->aggressive = extract_yn("", "aggressive", wm->aggressive, /*default*/false,wm, c->logger);

	config->decap_dscp = extract_yn("", "decap-dscp", wm->decap_dscp, /*default*/false,wm, c->logger);

	config->encap_dscp = extract_yn("", "encap-dscp", wm->encap_dscp, /*default*/true,wm, c->logger);

	config->nopmtudisc = extract_yn("", "nopmtudisc", wm->nopmtudisc, /*default*/false,wm, c->logger);

	bool mobike = extract_yn("", "mobike", wm->mobike, /*default*/false, wm, c->logger);
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

	/*
	 * RFC 5685 - IKEv2 Redirect mechanism.
	 */
	config->redirect.to = clone_str(wm->redirect_to, "connection redirect_to");
	config->redirect.accept_to = clone_str(wm->accept_redirect_to, "connection accept_redirect_to");
	if (wm->ike_version == IKEv1) {
		if (wm->send_redirect != YNA_UNSET) {
			llog(RC_INFORMATIONAL, c->logger,
			     "warning: IKEv1 connection ignores send-redirect=");
		}
	} else {
		switch (wm->send_redirect) {
		case YNA_YES:
			if (wm->redirect_to == NULL) {
				llog(RC_INFORMATIONAL, c->logger,
				     "warning: send-redirect=yes ignored, redirect-to= was not specified");
			}
			/* set it anyway!?!  the code checking it
			 * issues a second warning */
			config->redirect.send_always = true;
			break;

		case YNA_NO:
			if (wm->redirect_to != NULL) {
				llog(RC_INFORMATIONAL, c->logger,
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
			llog(RC_INFORMATIONAL, c->logger,
			     "warning: IKEv1 connection ignores accept-redirect=");
		}
	} else {
		config->redirect.accept = extract_yn("", "acceept-redirect", wm->accept_redirect, /*default*/false, wm, c->logger);
	}

	/* fragmentation */

	/*
	 * some options are set as part of our default, but
	 * some make no sense for shunts, so remove those again
	 */
	if (never_negotiate_wm(wm)) {
		if (wm->fragmentation != YNF_UNSET) {
			llog(RC_INFORMATIONAL, c->logger,
			     "warning: never-negotiate connection ignores fragmentation=%s",
			     sparse_name(ynf_option_names, wm->fragmentation));
		}
	} else if (wm->ike_version >= IKEv2 && wm->fragmentation == YNF_FORCE) {
		llog(RC_INFORMATIONAL, c->logger,
		     "warning: IKEv1 only fragmentation=%s ignored; using fragmentation=yes",
		     sparse_name(ynf_option_names, wm->fragmentation));
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
			llog(RC_INFORMATIONAL, c->logger,
			     "warning: enable-tcp=%s ignored for type=passthrough connection",
			     str_sparse(tcp_option_names, wm->enable_tcp, &eb));
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
			llog(RC_INFORMATIONAL, c->logger,
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
		bad_sparse(c->logger, tcp_option_names, iketcp);
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

	if (wm->right.protoport.has_port_wildcard && wm->left.protoport.has_port_wildcard) {
		return diag("cannot have protoports with wildcard (%%any) ports on both sides");
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
		return d;
	}
	if (host_afi == NULL) {
		return diag("host address family unknown");
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
		return diag("must specify host IP address for our side");
	}

	/* duplicate any alias, adding spaces to the beginning and end */
	config->connalias = clone_str(wm->connalias, "connection alias");

	config->dnshostname = clone_str(wm->dnshostname, "connection dnshostname");

	config->ikev2_allow_narrowing =
		extract_yn("", "ikev2-allow-narrowing", wm->ikev2_allow_narrowing,
			   (wm->ike_version == IKEv2 && (wm->left.addresspool != NULL ||
							 wm->right.addresspool != NULL)),
			   wm, c->logger);
	if (config->ikev2_allow_narrowing &&
	    wm->ike_version < IKEv2) {
		return diag("narrowing=yes requires IKEv2");
	}

	config->rekey = extract_yn("", "rekey", wm->rekey, true, wm, c->logger);
	config->reauth = extract_yn("", "reauth", wm->reauth, false, wm, c->logger);

	config->autostart = wm->autostart;
	switch (wm->autostart) {
	case AUTOSTART_KEEP:
	case AUTOSTART_START:
		ldbg(c->logger, "autostart=%s implies +POLICY_UP",
		     enum_name_short(&autostart_names, wm->autostart));
		add_policy(c, policy.up);
		break;
	case AUTOSTART_IGNORE:
	case AUTOSTART_ADD:
	case AUTOSTART_ONDEMAND:
		break;
	}

	/*
	 * Extract configurable shunts, set hardwired shunts.
	 */

	d = extract_shunt(config, wm, SHUNT_KIND_NEVER_NEGOTIATE,
			  /*unset*/SHUNT_UNSET);
	if (d != NULL) {
		return d;
	}

	d = extract_shunt(config, wm, SHUNT_KIND_NEGOTIATION,
			  /*unset*/SHUNT_HOLD);
	if (d != NULL) {
		return d;
	}

	if (is_fips_mode() && config->negotiation_shunt == SHUNT_PASS) {
		enum_buf sb;
		llog(RC_LOG_SERIOUS, c->logger,
		     "FIPS: ignored negotiationshunt=%s - packets MUST be blocked in FIPS mode",
		     str_enum_short(&shunt_policy_names, config->negotiation_shunt, &sb));
		config->negotiation_shunt = SHUNT_HOLD;
	}

	d = extract_shunt(config, wm, SHUNT_KIND_FAILURE,
			  /*unset*/SHUNT_NONE);
	if (d != NULL) {
		return d;
	}

	/* make kernel code easier */
	config->shunt[SHUNT_KIND_BLOCK] = SHUNT_DROP;
	config->shunt[SHUNT_KIND_ONDEMAND] = SHUNT_TRAP;
	config->shunt[SHUNT_KIND_IPSEC] = SHUNT_IPSEC;

	if (is_fips_mode() && config->failure_shunt != SHUNT_NONE) {
		enum_buf eb;
		llog(RC_LOG_SERIOUS, c->logger,
		     "FIPS: ignored failureshunt=%s - packets MUST be blocked in FIPS mode",
		     str_enum_short(&shunt_policy_names, config->failure_shunt, &eb));
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

	if (wm->replay_window > kernel_ops->max_replay_window) {
		return diag("replay-window=%ju exceeds %s kernel interface limit of %ju",
			    wm->replay_window,
			    kernel_ops->interface_name,
			    kernel_ops->max_replay_window);
	} else if (!never_negotiate_wm(wm)) {
		config->child_sa.replay_window = wm->replay_window;
	}

	if (never_negotiate_wm(wm)) {
		if (wm->esn != YNE_UNSET) {
			llog(RC_INFORMATIONAL, c->logger,
			     "warning: ignoring esn=%s as connection is never-negotiate",
			     sparse_name(yne_option_names, wm->esn));
		}
	} else if (wm->replay_window == 0) {
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
			llog(RC_INFORMATIONAL, c->logger,
			     "warning: forcing esn=no as replay-window=0");
		} else {
			dbg("ESN: disabled as replay-window=0"); /* XXX: log? */
		}
		config->esn.no = true;
	} else if (!kernel_ops->esn_supported) {
		/*
		 * YNE_UNSET default's to YES|NO, hence need to warn
		 * for that ESN was disabled for that and YNE_YES and
		 * YNE_EITHER.
		 */
		if (wm->esn != YNE_NO) {
			llog(RC_LOG, c->logger,
			     "warning: %s kernel interface does not support ESN so disabling",
			     kernel_ops->interface_name);
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
			llog(RC_INFORMATIONAL, c->logger,
			     "warning: ignoring esn=%s as not implemented with IKEv1",
			     sparse_name(yne_option_names, wm->esn));
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
			llog(RC_INFORMATIONAL, c->logger,
			     "warning: ignoring ppk=%s as IKEv1",
			     str_sparse(nppi_option_names, wm->ppk, &sb));
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
			llog(RC_INFORMATIONAL, c->logger,
			     "ignored ike= option for type=passthrough connection");
		}
	} else if (!wm->authby.never && (wm->ike != NULL ||
					 wm->ike_version == IKEv2)) {
		const struct proposal_policy proposal_policy = {
			/* logic needs to match pick_initiator() */
			.version = c->config->ike_version,
			.alg_is_ok = ike_alg_is_ike,
			.pfs = pfs,
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
			llog_v2_proposals(LOG_STREAM/*not-whack*/|RC_LOG, c->logger,
					  config->v2_ike_proposals,
					  "IKE SA proposals (connection add)");
		}
	}

	/* ESP or AH cipher suites (but not both) */

	if (never_negotiate_wm(wm)) {
		if (wm->esp != NULL) {
			llog(RC_INFORMATIONAL, c->logger,
			     "ignored esp= option for type=passthrough connection");
		}
	} else if (wm->esp != NULL ||
		   (c->config->ike_version == IKEv2 && encap_proto != ENCAP_PROTO_UNSET)) {

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
			llog_v2_proposals(LOG_STREAM/*not-whack*/|RC_LOG, c->logger,
					  config->child_sa.v2_ike_auth_proposals,
					  "Child SA proposals (connection add)");
		}
	}

	config->encapsulation = extract_yna("", "encapsulation", wm->encapsulation,
					    YNA_AUTO, YNA_NO, wm, c->logger);

	config->vti.shared = extract_yn("", "vti-shared", wm->vti_shared, false,
					wm, c->logger);
	config->vti.routing = extract_yn("", "vti-routing", wm->vti_routing, false,
					 wm, c->logger);
	if (wm->vti_interface != NULL && strlen(wm->vti_interface) >= IFNAMSIZ) {
		llog(RC_INFORMATIONAL, c->logger,
		     "warning: length of vti-interface '%s' exceeds IFNAMSIZ (%u)",
		     wm->vti_interface, (unsigned) IFNAMSIZ);
	}
	config->vti.interface = extract_str("",  "vti-interface", wm->vti_interface,
					    wm, c->logger);

	if (never_negotiate_wm(wm)) {
		if (wm->nic_offload != NIC_OFFLOAD_UNSET) {
			llog(RC_LOG, c->logger, "nic-offload=%s ignored for never-negotiate connection",
			     sparse_name(nic_offload_option_names, wm->nic_offload));
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
			if (kernel_ops->nic_detect_offload == NULL) {
				return diag("no kernel support for nic-offload[=%s]",
					    sparse_name(nic_offload_option_names, wm->nic_offload));
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

			switch (wm->replay_window) {
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

	if (never_negotiate_wm(wm)) {
		dbg("skipping over misc settings as NEVER_NEGOTIATE");
	} else {

		d = extract_lifetime(&config->sa_ike_max_lifetime,
				     "ikelifetime", wm->ikelifetime,
				     IKE_SA_LIFETIME_DEFAULT,
				     IKE_SA_LIFETIME_MAXIMUM,
				     FIPS_IKE_SA_LIFETIME_MAXIMUM,
				     c->logger, wm);
		if (d != NULL) {
			return d;
		}
		d = extract_lifetime(&config->sa_ipsec_max_lifetime,
				     "ipsec-lifetime", wm->ipsec_lifetime,
				     IPSEC_SA_LIFETIME_DEFAULT,
				     IPSEC_SA_LIFETIME_MAXIMUM,
				     FIPS_IPSEC_SA_LIFETIME_MAXIMUM,
				     c->logger, wm);
		if (d != NULL) {
			return d;
		}

		config->sa_rekey_margin = wm->sa_rekey_margin;
		config->sa_rekey_fuzz = wm->sa_rekeyfuzz_percent;

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

		const struct timescale *const dpd_timescale = &timescale_seconds;
		switch (wm->ike_version) {
		case IKEv1:
			/* IKEv1's RFC 3706 DPD */
			if (wm->dpddelay != NULL &&
			    wm->dpdtimeout != NULL) {
				diag_t d;
				d = ttodeltatime(wm->dpddelay,
						 &config->dpd.delay,
						 dpd_timescale);
				if (d != NULL) {
					return diag_diag(&d, "dpddelay=%s invalid, ",
							 wm->dpddelay);
				}
				d = ttodeltatime(wm->dpdtimeout,
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
				d = ttodeltatime(wm->dpddelay,
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
		config->remote_peer_cisco = wm->remote_peer_type == REMOTE_PEER_CISCO;

		config->child_sa.metric = wm->metric;
		config->child_sa.mtu = wm->mtu;
		config->nat_keepalive = wm->nat_keepalive;
		if (wm->nat_ikev1_method == 0) {
			config->ikev1_natt = NATT_BOTH;
		} else {
			config->ikev1_natt = wm->nat_ikev1_method;
		}
		config->send_initial_contact = wm->initial_contact;
		config->send_vid_cisco_unity = wm->cisco_unity;
		config->send_vid_fake_strongswan = wm->fake_strongswan;
		config->send_vendorid = wm->send_vendorid;
		config->send_ca = wm->send_ca;
		config->xauthby = wm->xauthby;
		config->xauthfail = wm->xauthfail;

		diag_t d = ttoaddresses_num(shunk1(wm->modecfgdns), ", ",
					    /* IKEv1 doesn't do IPv6 */
					    (wm->ike_version == IKEv1 ? &ipv4_info : NULL),
					    &config->modecfg.dns);
		if (d != NULL) {
			return diag_diag(&d, "modecfgdns=%s invalid: ", wm->modecfgdns);
		}

		config->modecfg.domains = clone_shunk_tokens(shunk1(wm->modecfgdomains),
							     ", ", HERE);
		if (wm->ike_version == IKEv1 &&
		    config->modecfg.domains != NULL &&
		    config->modecfg.domains[1].ptr != NULL) {
			llog(RC_LOG_SERIOUS, c->logger,
			     "IKEv1 only uses the first domain in modecfgdomain=%s",
			     wm->modecfgdomains);
			config->modecfg.domains[1] = null_shunk;
		}

		config->modecfg.banner = clone_str(wm->modecfgbanner, "connection modecfg_banner");

		/* RFC 8784 and draft-smyslov-ipsecme-ikev2-qr-alt-07 */
		config->ppk_ids = clone_str(wm->ppk_ids, "connection ppk_ids");
		if (config->ppk_ids != NULL) {
			config->ppk_ids_shunks = shunks(shunk1(config->ppk_ids),
							", ",
							EAT_EMPTY_SHUNKS,
							HERE); /* process into shunks once */
		}

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
		if (wm->mark != NULL) {
			mark_parse(wm->mark, &c->sa_marks.in, c->logger);
			mark_parse(wm->mark, &c->sa_marks.out, c->logger);
			if (wm->mark_in != NULL || wm->mark_out != NULL) {
				llog(RC_LOG_SERIOUS, c->logger,
				     "conflicting mark specifications");
			}
		}
		if (wm->mark_in != NULL)
			mark_parse(wm->mark_in, &c->sa_marks.in, c->logger);
		if (wm->mark_out != NULL)
			mark_parse(wm->mark_out, &c->sa_marks.out, c->logger);
	}

	/* ipsec-interface */

	if (never_negotiate_wm(wm)) {
		if (wm->ipsec_interface != NULL) {
			llog(RC_INFORMATIONAL, c->logger,
			     "warning: ipsec-interface=%s ignored for never-negotiate connection",
			     wm->ipsec_interface);
		}
	} else if (wm->ipsec_interface != NULL) {
#ifdef USE_XFRM_INTERFACE
		diag_t d = setup_xfrm_interface(c, wm->ipsec_interface);
		if (d != NULL) {
			return d;
		}
#else
		return diag("ipsec-interface= is not supported");
#endif
	}

#ifdef HAVE_NM
	config->nm_configured = extract_yn("", "nm-configured", wm->nm_configured, false, wm, c->logger);
#endif

#ifdef USE_NFLOG
	c->nflog_group = wm->nflog_group;
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

	config->send_no_esp_tfc = wm->send_no_esp_tfc;

	/*
	 * Since security labels use the same REQID for everything,
	 * pre-assign it.
	 */
	config->sa_reqid = (wm->sa_reqid != 0 ? wm->sa_reqid :
			    wm->ike_version != IKEv2 ? /*generated later*/0 :
			    wm->sec_label != NULL ? gen_reqid() :
			    /*generated later*/0);
	ldbg(c->logger,
	     "c->sa_reqid="PRI_REQID" because wm->sa_reqid="PRI_REQID" and sec-label=%s",
	     pri_reqid(config->sa_reqid),
	     pri_reqid(wm->sa_reqid),
	     (wm->ike_version != IKEv2 ? "not-IKEv2" :
	      wm->sec_label != NULL ? wm->sec_label :
	      "n/a"));

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

	if (wm->left.addresspool != NULL && wm->right.addresspool != NULL) {
		return diag("both left and right define addresspool=");
	}

	if (wm->left.modecfg_server && wm->right.modecfg_server) {
		diag_t d = diag("both left and right define modecfgserver=yes");
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		llog_diag(RC_LOG, c->logger, &d, "opportunistic: ");
	}

	if (wm->left.modecfg_client && wm->right.modecfg_client) {
		diag_t d = diag("both left and right define modecfgclient=yes");
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		llog_diag(RC_LOG, c->logger, &d, "opportunistic: ");
	}

	if (wm->left.cat && wm->right.cat) {
		diag_t d = diag("both left and right define cat=yes");
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		llog_diag(RC_LOG, c->logger, &d, "opportunistic: ");
	}

	if (wm->left.virt != NULL && wm->right.virt != NULL) {
		return diag("both left and right define virtual subnets");
	}

	if ((c->end[LEFT_END].kind == CK_GROUP || c->end[RIGHT_END].kind == CK_GROUP) &&
	    (wm->left.virt != NULL || wm->right.virt != NULL)) {
		return diag("connection groups do not support virtual subnets");
	}

	/*
	 * Unpack and verify the ends.
	 */

	bool same_ca[END_ROOF] = { false, };

	FOR_EACH_THING(this, LEFT_END, RIGHT_END) {
		diag_t d;
		int that = (this + 1) % END_ROOF;
		d = extract_host_end(c, &c->end[this].host,
				     &config->end[this].host, &config->end[that].host,
				     wm, whack_ends[this], whack_ends[that],
				     &same_ca[this], c->logger);
		if (d != NULL) {
			return d;
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
		llog_diag(RC_LOG, c->logger, &d, "opportunistic: ");
	}

	if (config->end[LEFT_END].host.modecfg.client &&
	    config->end[RIGHT_END].host.modecfg.client) {
		diag_t d = diag("both left and right are configured as a client");
		if (!is_opportunistic_wm(wm)) {
			return d;
		}
		llog_diag(RC_LOG, c->logger, &d, "opportunistic: ");
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
			return diag("cannot mix PSK and NULL authentication (%sauth=%s and %sauth=%s)",
				    c->local->config->leftright,
				    enum_name(&keyword_auth_names, c->local->host.config->auth),
				    c->remote->config->leftright,
				    enum_name(&keyword_auth_names, c->remote->host.config->auth));
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
					     &config->end[end].child,
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

	struct {
		bool used;
		const char *field;
		char *value;
	} end_family[END_ROOF][IP_INDEX_ROOF] = {0};
	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		const ip_selectors *const selectors = &c->end[end].config->child.selectors;
		const ip_ranges *const pools = &c->end[end].config->host.pool_ranges;
		if (selectors->len > 0) {
			FOR_EACH_ELEMENT(afi, ip_families) {
				if (selectors->ip[afi->ip_index].len > 0) {
					end_family[end][afi->ip_index].used = true;
					end_family[end][afi->ip_index].field = "subnet";
					end_family[end][afi->ip_index].value = whack_ends[end]->subnet;
				}
			}
		} else if (pools->len > 0) {
			FOR_EACH_ELEMENT(afi, ip_families) {
				if (pools->ip[afi->ip_index].len > 0) {
					end_family[end][afi->ip_index].used = true;
					end_family[end][afi->ip_index].field = "addresspool";
					end_family[end][afi->ip_index].value = whack_ends[end]->addresspool;
				}
			}
		} else {
			end_family[end][host_afi->ip_index].used = true;
			end_family[end][host_afi->ip_index].field = "";
			end_family[end][host_afi->ip_index].value = whack_ends[end]->host_addr_name;
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
	c->child.reqid = (c->config->sa_reqid == 0 ? gen_reqid() : c->config->sa_reqid);
	ldbg(c->logger, "child.reqid="PRI_REQID" because c->sa_reqid="PRI_REQID" (%s)",
	     pri_reqid(c->child.reqid),
	     pri_reqid(c->config->sa_reqid),
	     (c->config->sa_reqid == 0 ? "generate" : "use"));

	/*
	 * Fill in the child's selector proposals from the config.  It
	 * might use subnet or host or addresspool.
	 */

	set_connection_selector_proposals(c, host_afi);

	/*
	 * Generate the SPDs from the populated selectors.  Is this
	 * needed now?
	 */
	add_connection_spds(c, host_afi);
	if (!pexpect(c->spd != NULL)) {
		return diag("internal error");
	}

	/*
	 * All done, enter it into the databases.  Since orient() may
	 * switch ends, triggering an spd rehash, insert things into
	 * the database first.
	 */
	connection_db_add(c);

	/*
	 * Force orientation (currently kind of unoriented?).  If the
	 * connection orients,the SPDs and host-pair hash tables are
	 * updated.
	 *
	 * This function holds the just allocated reference.
	 */
	orient(c, c->logger);

	return NULL;
}

bool add_connection(const struct whack_message *wm, struct logger *logger)
{
	/* will inherit defaults */
	lset_t debugging = lmod(LEMPTY, wm->debugging);

	/*
	 * Allocate the configuration - only allocated on root
	 * connection; connection instances (clones) inherit these
	 * pointers.
	 */
	struct config *root_config = alloc_config();
	struct connection *c = alloc_connection(wm->name, NULL, root_config,
						debugging | wm->conn_debug,
						logger, HERE);
	c->root_config = root_config;

	diag_t d = extract_connection(wm, c, root_config);
	if (d != NULL) {
		llog_diag(RC_FATAL, c->logger, &d, ADD_FAILED_PREFIX);
		struct connection *cp = c;
		PASSERT(c->logger, delref_where(&cp, c->logger, HERE) == c);
		discard_connection(&c, false/*not-valid*/, HERE);
		return false;
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
	return true;
}

/* priority formatting */
size_t jam_connection_priority(struct jambuf *buf, const struct connection *c)
{
	connection_priority_t pp = connection_priority(c);
	if (pp == BOTTOM_PRIORITY) {
		return jam_string(buf, "0");
	}

	return jam(buf, "%" PRIu32 ",%" PRIu32,
		   pp >> 17, (pp & ~(~(connection_priority_t)0 << 17)) >> 8);
}

const char *str_connection_priority(const struct connection *c, connection_priority_buf *buf)
{
	struct jambuf jb = ARRAY_AS_JAMBUF(buf->buf);
	jam_connection_priority(&jb, c);
	return buf->buf;
}

static connection_priority_t end_maskbits(const struct connection *c,
					  struct connection_end *end)
{
	if (c->spd != NULL) {
		return c->spd->end[end->config->index].client.maskbits;
	}
	if (end->child.selectors.proposed.len > 0) {
		return end->child.selectors.proposed.list[0].maskbits;
	}
	return 0;
}

connection_priority_t connection_priority(const struct connection *c)
{
	connection_priority_t pp = 0;
	pp |= end_maskbits(c, c->local) << 17;
	pp |= end_maskbits(c, c->remote) << 8;
	pp |= 1;
	return pp;
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
		FOR_EACH_ITEM(selector, selectors) {
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

#define CS(S)					\
	{					\
		s += jam_string(buf, sep);	\
		s += jam_string(buf, S);	\
		sep = "+";			\
	}
#define CT(C, N)				\
	if (!never_negotiate(c) &&		\
	    c->config->C) {			\
		/* show when true */		\
		CS(#N);				\
	}
#define CF(C, N)				\
	if (!never_negotiate(c) &&		\
	    !c->config->C) {			\
		/* show when false */		\
		CS(#N);				\
	}
#define CP(P, N)				\
	if (!never_negotiate(c) &&		\
	    P) {				\
		/* show when false */		\
		CS(#N);				\
	}
#define CNN(C,N)				\
	if (C) {				\
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
		CS(enum_name_short(&encap_mode_names, c->config->child_sa.encap_mode));
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

	CP(is_xauth(c), XAUTH);
	CT(modecfg.pull, MODECFG_PULL);

	CT(aggressive, AGGRESSIVE);
	CT(overlapip, OVERLAPIP);

	CT(ikev2_allow_narrowing, IKEV2_ALLOW_NARROWING);

	CT(ikev2_pam_authorize, IKEV2_PAM_AUTHORIZE);

	CT(redirect.send_always, SEND_REDIRECT_ALWAYS);
	CT(redirect.send_never, SEND_REDIRECT_NEVER);
	CT(redirect.accept, ACCEPT_REDIRECT_YES);

	CT(ike_frag.allow, IKE_FRAG_ALLOW);
	CT(ike_frag.v1_force, IKE_FRAG_FORCE);

	/* need to flip parity */
	CF(ikepad, NO_IKEPAD);

	CT(mobike, MOBIKE);
	CT(ppk.allow, PPK_ALLOW);
	CT(ppk.insist, PPK_INSIST);
	CT(esn.no, ESN_NO);
	CT(esn.yes, ESN_YES);
	CT(intermediate, INTERMEDIATE);
	CT(ignore_peer_dns, IGNORE_PEER_DNS);

	CNN(is_group(c), GROUP);

	shunt = c->config->never_negotiate_shunt;
	if (shunt != SHUNT_UNSET) {
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
					      struct logger *logger)
{
	packet_buf pb;
	ldbg(logger, "%s() looking for an out-going connection that matches packet %s sec_label="PRI_SHUNK,
	     __func__, str_packet(&packet, &pb), pri_shunk(sec_label));

	const ip_selector packet_src = packet_src_selector(packet);
	const ip_endpoint packet_dst = packet_dst_endpoint(packet);

	struct connection *best_connection = NULL;
	connection_priority_t best_priority = BOTTOM_PRIORITY;

	struct connection_filter cq = { .where = HERE, };
	while (next_connection(NEW2OLD, &cq)) {
		struct connection *c = cq.c;

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
		if (!kernel_route_installed(c) && !instance_initiation_ok &&
		    c->config->sec_label.len == 0) {
			connection_buf cb;
			selector_pair_buf sb;
			ldbg(logger, "    skipping "PRI_CONNECTION" %s; !routed,!instance_initiation_ok,!sec_label",
			     pri_connection(c, &cb),
			     str_selector_pair(&c->spd->local->client, &c->spd->remote->client, &sb));
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
			(8 * (connection_priority(c) + is_instance(c)) +
			 (src - 1/*strip 1 added above*/) +
			 (dst - 1/*strip 1 added above*/));

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
struct connection **sort_connections(void)
{
	/* count up the connections */
	unsigned nr_connections = 0;
	{
		struct connection_filter cq = { .where = HERE, };
		while (next_connection(NEW2OLD, &cq)) {
			nr_connections++;
		}
	}

	if (nr_connections == 0) {
		return NULL;
	}

	/* make a NULL terminated array of connections */
	struct connection **connections = alloc_things(struct connection *,
						       nr_connections + 1,
						       "connection array");
	{
		unsigned i = 0;
		struct connection_filter cq = { .where = HERE, };
		while (next_connection(NEW2OLD, &cq)) {
			connections[i++] = cq.c;
		}
		passert(i == nr_connections);
	}

	/* sort it! */
	qsort(connections, nr_connections, sizeof(struct connection *),
	      connection_compare_qsort);

	return connections;
}

ip_address spd_end_sourceip(const struct spd_end *spde)
{
	/*
	 * Find a sourceip within the SPD selector.
	 */
	const ip_addresses *sourceip = &spde->child->config->sourceip;
	FOR_EACH_ITEM(s, sourceip) {
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
			 const struct ip_info *afi, ip_selector selector/*could be unset*/,
			 struct logger *logger, where_t where)
{
	PASSERT_WHERE(logger, where, (selector_is_unset(&selector) ||
				      selector_info(selector) == afi));
	/*
	 * Either uninitialized, or using the (first) scratch entry
	 */
	if (end->child.selectors.proposed.list == NULL) {
		PASSERT_WHERE(logger, where, end->child.selectors.proposed.len == 0);
		end->child.selectors.proposed.list = end->child.selectors.assigned;
	} else {
		PASSERT_WHERE(logger, where, end->child.selectors.proposed.len > 0);
		PASSERT_WHERE(logger, where, end->child.selectors.proposed.list == end->child.selectors.assigned);
	}
	/* space? */
	PASSERT_WHERE(logger, where, end->child.selectors.proposed.len < elemsof(end->child.selectors.assigned));
	PASSERT_WHERE(logger, where, end->child.selectors.proposed.ip[afi->ip_index].len == 0);

	/* append the selector to assigned; always initlaize .list */
	unsigned i = end->child.selectors.proposed.len++;
	end->child.selectors.assigned[i] = selector;
	/* keep IPv[46] table in sync */
	end->child.selectors.proposed.ip[afi->ip_index].len = 1;
	end->child.selectors.proposed.ip[afi->ip_index].list = &end->child.selectors.assigned[i];

	selector_buf nb;
	ldbg(logger, "%s() %s.child.selectors.proposed[%d] %s "PRI_WHERE,
	     __func__,
	     end->config->leftright,
	     i, str_selector(&selector, &nb),
	     pri_where(where));
}

void scribble_end_selector(struct connection *c, enum left_right end,
			   ip_selector selector, where_t where, unsigned nr)
{
	struct child_end_selectors *end_selectors = &c->end[end].child.selectors;
	struct logger *logger = c->logger;
	if (!PEXPECT_WHERE(logger, where, nr < elemsof(end_selectors->assigned))) {
		return;
	}
	const struct ip_info *afi = selector_info(selector);
	end_selectors->assigned[nr] = selector;
	/* keep IPv[46] table in sync */
	end_selectors->proposed.ip[afi->ip_index].len = 1;
	end_selectors->proposed.ip[afi->ip_index].list = &end_selectors->assigned[nr];

	selector_buf nb;
	ldbg(c->logger, "%s() %s.child.selector[%d] %s "PRI_WHERE,
	     __func__,
	     c->end[end].config->leftright,
	     nr,
	     str_selector(&selector, &nb),
	     pri_where(where));
}

void update_end_selector_where(struct connection *c, enum left_right lr,
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
	const struct ip_info *afi = selector_info(new_selector);
	append_end_selector(end, afi, new_selector, c->logger, where);

	/*
	 * If needed, also update the SPD.  It's assumed for this code
	 * path there is only one (just like there is only one
	 * selector).
	 */
	if (c->spd != NULL) {
		PEXPECT_WHERE(c->logger, where, c->child.spds.len == 1);
		ip_selector old_client = c->spd->end[lr].client;
		if (!selector_eq_selector(old_selector, old_client)) {
			selector_buf sb, cb;
			llog_pexpect(c->logger, where,
				     "%s() %s.child.selector %s does not match %s.spd.client %s",
				     __func__, leftright,
				     str_selector(&old_selector, &sb),
				     end->config->leftright,
				     str_selector(&old_client, &cb));
		}
		c->spd->end[lr].client = new_selector;
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
		if (end->config->host.pool_ranges.len > 1) {
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
		 enum sa_type sa_type)
{
	if (c == NULL) {
		return false;
	}
	switch (sa_type) {
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
	bad_case(sa_type);
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

bool is_v1_cisco_split(const struct spd *spd UNUSED, where_t where UNUSED)
{
#ifdef USE_CISCO_SPLIT
	if (spd->connection->remotepeertype == CISCO &&
	    spd->connection->child.spds.list == spd &&
	    spd->connection->child.spds.len > 1) {
		ldbg(spd->connection->logger,
		     "kernel: skipping first SPD, remotepeertype is CISCO, damage done "PRI_WHERE,
		     pri_where(were));
		return true;
	}
#endif
	return false;
}


/* IKE SA | ISAKMP SA || Child SA | IPsec SA */
const char *connection_sa_name(const struct connection *c, enum sa_type sa_type)
{
	switch (sa_type) {
	case IKE_SA:
		return c->config->ike_info->parent_sa_name;
	case CHILD_SA:
		return c->config->ike_info->child_sa_name;
	}
	bad_case(sa_type);
}

/* IKE | ISAKMP || Child | IPsec */
const char *connection_sa_short_name(const struct connection *c, enum sa_type sa_type)
{
	switch (sa_type) {
	case IKE_SA:
		return c->config->ike_info->parent_name;
	case CHILD_SA:
		return c->config->ike_info->child_name;
	}
	bad_case(sa_type);
}

lset_t child_sa_policy(const struct connection *c)
{
	lset_t policy = LEMPTY;
	policy |= (c->config->child_sa.ipcomp ? POLICY_COMPRESS : LEMPTY);
	policy |= (c->config->child_sa.pfs ? POLICY_PFS : LEMPTY);
	policy |= (c->config->child_sa.encap_proto == ENCAP_PROTO_ESP ? POLICY_ENCRYPT :
		   c->config->child_sa.encap_proto == ENCAP_PROTO_AH ? POLICY_AUTHENTICATE :
		   LEMPTY);
	policy |= (c->config->child_sa.encap_mode == ENCAP_MODE_TUNNEL ? POLICY_TUNNEL :
		   LEMPTY);
	return policy;
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
