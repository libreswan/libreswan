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

#include "defs.h"
#include "connections.h" /* needs id.h */
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
#include "pluto_crypt.h"  /* for pluto_crypto_req & pluto_crypto_req_cont */
#include "ikev2.h"
#include "virtual_ip.h"	/* needs connections.h */
#include "hostpair.h"
#include "lswfips.h"
#include "crypto.h"
#include "kernel_xfrm.h"
#include "ip_address.h"
#include "ip_info.h"
#include "keyhi.h" /* for SECKEY_DestroyPublicKey */
#include "state_db.h"
# include "kernel_xfrm_interface.h"
#include "iface.h"
#include "ip_selector.h"
#include "nss_cert_reread.h"

struct connection *connections = NULL;

#define MINIMUM_IPSEC_SA_RANDOM_MARK 65536
static uint32_t global_marks = MINIMUM_IPSEC_SA_RANDOM_MARK;

static bool idr_wildmatch(const struct end *this, const struct id *b, struct logger *logger);

/*
 * Find a connection by name.
 *
 * strict: don't accept a CK_INSTANCE.
 *
 * If none is found, and strict&&!queit, a diagnostic is logged to
 * whack.
 *
 * XXX: Fun fact: this function re-orders the list, moving the entry
 * to the front as a side effect (ulgh)!.
 */
struct connection *conn_by_name(const char *nm, bool strict)
{
	struct connection *p, *prev;

	dbg("FOR_EACH_CONNECTION_... in %s", __func__);
	for (prev = NULL, p = connections; ; prev = p, p = p->ac_next) {
		if (p == NULL) {
			break;
		}
		if (streq(p->name, nm) &&
		    (!strict || p->kind != CK_INSTANCE)) {
			if (prev != NULL) {
				/* remove p from list */
				prev->ac_next = p->ac_next;
				/* and stick it on front */
				p->ac_next = connections;
				connections = p;
			}
			break;
		}
	}
	return p;
}

void release_connection(struct connection *c, bool relations, struct fd *whackfd)
{
	if (c->kind == CK_INSTANCE) {
		/*
		 * This does everything we need.
		 * Note that we will be called recursively by delete_connection,
		 * but kind will be CK_GOING_AWAY.
		 */
		delete_connection(c, relations);
	} else {
		flush_pending_by_connection(c);
		delete_states_by_connection(c, relations, whackfd);
		unroute_connection(c);
	}
}

/* Delete a connection */
static void delete_end(struct end *e)
{
	free_id_content(&e->id);

	if (e->cert.u.nss_cert != NULL)
		CERT_DestroyCertificate(e->cert.u.nss_cert);

	free_chunk_content(&e->ca);
	pfreeany(e->updown);
	pfreeany(e->host_addr_name);
	pfreeany(e->xauth_password);
	pfreeany(e->xauth_username);
	pfreeany(e->ckaid);
}

static void delete_sr(struct spd_route *sr)
{
	delete_end(&sr->this);
	delete_end(&sr->that);
}

/*
 * delete_connection -- removes a connection by pointer
 *
 * @c - the connection pointer
 * @relations - whether to delete any instances as well.
 * @connection_valid - apply sanity checks
 *
 */

static void discard_connection(struct connection *c,
			       bool connection_valid,
			       struct logger *connection_logger);

void delete_connection(struct connection *c, bool relations)
{
	struct fd *whackfd = whack_log_fd;

	/*
	 * Must be careful to avoid circularity:
	 * we mark c as going away so it won't get deleted recursively.
	 */
	passert(c->kind != CK_GOING_AWAY);
	if (c->kind == CK_INSTANCE) {
		if ((c->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
			address_buf b;
			log_connection(RC_LOG, whackfd, c,
				       "deleting connection instance with peer %s {isakmp=#%lu/ipsec=#%lu}",
				       str_address_sensitive(&c->spd.that.host_addr, &b),
				       c->newest_isakmp_sa, c->newest_ipsec_sa);
		}
		c->kind = CK_GOING_AWAY;
		if (c->pool != NULL) {
			free_that_address_lease(c);
		}
	}
	release_connection(c, relations, whackfd); /* won't delete c */
	/* make a copy of the logger so it works even after the delete */
	struct logger tmp = CONNECTION_LOGGER(c, whack_log_fd);
	struct logger *connection_logger = clone_logger(&tmp); /* must-free */
	discard_connection(c, true/*connection_valid*/, connection_logger);
	free_logger(&connection_logger, HERE);
}

static void discard_connection(struct connection *c,
			       bool connection_valid,
			       struct logger *connection_logger)
{
	if (c->kind == CK_GROUP)
		delete_group(c);

	if (c->pool != NULL)
		unreference_addresspool(c);

	if (IS_XFRMI && c->xfrmi != NULL)
		unreference_xfrmi(c, connection_logger);

	/* find and delete c from connections list */
	/* XXX: if in list, remove_list_entry(c->ac_next); */
	for (struct connection **head = &connections;
	     *head != NULL; head = &(*head)->ac_next) {
		if (*head == c) {
			*head = c->ac_next;
			c->ac_next = NULL;
			break;
		}
	}

	/* find and delete c from the host pair list */
	host_pair_remove_connection(c, connection_valid);

	flush_revival(c);

	pfreeany(c->name);
	pfreeany(c->foodgroup);
	pfreeany(c->connalias);
	pfreeany(c->vti_iface);
	pfreeany(c->modecfg_dns);
	pfreeany(c->modecfg_domains);
	pfreeany(c->modecfg_banner);
	pfreeany(c->policy_label);
	pfreeany(c->dnshostname);
	pfreeany(c->redirect_to);
	pfreeany(c->accept_redirect_to);

	/* deal with top spd_route and then the rest */

	passert(c->spd.this.virt == NULL);

	virtual_ip_delref(&c->spd.this.virt, HERE);
	virtual_ip_delref(&c->spd.that.virt, HERE);

	struct spd_route *sr = c->spd.spd_next;

	delete_sr(&c->spd);

	while (sr != NULL) {
		struct spd_route *next_sr = sr->spd_next;

		passert(sr->this.virt == NULL);
		passert(sr->that.virt == NULL);
		delete_sr(sr);
		/* ??? should we: pfree(sr); */
		sr = next_sr;
	}

	proposals_delref(&c->ike_proposals.p);
	proposals_delref(&c->child_proposals.p);

	free_ikev2_proposals(&c->v2_ike_proposals);
	free_ikev2_proposals(&c->v2_ike_auth_child_proposals);
	free_ikev2_proposals(&c->v2_create_child_proposals);
	c->v2_create_child_proposals_default_dh = NULL; /* static pointer */

	remove_connection_from_db(c);

	pfree(c);
}

int foreach_connection_by_alias(const char *alias, struct fd *whackfd,
				int (*f)(struct connection *c,
					 struct fd *whackfd,
					 void *arg),
				void *arg)
{
	struct connection *p, *pnext;
	int count = 0;

	dbg("FOR_EACH_CONNECTION_... in %s", __func__);
	for (p = connections; p != NULL; p = pnext) {
		pnext = p->ac_next;

		if (lsw_alias_cmp(alias, p->connalias))
			count += (*f)(p, whackfd, arg);
	}
	return count;
}

static int delete_connection_wrap(struct connection *c,
				  struct fd *unused_whackfd UNUSED,
				  void *arg)
{
	bool *barg = (bool *)arg;

	delete_connection(c, *barg);
	return 1;
}

/* Delete connections with the specified name */
void delete_connections_by_name(const char *name, bool strict, struct fd *whackfd)
{
	bool f = FALSE;

	passert(name != NULL);
	struct connection *c = conn_by_name(name, strict);

	if (c == NULL) {
		(void)foreach_connection_by_alias(name, whackfd,
						  delete_connection_wrap,
						  &f);
	} else {
		for (; c != NULL; c = conn_by_name(name, false/*!strict*/))
			delete_connection(c, FALSE);
	}
}

void delete_every_connection(void)
{
	while (connections != NULL)
		delete_connection(connections, TRUE);
}

void update_ends_from_this_host_addr(struct end *this, struct end *that)
{
	const struct ip_info *afi = address_type(&this->host_addr);
	if (afi == NULL) {
		dbg("%s.host_addr's address family is unknown; skipping default_end()",
		    this->leftright);
		return;
	}

	if (address_eq_any(&this->host_addr)) {
		dbg("%s.host_addr's is %%any; skipping default_end()",
		    this->leftright);
		return;
	}

	dbg("updating connection from %s.host_addr", this->leftright);

	/* Default ID to IP (but only if not NO_IP -- WildCard) */
	if (this->id.kind == ID_NONE && endpoint_is_specified(&this->host_addr)) {
		this->id.kind = afi->id_addr;
		this->id.ip_addr = this->host_addr;
		this->has_id_wildcards = FALSE;
	}

	/* propogate this HOST_ADDR to that. */
	if (isanyaddr(&that->host_nexthop)) {
		that->host_nexthop = this->host_addr;
		address_buf ab;
		dbg("%s host_nexthop %s",
		    that->leftright, str_address(&that->host_nexthop, &ab));
	}

	/*
	 * If THAT has an IKEPORT (which means messages are ESP=0
	 * prefixed), then THIS must send from either IKEPORT or the
	 * NAT port (and also ESP=0 prefix messages).
	 */
	this->host_port = (this->raw.host.ikeport != 0 ? this->raw.host.ikeport :
			   that->raw.host.ikeport != 0 ? NAT_IKE_UDP_PORT :
			   IKE_UDP_PORT);
	dbg("%s host_port %d", this->leftright, this->host_port);

	/* Default client to subnet containing only self */
	if (!this->has_client) {
		/*
		 * Default client to a subnet containing only self.
		 *
		 * For instance, the config file omitted subnet, but
		 * specified protoport; merge that.
		 */
		this->client = selector_from_address(&this->host_addr, &this->raw.client.protoport);
	}

	if (this->sendcert == 0) {
		/* uninitialized (ugly hack) */
		this->sendcert = CERT_SENDIFASKED;
	}
}

/*
 * Format the topology of a connection end, leaving out defaults.
 * Used to construct strings of the form:
 *
 *      LOCAL_END ...END_REMOTE
 *
 * where END_REMOTE is roughly formatted as the mirror image of
 * LOCAL_END.  IS_LEFT (confusing name given connection left/right)
 * determines if the LHS or RHS string is being emitted..  LOCAL_END's
 * longest string is:
 *
 *    client === host : port [ host_id ] --- HOP
 *
 * Note: if that == NULL, skip nexthop Returns strlen of formatted
 * result (length excludes NUL at end).
 */

static void jam_end_host(struct jambuf *buf, const struct end *this, lset_t policy)
{
	/* HOST */
	bool dohost_name;
	bool dohost_port;
	if (!address_is_set(&this->host_addr) ||
	    address_eq_any(&this->host_addr)) {
		dohost_port = false;
		if (this->host_type == KH_IPHOSTNAME) {
			dohost_name = true;
			jam_string(buf, "%dns");
		} else {
			dohost_name = false;
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
	} else if (is_virtual_end(this)) {
		dohost_name = false;
		dohost_port = false;
		jam_string(buf, "%virtual");
	} else {
		dohost_name = true;
		dohost_port = true;
		jam_address_sensitive(buf, &this->host_addr);
	}

	/* <NAME> */
	if (dohost_name && this->host_addr_name != NULL) {
		jam(buf, "<%s>", this->host_addr_name);
	}

	/*
	 * XXX: only print anomalies: when the host address is
	 * "non-zero", a non-IKE_UDP_PORT; and when zero, any non-zero
	 * port.
	 */
	if (dohost_port ? (this->raw.host.ikeport != 0 || this->host_port != IKE_UDP_PORT) :
	    this->host_port != 0) {
		/*
		 * XXX: Part of the problem is that code is stomping
		 * on the HOST_ADDR's port setting it to the CLIENT's
		 * port.
		 *
		 * XXX: Format this as ADDRESS:PORT<name> not
		 * ADDRESS<name>:PORT?  Or always emit the PORT?
		 */
		jam(buf, ":%u", this->host_port);
	}
}

static void jam_end_client(struct jambuf *buf, const struct end *this,
			   lset_t policy, bool is_left)
{
	/* [CLIENT===] or [===CLIENT] */
	if (this->has_client && subnet_is_set(&this->client)) {
		bool boring = (subnet_contains_all_addresses(&this->client) &&
			       (policy & (POLICY_GROUP | POLICY_OPPORTUNISTIC)));

		if (!boring && !is_left) {
			jam_string(buf, "===");
		}

		if (boring) {
			/* boring case */
		} else if (is_virtual_end(this)) {
			if (is_virtual_vhost(this))
				jam_string(buf, "vhost:?");
			else
				jam_string(buf,  "vnet:?");
		} else if (subnet_contains_no_addresses(&this->client)) {
			jam_string(buf, "?");
		} else {
			jam_subnet(buf, &this->client);
		}

		if (!boring && is_left) {
			jam_string(buf, "===");
		}

	}
}

static void jam_end_protoport(struct jambuf *buf, const struct end *this)
{
	/* payload portocol and port */
	if (this->has_port_wildcard) {
		jam(buf, ":%u/%%any", this->protocol);
	} else if (this->port || this->protocol) {
		jam(buf, ":%u/%u", this->protocol, this->port);
	}
}

static void jam_end_id(struct jambuf *buf, const struct end *this)
{
	/* id, if different from host */
	bool open_paren = false;
	if (!(this->id.kind == ID_NONE ||
	      (id_is_ipaddr(&this->id) &&
	       sameaddr(&this->id.ip_addr, &this->host_addr)))) {
		open_paren = true;
		jam_string(buf, "[");
		jam_id(buf, &this->id, jam_sanitized_bytes);
	}

	if (this->modecfg_server || this->modecfg_client ||
	    this->xauth_server || this->xauth_client ||
	    this->sendcert != cert_defaultcertpolicy) {

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
		if (this->xauth_server)
			jam_string(buf, "+XS");
		if (this->xauth_client)
			jam_string(buf, "+XC");

		switch (this->sendcert) {
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
			    const struct end *that, bool filter_rnh, bool is_left)
{
	/* [---hop] */
	if (that != NULL &&
	    !filter_rnh &&
	    !sameaddr(&this->host_nexthop, &that->host_addr)) {
		if (is_left) {
			jam_string(buf, "---");
		}
		jam_address(buf, &this->host_nexthop);
		if (!is_left) {
			jam_string(buf, "---");
		}
	}
}

static void jam_end(struct jambuf *buf,
		  const struct end *this,
		    const struct end *that,
		    bool is_left,
		    lset_t policy,
		    bool filter_rnh)
{
	if (is_left) {
		/* CLIENT=== */
		jam_end_client(buf, this, policy, is_left);
		/* HOST */
		jam_end_host(buf, this, policy);
		/* [ID+OPTS] */
		jam_end_id(buf, this);
		/* /PROTOCOL:PORT */
		jam_end_protoport(buf, this);
		/* ---NEXTHOP */
		jam_end_nexthop(buf, this, that, filter_rnh, is_left);
	} else {
		/* HOPNEXT--- */
		jam_end_nexthop(buf, this, that, filter_rnh, is_left);
		/* HOST */
		jam_end_host(buf, this, policy);
		/* [ID+OPTS] */
		jam_end_id(buf, this);
		/* /PROTOCOL:PORT */
		jam_end_protoport(buf, this);
		/* ===CLIENT */
		jam_end_client(buf, this, policy, is_left);
	}
}

size_t format_end(char *buf,
		  size_t buf_len,
		  const struct end *this,
		  const struct end *that,
		  bool is_left,
		  lset_t policy,
		  bool filter_rnh)
{
	struct jambuf b = array_as_jambuf(buf, buf_len);
	jam_end(&b, this, that, is_left, policy, filter_rnh);
	return strlen(buf);
}

/*
 * format topology of a connection.
 * Two symmetric ends separated by ...
 */
#define CONN_BUF_LEN    (2 * (END_BUF - 1) + 4)

static char *format_connection(char *buf, size_t buf_len,
			const struct connection *c,
			const struct spd_route *sr)
{
	size_t w =
		format_end(buf, buf_len, &sr->this, &sr->that, TRUE, LEMPTY, FALSE);

	snprintf(buf + w, buf_len - w, "...");
	w += strlen(buf + w);
	(void) format_end(buf + w, buf_len - w, &sr->that, &sr->this, FALSE, c->policy,
		oriented(*c));
	return buf;
}

/* spd_route's with end's get copied in xauth.c */
void unshare_connection_end(struct end *e)
{
	e->id = clone_id(&e->id, "unshare connection id");

	if (e->cert.u.nss_cert != NULL) {
		e->cert.u.nss_cert = CERT_DupCertificate(e->cert.u.nss_cert);
		passert(e->cert.u.nss_cert != NULL);
	}

	e->ca = clone_hunk(e->ca, "ca string");
	e->updown = clone_str(e->updown, "updown");
	e->xauth_username = clone_str(e->xauth_username, "xauth username");
	e->xauth_password = clone_str(e->xauth_password, "xauth password");
	e->host_addr_name = clone_str(e->host_addr_name, "host ip");
	e->virt = virtual_ip_addref(e->virt, HERE);
	if (e->ckaid != NULL) {
		e->ckaid = clone_thing(*e->ckaid, "ckaid");
	}
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
 * up after the event, a guaranteed way to create use-after-free
 * problems.
 */
static void unshare_connection(struct connection *c)
{
	c->foodgroup = clone_str(c->foodgroup, "connection foodgroup");

	c->modecfg_dns = clone_str(c->modecfg_dns,
				"connection modecfg_dns");
	c->modecfg_domains = clone_str(c->modecfg_domains,
				"connection modecfg_domains");
	c->modecfg_banner = clone_str(c->modecfg_banner,
				"connection modecfg_banner");
	c->policy_label = clone_str(c->policy_label,
				    "connection policy_label");
	c->dnshostname = clone_str(c->dnshostname, "connection dnshostname");

	/* duplicate any alias, adding spaces to the beginning and end */
	c->connalias = clone_str(c->connalias, "connection alias");

	c->vti_iface = clone_str(c->vti_iface, "connection vti_iface");

	c->redirect_to = clone_str(c->redirect_to,\
					"connection redirect_to");
	c->accept_redirect_to = clone_str(c->accept_redirect_to,\
					"connection accept_redirect_to");

	struct spd_route *sr;

	for (sr = &c->spd; sr != NULL; sr = sr->spd_next) {
		unshare_connection_end(&sr->this);
		unshare_connection_end(&sr->that);
	}

	/* increment references to algo's, if any */
	proposals_addref(&c->ike_proposals.p);
	proposals_addref(&c->child_proposals.p);

	if (c->pool !=  NULL)
		reference_addresspool(c);

	if (IS_XFRMI && c->xfrmi != NULL)
		reference_xfrmi(c);
}

static int extract_end(struct end *dst,
		       const struct whack_end *src,
		       const char *leftright,
		       struct logger *logger/*connection "..."*/)
{
	dst->leftright = leftright;

	bool same_ca = 0;

	/*
	 * decode id, if any
	 *
	 * For %fromcert, the load_end_cert*() call will update it.
	 */
	if (src->id == NULL) {
		dst->id.kind = ID_NONE;
	} else {
		err_t ugh = atoid(src->id, &dst->id);
		if (ugh != NULL) {
			log_message(RC_BADID, logger,
				    "bad %s --id: %s (ignored)", leftright, ugh);
		}
	}

	/* decode CA distinguished name, if any */
	dst->ca = EMPTY_CHUNK;
	if (src->ca != NULL) {
		if (streq(src->ca, "%same")) {
			same_ca = 1;
		} else if (!streq(src->ca, "%any")) {
			err_t ugh;

			/* convert the CA into a DN blob */
			ugh = atodn(src->ca, &dst->ca); /* static result! */
			if (ugh != NULL) {
				log_message(RC_LOG, logger,
					    "bad %s CA string '%s': %s (ignored)",
					    leftright, src->ca, ugh);
				dst->ca = EMPTY_CHUNK;
			} else {
				dst->ca = clone_hunk(dst->ca, "ca string");
				/* now try converting it back; isn't failing this a bug? */
				ugh = parse_dn(dst->ca);
				if (ugh != NULL) {
					log_message(RC_LOG, logger,
						    "error parsing %s CA converted to DN: %s",
						    leftright, ugh);
					DBG_dump_hunk(NULL, dst->ca);
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
			log_message(RC_LOG, logger,
				    "warning: ignoring %s ckaid '%s' and using %s certificate '%s'",
				    dst->leftright, src->cert,
				    dst->leftright, src->cert);
		}
		if (src->rsasigkey != NULL) {
			log_message(RC_LOG, logger,
				    "warning: ignoring %s rsasigkey '%s' and using %s certificate '%s'",
				    dst->leftright, src->cert,
				    dst->leftright, src->cert);
		}
		CERTCertificate *cert = get_cert_by_nickname_from_nss(src->cert, logger);
		if (cert == NULL) {
			log_message(RC_FATAL, logger,
				    "failed to add connection: %s certificate '%s' not found in the NSS database",
				    dst->leftright, src->cert);
			return -1; /* fatal */
		}
		diag_t diag = add_end_cert_and_preload_private_key(cert, dst,
								   same_ca/*preserve_ca*/,
								   logger);
		if (diag != NULL) {
			log_diag(RC_FATAL, logger, &diag, "failed to add connection: ");
			CERT_DestroyCertificate(cert);
			return -1;
		}
	} else if (src->rsasigkey != NULL) {
		if (src->ckaid != NULL) {
			log_message(RC_LOG, logger,
				    "warning: ignoring %s ckaid '%s' and using %s rsasigkey",
				    dst->leftright, src->ckaid, dst->leftright);
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
			log_message(RC_FATAL, logger,
				    "failed to add connection: %s raw public key invalid: %s",
				    dst->leftright, err);
			return -1;
		}
		ckaid_buf ckb;
		dbg("saving %s CKAID %s extracted from raw %s public key",
		    dst->leftright, str_ckaid(&ckaid, &ckb), type->name);
		dst->ckaid = clone_const_thing(ckaid, "raw pubkey's ckaid");
		type->free_pubkey_content(&pkc);
		/* try to pre-load the private key */
		bool load_needed;
		err = preload_private_key_by_ckaid(&ckaid, &load_needed, logger);
		if (err != NULL) {
			ckaid_buf ckb;
			dbg("no private key matching %s CKAID %s: %s",
			    dst->leftright, str_ckaid(dst->ckaid, &ckb), err);
		} else if (load_needed) {
			ckaid_buf ckb;
			log_message(RC_LOG|LOG_STREAM/*not-whack-for-now*/, logger,
				    "loaded private key matching %s CKAID %s",
				    dst->leftright, str_ckaid(dst->ckaid, &ckb));
		}
	} else if (src->ckaid != NULL) {
		ckaid_t ckaid;
		err_t err = string_to_ckaid(src->ckaid, &ckaid);
		if (err != NULL) {
			/* should have been rejected by whack? */
			/* XXX: don't trust whack */
			log_message(RC_FATAL, logger,
				    "failed to add connection: %s CKAID '%s' invalid: %s",
				    dst->leftright, src->ckaid, err);
			return -1; /* fatal */
		}
		/*
		 * Always save the CKAID so lazy load of the private
		 * key will work.
		 */
		dst->ckaid = clone_thing(ckaid, "end ckaid");
		/*
		 * See if there's a certificate matching the CKAID, if
		 * not assume things will later find the private key.
		 */
		CERTCertificate *cert = get_cert_by_ckaid_from_nss(&ckaid, logger);
		if (cert != NULL) {
			diag_t diag = add_end_cert_and_preload_private_key(cert, dst,
									   same_ca/*preserve_ca*/,
									   logger);
			if (diag != NULL) {
				log_diag(RC_FATAL, logger, &diag, "failed to add connection: ");
				CERT_DestroyCertificate(cert);
				return -1;
			}
		} else {
			dbg("%s CKAID '%s' did not match a certificate in the NSS database",
			    dst->leftright, src->ckaid);
			/* try to pre-load the private key */
			bool load_needed;
			err_t err = preload_private_key_by_ckaid(&ckaid, &load_needed, logger);
			if (err != NULL) {
				ckaid_buf ckb;
				dbg("no private key matching %s CKAID %s: %s",
				    dst->leftright, str_ckaid(dst->ckaid, &ckb), err);
			} else {
				ckaid_buf ckb;
				log_message(RC_LOG|LOG_STREAM/*not-whack-for-now*/, logger,
					    "loaded private key matching %s CKAID %s",
					    dst->leftright, str_ckaid(dst->ckaid, &ckb));
			}
		}
	}

	/* does id have wildcards? */
	dst->has_id_wildcards = id_count_wildcards(&dst->id) > 0;

	/* the rest is simple copying of corresponding fields */
	dst->host_type = src->host_type;
	dst->host_addr = src->host_addr;
	dst->host_addr_name = clone_str(src->host_addr_name, "host ip");
	dst->host_nexthop = src->host_nexthop;
	dst->host_srcip = src->host_srcip;
	dst->host_vtiip = src->host_vtiip;
	dst->ifaceip = src->ifaceip;
	dst->modecfg_server = src->modecfg_server;
	dst->modecfg_client = src->modecfg_client;
	dst->cat = src->cat;
	dst->pool_range = src->pool_range;

	dst->xauth_server = src->xauth_server;
	dst->xauth_client = src->xauth_client;
	dst->xauth_username = clone_str(src->xauth_username, "xauth username");

	dst->authby = src->authby;

	/* save some defaults */
	dst->raw.client.subnet = src->client;
	dst->raw.client.protoport = src->protoport;

	/*
	 * .has_client means that .client contains a hardwired value,
	 * if it doesn't then it is filled in later (for instance by
	 * instantiate() calling default_end() after host_addr is
	 * known).
	 */
	dst->has_client = src->has_client;
	if (src->has_client) {
		pexpect(subnet_is_set(&src->client));
		dst->client = selector_from_subnet(&src->client,
						   &src->protoport);
	}

	dst->protocol = src->protoport.protocol;
	dst->port = src->protoport.port;
	dst->has_port_wildcard = protoport_has_any_port(&src->protoport);
	dst->key_from_DNS_on_demand = src->key_from_DNS_on_demand;
	dst->updown = clone_str(src->updown, "updown");
	dst->sendcert =  src->sendcert;

	dst->raw.host.ikeport = src->host_ikeport;
	if (src->host_ikeport > 65535) {
		log_message(RC_BADID, logger,
			    "%sikeport=%u must be between 1..65535, ignored",
			    leftright, src->host_ikeport);
		dst->raw.host.ikeport = 0;
	}

	/*
	 * see if we can resolve the DNS name right now
	 * XXX this is WRONG, we should do this asynchronously, as part of
	 * the normal loading process
	 */
	switch (dst->host_type) {
	case KH_IPHOSTNAME:
	{
		err_t er = domain_to_address(shunk1(dst->host_addr_name),
					     address_type(&dst->host_addr),
					     &dst->host_addr);
		if (er != NULL) {
			log_message(RC_COMMENT, logger,
				    "failed to convert '%s' at load time: %s",
				    dst->host_addr_name, er);
		}
		break;
	}

	default:
		break;
	}

	return same_ca;
}

static bool check_connection_end(const struct whack_end *this,
				const struct whack_end *that,
				const struct whack_message *wm)
{
	if ((this->host_type == KH_IPADDR || this->host_type == KH_IFACE) &&
		(wm->addr_family != addrtypeof(&this->host_addr) ||
			wm->addr_family != addrtypeof(&this->host_nexthop))) {
		/*
		 * This should have been diagnosed by whack, so we need not
		 * be clear.
		 * !!! overloaded use of RC_CLASH
		 */
		loglog(RC_CLASH,
			"address family inconsistency in this connection=%d host=%d/nexthop=%d",
			wm->addr_family,
			addrtypeof(&this->host_addr),
			addrtypeof(&this->host_nexthop));
		return FALSE;
	}

	/* ??? seems like a nasty test (in-band, low-level) */
	/* XXX: still nasty; just less low-level */
	if (range_is_specified(&this->pool_range)) {
		struct ip_pool *pool;
		err_t er = find_addresspool(&this->pool_range, &pool);

		if (er != NULL) {
			loglog(RC_CLASH, "leftaddresspool clash");
			return FALSE;
		}
	}

	if (subnet_is_specified(&this->client) &&
	    subnet_is_specified(&that->client)) {
		/* IPv4 vs IPv6? */
		if (subnet_type(&this->client) != subnet_type(&that->client)) {
			/*
			 * !!! overloaded use of RC_CLASH
			 */
			loglog(RC_CLASH,
				"address family inconsistency in this/that connection");
			return FALSE;
		}
	}

	/* MAKE this more sane in the face of unresolved IP addresses */
	if (that->host_type != KH_IPHOSTNAME && isanyaddr(&that->host_addr)) {
		/*
		 * Other side is wildcard: we must check if other conditions
		 * met.
		 */
		if (this->host_type != KH_IPHOSTNAME &&
			isanyaddr(&this->host_addr)) {
			loglog(RC_ORIENT,
				"connection %s must specify host IP address for our side",
				wm->name);
			return FALSE;
		}
	}

	if (this->protoport.protocol == 0 && this->protoport.port != 0) {
		loglog(RC_ORIENT, "connection %s cannot specify non-zero port %d for prototcol 0",
			wm->name, this->protoport.port);
		return FALSE;
	}

	if (this->id != NULL && streq(this->id, "%fromcert")) {
		lset_t auth_pol = (wm->policy & POLICY_ID_AUTH_MASK);

		if (this->authby == AUTHBY_PSK || this->authby == AUTHBY_NULL ||
			auth_pol == POLICY_PSK || auth_pol == POLICY_AUTH_NULL) {
			loglog(RC_FATAL, "ID cannot be specified as %%fromcert if PSK or AUTH-NULL is used");
			return false;
		}
	}

	return TRUE; /* happy */
}

diag_t add_end_cert_and_preload_private_key(CERTCertificate *cert,
					    struct end *dst_end,
					    bool preserve_ca,
					    struct logger *logger)
{
	passert(cert != NULL);
	dst_end->cert.ty = CERT_NONE;
	dst_end->cert.u.nss_cert = NULL;
	const char *nickname = cert->nickname;

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
				    dst_end->leftright, nickname,
				    pk->u.rsa.modulus.len * BITS_PER_BYTE,
				    FIPS_MIN_RSA_KEY_SIZE);
		}
		/* TODO FORCE MINIMUM SIZE ECDSA KEY */
		SECKEY_DestroyPublicKey(pk);
	}

	/* XXX: should this be after validity check? */
	select_nss_cert_id(cert, &dst_end->id);

	/* check validity of cert */
	if (CERT_CheckCertValidTimes(cert, PR_Now(), FALSE) !=
			secCertTimeValid) {
		return diag("%s certificate '%s' is expired or not yet valid",
			    dst_end->leftright, nickname);
	}

	dbg("loading %s certificate \'%s\' pubkey", dst_end->leftright, nickname);
	if (!add_pubkey_from_nss_cert(&pluto_pubkeys, &dst_end->id, cert, logger)) {
		/* XXX: push diag_t into add_pubkey_from_nss_cert()? */
		return diag("%s certificate \'%s\' pubkey could not be loaded",
			    dst_end->leftright, nickname);
	}

	dst_end->cert.ty = CERT_X509_SIGNATURE;
	dst_end->cert.u.nss_cert = cert;

	/*
	 * If no CA is defined, use issuer as default; but only when
	 * update is ok.
	 *
	 */
	if (preserve_ca || dst_end->ca.ptr != NULL) {
		dbg("preserving existing %s ca", dst_end->leftright);
	} else {
		dst_end->ca = clone_secitem_as_chunk(cert->derIssuer, "issuer ca");
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
	err_t ugh = preload_private_key_by_cert(&dst_end->cert, &load_needed, logger);
	if (ugh != NULL) {
		dbg("no private key matching %s certificate %s: %s",
		    dst_end->leftright, nickname, ugh);
	} else if (load_needed) {
		log_message(RC_LOG|LOG_STREAM/*not-whack-for-now*/, logger,
			    "loaded private key matching %s certificate '%s'",
			    dst_end->leftright, nickname);
	}
	return NULL;
}

/* only used by add_connection() */
static void mark_parse(/*const*/ char *wmmark,
		       struct sa_mark *sa_mark,
		       struct logger *logger/*connection "...":*/)
{
	/*const*/ char *val_end;

	sa_mark->unique = FALSE;
	sa_mark->val = 0xffffffff;
	sa_mark->mask = 0xffffffff;
	if (streq(wmmark, "-1") || startswith(wmmark, "-1/")) {
		sa_mark->unique = TRUE;
		val_end = wmmark + strlen("-1");
	} else {
		errno = 0;
		unsigned long v = strtoul(wmmark, &val_end, 0);
		if (errno != 0 || v > 0xffffffff ||
		    (*val_end != '\0' && *val_end != '/'))
		{
			/* ??? should be detected and reported by confread and whack */
			/* XXX: don't trust whack */
			log_message(RC_LOG_SERIOUS, logger,
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
			log_message(RC_LOG_SERIOUS, logger,
				   "bad mark mask \"%s\"", mask_end);
		} else {
			sa_mark->mask = v;
		}
	}
	if ((sa_mark->val & ~sa_mark->mask) != 0) {
		/* ??? should be detected and reported by confread and whack */
		/* XXX: don't trust whack */
		log_message(RC_LOG_SERIOUS, logger,
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
 * return false, the caller will then use delete_connection() to free
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
			       struct connection *c,
			       struct logger *logger/*connection "..": */)
{
	passert(c->name != NULL); /* see alloc_connection() */
	if (conn_by_name(wm->name, false/*!strict*/) != NULL) {
		log_message(RC_DUPNAME, logger,
			    "attempt to redefine connection \"%s\"",
			    wm->name);
		return false;
	}

	if ((wm->policy & POLICY_COMPRESS) && !can_do_IPcomp) {
		log_message(RC_FATAL, logger,
			    "failed to add connection with compress because kernel is not configured to do IPCOMP");
		return false;
	}

	if ((wm->policy & POLICY_TUNNEL) == LEMPTY) {
		if (wm->sa_tfcpad != 0) {
			log_message(RC_FATAL, logger,
				    "failed to add connection: connection with type=transport cannot specify tfc=");
			return false;
		}
		if (wm->vti_iface != NULL) {
			log_message(RC_FATAL, logger,
				    "failed to add connection: VTI requires tunnel mode but connection specifies type=transport");
			return false;
		}
	}
	if (LIN(POLICY_AUTHENTICATE, wm->policy)) {
		if (wm->sa_tfcpad != 0) {
			log_message(RC_FATAL, logger,
				    "failed to add connection: connection with phase2=ah cannot specify tfc=");
			return false;
		}
	}

	if (LIN(POLICY_AUTH_NEVER, wm->policy)) {
		if ((wm->policy & POLICY_SHUNT_MASK) == POLICY_SHUNT_TRAP) {
			log_message(RC_FATAL, logger,
				    "failed to add connection: connection with authby=never must specify shunt type via type=");
			return false;
		}
	}
	if ((wm->policy & POLICY_SHUNT_MASK) != POLICY_SHUNT_TRAP) {
		if ((wm->policy & (POLICY_ID_AUTH_MASK & ~POLICY_AUTH_NEVER)) != LEMPTY) {
			log_message(RC_FATAL, logger,
				    "failed to add connection: shunt connection cannot have authentication method other then authby=never");
			return false;
		}
	} else {
		switch (wm->policy & (POLICY_AUTHENTICATE  | POLICY_ENCRYPT)) {
		case LEMPTY:
			if (!LIN(POLICY_AUTH_NEVER, wm->policy)) {
				log_message(RC_FATAL, logger,
					    "failed to add connection: non-shunt connection must have AH or ESP");
				return false;
			}
			break;
		case POLICY_AUTHENTICATE | POLICY_ENCRYPT:
			log_message(RC_FATAL, logger,
				    "failed to add connection: non-shunt connection must not specify both AH and ESP");
			return false;
		}
	}

	switch (wm->policy & (POLICY_IKEV1_ALLOW | POLICY_IKEV2_ALLOW)) {
	case POLICY_IKEV1_ALLOW:
		c->ike_version = IKEv1;
		if (pluto_ikev1_pol != GLOBAL_IKEv1_ACCEPT) {
			log_message(RC_FATAL, logger,
				    "failed to add IKEv1 connection: global ikev1-policy does not allow IKEv1 connections");
			return false;
		}
		break;
	case POLICY_IKEV2_ALLOW:
		c->ike_version = IKEv2;
		break;
	case 0:
		c->ike_version = 0; /* i.e., none */
		break;
	default:
		log_message(RC_FATAL, logger,
			    "failed to add connection: connection can only be IKEv1 or IKEv2");
		return false;
	}

	if (wm->policy & POLICY_OPPORTUNISTIC &&
	    c->ike_version == IKEv1) {
		log_message(RC_FATAL, logger,
			    "failed to add connection: opportunistic connection MUST have IKEv2");
		return false;
	}

	if (wm->policy & POLICY_MOBIKE &&
	    c->ike_version == IKEv1) {
		log_message(RC_FATAL, logger,
			    "failed to add connection: MOBIKE requires IKEv2");
		return false;
	}

	if (wm->policy & POLICY_IKEV2_ALLOW_NARROWING &&
	    c->ike_version == IKEv1) {
		log_message(RC_FATAL, logger,
			    "failed to add connection: narrowing=yes requires IKEv2");
		return false;
	}

	if (wm->iketcp != IKE_TCP_NO &&
	    c->ike_version != IKEv2) {
		log_message(RC_FATAL, logger,
			    "failed to add connection: enable-tcp= requires IKEv2");
		return false;
	}

	if (wm->policy & POLICY_MOBIKE) {
		if (kernel_ops->migrate_sa_check == NULL) {
			log_message(RC_FATAL, logger,
				    "failed to add connection: MOBIKE not supported by %s interface",
				    kernel_ops->kern_name);
			return false;
		}
		/* probe the interface */
		err_t err = kernel_ops->migrate_sa_check();
		if (err != NULL) {
			log_message(RC_FATAL, logger,
				    "failed to add connection: MOBIKE kernel support missing for %s interface: %s",
				    kernel_ops->kern_name, err);
			return false;
		}
	}

	if (wm->iketcp != IKE_TCP_NO && (wm->remote_tcpport == 0 || wm->remote_tcpport == 500)) {
		log_message(RC_FATAL, logger,
			    "failed to add connection: tcp-remoteport cannot be 0 or 500");
		return false;
	}

	/* we could complain about a lot more whack strings */
	if (NEVER_NEGOTIATE(wm->policy)) {
		if (wm->ike != NULL) {
			log_message(RC_INFORMATIONAL, logger,
				    "ignored ike= option for type=passthrough connection");
		}
		if (wm->esp != NULL) {
			log_message(RC_INFORMATIONAL, logger,
				    "ignored esp= option for type=passthrough connection");
		}
		if (wm->iketcp != IKE_TCP_NO) {
			log_message(RC_INFORMATIONAL, logger,
				    "ignored enable-tcp= option for type=passthrough connection");
		}
		if (wm->left.authby != AUTHBY_UNSET || wm->right.authby != AUTHBY_UNSET) {
			log_message(RC_FATAL, logger,
				    "failed to add connection: leftauth= / rightauth= options are invalid for type=passthrough connection");
			return false;
		}
	} else {
		/* reject all bad combinations of authby with leftauth=/rightauth= */
		if (wm->left.authby != AUTHBY_UNSET || wm->right.authby != AUTHBY_UNSET) {
			if (c->ike_version == IKEv1) {
				log_message(RC_FATAL, logger,
					    "failed to add connection: leftauth= and rightauth= require ikev2");
				return false;
			}
			if (wm->left.authby == AUTHBY_UNSET || wm->right.authby == AUTHBY_UNSET) {
				log_message(RC_FATAL, logger,
					    "failed to add connection: leftauth= and rightauth= must both be set or both be unset");
				return false;
			}
			/* ensure no conflicts of set left/rightauth with (set or unset) authby= */
			if (wm->left.authby == wm->right.authby) {

				lset_t auth_pol = (wm->policy & POLICY_ID_AUTH_MASK);
				const char *conflict = NULL;
				switch (wm->left.authby) {
				case AUTHBY_PSK:
					if (auth_pol != POLICY_PSK && auth_pol != LEMPTY) {
						conflict = "leftauthby=secret but authby= is not secret";
					}
					break;
				case AUTHBY_NULL:
					if (auth_pol != POLICY_AUTH_NULL && auth_pol != LEMPTY) {
						conflict = "leftauthby=null but authby= is not null";
					}
					break;
				case AUTHBY_NEVER:
					if ((wm->policy & POLICY_ID_AUTH_MASK) != LEMPTY) {
						conflict = "leftauthby=never but authby= is not never - double huh?";
					}
					break;
				case AUTHBY_RSASIG:
				case AUTHBY_ECDSA:
					/* will be fixed later below */
					break;
				default:
					bad_case(wm->left.authby);
				}
				if (conflict != NULL) {
					log_message(RC_FATAL, logger,
						    "failed to add connection: leftauth=%s and rightauth=%s conflict with authby=%s, %s",
						    enum_name(&keyword_authby_names, wm->left.authby),
						    enum_name(&keyword_authby_names, wm->right.authby),
						    prettypolicy(wm->policy & POLICY_ID_AUTH_MASK),
						    conflict);
					return false;
				}
			} else {
				if ((wm->left.authby == AUTHBY_PSK && wm->right.authby == AUTHBY_NULL) ||
				    (wm->left.authby == AUTHBY_NULL && wm->right.authby == AUTHBY_PSK)) {
					log_message(RC_FATAL, logger,
						    "failed to add connection: cannot mix PSK and NULL authentication (leftauth=%s and rightauth=%s)",
						    enum_name(&keyword_authby_names, wm->left.authby),
						    enum_name(&keyword_authby_names, wm->right.authby));
					return false;
				}
			}
		}
	}

	if (protoport_has_any_port(&wm->right.protoport) &&
	    protoport_has_any_port(&wm->left.protoport)) {
		log_message(RC_FATAL, logger,
			    "failed to add connection: cannot have protoport with %%any on both sides");
		return false;
	}

	if (!check_connection_end(&wm->right, &wm->left, wm) ||
	    !check_connection_end(&wm->left, &wm->right, wm)) {
		/* XXX: shouldn't check_connection_end() log the error? */
		log_message(RC_FATAL, logger,
			    "failed to add connection: attempt to load incomplete connection");
		return false;
	}

	if (subnet_type(&wm->left.client) != subnet_type(&wm->right.client)) {
		log_message(RC_FATAL, logger,
			    "failed to add connection: subnets must have the same address family");
		return false;
	}

	/* duplicate any alias, adding spaces to the beginning and end */
	c->connalias = clone_str(wm->connalias, "connection alias");

	c->dnshostname = clone_str(wm->dnshostname, "connection dnshostname");
	c->policy = wm->policy;
       /* ignore IKEv2 ECDSA and legacy RSA policies for IKEv1 connections */
	if (c->ike_version == IKEv1)
		c->policy = (c->policy & ~(POLICY_ECDSA | POLICY_RSASIG_v1_5));
	/* ignore symmetrical defaults if we got left/rightauth */
	if (wm->left.authby != wm->right.authby)
		c->policy = c->policy & ~POLICY_ID_AUTH_MASK;
	/* remove default pubkey policy if left/rightauth is specified */
	if (wm->left.authby == wm->right.authby) {
		if (wm->left.authby == AUTHBY_RSASIG)
			c->policy = (c->policy & ~(POLICY_ECDSA));
		if (wm->left.authby == AUTHBY_ECDSA)
			c->policy = (c->policy & ~(POLICY_RSASIG | POLICY_RSASIG_v1_5));
	}
	/* ignore supplied sighash and ECDSA (from defaults) for IKEv1 */
	if (c->ike_version == IKEv2)
		c->sighash_policy = wm->sighash_policy;

	if (NEVER_NEGOTIATE(c->policy)) {
		/* cleanup inherited default */
		c->policy &= ~(POLICY_IKEV1_ALLOW|POLICY_IKEV2_ALLOW);
		c->ike_version = 0;
		c->iketcp = IKE_TCP_NO;
		c->remote_tcpport = 0;
	}

	if (libreswan_fipsmode()) {
		if (c->policy & POLICY_NEGO_PASS) {
			c->policy &= ~POLICY_NEGO_PASS;
			log_message(RC_LOG_SERIOUS, logger,
				    "FIPS: ignored negotiationshunt=passthrough - packets MUST be blocked in FIPS mode");
		}
		if ((c->policy & POLICY_FAIL_MASK) == POLICY_FAIL_PASS) {
			c->policy &= ~POLICY_FAIL_MASK;
			c->policy |= POLICY_FAIL_NONE;
			log_message(RC_LOG_SERIOUS, logger,
				    "FIPS: ignored failureshunt=passthrough - packets MUST be blocked in FIPS mode");
		}
	}

	dbg("added new connection %s with policy %s%s",
	    c->name, prettypolicy(c->policy),
	    NEVER_NEGOTIATE(c->policy) ? "+NEVER_NEGOTIATE" : "");

	if (NEVER_NEGOTIATE(wm->policy)) {
		/* set default to AUTHBY_NEVER if unset and we do not expect to do IKE */
		if (wm->left.authby == AUTHBY_UNSET && wm->right.authby == AUTHBY_UNSET) {
			if ((c->policy & POLICY_ID_AUTH_MASK) == LEMPTY) {
				/* authby= was also not specified - fill in default */
				c->policy |= POLICY_AUTH_NEVER;
				dbg("no AUTH policy was set for type=passthrough - defaulting to %s",
				    prettypolicy(c->policy & POLICY_ID_AUTH_MASK));
			}
		}
	} else {
		/* set default to RSASIG if unset and we expect to do IKE */
		if (wm->left.authby == AUTHBY_UNSET && wm->right.authby == AUTHBY_UNSET) {
			 if ((c->policy & POLICY_ID_AUTH_MASK) == LEMPTY) {
				/* authby= was also not specified - fill in default */
				c->policy |= POLICY_DEFAULT;
				dbg("no AUTH policy was set - defaulting to %s",
				    prettypolicy(c->policy & POLICY_ID_AUTH_MASK));
			}
		}

		/* fixup symmetric policy flags based on asymmetric ones */
		if ((wm->left.authby == AUTHBY_NULL && wm->right.authby == AUTHBY_RSASIG) ||
		    (wm->left.authby == AUTHBY_RSASIG && wm->right.authby == AUTHBY_NULL)) {
			c->policy |= POLICY_RSASIG;
		}
		if ((wm->left.authby == AUTHBY_NULL && wm->right.authby == AUTHBY_ECDSA) ||
		    (wm->left.authby == AUTHBY_ECDSA && wm->right.authby == AUTHBY_NULL)) {
			c->policy |= POLICY_ECDSA;
		}

		/* IKE cipher suites */

		if (!LIN(POLICY_AUTH_NEVER, wm->policy) &&
		    (wm->ike != NULL || c->ike_version == IKEv2)) {
			const struct proposal_policy proposal_policy = {
				/* logic needs to match pick_initiator() */
				.version = c->ike_version,
				.alg_is_ok = ike_alg_is_ike,
				.pfs = LIN(POLICY_PFS, wm->policy),
				.check_pfs_vs_dh = false,
				.logger_rc_flags = ALL_STREAMS|RC_LOG,
				.logger = logger,
				/* let defaults stumble on regardless */
				.ignore_parser_errors = (wm->ike == NULL),
			};

			struct proposal_parser *parser = ike_proposal_parser(&proposal_policy);
			c->ike_proposals.p = proposals_from_str(parser, wm->ike);

			if (c->ike_proposals.p == NULL) {
				pexpect(parser->diag != NULL); /* something */
				log_diag(RC_FATAL, logger, &parser->diag,
					 "failed to add connection: ");
				free_proposal_parser(&parser);
				/* caller will free C */
				return false;
			}
			free_proposal_parser(&parser);

			/* from here on, error returns should alg_info_free(&c->ike_proposals->ai); */

			LSWDBGP(DBG_BASE, buf) {
				jam_string(buf, "ike (phase1) algorithm values: ");
				jam_proposals(buf, c->ike_proposals.p);
			}
		}

		/* ESP or AH cipher suites (but not both) */

		if (wm->esp != NULL ||
		    (c->ike_version == IKEv2 &&
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
				.version = c->ike_version,
				.alg_is_ok = kernel_alg_is_ok,
				.pfs = LIN(POLICY_PFS, wm->policy),
				.check_pfs_vs_dh = true,
				.logger_rc_flags = ALL_STREAMS|RC_LOG,
				.logger = logger,
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
			c->child_proposals.p = proposals_from_str(parser, wm->esp);
			if (c->child_proposals.p == NULL) {
				pexpect(parser->diag != NULL);
				log_diag(RC_FATAL, logger, &parser->diag,
					 "failed to add connection: ");
				free_proposal_parser(&parser);
				/* caller will free C */
				return false;
			}
			free_proposal_parser(&parser);

			/* from here on, error returns should alg_info_free(&c->child_proposals->ai); */

			LSWDBGP(DBG_BASE, buf) {
				jam_string(buf, "ESP/AH string values: ");
				jam_proposals(buf, c->child_proposals.p);
			};
		}

		c->nic_offload = wm->nic_offload;
		c->sa_ike_life_seconds = wm->sa_ike_life_seconds;
		c->sa_ipsec_life_seconds = wm->sa_ipsec_life_seconds;
		c->sa_rekey_margin = wm->sa_rekey_margin;
		c->sa_rekey_fuzz = wm->sa_rekey_fuzz;
		c->sa_keying_tries = wm->sa_keying_tries;
		c->sa_replay_window = wm->sa_replay_window;
		c->r_timeout = wm->r_timeout;
		c->r_interval = wm->r_interval;

		if (deltatime_cmp(c->sa_rekey_margin, >=, c->sa_ipsec_life_seconds)) {
			deltatime_t new_rkm = deltatimescale(1, 2, c->sa_ipsec_life_seconds);

			log_message(RC_LOG, logger,
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
				log_message(RC_LOG_SERIOUS, logger,
					    "IKE lifetime limited to the maximum allowed %jds",
					    (intmax_t) max_ike);
				c->sa_ike_life_seconds = deltatime(max_ike);
			}
			if (deltasecs(c->sa_ipsec_life_seconds) > max_ipsec) {
				log_message(RC_LOG_SERIOUS, logger,
					    "IPsec lifetime limited to the maximum allowed %jds",
					    (intmax_t) max_ipsec);
				c->sa_ipsec_life_seconds = deltatime(max_ipsec);
			}
		}

		/* RFC 3706 DPD */
		c->dpd_delay = wm->dpd_delay;
		c->dpd_timeout = wm->dpd_timeout;
		c->dpd_action = wm->dpd_action;

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
			mark_parse(wm->conn_mark_both, &c->sa_marks.in, logger);
			mark_parse(wm->conn_mark_both, &c->sa_marks.out, logger);
			if (wm->conn_mark_in != NULL || wm->conn_mark_out != NULL) {
				log_message(RC_LOG_SERIOUS, logger,
					    "conflicting mark specifications");
			}
		}
		if (wm->conn_mark_in != NULL)
			mark_parse(wm->conn_mark_in, &c->sa_marks.in, logger);
		if (wm->conn_mark_out != NULL)
			mark_parse(wm->conn_mark_out, &c->sa_marks.out, logger);

		c->vti_iface = clone_str(wm->vti_iface, "connection vti_iface");
		c->vti_routing = wm->vti_routing;
		c->vti_shared = wm->vti_shared;
#ifdef USE_XFRM_INTERFACE
		if (wm->xfrm_if_id != UINT32_MAX) {
			err_t err = xfrm_iface_supported(logger);
			if (err == NULL) {
				if (!setup_xfrm_interface(c, wm->xfrm_if_id == 0 ?
					PLUTO_XFRMI_REMAP_IF_ID_ZERO : wm->xfrm_if_id ))
					return false;
			} else {
				log_message(RC_FATAL, logger,
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

	c->policy_label = clone_str(wm->policy_label, "connection policy_label");
#ifndef HAVE_LABELED_IPSEC
	if ((c->policy_label != NULL) && (strlen(c->policy_label) > 0)) {
		log_message(RC_FATAL, logger,
			    "failed to add connection: labeled IPsec not compiled in. policy-label=%s not supported.",
			    c->policy_label);

		return false;
	}
#endif
	c->nflog_group = wm->nflog_group;
	c->sa_priority = wm->sa_priority;
	c->sa_tfcpad = wm->sa_tfcpad;
	c->send_no_esp_tfc = wm->send_no_esp_tfc;
	c->sa_reqid = wm->sa_reqid;

	/*
	 * Since at this point 'this' and 'that' are disoriented their
	 * names are pretty much meaningless.  Hence the strange
	 * combination if 'this' and 'left' and 'that' and 'right.
	 *
	 * XXX: This is all too confusing - wouldn't it be simpler if
	 * there was a '.left' and '.right' (or even .end[2] - this
	 * code seems to be crying out for a for loop) and then having
	 * orient() set up .local and .remote pointers or indexes
	 * accordingly?
	 */
	int same_leftca = extract_end(&c->spd.this, &wm->left, "left", logger);
	if (same_leftca < 0) {
		return false;
	}
	int same_rightca = extract_end(&c->spd.that, &wm->right, "right", logger);
	if (same_rightca < 0) {
		return false;
	}

	if (same_rightca == 1) {
		c->spd.that.ca = clone_hunk(c->spd.this.ca, "same rightca");
	} else if (same_leftca == 1) {
		c->spd.this.ca = clone_hunk(c->spd.that.ca, "same leftca");
	}

	/*
	 * How to add addresspool only for responder?
	 * It is not necessary on the initiator
	 */

	if ((range_type(&wm->left.pool_range) == &ipv4_info ||
		range_type(&wm->left.pool_range) == &ipv6_info)	&&
		range_is_specified(&wm->left.pool_range)) {
		/* there is address pool range add to the global list */
		c->pool = install_addresspool(&wm->left.pool_range);
		c->spd.that.modecfg_server = TRUE;
		c->spd.this.modecfg_client = TRUE;
	}
	if ((range_type(&wm->right.pool_range) == &ipv4_info ||
		range_type(&wm->right.pool_range) == &ipv6_info) &&
		range_is_specified(&wm->right.pool_range)) {
		/* there is address pool range add to the global list */
		c->pool = install_addresspool(&wm->right.pool_range);
		c->spd.that.modecfg_client = TRUE;
		c->spd.this.modecfg_server = TRUE;
	}

	if (c->spd.this.xauth_server || c->spd.that.xauth_server)
		c->policy |= POLICY_XAUTH;

	update_ends_from_this_host_addr(&c->spd.this, &c->spd.that);
	update_ends_from_this_host_addr(&c->spd.that, &c->spd.this);

	/*
	 * If both left/rightauth is unset, fill it in with (preferred) symmetric policy
	 */
	if (wm->left.authby == AUTHBY_UNSET && wm->right.authby == AUTHBY_UNSET) {
		if (c->policy & POLICY_RSASIG)
			c->spd.this.authby = c->spd.that.authby = AUTHBY_RSASIG;
		else if (c->policy & POLICY_ECDSA)
			c->spd.this.authby = c->spd.that.authby = AUTHBY_ECDSA;
		else if (c->policy & POLICY_PSK)
			c->spd.this.authby = c->spd.that.authby = AUTHBY_PSK;
		else if (c->policy & POLICY_AUTH_NULL)
			c->spd.this.authby = c->spd.that.authby = AUTHBY_NULL;
	}

	/* if left/rightauth are set, but symmetric policy is not, fill it in */
	if (wm->left.authby == wm->right.authby) {
		switch (wm->left.authby) {
		case AUTHBY_RSASIG:
			c->policy |= POLICY_RSASIG;
			break;
		case AUTHBY_ECDSA:
			c->policy |= POLICY_ECDSA;
			break;
		case AUTHBY_PSK:
			c->policy |= POLICY_PSK;
			break;
		case AUTHBY_NULL:
			c->policy |= POLICY_AUTH_NULL;
			break;
		default:
			break;
		}
	}

	/*
	 * force any wildcard host IP address, any wildcard subnet
	 * or any wildcard ID to _that_ end
	 */
	if (isanyaddr(&c->spd.this.host_addr) ||
	    c->spd.this.has_port_wildcard ||
	    c->spd.this.has_id_wildcards) {
		struct end t = c->spd.this;

		c->spd.this = c->spd.that;
		c->spd.that = t;
	}

	c->spd.spd_next = NULL;

	/*
	 * XXX: Install the connection.  Yes right in the middle of
	 * the struct being constructed!  Why?  Because that's the way
	 * it's always been done.
	 */
	c->ac_next = connections;
	connections = c;

	/* set internal fields */
	c->instance_serial = 0;
	c->interface = NULL;
	c->spd.routing = RT_UNROUTED;
	c->newest_isakmp_sa = SOS_NOBODY;
	c->newest_ipsec_sa = SOS_NOBODY;
	c->spd.eroute_owner = SOS_NOBODY;
	c->temp_vars.num_redirects = 0;
	/*
	 * is spd.reqid necessary for all c? CK_INSTANCE or CK_PERMANENT
	 * need one. Does CK_TEMPLATE need one?
	 */
	c->spd.reqid = c->sa_reqid == 0 ? gen_reqid() : c->sa_reqid;

	/* force all oppo connections to have a client */
	if (c->policy & POLICY_OPPORTUNISTIC) {
		c->spd.that.has_client = TRUE;
		c->spd.that.client.maskbits = 0; /* ??? shouldn't this be 32 for v4? */
		/*
		 * We cannot have unlimited keyingtries for Opportunistic, or else
		 * we gain infinite partial IKE SA's. But also, more than one makes
		 * no sense, since it will be installing a failureshunt (not
		 * negotiationshunt) on the 2nd keyingtry, and try to re-install another
		 * negotiation or failure shunt
		 */
		if (c->sa_keying_tries == 0) {
			c->sa_keying_tries = 1;
			log_message(RC_LOG, logger,
				    "the connection is Opportunistic, but used keyingtries=0. The specified value was changed to 1");
		}
	}

	if (c->policy & POLICY_GROUP) {
		c->kind = CK_GROUP;
		add_group(c);
	} else if ((isanyaddr(&c->spd.that.host_addr) &&
			!NEVER_NEGOTIATE(c->policy)) ||
		c->spd.that.has_port_wildcard ||
		((c->policy & POLICY_SHUNT_MASK) == POLICY_SHUNT_TRAP &&
			c->spd.that.has_id_wildcards )) {
		dbg("based upon policy, the connection is a template.");

		/*
		 * Opportunistic or Road Warrior or wildcard client
		 * subnet
		 * or wildcard ID
		 */
		c->kind = CK_TEMPLATE;
	} else if (wm->left.virt != NULL || wm->right.virt != NULL) {
		/*
		 * If we have a subnet=vnet: needing instantiation
		 * so we can accept multiple subnets from
		 * the remote peer.
		 */
		c->kind = CK_TEMPLATE;
	} else if (c->policy & POLICY_IKEV2_ALLOW_NARROWING) {
		dbg("based upon policy narrowing=yes, the connection is a template.");
		c->kind = CK_TEMPLATE;
	} else {
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
		 * passert(isanyaddr(&c->spd.that.host_addr));
		 */
		passert(c->spd.that.virt == NULL);
		c->spd.that.virt = create_virtual(wm->left.virt != NULL ?
						  wm->left.virt :
						  wm->right.virt,
						  logger);
		if (c->spd.that.virt != NULL)
			c->spd.that.has_client = TRUE;
	}

	if (c->pool !=  NULL)
		reference_addresspool(c);

	(void)orient(c);

	connect_to_host_pair(c);
	/* non configurable */
	c->ike_window = IKE_V2_OVERLAPPING_WINDOW_SIZE;
	return true;
}

/* slightly different names compared to pluto_constants.c */
static const char *const policy_shunt_names[4] = {
	"trap[should not happen]",
	"passthrough",
	"drop",
	"reject",
};

void add_connection(struct fd *whackfd, const struct whack_message *wm)
{
	struct logger *logger = string_logger(whackfd, HERE,
					      "connection \"%s\": ", wm->name); /*must-free*/
	struct connection *c = alloc_connection(wm->name, HERE);
	if (extract_connection(wm, c, logger)) {
		/* log all about this connection */
		libreswan_log("added %s connection \"%s\"",
		NEVER_NEGOTIATE(c->policy) ?
			policy_shunt_names[(c->policy & POLICY_SHUNT_MASK) >> POLICY_SHUNT_SHIFT] :
			LIN(POLICY_IKEV2_ALLOW, c->policy) ? "IKEv2" : "IKEv1",	 c->name);
		dbg("ike_life: %jd; ipsec_life: %jds; rekey_margin: %jds; rekey_fuzz: %lu%%; keyingtries: %lu; replay_window: %u; policy: %s%s",
		    deltasecs(c->sa_ike_life_seconds),
		    deltasecs(c->sa_ipsec_life_seconds),
		    deltasecs(c->sa_rekey_margin),
		    c->sa_rekey_fuzz,
		    c->sa_keying_tries,
		    c->sa_replay_window,
		    prettypolicy(c->policy),
		    NEVER_NEGOTIATE(c->policy) ? "+NEVER_NEGOTIATE" : "");
		char topo[CONN_BUF_LEN];
		dbg("%s", format_connection(topo, sizeof(topo), c, &c->spd));
	} else {
		/*
		 * Don't log here - it's assumed that
		 * extract_connection() has already displayed an
		 * RC_FATAL log message.
		 */
		discard_connection(c, false/*not-valid*/, logger);
	}
	free_logger(&logger, HERE);
}

/*
 * Derive a template connection from a group connection and target.
 * Similar to instantiate().  Happens at whack --listen.
 * Returns name of new connection.  NULL on failure (duplicated name).
 * Caller is responsible for pfreeing name.
 */
struct connection *add_group_instance(struct fd *whackfd,
				      struct connection *group, const ip_subnet *target,
				      uint8_t proto , uint16_t sport , uint16_t dport)
{
	passert(group->kind == CK_GROUP);
	passert(oriented(*group));

	/*
	 * Manufacture a unique name for this template.
	 */
	char *namebuf; /* must free */

	subnet_buf targetbuf;
	str_subnet(target, &targetbuf);

	if (proto == 0) {
		namebuf = alloc_printf("%s#%s", group->name, targetbuf.buf);
	} else {
		namebuf = alloc_printf("%s#%s-(%d--%d--%d)", group->name,
				       targetbuf.buf, sport, proto, dport);
	}

	if (conn_by_name(namebuf, false/*!strict*/) != NULL) {
		log_connection(RC_DUPNAME, whackfd, group,
			       "group name + target yields duplicate name \"%s\"",
			       namebuf);
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

	unshare_connection(t);
	passert(t->foodgroup != t->name); /* XXX: see DANGER above */

	t->spd.that.client = *target;
	if (proto != 0) {
		/* if foodgroup entry specifies protoport, override protoport= settings */
		t->spd.this.protocol = proto;
		t->spd.that.protocol = proto;
		t->spd.this.port = sport;
		t->spd.that.port = dport;
	}
	t->policy &= ~(POLICY_GROUP | POLICY_GROUTED);
	t->policy |= POLICY_GROUPINSTANCE; /* mark as group instance for later */
	t->kind = isanyaddr(&t->spd.that.host_addr) &&
		!NEVER_NEGOTIATE(t->policy) ?
		CK_TEMPLATE : CK_INSTANCE;

	/* reset log file info */
	t->log_file_name = NULL;
	t->log_file = NULL;
	t->log_file_err = FALSE;

	t->spd.reqid = group->sa_reqid == 0 ?
		gen_reqid() : group->sa_reqid;

	/* add to connections list */
	t->ac_next = connections;
	connections = t;

	/* same host_pair as parent: stick after parent on list */
	/* t->hp_next = group->hp_next; */	/* done by clone_thing */
	group->hp_next = t;

	/* route if group is routed */
	if (group->policy & POLICY_GROUTED) {
		if (!trap_connection(t, whackfd))
			whack_log(RC_ROUTE, whackfd,
				  "could not route");
	}
	return t;
}

/* An old target has disappeared for a group: delete instance. */
void remove_group_instance(const struct connection *group,
			const char *name)
{
	struct fd *whackfd = whack_log_fd; /* placeholder */
	passert(group->kind == CK_GROUP);

	delete_connections_by_name(name, false, whackfd);
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
			       const struct id *peer_id)
{
	passert(c->kind == CK_TEMPLATE);
	passert(c->spd.spd_next == NULL);

	c->instance_serial++;
	struct connection *d = clone_connection(c->name, c, HERE);
	passert(c->name != d->name); /* see clone_connection() */
	if (peer_id != NULL) {
		int wildcards;	/* value ignored */

		passert(d->spd.that.id.kind == ID_FROMCERT || match_id(peer_id, &d->spd.that.id, &wildcards));
		d->spd.that.id = *peer_id;
		d->spd.that.has_id_wildcards = FALSE;
	}
	unshare_connection(d);

	d->kind = CK_INSTANCE;

	passert(oriented(*d));
	if (peer_addr != NULL) {
		d->spd.that.host_addr = *peer_addr;
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

	/* since both ends updated; presumably already oriented? */
	set_policy_prio(d);

	/* set internal fields */
	d->ac_next = connections;
	connections = d;
	d->spd.routing = RT_UNROUTED;
	d->newest_isakmp_sa = SOS_NOBODY;
	d->newest_ipsec_sa = SOS_NOBODY;
	d->spd.eroute_owner = SOS_NOBODY;

	/* reset log file info */
	d->log_file_name = NULL;
	d->log_file = NULL;
	d->log_file_err = FALSE;

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

	return d;
}

struct connection *rw_instantiate(struct connection *c,
				  const ip_address *peer_addr,
				  const ip_subnet *peer_subnet,
				  const struct id *peer_id)
{
	struct connection *d = instantiate(c, peer_addr, peer_id);

	if (peer_subnet != NULL && is_virtual_connection(c)) {
		d->spd.that.client = *peer_subnet;
		if (subnetishost(peer_subnet) && addrinsubnet(peer_addr, peer_subnet))
			d->spd.that.has_client = FALSE;
	}

	if (d->policy & POLICY_OPPORTUNISTIC) {
		/*
		 * This must be before we know the client addresses.
		 * Fill in one that is impossible. This prevents anyone else
		 * from trying to use this connection to get to a particular
		 * client
		 */
		d->spd.that.client = subnet_type(&d->spd.that.client)->no_addresses;
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
				    const ip_subnet *client, const ip_address *gw)
{
	size_t s = 0;
	if (subnetisaddr(client, gw)) {
		/* compact denotation for "self" */
	} else {
		s += jam_string(b, prefix);
		if (subnet_contains_no_addresses(client)) {
			s += jam_string(b, "?"); /* unknown */
		} else {
			s += jam_subnet(b, client);
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
					   &c->spd.this.client,
					   &c->spd.this.host_addr);
		s += jam_string(buf, " ...");
		s += jam_address(buf, &c->spd.that.host_addr);
		s += jam_connection_client(buf, "===", "",
					   &c->spd.that.client,
					   &c->spd.that.host_addr);
	} else {
		s += jam_string(buf, " ");
		s += jam_address_sensitive(buf, &c->spd.that.host_addr);
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

/*
 * This function is called using the convention:
 *
 *    printf("\"%s\"%s", c->name, fmt_conn_instance(c, &buf));
 *
 * The CK_INSTANCE check is so it returns "" when false.
 */
char *fmt_conn_instance(const struct connection *c, char buf[CONN_INST_BUF])
{
	/* not sizeof(buf), as BUF is an address */
	struct jambuf p = array_as_jambuf(buf, CONN_INST_BUF);
	if (c->kind == CK_INSTANCE) {
		jam_connection_instance(&p, c);
	}
	return buf;
}

/*
 * Find an existing connection for a trapped outbound packet.
 * This is attempted before we bother with gateway discovery.
 *   + this connection is routed or instance_of_routed_template
 *     (i.e. approved for on-demand)
 *   + this subnet contains our_client (or we are our_client)
 *   + that subnet contains peer_client (or peer is peer_client)
 *   + don't care about Phase 1 IDs (we don't know)
 * Note: result may still need to be instantiated.
 * The winner has the highest policy priority.
 *
 * If there are several with that priority, we give preference to
 * the first one that is an instance.
 *
 * See also build_outgoing_opportunistic_connection.
 */
struct connection *find_connection_for_clients(struct spd_route **srp,
					const ip_address *our_client,
					const ip_address *peer_client,
					int transport_proto)
{
	int our_port = ntohs(portof(our_client));
	int peer_port = ntohs(portof(peer_client));

	struct connection *best = NULL;
	policy_prio_t best_prio = BOTTOM_PRIO;
	struct spd_route *best_sr = NULL;

	passert(endpoint_is_specified(our_client));
	passert(endpoint_is_specified(peer_client));

	address_buf a, b;
	dbg("find_connection: looking for policy for connection: %s:%d/%d -> %s:%d/%d",
	    str_address(our_client, &a),
	    transport_proto, our_port,
	    str_address(peer_client, &b),
	    transport_proto, peer_port);

	struct connection *c;

	dbg("FOR_EACH_CONNECTION_... in %s", __func__);
	for (c = connections; c != NULL; c = c->ac_next) {
		if (c->kind == CK_GROUP)
			continue;

		struct spd_route *sr;

		for (sr = &c->spd; best != c && sr; sr = sr->spd_next) {
			if ((routed(sr->routing) ||
					c->instance_initiation_ok) &&
				addrinsubnet(our_client, &sr->this.client) &&
				addrinsubnet(peer_client, &sr->that.client) &&
				(sr->this.protocol == 0 ||
					transport_proto == sr->this.protocol) &&
				(sr->this.port == 0 ||
					our_port == sr->this.port) &&
				(sr->that.port == 0 ||
					peer_port == sr->that.port))
			{
				policy_prio_t prio =
					8 * (c->policy_prio +
					     (c->kind == CK_INSTANCE)) +
					2 * (sr->this.port == our_port) +
					2 * (sr->that.port == peer_port) +
					1 * (sr->this.protocol == transport_proto);

				if (DBGP(DBG_BASE)) {
					connection_buf cib;
					selector_buf c_ocb;
					selector_buf c_pcb;
					DBG_log("find_connection: conn "PRI_CONNECTION" has compatible peers: %s -> %s [pri: %" PRIu32 "]",
						pri_connection(c, &cib),
						str_selector(&c->spd.this.client, &c_ocb),
						str_selector(&c->spd.that.client, &c_pcb),
						prio);

					if (best == NULL) {
						connection_buf cib2;
						DBG_log("find_connection: first OK "PRI_CONNECTION" [pri:%" PRIu32 "]{%p} (child %s)",
							pri_connection(c, &cib2),
							prio, c,
							c->policy_next ?
								c->policy_next->name :
								"none");
					} else {
						connection_buf cib;
						connection_buf cib2;
						DBG_log("find_connection: comparing best "PRI_CONNECTION" [pri:%" PRIu32 "]{%p} (child %s) to "PRI_CONNECTION" [pri:%" PRIu32 "]{%p} (child %s)",
							pri_connection(best, &cib),
							best_prio,
							best,
							best->policy_next ?
								best->policy_next->name :
								"none",
							pri_connection(c, &cib2),
							prio, c,
							c->policy_next ?
								c->policy_next->name :
								"none");
					}
				}

				if (best == NULL || prio > best_prio) {
					best = c;
					best_sr = sr;
					best_prio = prio;
				}
			}
		}
	}

	if (best != NULL && NEVER_NEGOTIATE(best->policy))
		best = NULL;

	if (srp != NULL && best != NULL)
		*srp = best_sr;

	if (DBGP(DBG_BASE)) {
		if (best != NULL) {
			connection_buf cib;
			DBG_log("find_connection: concluding with "PRI_CONNECTION" [pri:%" PRIu32 "]{%p} kind=%s",
				pri_connection(best, &cib),
				best_prio, best,
				enum_name(&connection_kind_names, best->kind));
		} else {
			DBG_log("find_connection: concluding with empty");
		}
	}

	return best;
}

struct connection *oppo_instantiate(struct connection *c,
				    const ip_address *peer_addr,
				    const struct id *peer_id,
				    const ip_address *our_client,
				    const ip_address *peer_client)
{
	struct connection *d = instantiate(c, peer_addr, peer_id);

	dbg("oppo instantiate d=\"%s\" from c=\"%s\" with c->routing %s, d->routing %s",
	    d->name, c->name,
	    enum_name(&routing_story, c->spd.routing),
	    enum_name(&routing_story, d->spd.routing));
	if (DBGP(DBG_BASE)) {
		char instbuf[512];
		DBG_log("new oppo instance: %s",
			format_connection(instbuf, sizeof(instbuf), d, &d->spd));
	}

	passert(d->spd.spd_next == NULL);

	/* fill in our client side */
	if (d->spd.this.has_client) {
		/*
		 * There was a client in the abstract connection so we demand
		 * that the required client is within that subnet, * or that
		 * it is our private ip in case we are behind a port forward
		 */
		passert(addrinsubnet(our_client, &d->spd.this.client) || sameaddr(our_client, &d->spd.this.host_addr));

		/* opportunistic connections do not use port selectors */
		if (addrinsubnet(our_client, &d->spd.this.client)) {
			d->spd.this.client = selector_from_address(our_client, &unset_protoport/*all*/);
		} else {
			update_selector_hport(&d->spd.this.client, 0);
		}
	} else {
		/*
		 * There was no client in the abstract connection
		 * so we demand that the required client be the host.
		 */
		passert(sameaddr(our_client, &d->spd.this.host_addr));
	}

	/*
	 * Fill in peer's client side.
	 * If the client is the peer, excise the client from the connection.
	 */
	passert(d->policy & POLICY_OPPORTUNISTIC);
	passert(addrinsubnet(peer_client, &d->spd.that.client));
	happy(endtosubnet(peer_client, &d->spd.that.client, HERE));

	/* opportunistic connections do not use port selectors */
	setportof(0, &d->spd.that.client.addr);

	if (sameaddr(peer_client, &d->spd.that.host_addr))
		d->spd.that.has_client = FALSE;

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
		d->instance_initiation_ok = TRUE;

	if (DBGP(DBG_BASE)) {
		char topo[CONN_BUF_LEN];
		connection_buf inst;
		DBG_log("oppo_instantiate() instantiated "PRI_CONNECTION": %s",
			pri_connection(d, &inst),
			format_connection(topo, sizeof(topo), d, &d->spd));
	}
	return d;
}

/*
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
struct connection *build_outgoing_opportunistic_connection(const ip_address *our_client,
							   const ip_address *peer_client,
							   const int transport_proto)
{
	struct connection *best = NULL;
	struct spd_route *bestsr = NULL;	/* initialization not necessary */
	int our_port, peer_port;

	passert(endpoint_is_specified(our_client));
	passert(endpoint_is_specified(peer_client));

	our_port = endpoint_hport(our_client);
	peer_port = endpoint_hport(peer_client);

	struct iface_port *p;

	struct connection *c = NULL;

	for (p = interfaces; p != NULL; p = p->next) {
		/*
		 * Go through those connections with our address and NO_IP as
		 * hosts.
		 * We cannot know what port the peer would use, so we assume
		 * that it is pluto_port (makes debugging easier).
		 */
		c = find_host_pair_connections(&p->local_endpoint, NULL);

		for (; c != NULL; c = c->hp_next) {
			dbg("checking %s", c->name);
			if (c->kind == CK_GROUP)
				continue;

			struct spd_route *sr;

			/* for each sr of c, see if we have a new best */
			/* Paul: while this code can reject unmatched conns, it does not find the most narrow match! */
			for (sr = &c->spd; sr != NULL; sr = sr->spd_next) {
				if (!routed(sr->routing) ||
				    !addrinsubnet(our_client, &sr->this.client) ||
				    !addrinsubnet(peer_client, &sr->that.client) ||
				    ((sr->this.protocol != 0) && transport_proto != 0 && sr->this.protocol != transport_proto) ||
				    ((sr->this.protocol != 0) && sr->that.port != 0 && peer_port != sr->that.port) ||
				    ((sr->this.protocol != 0) && sr->this.port != 0 && our_port != sr->this.port)
				   )
				{
					/*  sr does not work for these clients */
				} else if (best == NULL ||
					   !subnetinsubnet(&bestsr->this.client, &sr->this.client) ||
					   (samesubnet(&bestsr->this.client, &sr->this.client) &&
					    !subnetinsubnet(&bestsr->that.client, &sr->that.client)))
				{
					/*
					 * First or better solution.
					 *
					 * The test for better (see above) is:
					 *   sr's this is narrower, or
					 *   sr's this is same and sr's that is narrower.
					 * ??? not elegant, not symmetric.
					 * Possible replacement test:
					 *   bestsr->this.client.maskbits + bestsr->that.client.maskbits >
					 *   sr->this.client.maskbits + sr->that.client.maskbits
					 * but this knows too much about the representation of ip_subnet.
					 * What is the correct semantics?
					 */
					best = c;
					bestsr = sr;
				}
			}
		}
	}

	if (best == NULL ||
		NEVER_NEGOTIATE(best->policy) ||
		(best->policy & POLICY_OPPORTUNISTIC) == LEMPTY ||
		best->kind != CK_TEMPLATE)
	{
		return NULL;
	} else {
		/* XXX we might not yet know the ID! */
		ip_address peer_addr = endpoint_address(peer_client);
		return oppo_instantiate(best, &peer_addr, NULL,
					our_client, peer_client);
	}
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
	if (!oriented(*c)) {
		libreswan_log("route_owner: connection no longer oriented - system interface change?");
		return NULL;
	}

	struct connection
		*best_ro = c,
		*best_ero = c;
	struct spd_route *best_sr = NULL,
		*best_esr = NULL;
	enum routing_t best_routing = cur_spd->routing,
		best_erouting = best_routing;

	dbg("FOR_EACH_CONNECTION_... in %s", __func__);
	for (struct connection *d = connections; d != NULL; d = d->ac_next) {
		if (!oriented(*d))
			continue;

		/*
		 * consider policies different if the either in or out marks
		 * differ (after masking)
		 */
		if (DBGP(DBG_BASE)) {
			DBG_log(" conn %s mark %" PRIu32 "/%#08" PRIx32 ", %" PRIu32 "/%#08" PRIx32 " vs",
				c->name, c->sa_marks.in.val, c->sa_marks.in.mask,
				c->sa_marks.out.val, c->sa_marks.out.mask);
			DBG_log(" conn %s mark %" PRIu32 "/%#08" PRIx32 ", %" PRIu32 "/%#08" PRIx32,
				d->name, d->sa_marks.in.val, d->sa_marks.in.mask,
				d->sa_marks.out.val, d->sa_marks.out.mask);
		}

		if ( (c->sa_marks.in.val & c->sa_marks.in.mask) != (d->sa_marks.in.val & d->sa_marks.in.mask) ||
		     (c->sa_marks.out.val & c->sa_marks.out.mask) != (d->sa_marks.out.val & d->sa_marks.out.mask) )
			continue;

		struct spd_route *srd;

		for (srd = &d->spd; srd != NULL; srd = srd->spd_next) {
			if (srd->routing == RT_UNROUTED)
				continue;

			const struct spd_route *src;

			for (src = &c->spd; src != NULL; src = src->spd_next) {
				if (src == srd)
					continue;

				if (!samesubnet(&src->that.client,
						&srd->that.client) ||
				    src->that.protocol != srd->that.protocol ||
				    src->that.port != srd->that.port ||
				    !sameaddr(&src->this.host_addr,
						&srd->this.host_addr))
					continue;

				if (srd->routing > best_routing) {
					best_ro = d;
					best_sr = srd;
					best_routing = srd->routing;
				}

				if (samesubnet(&src->this.client,
						&srd->this.client) &&
				    src->this.protocol == srd->this.protocol &&
				    src->this.port == srd->this.port &&
				    srd->routing > best_erouting)
				{
					best_ero = d;
					best_esr = srd;
					best_erouting = srd->routing;
				}
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
		} else if (best_ro == c) {
			jam(buf, "self");
		} else {
			connection_buf cib;
			jam(buf, ""PRI_CONNECTION" %s",
			    pri_connection(best_ro, &cib),
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
		*srp = best_sr;
		if (esrp != NULL )
			*esrp = best_esr;
	}

	return routed(best_routing) ? best_ro : NULL;
}

/*
 * Extracts the peer's ca from the chained list of public keys.
 */
static chunk_t get_peer_ca(struct pubkey_list *const *pubkey_db,
			   const struct id *peer_id)
{
	struct pubkey_list *p;

	for (p = *pubkey_db; p != NULL; p = p->next) {
		struct pubkey *key = p->key;
		if (key->type == &pubkey_type_rsa && same_id(peer_id, &key->id))
			return key->issuer;
	}
	return EMPTY_CHUNK;
}

/*
 * ??? NOTE: THESE IMPORTANT COMMENTS DO NOT REFLECT ANY CHANGES MADE AFTER FreeS/WAN.
 *
 * Given an up-until-now satisfactory connection, find the best connection
 * now that we just got the Phase 1 Id Payload from the peer.
 *
 * Comments in the code describe the (tricky!) matching criteria.
 * Although this routine could handle the initiator case,
 * it isn't currently called in this case.
 * If it were, it could "upgrade" an Opportunistic Connection
 * to a Road Warrior Connection if a suitable Peer ID were found.
 *
 * In RFC 2409 "The Internet Key Exchange (IKE)",
 * in 5.1 "IKE Phase 1 Authenticated With Signatures", describing Main
 * Mode:
 *
 *         Initiator                          Responder
 *        -----------                        -----------
 *         HDR, SA                     -->
 *                                     <--    HDR, SA
 *         HDR, KE, Ni                 -->
 *                                     <--    HDR, KE, Nr
 *         HDR*, IDii, [ CERT, ] SIG_I -->
 *                                     <--    HDR*, IDir, [ CERT, ] SIG_R
 *
 * In 5.4 "Phase 1 Authenticated With a Pre-Shared Key":
 *
 *               HDR, SA             -->
 *                                   <--    HDR, SA
 *               HDR, KE, Ni         -->
 *                                   <--    HDR, KE, Nr
 *               HDR*, IDii, HASH_I  -->
 *                                   <--    HDR*, IDir, HASH_R
 *
 * refine_host_connection could be called in two case:
 *
 * - the Responder receives the IDii payload:
 *   + [PSK] after using PSK to decode this message
 *   + before sending its IDir payload
 *   + before using its ID in HASH_R computation
 *   + [DSig] before using its private key to sign SIG_R
 *   + before using the Initiator's ID in HASH_I calculation
 *   + [DSig] before using the Initiator's public key to check SIG_I
 *
 * - the Initiator receives the IDir payload:
 *   + [PSK] after using PSK to encode previous message and decode this message
 *   + after sending its IDii payload
 *   + after using its ID in HASH_I computation
 *   + [DSig] after using its private key to sign SIG_I
 *   + before using the Responder's ID to compute HASH_R
 *   + [DSig] before using Responder's public key to check SIG_R
 *
 * refine_host_connection can choose a different connection, as long as
 * nothing already used is changed.
 *
 * In the Initiator case, the particular connection might have been
 * specified by whatever provoked Pluto to initiate.  For example:
 *	whack --initiate connection-name
 * The advantages of switching connections when we're the Initiator seem
 * less important than the disadvantages, so after FreeS/WAN 1.9, we
 * don't do this.
 */
struct connection *refine_host_connection(const struct state *st,
					const struct id *peer_id,
					const struct id *tarzan_id,
					bool initiator,
					lset_t auth_policy /* used by ikev1 */,
					enum keyword_authby this_authby /* used by ikev2 */,
					bool *fromcert)
{
	struct connection *c = st->st_connection;
	const generalName_t *requested_ca = st->st_requested_ca;
	/* Ensure the caller and we know the IKE version we are looking for */
	bool ikev1 = auth_policy != LEMPTY;
	bool ikev2 = this_authby != AUTHBY_UNSET;

	*fromcert = FALSE;

	passert(ikev1 != ikev2 && ikev2 == (st->st_ike_version == IKEv2));
	passert(this_authby != AUTHBY_NEVER);

	/*
	 * Translate the IKEv1 policy onto an IKEv2 policy.
	 * Saves duplicating the checks for v1 and v2, and the
	 * v1 policy is a subset of the v2 policy. Use the ikev2
	 * bool for IKEv2-only feature checks.
	 */
	if (ikev1) {
		/* ??? are these cases mutually exclusive? */
		if (LIN(POLICY_RSASIG, auth_policy))
			this_authby = AUTHBY_RSASIG;
		if (LIN(POLICY_PSK, auth_policy))
			this_authby = AUTHBY_PSK;
		passert(this_authby != AUTHBY_UNSET);
	}
	/* from here on, auth_policy must only be used to check POLICY_AGGRESSIVE */

	connection_buf cib;
	dbg("refine_host_connection for %s: starting with "PRI_CONNECTION"",
	    enum_name(&ike_version_names, st->st_ike_version),
	    pri_connection(c, &cib));

	/*
	 * Find the PEER's CA, check the per-state DB first.
	 */
	pexpect(st->st_remote_certs.processed);
	chunk_t peer_ca = get_peer_ca(&st->st_remote_certs.pubkey_db, peer_id);

	if (hunk_isempty(peer_ca)) {
		peer_ca = get_peer_ca(&pluto_pubkeys, peer_id);
	}

	{
		int opl;
		int ppl;

		if (same_id(&c->spd.that.id, peer_id) &&
		    peer_ca.ptr != NULL &&
		    trusted_ca_nss(peer_ca, c->spd.that.ca, &ppl) &&
		    ppl == 0 &&
		    match_requested_ca(requested_ca, c->spd.this.ca, &opl) &&
		    opl == 0) {

			connection_buf cib;
			dbg("refine_host_connection: happy with starting point: "PRI_CONNECTION"",
			    pri_connection(c, &cib));

			/* peer ID matches current connection -- check for "you Tarzan, me Jane" */
			if (!initiator && tarzan_id != NULL) {
				/* ??? pexpect(c->spd.spd_next == NULL); */
				if (idr_wildmatch(&c->spd.this, tarzan_id, st->st_logger)) {
					dbg("the remote specified our ID in its IDr payload");
					return c;
				} else {
					dbg("the remote specified an IDr that is not our ID for this connection");
				}
			} else {
				dbg("the remote did not specify an IDr and our current connection is good enough");
				return c;
			}
		}
	}

	const chunk_t *psk = NULL;
	const struct RSA_private_key *my_RSA_pri = NULL;

	if (initiator)
	{
		switch (this_authby) {
		case AUTHBY_PSK:
			psk = get_connection_psk(c, st->st_logger);
			/*
			 * It should be virtually impossible to fail to find
			 * PSK: we just used it to decode the current message!
			 * Paul: only true for IKEv1
			 */
			if (psk == NULL) {
				loglog(RC_LOG_SERIOUS, "cannot find PSK");
				return c; /* cannot determine PSK, so not switching */
			}
			break;
		case AUTHBY_NULL:
			/* we know our AUTH_NULL key :) */
			break;

		case AUTHBY_RSASIG:
		{
			/*
			 * At this point, we've committed to our
			 * private key: we used it in our previous
			 * message.  Paul: only true for IKEv1
			 */
			const struct pubkey_type *type = &pubkey_type_rsa;
			if (get_connection_private_key(c, type, st->st_logger) == NULL) {
				loglog(RC_LOG_SERIOUS, "cannot find %s key", type->name);
				 /* cannot determine my private key, so not switching */
				return c;
			}
			break;
		}
#if 0
		case AUTHBY_ECDSA:
		{
			/*
			 * At this point, we've committed to our
			 * private key: we used it in our previous
			 * message.  Paul: only true for IKEv1
			 */
			const struct pubkey_type *type = &pubkey_type_ecdsa;
			if (get_connection_private_key(c, type) == NULL) {
				loglog(RC_LOG_SERIOUS, "cannot find %s key", type->name);
				 /* cannot determine my private key, so not switching */
				return c;
			}
			break;
		}
#endif
		default:
			/* don't die on bad_case(auth); */

			/* ??? why not dies?  How could this happen? */
			loglog(RC_LOG_SERIOUS, "refine_host_connection: unexpected auth policy (%s): only handling PSK, NULL or RSA",
				enum_name(&keyword_authby_names, this_authby));
			return c;
		}
	}

	/*
	 * The current connection won't do: search for one that will.
	 * First search for one with the same pair of hosts.
	 * If that fails, search for a suitable Road Warrior or Opportunistic
	 * connection (i.e. wildcard peer IP).
	 * We need to match:
	 * - peer_id (slightly complicated by instantiation)
	 * - if PSK auth, the key must not change (we used it to decode message)
	 * - policy-as-used must be acceptable to new connection
	 * - if initiator, also:
	 *   + our ID must not change (we sent it in previous message)
	 *   + our RSA key must not change (we used in in previous message)
	 */
	passert(c != NULL);

	struct connection *d = c->host_pair->connections;

	int best_our_pathlen = 0;
	int best_peer_pathlen = 0;
	struct connection *best_found = NULL;
	int best_wildcards = 0;

	/* wcip stands for: wildcard Peer IP? */
	for (bool wcpip = FALSE;; wcpip = TRUE) {
		for (; d != NULL; d = d->hp_next) {
			int wildcards;
			bool matching_peer_id = match_id(peer_id,
							&d->spd.that.id,
							&wildcards);

			int peer_pathlen;
			bool matching_peer_ca = trusted_ca_nss(peer_ca,
							d->spd.that.ca,
							&peer_pathlen);

			int our_pathlen;
			bool matching_requested_ca = match_requested_ca(requested_ca,
							d->spd.this.ca,
							&our_pathlen);

			if (DBGP(DBG_BASE)) {
				connection_buf b1, b2;
				DBG_log("refine_host_connection: checking "PRI_CONNECTION" against "PRI_CONNECTION", best=%s with match=%d(id=%d(%d)/ca=%d(%d)/reqca=%d(%d))",
					pri_connection(c, &b1), pri_connection(d, &b2),
					best_found != NULL ? best_found->name : "(none)",
					matching_peer_id && matching_peer_ca && matching_requested_ca,
					matching_peer_id, wildcards,
					matching_peer_ca, peer_pathlen,
					matching_requested_ca, our_pathlen);
				DBG_log("warning: not switching back to template of current instance");
			}

			/* 'You Tarzan, me Jane' check based on received IDr */
			if (!initiator && tarzan_id != NULL) {
				id_buf tzb;
				dbg("peer expects us to be %s (%s) according to its IDr payload",
				    str_id(tarzan_id, &tzb),
				    enum_show(&ike_idtype_names, tarzan_id->kind));
				id_buf usb;
				dbg("this connection's local id is %s (%s)",
				    str_id(&d->spd.this.id, &usb),
				    enum_show(&ike_idtype_names, d->spd.this.id.kind));
				/* ??? pexpect(d->spd.spd_next == NULL); */
				if (!idr_wildmatch(&d->spd.this, tarzan_id, st->st_logger)) {
					dbg("peer IDr payload does not match our expected ID, this connection will not do");
					continue;
				}
			} else {
				dbg("no IDr payload received from peer");
			}

			/* ignore group connections */
			if (d->policy & POLICY_GROUP) {
				dbg("skipping group connection");
				continue;
			}

			/* matching_peer_ca and matching_requested_ca are required */
			if (!matching_peer_ca || !matching_requested_ca) {
				dbg("skipping !match2 || !match3");
				continue;
			}
			/*
			 * Check if peer_id matches, exactly or after
			 * instantiation.
			 * Check for the match but also check to see if it's
			 * the %fromcert + peer id match result. - matt
			 */
			bool d_fromcert = FALSE;
			if (!matching_peer_id) {
				d_fromcert = d->spd.that.id.kind == ID_FROMCERT;
				if (!d_fromcert) {
					dbg("skipping because peer_id does not match");
					continue;
				}
			}

			/* if initiator, our ID must match exactly */
			if (initiator &&
				!same_id(&c->spd.this.id, &d->spd.this.id)) {
					dbg("skipping because initiator id does not match");
					continue;
			}

			if (d->ike_version != st->st_ike_version) {
				/* IKE version has to match */
				dbg("skipping because mismatching IKE version");
				continue;
			}

			/*
			 * Authentication used must fit policy of this
			 * connection.
			 */
			if (ikev1) {
				if ((auth_policy ^ d->policy) & POLICY_AGGRESSIVE)
					continue;	/* differ about aggressive mode */

				if ((d->policy & auth_policy & ~POLICY_AGGRESSIVE) == LEMPTY) {
					/* Our auth isn't OK for this connection. */
					dbg("skipping because AUTH isn't right");
					continue;
				}
			} else {
				/*
				 * We need to check if leftauth and rightauth match, but we only know
				 * what the remote end will send IKE_AUTH message..
				 * Note with IKEv2 we are guaranteed to be a RESPONDER
				 * this_authby is the received AUTH payload type in IKE_AUTH reply.
				 * This also means, we have already sent out AUTH payload, so we cannot
				 * switch away from previously used this.authby.
				 */
				pexpect(!initiator);
				if (this_authby != d->spd.that.authby) {
					dbg("skipping because mismatched authby");
					continue;
				}
				if (c->spd.this.authby != d->spd.this.authby) {
					dbg("skipping because mismatched this authby");
					continue;
				}
			}

			if (d->spd.this.xauth_server != c->spd.this.xauth_server) {
				/* Disallow IKEv2 CP or IKEv1 XAUTH mismatch */
				dbg("skipping because mismatched xauthserver");
				continue;
			}

			if (d->spd.this.xauth_client != c->spd.this.xauth_client) {
				/* Disallow IKEv2 CP or IKEv1 XAUTH mismatch */
				dbg("skipping because mismatched xauthclient");
				continue;
			}

			connection_buf b1, b2;
			dbg("refine_host_connection: checked "PRI_CONNECTION" against "PRI_CONNECTION", now for see if best",
			    pri_connection(c, &b1), pri_connection(d, &b2));

			if (this_authby == AUTHBY_PSK) {
				/* secret must match the one we already used */
				const chunk_t *dpsk = get_connection_psk(d, st->st_logger);

				/*
				 * We can change PSK mid-way in IKEv2 or aggressive mode.
				 * If we initiated, the key we used and the key
				 * we would have used with d must match.
				 */
				if (!((st->st_ike_version == IKEv2) || (auth_policy & POLICY_AGGRESSIVE))) {
					if (dpsk == NULL)
						continue; /* no secret */

					if (initiator &&
					    !(psk->len == dpsk->len &&
					      memeq(psk->ptr, dpsk->ptr, psk->len)))
					{
						continue; /* different secret */
					}
				}
			}

			if (this_authby == AUTHBY_RSASIG) {
				/*
				 * We must at least be able to find our private key.
				 * If we initiated, it must match the one we used in
				 * the IKEv1 SIG_I payload or IKEv2 AUTH payload that
				 * we sent previously.
				 */
				const struct pubkey_type *type = &pubkey_type_rsa;
				const struct private_key_stuff *pks = get_connection_private_key(d, type, st->st_logger);
				if (pks == NULL)
					continue;	/* no key */

				/* XXX: same_{RSA,ECDSA}_public_key()? */
				const struct RSA_private_key *pri = &pks->u.RSA_private_key;

				if (initiator &&
				    !same_RSA_public_key(&my_RSA_pri->pub, &pri->pub)) {
					dbg("skipping because mismatched pubkey");
					continue;	/* different key */
				}
			}

			/*
			 * Paul: We need to check all the other relevant
			 * policy bits, like compression, pfs, etc
			 */

			/*
			 * d has passed all the tests.
			 * We'll go with it if the Peer ID was an exact match.
			 */
			if (matching_peer_id && wildcards == 0 &&
			    peer_pathlen == 0 && our_pathlen == 0)
			{
				*fromcert = d_fromcert;
				dbg("returning because exact peer id match");
				return d;
			}

			/*
			 * If it was a non-exact (wildcard) match, we'll
			 * remember it as best_found in case an exact match
			 * doesn't come along.
			 * ??? the logic involving *_pathlen looks wrong.
			 * ??? which matters more peer_pathlen or our_pathlen minimization?
			 */
			if (best_found == NULL || wildcards < best_wildcards ||
				((wildcards == best_wildcards &&
				  peer_pathlen < best_peer_pathlen) ||
				 (peer_pathlen == best_peer_pathlen &&
				  our_pathlen < best_our_pathlen))) {
				char cib[CONN_INST_BUF];
				dbg("refine_host_connection: picking new best \"%s\"%s (wild=%d, peer_pathlen=%d/our=%d)",
					d->name,
					fmt_conn_instance(d, cib),
					wildcards, peer_pathlen,
					our_pathlen);
				*fromcert = d_fromcert;
				best_found = d;
				best_wildcards = wildcards;
				best_peer_pathlen = peer_pathlen;
				best_our_pathlen = our_pathlen;
			}
		}

		if (wcpip) {
			/* been around twice already */
			dbg("returning since no better match than original best_found");
			return best_found;
		}

		/*
		 * Starting second time around.
		 * We're willing to settle for a connection that needs Peer IP
		 * instantiated: Road Warrior or Opportunistic.
		 * Look on list of connections for host pair with wildcard
		 * Peer IP.
		 */
		dbg("refine going into 2nd loop allowing instantiated conns as well");
		d = find_host_pair_connections(&c->spd.this.host_addr, NULL);
	}
}

/*
 * With virtual addressing, we must not allow someone to use an already
 * used (by another id) addr/net.
 */
static bool is_virtual_net_used(struct connection *c,
				const ip_subnet *peer_net,
				const struct id *peer_id)
{
	dbg("FOR_EACH_CONNECTION_... in %s", __func__);
	for (struct connection *d = connections; d != NULL; d = d->ac_next) {
		switch (d->kind) {
		case CK_PERMANENT:
		case CK_TEMPLATE:
		case CK_INSTANCE:
			if ((subnetinsubnet(peer_net, &d->spd.that.client) ||
					subnetinsubnet(&d->spd.that.client,
						peer_net)) &&
				!same_id(&d->spd.that.id, peer_id))
			{
				id_buf idb;
				connection_buf cbuf;
				subnet_buf client;
				libreswan_log("Virtual IP %s overlaps with connection "PRI_CONNECTION" (kind=%s) '%s'",
					      str_subnet(peer_net, &client),
					      pri_connection(d, &cbuf),
					      enum_name(&connection_kind_names,
							d->kind),
					      str_id(&d->spd.that.id, &idb));

				if (!kernel_ops->overlap_supported) {
					libreswan_log(
						"Kernel method '%s' does not support overlapping IP ranges",
						kernel_ops->kern_name);
					return TRUE;
				}

				if (LIN(POLICY_OVERLAPIP, c->policy & d->policy)) {
					libreswan_log(
						"overlap is okay by mutual consent");

					/*
					 * Look for another overlap to report
					 * on.
					 */
					break;
				}

				/* We're not allowed to overlap.  Carefully report. */

				const struct connection *x =
					LIN(POLICY_OVERLAPIP, c->policy) ? d :
					LIN(POLICY_OVERLAPIP, d->policy) ? c :
					NULL;

				if (x == NULL) {
					libreswan_log(
						"overlap is forbidden (neither agrees to overlap)");
				} else {
					libreswan_log("overlap is forbidden ("PRI_CONNECTION" does not agree to overlap)",
						      pri_connection(x, &cbuf));
				}

				/* ??? why is this a separate log line? */
				libreswan_log("Your ID is '%s'", str_id(peer_id, &idb));

				return TRUE; /* already used by another one */
			}
			break;

		case CK_GOING_AWAY:
		default:
			break;
		}
	}
	return FALSE; /* you can safely use it */
}

/*
 * find_client_connection: given a connection suitable for ISAKMP
 * (i.e. the hosts match), find a one suitable for IPSEC
 * (i.e. with matching clients).
 *
 * If we don't find an exact match (not even our current connection),
 * we try for one that still needs instantiation.  Try Road Warrior
 * abstract connections and the Opportunistic abstract connections.
 * This requires inverse instantiation: abstraction.
 *
 * After failing to find an exact match, we abstract the peer
 * to be NO_IP (the wildcard value).  This enables matches with
 * Road Warrior and Opportunistic abstract connections.
 *
 * After failing that search, we also abstract the Phase 1 peer ID
 * if possible.  If the peer's ID was the peer's IP address, we make
 * it NO_ID; instantiation will make it the peer's IP address again.
 *
 * If searching for a Road Warrior abstract connection fails,
 * and conditions are suitable, we search for the best Opportunistic
 * abstract connection.
 *
 * Note: in the end, both Phase 1 IDs must be preserved, after any
 * instantiation.  They are the IDs that have been authenticated.
 */

#define PATH_WEIGHT 1
#define WILD_WEIGHT (MAX_CA_PATH_LEN + 1)
#define PRIO_WEIGHT ((MAX_WILDCARDS + 1) * WILD_WEIGHT)

/* fc_try: a helper function for find_client_connection */
static struct connection *fc_try(const struct connection *c,
				const struct host_pair *hp,
				const ip_subnet *our_net,
				const ip_subnet *peer_net,
				const uint8_t our_protocol,
				const uint16_t our_port,
				const uint8_t peer_protocol,
				const uint16_t peer_port)
{
	struct connection *best = NULL;
	policy_prio_t best_prio = BOTTOM_PRIO;
	const bool peer_net_is_host = subnetisaddr(peer_net,
						&c->spd.that.host_addr);
	err_t virtualwhy = NULL;

	struct connection *d;

	for (d = hp->connections; d != NULL; d = d->hp_next) {
		if (d->policy & POLICY_GROUP)
			continue;

		int wildcards, pathlen;

		if (!(same_id(&c->spd.this.id, &d->spd.this.id) &&
		      match_id(&c->spd.that.id, &d->spd.that.id, &wildcards) &&
		      trusted_ca_nss(c->spd.that.ca, d->spd.that.ca, &pathlen)))
		{
			continue;
		}

		/* compare protocol and ports */
		if (!(d->spd.this.protocol == our_protocol &&
		      d->spd.that.protocol == peer_protocol &&
		      (d->spd.this.port == 0 || d->spd.this.port == our_port) &&
		      (d->spd.that.has_port_wildcard || d->spd.that.port == peer_port)))
		{
			continue;
		}

		/*
		 * non-Opportunistic case:
		 * our_client must match.
		 *
		 * So must peer_client, but the testing is complicated
		 * by the fact that the peer might be a wildcard
		 * and if so, the default value of that.client
		 * won't match the default peer_net. The appropriate test:
		 *
		 * If d has a peer client, it must match peer_net.
		 * If d has no peer client, peer_net must just have peer itself.
		 */

		const struct spd_route *sr;

		for (sr = &d->spd; best != d && sr != NULL; sr = sr->spd_next) {
			if (DBGP(DBG_BASE)) {
				selector_buf s1, d1;
				selector_buf s3, d3;
				DBG_log("  fc_try trying %s:%s:%d/%d -> %s:%d/%d%s vs %s:%s:%d/%d -> %s:%d/%d%s",
					c->name, str_selector(our_net, &s1),
					c->spd.this.protocol, c->spd.this.port,
					str_selector(peer_net, &d1),
					c->spd.that.protocol, c->spd.that.port,
					is_virtual_connection(c) ?
					"(virt)" : "", d->name,
					str_selector(&sr->this.client, &s3),
					sr->this.protocol, sr->this.port,
					str_selector(&sr->that.client, &d3),
					sr->that.protocol, sr->that.port,
					is_virtual_sr(sr) ? "(virt)" : "");
			}

			if (!samesubnet(&sr->this.client, our_net)) {
				if (DBGP(DBG_BASE)) {
					selector_buf s1, s3;
					DBG_log("   our client (%s) not in our_net (%s)",
						str_selector(&sr->this.client, &s3),
						str_selector(our_net, &s1));
				}

				continue;
			}

			if (sr->that.has_client) {
				if (!samesubnet(&sr->that.client, peer_net) &&
				    !is_virtual_sr(sr)) {
					if (DBGP(DBG_BASE)) {
						selector_buf d1, d3;
						DBG_log("   their client (%s) not in same peer_net (%s)",
							str_selector(&sr->that.client, &d3),
							str_selector(peer_net, &d1));
					}
					continue;
				}

				virtualwhy = check_virtual_net_allowed(
						d,
						peer_net,
						&sr->that.host_addr);

				if (is_virtual_sr(sr) &&
				    (virtualwhy != NULL ||
				     is_virtual_net_used(
					d,
					peer_net,
					&sr->that.id)))
				{
					dbg("   virtual net not allowed");
					continue;
				}
			} else if (!peer_net_is_host) {
				continue;
			}

			/*
			 * We've run the gauntlet -- success:
			 * We've got an exact match of subnets.
			 * The connection is feasible, but we continue looking
			 * for the best.
			 * The highest priority wins, implementing eroute-like
			 * rule.
			 * - a routed connection is preferrred
			 * - given that, the smallest number of ID wildcards
			 *   are preferred
			 * - given that, the shortest CA pathlength is preferred
			 * - given that, not switching is preferred
			 */
			policy_prio_t prio =
				PRIO_WEIGHT * routed(sr->routing) +
				WILD_WEIGHT * (MAX_WILDCARDS - wildcards) +
				PATH_WEIGHT * (MAX_CA_PATH_LEN - pathlen) +
				(c == d ? 1 : 0) +
				1;
			if (prio > best_prio) {
				best = d;
				best_prio = prio;
			}
		}
	}

	if (best != NULL && NEVER_NEGOTIATE(best->policy))
		best = NULL;

	dbg("  fc_try concluding with %s [%" PRIu32 "]",
	    (best ? best->name : "none"), best_prio);

	if (best == NULL && virtualwhy != NULL) {
		libreswan_log(
			"peer proposal was rejected in a virtual connection policy: %s",
			virtualwhy);
	}

	return best;
}

static struct connection *fc_try_oppo(const struct connection *c,
				const struct host_pair *hp,
				const ip_subnet *our_net,
				const ip_subnet *peer_net,
				const uint8_t our_protocol,
				const uint16_t our_port,
				const uint8_t peer_protocol,
				const uint16_t peer_port)
{
	struct connection *best = NULL;
	policy_prio_t best_prio = BOTTOM_PRIO;

	struct connection *d;

	for (d = hp->connections; d != NULL; d = d->hp_next) {
		if (d->policy & POLICY_GROUP)
			continue;

		int wildcards, pathlen;

		if (!(same_id(&c->spd.this.id, &d->spd.this.id) &&
		      match_id(&c->spd.that.id, &d->spd.that.id, &wildcards) &&
		      trusted_ca_nss(c->spd.that.ca, d->spd.that.ca, &pathlen)))
		{
			continue;
		}

		/* compare protocol and ports */
		if (d->spd.this.protocol != our_protocol ||
			(d->spd.this.port && d->spd.this.port != our_port) ||
			d->spd.that.protocol != peer_protocol ||
			(d->spd.that.port != peer_port &&
				!d->spd.that.has_port_wildcard))
			continue;

		/*
		 * Opportunistic case:
		 * our_net must be inside d->spd.this.client
		 * and peer_net must be inside d->spd.that.client
		 * Note: this host_pair chain also has shunt
		 * eroute conns (clear, drop), but they won't
		 * be marked as opportunistic.
		 */

		const struct spd_route *sr;

		for (sr = &d->spd; sr != NULL; sr = sr->spd_next) {
			if (DBGP(DBG_BASE)) {
				selector_buf s1;
				selector_buf d1;
				selector_buf s3;
				selector_buf d3;
				DBG_log("  fc_try_oppo trying %s:%s -> %s vs %s:%s -> %s",
					c->name, str_selector(our_net, &s1),
					str_selector(peer_net, &d1),
					d->name, str_selector(&sr->this.client, &s3),
					str_selector(&sr->that.client, &d3));
			}

			if (!subnetinsubnet(our_net, &sr->this.client) ||
				!subnetinsubnet(peer_net, &sr->that.client))
				continue;

			/*
			 * The connection is feasible, but we continue looking
			 * for the best.
			 * The highest priority wins, implementing eroute-like
			 * rule.
			 * - our smallest client subnet is preferred (longest
			 *   mask)
			 * - given that, peers smallest client subnet is preferred
			 * - given that, a routed connection is preferrred
			 * - given that, the smallest number of ID wildcards
			 *   are preferred
			 * - given that, the shortest CA pathlength is preferred
			 */
			policy_prio_t prio =
				PRIO_WEIGHT * (d->policy_prio + routed(sr->routing)) +
				WILD_WEIGHT * (MAX_WILDCARDS - wildcards) +
				PATH_WEIGHT * (MAX_CA_PATH_LEN - pathlen);

			if (prio > best_prio) {
				best = d;
				best_prio = prio;
			}
		}
	}

	/* if the best wasn't opportunistic, we fail: it must be a shunt */
	if (best != NULL &&
	    (NEVER_NEGOTIATE(best->policy) ||
	     (best->policy & POLICY_OPPORTUNISTIC) == LEMPTY))
		best = NULL;

	dbg("  fc_try_oppo concluding with %s [%" PRIu32 "]",
	    (best ? best->name : "none"), best_prio);
	return best;
}

struct connection *find_client_connection(struct connection *const c,
					const ip_subnet *our_net,
					const ip_subnet *peer_net,
					const uint8_t our_protocol,
					const uint16_t our_port,
					const uint8_t peer_protocol,
					const uint16_t peer_port)
{
	struct connection *d;

	/* weird things can happen to our interfaces */
	if (!oriented(*c)) {
		return NULL;
	}

	if (DBGP(DBG_BASE)) {
		selector_buf s1;
		selector_buf d1;
		DBG_log("find_client_connection starting with %s",
			c->name);
		DBG_log("  looking for %s:%d/%d -> %s:%d/%d",
			str_selector(our_net, &s1), our_protocol, our_port,
			str_selector(peer_net, &d1), peer_protocol, peer_port);
	}

	/*
	 * Give priority to current connection
	 * but even greater priority to a routed concrete connection.
	 */
	{
		struct connection *unrouted = NULL;
		int srnum = -1;

		const struct spd_route *sr;

		for (sr = &c->spd; unrouted == NULL && sr != NULL;
			sr = sr->spd_next) {
			srnum++;

			if (DBGP(DBG_BASE)) {
				selector_buf s2;
				selector_buf d2;
				DBG_log("  concrete checking against sr#%d %s -> %s", srnum,
					str_selector(&sr->this.client, &s2),
					str_selector(&sr->that.client, &d2));
			}

			if (samesubnet(&sr->this.client, our_net) &&
				samesubnet(&sr->that.client, peer_net) &&
				sr->this.protocol == our_protocol &&
				(!sr->this.port ||
					sr->this.port == our_port) &&
				(sr->that.protocol == peer_protocol) &&
				(!sr->that.port ||
					sr->that.port == peer_port)) {
				if (routed(sr->routing))
					return c;

				unrouted = c;
			}
		}

		/* exact match? */
		/*
		 * clang 3.4 says: warning: Access to field 'host_pair' results in a dereference of a null pointer (loaded from variable 'c')
		 * If so, the caller must have passed NULL for it
		 * and earlier references would be wrong (segfault).
		 */
		d = fc_try(c, c->host_pair, our_net, peer_net,
			our_protocol, our_port, peer_protocol, peer_port);

		dbg("  fc_try %s gives %s", c->name, (d ? d->name : "none"));

		if (d == NULL)
			d = unrouted;
	}

	if (d == NULL) {
		/* look for an abstract connection to match */
		const struct host_pair *hp = NULL;

		const struct spd_route *sra;

		for (sra = &c->spd; hp == NULL &&
				sra != NULL; sra = sra->spd_next) {
			hp = find_host_pair(&sra->this.host_addr, NULL);
			if (DBGP(DBG_BASE)) {
				selector_buf s2;
				selector_buf d2;
				DBG_log("  checking hostpair %s -> %s is %s",
					str_selector(&sra->this.client, &s2),
					str_selector(&sra->that.client, &d2),
					(hp ? "found" : "not found"));
			}
		}

		if (hp != NULL) {
			/* RW match with actual peer_id or abstract peer_id? */
			d = fc_try(c, hp, our_net, peer_net,
				our_protocol, our_port, peer_protocol,
				peer_port);

			if (d == NULL &&
				subnetishost(our_net) &&
				subnetishost(peer_net)) {
				/*
				 * Opportunistic match?
				 * Always use abstract peer_id.
				 * Note that later instantiation will result
				 * in the same peer_id.
				 */
				d = fc_try_oppo(c, hp, our_net, peer_net,
						our_protocol, our_port,
						peer_protocol, peer_port);
			}
		}
	}

	dbg("  concluding with d = %s", (d ? d->name : "none"));
	return d;
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

	show_comment(s, "\"%s\"%s: %s; %s; eroute owner: #%lu",
		c->name, instance,
		format_connection(topo, sizeof(topo), c, sr),
		enum_name(&routing_story, sr->routing),
		sr->eroute_owner);

#define OPT_HOST(h, ipb)  (address_is_specified(h) ? str_address(h, &ipb) : "unset")

		/* note: this macro generates a pair of arguments */
#define OPT_PREFIX_STR(pre, s) (s) == NULL ? "" : (pre), (s) == NULL? "" : (s)

	show_comment(s,
		"\"%s\"%s:     %s; my_ip=%s; their_ip=%s%s%s%s%s; my_updown=%s;",
		c->name, instance,
		oriented(*c) ? "oriented" : "unoriented",
		OPT_HOST(&c->spd.this.host_srcip, thisipb),
		OPT_HOST(&c->spd.that.host_srcip, thatipb),
		OPT_PREFIX_STR("; mycert=", cert_nickname(&sr->this.cert)),
		OPT_PREFIX_STR("; peercert=", cert_nickname(&sr->that.cert)),
		(sr->this.updown == NULL || streq(sr->this.updown, "%disabled")) ?
			"<disabled>" : sr->this.updown
	);

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

	show_comment(s,
		"\"%s\"%s:   xauth us:%s, xauth them:%s, %s my_username=%s; their_username=%s",
		c->name, instance,
		/*
		 * Both should not be set, but if they are, we want to
		 * know
		 */
		COMBO(sr->this, xauth_server, xauth_client),
		COMBO(sr->that, xauth_server, xauth_client),
		/* should really be an enum name */
		sr->this.xauth_server ?
			c->xauthby == XAUTHBY_FILE ?
				"xauthby:file;" :
			c->xauthby == XAUTHBY_PAM ?
				"xauthby:pam;" :
				"xauthby:alwaysok;" :
			"",
		sr->this.xauth_username != NULL ? sr->this.xauth_username : "[any]",
		sr->that.xauth_username != NULL ? sr->that.xauth_username : "[any]");

	struct esb_buf auth1, auth2;

	show_comment(s,
		"\"%s\"%s:   our auth:%s, their auth:%s",
		c->name, instance,
		enum_show_shortb(&keyword_authby_names, sr->this.authby, &auth1),
		enum_show_shortb(&keyword_authby_names, sr->that.authby, &auth2));

	show_comment(s,
		"\"%s\"%s:   modecfg info: us:%s, them:%s, modecfg policy:%s, dns:%s, domains:%s%s, cat:%s;",
		c->name, instance,
		COMBO(sr->this, modecfg_server, modecfg_client),
		COMBO(sr->that, modecfg_server, modecfg_client),

		(c->policy & POLICY_MODECFG_PULL) ? "pull" : "push",
		(c->modecfg_dns == NULL) ? "unset" : c->modecfg_dns,
		(c->modecfg_domains == NULL) ? "unset" : c->modecfg_domains,
		(c->modecfg_banner == NULL) ? ", banner:unset" : "",
		sr->this.cat ? "set" : "unset");

#undef COMBO

	if (c->modecfg_banner != NULL) {
		show_comment(s, "\"%s\"%s: banner:%s;",
		c->name, instance, c->modecfg_banner);
	}

	const char *policy_label;
	policy_label = (c->policy_label == NULL) ? "unset" : c->policy_label;
	show_comment(s, "\"%s\"%s:   policy_label:%s;",
		  c->name, instance, policy_label);
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

	if (oriented(*c)) {
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
	if (c->spd.this.ca.ptr != NULL || c->spd.that.ca.ptr != NULL) {
		dn_buf this_ca, that_ca;
		show_comment(s,
			  "\"%s\"%s:   CAs: '%s'...'%s'",
			  c->name,
			  instance,
			  str_dn_or_null(c->spd.this.ca, "%any", &this_ca),
			  str_dn_or_null(c->spd.that.ca, "%any", &that_ca));
	}

	show_comment(s,
		"\"%s\"%s:   ike_life: %jds; ipsec_life: %jds; replay_window: %u; rekey_margin: %jds; rekey_fuzz: %lu%%; keyingtries: %lu;",
		c->name,
		instance,
		deltasecs(c->sa_ike_life_seconds),
		deltasecs(c->sa_ipsec_life_seconds),
		c->sa_replay_window,
		deltasecs(c->sa_rekey_margin),
		c->sa_rekey_fuzz,
		c->sa_keying_tries);

	show_comment(s,
		  "\"%s\"%s:   retransmit-interval: %jdms; retransmit-timeout: %jds; iketcp:%s; iketcp-port:%d;",
		  c->name,
		  instance,
		  deltamillisecs(c->r_interval),
		  deltasecs(c->r_timeout),
		  c->iketcp == IKE_TCP_NO ? "no" : c->iketcp == IKE_TCP_ONLY ? "yes" :
			c->iketcp == IKE_TCP_FALLBACK ? "fallback" : "<BAD VALUE>",
		  c->remote_tcpport);

	show_comment(s,
		  "\"%s\"%s:   initial-contact:%s; cisco-unity:%s; fake-strongswan:%s; send-vendorid:%s; send-no-esp-tfc:%s;",
		  c->name, instance,
		  bool_str(c->initial_contact),
		  bool_str(c->cisco_unity),
		  bool_str(c->fake_strongswan),
		  bool_str(c->send_vendorid),
		  bool_str(c->send_no_esp_tfc));

	if (c->policy_next != NULL) {
		show_comment(s,
			"\"%s\"%s:   policy_next: %s",
			c->name, instance, c->policy_next->name);
	}

	show_comment(s, "\"%s\"%s:   policy: %s%s%s%s%s;",
		  c->name, instance,
		  prettypolicy(c->policy),
		  NEVER_NEGOTIATE(c->policy) ? "+NEVER_NEGOTIATE" : "",
		  c->spd.this.key_from_DNS_on_demand |
			c->spd.that.key_from_DNS_on_demand ? "; " : "",
		  c->spd.this.key_from_DNS_on_demand ? "+lKOD" : "",
		  c->spd.that.key_from_DNS_on_demand ? "+rKOD" : "");

	if (c->ike_version == IKEv2) {
		char hashpolbuf[200];
		const char *hashstr = bitnamesofb(sighash_policy_bit_names,
				c->sighash_policy,
				hashpolbuf, sizeof(hashpolbuf));

		show_comment(s, "\"%s\"%s:   v2-auth-hash-policy: %s;",
			c->name, instance, hashstr);
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
	show_comment(s,
		  "\"%s\"%s:   conn_prio: %s; interface: %s; metric: %u; mtu: %s; sa_prio:%s; sa_tfc:%s;",
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

	show_comment(s,
		  "\"%s\"%s:   nflog-group: %s; mark: %s; vti-iface:%s; "
		  "vti-routing:%s; vti-shared:%s;"
		 " nic-offload:%s;"
		  ,
		  c->name, instance, nflogstr, markstr,
		  c->vti_iface == NULL ? "unset" : c->vti_iface,
		  bool_str(c->vti_routing),
		  bool_str(c->vti_shared),
		  (c->nic_offload == yna_auto) ? "auto" :
			bool_str(c->nic_offload == yna_yes)
	);

	{
		id_buf thisidb;
		id_buf thatidb;

	show_comment(s,
		"\"%s\"%s:   our idtype: %s; our id=%s; their idtype: %s; their id=%s",
		c->name, instance,
		enum_name(&ike_idtype_names_extended, c->spd.this.id.kind),
		str_id(&c->spd.this.id, &thisidb),
		enum_name(&ike_idtype_names_extended, c->spd.that.id.kind),
		str_id(&c->spd.that.id, &thatidb));
	}

	/* slightly complicated stuff to avoid extra crap */
	show_comment(s,
		"\"%s\"%s:   dpd: %s; delay:%ld; timeout:%ld; nat-t: encaps:%s; nat_keepalive:%s; ikev1_natt:%s",
		c->name, instance,
		enum_name(&dpd_action_names, c->dpd_action),
		(long) deltasecs(c->dpd_delay),
		(long) deltasecs(c->dpd_timeout),
		(c->encaps == yna_auto) ? "auto" :
		    bool_str(c->encaps == yna_yes),
		bool_str(c->nat_keepalive),
		(c->ikev1_natt == NATT_BOTH) ? "both" :
		 (c->ikev1_natt == NATT_RFC) ? "rfc" :
		 (c->ikev1_natt == NATT_DRAFTS) ? "drafts" : "none"
		);

	if (!lmod_empty(c->extra_debugging)) {
		SHOW_JAMBUF(RC_COMMENT, s, buf) {
			jam(buf, "\"%s\"%s:   debug: ",
			    c->name, instance);
			jam_lmod(buf, &debug_names, "+", c->extra_debugging);
		}
	}

	SHOW_JAMBUF(RC_COMMENT, s, buf) {
		jam(buf, "\"%s\"%s:   newest ISAKMP SA: #%lu; newest IPsec SA: #%lu; conn serial: "PRI_CO"",
		    c->name,
		    instance,
		    c->newest_isakmp_sa,
		    c->newest_ipsec_sa,
		    pri_co(c->serialno));
		if (c->serial_from.co/*oops*/ != 0) {
			jam(buf, ", instantiated from: "PRI_CO";",
			    pri_co(c->serial_from));
		} else {
			jam(buf, ";");
		}
	}

	if (c->connalias != NULL) {
		show_comment(s, "\"%s\"%s:   aliases: %s",
			     c->name,
			     instance,
			     c->connalias);
	}

	show_ike_alg_connection(s, c, instance);
	show_kernel_alg_connection(s, c, instance);
}

void show_connections_status(struct show *s)
{
	int count = 0;
	int active = 0;
	struct connection *c;

	show_separator(s);
	show_comment(s, "Connection list:");
	show_separator(s);

	dbg("FOR_EACH_CONNECTION_... in %s", __func__);
	for (c = connections; c != NULL; c = c->ac_next) {
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

		dbg("FOR_EACH_CONNECTION_... in %s", __func__);
		for (c = connections; c != NULL; c = c->ac_next)
			array[i++] = c;

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
void connection_discard(struct connection *c)
{
	dbg("in connection_discard for connection %s", c->name);

	if (c->kind == CK_INSTANCE) {
		dbg("connection is instance");
		if (in_pending_use(c)) {
			dbg("in pending use");
			return;
		}
		dbg("not in pending use");

		/* find the first */
		struct state *st = state_by_connection(c, NULL, NULL, __func__);
		if (DBGP(DBG_BASE)) {
			/*
			 * Cross check that the state DB has been kept
			 * up-to-date.
			 */
			struct state *dst = NULL;
			FOR_EACH_STATE_NEW2OLD(dst) {
				if (dst->st_connection == c) {
					break;
				}
			}
			/* found a state, may not be the same */
			pexpect((dst == NULL) == (st == NULL));
			st = dst; /* let the truth be free */
		}

		if (st == NULL) {
			dbg("no states use this connection instance, deleting");
			delete_connection(c, FALSE);
		} else {
			dbg("states still using this connection instance, retaining");
		}
	}
}

/*
 * Every time a state's connection is changed, the following need to happen:
 *
 * - update the connection->state hash table
 *
 * - discard the old connection when not in use
 */
void update_state_connection(struct state *st, struct connection *c)
{
	struct connection *old = st->st_connection;

	if (old != c) {
		st->st_connection = c;
		st->st_peer_alt_id = FALSE; /* must be rechecked against new 'that' */
		rehash_state_connection(st);
		if (old != NULL) {
			connection_discard(old);
		}
	}
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
	struct connection *ue;

	dbg("FOR_EACH_CONNECTION_... in %s", __func__);
	for (ue = connections; ue != NULL; ue = ue->ac_next) {
		struct spd_route *srue;

		for (srue = &ue->spd; srue != NULL; srue =srue->spd_next) {
			const struct spd_route *src;

			for (src = &c->spd; src != NULL; src = src->spd_next) {
				if (srue->routing == RT_ROUTED_ECLIPSED &&
				    samesubnet(&src->this.client, &srue->this.client) &&
				    samesubnet(&src->that.client, &srue->that.client))
				{
					dbg("%s eclipsed %s", c->name, ue->name);
					*esrp = srue;
					return ue;
				}
			}
		}
	}
	*esrp = NULL;
	return NULL;
}

void liveness_clear_connection(struct connection *c, const char *v)
{
	/*
	 * For CK_INSTANCE, delete_states_by_connection() will clear
	 * Note that delete_states_by_connection changes c->kind but we need
	 * to remember what it was to know if we still need to unroute after delete
	 */
	if (c->kind == CK_INSTANCE) {
		delete_states_by_connection(c, TRUE, null_fd/*no-whack?*/);
	} else {
		flush_pending_by_connection(c); /* remove any partial negotiations that are failing */
		delete_states_by_connection(c, TRUE, null_fd/*no-whack?*/);
		dbg("%s: unrouting connection %s action - clearing",
		    enum_name(&connection_kind_names, c->kind), v);
		unroute_connection(c); /* --unroute */
	}
}

void liveness_action(struct state *st)
{
	struct connection *c = st->st_connection;
	const char *ikev = enum_name(&ike_version_liveness_names, st->st_ike_version);
	passert(ikev != NULL);

	switch (c->dpd_action) {
	case DPD_ACTION_CLEAR:
		log_state(RC_LOG, st,
			  "%s action - clearing connection kind %s", ikev,
			  enum_name(&connection_kind_names, c->kind));
		liveness_clear_connection(c, ikev);
		break;

	case DPD_ACTION_RESTART:
		log_state(RC_LOG, st,
			  "%s action - restarting all connections that share this peer",
			  ikev);
		restart_connections_by_peer(c);
		break;

	case DPD_ACTION_HOLD:
		log_state(RC_LOG, st,
			  "%s action - putting connection into hold", ikev);
		if (c->kind == CK_INSTANCE) {
			dbg("%s warning dpdaction=hold on instance futile - will be deleted", ikev);
		}
		delete_states_by_connection(c, TRUE, null_fd/*no-whack?*/);
		break;

	default:
		bad_case(c->dpd_action);
	}
}

/*
 * This is to support certificates with SAN using wildcard, eg SAN
 * contains DNS:*.vpnservice.com where our leftid=*.vpnservice.com
 */
static bool idr_wildmatch(const struct end *this, const struct id *idr, struct logger *logger)
{
	/* check if received IDr is a valid SAN of our cert */
	/* cert_VerifySubjectAltName, if called, will [debug]log any errors */
	/* XXX:  calling cert_VerifySubjectAltName with ID_DER_ASN1_DN futile? */
	/* ??? if cert matches we don't actually do any further ID matching, wildcard or not */
	if (this->cert.ty != CERT_NONE &&
	    (idr->kind == ID_FQDN || idr->kind == ID_DER_ASN1_DN) &&
	    cert_VerifySubjectAltName(this->cert.u.nss_cert, idr, logger))
		return true;

	const struct id *wild = &this->id;

	/* if not both ID_FQDN, fall back to same_id (no wildcarding possible) */
	if (idr->kind != ID_FQDN || wild->kind != ID_FQDN)
		return same_id(wild, idr);

	size_t wl = wild->name.len;
	const char *wp = (const char *) wild->name.ptr;

	/* if wild has no *, fall back to same_id (no wildcard present) */
	if (wl == 0 || wp[0] != '*')
		return same_id(wild, idr);

	while (wp[wl - 1] == '.')
		wl--;	/* strip trailing dot */

	size_t il = idr->name.len;
	const char *ip = (const char *) idr->name.ptr;
	while (il > 0 && ip[il - 1] == '.')
		il--;	/* strip trailing dot */

	/*
	 * ??? should we require that the * match only whole components?
	 * wl-1 == il ||   // total match
	 * wl > 1 && wp[1] == '.' ||   // wild included leading "."
	 * ip[il-(wl-1) - 1] == '.'   // match preceded by "."
	 */

	return wl-1 <= il && strncaseeq(&wp[1], &ip[il-(wl-1)], wl-1);
}

/* sa priority and type should really go into kernel_sa */
uint32_t calculate_sa_prio(const struct connection *c, bool oe_shunt)
{
	if (c->sa_priority != 0) {
		dbg("priority calculation of connection \"%s\" overruled by connection specification of %"PRIu32" (%#"PRIx32")",
		    c->name, c->sa_priority, c->sa_priority);
		return c->sa_priority;
	}

	if (LIN(POLICY_GROUP, c->policy)) {
		dbg("priority calculation of connection \"%s\" skipped - group template does not install SPDs",
		    c->name);
		return 0;
	}

	uint32_t pmax =
		(LIN(POLICY_GROUPINSTANCE, c->policy)) ?
			(LIN(POLICY_AUTH_NULL, c->policy)) ?
				PLUTO_SPD_OPPO_ANON_MAX :
				PLUTO_SPD_OPPO_MAX :
			PLUTO_SPD_STATIC_MAX;

	uint32_t portsw = /* max 2 (2 bits) */
		(c->spd.this.port == 0 ? 0 : 1) +
		(c->spd.that.port == 0 ? 0 : 1);

	uint32_t protow = c->spd.this.protocol == 0 ? 0 : 1;	/* (1 bit) */


	/*
	 * For transport mode or /32 to /32, the client mask bits are
	 * set based on the host_addr parameters.
	 */
	uint32_t srcw, dstw;	/* each max 128 (8 bits) */
	srcw = c->spd.this.client.maskbits;
	dstw = c->spd.that.client.maskbits;
	/* if opportunistic, override the template destination mask with /32 or /128 */
	if (oe_shunt) {
		dstw = (addrtypeof(&c->spd.that.host_addr) == AF_INET) ? 32 : 128;
	}

	/* ensure an instance of a template/OE-group always has preference */
	uint32_t instw = (c->kind == CK_INSTANCE ? 0u : 1u);

	uint32_t prio = pmax - (portsw << 18 | protow << 17 | srcw << 9 | dstw << 1 | instw);

	dbg("priority calculation of connection \"%s\" is %"PRIu32" (%#"PRIx32")",
	    c->name, prio, prio);
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
		newest = c->newest_isakmp_sa;
		dbg("picked newest_isakmp_sa #%lu for #%lu",
		    newest, st->st_serialno);
	} else {
		newest = c->newest_ipsec_sa;
		dbg("picked newest_ipsec_sa #%lu for #%lu",
		    newest, st->st_serialno);
	}

	if (newest != SOS_NOBODY && newest > st->st_serialno) {
		return newest;
	} else {
		return SOS_NOBODY;
	}
}

/* check to see that Ids of peers match */
bool same_peer_ids(const struct connection *c, const struct connection *d,
		   const struct id *peer_id)
{
	return same_id(&c->spd.this.id, &d->spd.this.id) &&
	       same_id(peer_id == NULL ? &c->spd.that.id : peer_id,
		       &d->spd.that.id);
}

/* reread all left/right certificates from NSS DB */
void reread_cert_connections(struct fd *whackfd)
{
	struct connection *c;

	dbg("FOR_EACH_CONNECTION_... in %s", __func__);
	for (c = connections; c != NULL; c = c->ac_next) {
		reread_cert(whackfd, c);
	}
}
