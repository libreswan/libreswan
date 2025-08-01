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

#include "ip_info.h"

#include "defs.h"
#include "instantiate.h"
#include "iface.h"
#include "connections.h"
#include "state.h"
#include "log.h"
#include "orient.h"
#include "connection_db.h"	/* for finish_connection() */
#include "addresspool.h"
#include "ipsec_interface.h"
#include "virtual_ip.h"
#include "kernel.h"
#include "verbose.h"

#define MINIMUM_IPSEC_SA_RANDOM_MARK 65536
static uint32_t global_marks = MINIMUM_IPSEC_SA_RANDOM_MARK;

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

static struct connection *duplicate_connection(const char *name, struct connection *t,
					       const struct id *peer_id, where_t where)
{
	struct connection *c = alloc_connection(name, t, NULL,
						t->logger->debugging,
						t->logger,
						where);

	/*
	 * Now explicitly copy over anything needed from T into C.
	 */

	c->iface = iface_addref(t->iface);

	c->local->host.id = clone_id(&t->local->host.id, "unshare local connection id");
	c->remote->host.id = clone_id((peer_id != NULL ? peer_id : &t->remote->host.id),
				      "unshare remote connection id");

	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		struct host_end *ce = &c->end[end].host;
		const struct host_end *te = &t->end[end].host;
		ce->encap = te->encap;
		ce->port = te->port;
		ce->nexthop = te->nexthop;
		ce->addr = te->addr;
		ce->first_addr = te->first_addr;
	}

	FOR_EACH_ELEMENT(afi, ip_families) {
		c->pool[afi->ip.version] = addresspool_addref(t->pool[afi->ip.version]);
	}

	c->sa_marks = t->sa_marks; /* no pointers? */
	c->ipsec_interface = ipsec_interface_addref(t->ipsec_interface,
						    c->logger, HERE);

	/* inherit UP, ROUTE, and KEEP */
	c->policy = t->policy;

	return c;
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
				     ip_port remote_port,
				     where_t where)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, group->logger, NULL);
	subnet_buf rsb;
	vdbg_connection(group, verbose, where,
			"%s: "PRI_HPORT" %s -> [%s]:"PRI_HPORT,
			__func__,
			pri_hport(local_port),
			protocol->name,
			str_subnet(&remote_subnet, &rsb),
			pri_hport(remote_port));
	verbose.level++;

	vassert(is_group(group));
	vassert(oriented(group));
	vassert(protocol != NULL);
	vassert(group->child.spds.len <= 1);
	vassert(group->child.spds.len == 0 || group->child.spds.list->local->virt == NULL);

	/*
	 * Manufacture a unique name for this template.
	 */
	char *base_name; /* must free */
	if (protocol == &ip_protocol_all) {
		/* all protocols implies all ports */
		pexpect(local_port.hport == 0);
		pexpect(remote_port.hport == 0);
		subnet_buf tb;
		base_name = alloc_printf("%s#%s", group->config->name,
					 str_subnet(&remote_subnet, &tb));
	} else {
		subnet_buf tb;
		base_name = alloc_printf("%s#%s-("PRI_HPORT"--%d--"PRI_HPORT")",
					 group->config->name,
					 str_subnet(&remote_subnet, &tb),
					 pri_hport(local_port),
					 protocol->ipproto,
					 pri_hport(remote_port));
	}

	if (connection_with_name_exists(base_name)) {
		llog_rc(RC_DUPNAME, group->logger,
			"group name + target yields duplicate name \"%s\"", base_name);
		pfreeany(base_name);
		return NULL;
	}

	struct connection *t = duplicate_connection(base_name, group, NULL/*id*/, HERE);
	PASSERT(t->logger, !streq(group->name, t->name));
	PASSERT(t->logger, !streq(group->base_name, t->base_name));
	PASSERT(t->logger, t->base_name != base_name); /* see duplicate_connection() */
	pfreeany(base_name);

	/*
	 * Start the template counter so that further instantiating
	 * the group instance assigns serial numbers..
	 */
	t->next_instance_serial = 1;

#define set_end_selector(END, SELECTOR, LOGGER)				\
	{								\
		PASSERT(LOGGER, (END)->child.selectors.proposed.list == NULL); \
		PASSERT(LOGGER, (END)->child.selectors.proposed.len == 0); \
		struct verbose verbose_ = VERBOSE(DEBUG_STREAM, LOGGER, NULL); \
		append_end_selector(END, SELECTOR, verbose_);		\
	}

	/*
	 * For the remote end, just use what ever the group specified
	 * (i.e., ignore protoport=).
	 */
	ip_selector remote_selector =
		selector_from_subnet_protocol_port(remote_subnet, protocol, remote_port);
	set_end_selector(t->remote, remote_selector, t->logger);

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

	set_end_selector(t->local, local_selector, t->logger);

	del_policy(t, policy.route);
	/*
	 * Mark as template+group aka GROUPINSTANCE for later.
	 *
	 * When this template_group is instantiated the policy bit is
	 * inherited resulting in instance+group aka GROUPINSTANCE
	 * also. */
	t->local->kind = t->remote->kind = CK_TEMPLATE;
	t->child.reqid = child_reqid(t->config, t->logger);

	PEXPECT(t->logger, oriented(t));

	/*
	 * All host/selector fields set, can enter into DB.
	 */
	connection_db_add(t);

	/*
	 * Fill in the SPDs; and add entries to the SPD db
	 */
	build_connection_spds_from_proposals(t);

	vdbg_connection(t, verbose, HERE, "%s: from %s",
			__func__, group->name);
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
				      shunk_t sec_label, /* for ldbg() message only */
				      const char *func,
				      struct verbose verbose,
				      where_t where)
{
	address_buf ab;
	id_buf idb;
	name_buf kb;
	vdbg_connection(t, verbose, where,
			"%s: remote=%s id=%s kind=%s sec_label="PRI_SHUNK,
			func, str_address(&remote_addr, &ab),
			str_id(peer_id, &idb),
			str_enum_short(&connection_kind_names, t->local->kind, &kb),
			pri_shunk(sec_label));

	vassert(address_is_specified(remote_addr)); /* always */
	vassert((is_template(t) ||
			    is_labeled_template(t) ||
			    is_labeled_parent(t)));

	if (peer_id != NULL) {
		struct verbose verbose = VERBOSE(DEBUG_STREAM, t->logger, NULL);
		int wildcards;	/* value ignored */
		passert(t->remote->host.id.kind == ID_FROMCERT ||
			match_id(peer_id, &t->remote->host.id, &wildcards, verbose));
	}

	struct connection *d = duplicate_connection(t->base_name, t, peer_id, where);
	PASSERT(d->logger, !streq(t->name, d->name));
	PASSERT(d->logger, t->base_name != d->base_name); /* see duplicate_connection() */

	d->local->kind = d->remote->kind =
		(is_labeled_template(t) ? CK_LABELED_PARENT :
		 is_labeled_parent(t) ? CK_LABELED_CHILD :
		 CK_INSTANCE);

	/* propagate remote address when set */
	if (address_is_specified(d->remote->host.addr)) {
		/* can't change remote once set */
		PASSERT(d->logger, address_eq_address(remote_addr, d->remote->host.addr));
	} else {
		/* this updates ID NULL */
		update_hosts_from_end_host_addr(d, d->remote->config->index,
						remote_addr, d->local->host.nexthop,
						HERE); /* from whack initiate */
	}

	d->child.reqid = child_reqid(t->config, d->logger);

	/*
	 * assumption: orientation is the same as c's - while the
	 * remote endpoint may go from <unset> to <valid> the local
	 * endpoint and iface are unchanged.
	 */
	passert(oriented(d));

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

	/*
	 * With D initialized, enter it into the DB.
	 */
	connection_db_add(d);

	return d;
}

/*
 * In addition to instantiate() also clone the SPD entries.
 *
 * XXX: it's arguable that SPD entries are being created far too early
 * (currently during connection add).  The IKEv2 TS responder, for
 * instance, ends up throwing away the SPDs creating its own.
 */

struct connection *spd_instantiate(struct connection *t,
				   const ip_address remote_addr,
				   where_t where)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, t->logger, NULL);
	vdbg("%s() ...", __func__);
	verbose.level++;

	vassert(!is_labeled(t));

	struct connection *d = instantiate(t, remote_addr, /*peer-id*/NULL,
					   empty_shunk, __func__,
					   verbose, where);

	build_connection_proposals_from_hosts_and_configs(d, verbose);
	build_connection_spds_from_proposals(d);

	/* leave breadcrumb */
	pexpect(d->negotiating_child_sa == SOS_NOBODY);
	pexpect(d->routing.state == RT_UNROUTED);

	vdbg_connection(d, verbose, where, "%s: from %s",
			__func__, t->name);

	return d;
}

/*
 * For a template SEC_LABEL connection, instantiate it creating the
 * parent.
 */

struct connection *labeled_template_instantiate(struct connection *t,
						const ip_address remote_address,
						where_t where)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, t->logger, NULL);
	vdbg("%s() ...", __func__);
	verbose.level++;

	vassert(is_labeled_template(t));

	struct connection *p = instantiate(t, remote_address, /*peer-id*/NULL,
					   empty_shunk, __func__,
					   verbose, where);

	build_connection_proposals_from_hosts_and_configs(p, verbose);
	build_connection_spds_from_proposals(p);

	pexpect(p->negotiating_child_sa == SOS_NOBODY);
	pexpect(p->routing.state == RT_UNROUTED);

	vdbg_connection(p, verbose, where, "%s: from %s",
			__func__, t->name);

	return p;
}

/*
 * For an established SEC_LABEL connection, instantiate a connection
 * for the Child SA.
 */

struct connection *labeled_parent_instantiate(struct ike_sa *ike,
					      shunk_t sec_label,
					      where_t where)
{
	struct connection *p = ike->sa.st_connection;
	struct verbose verbose = VERBOSE(DEBUG_STREAM, p->logger, NULL);
	vdbg("%s() ...", __func__);
	verbose.level++;

	vassert(is_labeled_parent(p));

	ip_address remote_addr = endpoint_address(ike->sa.st_remote_endpoint);
	struct connection *c = instantiate(p, remote_addr, /*peer-id*/NULL,
					   sec_label, __func__,
					   verbose, where);

	/*
	 * Install the sec_label from either an acquire or child
	 * payload into both ends.
	 */
	PASSERT(c->logger, c->child.sec_label.ptr == NULL);
	c->child.sec_label = clone_hunk(sec_label, __func__);

	build_connection_proposals_from_hosts_and_configs(c, verbose);
	build_connection_spds_from_proposals(c);

	pexpect(c->negotiating_child_sa == SOS_NOBODY);
	pexpect(c->routing.state == RT_UNROUTED);

	vdbg_connection(c, verbose, where, "%s: from %s",
			__func__, p->name);

	return c;
}

struct connection *rw_responder_instantiate(struct connection *t,
					    const ip_address peer_addr,
					    where_t where)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, t->logger, NULL);
	vdbg("%s() ...", __func__);
	verbose.level++;

	vassert(!is_opportunistic(t));
	vassert(!is_labeled(t));

	struct connection *d = instantiate(t, peer_addr,
					   /*TBD-peer_id*/NULL,
					   empty_shunk, __func__,
					   verbose, where);

	build_connection_proposals_from_hosts_and_configs(d, verbose);
	build_connection_spds_from_proposals(d);

	vdbg_connection(d, verbose, where, "%s: from %s",
			__func__, t->name);
	return d;
}

struct connection *rw_responder_id_instantiate(struct connection *t,
					       const ip_address remote_addr,
					       const struct id *remote_id,
					       where_t where)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, t->logger, NULL);
	vdbg("%s() ...", __func__);
	verbose.level++;

	vassert(!is_opportunistic(t));
	vassert(!is_labeled(t));
	vassert(remote_id != NULL);

	/*
	 * XXX: this function is never called when there are
	 * sec_labels?
	 */
	struct connection *d = instantiate(t, remote_addr, remote_id,
					   empty_shunk, __func__,
					   verbose, where);

	/* real selectors are still unknown */
	build_connection_proposals_from_hosts_and_configs(d, verbose);
	build_connection_spds_from_proposals(d);

	vdbg_connection(d, verbose, where, "%s: from %s",
			__func__, t->name);
	return d;

}

/*
 * XXX: unlike update_selectors(), this code has to handle the remote
 * subnet.
 */

static bool update_v1_quick_n_dirty_selectors(struct connection *d,
					      const ip_selector remote_subnet,
					      struct verbose verbose)
{
	selector_buf sb; /*handles NULL*/
	vdbg("%s() %s ...", __func__, str_selector(&remote_subnet, &sb));
	verbose.level++;

	/*
	 * Need to fill in selectors for both left and right.
	 */
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
			/* see also clone_connection */
			set_end_child_has_client(d, end->config->index, true);
			continue;
		}

		/* remote is virtual-ip */
		if (&end->child == &d->remote->child &&
		    d->remote->config->child.virt != NULL) {
			vdbg("%s.child is virtual", leftright);
			PASSERT(d->logger, &end->host == &d->remote->host);
			set_end_selector(end, remote_subnet, d->logger);
			if (selector_eq_address(remote_subnet, d->remote->host.addr)) {
				ldbg(d->logger,
				     "forcing remote %s.spd.has_client=false",
				     d->child.spds.list->remote->config->leftright);
			}
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
				append_end_selector(end, selector, verbose);
			}
			continue;
		}

		/* {left,right}= */
		if (address_is_specified(end->host.addr)) {
			/*
			 * Default the end's child selector (client)
			 * to a subnet containing only the end's host
			 * address.
			 *
			 * If the other end has multiple child
			 * selectors then the combination becomes a
			 * list.
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
			append_end_selector(end, selector, verbose);
			continue;
		}

#if 0
		/*
		 * to-be-determined from the host (for instance,
		 * waiting on DNS) or the opportunistic group (needs
		 * to be expanded).
		 *
		 * Make space regardless so that loops have something
		 * to iterate over.
		 */
		if (vbad(host_afi == NULL)) {
			return;
		}

		vexpect(is_permanent(c) || is_group(c) || is_template(c));
		vdbg("%s selector proposals from unset host family %s",
		     leftright, host_afi->ip_name);
		append_end_selector(end, unset_selector, verbose);
#else
		llog_pexpect(verbose.logger, HERE, "no address");
		return false;
#endif
	}

	return true;
}

struct connection *rw_responder_v1_quick_n_dirty_instantiate(struct connection *t,
							     const ip_address remote_addr,
							     const ip_selector remote_subnet,
							     const struct id *remote_id,
							     struct verbose verbose,
							     where_t where)
{
	vdbg("%s() ...", __func__);
	verbose.level++;

	vassert(!is_opportunistic(t));
	vassert(!is_labeled(t));
	vassert(remote_id != NULL);

	/*
	 * XXX: this function is never called when there are
	 * sec_labels?
	 */
	struct connection *d = instantiate(t, remote_addr, remote_id,
					   empty_shunk, __func__,
					   verbose, where);

	update_v1_quick_n_dirty_selectors(d, remote_subnet, verbose);
	build_connection_spds_from_proposals(d);

	vdbg_connection(d, verbose, where, "%s: from %s",
			__func__, t->name);
	return d;
}

static struct connection *oppo_instantiate(struct connection *t,
					   const ip_address remote_address,
					   const char *func,
					   struct verbose verbose,
					   where_t where)
{
	vassert(is_template(t));
	vassert(oriented(t)); /* else won't instantiate */
	vassert(t->local->child.selectors.proposed.len == 1);
	vassert(t->remote->child.selectors.proposed.len == 1);

	/*
	 * Instance inherits remote ID of child; exception being when
	 * ID is NONE when it is set to the remote address.
	 */

	struct connection *d = instantiate(t, remote_address, /*peer_id*/NULL,
					   empty_shunk, func,
					   verbose, where);

	PASSERT(d->logger, is_instance(d));
	PASSERT(d->logger, oriented(d)); /* else won't instantiate */
	PASSERT(d->logger, is_opportunistic(d));
	PASSERT(d->logger, address_eq_address(d->remote->host.addr, remote_address));

	/*
	 * Fill in the local client - just inherit the parent's value.
	 */
	ip_selector local_selector = t->local->child.selectors.proposed.list[0];
	set_end_selector(d->local, local_selector, d->logger);

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
	set_end_selector(d->remote, remote_selector, d->logger);

	PEXPECT(d->logger, oriented(d));
	build_connection_spds_from_proposals(d);

	vdbg_connection(d, verbose, where, "%s: from %s",
			func, t->name);
	return d;
}

struct connection *oppo_responder_instantiate(struct connection *t,
					      const ip_address remote_address,
					      where_t where)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, t->logger, NULL);
	vdbg("%s() ...", __func__);
	verbose.level++;

	/*
	 * Did find oppo connection do its job?
	 *
	 * On the responder all that is known is the address of the
	 * remote IKE daemon that initiated the exchange.  Hence check
	 * it falls within the selector's range (can't match port as
	 * not yet known).
	 */
	vassert(t->remote->child.selectors.proposed.len == 1);
	ip_selector remote_template = t->remote->child.selectors.proposed.list[0];
	vassert(address_in_selector_range(remote_address, remote_template));
	return oppo_instantiate(t, remote_address, __func__, verbose, where);
}

struct connection *oppo_initiator_instantiate(struct connection *t,
					      ip_packet packet,
					      where_t where)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, t->logger, NULL);
	vdbg("%s() ...", __func__);
	verbose.level++;

	/*
	 * Did find oppo connection do its job?
	 *
	 * On the initiator the triggering packet provides the exact
	 * endpoint that needs to be negotiated.  Hence this endpoint
	 * must be fully within the template's selector).
	 */
	vassert(t->remote->child.selectors.proposed.len == 1);
	ip_selector remote_template = t->remote->child.selectors.proposed.list[0];
	ip_endpoint remote_endpoint = packet_dst_endpoint(packet);
	vassert(endpoint_in_selector(remote_endpoint, remote_template));
	ip_address local_address = packet_src_address(packet);
	PEXPECT(t->logger, address_eq_address(local_address, t->local->host.addr));
	ip_address remote_address = endpoint_address(remote_endpoint);
	return oppo_instantiate(t, remote_address, __func__, verbose, where);
}
