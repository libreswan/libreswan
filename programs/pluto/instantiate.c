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
#include "kernel_xfrm_interface.h"
#include "host_pair.h"
#include "virtual_ip.h"
#include "kernel.h"

#define MINIMUM_IPSEC_SA_RANDOM_MARK 65536
static uint32_t global_marks = MINIMUM_IPSEC_SA_RANDOM_MARK;

static struct connection *clone_connection(const char *name, struct connection *t,
					   const struct id *peer_id, where_t where);

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
	zero_thing(c->connection_db_entries); /* keep init_list_entry() happy */
	finish_connection(c, name, t, t->config,
			  t->logger->debugging,
			  t->logger->object_whackfd,
			  where);

	/* caller responsible for re-building these */
	c->spd = NULL;
	zero(&c->child.spds);

	c->log_file_name = NULL;
	c->log_file = NULL;
	c->log_file_err = false;

	c->next_instance_serial = 0;	/* restart count */
	c->instance_serial = 0;		/* restart count */
	c->root_config = NULL; /* block write access */
	c->foodgroup = clone_str(t->foodgroup, "food groups");
	c->vti_iface = clone_str(t->vti_iface, "connection vti_iface");
	c->interface = iface_endpoint_addref(t->interface);

	/* Template can't yet have an assigned SEC_LABEL */
	PASSERT(t->logger, t->child.sec_label.len == 0);
	PASSERT(c->logger, c->child.sec_label.len == 0);

	c->local->host.id = clone_id(&t->local->host.id, "unshare local connection id");
	c->remote->host.id = clone_id((peer_id != NULL ? peer_id : &t->remote->host.id),
				      "unshare remote connection id");

	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		zero(&c->end[end].child.selectors);
	}

	FOR_EACH_ELEMENT(afi, ip_families) {
		c->pool[afi->ip_index] = addresspool_addref(t->pool[afi->ip_index]);
	}

	if (IS_XFRMI && c->xfrmi != NULL) {
		reference_xfrmi(c);
	}

	/* trash cloned value; applies to parent */
	c->child.routing = RT_UNROUTED;
	c->child.newest_routing_sa = SOS_NOBODY;
	set_child_routing(c, RT_UNROUTED, SOS_NOBODY);

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
	subnet_buf rsb;
	ldbg_connection(group, where, "%s: "PRI_HPORT" %s -> [%s]:"PRI_HPORT,
			__func__,
			pri_hport(local_port),
			protocol->name,
			str_subnet(&remote_subnet, &rsb),
			pri_hport(remote_port));
	PASSERT(group->logger, group->kind == CK_GROUP);
	PASSERT(group->logger, oriented(group));
	PASSERT(group->logger, protocol != NULL);
	PASSERT(group->logger, group->child.spds.len <= 1);
	PASSERT(group->logger, (group->child.spds.len == 0 ||
				group->child.spds.list->local->virt == NULL));

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

	t->policy &= ~POLICY_ROUTE;
	t->policy |= POLICY_GROUPINSTANCE; /* mark as group instance for later */
	t->kind = CK_TEMPLATE;
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
	PEXPECT(t->logger, oriented(t));
	add_connection_spds(t, address_info(t->local->host.addr));

	connection_buf gb;
	ldbg_connection(t, HERE, "%s: from "PRI_CONNECTION,
			__func__, pri_connection(group, &gb));
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
				      bool assign_serial,
				      shunk_t sec_label, /* for ldbg() message only */
				      const char *func, where_t where)
{
	address_buf ab;
	id_buf idb;
	ldbg_connection(t, where, "%s: remote=%s id=%s kind=%s sec_label="PRI_SHUNK,
			func, str_address(&remote_addr, &ab),
			str_id(peer_id, &idb),
			enum_name_short(&connection_kind_names, t->kind),
			pri_shunk(sec_label));

	PASSERT(t->logger, address_is_specified(remote_addr)); /* always */
	PASSERT(t->logger, (t->kind == CK_TEMPLATE ||
			    labeled_template(t) ||
			    labeled_parent(t)));

	if (peer_id != NULL) {
		int wildcards;	/* value ignored */
		passert(t->remote->host.id.kind == ID_FROMCERT ||
			match_id("", peer_id, &t->remote->host.id, &wildcards));
	}

	struct connection *d = clone_connection(t->name, t, peer_id, HERE);
	passert(t->name != d->name); /* see clone_connection() */

	/*
	 *  Only update .instance_serial when requested by caller.
	 */
	if (assign_serial) {
		d->instance_serial = ++t->next_instance_serial;
		ldbg(d->logger, "updating instance serial %lu next %lu",
		     d->instance_serial, t->next_instance_serial);
	}

	d->kind = CK_INSTANCE;
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

	/*
	 * Reset; sec_label templates will have set this.
	 */
	d->newest_ike_sa = SOS_NOBODY;
	pexpect(d->newest_ipsec_sa == SOS_NOBODY);

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

static void update_selectors(struct connection *d)
{
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
}

/*
 * XXX: unlike rw_responder_id_instantiate(), this code has to
 * handle the remote subnet
 */
static void update_subnet_selectors(struct connection *d,
				    const ip_selector *remote_subnet)
{
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
				ldbg(d->logger, "forcing remote %s.spd.has_client=false",
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
	PASSERT(t->logger, !labeled(t));

	struct connection *d = instantiate(t, remote_addr, /*peer-id*/NULL,
					   /*update_serial*/true, empty_shunk,
					   __func__, where);

	update_selectors(d);
	add_connection_spds(d, address_info(d->local->host.addr));

	/* leave breadcrumb */
	pexpect(d->child.newest_routing_sa == SOS_NOBODY);
	set_child_routing(d, d->child.routing, SOS_NOBODY);

	connection_buf tb;
	ldbg_connection(d, where, "%s: from "PRI_CONNECTION,
			__func__, pri_connection(t, &tb));

	return d;
}

/*
 * For a template SEC_LABEL connection, instantiate it creating the
 * parent.
 */

struct connection *sec_label_parent_instantiate(struct connection *t,
						const ip_address remote_address,
						where_t where)
{
	PASSERT(t->logger, labeled_template(t));

	struct connection *d = instantiate(t, remote_address, /*peer-id*/NULL,
					   /*update_serial*/false, empty_shunk,
					   __func__, where);

	update_selectors(d);
	add_connection_spds(d, address_info(d->local->host.addr));

	/* leave breadcrumb */
	pexpect(d->child.newest_routing_sa == SOS_NOBODY);
	set_child_routing(d, d->child.routing, SOS_NOBODY);

	connection_buf tb;
	ldbg_connection(d, where, "%s: from "PRI_CONNECTION,
			__func__, pri_connection(t, &tb));

	return d;
}

/*
 * For an established SEC_LABEL connection, instantiate a connection
 * for the Child SA.
 */

struct connection *sec_label_child_instantiate(struct ike_sa *ike,
					       shunk_t sec_label,
					       where_t where)
{
	struct connection *t = ike->sa.st_connection;
	PEXPECT_WHERE(t->logger, where, labeled_torp(t));

	ip_address remote_addr = endpoint_address(ike->sa.st_remote_endpoint);
	struct connection *d = instantiate(t, remote_addr, /*peer-id*/NULL,
					   /*update_serial*/true, sec_label,
					   __func__, where);

	/*
	 * Install the sec_label from either an acquire or child
	 * payload into both ends.
	 */
	pexpect(t->child.sec_label.ptr == NULL);
	d->child.sec_label = clone_hunk(sec_label, __func__);

	update_selectors(d);
	add_connection_spds(d, address_info(d->local->host.addr));

	/* leave breadcrumb */
	pexpect(d->child.newest_routing_sa == SOS_NOBODY);
	set_child_routing(d, d->child.routing, SOS_NOBODY);

	connection_buf tb;
	ldbg_connection(d, where, "%s: from "PRI_CONNECTION,
			__func__, pri_connection(t, &tb));

	return d;
}

struct connection *rw_responder_instantiate(struct connection *t,
					    const ip_address peer_addr,
					    where_t where)
{
	PASSERT(t->logger, (t->policy & POLICY_OPPORTUNISTIC) == LEMPTY);
	PASSERT(t->logger, !labeled(t));

	struct connection *d = instantiate(t, peer_addr, /*TBD peer_id*/NULL,
					   /*update_serial*/true, empty_shunk,
					   __func__, where);

	update_selectors(d);
	add_connection_spds(d, address_info(d->local->host.addr));

	connection_buf tb;
	ldbg_connection(d, where, "%s: from "PRI_CONNECTION,
			__func__, pri_connection(t, &tb));
	return d;
}

struct connection *rw_responder_id_instantiate(struct connection *t,
					       const ip_address remote_addr,
					       const ip_selector *remote_subnet,
					       const struct id *remote_id,
					       where_t where)
{
	PASSERT(t->logger, (t->policy & POLICY_OPPORTUNISTIC) == LEMPTY);
	PASSERT(t->logger, !labeled(t));

	/*
	 * XXX: this function is never called when there are
	 * sec_labels?
	 */
	struct connection *d = instantiate(t, remote_addr, remote_id,
					   /*update_serial*/true, empty_shunk,
					   __func__, where);

	update_subnet_selectors(d, remote_subnet);
	add_connection_spds(d, address_info(d->local->host.addr));

	connection_buf tb;
	ldbg_connection(d, where, "%s: from "PRI_CONNECTION,
			__func__, pri_connection(t, &tb));
	return d;

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

	struct connection *d = instantiate(t, remote_address, /*peer_id*/NULL,
					   /*update_serial*/true, empty_shunk,
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

	PEXPECT(d->logger, oriented(d));
	add_connection_spds(d, address_info(d->local->host.addr));

	connection_buf tb;
	ldbg_connection(d, where, "%s: from "PRI_CONNECTION,
			func, pri_connection(t, &tb));
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
