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
#include "spd_route_db.h"
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

static void discard_connection(struct connection **cp, bool connection_valid);

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
			 enum_name_short(&routing_names, c->child.routing),
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

/*
 * Is there an existing connection with NAME?
 */

bool connection_with_name_exists(const char *name)
{
	struct connection_filter cq = {
		.name = name,
		.where = HERE,
	};
	while (next_connection_new2old(&cq)) {
		return true;
	}
	return false;
}

/* Delete a connection */
static void discard_spd_end_content(struct spd_end *e)
{
	virtual_ip_delref(&e->virt);
}

static void discard_spd_content(struct spd_route *spd)
{
	spd_route_db_del(spd);
	FOR_EACH_THING(end, LEFT_END, RIGHT_END) {
		discard_spd_end_content(&spd->end[end]);
	}
}

void discard_connection_spds(struct connection *c)
{
	FOR_EACH_ITEM(spd, &c->child.spds) {
		discard_spd_content(spd);
	}
	pfreeany(c->child.spds.list);
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
 */

void delete_connection(struct connection **cp)
{
	if (is_instance(*cp)) {
		/* XXX: pointless check? */
		if (!is_opportunistic(*cp)) {
			/* XXX: pointless log? */
			address_buf b;
			llog(RC_LOG, (*cp)->logger,
			     "deleting connection instance with peer %s",
			     str_address_sensitive(&(*cp)->remote->host.addr, &b));
		}
	}

	discard_connection(cp, true/*connection_valid*/);
}

static void discard_connection(struct connection **cp, bool connection_valid)
{
	struct connection *c = *cp;
	*cp = NULL;

	ldbg(c->logger, "%s() %s "PRI_CO" cloned from "PRI_CO,
	     __func__, c->name,
	     pri_connection_co(c),
	     pri_connection_co(c->clonedfrom));

	/*
	 * Must be unrouted (i.e., all policies have been pulled).
	 */
	if (c->child.routing != RT_UNROUTED) {
		enum_buf rn;
		llog_passert(c->logger, HERE,
			     "connection still %s",
			     str_enum_short(&routing_names, c->child.routing, &rn));
	}

	/*
	 * Must not be pending (i.e., not on a queue waiting for an
	 * IKE SA to establish).
	 */
	PASSERT(c->logger, !connection_is_pending(c));

	/*
	 * Must have newest all cleared.
	 */
	if (c->newest_ike_sa != SOS_NOBODY) {
		llog_passert(c->logger, HERE,
			     "connection still has %s "PRI_SO,
			     c->config->ike_info->ike_sa_name,
			     pri_so(c->newest_ike_sa));
	}
	if (c->newest_ipsec_sa != SOS_NOBODY) {
		llog_passert(c->logger, HERE,
			     "connection still has %s "PRI_SO,
			     c->config->ike_info->child_sa_name,
			     pri_so(c->newest_ipsec_sa));
	}
	if (c->child.newest_routing_sa != SOS_NOBODY) {
		llog_passert(c->logger, HERE,
			     "connection still has routing SA "PRI_SO,
			     pri_so(c->child.newest_routing_sa));
	}

	/*
	 * Must not have instances (i.e., all intantiations are gone).
	 */
	struct connection_filter instance = {
		.clonedfrom = c,
		.where = HERE,
	};
	if (next_connection_old2new(&instance)) {
		connection_buf cb;
		llog_passert(c->logger, HERE,
			     "connection still instantiated as "PRI_CONNECTION,
			     pri_connection(instance.c, &cb));
	}

	/*.
	 * Must not have states (i.e., no states are refering to this
	 * connection).
	 */
	struct state_filter state = {
		.connection_serialno = c->serialno,
		.where = HERE,
	};
	if (next_state_new2old(&state)) {
		state_buf sb;
		llog_passert(c->logger, HERE,
			     "connection is still being used by %s "PRI_STATE,
			     sa_name(state.st->st_connection->config->ike_version,
				     state.st->st_sa_type_when_established),
			     pri_state(state.st, &sb));
	}

	/*
	 * Finall start cleanup.
	 */

	FOR_EACH_ELEMENT(afi, ip_families) {
		if (c->pool[afi->ip_index] != NULL) {
			free_that_address_lease(c, afi);
			addresspool_delref(&c->pool[afi->ip_index]);
		}
	}

	if (IS_XFRMI && c->xfrmi != NULL)
		unreference_xfrmi(c);

	/* find and delete c from the host pair list */
	host_pair_remove_connection(c, connection_valid);

	flush_connection_events(c);

	if (connection_valid) {
		connection_db_del(c);
	}
	discard_connection_spds(c);

	FOR_EACH_ELEMENT(end, c->end) {
		free_id_content(&end->host.id);
		pfreeany(end->child.selectors.accepted.list);
	}

	remove_from_group(c);

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
		passert(co_serial_is_unset(c->clonedfrom));
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
		pfreeany(config->ppk_ids);
		if (config->ppk_ids_shunks != NULL) {
			pfree(config->ppk_ids_shunks);
		}
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

void delete_every_connection(void)
{
	/*
	 * Keep deleting the newest connection until there isn't one.
	 *
	 * Deleting new-to-old means that instances are deleted before
	 * templates.  Picking away at the queue avoids the posability
	 * of a cascading delete deleting multiple connections.
	 */
	while (true) {
		struct connection_filter cq = { .where = HERE, };
		if (!next_connection_new2old(&cq)) {
			break;
		}
		struct connection *c = cq.c;

		remove_connection_from_pending(c);
		delete_states_by_connection(c);
		connection_unroute(c, HERE);

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

	if (src->groundhog != NULL) {
		err_t e = ttobool(src->groundhog, &host_config->groundhog);
		if (e != NULL) {
			return diag("%sgroundhog=%s, %s", leftright, src->groundhog, e);
		}
		if (host_config->groundhog && libreswan_fipsmode()) {
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
		if ((wm->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
			return d;
		}
		llog_diag(RC_LOG, logger, &d, "opportunistic: ");
	}

	if (src->modecfg_server && src->cat) {
		diag_t d = diag("both %smodecfgserver=yes and %scat=yes defined",
				leftright, leftright);
		if ((wm->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
			return d;
		}
		llog_diag(RC_LOG, logger, &d, "opportunistic: ");
	}

	if (src->modecfg_client && other_src->cat) {
		diag_t d = diag("both %smodecfgclient=yes and %scat=yes defined",
				leftright, other_src->leftright);
		if ((wm->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
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
		if ((wm->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
			return d;
		}
		llog_diag(RC_LOG, logger, &d, "opportunistic: ");
	}

	if (src->cat && other_src->addresspool != NULL) {
		diag_t d = diag("both %scat=yes and %saddresspool= defined",
				leftright, other_src->leftright);
		if ((wm->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
			return d;
		}
		llog_diag(RC_LOG, logger, &d, "opportunistic: ");
	}

	if (src->modecfg_client && other_src->addresspool != NULL) {
		diag_t d = diag("both %smodecfgclient=yes and %saddresspool= defined",
				leftright, other_src->leftright);
		if ((wm->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
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

	if (child_selectors->len > 1 && wm->connalias != NULL) {
		/* XXX: don't know which end has subnets= */
		return diag("multi-selector \"%ssubnet=%s\" combined with subnets=",
			    leftright, src->subnet);
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
	if (libreswan_fipsmode()) {
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

void alloc_connection_spds(struct connection *c, unsigned nr_spds)
{
	PASSERT(c->logger, c->child.spds.len == 0);
	ldbg(c->logger, "allocating %u SPDs", nr_spds);
	c->child.spds = (struct spds) {
		.len = nr_spds,
		.list = alloc_things(struct spd_route, nr_spds, "spds"),
	};
	c->spd = c->child.spds.list;
	FOR_EACH_ITEM(spd, &c->child.spds) {
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
		spd_route_db_init_spd_route(spd);
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
				struct spd_route *spd = &c->child.spds.list[spds++];
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
				spd_route_db_add(spd);
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
	if (libreswan_fipsmode()) {
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
		     "%s%s=%ju seconds exceeds maximum of %ju seconds, seting to the maximum allowed",
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
	if (wm->is_connection_group) {
		ldbg(logger, "%s connection is CK_GROUP: by .connection_group",
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
		if (!NEVER_NEGOTIATE(wm->policy) &&
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

static diag_t extract_shunt(const char *shunt_name,
			    struct config *config,
			    const struct whack_message *wm,
			    enum shunt_kind shunt_kind,
			    enum shunt_policy unset_shunt)
{
	enum shunt_policy shunt_policy = wm->shunt[shunt_kind];
	if (shunt_policy == SHUNT_UNSET) {
		shunt_policy = unset_shunt;
	}
	if (!shunt_ok(shunt_kind, shunt_policy)) {
		enum_buf sb;
		return diag("%sshunt=%s invalid",
			    shunt_name, str_enum_short(&shunt_policy_names, shunt_policy, &sb));
	}
	config->shunt[shunt_kind] = shunt_policy;
	return NULL;
}

/*
 * Allocate connections.
 */

void finish_connection(struct connection *c, const char *name,
		       struct connection *t,
		       const struct config *config,
		       lset_t debugging, struct fd *whackfd,
		       where_t where)
{
	/* announce it (before code below logs its address) */
	dbg_alloc(name, c, where);

	c->name = clone_str(name, __func__);
	c->logger = alloc_logger(c, &logger_connection_vec,
				 debugging, whackfd, where);

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
	c->clonedfrom = t;
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

static struct connection *alloc_connection(const char *name,
					   lset_t debugging, struct fd *whackfd,
					   where_t where)
{
	struct connection *c = alloc_thing(struct connection, where->func);

	/*
	 * Allocate the configuration - only allocated on root
	 * connection; connection instances (clones) inherit these
	 * pointers.
	 */
	c->root_config = alloc_config();

	finish_connection(c, name, NULL/*no template*/,
			  c->root_config,
			  debugging, whackfd, where);

	return c;
}

static bool extract_yn(enum yn_options yn, bool unset)
{
	switch (yn) {
	case YN_NO: return false;
	case YN_YES: return true;
	case YN_UNSET: return unset;
	}
	bad_case(yn);
}

static diag_t extract_connection(const struct whack_message *wm,
				 struct connection *c)
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
	struct config *config = c->root_config; /* writeable; root only */
	passert(c->name != NULL); /* see alloc_connection() */

	if ((wm->policy & POLICY_TUNNEL) == LEMPTY) {
		if (wm->sa_tfcpad != 0) {
			return diag("connection with type=transport cannot specify tfc=");
		}
		if (wm->vti_iface != NULL) {
			return diag("VTI requires tunnel mode but connection specifies type=transport");
		}
	}
	if (LIN(POLICY_AUTHENTICATE, wm->policy)) {
		if (wm->sa_tfcpad != 0) {
			return diag("connection with phase2=ah cannot specify tfc=");
		}
	}

	if (wm->authby.never) {
		if (wm->never_negotiate_shunt == SHUNT_UNSET) {
			return diag("connection with authby=never must specify shunt type via type=");
		}
	}
	if (wm->never_negotiate_shunt != SHUNT_UNSET) {
		if (!authby_eq(wm->authby, (struct authby) { .never = true, })) {
			return diag("shunt connection cannot have authentication method other then authby=never");
		}
	} else {
		switch (wm->policy & (POLICY_AUTHENTICATE | POLICY_ENCRYPT)) {
		case LEMPTY:
			if (!wm->authby.never) {
				return diag("non-shunt connection must have AH or ESP");
			}
			break;
		case POLICY_AUTHENTICATE | POLICY_ENCRYPT:
			return diag("non-shunt connection must not specify both AH and ESP");
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
			.ike_name = "ISAKMP",
			.child_name = "IPsec",
			.ike_sa_name = "ISAKMP SA",
			.child_sa_name = "IPsec SA",
			.replace_event = EVENT_v1_REPLACE,
		},
		[IKEv2] = {
			.version = IKEv2,
			.version_name = "IKEv2",
			.ike_name = "IKE",
			.child_name = "Child",
			.ike_sa_name = "IKE SA",
			.child_sa_name = "Child SA",
			.replace_event = EVENT_v2_REPLACE,
		},
	};
	PASSERT(c->logger, wm->ike_version < elemsof(ike_info));
	PASSERT(c->logger, ike_info[wm->ike_version].version > 0);
	config->ike_info = &ike_info[wm->ike_version];

	if (wm->policy & POLICY_OPPORTUNISTIC &&
	    c->config->ike_version < IKEv2) {
		return diag("opportunistic connection MUST have IKEv2");
	}

	if (wm->policy & POLICY_MOBIKE &&
	    c->config->ike_version < IKEv2) {
		return diag("MOBIKE requires IKEv2");
	}

	if ((wm->policy & POLICY_MOBIKE) &&
	    (wm->policy & POLICY_TUNNEL) == LEMPTY) {
		return diag("MOBIKE requires tunnel mode");
	}

	if (wm->policy & POLICY_MOBIKE) {
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

	/* RFC 8229 TCP encap*/

	if (NEVER_NEGOTIATE(wm->policy)) {
		if (wm->enable_tcp != 0) {
			enum_buf eb;
			llog(RC_INFORMATIONAL, c->logger,
			     "warning: enable-tcp=%s ignored for type=passthrough connection",
			     str_enum_short(&tcp_option_story, wm->enable_tcp, &eb));
		}
		/* cleanup inherited default; XXX: ? */
		config->iketcp = IKE_TCP_NO;
	} else if (c->config->ike_version < IKEv2) {
		if (wm->enable_tcp != 0 &&
		    wm->enable_tcp != IKE_TCP_NO) {
			return diag("enable-tcp= requires IKEv2");
		}
		config->iketcp = IKE_TCP_NO;
	} else if (wm->enable_tcp == 0) {
		config->iketcp = IKE_TCP_NO; /* default */
	} else {
		config->iketcp = wm->enable_tcp;
	}

	switch (config->iketcp) {
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
		bad_case(config->iketcp);
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
	c->policy = wm->policy;

	config->ikev2_allow_narrowing =
		extract_yn(wm->ikev2_allow_narrowing,
			   (wm->ike_version == IKEv2 && (wm->left.addresspool != NULL ||
							 wm->right.addresspool != NULL)));
	if (config->ikev2_allow_narrowing &&
	    wm->ike_version < IKEv2) {
		return diag("narrowing=yes requires IKEv2");
	}

	config->rekey = extract_yn(wm->rekey, true);
	config->reauth = extract_yn(wm->reauth, false);

	config->autostart = wm->autostart;
	switch (wm->autostart) {
	case AUTOSTART_KEEP:
	case AUTOSTART_START:
		ldbg(c->logger, "autostart=%s implies +POLICY_UP",
		     enum_name_short(&autostart_names, wm->autostart));
		add_policy(c, POLICY_UP);
		break;
	case AUTOSTART_IGNORE:
	case AUTOSTART_ADD:
	case AUTOSTART_ONDEMAND:
		break;
	}

	d = extract_shunt("never-negotiate", config, wm,
			  SHUNT_KIND_NEVER_NEGOTIATE,
			  /*unset*/SHUNT_UNSET);
	if (d != NULL) {
		return d;
	}

	d = extract_shunt("negotiation", config, wm,
			  SHUNT_KIND_NEGOTIATION,
			  /*unset*/SHUNT_HOLD);
	if (d != NULL) {
		return d;
	}

	if (libreswan_fipsmode() && config->negotiation_shunt == SHUNT_PASS) {
		enum_buf sb;
		llog(RC_LOG_SERIOUS, c->logger,
		     "FIPS: ignored negotiationshunt=%s - packets MUST be blocked in FIPS mode",
		     str_enum_short(&shunt_policy_names, config->negotiation_shunt, &sb));
		config->negotiation_shunt = SHUNT_HOLD;
	}

	d = extract_shunt("failure", config, wm,
			  SHUNT_KIND_FAILURE,
			  /*unset*/SHUNT_NONE);
	if (d != NULL) {
		return d;
	}

	/* make kernel code easier */
	config->shunt[SHUNT_KIND_BLOCK] = SHUNT_DROP;
	config->shunt[SHUNT_KIND_ONDEMAND] = SHUNT_TRAP;

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
		del_policy(c, POLICY_ESN_YES);
		add_policy(c, POLICY_ESN_NO);
#ifdef USE_IKEv1
	} else if (wm->ike_version == IKEv1) {
#if 0
		dbg("ESN: disabled as not implemented with IKEv1");
		del_policy(c, POLICY_ESN_YES);
		add_policy(c, POLICY_ESN_NO);
#else
		dbg("ESN: ignored as not implemented with IKEv1");
#endif
#endif
	} else if (!kernel_ops->esn_supported) {
		llog(RC_LOG, c->logger,
		     "kernel interface does not support ESN so disabling");
		del_policy(c, POLICY_ESN_YES);
		add_policy(c, POLICY_ESN_NO);
	} else if (wm->sa_replay_window > kernel_ops->max_replay_window) {
		return diag("replay-window=%ju exceeds %s limit of %ju",
			    wm->sa_replay_window,
			    kernel_ops->interface_name, kernel_ops->max_replay_window);
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

	if (NEVER_NEGOTIATE(wm->policy)) {
		if (wm->esp != NULL) {
			llog(RC_INFORMATIONAL, c->logger,
			     "ignored esp= option for type=passthrough connection");
		}
	} else if (wm->esp != NULL ||
		   (c->config->ike_version == IKEv2 &&
		    (c->policy & (POLICY_ENCRYPT|POLICY_AUTHENTICATE)))) {

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
			diag_t d = parser->diag; parser->diag = NULL;
			free_proposal_parser(&parser);
			return d;
		}
		free_proposal_parser(&parser);

		LDBGP_JAMBUF(DBG_BASE, c->logger, buf) {
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

		config->nic_offload = wm->nic_offload;

		config->sa_rekey_margin = wm->sa_rekey_margin;
		config->sa_rekey_fuzz = wm->sa_rekeyfuzz_percent;
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

		const struct timescale *const dpd_timescale = &timescale_seconds;
		switch (wm->ike_version) {
		case IKEv1:
			/* IKEv1's RFC 3706 DPD */
			if (wm->dpd_delay != NULL &&
			    wm->dpd_timeout != NULL) {
				if (wm->dpd_action != DPD_ACTION_UNSET) {
					llog(RC_LOG, c->logger,
					     "warning: IKEv1 ignores dpdaction=");
				}
				diag_t d;
				d = ttodeltatime(wm->dpd_delay,
						 &config->dpd.delay,
						 dpd_timescale);
				if (d != NULL) {
					return diag_diag(&d, "dpddelay=%s invalid, ",
							 wm->dpd_delay);
				}
				d = ttodeltatime(wm->dpd_timeout,
						 &config->dpd.timeout,
						 dpd_timescale);
				if (d != NULL) {
					return diag_diag(&d, "dpdtimeout=%s invalid, ",
							 wm->dpd_timeout);
				}
				deltatime_buf db, tb;
				ldbg(c->logger, "IKEv1 dpd.timeout=%s dpd.delay=%s",
				     str_deltatime(config->dpd.timeout, &db),
				     str_deltatime(config->dpd.delay, &tb));
			} else if (wm->dpd_action != DPD_ACTION_UNSET) {
				llog(RC_LOG, c->logger,
				     "warning: IKEv1 ignores dpdaction=, use dpdtimeout= and dpddelay=");
			} else if (wm->dpd_delay != NULL  ||
				   wm->dpd_timeout != NULL) {
				llog(RC_LOG, c->logger,
				     "warning: IKEv1 dpd settings are ignored unless both dpdtimeout= and dpddelay= are set");
			}
			break;
		case IKEv2:
			if (wm->dpd_delay != NULL) {
				diag_t d;
				d = ttodeltatime(wm->dpd_delay,
						 &config->dpd.delay,
						 dpd_timescale);
				if (d != NULL) {
					return diag_diag(&d, "dpddelay=%s invalid, ",
							 wm->dpd_delay);
				}
			}
			if (wm->dpd_timeout != NULL ||
			    wm->dpd_action != DPD_ACTION_UNSET) {
				/* actual values don't matter */
				llog(RC_LOG, c->logger,
				     "warning: IKEv2 ignores dpdtimeout= and dpdaction=; use dpddelay= and retransmit-timeout=");
			}
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
			return diag_diag(&d, "modecfgdns=%s invalid: ", wm->modecfg_dns);
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

		/* RFC 8784 and draft-smyslov-ipsecme-ikev2-qr-alt-07 */
		config->ppk_ids = clone_str(wm->ppk_ids, "connection ppk_ids");
		if (config->ppk_ids != NULL) {
			config->ppk_ids_shunks = shunks(shunk1(config->ppk_ids),
							", ",
							EAT_EMPTY_SHUNKS,
							HERE); /* process into shunks once */
		}

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
				return diag("ipsec-interface=%u not supported. %s",
					    wm->xfrm_if_id, err);
			}
			if (!setup_xfrm_interface(c, (wm->xfrm_if_id == 0 ? PLUTO_XFRMI_REMAP_IF_ID_ZERO :
						      wm->xfrm_if_id))) {
				/* XXX: never happens?!? */
				return diag("setup xfrmi interface failed");
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
		if ((wm->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
			return d;
		}
		llog_diag(RC_LOG, c->logger, &d, "opportunistic: ");
	}

	if (wm->left.modecfg_client && wm->right.modecfg_client) {
		diag_t d = diag("both left and right define modecfgclient=yes");
		if ((wm->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
			return d;
		}
		llog_diag(RC_LOG, c->logger, &d, "opportunistic: ");
	}

	if (wm->left.cat && wm->right.cat) {
		diag_t d = diag("both left and right define cat=yes");
		if ((wm->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
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
		if ((wm->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
			return d;
		}
		llog_diag(RC_LOG, c->logger, &d, "opportunistic: ");
	}

	if (config->end[LEFT_END].host.modecfg.client &&
	    config->end[RIGHT_END].host.modecfg.client) {
		diag_t d = diag("both left and right are configured as a client");
		if ((wm->policy & POLICY_OPPORTUNISTIC) == LEMPTY) {
			return d;
		}
		llog_diag(RC_LOG, c->logger, &d, "opportunistic: ");
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

	if (c->local->host.config->xauth.server || c->remote->host.config->xauth.server) {
		add_policy(c, POLICY_XAUTH);
	}

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
	 * and try to re-install another negotiation or failure shunt.
	 */
	if (wm->keyingtries.set) {
		if (NEVER_NEGOTIATE(wm->policy)) {
			llog(RC_LOG, c->logger,
			     "warning: keyingtries=%ju ignored, connection will never negotiate",
			     wm->keyingtries.value);
		} else if ((wm->policy & POLICY_OPPORTUNISTIC) &&
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
	ldbg(c->logger, "child.reqid=%d because c->sa_reqid=%d (%s)",
	     c->child.reqid, c->config->sa_reqid,
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

	/* this triggers a rehash of the SPDs */
	orient(&c, c->logger);

	connect_to_host_pair(c);

	return NULL;
}

void add_connection(const struct whack_message *wm, struct logger *logger)
{
	/*
	 * Check for duplicate before allocating; otherwise the lookup
	 * will return the just allocated connection missing the
	 * original.
	 */
	if (connection_with_name_exists(wm->name)) {
		llog(RC_DUPNAME, logger,
		     "attempt to redefine connection \"%s\"", wm->name);
		return;
	}

	/* will inherit defaults */
	lset_t debugging = lmod(LEMPTY, wm->debugging);
	struct connection *c = alloc_connection(wm->name,
						debugging | wm->conn_debug,
						logger->global_whackfd,
						HERE);

	diag_t d = extract_connection(wm, c);
	if (d != NULL) {
		llog_diag(RC_FATAL, c->logger, &d, ADD_FAILED_PREFIX);
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

	/* connection is good-to-go: log against it */
	err_t tss = connection_requires_tss(c);
	if (tss != NULL) {
		llog(RC_LOG, c->logger, "connection is using multiple %s", tss);
	}
	const char *what = (never_negotiate(c) ? policy_shunt_names[c->config->never_negotiate_shunt] :
			    c->config->ike_info->version_name);
	llog(RC_LOG, c->logger, "added %s connection", what);
	policy_buf pb;
	dbg("ike_life: %jd; ipsec_life: %jds; rekey_margin: %jds; rekey_fuzz: %lu%%; replay_window: %u; policy: %s ipsec_max_bytes: %ju ipsec_max_packets %ju",
	    deltasecs(c->config->sa_ike_max_lifetime),
	    deltasecs(c->config->sa_ipsec_max_lifetime),
	    deltasecs(c->config->sa_rekey_margin),
	    c->config->sa_rekey_fuzz,
	    c->sa_replay_window,
	    str_connection_policies(c, &pb),
	    c->config->sa_ipsec_max_bytes,
	    c->config->sa_ipsec_max_packets);
	spd_buf spdb;
	dbg("%s", str_spd(c->spd, &spdb));
	release_whack(c->logger, HERE);
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

static size_t jam_connection_serials(struct jambuf *buf, const struct connection *c)
{
	size_t s = 0;
	if (c->instance_serial > 0) {
		if (c->clonedfrom != NULL) {
			s += jam_connection_serials(buf, c->clonedfrom);
		}
		s += jam(buf, "[%lu]", c->instance_serial);
	}
	return s;
}

size_t jam_connection_instance(struct jambuf *buf, const struct connection *c)
{
	/*
	 * Not PEXPECT(c->connection) as that will recursively call
	 * this function when trying to log prefix.
	 */
	if (!pexpect(is_instance(c))) {
		return 0;
	}
	size_t s = 0;
	s += jam_connection_serials(buf, c);
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
	s += jam(buf, "\"%s\"", c->name);
	if (c->instance_serial > 0) {
		s += jam_connection_instance(buf, c);
	}
	return s;
}

const char *str_connection_instance(const struct connection *c, connection_buf *buf)
{
	struct jambuf p = ARRAY_AS_JAMBUF(buf->buf);
	if (c->instance_serial > 0) {
		jam_connection_instance(&p, c);
	}
	return buf->buf;
}

size_t jam_connection_policies(struct jambuf *buf, const struct connection *c)
{
	const char *sep = "";
	size_t s = 0;
	enum shunt_policy shunt;
	lset_t policy = c->policy;

	if (c->config->ike_version > 0) {
		s += jam_string(buf, c->config->ike_info->version_name);
		sep = "+";
	}

	struct authby authby = c->local->host.config->authby;
	if (authby_is_set(authby)) {
		s += jam_string(buf, sep);
		s += jam_authby(buf, authby);
		sep = "+";
	}

#define PP(P)					\
	if (policy & POLICY_##P) {		\
		s += jam_string(buf, sep);	\
		s += jam_string(buf, #P);	\
		sep = "+";			\
		policy &= ~POLICY_##P;		\
	}
#define CP(C)						\
	if (c->config->C) {				\
		s += jam_string(buf, sep);		\
		s += jam_ucase_string(buf, #C);		\
		sep = "+";				\
	}

	PP(ENCRYPT);
	PP(AUTHENTICATE);
	PP(COMPRESS);
	PP(TUNNEL);
	PP(PFS);
	PP(DECAP_DSCP);
	PP(NOPMTUDISC);
	PP(MSDH_DOWNGRADE);
	PP(ALLOW_NO_SAN);
	PP(DNS_MATCH_ID);
	PP(SHA2_TRUNCBUG);

	/* note reversed logic */
	if (!c->config->rekey) {
		s += jam_string(buf, sep);
		s += jam_string(buf, "DONT_REKEY");
		sep = "+";
	}

	CP(reauth);

	PP(OPPORTUNISTIC);
	PP(GROUPINSTANCE);
	PP(ROUTE);
	PP(UP);
	PP(XAUTH);
	PP(MODECFG_PULL);
	PP(AGGRESSIVE);
	PP(OVERLAPIP);

	CP(ikev2_allow_narrowing);

	PP(IKEV2_PAM_AUTHORIZE);

	PP(SEND_REDIRECT_ALWAYS);
	PP(SEND_REDIRECT_NEVER);
	PP(ACCEPT_REDIRECT_YES);

	PP(IKE_FRAG_ALLOW);
	PP(IKE_FRAG_FORCE);
	PP(NO_IKEPAD);
	PP(MOBIKE);
	PP(PPK_ALLOW);
	PP(PPK_INSIST);
	PP(ESN_NO);
	PP(ESN_YES);
	PP(INTERMEDIATE);
	PP(IGNORE_PEER_DNS);

	/* just in case something was missed */
	if (policy != LEMPTY) {
		s += jam_string(buf, sep);
		s += jam_lset_short(buf, &sa_policy_bit_names, "+", policy);
		sep = "+";
	}

	if (is_group(c)) {
		s += jam_string(buf, sep);
		s += jam_string(buf, "GROUP");
		sep = "+";
	}

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

	if (never_negotiate(c)) {
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
	while (next_connection_new2old(&cq)) {
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
		 * its template, then let it be resued for an outgoing
		 * connection?!?
		 */
		bool instance_initiation_ok =
			(is_opportunistic(c) &&
			 is_instance(c) &&
			 pexpect(c->clonedfrom != NULL) /* because instance */ &&
			 routed(c->clonedfrom));
		if (!routed(c) && !instance_initiation_ok &&
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
		while (next_connection_new2old(&cq)) {
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
		while (next_connection_new2old(&cq)) {
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

	if (c->going_away) {
		connection_buf cb;
		dbg("connection "PRI_CONNECTION" is going away, skipping delete-unused",
		    pri_connection(c, &cb));
		return;
	}

	if (!is_instance(c)) {
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
	attach_fd(c->logger, whackfd);

	remove_connection_from_pending(c);
	delete_states_by_connection(c);
	connection_unroute(c, HERE);

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
	return (c != NULL && NEVER_NEGOTIATE(c->policy));
}

bool is_opportunistic(const struct connection *c)
{
	return (c != NULL && (c->policy & POLICY_OPPORTUNISTIC));
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

bool is_labeled(const struct connection *c)
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
		PASSERT(c->logger, c->config->sec_label.len > 0);
		return true;
	case CK_TEMPLATE:
	case CK_PERMANENT:
	case CK_GROUP:
	case CK_INSTANCE:
		PASSERT(c->logger, c->config->sec_label.len == 0);
		return false;
	}
	bad_case(c->local->kind);
}

bool is_labeled_template(const struct connection *c)
{
	if (c == NULL) {
		return false;
	}
	switch (c->local->kind) {
	case CK_INVALID:
		break;
	case CK_LABELED_TEMPLATE:
		PASSERT(c->logger, (c->config->sec_label.len > 0 &&
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

bool is_labeled_parent(const struct connection *c)
{
	if (c == NULL) {
		return false;
	}
	switch (c->local->kind) {
	case CK_INVALID:
		break;
	case CK_LABELED_PARENT:
		PASSERT(c->logger, (c->config->sec_label.len > 0 &&
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

bool is_labeled_child(const struct connection *c)
{
	if (c == NULL) {
		return false;
	}
	switch (c->local->kind) {
	case CK_INVALID:
		break;
	case CK_LABELED_CHILD:
		PASSERT(c->logger, (c->config->sec_label.len > 0 &&
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
