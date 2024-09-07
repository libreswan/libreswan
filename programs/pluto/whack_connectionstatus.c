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
 * Copyright (C) 2016-2022 Andrew Cagney <cagney@gnu.org>
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

#include "whack_connectionstatus.h"
#include "whack_connection.h"

#include "ike_alg.h"

#include "defs.h"
#include "connections.h"
#include "orient.h"
#include "virtual_ip.h"        /* needs connections.h */
#include "ipsec_interface.h"
#include "iface.h"
#include "nat_traversal.h"
#include "log.h"
#include "show.h"
#include "crypto.h"		/* for show_ike_alg_connection() */
#include "plutoalg.h"	/* for show_kernel_alg_connection() */
#include "kernel.h"		/* for enum direction */
#include "sparse_names.h"

/* Passed in to jam_end_client() */
static const char END_SEPARATOR[] = "===";

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

void jam_end_host(struct jambuf *buf,
		  const struct connection *c,
		  const struct host_end *end)
{
	/* HOST */
	if (!address_is_specified(end->addr)) {
		if (end->config->type == KH_IPHOSTNAME) {
			jam_string(buf, "%dns");
			jam(buf, "<%s>", end->config->addr_name);
		} else {
			if (is_group(c)) {
				if (is_opportunistic(c)) {
					jam_string(buf, "%opportunisticgroup");
				} else {
					jam_string(buf, "%group");
				}
			} else if (is_opportunistic(c)) {
				jam_string(buf, "%opportunistic");
			} else {
				jam_string(buf, "%any");
			}
		}
		/*
		 * XXX: only print anomalies: since the host address
		 * is zero, so too should be the port.
		 */
		if (end->port != 0) {
			jam(buf, ":%u", end->port);
		}
	} else {
		/* ADDRESS[:PORT][<HOSTNAME>] */
		/*
		 * XXX: only print anomalies: when the host address is
		 * valid, any hardwired IKEPORT or a port other than
		 * IKE_UDP_PORT.
		 */
		bool include_port = (end->config->ikeport != 0 ||
				     end->port != IKE_UDP_PORT);
		if (!log_ip) {
			/* ADDRESS(SENSITIVE) */
			jam_string(buf, "<address>");
		} else if (include_port) {
			/* [ADDRESS]:PORT */
			jam_address_wrapped(buf, &end->addr);
			jam(buf, ":%u", end->port);
		} else {
			/* ADDRESS */
			jam_address(buf, &end->addr);
		}
		/* [<HOSTNAME>] */
		address_buf ab;
		if (end->config->addr_name != NULL &&
		    !streq(str_address(&end->addr, &ab),
			   end->config->addr_name)) {
			jam(buf, "<%s>", end->config->addr_name);
		}
	}
}

void jam_end_client(struct jambuf *buf, const struct connection *c,
		    const struct spd_end *this, enum left_right left_right,
		    const char *separator)
{
	/* left: [CLIENT/PROTOCOL:PORT===] or right: [===CLIENT/PROTOCOL:PORT] */

	if (!this->client.is_set) {
		return;
	}

	if (selector_eq_address(this->client, this->host->addr)) {
		return;
	}

	if (selector_is_all(this->client)) {
		if (is_group(c) || is_opportunistic(c)) {
			/* booring */
			return;
		}
		if (this->host->config->pool_ranges.len > 0) {
			/*
			 * Suppress zero selectors that were probably derived
			 * from the address pool.
			 */
			return;
		}
	}

	if (left_right == RIGHT_END && separator != NULL) {
		jam_string(buf, separator);
	}

	if (is_virtual_spd_end(this)) {
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

	if (left_right == LEFT_END && separator != NULL) {
		jam_string(buf, separator);
	}
}

static void jam_end_id(struct jambuf *buf, const struct spd_end *this)
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

	if (this->host->config->modecfg.server ||
	    this->host->config->modecfg.client ||
	    this->host->config->xauth.server ||
	    this->host->config->xauth.client ||
	    this->host->config->sendcert != cert_defaultcertpolicy) {

		if (open_paren) {
			jam_string(buf, ",");
		} else {
			open_paren = true;
			jam_string(buf, "[");
		}

		if (this->host->config->modecfg.server)
			jam_string(buf, "MS");
		if (this->host->config->modecfg.client)
			jam_string(buf, "+MC");
		if (this->child->config->has_client_address_translation)
			jam_string(buf, "+CAT");
		if (this->host->config->xauth.server)
			jam_string(buf, "+XS");
		if (this->host->config->xauth.client)
			jam_string(buf, "+XC");

		switch (this->host->config->sendcert) {
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

static void jam_end_nexthop(struct jambuf *buf, const struct spd_end *this,
			    const struct spd_end *that, bool skip_next_hop,
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

void jam_spd_end(struct jambuf *buf, const struct connection *c,
		 const struct spd_end *this, const struct spd_end *that,
		 enum left_right left_right, bool skip_next_hop)
{
	switch (left_right) {
	case LEFT_END:
		/* CLIENT/PROTOCOL:PORT=== */
		jam_end_client(buf, c, this, left_right, END_SEPARATOR);
		/* HOST */
		jam_end_host(buf, c, this->host);
		/* [ID+OPTS] */
		jam_end_id(buf, this);
		/* ---NEXTHOP */
		jam_end_nexthop(buf, this, that, skip_next_hop, left_right);
		break;
	case RIGHT_END:
		/* HOPNEXT--- */
		jam_end_nexthop(buf, this, that, skip_next_hop, left_right);
		/* HOST */
		jam_end_host(buf, c, this->host);
		/* [ID+OPTS] */
		jam_end_id(buf, this);
		/* ===CLIENT/PROTOCOL:PORT */
		jam_end_client(buf, c, this, left_right, END_SEPARATOR);
		break;
	}
}

/*
 * format topology of a connection.
 * Two symmetric ends separated by ...
 */

static void jam_spd_topology(struct jambuf *buf, const struct spd *spd)
{
	jam_spd_end(buf, spd->connection, spd->local, spd->remote,
		    LEFT_END, false);
	jam_string(buf, "...");
	jam_spd_end(buf, spd->connection, spd->remote, spd->local,
		    RIGHT_END, oriented(spd->connection));
}

static void show_one_spd(struct show *s,
			 const struct connection *c,
			 const struct spd *spd)
{
	SHOW_JAMBUF(s, buf) {
		jam_connection_short(buf, c);
		jam_string(buf, ":");
		/* one SPD */
		jam_string(buf, " ");
		jam_spd_topology(buf, spd);
		jam_string(buf, ";");
		/* routing/orienting */
		jam_string(buf, " ");
		if (!oriented(c)) {
			jam_string(buf, "unoriented");
			PEXPECT(show_logger(s), c->routing.state == RT_UNROUTED);
		} else {
			jam_enum_human(buf, &routing_names, c->routing.state);
		}
		jam_string(buf, ";");
#define OPT_HOST(H)					\
		if (address_is_specified(H)) {		\
			jam_address(buf, &(H));		\
		} else {				\
			jam_string(buf, "unset");	\
		}
		/* my_ip */
		ip_address my_sourceip = spd_end_sourceip(spd->local);
		jam_string(buf, " my_ip=");
		OPT_HOST(my_sourceip);
		jam_string(buf, ";");
		/* their_ip */
		ip_address their_sourceip = spd_end_sourceip(spd->remote);
		jam_string(buf, " their_ip=");
		OPT_HOST(their_sourceip);
		jam_string(buf, ";");
#undef OPT_HOST
	}


}

static void jam_connection_owners(struct jambuf *buf,
				  const struct connection *c,
				  enum connection_owner owner_floor,
				  enum connection_owner owner_roof)
{
	for (enum connection_owner owner = owner_floor;
	     owner < owner_roof; owner++) {
		if (c->routing.owner[owner] == SOS_NOBODY) {
			continue;
		}
		if (owner + 1 < owner_roof &&
		    c->routing.owner[owner] == c->routing.owner[owner+1]) {
			continue;
		}

		jam_string(buf, " ");
		switch (owner) {
		case NEGOTIATING_IKE_SA:
		case NEGOTIATING_CHILD_SA:
			jam_string(buf, "negotiating");
			break;
		case ESTABLISHED_IKE_SA:
		case ESTABLISHED_CHILD_SA:
			jam_string(buf, "established");
			break;
		case ROUTING_SA:
			jam_string(buf, "routing");
			break;
		}
		jam_string(buf, " ");
		switch (owner) {
		case NEGOTIATING_IKE_SA:
		case ESTABLISHED_IKE_SA:
			jam_string(buf, c->config->ike_info->parent_sa_name);
			break;
		case NEGOTIATING_CHILD_SA:
		case ESTABLISHED_CHILD_SA:
			jam_string(buf, c->config->ike_info->child_sa_name);
			break;
		case ROUTING_SA:
			jam_string(buf, "SA");
			break;
		}
		jam_string(buf, ": ");
		jam_so(buf, c->routing.owner[owner]);
		jam_string(buf, ";");
	}
}

static void show_connection_status(struct show *s, const struct connection *c)
{
	/* Show topology. */
	FOR_EACH_ITEM(spd, &c->child.spds) {
		show_one_spd(s, c, spd);
	}

	SHOW_JAMBUF(s, buf) {
		jam_connection_short(buf, c);
		jam_string(buf, ":  ");
		jam_string(buf, " host: ");
		jam_string(buf, (oriented(c) ? "oriented" : "unoriented"));
		jam_string(buf, ";");
		/* details */
		if (oriented(c)) {
			jam_string(buf, " local: ");
			jam_end_host(buf, c, &c->local->host);
			jam_string(buf, ";");
			jam_string(buf, " remote: ");
			jam_end_host(buf, c, &c->remote->host);
			jam_string(buf, ";");
		} else {
			jam_string(buf, " left: ");
			jam_end_host(buf, c, &c->end[LEFT_END].host);
			jam_string(buf, ";");
			jam_string(buf, " right: ");
			jam_end_host(buf, c, &c->end[RIGHT_END].host);
			jam_string(buf, ";");
		}

		jam_connection_owners(buf, c, IKE_SA_OWNER_FLOOR, IKE_SA_OWNER_ROOF);
	}

	SHOW_JAMBUF(s, buf) {
		jam_connection_short(buf, c);
		jam_string(buf, ":  ");
		const char *local_cert = cert_nickname(&c->local->host.config->cert);
		if (local_cert != NULL) {
			jam(buf, " mycert=%s;", local_cert);
		}
		const char *remote_cert = cert_nickname(&c->remote->host.config->cert);
		if (remote_cert != NULL) {
			jam(buf, " peercert=%s;", remote_cert);
		}

#define JAM_UPDOWN(BUF, E)						\
		{							\
			if ((E)->config->child.updown == NULL) {	\
				jam_string(BUF, "<disabled>");		\
			} else {					\
				jam_string(BUF, (E)->config->child.updown); \
			}						\
			jam_string(BUF, ";");				\
		}
		if (oriented(c)) {
			/* left? */
			jam_string(buf, " my_updown=");
			JAM_UPDOWN(buf, c->local);
		} else {
			jam_string(buf, " leftupdown=");
			JAM_UPDOWN(buf, &c->end[LEFT_END]);
			jam_string(buf, " rightupdown=");
			JAM_UPDOWN(buf, &c->end[RIGHT_END]);
		}
#undef JAM_UPDOWN
	}

	/*
	 * Both should not be set, but if they are, we want
	 * to know.
	 *
	 * XXX: better way to do this would be to PBAD() the first
	 * check! Then we'd really know.
	 */
#define COMBO(END)					\
	((END).server && (END).client ? "BOTH!?!" :	\
	 (END).server ? "server" :			\
	 (END).client ? "client" :			\
	 "none")

	SHOW_JAMBUF(s, buf) {
		jam_connection_short(buf, c);
		jam_string(buf, ":  ");
		/*
		 * Both should not be set, but if they are, we
		 * want to know.
		 */
		/* us */
		jam_string(buf, " xauth us:");
		jam_string(buf, COMBO(c->local->config->host.xauth));
		jam_string(buf, ",");
		/* them */
		jam_string(buf, " xauth them:");
		jam_string(buf, COMBO(c->remote->config->host.xauth));
		jam_string(buf, ",");
		/* should really be an enum name */
		jam_string(buf, " ");
		jam_string(buf, (c->local->config->host.xauth.server ?
				 c->config->xauthby == XAUTHBY_FILE ? "xauthby:file;" :
				 c->config->xauthby == XAUTHBY_PAM ? "xauthby:pam;" :
				 "xauthby:alwaysok;" :
				 ""));
		jam_string(buf, " my_username=");
		jam_string(buf, (c->local->config->host.xauth.username == NULL ? "[any]" :
				 c->local->config->host.xauth.username));
		jam_string(buf, ";");
		jam_string(buf, " their_username=");
		jam_string(buf, (c->remote->config->host.xauth.username == NULL ? "[any]" :
				 c->remote->config->host.xauth.username));
		/* jam_string(buf, ";"); */
	}

	SHOW_JAMBUF(s, buf) {
		jam_connection_short(buf, c);
		jam_string(buf, ":   ");
		/*
		 * When showing the AUTH try to show just the AUTH=
		 * text (and append the AUTHBY mask when things don't
		 * match).
		 *
		 * For instance, given authby=null and auth=null, just
		 * show "null".
		 *
		 * But there's a twist: when the oriented peer AUTH
		 * and AUTHBY don't match, show just AUTHBY.  When
		 * authenticating (at least for IKEv2) AUTH is
		 * actually ignored - it's AUTHBY that counts.
		 */
		const char *who = "our";
		FOR_EACH_THING(end, c->local->host.config, c->remote->host.config) {
			jam(buf, "%s auth:", who);
			/*
			 * EXPECT everything except rsasig_v1_5.
			 */
			struct authby expect = authby_from_auth(end->auth);
			struct authby mask = (oriented(c) && end == c->local->host.config ? expect : AUTHBY_ALL);
			expect.rsasig_v1_5 = false;
			struct authby authby = authby_and(end->authby, mask);
			if (authby_eq(authby, expect)) {
				jam_enum_short(buf, &keyword_auth_names, end->auth);
			} else if (oriented(c) && end == c->remote->host.config) {
				jam_authby(buf, end->authby);
			} else {
				jam_enum_short(buf, &keyword_auth_names, end->auth);
				jam_string(buf, "(");
				jam_authby(buf, authby);
				jam_string(buf, ")");
			}
			who = ", their";
		}
		/* eap */
		who = ", our";
		FOR_EACH_THING(end, c->local->host.config, c->remote->host.config) {
			jam(buf, "%s autheap:%s", who,
			    (end->eap == IKE_EAP_NONE ? "none" :
			     end->eap == IKE_EAP_TLS ? "tls" : "???"));
			who = ", their";
		}
		jam_string(buf, ";");
	}

	SHOW_JAMBUF(s, buf) {
		jam_connection_short(buf, c);
		jam_string(buf, ":  ");
		/* mode config */
		jam(buf, " modecfg info:");
		jam(buf, " us:%s,", COMBO(c->local->config->host.modecfg));
		jam(buf, " them:%s,", COMBO(c->remote->config->host.modecfg));
		jam(buf, " modecfg policy:%s,", (c->config->modecfg.pull ? "pull" : "push"));

		jam_string(buf, " dns:");
		if (c->config->modecfg.dns.len == 0) {
			jam_string(buf, "unset,");
		} else {
			const char *sep = "";
			FOR_EACH_ITEM(dns, &c->config->modecfg.dns) {
				jam_string(buf, sep);
				sep = ", ";
				jam_address(buf, dns);
			}
			jam_string(buf, ",");
		}

		jam_string(buf, " domains:");
		if (c->config->modecfg.domains == NULL) {
			jam_string(buf, "unset,");
		} else {
			for (const shunk_t *domain = c->config->modecfg.domains;
			     domain->ptr != NULL; domain++) {
				jam_sanitized_hunk(buf, *domain);
				jam_string(buf, ",");
			}
		}

		jam(buf, " cat:%s;", c->local->config->child.has_client_address_translation ? "set" : "unset");
	}

#undef COMBO

	/* the banner */
	if (c->config->modecfg.banner != NULL) {
		SHOW_JAMBUF(s, buf) {
			jam_connection_short(buf, c);
			jam_string(buf, ":  ");
			/* banner */
			jam_string(buf, " banner:");
			jam_string(buf, c->config->modecfg.banner);
			jam_string(buf, ";");
		}
	}

	/* The first valid sec_label. */
	SHOW_JAMBUF(s, buf) {
		jam_connection_short(buf, c);
		jam_string(buf, ":  ");
		jam_string(buf, " sec_label:");
		if (is_labeled_child(c)) {
			/* negotiated (IKEv2) */
			jam_shunk(buf, c->child.sec_label);
			/* jam_string(buf, ";"); */
		} else if (is_labeled_template(c) ||
			   is_labeled_parent(c)) {
			/* configured */
			jam_shunk(buf, c->config->sec_label);
			/* jam_string(buf, ";"); */
		} else {
			jam_string(buf, "unset;");
		}
	}

	/* Show CAs */
	if (c->local->host.config->ca.ptr != NULL ||
	    c->remote->host.config->ca.ptr != NULL) {
		SHOW_JAMBUF(s, buf) {
			jam_connection_short(buf, c);
			jam_string(buf, ":  ");
			/* CAs */
			jam_string(buf, " CAs: ");
			/* this */
			jam_string(buf, "'");
			jam_dn_or_null(buf, ASN1(c->local->host.config->ca), "%any", jam_sanitized_bytes);
			jam_string(buf, "'");
			/* sep */
			jam_string(buf, "...");
			/* that */
			jam_string(buf, "'");
			jam_dn_or_null(buf, ASN1(c->remote->host.config->ca), "%any", jam_sanitized_bytes);
			jam_string(buf, "'");
		}
	}

	SHOW_JAMBUF(s, buf) {
		jam_connection_short(buf, c);
		jam_string(buf, ":  ");
		jam(buf, " ike_life: %jds;", deltasecs(c->config->sa_ike_max_lifetime));
		jam(buf, " ipsec_life: %jds;", deltasecs(c->config->sa_ipsec_max_lifetime));
		jam_humber_uintmax(buf, " ipsec_max_bytes: ", c->config->sa_ipsec_max_bytes, "B;");
		jam_humber_uintmax(buf, " ipsec_max_packets: ", c->config->sa_ipsec_max_packets, ";");
		jam(buf, " replay_window: %ju;", c->config->child_sa.replay_window);
		jam(buf, " rekey_margin: %jds;", deltasecs(c->config->sa_rekey_margin));
		jam(buf, " rekey_fuzz: %lu%%;", c->config->sa_rekey_fuzz);
	}

	SHOW_JAMBUF(s, buf) {
		jam_connection_short(buf, c);
		jam_string(buf, ":  ");
		jam(buf, " iptfs: %s;", bool_str(c->config->child_sa.iptfs));
		jam(buf, " dont-frag: %s;", bool_str(c->config->child_sa.iptfs_dont_frag));
		jam(buf, " pkt-size: %ju;", c->config->child_sa.iptfs_pkt_size);
		jam(buf, " max-queue-size: %ju", c->config->child_sa.iptfs_max_qsize);
		jam(buf, " drop-time: %ju", c->config->child_sa.iptfs_drop_time);
		jam(buf, " init-delay: %ju", c->config->child_sa.iptfs_init_delay);
		jam(buf, " reorder-window: %ju", c->config->child_sa.iptfs_reord_win);
	}

	SHOW_JAMBUF(s, buf) {
		jam_connection_short(buf, c);
		jam_string(buf, ":  ");
		jam(buf, " retransmit-interval: %jdms;",
		    deltamillisecs(c->config->retransmit_interval));
		jam(buf, " retransmit-timeout: %jds;",
		    deltasecs(c->config->retransmit_timeout));
		/* tcp? */
		jam_string(buf, " iketcp:");
		jam_sparse(buf, &tcp_option_names, c->local->config->host.iketcp);
		jam_string(buf, ";");
		/* tcp-port */
		jam_string(buf, " iketcp-port:");
		jam_hport(buf, c->config->remote_tcpport);
		jam_string(buf, ";");
	}

	SHOW_JAMBUF(s, buf) {
		jam_connection_short(buf, c);
		jam_string(buf, ":  ");
		jam(buf, " initial-contact:%s;", bool_str(c->config->send_initial_contact));
		jam(buf, " cisco-unity:%s;", bool_str(c->config->send_vid_cisco_unity));
		jam(buf, " fake-strongswan:%s;", bool_str(c->config->send_vid_fake_strongswan));
		jam(buf, " send-vendorid:%s;", bool_str(c->config->send_vendorid));
		jam(buf, " send-no-esp-tfc:%s;", bool_str(c->config->send_no_esp_tfc));
	}

	SHOW_JAMBUF(s, buf) {
		jam_connection_short(buf, c);
		jam_string(buf, ":  ");
		/* policy */
		jam_string(buf, " policy: ");
		jam_connection_policies(buf, c);
		if (c->local->host.config->key_from_DNS_on_demand ||
		    c->remote->host.config->key_from_DNS_on_demand) {
			jam_string(buf, "; ");
			if (c->local->host.config->key_from_DNS_on_demand) {
				jam_string(buf, "+lKOD");
			}
			if (c->remote->host.config->key_from_DNS_on_demand) {
				jam_string(buf, "+rKOD");
			}
		}
		jam_string(buf, ";");
	}

	if (c->config->ike_version == IKEv2) {
		SHOW_JAMBUF(s, buf) {
			jam_connection_short(buf, c);
			jam_string(buf, ":  ");
			/* policy */
			jam_string(buf, " v2-auth-hash-policy: ");
			jam_lset_short(buf, &ikev2_hash_algorithm_names, "+",
				       c->config->sighash_policy);
			jam_string(buf, ";");
		}
	}

	SHOW_JAMBUF(s, buf) {
		connection_priority_buf prio;
		jam_connection_short(buf, c);
		jam_string(buf, ":  ");
		/* priority */
		jam(buf, " conn_prio: %s;", str_connection_priority(c, &prio));
		/* .interface: [id_rname@][id_vname] */
		jam_string(buf, " interface: ");
		if (c->config->ipsec_interface.enabled) {
			jam_ipsec_interface_id(buf, c->config->ipsec_interface.id);
			jam_string(buf, "@");
		}
		if (oriented(c)) {
			jam_string(buf, c->iface->real_device_name);
		}
		jam_string(buf, ";");
		/* .metric */
		jam(buf, " metric: %u;", c->config->child_sa.metric);
		/* .connmtu */
		jam_string(buf, " mtu: ");
		if (c->config->child_sa.mtu == 0) {
			jam_string(buf, "unset");
		} else {
			jam(buf, "%d", c->config->child_sa.mtu);
		}
		jam_string(buf, ";");
		/* .sa_priority */
		jam_string(buf, " sa_prio:");
		if (c->config->child_sa.priority == 0) {
			jam_string(buf, "auto");
		} else {
			jam(buf, "%ju", c->config->child_sa.priority);
		}
		jam_string(buf, ";");
		/* .sa_tfcpad */
		jam_string(buf, " sa_tfc:");
		if (c->config->child_sa.tfcpad == 0) {
			jam_string(buf, "none");
		} else {
			jam(buf, "%ju", c->config->child_sa.tfcpad);
		}
		jam_string(buf, ";");
	}


	SHOW_JAMBUF(s, buf) {
		jam_connection_short(buf, c);
		jam_string(buf, ":  ");
		/* .nflog_group */
		jam_string(buf, " nflog-group: ");
		if (c->nflog_group == 0) {
			jam_string(buf, "unset");
		} else {
			jam(buf, "%d", c->nflog_group);
		}
		jam_string(buf, ";");
		/* .sa_marks */
		jam_string(buf, " mark: ");
		if (c->sa_marks.in.val == 0 && c->sa_marks.out.val == 0 ) {
			jam_string(buf, "unset");
		} else {
			jam(buf, "%" PRIu32 "/%#08" PRIx32 ", %" PRIu32 "/%#08" PRIx32,
			    c->sa_marks.in.val, c->sa_marks.in.mask,
			    c->sa_marks.out.val, c->sa_marks.out.mask);
		}
		jam_string(buf, ";");
		/* ... */
		jam(buf, " vti-iface:%s;", (c->config->vti.interface == NULL ? "unset" :
					    c->config->vti.interface));
		jam(buf, " vti-routing:%s;", bool_str(c->config->vti.routing));
		jam(buf, " vti-shared:%s;", bool_str(c->config->vti.shared));

		jam_string(buf, " nic-offload:");
		jam_sparse(buf, &nic_offload_option_names, c->config->nic_offload);
		jam_string(buf, ";");
	}


	SHOW_JAMBUF(s, buf) {
		jam_connection_short(buf, c);
		jam_string(buf, ":  ");
		/* our id */
		jam_string(buf, " our idtype: ");
		jam_enum(buf, &ike_id_type_names, c->local->host.id.kind);
		jam_string(buf, ";");
		jam_string(buf, " our id=");
		jam_id(buf, &c->local->host.id);
		jam_string(buf, ";");
		/* our id */
		jam_string(buf, " their idtype: ");
		jam_enum(buf, &ike_id_type_names, c->remote->host.id.kind);
		jam_string(buf, ";");
		jam_string(buf, " their id=");
		jam_id(buf, &c->remote->host.id);
	}

	switch (c->config->ike_version) {
	case IKEv1:
		SHOW_JAMBUF(s, buf) {
			jam_connection_short(buf, c);
			jam_string(buf, ":  ");
			/* dpd */
			jam(buf, " dpd: %s;", (deltasecs(c->config->dpd.delay) > 0 &&
					       deltasecs(c->config->dpd.timeout) > 0 ? "active" : "passive"));
			jam(buf, " delay:%jds;", deltasecs(c->config->dpd.delay));
			jam(buf, " timeout:%jds", deltasecs(c->config->dpd.timeout));
		}
		break;
	case IKEv2:
		SHOW_JAMBUF(s, buf) {
			jam_connection_short(buf, c);
			jam_string(buf, ":  ");
			/* liveness */
			jam(buf, " liveness: %s;", (deltasecs(c->config->dpd.delay) > 0 ? "active" : "passive"));
			jam(buf, " dpddelay:%jds;", deltasecs(c->config->dpd.delay));
			jam(buf, " retransmit-timeout:%jds", deltasecs(c->config->retransmit_timeout));
		}
		break;
	}

	SHOW_JAMBUF(s, buf) {
		jam_connection_short(buf, c);
		jam_string(buf, ":  ");
		/* nat */
		jam(buf, " nat-traversal:");
		/* encapsulation= */
		jam_string(buf, " encapsulation:");
		jam_sparse(buf, &yna_option_names, c->config->encapsulation);
		jam_string(buf, ";");
		/* nat-keepalive= + keep-alive= */
		jam_string(buf, " keepalive:");
		if (c->config->nat_keepalive) {
			jam(buf, "%jds", deltasecs(nat_keepalive_period));
		} else {
			jam_string(buf, bool_str(false));
		}
		/* nat-ikev1-method= */
		if (c->config->ike_version == IKEv1) {
			jam_string(buf, "; ikev1-method:");
			switch (c->config->ikev1_natt) {
			case NATT_BOTH: jam_string(buf, "rfc+drafts"); break;
			case NATT_RFC: jam_string(buf, "rfc"); break;
			case NATT_DRAFTS: jam_string(buf, "drafts"); break;
			case NATT_NONE: jam_string(buf, "none"); break;
			default: bad_case(c->config->ikev1_natt);
			}
		}
	}

	if (c->logger->debugging != LEMPTY) {
		SHOW_JAMBUF(s, buf) {
			jam_connection_short(buf, c);
			jam_string(buf, ":  ");
			/* debug */
			jam_string(buf, " debug: ");
			jam_lset_short(buf, &debug_names, "+", c->logger->debugging);
			/* strip off connection debugging bits */
			lset_t global_debugging = cur_debugging & ~c->logger->debugging;
			if (global_debugging != LEMPTY) {
				jam_string(buf, " + ");
				jam_lset_short(buf, &debug_names, "+", global_debugging);
			}
		}
	}

	/* routing */

	SHOW_JAMBUF(s, buf) {
		jam_connection_short(buf, c);
		jam_string(buf, ":  ");
		/* routing */
		jam_string(buf, " routing: ");
		jam_enum_human(buf, &routing_names, c->routing.state);
		jam_string(buf, ";");
		struct state *sa = state_by_serialno(c->routing_sa);
		if (sa != NULL) {
			jam_string(buf, " owner: ");
			jam_string(buf, state_sa_name(sa));
			jam_string(buf, " ");
			jam_so(buf, sa->st_serialno);
			jam_string(buf, ";");
		}
		jam_connection_owners(buf, c, IKE_SA_OWNER_FLOOR, IKE_SA_OWNER_ROOF);
		jam_connection_owners(buf, c, CHILD_SA_OWNER_FLOOR, CHILD_SA_OWNER_ROOF);
	}

	SHOW_JAMBUF(s, buf) {
		jam_connection_short(buf, c);
		jam_string(buf, ":  ");
		/* serial */
		jam(buf, " conn serial: "PRI_CO,
		    pri_co(c->serialno));
		if (c->clonedfrom != UNSET_CO_SERIAL) {
			jam(buf, ", instantiated from: "PRI_CO,
			    pri_connection_co(c->clonedfrom));
		}
		jam_string(buf, ";");
	}

	if (c->config->connalias != NULL) {
		SHOW_JAMBUF(s, buf) {
			jam_connection_short(buf, c);
			jam_string(buf, ":  ");
			/* aliases */
			jam_string(buf, " aliases: ");
			jam_string(buf, c->config->connalias);
		}
	}

	show_ike_alg_connection(s, c);
	show_kernel_alg_connection(s, c);
}

void show_connection_statuses(struct show *s)
{
	show_separator(s);
	show(s, "Connection list:");
	show_separator(s);

	int count = 0;
	int active = 0;

	struct connection **connections = sort_connections();
	if (connections != NULL) {
		/* make an array of connections, sort it, and report it */
		for (struct connection **c = connections; *c != NULL; c++) {
			count++;
			if ((*c)->routing.state == RT_ROUTED_TUNNEL) {
				active++;
			}
			show_connection_status(s, *c);
		}
		pfree(connections);
		show_separator(s);
	}

	show(s, "Total IPsec connections: loaded %d, active %d",
		     count, active);
}

static unsigned whack_connection_status(const struct whack_message *m UNUSED,
					struct show *s,
					struct connection *c)
{
	show_connection_status(s, c);
	return 1; /* the connection counts */
}

void whack_connectionstatus(const struct whack_message *m, struct show *s)
{
	if (m->name == NULL) {
		show_connection_statuses(s);
		return;
	}

	whack_connections_bottom_up(m, s, whack_connection_status,
				    (struct each) {
					    .log_unknown_name = true,
				    });
}
