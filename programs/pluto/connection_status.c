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

#include <net/if.h>		/* for IFNAMSIZ */

#include "ike_alg.h"

#include "defs.h"
#include "connections.h"
#include "orient.h"
#include "virtual_ip.h"        /* needs connections.h */
#include "kernel_xfrm_interface.h"
#include "iface.h"
#include "nat_traversal.h"
#include "log.h"
#include "show.h"
#include "crypto.h"		/* for show_ike_alg_connection() */
#include "plutoalg.h"		/* for show_kernel_alg_connection() */

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

static void jam_end_host(struct jambuf *buf, const struct connection *c,
			 const struct spd_end *this)
{
	/* HOST */
	if (!address_is_specified(this->host->addr)) {
		if (this->host->config->type == KH_IPHOSTNAME) {
			jam_string(buf, "%dns");
			jam(buf, "<%s>", this->host->config->addr_name);
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
		if (this->host->port != 0) {
			jam(buf, ":%u", this->host->port);
		}
	} else if (is_virtual_spd_end(this)) {
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
		bool include_port = (this->host->config->ikeport != 0 ||
				     this->host->port != IKE_UDP_PORT);
		if (!log_ip) {
			/* ADDRESS(SENSITIVE) */
			jam_string(buf, "<address>");
		} else if (include_port) {
			/* [ADDRESS]:PORT */
			jam_address_wrapped(buf, &this->host->addr);
			jam(buf, ":%u", this->host->port);
		} else {
			/* ADDRESS */
			jam_address(buf, &this->host->addr);
		}
		/* [<HOSTNAME>] */
		address_buf ab;
		if (this->host->config->addr_name != NULL &&
		    !streq(str_address(&this->host->addr, &ab),
			   this->host->config->addr_name)) {
			jam(buf, "<%s>", this->host->config->addr_name);
		}
	}
}

static void jam_end_client(struct jambuf *buf, const struct connection *c,
			   const struct spd_end *this, enum left_right left_right)
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

	if (left_right == RIGHT_END) {
		jam_string(buf, "===");
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

	if (left_right == LEFT_END) {
		jam_string(buf, "===");
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
		jam_end_client(buf, c, this, left_right);
		/* HOST */
		jam_end_host(buf, c, this);
		/* [ID+OPTS] */
		jam_end_id(buf, this);
		/* ---NEXTHOP */
		jam_end_nexthop(buf, this, that, skip_next_hop, left_right);
		break;
	case RIGHT_END:
		/* HOPNEXT--- */
		jam_end_nexthop(buf, this, that, skip_next_hop, left_right);
		/* HOST */
		jam_end_host(buf, c, this);
		/* [ID+OPTS] */
		jam_end_id(buf, this);
		/* ===CLIENT/PROTOCOL:PORT */
		jam_end_client(buf, c, this, left_right);
		break;
	}
}

/*
 * format topology of a connection.
 * Two symmetric ends separated by ...
 */

void jam_spd(struct jambuf *buf, const struct spd_route *spd)
{
	jam_spd_end(buf, spd->connection, spd->local, spd->remote,
		    LEFT_END, false);
	jam_string(buf, "...");
	jam_spd_end(buf, spd->connection, spd->remote, spd->local,
		    RIGHT_END, oriented(spd->connection));
}

const char *str_spd(const struct spd_route *spd, spd_buf *buf)
{
	struct jambuf jambuf = ARRAY_AS_JAMBUF(buf->buf);
	jam_spd(&jambuf, spd);
	return buf->buf;
}

static void show_one_spd(struct show *s,
			 const struct connection *c,
			 const struct spd_route *spd,
			 const char *instance)
{
	spd_buf spdb;
	ipstr_buf thisipb, thatipb;

	show_comment(s, PRI_CONNECTION": %s; %s; eroute owner: #%lu",
		     c->name, instance,
		     str_spd(spd, &spdb),
		     enum_name(&routing_story, c->child.routing),
		     c->child.newest_routing_sa);

#define OPT_HOST(h, ipb)  (address_is_specified(h) ? str_address(&h, &ipb) : "unset")

	ip_address this_sourceip = spd_end_sourceip(spd->local);
	ip_address that_sourceip = spd_end_sourceip(spd->remote);

	show_comment(s, PRI_CONNECTION":     %s; my_ip=%s; their_ip=%s;",
		     c->name, instance,
		     oriented(c) ? "oriented" : "unoriented",
		     OPT_HOST(this_sourceip, thisipb),
		     OPT_HOST(that_sourceip, thatipb));

#undef OPT_HOST

}

void show_connection_status(struct show *s, const struct connection *c)
{
	char instance[32];

	instance[0] = '\0';
	if (c->instance_serial > 0)
		snprintf(instance, sizeof(instance), "[%lu]",
			c->instance_serial);

	/* Show topology. */
	FOR_EACH_ITEM(spd, &c->child.spds) {
		show_one_spd(s, c, spd, instance);
	}

	SHOW_JAMBUF(RC_COMMENT, s, buf) {
		jam(buf, PRI_CONNECTION":  ", c->name, instance);
		const char *local_cert = cert_nickname(&c->local->host.config->cert);
		if (local_cert != NULL) {
			jam(buf, " mycert=%s;", local_cert);
		}
		const char *remote_cert = cert_nickname(&c->remote->host.config->cert);
		if (remote_cert != NULL) {
			jam(buf, " peercert=%s;", remote_cert);
		}
		jam_string(buf, " my_updown=");
		if (c->local->config->child.updown == NULL ||
		    streq(c->local->config->child.updown, "%disabled")) {
			jam_string(buf, "<disabled>;");
		} else {
			jam_string(buf, c->local->config->child.updown);
			jam_string(buf, ";");
		}
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

	show_comment(s, PRI_CONNECTION":   xauth us:%s, xauth them:%s, %s my_username=%s; their_username=%s",
		     c->name, instance,
		     /*
		      * Both should not be set, but if they are, we
		      * want to know.
		      */
		     COMBO(c->local->config->host.xauth),
		     COMBO(c->remote->config->host.xauth),
		     /* should really be an enum name */
		     (c->local->config->host.xauth.server ?
		      c->config->xauthby == XAUTHBY_FILE ? "xauthby:file;" :
		      c->config->xauthby == XAUTHBY_PAM ? "xauthby:pam;" :
		      "xauthby:alwaysok;" :
		      ""),
		     (c->local->config->host.xauth.username == NULL ? "[any]" :
		      c->local->config->host.xauth.username),
		     (c->remote->config->host.xauth.username == NULL ? "[any]" :
		      c->remote->config->host.xauth.username));

	SHOW_JAMBUF(RC_COMMENT, s, buf) {
		const char *who;
		jam(buf, PRI_CONNECTION":   ", c->name, instance);
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
		who = "our";
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

	SHOW_JAMBUF(RC_COMMENT, s, buf) {
		jam(buf, PRI_CONNECTION":   modecfg info:", c->name, instance);
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
		show_comment(s, PRI_CONNECTION":   banner:%s;",
			     c->name, instance, c->config->modecfg.banner);
	}

	/* The first valid sec_label. */
	SHOW_JAMBUF(RC_COMMENT, s, buf) {
		jam(buf, PRI_CONNECTION":   sec_label:", c->name, instance);
		if (is_labeled_child(c)) {
			/* negotiated (IKEv2) */
			jam_shunk(buf, c->child.sec_label);
		} else if (is_labeled_template(c) ||
			   is_labeled_parent(c)) {
			/* configured */
			jam_shunk(buf, c->config->sec_label);
		} else {
			jam_string(buf, "unset;");
		}
	}

	/* Show CAs */
	if (c->local->host.config->ca.ptr != NULL || c->remote->host.config->ca.ptr != NULL) {
		dn_buf this_ca, that_ca;
		show_comment(s, PRI_CONNECTION":   CAs: '%s'...'%s'",
			     c->name, instance,
			     str_dn_or_null(ASN1(c->local->host.config->ca), "%any", &this_ca),
			     str_dn_or_null(ASN1(c->remote->host.config->ca), "%any", &that_ca));
	}

	SHOW_JAMBUF(RC_COMMENT, s, buf) {
		jam(buf, PRI_CONNECTION":  ", c->name, instance);
		jam(buf, " ike_life: %jds;", deltasecs(c->config->sa_ike_max_lifetime));
		jam(buf, " ipsec_life: %jds;", deltasecs(c->config->sa_ipsec_max_lifetime));
		jam_humber_uintmax(buf, " ipsec_max_bytes: ", c->config->sa_ipsec_max_bytes, "B;");
		jam_humber_uintmax(buf, " ipsec_max_packets: ", c->config->sa_ipsec_max_packets, ";");
		jam(buf, " replay_window: %ju;", c->config->child_sa.replay_window);
		jam(buf, " rekey_margin: %jds;", deltasecs(c->config->sa_rekey_margin));
		jam(buf, " rekey_fuzz: %lu%%;", c->config->sa_rekey_fuzz);
	}

	show_comment(s, PRI_CONNECTION":   retransmit-interval: %jdms; retransmit-timeout: %jds; iketcp:%s; iketcp-port:"PRI_HPORT";",
		     c->name, instance,
		     deltamillisecs(c->config->retransmit_interval),
		     deltasecs(c->config->retransmit_timeout),
		     enum_name_short(&tcp_option_story, c->config->iketcp),
		     pri_hport(c->config->remote_tcpport));

	SHOW_JAMBUF(RC_COMMENT, s, buf) {
		jam(buf, PRI_CONNECTION":  ", c->name, instance);
		jam(buf, " initial-contact:%s;", bool_str(c->config->send_initial_contact));
		jam(buf, " cisco-unity:%s;", bool_str(c->config->send_vid_cisco_unity));
		jam(buf, " fake-strongswan:%s;", bool_str(c->config->send_vid_fake_strongswan));
		jam(buf, " send-vendorid:%s;", bool_str(c->config->send_vendorid));
		jam(buf, " send-no-esp-tfc:%s;", bool_str(c->config->send_no_esp_tfc));
	}

	SHOW_JAMBUF(RC_COMMENT, s, buf) {
		jam(buf, PRI_CONNECTION":   policy: ", c->name, instance);
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
#if 0
		/* XXX: where should this go? */
		switch (c->config->autostart) {
		case AUTOSTART_IGNORE: break;
		case AUTOSTART_ADD: jam(buf, "; auto:add"); break;
		case AUTOSTART_ONDEMAND: jam(buf, "; auto:ondemand"); break;
		case AUTOSTART_KEEP: jam(buf, "; auto:keep"); break;
		case AUTOSTART_START: jam(buf, "; auto:start"); break;
		}
#endif
		jam_string(buf, ";");
	}

	if (c->config->ike_version == IKEv2) {
		lset_buf hashpolbuf;
		show_comment(s, PRI_CONNECTION":   v2-auth-hash-policy: %s;",
			     c->name, instance,
			     str_lset_short(&ikev2_hash_algorithm_names, "+",
					    c->config->sighash_policy, &hashpolbuf));
	}

	SHOW_JAMBUF(RC_COMMENT, s, buf) {
		connection_priority_buf prio;
		jam(buf, PRI_CONNECTION":   conn_prio: %s;",
		    c->name, instance,
		    str_connection_priority(c, &prio));
		/* .interface? id_rname@id_vname? */
		jam_string(buf, " interface: ");
		if (oriented(c)) {
			if (c->xfrmi != NULL && c->xfrmi->name != NULL) {
				jam_string(buf, c->xfrmi->name);
				jam_string(buf, "@");
			}
			jam_string(buf, c->interface->ip_dev->id_rname);
		};
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


	SHOW_JAMBUF(RC_COMMENT, s, buf) {
		jam(buf, PRI_CONNECTION":  ",
		    c->name, instance);
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
		jam(buf, " vti-iface:%s;", (c->vti_iface == NULL ? "unset" :
					    c->vti_iface));
		jam(buf, " vti-routing:%s;", bool_str(c->vti_routing));
		jam(buf, " vti-shared:%s;", bool_str(c->vti_shared));
		jam(buf, " nic-offload:%s;", (c->config->nic_offload == offload_auto ? "auto" :
					      c->config->nic_offload == offload_packet ? "packet" :
					      c->config->nic_offload == offload_crypto ? "crypto" :
					      "no"));
	}

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
		show_comment(s, PRI_CONNECTION":   dpd: %s; delay:%jds; timeout:%jds",
			     c->name, instance,
			     (deltasecs(c->config->dpd.delay) > 0 &&
			      deltasecs(c->config->dpd.timeout) > 0 ? "active" : "passive"),
			     deltasecs(c->config->dpd.delay),
			     deltasecs(c->config->dpd.timeout));
		break;

	case IKEv2:
		show_comment(s, PRI_CONNECTION":   liveness: %s; dpddelay:%jds; retransmit-timeout:%jds",
			     c->name, instance,
			     deltasecs(c->config->dpd.delay) > 0 ? "active" : "passive",
			     deltasecs(c->config->dpd.delay),
			     deltasecs(c->config->retransmit_timeout));
		break;

	}

	SHOW_JAMBUF(RC_COMMENT, s, buf) {
		jam(buf, PRI_CONNECTION":   nat-traversal: encaps:%s",
		    c->name, instance,
		    (c->encaps == yna_auto ? "auto" :
		     bool_str(c->encaps == yna_yes)));
		jam_string(buf, "; keepalive:");
		if (c->config->nat_keepalive) {
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

	if (c->logger->debugging != LEMPTY) {
		SHOW_JAMBUF(RC_COMMENT, s, buf) {
			jam(buf, PRI_CONNECTION":   debug: ",
			    c->name, instance);
			jam_lset_short(buf, &debug_names, "+", c->logger->debugging);
		}
	}

	SHOW_JAMBUF(RC_COMMENT, s, buf) {
		jam(buf, PRI_CONNECTION":   newest %s: #%lu; newest IPsec SA: #%lu; conn serial: "PRI_CO"",
		    c->name, instance,
		    c->config->ike_info->ike_sa_name,
		    c->newest_ike_sa,
		    c->newest_ipsec_sa, /* IPsec SA or Child SA? */
		    pri_co(c->serialno));
		if (c->clonedfrom != UNSET_CO_SERIAL) {
			jam(buf, ", instantiated from: "PRI_CO";",
			    pri_connection_co(c->clonedfrom));
		} else {
			jam(buf, ";");
		}
	}

	if (c->config->connalias != NULL) {
		show_comment(s, PRI_CONNECTION":   aliases: %s",
			     c->name, instance,
			     c->config->connalias);
	}

	show_ike_alg_connection(s, c, instance);
	show_kernel_alg_connection(s, c, instance);
}

void show_connection_statuses(struct show *s)
{
	show_separator(s);
	show_comment(s, "Connection list:");
	show_separator(s);

	int count = 0;
	int active = 0;

	struct connection **connections = sort_connections();
	if (connections != NULL) {
		/* make an array of connections, sort it, and report it */
		for (struct connection **c = connections; *c != NULL; c++) {
			count++;
			if ((*c)->child.routing == RT_ROUTED_TUNNEL) {
				active++;
			}
			show_connection_status(s, *c);
		}
		pfree(connections);
		show_separator(s);
	}

	show_comment(s, "Total IPsec connections: loaded %d, active %d",
		     count, active);
}
