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

static void jam_end_host(struct jambuf *buf, const struct spd_end *this, lset_t policy)
{
	/* HOST */
	if (!address_is_specified(this->host->addr)) {
		if (this->host->config->type == KH_IPHOSTNAME) {
			jam_string(buf, "%dns");
			jam(buf, "<%s>", this->host->config->addr_name);
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

static void jam_end_client(struct jambuf *buf, const struct spd_end *this,
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

void jam_spd_end(struct jambuf *buf, const struct spd_end *this, const struct spd_end *that,
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

void jam_spd(struct jambuf *buf, const struct spd_route *spd)
{
	jam_spd_end(buf, spd->local, spd->remote, LEFT_END, LEMPTY, false);
	jam_string(buf, "...");
	jam_spd_end(buf, spd->remote, spd->local, RIGHT_END,
		    spd->connection->policy, oriented(spd->connection));
}

const char *str_spd(const struct spd_route *spd, spd_buf *buf)
{
	struct jambuf jambuf = ARRAY_AS_JAMBUF(buf->buf);
	jam_spd(&jambuf, spd);
	return buf->buf;
}

static void show_one_sr(struct show *s,
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
		     c->child.kernel_policy_owner);

#define OPT_HOST(h, ipb)  (address_is_specified(h) ? str_address(&h, &ipb) : "unset")

		/* note: this macro generates a pair of arguments */
#define OPT_PREFIX_STR(pre, s) (s) == NULL ? "" : (pre), (s) == NULL? "" : (s)

	ip_address this_sourceip = spd_end_sourceip(c->spd->local);
	ip_address that_sourceip = spd_end_sourceip(c->spd->remote);

	show_comment(s, PRI_CONNECTION":     %s; my_ip=%s; their_ip=%s%s%s%s%s; my_updown=%s;",
		     c->name, instance,
		     oriented(c) ? "oriented" : "unoriented",
		     OPT_HOST(this_sourceip, thisipb),
		     OPT_HOST(that_sourceip, thatipb),
		     OPT_PREFIX_STR("; mycert=", cert_nickname(&c->local->host.config->cert)),
		     OPT_PREFIX_STR("; peercert=", cert_nickname(&c->remote->host.config->cert)),
		     ((spd->local->config->child.updown == NULL ||
		       streq(spd->local->config->child.updown, "%disabled")) ? "<disabled>" :
		      spd->local->config->child.updown));

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
		     COMBO(spd->local->host->config->xauth, server, client),
		     COMBO(spd->remote->host->config->xauth, server, client),
		     /* should really be an enum name */
		     (spd->local->host->config->xauth.server ?
		      c->config->xauthby == XAUTHBY_FILE ? "xauthby:file;" :
		      c->config->xauthby == XAUTHBY_PAM ? "xauthby:pam;" :
		      "xauthby:alwaysok;" :
		      ""),
		     (spd->local->host->config->xauth.username == NULL ? "[any]" :
		      spd->local->host->config->xauth.username),
		     (spd->remote->host->config->xauth.username == NULL ? "[any]" :
		      spd->remote->host->config->xauth.username));

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
		jam(buf, " us:%s,", COMBO(spd->local->host->config->modecfg, server, client));
		jam(buf, " them:%s,", COMBO(spd->remote->host->config->modecfg, server, client));
		jam(buf, " modecfg policy:%s,", (c->policy & POLICY_MODECFG_PULL ? "pull" : "push"));

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

		jam(buf, " cat:%s;", spd->local->child->config->has_client_address_translation ? "set" : "unset");
	}

#undef COMBO

	if (c->config->modecfg.banner != NULL) {
		show_comment(s, PRI_CONNECTION": banner:%s;",
			     c->name, instance, c->config->modecfg.banner);
	}

	/*
	 * Show the first valid sec_label.
	 *
	 * We only support symmetric labels, but store it in struct
	 * end - pick one.
	 *
	 * XXX: IKEv1 stores the negotiated sec_label in the state.
	 */
	if (c->child.sec_label.len > 0) {
		/* negotiated (IKEv2) */
		show_comment(s, PRI_CONNECTION":   sec_label:"PRI_SHUNK,
			     c->name, instance,
			     pri_shunk(c->child.sec_label));
	} else if (c->config->sec_label.len > 0) {
		/* configured */
		show_comment(s, "\"%s\"%s:   sec_label:"PRI_SHUNK,
			     c->name, instance,
			     pri_shunk(c->config->sec_label));
	} else {
		show_comment(s, PRI_CONNECTION":   sec_label:unset;",
			     c->name, instance);
	}
}

void show_connection_status(struct show *s, const struct connection *c)
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
		const struct spd_route *sr = c->spd;

		while (sr != NULL) {
			show_one_sr(s, c, sr, instance);
			sr = sr->spd_next;
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
		jam_humber_max(buf, " ipsec_max_bytes: ", c->config->sa_ipsec_max_bytes, "B;");
		jam_humber_max(buf, " ipsec_max_packets: ", c->config->sa_ipsec_max_packets, ";");
		jam(buf, " replay_window: %u;", c->sa_replay_window);
		jam(buf, " rekey_margin: %jds;", deltasecs(c->config->sa_rekey_margin));
		jam(buf, " rekey_fuzz: %lu%%;", c->config->sa_rekey_fuzz);
		jam(buf, " keyingtries: %lu;", c->sa_keying_tries);
	}

	show_comment(s, PRI_CONNECTION":   retransmit-interval: %jdms; retransmit-timeout: %jds; iketcp:%s; iketcp-port:%d;",
		     c->name, instance,
		     deltamillisecs(c->config->retransmit_interval),
		     deltasecs(c->config->retransmit_timeout),
		     c->iketcp == IKE_TCP_NO ? "no" : c->iketcp == IKE_TCP_ONLY ? "yes" :
		     c->iketcp == IKE_TCP_FALLBACK ? "fallback" : "<BAD VALUE>",
		     c->remote_tcpport);

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
		jam_string(buf, ";");
	}

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

	connection_priority_buf prio;
	show_comment(s, PRI_CONNECTION":   conn_prio: %s; interface: %s; metric: %u; mtu: %s; sa_prio:%s; sa_tfc:%s;",
		     c->name, instance,
		     str_connection_priority(c->priority, &prio),
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
		     (c->config->nic_offload == off_auto ? "auto" :
		     (c->config->nic_offload == off_pkt ? "packet" :
		      bool_str(c->config->nic_offload == off_yes))));

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
		    c->config->ike_info->sa_type_name[IKE_SA],
		    c->newest_ike_sa,
		    c->newest_ipsec_sa, /* IPsec SA or Child SA? */
		    pri_co(c->serialno));
		if (c->serial_from != UNSET_CO_SERIAL) {
			jam(buf, ", instantiated from: "PRI_CO";",
			    pri_co(c->serial_from));
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

static int connection_compare_qsort(const void *a, const void *b)
{
	return connection_compare(*(const struct connection *const *)a,
				*(const struct connection *const *)b);
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
		if (c->child.routing == RT_ROUTED_TUNNEL)
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
			show_connection_status(s, array[i]);

		pfree(array);
		show_separator(s);
	}

	show_comment(s, "Total IPsec connections: loaded %d, active %d",
		     count, active);
}
