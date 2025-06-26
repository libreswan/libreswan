/* routines that interface with the kernel's IPsec mechanism, for libreswan
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2010  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008-2010 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010 Bart Trojanowski <bart@jukie.net>
 * Copyright (C) 2009-2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2010 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012-2015 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 Kim B. Heino <b@bbbs.net>
 * Copyright (C) 2016-2022 Andrew Cagney
 * Copyright (C) 2019 Paul Wouters <pwouters@redhat.com>
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

#include "ip_info.h"

#include "defs.h"
#include "updown.h"
#include "state.h"
#include "connections.h"
#include "log.h"
#include "kernel.h"
#include "ipsec_interface.h"
#include "iface.h"
#include "keys.h"		/* for pluto_pubkeys */
#include "secrets.h"		/* for struct pubkey_list */
#include "server_run.h"

/*
 * Remove all characters but [-_.0-9a-zA-Z] from a character string.
 * Truncates the result if it would be too long.
 */

static void jam_clean_xauth_username(struct jambuf *buf,
				     const char *src,
				     struct logger *logger)
{
	bool changed = false;
	const char *dst = jambuf_cursor(buf);
	while (*src != '\0') {
		if ((*src >= '0' && *src <= '9') ||
		    (*src >= 'a' && *src <= 'z') ||
		    (*src >= 'A' && *src <= 'Z') ||
		    *src == '_' || *src == '-' || *src == '.') {
			jam_char(buf, *src);
		} else {
			changed = true;
		}
		src++;
	}
	if (changed || !jambuf_ok(buf)) {
		llog(RC_LOG, logger,
			    "Warning: XAUTH username changed from '%s' to '%s'",
			    src, dst);
	}
}

/*
 * fmt_common_shell_out: form the command string
 *
 * note: this mutates *st by calling get_sa_bundle_info().
 */

static bool fmt_common_shell_out(char *buf,
				 size_t blen,
				 const struct connection *c,
				 const struct spd *sr,
				 struct child_sa *child,
				 struct updown_env updown_env,
				 struct verbose verbose/*C-or-CHILD*/)
{
	struct jambuf jb = array_as_jambuf(buf, blen);
	const bool tunneling = (c->config->child_sa.encap_mode == ENCAP_MODE_TUNNEL);

	/* macros to jam definitions of various forms */
#	define JDstr(name, string)  jam(&jb, name "='%s' ", string)
#	define JDuint(name, u)  jam(&jb, name "=%u ", u)
#	define JDuint64(name, u)  jam(&jb, name "=%" PRIu64 " ", u)
#	define JDemitter(name, emitter)  { jam_string(&jb, name "='"); emitter; jam_string(&jb, "' "); }
#	define JDipaddr(name, addr)  JDemitter(name, { ip_address ta = addr; jam_address(&jb, &ta); } )

	JDstr("PLUTO_CONNECTION", c->base_name);
	JDstr("PLUTO_CONNECTION_TYPE", (tunneling ? "tunnel" : "transport"));
	JDstr("PLUTO_VIRT_INTERFACE", (c->ipsec_interface != NULL ? c->ipsec_interface->name : "NULL"));
	JDstr("PLUTO_INTERFACE", c->iface == NULL ? "NULL" : c->iface->real_device_name);
	JDstr("PLUTO_XFRMI_ROUTE",  (c->ipsec_interface != NULL && c->ipsec_interface->if_id > 0) ? "yes" : "");

	if (address_is_specified(sr->local->host->nexthop)) {
		JDipaddr("PLUTO_NEXT_HOP", sr->local->host->nexthop);
	}

	JDipaddr("PLUTO_ME", sr->local->host->addr);
	JDemitter("PLUTO_MY_ID", jam_id_bytes(&jb, &c->local->host.id, jam_shell_quoted_bytes));
	jam(&jb, "PLUTO_CLIENT_FAMILY='ipv%s' ", selector_info(sr->local->client)->n_name);
	JDemitter("PLUTO_MY_CLIENT", jam_selector_range(&jb, &sr->local->client));
	JDipaddr("PLUTO_MY_CLIENT_NET", selector_prefix(sr->local->client));
	JDipaddr("PLUTO_MY_CLIENT_MASK", selector_prefix_mask(sr->local->client));

	if (cidr_is_specified(c->local->config->child.vti_ip)) {
		JDemitter("VTI_IP", jam_cidr(&jb, &c->local->config->child.vti_ip));
	}

	if (cidr_is_specified(c->local->config->child.ipsec_interface_ip)) {
		JDemitter("INTERFACE_IP", jam_cidr(&jb, &c->local->config->child.ipsec_interface_ip));
	}

	JDuint("PLUTO_MY_PORT", sr->local->client.hport);
	JDuint("PLUTO_MY_PROTOCOL", sr->local->client.ipproto);
	JDuint("PLUTO_SA_REQID", (child == NULL ? c->child.reqid :
				  child->sa.st_esp.protocol == &ip_protocol_esp ? reqid_esp(c->child.reqid) :
				  child->sa.st_ah.protocol == &ip_protocol_ah ? reqid_ah(c->child.reqid) :
				  child->sa.st_ipcomp.protocol == &ip_protocol_ipcomp ? reqid_ipcomp(c->child.reqid) :
				  c->child.reqid));

	JDstr("PLUTO_SA_TYPE", (child == NULL ? "none" :
				child->sa.st_esp.protocol == &ip_protocol_esp ? "ESP" :
				child->sa.st_ah.protocol == &ip_protocol_ah ? "AH" :
				child->sa.st_ipcomp.protocol == &ip_protocol_ipcomp ? "IPCOMP" :
				"unknown?"));

	JDipaddr("PLUTO_PEER", sr->remote->host->addr);
	JDemitter("PLUTO_PEER_ID", jam_id_bytes(&jb, &c->remote->host.id, jam_shell_quoted_bytes));

	/* for transport mode, things are complicated */
	jam_string(&jb, "PLUTO_PEER_CLIENT='");
	if (!tunneling && child != NULL &&
	    child->sa.hidden_variables.st_nated_peer) {
		/* pexpect(selector_eq_address(sr->remote->client, sr->remote->host->addr)); */
		jam_address(&jb, &sr->remote->host->addr);
		jam(&jb, "/%d", address_info(sr->local->host->addr)->mask_cnt/*32 or 128*/);
	} else {
		jam_selector_range(&jb, &sr->remote->client);
	}
	jam_string(&jb, "' ");

	JDipaddr("PLUTO_PEER_CLIENT_NET",
		 (!tunneling && child != NULL &&
		  child->sa.hidden_variables.st_nated_peer) ?
		 sr->remote->host->addr : selector_prefix(sr->remote->client));

	JDipaddr("PLUTO_PEER_CLIENT_MASK", selector_prefix_mask(sr->remote->client));
	JDuint("PLUTO_PEER_PORT", sr->remote->client.hport);
	JDuint("PLUTO_PEER_PROTOCOL", sr->remote->client.ipproto);

	jam_string(&jb, "PLUTO_PEER_CA='");
	for (struct pubkey_list *p = pluto_pubkeys; p != NULL; p = p->next) {
		struct pubkey *key = p->key;
		int pathlen;	/* value ignored */
		if (key->content.type == &pubkey_type_rsa &&
		    same_id(&c->remote->host.id, &key->id) &&
		    trusted_ca(key->issuer, ASN1(sr->remote->host->config->ca),
			       &pathlen, verbose)) {
			jam_dn_or_null(&jb, key->issuer, "", jam_shell_quoted_bytes);
			break;
		}
	}
	jam_string(&jb, "' ");

	JDstr("PLUTO_STACK", kernel_ops->updown_name);

	if (c->config->child_sa.metric != 0) {
		jam(&jb, "PLUTO_METRIC=%d ", c->config->child_sa.metric);
	}

	if (c->config->child_sa.mtu != 0) {
		jam(&jb, "PLUTO_MTU=%d ", c->config->child_sa.mtu);
	}

	JDuint64("PLUTO_ADDTIME", (child == NULL ? (uint64_t)0 : child->sa.st_esp.add_time));
	JDemitter("PLUTO_CONN_POLICY",	jam_connection_policies(&jb, c));
	JDemitter("PLUTO_CONN_KIND", jam_enum_long(&jb, &connection_kind_names, c->local->kind));
	jam(&jb, "PLUTO_CONN_ADDRFAMILY='ipv%s' ", address_info(sr->local->host->addr)->n_name);
	JDuint("XAUTH_FAILED", (child != NULL && child->sa.st_xauth_soft ? 1 : 0));

	if (child != NULL && child->sa.st_xauth_username[0] != '\0') {
		JDemitter("PLUTO_USERNAME", jam_clean_xauth_username(&jb, child->sa.st_xauth_username, child->sa.logger));
	}

	ip_address sourceip = spd_end_sourceip(sr->local);
	if (sourceip.ip.is_set) {
		JDipaddr("PLUTO_MY_SOURCEIP", sourceip);
		if (child != NULL) {
			JDstr("PLUTO_MOBIKE_EVENT",
			      (updown_env.pluto_mobike_event ? "yes" : ""));
		}
	}

	JDuint("PLUTO_IS_PEER_CISCO", c->config->host.cisco.peer);
	JDstr("PLUTO_PEER_DNS_INFO", (child != NULL && child->sa.st_seen_cfg_dns != NULL ? child->sa.st_seen_cfg_dns : ""));
	JDstr("PLUTO_PEER_DOMAIN_INFO", (child != NULL && child->sa.st_seen_cfg_domains != NULL ? child->sa.st_seen_cfg_domains : ""));
	JDstr("PLUTO_PEER_BANNER", (child != NULL && child->sa.st_seen_cfg_banner != NULL ? child->sa.st_seen_cfg_banner : ""));
	JDuint("PLUTO_CFG_SERVER", sr->local->host->config->modecfg.server);
	JDuint("PLUTO_CFG_CLIENT", sr->local->host->config->modecfg.client);
	JDuint("PLUTO_NM_CONFIGURED", c->config->host.cisco.nm);

	struct ipsec_proto_info *const first_ipsec_proto =
		(child == NULL ? NULL :
		 child->sa.st_esp.protocol == &ip_protocol_esp ? &child->sa.st_esp :
		 child->sa.st_ah.protocol == &ip_protocol_ah ? &child->sa.st_ah :
		 child->sa.st_ipcomp.protocol == &ip_protocol_ipcomp ? &child->sa.st_ipcomp :
		 NULL);

	if (first_ipsec_proto != NULL) {
		/*
		 * note: this mutates *st by calling get_sa_bundle_info
		 *
		 * XXX: does the get_sa_bundle_info() call order matter? Should this
		 * be a single "atomic" call?
		 */
		if (get_ipsec_traffic(child, first_ipsec_proto, DIRECTION_INBOUND)) {
			JDuint64("PLUTO_INBYTES", first_ipsec_proto->inbound.bytes);
		}
		if (get_ipsec_traffic(child, first_ipsec_proto, DIRECTION_OUTBOUND)) {
			JDuint64("PLUTO_OUTBYTES", first_ipsec_proto->outbound.bytes);
		}
	}

	if (c->nflog_group != 0) {
		jam(&jb, "NFLOG=%d ", c->nflog_group);
	}

	if (c->sa_marks.in.val != 0) {
		jam(&jb, "CONNMARK_IN=%" PRIu32 "/%#08" PRIx32 " ",
		    c->sa_marks.in.val, c->sa_marks.in.mask);
	}
	if (c->sa_marks.out.val != 0 && c->ipsec_interface == NULL) {
		jam(&jb, "CONNMARK_OUT=%" PRIu32 "/%#08" PRIx32 " ",
		    c->sa_marks.out.val, c->sa_marks.out.mask);
	}
	if (c->ipsec_interface != NULL) {
		if (c->sa_marks.out.val != 0) {
			/* user configured XFRMI_SET_MARK (a.k.a. output mark) add it */
			jam(&jb, "PLUTO_XFRMI_FWMARK='%" PRIu32 "/%#08" PRIx32 "' ",
			    c->sa_marks.out.val, c->sa_marks.out.mask);
		} else if (address_in_selector_range(sr->remote->host->addr, sr->remote->client)) {
			jam(&jb, "PLUTO_XFRMI_FWMARK='%" PRIu32 "/0xffffffff' ",
			    c->ipsec_interface->if_id);
		} else {
			address_buf bpeer;
			selector_buf peerclient_str;
			vdbg("not adding PLUTO_XFRMI_FWMARK. PLUTO_PEER=%s is not inside PLUTO_PEER_CLIENT=%s",
			     str_address(&sr->remote->host->addr, &bpeer),
			     str_selector_range_port(&sr->remote->client, &peerclient_str));
			jam(&jb, "PLUTO_XFRMI_FWMARK='' ");
		}
	}
	JDstr("VTI_IFACE", (c->config->vti.interface == NULL ? "" : c->config->vti.interface));
	JDstr("VTI_ROUTING", bool_str(c->config->vti.routing));
	JDstr("VTI_SHARED", bool_str(c->config->vti.shared));

	if (c->local->child.has_cat) {
		jam_string(&jb, "CAT='YES' ");
	}

	jam(&jb, "SPI_IN=0x%x SPI_OUT=0x%x " /* SPI_IN SPI_OUT */,
		first_ipsec_proto == NULL ? 0 : ntohl(first_ipsec_proto->outbound.spi),
		first_ipsec_proto == NULL ? 0 : ntohl(first_ipsec_proto->inbound.spi));

	if (DBGP(DBG_UPDOWN)) {
		JDstr("IPSEC_INIT_SCRIPT_DEBUG", "yes");
	}

	return jambuf_ok(&jb);

#	undef JDstr
#	undef JDuint
#	undef JDuint64
#	undef JDemitter
#	undef JDipaddr
}

static bool do_updown_verb(const char *verb,
			   const struct connection *c,
			   const struct spd *spd,
			   struct child_sa *child,
			   struct updown_env updown_env,
			   struct verbose verbose/*C-or-CHILD*/)
{
	if (c->child.spds.len > 1) {
		/* i.e., more selectors than just this */
		selector_pair_buf sb;
		vlog("running updown %s %s", verb,
		     str_selector_pair(&spd->local->client, &spd->remote->client, &sb));
	} else {
		vdbg("kernel: running updown command \"%s\" for verb %s ",
		     c->local->config->child.updown, verb);
	}

	/*
	 * Figure out which verb suffix applies.
	 */
	const char *verb_suffix;

	{
		const struct ip_info *host_afi = address_info(spd->local->host->addr);
		const struct ip_info *child_afi = selector_info(spd->local->client);
		if (host_afi == NULL || child_afi == NULL) {
			llog_pexpect(verbose.logger, HERE,
				     "unknown address family");
			return false;
		}

		const char *host_suffix;
		switch (host_afi->af) {
		case AF_INET:
			host_suffix = "-host";
			break;
		case AF_INET6:
			host_suffix = "-host-v6";
			break;
		default:
			bad_case(host_afi->af);
		}

		const char *child_suffix;
		switch (child_afi->af) {
		case AF_INET:
			child_suffix = "-client"; /* really child; legacy name */
			break;
		case AF_INET6:
			child_suffix = "-client-v6"; /* really child; legacy name */
			break;
		default:
			bad_case(child_afi->af);
		}

		/*
		 * Use the HOST_SUFFIX when the selector is just the
		 * host.addr (perhaps with a sprinkling of protoport).
		 */
		ip_range client_range = selector_range(spd->local->client);
		bool client_is_host = range_eq_address(client_range, spd->local->host->addr);
		verb_suffix = (client_is_host ? host_suffix : child_suffix);
	}

	vdbg("kernel: command executing %s%s", verb, verb_suffix);

	char common_shell_out_str[2048];
	if (!fmt_common_shell_out(common_shell_out_str,
				  sizeof(common_shell_out_str), c, spd,
				  child, updown_env, verbose)) {
		vlog("%s%s command too long!", verb,
		     verb_suffix);
		return false;
	}

	/* must free */
	char *cmd = alloc_printf("2>&1 "      /* capture stderr along with stdout */
				 "PLUTO_VERB='%s%s' "
				 "%s"         /* other stuff */
				 "%s",        /* actual script */
				 verb, verb_suffix,
				 common_shell_out_str,
				 c->local->config->child.updown);
	if (cmd == NULL) {
		vlog("%s%s command too long!", verb,
		     verb_suffix);
		return false;
	}

	bool ok = server_run(verb, verb_suffix, cmd, verbose);
	pfree(cmd);
	return ok;
}

static bool do_updown_1(enum updown updown_verb,
			const struct connection *c,
			const struct spd *spd,
			struct child_sa *child,
			struct updown_env updown_env,
			struct verbose verbose/*C-or-CHILD*/)
{
#if 0
	/*
	 * Depending on context, logging for either the connection or
	 * the state?
	 *
	 * The sec_label code violates this expectation somehow.
	 */
	PEXPECT(logger, ((c != NULL && c->logger == logger) ||
			 (st != NULL && st->logger == logger)));
#endif

	/*
	 * Support for skipping updown, eg leftupdown="".  Useful on
	 * busy servers that do not need to use updown for anything.
	 * Same for never_negotiate().
	 */
	if (c->local->config->child.updown == NULL) {
		vdbg("skipped updown command - disabled per policy");
		return true;
	}

	name_buf verb;
	if (!vexpect(enum_short(&updown_stories, updown_verb, &verb))) {
		return false;
	}

	return do_updown_verb(verb.buf, c, spd, child, updown_env, verbose);
}

bool do_updown(enum updown updown_verb,
	       const struct connection *c,
	       const struct spd *spd,
	       struct child_sa *child,
	       struct logger *logger/*C-or-CHILD*/)
{
	name_buf vb;
	enum_long(&updown_names, updown_verb, &vb);
	struct verbose verbose = VERBOSE(DEBUG_STREAM, logger, vb.buf);
	return do_updown_1(updown_verb, c, spd, child,
			   (struct updown_env) {0}, verbose);
}

void do_updown_child(enum updown updown_verb, struct child_sa *child)
{
	/* use full UPDOWN_UP as prefix */
	name_buf vb;
	enum_long(&updown_names, updown_verb, &vb);
	struct verbose verbose = VERBOSE(DEBUG_STREAM, child->sa.logger, vb.buf);

	struct connection *c = child->sa.st_connection;
	FOR_EACH_ITEM(spd, &c->child.spds) {
		do_updown_1(updown_verb, c, spd, child,
			    (struct updown_env) {0}, verbose);
	}
}

/*
 * Delete any kernel policies for a connection and unroute it if route
 * isn't shared.
 */

void do_updown_unroute_spd(const struct spd *spd, const struct spd_owner *owner,
			   struct child_sa *child, struct logger *logger,
			   struct updown_env updown_env)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, logger, "UNBOUND_UNROUTE");
	if (owner->bare_route != NULL) {
		vdbg("skip as has owner->bare_route");
		return;
	}

	do_updown_1(UPDOWN_UNROUTE, spd->connection, spd, child,
		    updown_env, verbose);
}
