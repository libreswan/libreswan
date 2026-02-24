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
#include "flags.h"

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
#include "server_fork.h"

static server_fork_cb updown_async_callback;
const char *pluto_dns_resolver;

static struct verbose verbose_updown(struct logger *logger,
				     enum updown updown_verb,
				     const char **verb)
{
	name_buf vb;
	if (PEXPECT(logger, enum_short(&updown_stories, updown_verb, &vb))) {
		/* points into static string */
		PEXPECT(logger, vb.buf != vb.tmp);
		*verb = vb.buf;
	} else {
		*verb = "???";
	}
	return VERBOSE(DEBUG_STREAM, logger, *verb);
}

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
 * build updown's environment; strings are saved in JB.
 *
 * note: this mutates *st by calling get_sa_bundle_info().
 */


#define UPDOWN_ARGV_MAX 32

struct updown_exec {
    char buffer[2048];
    const char *env[100];
    const char *arg[UPDOWN_ARGV_MAX];
    char cmd[512]; // writable copy of the command used for tokenization
};


static bool build_updown_exec(struct updown_exec *exec,
			      const char *verb, const char *verb_suffix,
			      const struct connection *c,
			      const struct spd *sr,
			      struct child_sa *child,
			      struct updown_env updown_env,
			      struct verbose verbose/*C-or-CHILD*/)
{

	/*
	* Build argv[]
	*/
	
	const char *cmd = c->local->config->child.updown.command;
	const char **argv = exec->arg;

	if (c->local->config->child.updown.updown_config_exec) {

		// copy the command string inside exec->cmd so we can modify it for tokenization
		if (strlcpy(exec->cmd, cmd, sizeof(exec->cmd)) >= sizeof(exec->cmd)) {
				// if it doesn't fit, log and return false
				llog(RC_LOG, verbose.logger, "updown command too long");
				return false;
		}

		// convert the command string into a shrunk
		shunk_t input = {
				.ptr = exec->cmd,
				.len = strlen(exec->cmd),
		};

		// get tokens by splitting on whitespace or tab by using ttoshunks
		struct shunks *toks = ttoshunks(input, " \t", EAT_EMPTY_SHUNKS);

		if (toks == NULL || toks->len == 0) {
			// if there are no tokens, log and return false
			llog(RC_LOG, verbose.logger, "updown command is empty");
			pfreeany(toks);
			return false;
		}

		for (unsigned i = 0; i < toks->len; i++) {

			if (argv >= exec->arg + elemsof(exec->arg) - 1) {
				// if we have too many tokens, log and return false
				llog(RC_LOG, verbose.logger, "updown command has too many words");
				pfreeany(toks);
				return false;
			}

			shunk_t t = toks->item[i];

			//write a null terminator at the end of the token so we can use it as a C string
			((char *)t.ptr)[t.len] = '\0';

			*argv++ = t.ptr;
		}

		pfreeany(toks);

	} else {
		*argv++ = "/bin/sh";
		*argv++ = "-c";
		*argv++ = cmd;
	}

	*argv++ = NULL;
	vassert(argv <= exec->arg + elemsof(exec->arg));
	


	/*
	 * Build envp[]
	 */
	struct jambuf jb = ARRAY_AS_JAMBUF(exec->buffer);
	const char **envp = exec->env;
	/* leave space for trailing NULL */
	const char **envp_end = envp + elemsof(exec->env) - 1;

	const bool tunneling = (c->config->child.encap_mode == ENCAP_MODE_TUNNEL);

	/* macros to jam definitions of various forms */

#	define JDemitter(NAME, EMITTER)			\
	{						\
		if (envp < envp_end) {			\
			*envp++ = jambuf_cursor(&jb);	\
		}					\
		jam_string(&jb, NAME "=");		\
		EMITTER;				\
		uint8_t byte = 0;			\
		jam_raw_bytes(&jb, &byte, 1);		\
	}

#	define JD(NAME, FMT, ...)  JDemitter(NAME, jam(&jb, FMT, ##__VA_ARGS__))
#	define JDstr(NAME, STRING) JD(NAME, "%s", STRING)
#	define JDunsigned(NAME, U) JD(NAME, "%u", U)
#	define JDint(NAME, I)      JD(NAME, "%d", I)
#	define JDuint64(NAME, U)   JD(NAME, "%"PRIu64, U)
#	define JDipaddr(name, addr)					\
	JDemitter(name, { ip_address ta = addr; jam_address(&jb, &ta); } )

	/* use PLUTO's environment for defaults */
	JDstr("PATH", getenv("PATH"));

	JD("PLUTO_VERB", "%s%s", verb, verb_suffix);

	JDstr("PLUTO_CONNECTION", c->base_name);
	JDstr("PLUTO_CONNECTION_TYPE", (tunneling ? "tunnel" : "transport"));
	JDstr("PLUTO_VIRT_INTERFACE", (c->ipsec_interface != NULL ? c->ipsec_interface->name : "NULL"));
	JDstr("PLUTO_INTERFACE", c->iface == NULL ? "NULL" : c->iface->real_device_name);
	JDstr("PLUTO_XFRMI_ROUTE",  (c->ipsec_interface != NULL && c->ipsec_interface->if_id > 0) ? "yes" : "");

	if (address_is_specified(c->local->host.nexthop)) {
		JDipaddr("PLUTO_NEXT_HOP", c->local->host.nexthop);
	}

	JDipaddr("PLUTO_ME", c->local->host.addr);
	JDemitter("PLUTO_MY_ID", jam_id_bytes(&jb, &c->local->host.id, jam_sanitized_bytes));
	JD("PLUTO_CLIENT_FAMILY", "ipv%s", selector_info(sr->local->client)->n_name);
	JDemitter("PLUTO_MY_CLIENT", jam_selector_range(&jb, &sr->local->client));
	JDipaddr("PLUTO_MY_CLIENT_NET", selector_prefix(sr->local->client));
	JDipaddr("PLUTO_MY_CLIENT_MASK", selector_prefix_mask(sr->local->client));

	if (cidr_is_specified(c->local->config->child.vti_ip)) {
		JDemitter("VTI_IP", jam_cidr(&jb, &c->local->config->child.vti_ip));
	}

	if (cidr_is_specified(c->local->config->child.ipsec_interface_ip)) {
		JDemitter("INTERFACE_IP", jam_cidr(&jb, &c->local->config->child.ipsec_interface_ip));
	}

	JDunsigned("PLUTO_MY_PORT", sr->local->client.hport);
	JDunsigned("PLUTO_MY_PROTOCOL", sr->local->client.ipproto);
	JDunsigned("PLUTO_SA_REQID", (child == NULL ? c->child.reqid :
				  child->sa.st_esp.protocol == &ip_protocol_esp ? reqid_esp(c->child.reqid) :
				  child->sa.st_ah.protocol == &ip_protocol_ah ? reqid_ah(c->child.reqid) :
				  child->sa.st_ipcomp.protocol == &ip_protocol_ipcomp ? reqid_ipcomp(c->child.reqid) :
				  c->child.reqid));

	JDstr("PLUTO_SA_TYPE", (child == NULL ? "none" :
				child->sa.st_esp.protocol == &ip_protocol_esp ? "ESP" :
				child->sa.st_ah.protocol == &ip_protocol_ah ? "AH" :
				child->sa.st_ipcomp.protocol == &ip_protocol_ipcomp ? "IPCOMP" :
				"unknown?"));

	JDipaddr("PLUTO_PEER", c->remote->host.addr);
	JDemitter("PLUTO_PEER_ID", jam_id_bytes(&jb, &c->remote->host.id, jam_sanitized_bytes));

	/* for transport mode, things are complicated */
	JDemitter("PLUTO_PEER_CLIENT",
		  if (!tunneling && child != NULL &&
		      child->sa.hidden_variables.st_nated_peer) {
			  /* pexpect(selector_eq_address(sr->remote->client, sr->remote->host->addr)); */
			  jam_address(&jb, &c->remote->host.addr);
			  jam(&jb, "/%d", address_info(c->local->host.addr)->mask_cnt/*32 or 128*/);
		  } else {
			  jam_selector_range(&jb, &sr->remote->client);
		  });

	JDipaddr("PLUTO_PEER_CLIENT_NET",
		 (!tunneling && child != NULL &&
		  child->sa.hidden_variables.st_nated_peer) ?
		 c->remote->host.addr : selector_prefix(sr->remote->client));

	JDipaddr("PLUTO_PEER_CLIENT_MASK", selector_prefix_mask(sr->remote->client));
	JDunsigned("PLUTO_PEER_PORT", sr->remote->client.hport);
	JDunsigned("PLUTO_PEER_PROTOCOL", sr->remote->client.ipproto);

	JDemitter("PLUTO_PEER_CA",
		  for (struct pubkey_list *p = pluto_pubkeys; p != NULL; p = p->next) {
			  struct pubkey *key = p->key;
			  int pathlen;	/* value ignored */
			  if (key->content.type == &pubkey_type_rsa &&
			      same_id(&c->remote->host.id, &key->id) &&
			      trusted_ca(key->issuer, ASN1(c->remote->host.config->ca),
					 &pathlen, verbose)) {
				  jam_dn_or_null(&jb, key->issuer, "", jam_sanitized_bytes);
				  break;
			  }
		  });

	JDstr("PLUTO_STACK", kernel_ops->updown_name);
	JDstr("PLUTO_DNS_RESOLVER", pluto_dns_resolver);

	if (c->config->child.metric != 0) {
		JDint("PLUTO_METRIC", c->config->child.metric);
	}

	if (c->config->child.mtu != 0) {
		JDint("PLUTO_MTU", c->config->child.mtu);
	}

	JDuint64("PLUTO_ADDTIME", (child == NULL ? (uint64_t)0 : child->sa.st_esp.add_time));
	JDemitter("PLUTO_CONN_POLICY",	jam_connection_policies(&jb, c));
	JDemitter("PLUTO_CONN_KIND", jam_enum_long(&jb, &connection_kind_names, c->local->kind));
	JD("PLUTO_CONN_ADDRFAMILY", "ipv%s", address_info(c->local->host.addr)->n_name);
	JDunsigned("XAUTH_FAILED", (child != NULL && child->sa.st_xauth_soft ? 1 : 0));

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

	JDunsigned("PLUTO_IS_PEER_CISCO", c->config->host.cisco.peer);
	JDstr("PLUTO_PEER_DNS_INFO", (child != NULL && child->sa.st_seen_cfg_dns != NULL ? child->sa.st_seen_cfg_dns : ""));
	JDstr("PLUTO_PEER_DOMAIN_INFO", (child != NULL && child->sa.st_seen_cfg_domains != NULL ? child->sa.st_seen_cfg_domains : ""));
	JDstr("PLUTO_PEER_BANNER", (child != NULL && child->sa.st_seen_cfg_banner != NULL ? child->sa.st_seen_cfg_banner : ""));
	JDunsigned("PLUTO_CFG_SERVER", c->local->host.config->modecfg.server);
	JDunsigned("PLUTO_CFG_CLIENT", c->local->host.config->modecfg.client);
	JDunsigned("PLUTO_NM_CONFIGURED", c->config->host.cisco.nm);

	struct ipsec_proto_info *const first_ipsec_proto = (child == NULL ? NULL :
							    outer_ipsec_proto_info(child));

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
		JDint("NFLOG", c->nflog_group);
	}

	if (c->sa_marks.in.val != 0) {
		JD("CONNMARK_IN", "%"PRIu32"/%#08"PRIx32, c->sa_marks.in.val, c->sa_marks.in.mask);
	}
	if (c->sa_marks.out.val != 0 && c->ipsec_interface == NULL) {
		JD("CONNMARK_OUT", "%"PRIu32"/%#08"PRIx32, c->sa_marks.out.val, c->sa_marks.out.mask);
	}
	if (c->ipsec_interface != NULL) {
		if (c->sa_marks.out.val != 0) {
			/* user configured XFRMI_SET_MARK (a.k.a. output mark) add it */
			JD("PLUTO_XFRMI_FWMARK", "%"PRIu32"/%#08"PRIx32, c->sa_marks.out.val, c->sa_marks.out.mask);
		} else if (address_in_selector_range(c->remote->host.addr, sr->remote->client)) {
			JD("PLUTO_XFRMI_FWMARK", "%"PRIu32"/0xffffffff", c->ipsec_interface->if_id);
		} else {
			address_buf bpeer;
			selector_buf peerclient_str;
			vdbg("not adding PLUTO_XFRMI_FWMARK. PLUTO_PEER=%s is not inside PLUTO_PEER_CLIENT=%s",
			     str_address(&c->remote->host.addr, &bpeer),
			     str_selector_range_port(&sr->remote->client, &peerclient_str));
			JDstr("PLUTO_XFRMI_FWMARK", "");
		}
	}

	JDstr("VTI_IFACE", (c->config->vti.interface == NULL ? "" : c->config->vti.interface));
	JDstr("VTI_ROUTING", bool_str(c->config->vti.routing));
	JDstr("VTI_SHARED", bool_str(c->config->vti.shared));

	if (c->local->child.has_cat) {
		JDstr("CAT", "YES");
	}

	JD("SPI_IN", "0x%x", (first_ipsec_proto == NULL ? 0 : ntohl(first_ipsec_proto->outbound.spi)));
	JD("SPI_OUT", "0x%x", (first_ipsec_proto == NULL ? 0 : ntohl(first_ipsec_proto->inbound.spi)));

	if (LDBGP(DBG_UPDOWN, verbose.logger)) {
		JDstr("IPSEC_INIT_SCRIPT_DEBUG", "yes");
	}

	/*
	 * Terminate envp
	 */
	if (envp == envp_end) {
		verror(0, "environment overflow");
		return false;
	}
	*envp++ = NULL;

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
#if 0
	/*
	 * Depending on context, logging for either the connection or
	 * the state?
	 *
	 * The sec_label code violates this expectation somehow.
	 * Perhaps the logger points at the IKE SA?
	 */
	PEXPECT(logger, ((c != NULL && c->logger == logger) ||
			 (child != NULL && child->sa.logger == logger)));
#endif

	/*
	 * Support for skipping updown, eg leftupdown="".  Useful on
	 * busy servers that do not need to use updown for anything.
	 * Same for never_negotiate().
	 */
	if (c->local->config->child.updown.command == NULL) {
		vdbg("skipped updown command - disabled per policy");
		return true;
	}

	if (c->child.spds.len > 1) {
		/* i.e., more selectors than just this */
		selector_pair_buf sb;
		vlog("running updown %s %s", verb,
		     str_selector_pair(&spd->local->client, &spd->remote->client, &sb));
	} else {
		vdbg("kernel: running updown command \"%s\" for verb %s ",
		     c->local->config->child.updown.command, verb);
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
	struct updown_exec exec;
	if (!build_updown_exec(&exec, verb, verb_suffix, c, spd,
			       child, updown_env, verbose)) {
		vlog("%s%s command too long!", verb,
		     verb_suffix);
		return false;
	}

	return server_runve(verb, exec.arg, exec.env, verbose);
}

bool updown_connection_spd(enum updown updown_verb,
			   const struct connection *c,
			   const struct spd *spd,
			   struct logger *logger/*C-or-CHILD*/)
{
	const char *verb;
	struct verbose verbose = verbose_updown(logger, updown_verb, &verb);

	selector_pair_buf sb;
	str_selector_pair_sensitive(&spd->local->client, &spd->remote->client, &sb);

	vtime_t start = vdbg_start("%s", sb.buf);

	/*
	 * XXX: struct spds .list[] is a pointer, not an array, so
	 * need to search .list[] for SPD.
	 */
	vexpect(c != NULL);
	if (verbose.debug) {
		bool found = false;
		FOR_EACH_ITEM(sspd, &c->child.spds) {
			if (sspd == spd) {
				found = true;
				break;
			}
		}
		vexpect(found);
	}

	bool ok = do_updown_verb(verb, c, spd, /*child*/NULL,
				 (struct updown_env) {0},
				 verbose);

	vdbg_stop(&start, "%s", sb.buf);
	return ok;
}

static bool updown_child_spd_1(const char *verb,
			       struct child_sa *child,
			       const struct spd *spd,
			       struct verbose verbose)
{
	selector_pair_buf sb;
	str_selector_pair_sensitive(&spd->local->client, &spd->remote->client, &sb);

	vtime_t start = vdbg_start("%s", sb.buf);

	bool ok = do_updown_verb(verb, child->sa.st_connection, spd, child,
				 (struct updown_env) {0}, verbose);

	vdbg_stop(&start, "%s", sb.buf);
	return ok;
}

static void update_wip(struct spd *spd, enum updown updown_verb, bool ok)
{
	switch (updown_verb) {
	case UPDOWN_UP:
		spd->wip.installed.up = ok;
		return;
	case UPDOWN_ROUTE:
		spd->wip.installed.route = ok;
		return;
	default:
		return;
	}
}

bool updown_child_spds(enum updown updown_verb,
		       struct child_sa *child,
		       struct updown_config config)
{
	const char *verb;
	struct verbose verbose = verbose_updown(child->sa.logger, updown_verb, &verb);

	vtime_t start = vdbg_start("spds");

	verbose.level++;
	FOR_EACH_ITEM(spd, &child->sa.st_connection->child.spds) {
		const struct spd *bare_route = spd->wip.conflicting.owner.bare_route;
		if (bare_route != NULL &&
		    config.skip_wip_conflicting_owner_bare_route) {
			selector_pair_buf spb, brb;
			vdbg("skipping %s as conflicting owner.bare_route %s",
			     str_selector_pair_sensitive(&spd->local->client,
							 &spd->remote->client, &spb),
			     str_selector_pair_sensitive(&bare_route->local->client,
							 &bare_route->remote->client, &brb));
			continue;
		}

		if (updown_verb == UPDOWN_DOWN &&
		    config.down_wip_installed_up &&
		    !spd->wip.installed.up) {
			selector_pair_buf spb;
			vdbg("skipping %s as not UP",
			     str_selector_pair_sensitive(&spd->local->client,
							 &spd->remote->client, &spb));
		}

		if (!updown_child_spd_1(verb, child, spd, verbose)) {
			if (config.return_error) {
				return false;
			}
			continue;
		}

		update_wip(spd, updown_verb, true);
	}
	verbose.level--;

	vdbg_stop(&start, "spds");
	return true;
}

stf_status updown_async_callback(struct state *st,
				 struct msg_digest *md,
				 int wstatus, shunk_t output,
				 void *callback_context,
				 struct logger *logger)
{
	PEXPECT(logger, st == NULL);
	PEXPECT(logger, md == NULL);
	PEXPECT(logger, callback_context == NULL);
	llog(ALL_STREAMS, logger, "async finished %d "PRI_SHUNK,
	     wstatus, pri_shunk(output));
	return STF_OK;
}

bool updown_async_child(bool prepare, bool route, bool up,
			struct child_sa *child)
{
	char verb[sizeof("prepare-route-up")];
	snprintf(verb, sizeof(verb),
		 "%s%s%s%s%s",
		 (prepare ? "prepare" : ""),
		 (prepare && (route || up) ? "-" : ""),
		 (route ? "route" : ""),
		 (route && up ? "-" : ""),
		 (up ? "up" : ""));

	struct verbose verbose = VERBOSE(DEBUG_STREAM, child->sa.logger, verb);
	struct updown_exec exec;
	if (!build_updown_exec(&exec, verb, /*verb_suffix*/"",
			       child->sa.st_connection,
			       /*spd*/child->sa.st_connection->child.spds.list,
			       child,
			       (struct updown_env) {0},
			       verbose)) {
		return false;
	}

	server_fork_exec(exec.arg[0], (char**)exec.arg, (char**)exec.env,
			 /*input*/null_shunk,
			 ALL_STREAMS,
			 updown_async_callback,
			 /*callback_context*/NULL,
			 child->sa.logger);
	return true;
}


/*
 * Delete any kernel policies for a connection and unroute it if route
 * isn't shared.
 */

void do_updown_unroute_spd(const struct spd *spd,
			   const struct spd_owner *owner,
			   struct child_sa *child/*could-be-null*/,
			   struct logger *logger/*could-be-ST-or-connection*/,
			   struct updown_env updown_env)
{
	const char *verb;
	struct verbose verbose = verbose_updown(logger, UPDOWN_UNROUTE, &verb);

	if (owner->bare_route != NULL) {
		vdbg("skip as has owner->bare_route");
		return;
	}

	vexpect(spd != NULL);

	selector_pair_buf sb;
	str_selector_pair_sensitive(&spd->local->client, &spd->remote->client, &sb);

	vtime_t start = vdbg_start("%s", sb.buf);
	do_updown_verb(verb, spd->connection, spd, child, updown_env, verbose);
	vdbg_stop(&start, "%s", sb.buf);
}

void jam_updown_status(struct jambuf *buf, const char *prefix,
		       const struct connection_end *end)
{
	/* PREFIX-updown= */
	jam_string(buf, " ");
	jam_string(buf, prefix);
	jam_string(buf, "updown=");
	if (end->config->child.updown.command == NULL) {
		jam_string(buf, "<disabled>");
	} else {
		jam_string(buf, end->config->child.updown.command);
	}
	jam_string(buf, ";");
	/* PREFIX-updown-config= */
	jam_string(buf, " ");
	jam_string(buf, prefix);
	jam_string(buf, "updown-config=");
	jam_flags_human(buf,
			end->config->child.updown.updown_config,
			&updown_config_names);
	jam_string(buf, ";");
}

