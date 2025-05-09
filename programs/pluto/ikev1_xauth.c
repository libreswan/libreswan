/* XAUTH related functions
 *
 * Copyright (C) 2001-2002 Colubris Networks
 * Copyright (C) 2003 Sean Mathews - Nu Tech Software Solutions, inc.
 * Copyright (C) 2003-2004 Xelerance Corporation
 * Copyright (C) 2009 Ken Wilson <Ken_Wilson@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2012 Wes Hardaker <opensource@hardakers.net>
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2013 Philippe Vouters <philippe.vouters@laposte.net>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Antony Antony <antony@phenome.org>
 * Copyright (C) 2017-2019 Andrew Cagney <cagney@gnu.org>
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
 *
 * This code originally written by Colubris Networks, Inc.
 * Extraction of patch and porting to 1.99 codebases by Xelerance Corporation
 * Porting to 2.x by Sean Mathews
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <limits.h>

#if defined(linux)
/* is supposed to be in unistd.h, but it isn't on linux */
#include <crypt.h>
#endif

#include "lswalloc.h"

#include "sysdep.h"
#include "lswconf.h"
#include "constants.h"

#include "defs.h"
#include "state.h"
#include "ikev1_msgid.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"	/* needs id.h */
#include "packet.h"
#include "demux.h"		/* needs packet.h */
#include "log.h"
#include "timer.h"
#include "server.h"
#include "keys.h"
#include "ipsec_doi.h"	/* needs demux.h and state.h */
#ifdef USE_PAM_AUTH
#include "pam_auth.h"
#endif
#include "crypto.h"
#include "ike_alg.h"
#include "secrets.h"
#include "ikev1.h"
#include "ikev1_xauth.h"
#include "addresspool.h"
#include "ip_address.h"
#include "send.h"		/* for send without recording */
#include "ikev1_send.h"
#include "ip_info.h"
#include "ikev1_hash.h"
#include "impair.h"
#include "ikev1_message.h"

struct attrs;
struct modecfg_pbs;

/* forward declarations */
static stf_status xauth_client_ackstatus(struct ike_sa *ike,
					 struct msg_digest *md,
					 uint16_t ap_id);

static diag_t process_mode_cfg_attrs(struct ike_sa *ike,
				     const char *modecfg_payload,
				     struct pbs_in *attrs,
				     struct attrs *attrs_received);

/* see emit_mode_cfg_attrs() */

struct attrs {
	bool ikev1_internal_ip4_address;
	bool ikev1_internal_ip4_netmask;
	bool ikev1_internal_ip4_dns;
	bool ikev1_internal_ip4_subnet;
	bool modecfg_domain;
	bool modecfg_banner;
	bool cisco_split_inc;
};

static bool visit_attrs(const struct attrs *attrs,
			struct modecfg_pbs *modecfg_pbs,
			const char *modecfg_payload,
			struct ike_sa *ike,
			bool (*visitor)(struct modecfg_pbs *, const char *modecfg_payload,
					unsigned, struct ike_sa *))
{
#define VISIT(FIELD, ATTR)						\
	if (attrs->FIELD) {						\
		if (!visitor(modecfg_pbs, modecfg_payload, ATTR, ike)) {	\
			return false;					\
		}							\
	}
	VISIT(ikev1_internal_ip4_address, IKEv1_INTERNAL_IP4_ADDRESS);
	VISIT(ikev1_internal_ip4_netmask, IKEv1_INTERNAL_IP4_NETMASK);
	VISIT(ikev1_internal_ip4_dns, IKEv1_INTERNAL_IP4_DNS);
	VISIT(ikev1_internal_ip4_subnet, IKEv1_INTERNAL_IP4_SUBNET);
	VISIT(modecfg_domain, MODECFG_DOMAIN);
	VISIT(modecfg_banner, MODECFG_BANNER);
	VISIT(cisco_split_inc, CISCO_SPLIT_INC);
#undef VISIT
	return true;
}

static bool set_attr(struct attrs *attrs, unsigned attr)
{
	switch (attr) {
	case IKEv1_INTERNAL_IP4_ADDRESS | ISAKMP_ATTR_AF_TLV:
		attrs->ikev1_internal_ip4_address = true;
		return true;
	case IKEv1_INTERNAL_IP4_NETMASK | ISAKMP_ATTR_AF_TLV:
		attrs->ikev1_internal_ip4_netmask = true;
		return true;
	case IKEv1_INTERNAL_IP4_DNS | ISAKMP_ATTR_AF_TLV:
		attrs->ikev1_internal_ip4_dns = true;
		return true;
	case IKEv1_INTERNAL_IP4_SUBNET | ISAKMP_ATTR_AF_TLV:
		attrs->ikev1_internal_ip4_subnet = true;
		return true;
	case MODECFG_DOMAIN | ISAKMP_ATTR_AF_TLV:
		attrs->modecfg_domain = true;
		return true;
	case MODECFG_BANNER | ISAKMP_ATTR_AF_TLV:
		attrs->modecfg_banner = true;
		return true;
	case CISCO_SPLIT_INC | ISAKMP_ATTR_AF_TLV:
		attrs->cisco_split_inc = true;
		return true;
	case IKEv1_INTERNAL_IP4_NBNS:
		/* ignore */
		return true;
	}
	return false;
}

/*
 * Danger: double negative logic.
 *
 * visit_attrs() returns true when there are no attrs; so have
 * no_attr(), and hence, vist_attrs() return false when there is an
 * attr.
 */

static bool no_attr(struct modecfg_pbs *pbs UNUSED,
		    const char *modecfg_payload UNUSED,
		    unsigned attr UNUSED,
		    struct ike_sa *ike UNUSED)
{
	return false;
}

static bool has_attrs(const struct attrs *attrs)
{
	/* i.e., there's not no attrs */
	return !visit_attrs(attrs, NULL, NULL, NULL, no_attr);
}

/* CISCO_SPLIT_INC example payload
 *  70 04      00 0e      0a 00 00 00 ff 00 00 00 00 00 00 00 00 00
 *   \/          \/        \ \  /  /   \ \  / /   \  \  \ /  /  /
 *  28676        14        10.0.0.0    255.0.0.0
 *
 *  SPLIT_INC  Length       IP addr      mask     proto?,sport?,dport?,proto?,sport?,dport?
 */

struct CISCO_split_item {
	struct in_addr cs_addr;
	struct in_addr cs_mask;
	uint8_t protos_and_ports[6];
};

static field_desc CISCO_split_fields[] = {
	{ ft_raw, 4, "IPv4 address", NULL },
	{ ft_raw, 4, "IPv4 mask", NULL },
	{ ft_zig, 6, "protos and ports?", NULL },
	{ ft_end, 0, NULL, NULL }
};

struct_desc CISCO_split_desc = 	{
	.name = "CISCO split item",
	.fields = CISCO_split_fields,
	.size = 14,
};

oakley_auth_t xauth_calcbaseauth(oakley_auth_t baseauth)
{
	switch (baseauth) {
	case HybridInitRSA:
	case HybridRespRSA:
	case XAUTHInitRSA:
	case XAUTHRespRSA:
		baseauth = OAKLEY_RSA_SIG;
		break;

	case XAUTHInitDSS:
	case XAUTHRespDSS:
	case HybridInitDSS:
	case HybridRespDSS:
		baseauth = OAKLEY_DSS_SIG;
		break;

	case XAUTHInitPreShared:
	case XAUTHRespPreShared:
		baseauth = OAKLEY_PRESHARED_KEY;
		break;

	case XAUTHInitRSAEncryption:
	case XAUTHRespRSAEncryption:
		baseauth = OAKLEY_RSA_ENC;
		break;

	/* Not implemented */
	case XAUTHInitRSARevisedEncryption:
	case XAUTHRespRSARevisedEncryption:
		baseauth = OAKLEY_RSA_REVISED_MODE;
		break;
	}

	return baseauth;
}

/**
 * Compute HASH of Mode Config.
 *
 * @param dest
 * @param start
 * @param roof
 * @param st State structure
 * @return size_t Length of the HASH
 */

static bool emit_xauth_hash(struct ike_sa *ike, const char *what,
			    struct v1_hash_fixup *hash_fixup, struct pbs_out *out)
{
	return emit_v1_HASH(V1_HASH_1, what,
			    IMPAIR_v1_XAUTH_EXCHANGE,
			    &ike->sa, hash_fixup, out);
}

static void fixup_xauth_hash(struct ike_sa *ike,
			     struct v1_hash_fixup *hash_fixup,
			     const uint8_t *roof)
{
	fixup_v1_HASH(&ike->sa, hash_fixup, ike->sa.st_v1_msgid.phase15, roof);
}

/**
 * Add ISAKMP attribute
 *
 * Add a given Mode Config attribute to the reply stream.
 *
 * @param struct pbs_out strattr the reply stream (stream)
 * @param attr_type int the attribute type
 * @param ia internal_addr the IP information for the connection
 * @param st State structure
 * @return stf_status STF_OK or STF_INTERNAL_ERROR
 */

struct modecfg_pbs {
	struct pbs_out pbs;
};

static bool modecfg_out_open(struct pbs_out *rbody,
			     struct modecfg_pbs *modecfg_pbs,
			     const struct isakmp_mode_attr *attrh)
{
	return pbs_out_struct(rbody, &isakmp_attr_desc,
			      attrh, sizeof(*attrh), &modecfg_pbs->pbs);
}

static bool modecfg_out_attr(struct modecfg_pbs *modecfg_pbs,
			     const struct isakmp_attribute *attr,
			     struct pbs_out *attrval)
{
	return pbs_out_struct(&modecfg_pbs->pbs,
			      &isakmp_xauth_attribute_desc,
			      attr, sizeof(*attr),
			      attrval);
}

static bool modecfg_out_close(struct modecfg_pbs *modecfg_pbs, struct ike_sa *ike)
{
	if (ike != NULL && ike->sa.st_connection->config->v1_ikepad.modecfg) {
		emit_v1_zero_padding(&modecfg_pbs->pbs);
	}

	return close_pbs_out(&modecfg_pbs->pbs);
}

static bool isakmp_add_attr(struct modecfg_pbs *modecfg_pbs,
			    const int attr_type,
			    const struct ike_sa *ike)
{
	struct connection *c = ike->sa.st_connection;

	/* ISAKMP attr out */
	const struct isakmp_attribute attr = {
		.isaat_af_type = attr_type | ISAKMP_ATTR_AF_TLV
	};

	struct pbs_out attrval;
	if (!modecfg_out_attr(modecfg_pbs, &attr, &attrval)) {
		return false;
	}

	switch (attr_type) {
	case IKEv1_INTERNAL_IP4_ADDRESS:
	{
		/* YES, REMOTE, as leased */
		if (!PEXPECT(ike->sa.logger, c->child.spds.list->remote->client.is_set)) {
			return false;
		}
		if (!pbs_out_address(&attrval,
				     selector_prefix(c->child.spds.list->remote->client),
				     "IP_addr")) {
			/* already logged */
			return false;
		}
		break;
	}

	case IKEv1_INTERNAL_IP4_SUBNET:
	{
		if (!PEXPECT(ike->sa.logger, c->child.spds.list->local->client.is_set)) {
			return false;
		}
		ip_address addr = selector_prefix(c->child.spds.list->local->client);
		if (!pbs_out_address(&attrval, addr, "IP4_subnet(address)")) {
			/* already logged */
			return false;
		}
		ip_address mask = selector_prefix_mask(c->child.spds.list->local->client);
		if (!pbs_out_address(&attrval, mask, "IP4_subnet(mask)")) {
			/* already logged */
			return false;
		}
		break;
	}

	case IKEv1_INTERNAL_IP4_NETMASK:
	{
		if (!PEXPECT(ike->sa.logger, c->child.spds.list->local->client.is_set)) {
			return false;
		}
		ip_address mask = selector_prefix_mask(c->child.spds.list->local->client);
		if (!pbs_out_address(&attrval, mask, "IP4_netmask")) {
			/* already logged */
			return false;
		}
		break;
	}

	case IKEv1_INTERNAL_IP4_DNS:
	{
		/*
		 * Emit one attribute per DNS IP (all other cases emit
		 * exactly one attribute).
		 *
		 * The first's emission is started above and the
		 * last's is finished at the end so our loop structure
		 * is odd.
		 */
		ip_address *end = c->config->modecfg.dns.list + c->config->modecfg.dns.len;
		FOR_EACH_ITEM(dns, &c->config->modecfg.dns) {

			/* emit attribute's value */
			if (!pbs_out_address(&attrval, *dns, "IP4_dns")) {
				/* already logged */
				return false;
			}

			if (dns + 1 < end) {
				/* end this attribute */
				close_output_pbs(&attrval);

				/* start the next attribute */
				if (!modecfg_out_attr(modecfg_pbs, &attr, &attrval)) {
					return false;
				}
			}
		}
		break;
	}

	case MODECFG_DOMAIN:
	{
		/*
		 * IKEv2 allows more then one, separated by comma or space
		 * We don't know if existing IKEv1 implementations support
		 * more then one, so we just send the first one configured.
		 */
		if (c->config->modecfg.domains != NULL) {
			ldbg(ike->sa.logger, "we are sending '"PRI_SHUNK"' as domain",
			     pri_shunk(c->config->modecfg.domains[0]));
			shunk_t first = c->config->modecfg.domains[0];
			if (!out_raw(first.ptr, first.len, &attrval, "MODECFG_DOMAIN")) {
				return false;
			}
		}
		break;
	}

	case MODECFG_BANNER:
		ldbg(ike->sa.logger, "we are sending '%s' as banner",
		     c->config->modecfg.banner);
		if (!out_raw(c->config->modecfg.banner,
			     strlen(c->config->modecfg.banner),
			     &attrval, "")) {
			return false;
		}
		break;

	/*
	 * XXX: not sending if our end is 0.0.0.0/0 equals previous
	 * previous behaviour.
	 */
	case CISCO_SPLIT_INC:
	{
		/* XXX: bitstomask(c->child.spds.list->local->client.maskbits), */
		ip_address mask = selector_prefix_mask(c->child.spds.list->local->client);
		ip_address addr = selector_prefix(c->child.spds.list->local->client);
		struct CISCO_split_item i = {0};
		memcpy_hunk(&i.cs_addr, address_as_shunk(&addr), sizeof(i.cs_addr));
		memcpy_hunk(&i.cs_mask, address_as_shunk(&mask), sizeof(i.cs_mask));
		if (!pbs_out_struct(&attrval, &CISCO_split_desc, &i, sizeof(i), NULL)) {
			return false;
		}
		break;
	}

	default:
	{
		esb_buf b;
		llog(RC_LOG, ike->sa.logger,
		     "attempt to send unsupported mode cfg attribute %s.",
		     str_enum(&modecfg_attr_names, attr_type, &b));
		break;
	}
	}

	if (!close_pbs_out(&attrval)) {
		return false;
	}

	return true;
}

/**
 * Mode Config Reply
 *
 * Generates a reply stream containing Mode Config information (eg: IP, DNS, WINS)
 *
 * @param st State structure
 * @param resp Type of reply (lset_t)  ??? why singular -- this is a set?
 * @param struct pbs_out rbody Body of the reply (stream)
 * @param replytype int
 * @param use_modecfg_addr_as_client_addr bool
 *	True means force the IP assigned by Mode Config to be the
 *	spd.that.addr.  Useful when you know the client will change peers IP
 *	to be what was assigned immediately after authentication.
 * @param ap_id ISAMA Identifier
 * @return stf_status STF_OK or STF_INTERNAL_ERROR
 */

static bool emit_mode_cfg_attr(struct modecfg_pbs *modecfg_pbs,
			       const char *modecfg_payload,
			       unsigned attr, struct ike_sa *ike)
{
	struct connection *c = ike->sa.st_connection;

	switch (attr) {

	case IKEv1_INTERNAL_IP4_DNS:
		/*
		 * If there's a DNS name, add that as a bonus.
		 *
		 * XXX: could this, with misconfiguration, cause the
		 * client to send the DNS name to the server?
		 */
		if (c->config->modecfg.dns.len == 0) {
			ldbg(ike->sa.logger, "skip sending internal DNS in %s payload, nothing to send",
			     modecfg_payload);
			return true;
		}
		return isakmp_add_attr(modecfg_pbs, attr, ike);

	case MODECFG_DOMAIN:
		if (c->config->modecfg.domains == NULL) {
			ldbg(ike->sa.logger, "skip sending domains in %s payload, nothing to send",
			     modecfg_payload);
			return true;
		}
		return isakmp_add_attr(modecfg_pbs, MODECFG_DOMAIN, ike);

	case MODECFG_BANNER:
		if (c->config->modecfg.banner == NULL) {
			ldbg(ike->sa.logger, "skip sending banner in %s payload, nothing to send",
			     modecfg_payload);
			return true;
		}
		return isakmp_add_attr(modecfg_pbs, MODECFG_BANNER, ike);

	case CISCO_SPLIT_INC:
		if (selector_is_unset(&c->child.spds.list->local->client) ||
		    selector_is_all(c->child.spds.list->local->client)) {
			ldbg(ike->sa.logger, "skip sending CISCO_SPLIT in %s payload, we are 0.0.0.0/0",
			     modecfg_payload);
			return true;
		}
		ldbg(ike->sa.logger, "sending CISCO_SPLIT in %s payload with our selectors",
		     modecfg_payload);
		return isakmp_add_attr(modecfg_pbs, CISCO_SPLIT_INC, ike);

	default:
		return isakmp_add_attr(modecfg_pbs, attr, ike);

	}
}

static bool emit_empty_mode_cfg_attr(struct modecfg_pbs *modecfg_pbs,
				     const char *modecfg_payload UNUSED,
				     unsigned attr_type,
				     struct ike_sa *ike UNUSED)
{
	struct isakmp_attribute attrh = {
		.isaat_af_type = attr_type,
	};
	return modecfg_out_attr(modecfg_pbs, &attrh, NULL);
}

/*
 * Get an inside IP address,
 *
 * IKEv1_INTERNAL_IP4_ADDRESS and DNS if any for a connection
 *
 * XXX: like for ikev2-hostpair-02, could this be re-assigning the
 * same address?
 *
 * XXX: IKEv1 only implements IPv4 leases.
 */

static bool get_internal_address(struct ike_sa *ike)
{
	struct connection *c = ike->sa.st_connection;
	/* our IKEv1 doesn't do IPv6 */
	const struct ip_info *afi = &ipv4_info;

	const char *from;
	if (c->pool[afi->ip_index] != NULL) {

		ip_address assigned_address;
		err_t e = assign_remote_lease(c, ike->sa.st_xauth_username, afi,
					      /*preferred-address*/unset_address,
					      &assigned_address,
					      ike->sa.logger);
		if (e != NULL) {
			llog(RC_LOG, ike->sa.logger, "leasing %s address failed: %s",
			     afi->ip_name, e);
			return false;
		}

		ldbg(c->logger, "another hack to get the SPD in sync");
		FOR_EACH_ITEM(spd, &c->child.spds) {
			spd->remote->client = selector_from_address(assigned_address);
			spd_db_rehash_remote_client(spd);
		}

		from = "lease";

	} else if (PEXPECT(ike->sa.logger, c->child.spds.list->remote->client.is_set)) {

		from = "remote SPD";

	} else {
		return false;
	}
	selector_buf iab;
	ldbg(ike->sa.logger, "internal address %s from %s",
	     str_selector(&c->child.spds.list->remote->client, &iab),
	     from);

	return true;
}

static bool record_n_send_v1_mode_cfg(struct ike_sa *ike,
				      unsigned mode_cfg_type,
				      struct attrs attrs_recv)
{
	struct fragment_pbs_out packet;
	if (!open_fragment_pbs_out("MODE_CFG", &packet, ike->sa.logger)) {
		return false;
	}

	/* HDR out */

	struct isakmp_hdr hdr = {
		.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
			ISAKMP_MINOR_VERSION,
		.isa_xchg = ISAKMP_XCHG_MODE_CFG,
		.isa_flags = ISAKMP_FLAGS_v1_ENCRYPTION,
		.isa_msgid = ike->sa.st_v1_msgid.phase15,
		.isa_ike_initiator_spi = ike->sa.st_ike_spis.initiator,
		.isa_ike_responder_spi = ike->sa.st_ike_spis.responder,
	};

	if (impair.send_bogus_isakmp_flag) {
		hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
	}

	struct pbs_out rbody;
	if (!pbs_out_struct(&packet.pbs, &isakmp_hdr_desc, &hdr, sizeof(hdr), &rbody))
		return false;

	struct v1_hash_fixup hash_fixup;
	if (!emit_xauth_hash(ike, "mode config",
			     &hash_fixup, &rbody)) {
		return false;
	}

	/* ATTR out */

	struct isakmp_mode_attr attrh = {
		.isama_type = mode_cfg_type,
		.isama_identifier = 0 /* XXX ID !?! */,
	};

	struct modecfg_pbs modecfg_pbs;
	if (!modecfg_out_open(&rbody, &modecfg_pbs, &attrh)) {
		return false;
	}

	/* will never include IPv6 */

	static const unsigned default_attrs[] = {
		IKEv1_INTERNAL_IP4_ADDRESS,
		IKEv1_INTERNAL_IP4_SUBNET,
		IKEv1_INTERNAL_IP4_DNS,
		MODECFG_DOMAIN,
		MODECFG_BANNER,
		CISCO_SPLIT_INC,
	};

	switch (mode_cfg_type) {

	case ISAKMP_CFG_REQUEST: /* client initiating */
		/* send empty prompts */
		FOR_EACH_ELEMENT(attr, default_attrs) {
			if (!emit_empty_mode_cfg_attr(&modecfg_pbs, "client REQUEST", (*attr), ike)) {
				return false;
			}
		}
		break;
	case ISAKMP_CFG_REPLY: /* server responding */
		if (!visit_attrs(&attrs_recv, &modecfg_pbs, "server RESPONSE", ike, emit_mode_cfg_attr)) {
			return false;
		}
		break;

	case ISAKMP_CFG_SET: /* server initiating */
		FOR_EACH_ELEMENT(attr, default_attrs) {
			if (!emit_mode_cfg_attr(&modecfg_pbs, "server SET", *attr, ike)) {
				return false;
			}
		}
		break;
	case ISAKMP_CFG_ACK: /* client responding */
		/* send back empty entries */
		visit_attrs(&attrs_recv, &modecfg_pbs, "client ACK", ike, emit_empty_mode_cfg_attr);
		break;

	default:
		bad_case(mode_cfg_type);
	}

	if (!modecfg_out_close(&modecfg_pbs, ike)) {
		return false;
	}

	fixup_xauth_hash(ike, &hash_fixup, rbody.cur);

	if (!close_and_encrypt_v1_message(ike, &rbody, &ike->sa.st_v1_phase_2_iv)) {
		return false;
	}

	/* Transmit */

	record_and_send_v1_ike_msg(&ike->sa, &packet.pbs, "ModeCfg set");
	return true;
}

/*
 * Danger: the caller, ikev1.c, will
 * record'n'send the global REPLY_STREAM being
 * built here!
 */
static bool build_v1_modecfg_ack_from_md_in_reply_stream(struct ike_sa *ike,
							 const struct attrs attrs_recv,
							 struct msg_digest *md)
{
	struct isakmp_mode_attr *ma = &md->chain[ISAKMP_NEXT_MODECFG]->payload.mode_attribute;

	struct pbs_out rbody;
	ikev1_init_pbs_out_from_md_hdr(md, /*encrypt*/true, &reply_stream,
				       reply_buffer, sizeof(reply_buffer),
				       &rbody, ike->sa.logger);

	struct v1_hash_fixup hash_fixup;
	if (!emit_xauth_hash(ike, "mode config",
			     &hash_fixup, &rbody)) {
		return false;
	}

	/* ATTR out */

	struct isakmp_mode_attr attrh = {
		.isama_type = ISAKMP_CFG_ACK,
		.isama_identifier = ma->isama_identifier,
	};

	struct modecfg_pbs modecfg_pbs;
	if (!modecfg_out_open(&rbody, &modecfg_pbs, &attrh)) {
		return false;
	}

	if (!visit_attrs(&attrs_recv, &modecfg_pbs, "client ack", ike, emit_mode_cfg_attr)) {
		return false;
	}

	if (!modecfg_out_close(&modecfg_pbs, ike)) {
		return false;
	}

	fixup_xauth_hash(ike, &hash_fixup, rbody.cur);

	ike->sa.st_v1_phase_2_iv = md->v1_decrypt_iv;
	if (!close_and_encrypt_v1_message(ike, &rbody, &ike->sa.st_v1_phase_2_iv)) {
		return false;
	}

	return true;
}

/**
 * Set MODE_CONFIG data to client.  Pack IP Addresses, DNS, etc... and
 * ship
 *
 * Caller transitions to STATE_MODE_CFG_RACK ready for ACK.
 *
 * @param st State Structure
 * @return stf_status
 */
stf_status initiate_MODE_CFG_SET(struct ike_sa *ike, struct crypt_mac iv)
{
	llog(RC_LOG, ike->sa.logger, "initiating MODE_CFG SET");

	/*
	 * When this is the first Phase 1.5 exchange, need to generate
	 * fresh IV and MSGID.
	 */
	if (ike->sa.st_v1_msgid.phase15 == v1_MAINMODE_MSGID/*0*/) {
		ldbg(ike->sa.logger, "MODECFG SET generating Phase-1.5 Message ID and IV");
		/* pick a new message id */
		ike->sa.st_v1_msgid.phase15 = generate_msgid(&ike->sa);
		/* update the IV */
		iv = new_phase2_iv(ike, ike->sa.st_v1_msgid.phase15,
				   "IKE sending MODECFG set", HERE);
	}

	ike->sa.hidden_variables.st_modecfg_vars_set = true;

	/*
	 * Update the IV ready for the encrypt; it was either
	 * generated above or from MD's .v1_decrypt_iv
	 */
	ike->sa.st_v1_phase_2_iv = iv;

	/*
	 * ISAKMP responder, get client's address from a lease when
	 * available.
	 */

	if (!get_internal_address(ike)) {
		return STF_FATAL;
	}

	if (!record_n_send_v1_mode_cfg(ike, ISAKMP_CFG_SET, (struct attrs){0})) {
		return STF_FATAL;
	}

	if (*state_event_slot(&ike->sa, EVENT_v1_RETRANSMIT) == NULL) {
		delete_v1_event(&ike->sa);
		clear_retransmits(&ike->sa);
		start_retransmits(&ike->sa);
	}

	change_v1_state(&ike->sa, STATE_MODE_CFG_SERVER_WAITING_FOR_ACK);
	return STF_OK;
}

/*
 * Send XAUTH credential request (username + password request)
 * @param st State
 * @return stf_status
 */
stf_status xauth_send_request(struct ike_sa *ike)
{
	const enum state_kind p_state = ike->sa.st_state->kind;

	/* set up reply */
	uint8_t buf[256];
	struct pbs_out reply = open_pbs_out("xauth_buf", buf, sizeof(buf), ike->sa.logger);

	llog(RC_LOG, ike->sa.logger,
	     "XAUTH: Sending Username/Password request (%s->XAUTH_R0)",
	     ike->sa.st_state->short_name);

	/* this is the beginning of a new exchange */
	ike->sa.st_v1_msgid.phase15 = generate_msgid(&ike->sa);
	change_v1_state(&ike->sa, STATE_XAUTH_R0);

	/* HDR out */
	struct pbs_out rbody;
	{
		struct isakmp_hdr hdr = {
			.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				  ISAKMP_MINOR_VERSION,
			.isa_xchg = ISAKMP_XCHG_MODE_CFG,
			.isa_flags = ISAKMP_FLAGS_v1_ENCRYPTION,
			.isa_msgid = ike->sa.st_v1_msgid.phase15,
		};

		if (impair.send_bogus_isakmp_flag) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}
		hdr.isa_ike_initiator_spi = ike->sa.st_ike_spis.initiator;
		hdr.isa_ike_responder_spi = ike->sa.st_ike_spis.responder;

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
			return STF_INTERNAL_ERROR;
	}

	struct v1_hash_fixup hash_fixup;
	if (!emit_xauth_hash(ike, "XAUTH: send request",
			     &hash_fixup, &rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* ATTR out */
	{
		struct isakmp_mode_attr attrh = {
			.isama_type = ISAKMP_CFG_REQUEST,
			.isama_identifier = 0,
		};
		struct modecfg_pbs modecfg_pbs;
		if (!modecfg_out_open(&rbody, &modecfg_pbs, &attrh)) {
			return STF_INTERNAL_ERROR;
		}

		/* Empty name attribute */
		struct isakmp_attribute nm = {
			.isaat_af_type = IKEv1_ATTR_XAUTH_USER_NAME,
		};
		if (!modecfg_out_attr(&modecfg_pbs, &nm, NULL)) {
			return STF_INTERNAL_ERROR;
		}

		/* Empty password attribute */
		struct isakmp_attribute pw = {
			.isaat_af_type = IKEv1_ATTR_XAUTH_USER_PASSWORD,
		};
		if (!modecfg_out_attr(&modecfg_pbs, &pw, NULL)) {
			return STF_INTERNAL_ERROR;
		}

		if (!modecfg_out_close(&modecfg_pbs, ike)) {
			return STF_INTERNAL_ERROR;
		}
	}

	fixup_xauth_hash(ike, &hash_fixup, rbody.cur);
	ike->sa.st_v1_phase_2_iv =
		new_phase2_iv(ike, ike->sa.st_v1_msgid.phase15, "IKE sending xauth request", HERE);

	if (!close_and_encrypt_v1_message(ike, &rbody, &ike->sa.st_v1_phase_2_iv)) {
		return STF_INTERNAL_ERROR;
	}

	/* Transmit */
	if (!impair.send_no_xauth_r0) {
		if (p_state == STATE_AGGR_R2) {
			record_and_send_v1_ike_msg(&ike->sa, &reply, "XAUTH: req");
		} else {
			/*
			 * Main Mode responder: do not record XAUTH_R0 message.
			 * If retransmit timer goes off, retransmit the last
			 * Main Mode message and send/create a new XAUTH_R0
			 * message.
			 */
			send_pbs_out_using_state(&ike->sa, "XAUTH: req (unrecorded)", &reply);
		}
	} else {
		llog(RC_LOG, ike->sa.logger, "IMPAIR: Skipped sending XAUTH user/pass packet");
		if (p_state == STATE_AGGR_R2) {
			/* record-only so we properly emulate packet drop */
			record_outbound_v1_ike_msg(&ike->sa, &reply, "XAUTH: req");
		}
	}

	if (*state_event_slot(&ike->sa, EVENT_v1_RETRANSMIT) == NULL) {
		delete_v1_event(&ike->sa);
		clear_retransmits(&ike->sa);
		start_retransmits(&ike->sa);
	}

	return STF_OK;
}

/** Send modecfg IP address request (IP4 address)
 * @param st State
 * @return stf_status
 */

stf_status modecfg_send_request(struct ike_sa *ike)
{
	log_state(RC_LOG, &ike->sa, "modecfg: Sending IP request (MODECFG_I1)");

	/* this is the beginning of a new exchange */
	ike->sa.st_v1_msgid.phase15 = generate_msgid(&ike->sa);
	ike->sa.st_v1_phase_2_iv = new_phase2_iv(ike, ike->sa.st_v1_msgid.phase15,
						 "IKE sending mode cfg request", HERE);
	change_v1_state(&ike->sa, STATE_MODE_CFG_I1);

	if (!record_n_send_v1_mode_cfg(ike, ISAKMP_CFG_REQUEST, (struct attrs){0})) {
		return STF_FATAL;
	}

	if (*state_event_slot(&ike->sa, EVENT_v1_RETRANSMIT) == NULL) {
		delete_v1_event(&ike->sa);
		clear_retransmits(&ike->sa);
		start_retransmits(&ike->sa);
	}
	ike->sa.hidden_variables.st_modecfg_started = true;

	return STF_OK;
}

/** Send XAUTH status to client
 *
 * @param st State
 * @param status Status code
 * @return stf_status
 */
/* IN AN AUTH THREAD */
static stf_status xauth_send_status(struct ike_sa *ike, int status)
{
	/* set up reply */
	uint8_t buf[256];
	struct pbs_out reply = open_pbs_out("xauth_buf", buf, sizeof(buf), ike->sa.logger);

	/* pick a new message id */
	ike->sa.st_v1_msgid.phase15 = generate_msgid(&ike->sa);

	/* HDR out */
	struct pbs_out rbody;
	{
		struct isakmp_hdr hdr = {
			.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				  ISAKMP_MINOR_VERSION,
			.isa_xchg = ISAKMP_XCHG_MODE_CFG,
			.isa_flags = ISAKMP_FLAGS_v1_ENCRYPTION,
			.isa_msgid = ike->sa.st_v1_msgid.phase15,
		};

		if (impair.send_bogus_isakmp_flag) {
			hdr.isa_flags |= ISAKMP_FLAGS_RESERVED_BIT6;
		}
		hdr.isa_ike_initiator_spi = ike->sa.st_ike_spis.initiator;
		hdr.isa_ike_responder_spi = ike->sa.st_ike_spis.responder;

		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply, &rbody))
			return STF_INTERNAL_ERROR;
	}

	struct v1_hash_fixup hash_fixup;
	if (!emit_xauth_hash(ike, "XAUTH: status", &hash_fixup, &rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* ATTR out */
	{
		struct isakmp_mode_attr attrh = {
			.isama_type = ISAKMP_CFG_SET,
			.isama_identifier = 0,
		};
		struct modecfg_pbs modecfg_pbs;
		if (!modecfg_out_open(&rbody, &modecfg_pbs, &attrh)) {
			return STF_INTERNAL_ERROR;
		}

		/* ISAKMP attr out (status) */
		struct isakmp_attribute attr = {
			.isaat_af_type = IKEv1_ATTR_XAUTH_STATUS | ISAKMP_ATTR_AF_TV,
			.isaat_lv = status,
		};
		if (!modecfg_out_attr(&modecfg_pbs, &attr, NULL)) {
			return STF_INTERNAL_ERROR;
		}

		if (!modecfg_out_close(&modecfg_pbs, ike)) {
			return STF_INTERNAL_ERROR;
		}
	}

	fixup_xauth_hash(ike, &hash_fixup, rbody.cur);
	ike->sa.st_v1_phase_2_iv = new_phase2_iv(ike, ike->sa.st_v1_msgid.phase15,
					 "IKE sending xauth status", HERE);

	if (!close_and_encrypt_v1_message(ike, &rbody, &ike->sa.st_v1_phase_2_iv)) {
		return STF_INTERNAL_ERROR;
	}

	/* Set up a retransmission event, half a minute hence */
	/* Schedule retransmit before sending, to avoid race with main thread */
	delete_v1_event(&ike->sa);
	clear_retransmits(&ike->sa);
	start_retransmits(&ike->sa);

	/* Transmit */
	record_and_send_v1_ike_msg(&ike->sa, &reply, "XAUTH: status");

	if (status != 0)
		change_v1_state(&ike->sa, STATE_XAUTH_R1);

	return STF_OK;
}

/*
 * set user defined ip address or pool
 */

static bool add_xauth_addresspool(struct connection *c,
				  const char *userid,
				  const char *addresspool,
				  struct logger *logger)
{
	VERBOSE_DBGP(DBG_BASE, logger, "%s() ...", __func__);

	dbg("XAUTH: adding addresspool entry %s for the conn %s user %s",
	    addresspool, c->name, userid);

	/* allows <address>, <address>-<address> and <address>/bits */

	ip_range pool_range;
	err_t err = ttorange_num(shunk1(addresspool), &ipv4_info, &pool_range);
	if (err != NULL) {
		llog(RC_LOG, logger,
		     "XAUTH IP addresspool %s for the conn %s user %s is not valid: %s",
		     addresspool, c->name, userid, err);
		return false;
	}

	if (range_size(pool_range) == 0) {
		/* should have been rejected by ttorange() */
		llog(RC_LOG, logger,
		     "XAUTH IP addresspool %s for the conn %s user=%s is empty!?!",
		     addresspool, c->name, userid);
		return false;
	}

	if (!address_is_specified(range_start(pool_range))) {
		llog(RC_LOG, logger,
		     "XAUTH IP addresspool %s for the conn %s user=%s cannot start at address zero",
		     addresspool, c->name, userid);
		return false;
	}

	/*
	 * Install new addresspool
	 *
	 * First delete any existing pool if it exists.
	 */

	if (c->pool[IPv4_INDEX] != NULL) {
		free_that_address_lease(c, &ipv4_info, logger);
		addresspool_delref(&c->pool[IPv4_INDEX], logger);
	}

	diag_t d = install_addresspool(pool_range, c->pool, logger);
	if (d != NULL) {
		llog(RC_CLASH, logger, "XAUTH: invalid addresspool for the conn %s user %s: %s",
		     c->name, userid, str_diag(d));
		pfree_diag(&d);
		return false;
	}

	/*
	 * Now update the selectors, and re-build the SPDs.
	 */
	zero(&c->remote->child.selectors.proposed);
	ip_selector selector = selector_from_range(pool_range);
	selector_buf sb;
	vdbg("%s selector formed from address pool %s",
	     c->remote->config->leftright, str_selector(&selector, &sb));
	append_end_selector(c->remote, selector_info(selector), selector, verbose.logger, HERE);

	discard_connection_spds(c);
	add_connection_spds(c);

	return true;
}

/** Do authentication via /etc/ipsec.d/passwd file using MD5 passwords
 *
 * Structure is one entry per line.
 * Each line has fields separated by colons.
 * Empty lines and lines starting with # are ignored.
 * Whitespace is NOT ignored.
 *
 * Syntax of an entry:
 *	username:passwdhash[:connectioname[:addresspool]]
 *
 * If connectionname is present and not empty,
 * the entry only applies to connections with that name.
 * Otherwise the entry applies to all connections.
 *
 * Example creation of file with two entries (without connectionname):
 *	htpasswd -c -b /etc/ipsec.d/passwd road roadpass
 *	htpasswd -b /etc/ipsec.d/passwd home homepass
 *
 * NOTE: htpasswd on your system may create a crypt() incompatible hash
 * by default (i.e. a type id of $apr1$). To create a crypt() compatible
 * hash with htpasswd use the -d option.
 *
 * @return bool success
 */

static bool do_file_authentication(struct ike_sa *ike, const char *name,
				   const char *password, const char *connname)
{
	char pswdpath[PATH_MAX];
	char line[1024]; /* we hope that this is more than enough */
	int lineno = 0;
	bool win = false;

	snprintf(pswdpath, sizeof(pswdpath), "%s/passwd", lsw_init_options()->confddir);

	FILE *fp = fopen(pswdpath, "r");
	if (fp == NULL) {
		/* unable to open the password file */
		llog(RC_LOG, ike->sa.logger,
		     "XAUTH: unable to open password file (%s) for verification",
		     pswdpath);
		return false;
	}

	llog(RC_LOG, ike->sa.logger, "XAUTH: password file (%s) open.", pswdpath);

	/** simple stuff read in a line then go through positioning
	 * userid, passwd and conniectionname at the beginning of each of the
	 * memory locations of our real data and replace the ':' with '\0'
	 */

	while (fgets(line, sizeof(line), fp) != NULL) {
		char *p;	/* current position */
		char *userid;
		char *passwdhash;
		char *connectionname = NULL;
		char *addresspool = NULL;
		struct connection *c = ike->sa.st_connection;

		lineno++;

		/* strip final \n (optional: we accept a partial last line) */
		p = strchr(line, '\n');
		if (p != NULL)
			*p = '\0';

		/* ignore empty or comment line */
		if (*line == '\0' || *line == '#')
			continue;

		/* get userid */
		userid = line;
		p = strchr(userid, ':');	/* find end */
		if (p == NULL) {
			/* no end: skip line */
			llog(RC_LOG, ike->sa.logger,
			     "XAUTH: %s:%d missing password hash field",
			     pswdpath, lineno);
			continue;
		}

		*p++ ='\0'; /* terminate string by overwriting : */

		/* get password hash */
		passwdhash = p;
		p = strchr(passwdhash, ':'); /* find end */
		if (p != NULL) {
			/* optional connectionname */
			*p++='\0';     /* terminate string by overwriting : */
			connectionname = p;
			p = strchr(connectionname, ':'); /* find end */
			/* ??? any whitespace is included */
		}

		if (p != NULL) {
			/* optional addresspool */
			*p++ ='\0'; /* terminate connectionname string by overwriting : */
			addresspool = p;
		}

		/* now connnectionname is terminated; set to NULL if empty */
		if (connectionname != NULL && connectionname[0] == '\0')
			connectionname = NULL;

		dbg("XAUTH: found user(%s/%s) pass(%s) connid(%s/%s) addresspool(%s)",
		    userid, name, passwdhash,
		    connectionname == NULL ? "" : connectionname,
		    connname,
		    addresspool == NULL ? "" : addresspool);

		/* If connectionname is null, it applies to all connections */
		if (streq(userid, name) &&
		    (connectionname == NULL || streq(connectionname, connname)))
		{
			const char *cp;
			/*
			 * keep the passwords using whatever utilities
			 * we have NOTE: crypt() may not be
			 * thread-safe
			 */
			cp = crypt(password, passwdhash);
			win = cp != NULL && streq(cp, passwdhash);

			ldbgf(DBG_CRYPT, ike->sa.logger, "XAUTH: %s user(%s:%s) pass %s vs %s",
			      win ? "success" : "failure",
			      userid, connectionname, cp, passwdhash);

			llog(RC_LOG, ike->sa.logger, "XAUTH: %s user(%s:%s) ",
			     win ? "success" : "failure",
			     userid, connectionname);

			if (win) {
				if (addresspool != NULL && addresspool[0] != '\0') {
					/* ??? failure to add addresspool seems like a funny failure */
					/* ??? should we then keep trying other entries? */
					if (!add_xauth_addresspool(c, userid,
								   addresspool,
								   ike->sa.logger)) {
						win = false;
						continue;	/* try other entries */
					}
				}
				break;	/* we have a winner */
			}
		}
	}

	fclose(fp);
	return win;
}

/*
 * Main authentication routine will then call the actual compiled-in
 * method to verify the user/password
 */

#ifdef USE_PAM_AUTH
static pam_auth_callback_fn ikev1_xauth_callback;	/* type assertion */
#endif

static stf_status ikev1_xauth_callback(struct ike_sa *ike,
				       struct msg_digest *md UNUSED,
				       const char *name, bool results)
{
	if (ike == NULL) {
		return STF_INTERNAL_ERROR;
	}
	ldbg(ike->sa.logger, "%s() for "PRI_SO, __func__, pri_so(ike->sa.st_serialno));

	/*
	 * If XAUTH authentication failed, should we soft fail or hard fail?
	 * The soft fail mode is used to bring up the SA in a walled garden.
	 * This can be detected in the updown script by the env variable XAUTH_FAILED=1
	 */
	if (!results && ike->sa.st_connection->config->xauthfail == XAUTHFAIL_SOFT) {
		llog(RC_LOG, ike->sa.logger,
		     "XAUTH: authentication for %s failed, but policy is set to soft fail",
		     name);
		ike->sa.st_xauth_soft = true; /* passed to updown for notification */
		results = true;
	}

	if (results) {
		llog(RC_LOG, ike->sa.logger,
		     "XAUTH: User %s: Authentication Successful",
		     name);
		/* ??? result of xauth_send_status is ignored */
		xauth_send_status(ike, XAUTH_STATUS_OK);

		if (ike->sa.st_v1_quirks.xauth_ack_msgid)
			ike->sa.st_v1_msgid.phase15 = v1_MAINMODE_MSGID;

		jam_str(ike->sa.st_xauth_username, sizeof(ike->sa.st_xauth_username), name);
	} else {
		/*
		 * Login attempt failed, display error, send XAUTH status to client
		 * and reset state to XAUTH_R0
		 */
		llog(RC_LOG, ike->sa.logger,
		     "XAUTH: User %s: Authentication Failed: Incorrect Username or Password",
		     name);
		/* ??? result of xauth_send_status is ignored */
		xauth_send_status(ike, XAUTH_STATUS_FAIL);
	}
	return STF_SKIP_COMPLETE_STATE_TRANSITION;
}

/*
 * Schedule the XAUTH callback for NOW so it is (we hope) run next.
 *
 * This way all xauth mechanisms use the same code paths - suspend
 * state and then finish things in ikev1_xauth_callback().
 */

struct xauth_immediate_context {
	bool success;
	so_serial_t serialno;
	char *name;
	struct msg_digest *md;
};

static resume_cb xauth_immediate_callback;
static stf_status xauth_immediate_callback(struct state *ike_sa,
					   struct msg_digest *md,
					   void *arg)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa); /* could be NULL! */
	struct xauth_immediate_context *xic = (struct xauth_immediate_context *)arg;
	if (ike == NULL) {
		llog(RC_LOG, &global_logger,
		     "XAUTH: #%lu: state destroyed for user '%s'",
		     xic->serialno, xic->name);
	} else {
		/* ikev1_xauth_callback() will log result */
		ikev1_xauth_callback(ike, md, xic->name, xic->success);
	}
	pfree(xic->name);
	md_delref(&xic->md);
	pfree(xic);
	return STF_SKIP_COMPLETE_STATE_TRANSITION;
}

static void xauth_immediate(const char *name, const struct ike_sa *ike,
			    struct msg_digest *md, bool success)
{
	struct xauth_immediate_context *xic = alloc_thing(struct xauth_immediate_context, "xauth next");
	xic->success = success;
	xic->serialno = ike->sa.st_serialno;
	xic->name = clone_str(name, "xauth next name");
	xic->md = md_addref(md);
	schedule_resume("xauth immediate", ike->sa.st_serialno, &xic->md,
			xauth_immediate_callback, xic);
}

/** Launch an authentication prompt
 *
 * @param st State Structure
 * @param name Username
 * @param password Password
 */

static void xauth_launch_authent(struct ike_sa *ike,
				 struct msg_digest *md,
				 shunk_t *name,
				 shunk_t *password)
{
	/*
	 * XAUTH somehow already in progress?
	 */
#ifdef USE_PAM_AUTH
	if (ike->sa.st_pam_auth != NULL)
		return;
#endif

	char *arg_name = clone_hunk_as_string(*name, "NUL-terminated XAUTH name");
	char *arg_password = clone_hunk_as_string(*password, "NUL-terminated XAUTH password");

	/*
	 * For XAUTH, we're flipping between retransmitting the packet
	 * in the retransmit slot, and the XAUTH packet.
	 * Two alternative events can be outstanding. Cancel both.
	 */
	delete_v1_event(&ike->sa);
	clear_retransmits(&ike->sa);
	event_delete(EVENT_v1_SEND_XAUTH, &ike->sa);
	event_schedule(EVENT_v1_PAM_TIMEOUT, EVENT_v1_PAM_TIMEOUT_DELAY, &ike->sa);

	switch (ike->sa.st_connection->config->xauthby) {
#ifdef USE_PAM_AUTH
	case XAUTHBY_PAM:
		llog(RC_LOG, ike->sa.logger,
		     "XAUTH: PAM authentication method requested to authenticate user '%s'",
		     arg_name);
		pam_auth_fork_request(ike, md, arg_name, arg_password,
				      "XAUTH", ikev1_xauth_callback);
		break;
#endif

	case XAUTHBY_FILE:
		llog(RC_LOG, ike->sa.logger,
		     "XAUTH: password file authentication method requested to authenticate user '%s'",
		     arg_name);
		bool success = do_file_authentication(ike, arg_name, arg_password,
						      ike->sa.st_connection->name);
		xauth_immediate(arg_name, ike, md, success);
		break;

	case XAUTHBY_ALWAYSOK:
		llog(RC_LOG, ike->sa.logger,
		     "XAUTH: authentication method 'always ok' requested to authenticate user '%s'",
		     arg_name);
		xauth_immediate(arg_name, ike, md, true);
		break;

	default:
		llog(RC_LOG, ike->sa.logger,
		     "XAUTH: unknown authentication method requested to authenticate user '%s'",
		     arg_name);
		bad_case(ike->sa.st_connection->config->xauthby);
	}

	pfreeany(arg_name);
	pfreeany(arg_password);
}

/* log a nice description of an unsupported attribute */
static void log_bad_attr(const char *kind, enum_names *ed, unsigned val)
{
	esb_buf b;
	dbg("Unsupported %s %s attribute %s received.",
	    kind,
	    (val & ISAKMP_ATTR_AF_MASK) == ISAKMP_ATTR_AF_TV ? "basic" : "long",
	    str_enum(ed, val & ISAKMP_ATTR_RTYPE_MASK, &b));
}

/*
 * STATE_XAUTH_R0:
 * First REQUEST sent, expect for REPLY
 * HDR*, HASH, ATTR(REPLY,PASSWORD) --> HDR*, HASH, ATTR(STATUS)
 *
 * @param md Message Digest
 * @return stf_status
 */
stf_status xauth_inR0(struct state *ike_sa, struct msg_digest *md)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		return STF_INTERNAL_ERROR;
	}
	ldbg(ike->sa.logger, "%s() for "PRI_SO, __func__, pri_so(ike->sa.st_serialno));

	struct pbs_in *attrs = &md->chain[ISAKMP_NEXT_MODECFG]->pbs;

	/*
	 * There are many ways out of this routine
	 * so we don't want an obligation to free anything.
	 * We manage this by making these chunks just
	 * references to parts of the input packet.
	 */
	static const unsigned char unknown[] = "<unknown>";	/* never written to */
	shunk_t name = null_shunk;
	shunk_t password = null_shunk;
	bool gotname = false;
	bool gotpassword = false;

	name = shunk2(unknown, sizeof(unknown) - 1);	/* to make diagnostics easier */
	struct isakmp_mode_attr *ma = &md->chain[ISAKMP_NEXT_MODECFG]->payload.mode_attribute;

	/* XXX This needs checking with the proper RFC's - ISAKMP_CFG_ACK got added for Cisco interop */
	switch (ma->isama_type) {
	case ISAKMP_CFG_REPLY:
	case ISAKMP_CFG_ACK:
		break;	/* OK */
	default:
	{
		enum_buf mb;
		llog(RC_LOG, ike->sa.logger,
		     "expecting MODE_CFG_REPLY or ISAKMP_CFG_ACK; got %s instead; message ignored",
		     str_enum(&attr_msg_type_names, ma->isama_type, &mb));
		return STF_IGNORE;
	}
	}

	while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
		struct isakmp_attribute attr;
		struct pbs_in strattr;
		size_t sz;

		diag_t d = pbs_in_struct(attrs, &isakmp_xauth_attribute_desc,
					 &attr, sizeof(attr), &strattr);
		if (d != NULL) {
			llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
			pfree_diag(&d);
			/* fail if malformed */
			return STF_FAIL_v1N;
		}

		switch (attr.isaat_af_type) {
		case IKEv1_ATTR_XAUTH_TYPE | ISAKMP_ATTR_AF_TV:
			/* since we only accept XAUTH_TYPE_GENERIC we
			 * don't need to record this attribute */
			if (attr.isaat_lv != IKEv1_XAUTH_TYPE_GENERIC) {
				enum_buf b;
				ldbg(ike->sa.logger, "unsupported XAUTH_TYPE value %s received",
				     str_enum(&ikev1_xauth_type_names, attr.isaat_lv, &b));
				return STF_FAIL_v1N + v1N_NO_PROPOSAL_CHOSEN;
			}
			break;

		case IKEv1_ATTR_XAUTH_USER_NAME | ISAKMP_ATTR_AF_TLV:
			if (gotname) {
				dbg("XAUTH: two User Names!  Rejected");
				return STF_FAIL_v1N + v1N_NO_PROPOSAL_CHOSEN;
			}
			sz = pbs_left(&strattr);
			if (strnlen((const char *)strattr.cur, sz) != sz) {
				llog(RC_LOG, ike->sa.logger,
				     "XAUTH User Name contains NUL character: rejected");
				return STF_FAIL_v1N + v1N_NO_PROPOSAL_CHOSEN;
			}
			name = shunk2(strattr.cur, sz);
			gotname = true;
			break;

		case IKEv1_ATTR_XAUTH_USER_PASSWORD | ISAKMP_ATTR_AF_TLV:
			if (gotpassword) {
				llog(RC_LOG, ike->sa.logger,
				     "XAUTH: two User Passwords!  Rejected");
				return STF_FAIL_v1N + v1N_NO_PROPOSAL_CHOSEN;
			}
			sz = pbs_left(&strattr);
			if (sz > 0 && strattr.cur[sz-1] == '\0') {
				llog(RC_LOG, ike->sa.logger,
				     "Ignoring NUL at end of XAUTH User Password (Android Issue 36879?)");
				sz--;
			}
			if (strnlen((const char *)strattr.cur, sz) != sz) {
				llog(RC_LOG, ike->sa.logger,
				     "XAUTH User Password contains NUL character: rejected");
				return STF_FAIL_v1N + v1N_NO_PROPOSAL_CHOSEN;
			}
			password = shunk2(strattr.cur, sz);
			gotpassword = true;
			break;

		default:
			log_bad_attr("XAUTH (inR0)", &xauth_attr_names, attr.isaat_af_type);
			break;
		}
	}

	/** we must get a username and a password value */
	if (!gotname || !gotpassword) {
		llog(RC_LOG, ike->sa.logger,
		     "Expected MODE_CFG_REPLY is missing %s%s%s attribute",
		     !gotname ? "username" : "",
		     !gotname && !gotpassword ? " and " : "",
		     !gotpassword ? "password" : "");
		if (ike->sa.hidden_variables.st_xauth_client_attempt++ < XAUTH_PROMPT_TRIES) {
			stf_status stat = xauth_send_request(ike);
			LLOG_JAMBUF(RC_LOG, ike->sa.logger, buf) {
				jam_string(buf, "XAUTH: User ");
				jam_sanitized_hunk(buf, name);
				jam(buf, ": Authentication Failed (retry %d)",
				    ike->sa.hidden_variables.st_xauth_client_attempt);
			}
			/**
			 * STF_OK means that we transmitted again okay, but actually
			 * the state transition failed, as we are prompting again.
			 */
			return stat == STF_OK ? STF_IGNORE : stat;
		} else {
			stf_status stat = xauth_send_status(ike, XAUTH_STATUS_FAIL);

			LLOG_JAMBUF(RC_LOG, ike->sa.logger, buf) {
				jam_string(buf, "XAUTH: User ");
				jam_sanitized_hunk(buf, name);
				jam(buf, ": Authentication Failed (Retried %d times)",
				    ike->sa.hidden_variables.st_xauth_client_attempt);
			}

			return stat == STF_OK ? STF_FAIL_v1N : stat;
		}
	} else {
		xauth_launch_authent(ike, md, &name, &password);
		return STF_SUSPEND;
	}
}

/*
 * STATE_XAUTH_R1:
 * STATUS sent, expect for ACK
 * HDR*, ATTR(STATUS), HASH --> Done
 *
 * @param md Message Digest
 * @return stf_status
 */
stf_status xauth_inR1(struct state *ike_sa, struct msg_digest *md UNUSED)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		return STF_INTERNAL_ERROR;
	}
	ldbg(ike->sa.logger, "%s() for "PRI_SO, __func__, pri_so(ike->sa.st_serialno));

	/* Back to where we were */
	ike->sa.st_oakley.doing_xauth = false;

	if (!ike->sa.st_connection->local->host.config->modecfg.server) {
		dbg("not server, starting new exchange");
		ike->sa.st_v1_msgid.phase15 = v1_MAINMODE_MSGID;
	}

	if (ike->sa.st_connection->local->host.config->modecfg.server &&
	    ike->sa.hidden_variables.st_modecfg_vars_set) {
		dbg("modecfg server, vars are set. Starting new exchange.");
		ike->sa.st_v1_msgid.phase15 = v1_MAINMODE_MSGID;
	}

	if (ike->sa.st_connection->local->host.config->modecfg.server &&
	    ike->sa.st_connection->config->modecfg.pull) {
		dbg("modecfg server, pull mode. Starting new exchange.");
		ike->sa.st_v1_msgid.phase15 = v1_MAINMODE_MSGID;
	}
	return STF_OK;
}

/*
 * STATE_MODE_CFG_R0:
 * HDR*, HASH, ATTR(REQ=IP) --> HDR*, HASH, ATTR(REPLY=IP)
 *
 * This state occurs both in the responder and in the initiator.
 *
 * In the responding server, it occurs when the client *asks* for an IP
 * address or other information.
 *
 * Otherwise, it occurs in the initiator when the server sends a challenge
 * a set, or has a reply to our request.
 *
 * @param md Message Digest
 * @return stf_status
 */
stf_status modecfg_inR0(struct state *ike_sa, struct msg_digest *md)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		return STF_INTERNAL_ERROR;
	}
	ldbg(ike->sa.logger, "%s() for "PRI_SO, __func__, pri_so(ike->sa.st_serialno));

	struct isakmp_mode_attr *ma = &md->chain[ISAKMP_NEXT_MODECFG]->payload.mode_attribute;
	struct pbs_in *attrs = &md->chain[ISAKMP_NEXT_MODECFG]->pbs;
	struct attrs recv;

	dbg("arrived in modecfg_inR0");

	ike->sa.st_v1_msgid.phase15 = md->hdr.isa_msgid;

	switch (ma->isama_type) {

	case ISAKMP_CFG_REQUEST:
		while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
			/* ??? this looks kind of fishy:
			 * - what happens if attributes are repeated (resp cannot record that)?
			 * - who actually parses the subattributes to see if they are OK?
			 */
			struct isakmp_attribute attr;
			struct pbs_in strattr;

			diag_t d = pbs_in_struct(attrs, &isakmp_xauth_attribute_desc,
						 &attr, sizeof(attr), &strattr);
			if (d != NULL) {
				llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
				pfree_diag(&d);
				/* reject malformed */
				return STF_FAIL_v1N;
			}

			if (!set_attr(&recv, attr.isaat_af_type)) {
				log_bad_attr("modecfg (CFG_REQUEST)", &modecfg_attr_names, attr.isaat_af_type);
				break;
			}
		}

		/*
		 * ISAKMP responder, get client address from lease
		 * when possible.
		 */

		if (!get_internal_address(ike)) {
			md->v1_note = v1N_CERTIFICATE_UNAVAILABLE;
			return STF_FATAL;
		}

		ike->sa.st_v1_phase_2_iv = md->v1_decrypt_iv;
		if (!record_n_send_v1_mode_cfg(ike, ISAKMP_CFG_REPLY, recv)) {
			md->v1_note = v1N_CERTIFICATE_UNAVAILABLE;
			return STF_FATAL;
		}

		/* they asked us, we responded, msgid is done */
		ike->sa.st_v1_msgid.phase15 = v1_MAINMODE_MSGID;
		zero(&ike->sa.st_v1_phase_2_iv);
		break;

	default:
	{
		enum_buf tb;
		llog(RC_LOG, ike->sa.logger,
		     "expecting ISAKMP_CFG_REQUEST, got %s instead; message ignored",
		     str_enum(&attr_msg_type_names, ma->isama_type, &tb));
		/* ??? what should we do here?  Pretend all is well? */
		break;
	}
	}

	llog(RC_LOG, ike->sa.logger, "modecfg_inR0(STF_OK)");
	return STF_OK;
}

/*
 * STATE_MODE_CFG_R2:
 * HDR*, HASH, ATTR(SET=IP) --> HDR*, HASH, ATTR(ACK,OK)
 *
 * used in server push mode, on the client (initiator).
 *
 * @param md Message Digest
 * @return stf_status
 */
static stf_status modecfg_inI2(struct ike_sa *ike,
			       struct msg_digest *md)
{
	ldbg(ike->sa.logger, "%s() for "PRI_SO, __func__, pri_so(ike->sa.st_serialno));

	struct isakmp_mode_attr *ma = &md->chain[ISAKMP_NEXT_MODECFG]->payload.mode_attribute;
	struct pbs_in *attrs = &md->chain[ISAKMP_NEXT_MODECFG]->pbs;
	struct attrs recv = {0};

	dbg("modecfg_inI2");

	ike->sa.st_v1_msgid.phase15 = md->hdr.isa_msgid;

	/* CHECK that SET has been received. */

	switch (ma->isama_type) {

	case ISAKMP_CFG_SET:
		break;

	default:
	{
		name_buf mb;
		llog(RC_LOG, ike->sa.logger,
		     "expecting MODE_CFG_SET, got %s instead; message ignored.",
		     str_enum(&attr_msg_type_names, ma->isama_type, &mb));
		return STF_IGNORE;
	}
	}

	while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
		struct isakmp_attribute attr;
		struct pbs_in strattr;

		diag_t d = pbs_in_struct(attrs, &isakmp_xauth_attribute_desc,
					 &attr, sizeof(attr), &strattr);
		if (d != NULL) {
			llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
			pfree_diag(&d);
			/* reject malformed */
			return STF_FAIL_v1N;
		}

		switch (attr.isaat_af_type) {
		case IKEv1_INTERNAL_IP4_ADDRESS | ISAKMP_ATTR_AF_TLV:
		{
			struct connection *c = ike->sa.st_connection;

			ip_address a;
			diag_t d = pbs_in_address(&strattr, &a, &ipv4_info, "addr");
			if (d != NULL) {
				llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
				pfree_diag(&d);
				return STF_FATAL;
			}
			update_first_selector(c, local, selector_from_address(a));
			set_child_has_client(c, local, true);
			const struct ip_info *afi = address_info(a);
			c->local->child.lease[afi->ip_index] = a;

			subnet_buf caddr;
			str_selector_range(&c->child.spds.list->local->client, &caddr);
			llog(RC_LOG, ike->sa.logger, "Received IP address %s", caddr.buf);

			/*
			 * When the sourceip set in the config file,
			 * log the generated value.
			 *
			 * XXX: actually the opposite!  When sourceip=
			 * is absent from the config file, log that
			 * that the MODE_CFG address is being used as
			 * the SOURCEIP.  This is because sourceip=
			 * overrides the MODE_CFG address.
			 */
			if (c->local->config->child.sourceip.len == 0) {
				ip_address sourceip = spd_end_sourceip(c->child.spds.list->local);
				pexpect(address_eq_address(a, sourceip));
				llog(RC_LOG, ike->sa.logger, "setting ip source address to %s",
				     caddr.buf);
			}

			set_attr(&recv, attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
			break;
		}

		case IKEv1_INTERNAL_IP4_NETMASK | ISAKMP_ATTR_AF_TLV:
		case IKEv1_INTERNAL_IP4_DNS | ISAKMP_ATTR_AF_TLV:
		case IKEv1_INTERNAL_IP4_SUBNET | ISAKMP_ATTR_AF_TLV:
		case MODECFG_DOMAIN | ISAKMP_ATTR_AF_TLV:
		case MODECFG_BANNER | ISAKMP_ATTR_AF_TLV:
		case CISCO_SPLIT_INC | ISAKMP_ATTR_AF_TLV:
			set_attr(&recv, attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK);
			break;
		case IKEv1_INTERNAL_IP4_NBNS | ISAKMP_ATTR_AF_TLV:
			/* ignore */
			break;

		default:
			log_bad_attr("modecfg (inR2)", &modecfg_attr_names, attr.isaat_af_type);
			break;
		}
	}
	/* log_state(LOG_DEBUG, st, "ModeCfg ACK: 0x%" PRIxLSET, recv); */

	/*
	 * Build the response.
	 *
	 * Danger: the caller, ikev1.c, will record'n'send the global
	 * REPLY_STREAM being built here!
	 *
	 * ISAKMP initiator, propose remote SPD as address.
	 */

	if (!build_v1_modecfg_ack_from_md_in_reply_stream(ike, recv, md)) {
		/* something to send back */
		md->v1_note = v1N_CERTIFICATE_UNAVAILABLE;
		return STF_FATAL;
	}

	/*
	 * we are done with this exchange, clear things so
	 * that we can start phase 2 properly
	 */
	ike->sa.st_v1_msgid.phase15 = v1_MAINMODE_MSGID;
	if (has_attrs(&recv))
		ike->sa.hidden_variables.st_modecfg_vars_set = true;

	dbg("modecfg_inI2(STF_OK)");
	return STF_OK;
}

/*
 * cisco_stringify()
 *
 * Auxiliary function for modecfg_inR1()
 * Result is allocated on heap so caller must ensure it is freed.
 */

static char *cisco_stringify(struct pbs_in *input_pbs, const char *attr_name,
			     bool ignore, struct logger *logger)
{
	char strbuf[500]; /* Cisco maximum unknown - arbitrary choice */
	struct jambuf buf = ARRAY_AS_JAMBUF(strbuf); /* let jambuf deal with overflow */
	shunk_t str = pbs_in_left(input_pbs);

	/*
	 * detox string
	 */
	for (const char *p = (const void *)str.ptr, *end = p + str.len;
	     p < end && *p != '\0'; p++) {
		char c = *p;
		switch (c) {
		case '\'':
			/*
			 * preserve cisco_stringify() behaviour:
			 *
			 * ' is poison to the way this string will be
			 * used in system() and hence shell.  Remove
			 * any.
			 */
			jam(&buf, "?");
			break;
		case '\n':
		case '\r':
			/*
			 * preserve sanitize_string() behaviour:
			 *
			 * exception is that all vertical space just
			 * becomes white space
			 */
			jam(&buf, " ");
			break;
		default:
			/*
			 * preserve sanitize_string() behaviour:
			 *
			 * XXX: isprint() is wrong as it is affected
			 * by locale - need portable is printable
			 * ascii; is there something hiding in the
			 * x509 sources?
			 */
			if (c != '\\' && isprint(c)) {
				jam_char(&buf, c);
			} else {
				jam(&buf, "\\%03o", c);
			}
			break;
		}
	}
	llog(RC_LOG, logger,
	     "Received %s%s%s: %s%s",
	     ignore ? "and ignored " : "",
	     jambuf_ok(&buf) ? "" : "overlong ",
	     attr_name, strbuf,
	     jambuf_ok(&buf) ? "" : " (truncated)");
	if (ignore) {
		return NULL;
	}
	return clone_str(strbuf, attr_name);
}

/*
 * STATE_MODE_CFG_R1:
 * HDR*, HASH, ATTR(SET=IP) --> HDR*, HASH, ATTR(ACK,OK)
 *
 * @param md Message Digest
 * @return stf_status
 */

diag_t process_mode_cfg_attrs(struct ike_sa *ike,
			      const char *modecfg_payload,
			      struct pbs_in *attrs,
			      struct attrs *received)
{
	struct connection *c = ike->sa.st_connection;

	struct attrs resp = {0};

	while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
		struct isakmp_attribute attr;
		struct pbs_in strattr;

		diag_t d = pbs_in_struct(attrs, &isakmp_xauth_attribute_desc,
					 &attr, sizeof(attr), &strattr);
		if (d != NULL) {
			return d;
		}

		switch (attr.isaat_af_type) {
		case IKEv1_INTERNAL_IP4_ADDRESS | ISAKMP_ATTR_AF_TLV:
		{
			struct connection *c = ike->sa.st_connection;

			ip_address a;
			diag_t d = pbs_in_address(&strattr, &a, &ipv4_info, "addr");
			if (d != NULL) {
				return d;
			}
			set_child_has_client(c, local, true);
			const struct ip_info *afi = address_info(a);
			c->local->child.lease[afi->ip_index] = a;
			update_end_selector(c, c->local->config->index,
					    selector_from_address(a),
					    "^*(&^(* IKEv1 doing something with the address it received");

			subnet_buf caddr;
			str_selector_range(&c->child.spds.list->local->client, &caddr);
			llog(RC_LOG, ike->sa.logger,
			     "Received IPv4 address: %s",
			     caddr.buf);

			resp.ikev1_internal_ip4_address = true;
			break;
		}

		case IKEv1_INTERNAL_IP4_NETMASK | ISAKMP_ATTR_AF_TLV:
		{
			ip_address a;
			diag_t d = pbs_in_address(&strattr, &a, &ipv4_info, "addr");
			if (d != NULL) {
				return d;
			}

			address_buf b;
			dbg("Received IP4 NETMASK %s", str_address(&a, &b));
			resp.ikev1_internal_ip4_netmask = true;
			break;
		}

		case IKEv1_INTERNAL_IP4_DNS | ISAKMP_ATTR_AF_TLV:
		{
			ip_address a;
			diag_t d = pbs_in_address(&strattr, &a, &ipv4_info, "addr");
			if (d != NULL) {
				return d;
			}

			address_buf a_buf;
			const char *a_str = str_address(&a, &a_buf);
			bool ignore = c->config->ignore_peer_dns;
			llog(RC_LOG, ike->sa.logger, "Received %sDNS server %s",
			     ignore ? "and ignored " : "",
			     a_str);

			append_st_cfg_dns(&ike->sa, a_str);

			resp.ikev1_internal_ip4_dns = true;
			break;
		}

		case MODECFG_DOMAIN | ISAKMP_ATTR_AF_TLV:
			append_st_cfg_domain(&ike->sa, cisco_stringify(&strattr, "Domain",
								       false/*don't-ignore*/,
								       ike->sa.logger));
			resp.modecfg_domain = true;
			break;

		case MODECFG_BANNER | ISAKMP_ATTR_AF_TLV:
			ike->sa.st_seen_cfg_banner = cisco_stringify(&strattr, "Banner",
								     false/*don't-ignore*/,
								     ike->sa.logger);
			resp.modecfg_banner = true;
			break;

		case CISCO_SPLIT_INC | ISAKMP_ATTR_AF_TLV:
		{
			struct connection *c = ike->sa.st_connection;

			/* make sure that other side isn't an endpoint */
			if (!c->remote->child.has_client) {
				passert(c->child.spds.len == 1);
				set_child_has_client(c, remote, true);
				update_first_selector(c, remote, ipv4_info.selector.all);
				spd_db_rehash_remote_client(c->child.spds.list);
			}

			while (pbs_left(&strattr) > 0) {
				struct CISCO_split_item i;

				diag_t d = pbs_in_struct(&strattr, &CISCO_split_desc,
							 &i, sizeof(i), NULL);
				if (d != NULL) {
					llog(RC_LOG, ike->sa.logger,
					     "ignoring malformed CISCO_SPLIT_INC in %s payload from server: %s",
					     modecfg_payload, str_diag(d));
					pfree_diag(&d);
					break;
				}

				ip_address base = address_from_in_addr(&i.cs_addr);
				ip_address mask = address_from_in_addr(&i.cs_mask);
				ip_subnet wire_subnet;
				err_t ugh = address_mask_to_subnet(base, mask, &wire_subnet);
				if (ugh != NULL) {
					llog(RC_LOG, ike->sa.logger,
					     "ignoring malformed CISCO_SPLIT_INC subnet: %s",
					     ugh);
					break;
				}

				subnet_buf pretty_subnet;
				llog(RC_LOG, ike->sa.logger,
				     "received and ignored CISCO_SPLIT_INC subnet %s",
				     str_subnet(&wire_subnet, &pretty_subnet));
			}

			resp.cisco_split_inc = true;
			break;
		}

		case IKEv1_INTERNAL_IP4_NBNS | ISAKMP_ATTR_AF_TLV:
		case IKEv1_INTERNAL_IP6_NBNS | ISAKMP_ATTR_AF_TLV:
			llog(RC_LOG, ike->sa.logger, "received and ignored obsoleted Cisco NetBEUI NS info");
			break;

		default:
			log_bad_attr("modecfg (CISCO_SPLIT_INC)", &modecfg_attr_names, attr.isaat_af_type);
			break;

		}
	}

	*received = resp;
	return NULL;
}

stf_status modecfg_inR1(struct state *ike_sa, struct msg_digest *md)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		return STF_INTERNAL_ERROR;
	}
	ldbg(ike->sa.logger, "%s() for "PRI_SO, __func__, pri_so(ike->sa.st_serialno));

	/*
	 * XXX: does this go anywhere?  RBODY isn't used.
	 */
	struct pbs_out unused_rbody;
	ikev1_init_pbs_out_from_md_hdr(md, /*encrypt*/true, &reply_stream,
				       reply_buffer, sizeof(reply_buffer),
				       &unused_rbody, ike->sa.logger);

	struct isakmp_mode_attr *ma = &md->chain[ISAKMP_NEXT_MODECFG]->payload.mode_attribute;
	struct pbs_in *attrs = &md->chain[ISAKMP_NEXT_MODECFG]->pbs;
	struct attrs recv = {0};

	dbg("modecfg_inR1: received mode cfg reply");

	ike->sa.st_v1_msgid.phase15 = md->hdr.isa_msgid;

	switch (ma->isama_type) {

	case ISAKMP_CFG_ACK:
		/* CHECK that ACK has been received. */
		while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
			struct isakmp_attribute attr;

			struct pbs_in ignored;	/* we ignore the attribute value */
			diag_t d = pbs_in_struct(attrs, &isakmp_xauth_attribute_desc,
						 &attr, sizeof(attr), &ignored);
			if (d != NULL) {
				llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
				pfree_diag(&d);
				/* reject malformed */
				return STF_FAIL_v1N;
			}

			if (!set_attr(&recv, attr.isaat_af_type)) {
				log_bad_attr("modecfg (CFG_ACK)", &modecfg_attr_names, attr.isaat_af_type);
				break;
			}
		}
		break;

	case ISAKMP_CFG_REPLY:
	{
		diag_t d = process_mode_cfg_attrs(ike, "RESPONSE", attrs, &recv);
		if (d != NULL) {
			llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
			pfree_diag(&d);
			return STF_FATAL;
		}
		break;
	}

	default:
	{
		name_buf mb;
		llog(RC_LOG, ike->sa.logger,
		     "expecting ISAKMP_CFG_ACK or ISAKMP_CFG_REPLY, got %s instead; message ignored",
		     str_enum(&attr_msg_type_names, ma->isama_type, &mb));
		return STF_IGNORE;
	}

	}

	/* we are done with this exchange, clear things so that we can start phase 2 properly */
	ike->sa.st_v1_msgid.phase15 = v1_MAINMODE_MSGID;
	if (has_attrs(&recv))
		ike->sa.hidden_variables.st_modecfg_vars_set = true;

	dbg("modecfg_inR1(STF_OK)");
	return STF_OK;
}

stf_status modecfg_client_inSET(struct state *ike_sa, struct msg_digest *md)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		return STF_INTERNAL_ERROR;
	}
	ldbg(ike->sa.logger, "%s() for "PRI_SO, __func__, pri_so(ike->sa.st_serialno));

	struct isakmp_mode_attr *ma = &md->chain[ISAKMP_NEXT_MODECFG]->payload.mode_attribute;
	struct pbs_in *attrs = &md->chain[ISAKMP_NEXT_MODECFG]->pbs;
	struct attrs recv = {0};

	switch (ma->isama_type) {

	case ISAKMP_CFG_SET:
	{
		diag_t d = process_mode_cfg_attrs(ike, "SET", attrs, &recv);
		if (d != NULL) {
			llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
			pfree_diag(&d);
			return STF_FATAL;
		}
		break;
	}

	default:
	{
		name_buf mb;
		llog(RC_LOG, ike->sa.logger,
		     "expecting ISAKMP_CFG_SET, got %s instead; message ignored",
		     str_enum(&attr_msg_type_names, ma->isama_type, &mb));
		return STF_IGNORE;
	}

	}

	/*
	 * From RFC draft:
	 *
	 *   The Acknowledge code MUST return the zero length
	 *   attributes that it accepted.
	 */

	ike->sa.st_v1_msgid.phase15 = md->hdr.isa_msgid;
	ike->sa.st_v1_phase_2_iv = md->v1_decrypt_iv;

	if (!record_n_send_v1_mode_cfg(ike, ISAKMP_CFG_ACK, recv)) {
		return STF_FATAL;
	}

	/*
	 * We are done with this exchange, clear things so that Phase
	 * 2 can start, and the state machine doesn't bumble its way
	 * into a Phase 1.5 message.
	 */
	ike->sa.st_v1_msgid.phase15 = v1_MAINMODE_MSGID;
	zero(&ike->sa.st_v1_phase_2_iv);

	if (has_attrs(&recv)) {
		ike->sa.hidden_variables.st_modecfg_vars_set = true;
	}

	return STF_OK;
}

stf_status modecfg_server_inACK(struct state *ike_sa, struct msg_digest *md)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		return STF_INTERNAL_ERROR;
	}
	ldbg(ike->sa.logger, "%s() for "PRI_SO, __func__, pri_so(ike->sa.st_serialno));

	struct isakmp_mode_attr *ma = &md->chain[ISAKMP_NEXT_MODECFG]->payload.mode_attribute;

	ike->sa.st_v1_msgid.phase15 = md->hdr.isa_msgid;
	ike->sa.st_v1_phase_2_iv = md->v1_decrypt_iv;

	switch (ma->isama_type) {

	case ISAKMP_CFG_ACK:
		break;

	default:
	{
		name_buf mb;
		llog(RC_LOG, ike->sa.logger,
		     "expecting ISAKMP_CFG_ACK, got %s instead; message ignored",
		     str_enum(&attr_msg_type_names, ma->isama_type, &mb));
		return STF_IGNORE;
	}

	}

	llog(RC_LOG, ike->sa.logger, "processed MODE_CFG ACK");

	/*
	 * We are done with this exchange, clear things so that Phase
	 * 2 can start, and the state machine doesn't bumble its way
	 * into a Phase 1.5 message.
	 */
	ike->sa.st_v1_msgid.phase15 = v1_MAINMODE_MSGID;
	zero(&ike->sa.st_v1_phase_2_iv);

	return STF_OK;
}

/** XAUTH client code - response to challenge.  May open filehandle to console
 * in order to prompt user for password
 *
 * @param st State
 * @param xauth_resp XAUTH Response
 * @param rbody Reply Body
 * @param ap_id
 * @return stf_status
 */

static stf_status xauth_client_resp(struct ike_sa *ike,
				    struct msg_digest *md,
				    lset_t xauth_resp,
				    uint16_t ap_id)
{
	/*
	 * Send back the password.
	 *
	 * Danger: the caller, ikev1.c, will record'n'send the
	 * global REPLY_STREAM being built here!
	 */
	struct pbs_out rbody[1]; /*hack*/
	ikev1_init_pbs_out_from_md_hdr(md, /*encrypt*/true, &reply_stream,
				       reply_buffer, sizeof(reply_buffer),
				       rbody, ike->sa.logger);

	char xauth_username[MAX_XAUTH_USERNAME_LEN];

	struct v1_hash_fixup hash_fixup;
	if (!emit_xauth_hash(ike, "XAUTH: client response", &hash_fixup, rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* MODECFG out */
	{
		struct isakmp_mode_attr attrh = {
			.isama_type = ISAKMP_CFG_REPLY,
			.isama_identifier = ap_id,
		};
		struct modecfg_pbs modecfg_pbs;
		if (!modecfg_out_open(rbody, &modecfg_pbs, &attrh)) {
			return STF_INTERNAL_ERROR;
		}

		/* lset_t xauth_resp is used as a secondary index variable */

		for (int attr_type = IKEv1_ATTR_XAUTH_TYPE;
		     xauth_resp != LEMPTY; attr_type++) {
			if (xauth_resp & 1) {
				/* ISAKMP attr out */

				switch (attr_type) {
				case IKEv1_ATTR_XAUTH_TYPE:
				{
					struct isakmp_attribute attr = {
						.isaat_af_type = (attr_type |
								  ISAKMP_ATTR_AF_TV),
						.isaat_lv = IKEv1_XAUTH_TYPE_GENERIC,
					};
					if (!modecfg_out_attr(&modecfg_pbs, &attr, NULL)) {
						return STF_INTERNAL_ERROR;
					}
					break;
				}

				case IKEv1_ATTR_XAUTH_USER_NAME:
				{
					struct isakmp_attribute attr = {
						.isaat_af_type = (attr_type |
								  ISAKMP_ATTR_AF_TLV),
					};
					struct pbs_out attrval;
					if (!modecfg_out_attr(&modecfg_pbs, &attr, &attrval)) {
						return STF_INTERNAL_ERROR;
					}

					if (ike->sa.st_xauth_username[0] == '\0') {
						if (!whack_prompt_for(ike,
								      "Username",
								      true,
								      xauth_username,
								      sizeof(xauth_username))) {
							/* already logged */
							return STF_FATAL;
						}
						/* replace the first newline character with a string-terminating \0. */
						char *cptr = memchr(xauth_username,
								    '\n',
								    sizeof(xauth_username));
						if (cptr != NULL)
							*cptr = '\0';

						jam_str(ike->sa.st_xauth_username,
							sizeof(ike->sa.st_xauth_username),
							xauth_username);
					}

					if (!out_raw(ike->sa.st_xauth_username,
						     strlen(ike->sa. st_xauth_username),
						     &attrval,
						     "XAUTH username"))
						return STF_INTERNAL_ERROR;

					close_output_pbs(&attrval);

					break;
				}

				case IKEv1_ATTR_XAUTH_USER_PASSWORD:
				{
					struct isakmp_attribute attr = {
						.isaat_af_type = attr_type | ISAKMP_ATTR_AF_TLV,
					};
					struct pbs_out attrval;
					if (!modecfg_out_attr(&modecfg_pbs, &attr, &attrval)) {
						return STF_INTERNAL_ERROR;
					}

					if (ike->sa.st_xauth_password.ptr == NULL) {
						const struct secret_preshared_stuff *pks =
							xauth_secret_by_xauthname(ike->sa.st_xauth_username);
						dbg("looked up username=%s, got=%p",
						    ike->sa.st_xauth_username,
						    pks);
						if (pks != NULL) {
							ike->sa.st_xauth_password = clone_hunk(*pks, "saved xauth password");
						}
					}

					/*
					 * If we don't already have a password,
					 * try to ask for one through whack.
					 * We'll discard this password after use.
					 */
					bool discard_pw = false;

					if (ike->sa.st_xauth_password.ptr == NULL) {
						char xauth_password[XAUTH_MAX_PASS_LENGTH];
						if (!whack_prompt_for(ike,
								      "Password",
								      false,
								      xauth_password,
								      sizeof(xauth_password))) {
							/* already logged */
							return STF_FATAL;
						}

						/* replace the first newline character with a string-terminating \0. */
						{
							char *cptr = memchr(xauth_password,
								'\n',
								sizeof(xauth_password));
							if (cptr != NULL)
								*cptr = '\0';
						}
						/* see above */
						pexpect(ike->sa.st_xauth_password.ptr == NULL);
						ike->sa.st_xauth_password = clone_bytes_as_chunk(xauth_password,
											     strlen(xauth_password),
											     "XAUTH password");
						discard_pw = true;
					}

					if (!out_hunk(ike->sa.st_xauth_password, &attrval,
						      "XAUTH password")) {
						if (discard_pw) {
							free_chunk_content(&ike->sa.st_xauth_password);
						}
						return STF_INTERNAL_ERROR;
					}

					if (discard_pw) {
						free_chunk_content(&ike->sa.st_xauth_password);
					}
					close_output_pbs(&attrval);
					break;
				}

				default:
				{
					esb_buf b;
					llog(RC_LOG, ike->sa.logger,
					     "trying to send XAUTH reply, sending %s instead.",
					     str_enum(&modecfg_attr_names, attr_type, &b));
					break;
				}
				}
			}

			xauth_resp >>= 1;
		}

		/* do not PAD here, */
		close_output_pbs(&modecfg_pbs.pbs);
	}

	llog(RC_LOG, ike->sa.logger, "XAUTH: Answering XAUTH challenge with user='%s'",
	     ike->sa.st_xauth_username);

	fixup_xauth_hash(ike, &hash_fixup, rbody->cur);

	ike->sa.st_v1_phase_2_iv = md->v1_decrypt_iv;
	if (!close_and_encrypt_v1_message(ike, rbody, &ike->sa.st_v1_phase_2_iv)) {
		return STF_INTERNAL_ERROR;
	}

	return STF_OK;
}

#define XAUTHLELEM(x) (LELEM((x & ISAKMP_ATTR_RTYPE_MASK) - IKEv1_ATTR_XAUTH_TYPE))

/*
 * STATE_XAUTH_I0:
 * HDR*, HASH, ATTR(REQ=IP) --> HDR*, HASH, ATTR(REPLY=IP)
 *
 * This state occurs in initiator.
 *
 * In the initiating client, it occurs in XAUTH, when the responding server
 * demands a password, and we have to supply it.
 *
 * @param md Message Digest
 * @return stf_status
 */
stf_status xauth_inI0(struct state *ike_sa, struct msg_digest *md)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		return STF_INTERNAL_ERROR;
	}
	ldbg(ike->sa.logger, "%s() for "PRI_SO, __func__, pri_so(ike->sa.st_serialno));

	struct isakmp_mode_attr *ma = &md->chain[ISAKMP_NEXT_MODECFG]->payload.mode_attribute;
	struct pbs_in *attrs = &md->chain[ISAKMP_NEXT_MODECFG]->pbs;
	lset_t xauth_resp = LEMPTY;

	int status = 0;
	stf_status stat = STF_FAIL_v1N;
	bool gotrequest = false;
	bool gotset = false;
	bool got_status = false;

	if (ike->sa.hidden_variables.st_xauth_client_done) {
		return modecfg_inI2(ike, md);
	}

	dbg("arrived in xauth_inI0");

	if (impair.drop_xauth_r0) {
		llog(RC_LOG, ike->sa.logger, "IMPAIR: drop XAUTH R0 message ");
		return STF_FAIL_v1N;
	}

	ike->sa.st_v1_msgid.phase15 = md->hdr.isa_msgid;

	switch (ma->isama_type) {

	case ISAKMP_CFG_SET:
		gotset = true;
		break;

	case ISAKMP_CFG_REQUEST:
		gotrequest = true;
		break;

	default:
	{
		enum_buf tb;
		llog(RC_LOG, ike->sa.logger,
		     "expecting ISAKMP_CFG_REQUEST or ISAKMP_CFG_SET, got %s instead; message ignored",
		     str_enum(&attr_msg_type_names, ma->isama_type, &tb));
		/* ??? what are we supposed to do here?  Original code fell through to next case! */
		return STF_FAIL_v1N;
	}
	}

	while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
		struct isakmp_attribute attr;
		struct pbs_in strattr;

		diag_t d = pbs_in_struct(attrs, &isakmp_xauth_attribute_desc,
					 &attr, sizeof(attr), &strattr);
		if (d != NULL) {
			llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
			pfree_diag(&d);
			/* reject malformed */
			return STF_FAIL_v1N;
		}

		switch (attr.isaat_af_type) {
		case IKEv1_ATTR_XAUTH_STATUS | ISAKMP_ATTR_AF_TV:
			got_status = true;
			switch (attr.isaat_lv) {
			case XAUTH_STATUS_FAIL:
				llog(RC_LOG, ike->sa.logger, "Received Cisco XAUTH status: FAIL");
				status = attr.isaat_lv;
				break;
			case XAUTH_STATUS_OK:
				dbg("received Cisco XAUTH status: OK");
				status = attr.isaat_lv;
				break;
			default:
				/* ??? treat as fail?  Should we abort negotiation? */
				llog(RC_LOG, ike->sa.logger, "invalid XAUTH_STATUS value %u", attr.isaat_lv);
				status = XAUTH_STATUS_FAIL;
				break;
			}
			break;

		case IKEv1_ATTR_XAUTH_MESSAGE | ISAKMP_ATTR_AF_TLV:
		{
			/* ??? should the message be sanitized before logging? */
			/* XXX check RFC for max length? */
			size_t len = attr.isaat_lv;
			char msgbuf[81];

			dbg("received Cisco XAUTH message");
			if (len >= sizeof(msgbuf) )
				len = sizeof(msgbuf) - 1;
			memcpy(msgbuf, strattr.cur, len);
			msgbuf[len] = '\0';
			llog(RC_LOG, ike->sa.logger, "XAUTH Message: %s", msgbuf);
			break;
		}

		case IKEv1_ATTR_XAUTH_TYPE | ISAKMP_ATTR_AF_TV:
			if (attr.isaat_lv != IKEv1_XAUTH_TYPE_GENERIC) {
				llog(RC_LOG, ike->sa.logger, "XAUTH: Unsupported type: %d",
				     attr.isaat_lv);
				return STF_IGNORE;
			}
			dbg("received Cisco XAUTH type: Generic");
			xauth_resp |= XAUTHLELEM(IKEv1_ATTR_XAUTH_TYPE);
			break;

		case IKEv1_ATTR_XAUTH_USER_NAME | ISAKMP_ATTR_AF_TLV:
			dbg("received Cisco XAUTH username");
			xauth_resp |= XAUTHLELEM(IKEv1_ATTR_XAUTH_USER_NAME);
			break;

		case IKEv1_ATTR_XAUTH_USER_PASSWORD | ISAKMP_ATTR_AF_TLV:
			dbg("received Cisco XAUTH password");
			xauth_resp |= XAUTHLELEM(IKEv1_ATTR_XAUTH_USER_PASSWORD);
			break;

		case IKEv1_INTERNAL_IP4_ADDRESS | ISAKMP_ATTR_AF_TLV:
			dbg("received Cisco Internal IPv4 address");
			break;

		case IKEv1_INTERNAL_IP4_NETMASK | ISAKMP_ATTR_AF_TLV:
			dbg("received Cisco Internal IPv4 netmask");
			break;

		case IKEv1_INTERNAL_IP4_DNS | ISAKMP_ATTR_AF_TLV:
			dbg("received Cisco IPv4 DNS info");
			break;

		case IKEv1_INTERNAL_IP4_SUBNET | ISAKMP_ATTR_AF_TV:
			dbg("received Cisco IPv4 Subnet info");
			break;

		case IKEv1_INTERNAL_IP4_NBNS | ISAKMP_ATTR_AF_TV:
			dbg("received Cisco NetBEUI NS info");
			break;

		default:
			log_bad_attr("XAUTH (inI0)", &modecfg_attr_names, attr.isaat_af_type);
			break;
		}
	}

	if (gotset && got_status) {
		stat = xauth_client_ackstatus(ike, md,
					      md->chain[ISAKMP_NEXT_MODECFG]->payload.mode_attribute.isama_identifier);

		/* must have gotten a status */
		if (status != XAUTH_STATUS_FAIL && stat == STF_OK) {
			ike->sa.hidden_variables.st_xauth_client_done = true;
			llog(RC_LOG, ike->sa.logger, "XAUTH: Successfully Authenticated");
			ike->sa.st_oakley.doing_xauth = false;
			return STF_OK;
		}

		enum_buf sb;
		llog(RC_LOG, ike->sa.logger, "xauth: xauth_client_ackstatus() returned %s",
		     str_enum(&stf_status_names, stat, &sb));
		llog(RC_LOG, ike->sa.logger, "XAUTH: aborting entire IKE Exchange");
		return STF_FATAL;
	}

	if (gotrequest) {
		if (xauth_resp & (XAUTHLELEM(IKEv1_ATTR_XAUTH_USER_NAME) |
				  XAUTHLELEM(IKEv1_ATTR_XAUTH_USER_PASSWORD))) {
			if (!ike->sa.st_connection->local->host.config->xauth.client) {
				llog(RC_LOG, ike->sa.logger,
				     "XAUTH: Username or password request was received, but XAUTH client mode not enabled.");
				return STF_IGNORE;
			}
			ldbg(ike->sa.logger, "XAUTH: Username or password request received");
		} else {
			if (ike->sa.st_connection->local->host.config->xauth.client) {
				llog(RC_LOG, ike->sa.logger,
				     "XAUTH: No username or password request was received.");
				return STF_IGNORE;
			}
		}

		stat = xauth_client_resp(ike, md, xauth_resp,
					 md->chain[ISAKMP_NEXT_MODECFG]->payload.mode_attribute.isama_identifier);
	}

	if (stat != STF_OK) {
		/* notification payload - not exactly the right choice, but okay */
		md->v1_note = v1N_CERTIFICATE_UNAVAILABLE;
		return stat;
	}

	/* reset the message ID */
	ike->sa.st_v1_msgid.phase15 = v1_MAINMODE_MSGID;

	dbg("xauth_inI0(STF_OK)");
	return STF_OK;
}

/** XAUTH client code - Acknowledge status
 *
 * @param st State
 * @param rbody Response Body
 * @param ap_id
 * @return stf_status
 */
static stf_status xauth_client_ackstatus(struct ike_sa *ike,
					 struct msg_digest *md,
					 uint16_t ap_id)
{
	/*
	 * ACK whatever it was that we got.
	 *
	 * Danger: the caller, ikev1.c, will record'n'send the
	 * global REPLY_STREAM being built here!
	 */
	struct pbs_out rbody[1]; /*hack*/
	ikev1_init_pbs_out_from_md_hdr(md, /*encrypt*/true, &reply_stream,
				       reply_buffer, sizeof(reply_buffer),
				       rbody, ike->sa.logger);

	struct v1_hash_fixup hash_fixup;
	if (!emit_xauth_hash(ike, "XAUTH: ack status", &hash_fixup, rbody)) {
		return STF_INTERNAL_ERROR;
	}

	/* ATTR out */
	{
		struct isakmp_mode_attr attrh = {
			.isama_type = ISAKMP_CFG_ACK,
			.isama_identifier = ap_id,
		};
		struct modecfg_pbs modecfg_pbs;
		if (!modecfg_out_open(rbody, &modecfg_pbs, &attrh)) {
			return STF_INTERNAL_ERROR;
		}

		struct isakmp_attribute attr = {
			.isaat_af_type = IKEv1_ATTR_XAUTH_STATUS | ISAKMP_ATTR_AF_TV,
			.isaat_lv = XAUTH_STATUS_OK,
		};
		if (!modecfg_out_attr(&modecfg_pbs, &attr, NULL)) {
			return STF_INTERNAL_ERROR;
		}

		if (!modecfg_out_close(&modecfg_pbs, ike)) {
			return STF_INTERNAL_ERROR;
		}
	}

	fixup_xauth_hash(ike, &hash_fixup, rbody->cur);

	ike->sa.st_v1_phase_2_iv = md->v1_decrypt_iv;
	if (!close_and_encrypt_v1_message(ike, rbody, &ike->sa.st_v1_phase_2_iv)) {
		return STF_INTERNAL_ERROR;
	}

	return STF_OK;
}

/*
 * STATE_XAUTH_I1:
 * HDR*, HASH, ATTR(SET=IP) --> HDR*, HASH, ATTR(ACK,OK)
 *
 * @param md Message Digest
 * @return stf_status
 */
stf_status xauth_inI1(struct state *ike_sa, struct msg_digest *md)
{
	struct ike_sa *ike = pexpect_ike_sa(ike_sa);
	if (ike == NULL) {
		return STF_INTERNAL_ERROR;
	}
	ldbg(ike->sa.logger, "%s() for "PRI_SO, __func__, pri_so(ike->sa.st_serialno));

	struct isakmp_mode_attr *ma = &md->chain[ISAKMP_NEXT_MODECFG]->payload.mode_attribute;
	struct pbs_in *attrs = &md->chain[ISAKMP_NEXT_MODECFG]->pbs;
	bool got_status = false;
	unsigned int status = XAUTH_STATUS_FAIL;
	stf_status stat;

	dbg("xauth_inI1");

	if (ike->sa.hidden_variables.st_xauth_client_done) {
		dbg("st_xauth_client_done, moving into modecfg_inI2");
		return modecfg_inI2(ike, md);
	}

	dbg("Continuing with xauth_inI1");

	ike->sa.st_v1_msgid.phase15 = md->hdr.isa_msgid;

	switch (ma->isama_type) {

	case ISAKMP_CFG_SET:
		/* CHECK that SET has been received. */
		while (pbs_left(attrs) >= isakmp_xauth_attribute_desc.size) {
			struct isakmp_attribute attr;
			struct pbs_in strattr;

			diag_t d = pbs_in_struct(attrs, &isakmp_xauth_attribute_desc,
						 &attr, sizeof(attr), &strattr);
			if (d != NULL) {
				llog(RC_LOG, ike->sa.logger, "%s", str_diag(d));
				pfree_diag(&d);
				/* reject malformed */
				return STF_FAIL_v1N;
			}

			switch (attr.isaat_af_type) {
			case IKEv1_ATTR_XAUTH_STATUS | ISAKMP_ATTR_AF_TV:
				got_status = true;
				switch (attr.isaat_lv) {
				case XAUTH_STATUS_FAIL:
				case XAUTH_STATUS_OK:
					status = attr.isaat_lv;
					break;
				default:
					/* ??? treat as fail?  Should we abort negotiation? */
					llog(RC_LOG, ike->sa.logger, "invalid XAUTH_STATUS value %u", attr.isaat_lv);
					status = XAUTH_STATUS_FAIL;
					break;
				}
				break;

			default:
			{
				esb_buf b;
				llog(RC_LOG, ike->sa.logger,
				     "while waiting for XAUTH_STATUS, got %s %s instead.",
				     (attr.isaat_af_type & ISAKMP_ATTR_AF_MASK) == ISAKMP_ATTR_AF_TV ? "basic" : "long",
				     str_enum(&modecfg_attr_names,
					      attr.isaat_af_type & ISAKMP_ATTR_RTYPE_MASK, &b));
				break;
			}
			}
		}
		break;

	default:
	{
		name_buf mb;
		llog(RC_LOG, ike->sa.logger, "expecting MODE_CFG_SET, got %s instead; message ignored",
		     str_enum(&attr_msg_type_names, ma->isama_type, &mb));
		return STF_IGNORE;
	}
	}

	/* first check if we might be done! */
	if (!got_status || status == XAUTH_STATUS_FAIL) {
		/* oops, something seriously wrong */
		llog(RC_LOG, ike->sa.logger,
		     "did not get status attribute in xauth_inI1, looking for new challenge.");
		change_v1_state(&ike->sa, STATE_XAUTH_I0);
		return xauth_inI0(&ike->sa, md);
	}

	/* ACK whatever it was that we got */
	stat = xauth_client_ackstatus(ike, md,
				      md->chain[ISAKMP_NEXT_MODECFG]->payload.mode_attribute.isama_identifier);

	/* must have gotten a status */
	if (status && stat == STF_OK) {
		ike->sa.hidden_variables.st_xauth_client_done = true;
		llog(RC_LOG, ike->sa.logger, "successfully logged in");
		ike->sa.st_oakley.doing_xauth = false;

		return STF_OK;
	}

	/* what? */
	return stat;
}
