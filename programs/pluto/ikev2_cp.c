/* IKEv2 Configuration Payload, for Libreswan
 *
 * Copyright (C) 2007-2008 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008-2011 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2010,2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010-2019 Tuomo Soini <tis@foobar.fi
 * Copyright (C) 2012-2019 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012-2018 Antony Antony <antony@phenome.org>
 * Copyright (C) 2013-2019 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 David McCullough <ucdevel@gmail.com>
 * Copyright (C) 2013 Matt Rogers <mrogers@redhat.com>
 * Copyright (C) 2015-2019 Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017-2018 Sahana Prasad <sahana.prasad07@gmail.com>
 * Copyright (C) 2017-2018 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2017 Mayank Totale <mtotale@gmail.com>
 * Copyright (C) 2020 Yulia Kuzovkova <ukuzovkova@gmail.com>
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
#include "demux.h"
#include "connections.h"
#include "state.h"
#include "log.h"

#include "ikev2_cp.h"

/* Misleading name, also used for NULL sized type's */
static stf_status ikev2_ship_cp_attr_ip(uint16_t type, ip_address *ip,
					const char *story, struct pbs_out *outpbs)
{
	struct pbs_out a_pbs;

	struct ikev2_cp_attribute attr = {
		.type = type,
	};

	/* could be NULL */
	const struct ip_info *afi = address_type(ip);

	if (afi == NULL) {
		attr.len = 0;
	} else if (afi == &ipv6_info) {
		attr.len = INTERNAL_IP6_ADDRESS_SIZE; /* RFC hack to append IPv6 prefix len */
	} else {
		attr.len = address_type(ip)->ip_size;
	}

	if (!out_struct(&attr, &ikev2_cp_attribute_desc, outpbs,
				&a_pbs))
		return STF_INTERNAL_ERROR;

	if (attr.len > 0) {
		diag_t d = pbs_out_address(&a_pbs, *ip, story);
		if (d != NULL) {
			llog_diag(RC_LOG_SERIOUS, a_pbs.outs_logger, &d, "%s", "");
			return STF_INTERNAL_ERROR;
		}
	}

	if (attr.len == INTERNAL_IP6_ADDRESS_SIZE) { /* IPv6 address add prefix */
		uint8_t ipv6_prefix_len = INTERNL_IP6_PREFIX_LEN;
		diag_t d = pbs_out_raw(&a_pbs, &ipv6_prefix_len, sizeof(uint8_t), "INTERNL_IP6_PREFIX_LEN");
		if (d != NULL) {
			llog_diag(RC_LOG_SERIOUS, outpbs->outs_logger, &d, "%s", "");
			return STF_INTERNAL_ERROR;
		}
	}

	close_output_pbs(&a_pbs);
	return STF_OK;
}

static bool emit_v2CP_attribute(struct pbs_out *outpbs,
				uint16_t type, shunk_t attrib,
				const char *story)
{
	diag_t d;
	struct ikev2_cp_attribute attr = {
		.type = type,
		.len = attrib.len,
	};

	pb_stream a_pbs;
	d = pbs_out_struct(outpbs, &ikev2_cp_attribute_desc,
			   &attr, sizeof(attr), &a_pbs);
	if (d != NULL) {
		return pbs_out_diag(outpbs, HERE, &d);
	}

	if (attrib.len > 0) {
		diag_t d = pbs_out_hunk(&a_pbs, attrib, story);
		if (d != NULL) {
			return pbs_out_diag(outpbs, HERE, &d);
		}
	}

	close_output_pbs(&a_pbs);
	return true;
}

/*
 * CHILD is asking for configuration; hence log against child.
 */

bool emit_v2_child_configuration_payload(const struct child_sa *child, struct pbs_out *outpbs)
{
	struct connection *c = child->sa.st_connection;
	pb_stream cp_pbs;
	bool cfg_reply = c->spd.that.has_lease;
	struct ikev2_cp cp = {
		.isacp_critical = ISAKMP_PAYLOAD_NONCRITICAL,
		.isacp_type = cfg_reply ? IKEv2_CP_CFG_REPLY : IKEv2_CP_CFG_REQUEST,
	};

	dbg("Send Configuration Payload %s ",
	    cfg_reply ? "reply" : "request");

	if (!out_struct(&cp, &ikev2_cp_desc, outpbs, &cp_pbs))
		return false;

	if (cfg_reply) {
		ip_address that_client_address = selector_prefix(c->spd.that.client);
		ikev2_ship_cp_attr_ip(selector_type(&c->spd.that.client) == &ipv4_info ?
				      IKEv2_INTERNAL_IP4_ADDRESS : IKEv2_INTERNAL_IP6_ADDRESS,
				      &that_client_address, "Internal IP Address", &cp_pbs);

		for (ip_address *dns = c->config->modecfg.dns;
		     dns != NULL && dns->is_set; dns++) {
			const struct ip_info *afi = address_type(dns);
			switch (afi->ip_version) {
			case IPv4:
				if (ikev2_ship_cp_attr_ip(IKEv2_INTERNAL_IP4_DNS, dns,
							  "IP4_DNS", &cp_pbs) != STF_OK) {
					return false;
				}
				break;
			case IPv6:
				if (ikev2_ship_cp_attr_ip(IKEv2_INTERNAL_IP6_DNS, dns,
							  "IP6_DNS", &cp_pbs) != STF_OK) {
					return false;
				}
				break;
			}
		}

		for (const shunk_t *domain = c->config->modecfg.domains;
		     domain != NULL && domain->ptr != NULL; domain++) {
			if (!emit_v2CP_attribute(&cp_pbs,
						 IKEv2_INTERNAL_DNS_DOMAIN,
						 *domain,
						 "IKEv2_INTERNAL_DNS_DOMAIN")) {
				/* already logged */
				return false;
			}
		}
	} else { /* cfg request */
		ikev2_ship_cp_attr_ip(IKEv2_INTERNAL_IP4_ADDRESS, NULL, "IPV4 Address", &cp_pbs);
		ikev2_ship_cp_attr_ip(IKEv2_INTERNAL_IP4_DNS, NULL, "DNSv4", &cp_pbs);
		ikev2_ship_cp_attr_ip(IKEv2_INTERNAL_IP6_ADDRESS, NULL, "IPV6 Address", &cp_pbs);
		ikev2_ship_cp_attr_ip(IKEv2_INTERNAL_IP6_DNS, NULL, "DNSv6", &cp_pbs);
		ikev2_ship_cp_attr_ip(IKEv2_INTERNAL_DNS_DOMAIN, NULL, "Domain", &cp_pbs);
	}

	close_output_pbs(&cp_pbs);
	return true;
}
