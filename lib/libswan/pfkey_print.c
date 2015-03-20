/*
 * RFC2367 PF_KEYv2 Key management API message parser
 *
 * Copyright (C) 2003 Michael Richardson <mcr@freeswan.org>
 * Copyright (C) 2014 D. Hugh Redelmeier <hugh@mimosa.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */
#include <sys/types.h>
#include <stdio.h>
#include <inttypes.h>
#include <libreswan.h>
#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

void pfkey_print(struct sadb_msg *msg, FILE *out)
{
	unsigned len;
	struct sadb_ext *se;

	fprintf(out,
		"version=%u type=%u errno=%u satype=%u len=%u seq=%u pid=%u ",
		msg->sadb_msg_version,
		msg->sadb_msg_type,
		msg->sadb_msg_errno,
		msg->sadb_msg_satype,
		msg->sadb_msg_len,
		msg->sadb_msg_seq,
		msg->sadb_msg_pid);

	len = IPSEC_PFKEYv2_LEN(msg->sadb_msg_len);
	len -= sizeof(struct sadb_msg);

	se = (struct sadb_ext *) &msg[1];

	while (len > sizeof(struct sadb_ext)) {
		/* in units of IPSEC_PFKEYv2_ALIGN bytes */
		uint16_t ext_len = se->sadb_ext_len;
		/* in units of bytes */
		unsigned elen = IPSEC_PFKEYv2_LEN(ext_len);
		uint16_t ext_type = se->sadb_ext_type;
		const char *too_small_for = NULL;

		fprintf(out, "{ext=%u len=%u ", ext_type, ext_len);

		/* make sure that there is enough left */
		if (elen > len) {
			fprintf(out, "short-packet(%u<%u) ", len, elen);

			/*
			 * truncate ext_len it to match len
			 *
			 * partial words are ignored
			 */
			ext_len = IPSEC_PFKEYv2_WORDS(len);
			elen = IPSEC_PFKEYv2_LEN(ext_len);
			ext_type = SADB_X_EXT_DEBUG;	/* force plain dump */
		}

		if (elen < sizeof(struct sadb_ext)) {
			fprintf(out, "ext_len (%u) too small for sadb_ext header ",
				ext_len);
			break;
		}

		/* okay, decode what we know */
		switch (ext_type) {
		case SADB_EXT_SA:
			if (elen < sizeof(struct k_sadb_sa)) {
				too_small_for = "struct k_sadb_sa";
			} else {
				struct k_sadb_sa *sa = (struct k_sadb_sa *)se;
				fprintf(out,
					"spi=%08x replay=%u state=%u auth=%u encrypt=%u flags=%08x ref=%08x}",
					sa->sadb_sa_spi,
					sa->sadb_sa_replay,
					sa->sadb_sa_state,
					sa->sadb_sa_auth,
					sa->sadb_sa_encrypt,
					sa->sadb_sa_flags,
					sa->sadb_x_sa_ref);
			}
			break;

		case SADB_X_EXT_ADDRESS_SRC_FLOW:
		case SADB_X_EXT_ADDRESS_DST_FLOW:
		case SADB_X_EXT_ADDRESS_SRC_MASK:
		case SADB_X_EXT_ADDRESS_DST_MASK:
		case SADB_EXT_ADDRESS_DST:
		case SADB_EXT_ADDRESS_SRC:
			if (elen < sizeof(struct sadb_address)) {
				too_small_for = "struct sadb_address";
			} else {
				struct sadb_address *addr =
					(struct sadb_address *) se;
				int alen =
					IPSEC_PFKEYv2_LEN(
						addr->sadb_address_len) -
					sizeof(struct sadb_address);
				unsigned char *bytes =
					(unsigned char *)&addr[1];

				fprintf(out, "proto=%u prefixlen=%u addr=0x",
					addr->sadb_address_proto,
					addr->sadb_address_prefixlen);

				while (alen > 0) {
					fprintf(out, "%02x", *bytes);
					bytes++;
					alen--;
				}
				fprintf(out, " } ");
			}
			break;

		case SADB_X_EXT_PROTOCOL:
			if (elen < sizeof(struct sadb_protocol)) {
				too_small_for = "struct sadb_protocol";
			} else {
				struct sadb_protocol *sp =
					(struct sadb_protocol *) se;
				fprintf(out,
					"proto=%u direction=%u flags=%u } ",
					sp->sadb_protocol_proto,
					sp->sadb_protocol_direction,
					sp->sadb_protocol_flags);
			}
			break;

		case SADB_EXT_LIFETIME_CURRENT:
		case SADB_EXT_LIFETIME_HARD:
		case SADB_EXT_LIFETIME_SOFT:
			if (elen < sizeof(struct sadb_lifetime)) {
				too_small_for = "struct sadb_lifetime";
			} else {
				struct sadb_lifetime *life =
					(struct sadb_lifetime *)se;

				fprintf(out,
					"allocations=%u bytes=%" PRIu64
					" addtime=%" PRIu64
					" usetime=%" PRIu64
					" packets=%u",
					life->sadb_lifetime_allocations,
					life->sadb_lifetime_bytes,
					life->sadb_lifetime_addtime,
					life->sadb_lifetime_usetime,
					life->sadb_x_lifetime_packets);
				fprintf(out, " } ");
			}
			break;

		case SADB_EXT_RESERVED:
		case SADB_EXT_ADDRESS_PROXY:
		case SADB_EXT_KEY_AUTH:
		case SADB_EXT_KEY_ENCRYPT:
		case SADB_EXT_IDENTITY_SRC:
		case SADB_EXT_IDENTITY_DST:
		case SADB_EXT_SENSITIVITY:
		case SADB_EXT_PROPOSAL:
		case SADB_EXT_SUPPORTED_AUTH:
		case SADB_EXT_SUPPORTED_ENCRYPT:
		case SADB_EXT_SPIRANGE:
		case SADB_X_EXT_KMPRIVATE:
		case SADB_X_EXT_SATYPE2:
		case SADB_X_EXT_SA2:
		case SADB_X_EXT_ADDRESS_DST2:
		case SADB_X_EXT_DEBUG:	/* also used in malformed case */
		default:
		{
			unsigned int count = elen - sizeof(struct sadb_ext);
			unsigned char *bytes = (unsigned char *)&se[1];

			fprintf(out, "bytes=0x");
			while (count > 0) {
				fprintf(out, "%02x", *bytes);
				bytes++;
				count--;
			}
			fprintf(out, " } ");
		}
		break;
		}

		if (too_small_for != NULL)
			fprintf(out, "too small for %s ", too_small_for);

		/* skip to next extension header */
		se = (struct sadb_ext *) ((unsigned char *) se + elen);
		len -= elen;
	}

	if (len > 0)
		fprintf(out, "%u bytes left over", len);

	fprintf(out, "\n");
}
