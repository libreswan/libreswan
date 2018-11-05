/*
 * IPsec IKEv1 DOI Quick Mode functions.
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2013 Andrew Cagney
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
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "state.h"
#include "ikev1_msgid.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "keys.h"
#include "packet.h"
#include "demux.h"      /* needs packet.h */
#include "kernel.h"     /* needs connections.h */
#include "log.h"
#include "server.h"
#include "spdb.h"
#include "timer.h"
#include "rnd.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "whack.h"
#include "fetch.h"
#include "asn1.h"
#include "ikev1_send.h"
#include "crypto.h"
#include "secrets.h"

#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"

#include "pluto_crypt.h"
#include "crypt_prf.h"
#include "crypt_hash.h"
#include "ikev1.h"
#include "ikev1_quick.h"
#include "ikev1_continuations.h"

#include "ikev1_xauth.h"

#include "vendor.h"
#include "nat_traversal.h"
#include "virtual.h"	/* needs connections.h */
#include "ikev1_dpd.h"
#include "pluto_x509.h"
#include "alg_info.h"
#include "ip_address.h"
#include "af_info.h"

#include <blapit.h>

const struct oakley_group_desc *ikev1_quick_pfs(struct alg_info_esp *aie)
{
	if (aie == NULL) {
		return NULL;
	}
	if (aie->ai.alg_info_cnt == 0) {
		return NULL;
	}
	return aie->ai.proposals[0].dh;
}

/* accept_PFS_KE
 *
 * Check and accept optional Quick Mode KE payload for PFS.
 * Extends ACCEPT_PFS to check whether KE is allowed or required.
 */
static notification_t accept_PFS_KE(struct msg_digest *md, chunk_t *dest,
				    const char *val_name, const char *msg_name)
{
	struct state *st = md->st;
	struct payload_digest *const ke_pd = md->chain[ISAKMP_NEXT_KE];

	if (ke_pd == NULL) {
		if (st->st_pfs_group != NULL) {
			loglog(RC_LOG_SERIOUS,
			       "missing KE payload in %s message", msg_name);
			return INVALID_KEY_INFORMATION;
		}
		return NOTHING_WRONG;
	} else {
		if (st->st_pfs_group == NULL) {
			loglog(RC_LOG_SERIOUS,
			       "%s message KE payload requires a GROUP_DESCRIPTION attribute in SA",
			       msg_name);
			return INVALID_KEY_INFORMATION;
		}
		if (ke_pd->next != NULL) {
			loglog(RC_LOG_SERIOUS,
			       "%s message contains several KE payloads; we accept at most one",
			       msg_name);
			return INVALID_KEY_INFORMATION; /* ??? */
		}
		return accept_KE(dest, val_name, st->st_pfs_group,
				 &ke_pd->pbs);
	}
}

/* Initiate quick mode.
 * --> HDR*, HASH(1), SA, Nr [, KE ] [, IDci, IDcr ]
 * (see RFC 2409 "IKE" 5.5)
 * Note: this is not called from demux.c
 */

static bool emit_subnet_id(const ip_subnet *net,
			   uint8_t np,
			   uint8_t protoid,
			   uint16_t port,
			   pb_stream *outs)
{
	const struct af_info *ai = aftoinfo(subnettypeof(net));
	const bool usehost = net->maskbits == ai->mask_cnt;
	pb_stream id_pbs;

	struct isakmp_ipsec_id id = {
		.isaiid_np = np,
		.isaiid_idtype = usehost ? ai->id_addr : ai->id_subnet,
		.isaiid_protoid = protoid,
		.isaiid_port = port,
	};

	if (!out_struct(&id, &isakmp_ipsec_identification_desc, outs, &id_pbs))
		return FALSE;

	ip_address ta;
	networkof(net, &ta);
	const unsigned char *tbp;
	size_t tal = addrbytesptr_read(&ta, &tbp);
	if (!out_raw(tbp, tal, &id_pbs, "client network"))
		return FALSE;

	if (!usehost) {
		maskof(net, &ta);
		tal = addrbytesptr_read(&ta, &tbp);
		if (!out_raw(tbp, tal, &id_pbs, "client mask"))
			return FALSE;
	}

	close_output_pbs(&id_pbs);
	return TRUE;
}

/*
 * Produce the new key material of Quick Mode.
 * RFC 2409 "IKE" section 5.5
 * specifies how this is to be done.
 */
static void compute_proto_keymat(struct state *st,
				 uint8_t protoid,
				 struct ipsec_proto_info *pi,
				 const char *satypename)
{
	size_t needed_len = 0; /* bytes of keying material needed */

	/*
	 * Add up the requirements for keying material (It probably
	 * doesn't matter if we produce too much!)
	 *
	 * XXX: This entire switch can probably be reduced to just the
	 * "default:" case.
	 */
	switch (protoid) {
	case PROTO_IPSEC_ESP:
		switch (pi->attrs.transattrs.ta_ikev1_encrypt) {
		case ESP_NULL:
			needed_len = 0;
			break;
		case ESP_DES:
			needed_len = DES_CBC_BLOCK_SIZE;
			break;
		case ESP_3DES:
			needed_len = DES_CBC_BLOCK_SIZE * 3;
			break;
		case ESP_AES:
			needed_len = AES_CBC_BLOCK_SIZE;
			/* if an attribute is set, then use that! */
			if (st->st_esp.attrs.transattrs.enckeylen != 0) {
				needed_len =
					st->st_esp.attrs.transattrs.enckeylen /
					BITS_PER_BYTE;
				/* XXX: obtained from peer - was it verified for validity yet? */
			}
			break;
		case ESP_AES_CTR:
			if (st->st_esp.attrs.transattrs.enckeylen != 0) {
				needed_len =
					st->st_esp.attrs.transattrs.enckeylen /
					BITS_PER_BYTE;
				/* XXX: obtained from peer - was it verified for validity yet? */
			} else {
				/* if no keylength set, pick strongest allowed */
				needed_len = AES_CTR_KEY_MAX_LEN / BITS_PER_BYTE;
			}
			/* AES_CTR requires an extra AES_CTR_SALT_BYTES (4) bytes of salt */
			needed_len += AES_CTR_SALT_BYTES;
			break;
		case ESP_AES_GCM_8:
		case ESP_AES_GCM_12:
		case ESP_AES_GCM_16:
			/* valid keysize enforced before we get here */
			if (st->st_esp.attrs.transattrs.enckeylen != 0) {
				passert(st->st_esp.attrs.transattrs.enckeylen == 128 ||
					st->st_esp.attrs.transattrs.enckeylen == 192 ||
					st->st_esp.attrs.transattrs.enckeylen == 256);
				needed_len = st->st_esp.attrs.transattrs.enckeylen / BITS_PER_BYTE;
			} else {
				/* if no keylength set, pick strongest allowed */
				needed_len = AEAD_AES_KEY_MAX_LEN / BITS_PER_BYTE;
			}
			/* AES_GCM requires an extra AES_GCM_SALT_BYTES (4) bytes of salt */
			needed_len += AES_GCM_SALT_BYTES;
			break;
		case ESP_AES_CCM_8:
		case ESP_AES_CCM_12:
		case ESP_AES_CCM_16:
			/* valid keysize enforced before we get here */
			if (st->st_esp.attrs.transattrs.enckeylen != 0) {
				passert(st->st_esp.attrs.transattrs.enckeylen == 128 ||
					st->st_esp.attrs.transattrs.enckeylen == 192 ||
					st->st_esp.attrs.transattrs.enckeylen == 256);
				needed_len = st->st_esp.attrs.transattrs.enckeylen / BITS_PER_BYTE;
			} else {
				/* if no keylength set, pick strongest allowed */
				needed_len = AEAD_AES_KEY_MAX_LEN / BITS_PER_BYTE;
			}
			/* AES_CCM requires an extra AES_CCM_SALT_BYTES (3) bytes of salt */
			needed_len += AES_CCM_SALT_BYTES;
			break;

		case ESP_CAST:
			/* CAST can use 40-28 bits but requires padding up to 128
			 * We use a minimum of 128bits to avoid padding
			 * This is also the max keysize for cast128
			 */
			if (st->st_esp.attrs.transattrs.enckeylen != 0) {
				passert(st->st_esp.attrs.transattrs.enckeylen == 128);
			}
			/* minimum = default = maximum */
			needed_len = CAST_KEY_DEF_LEN / BITS_PER_BYTE;
			break;

		case ESP_CAMELLIA:
			/* if an attribute is set, then use that! */
			if (st->st_esp.attrs.transattrs.enckeylen == 0) {
				needed_len = CAMELLIA_BLOCK_SIZE;
			} else {
				needed_len =
					st->st_esp.attrs.transattrs.enckeylen /
					BITS_PER_BYTE;
				/* XXX: obtained from peer - was it verified for validity yet? */
			}
			break;
		case ESP_TWOFISH:
		case ESP_SERPENT:
			/* valid keysize enforced before we get here */
			if (st->st_esp.attrs.transattrs.enckeylen != 0) {
				passert(st->st_esp.attrs.transattrs.enckeylen == 128 ||
					st->st_esp.attrs.transattrs.enckeylen == 192 ||
					st->st_esp.attrs.transattrs.enckeylen == 256);
				needed_len = st->st_esp.attrs.transattrs.enckeylen / BITS_PER_BYTE;
			} else {
				/*
				 * If no keylength set, pick mandatory to implement default
				 * {TWOFISH,SERPENT}_DEF_KEY_LEN = 128
				 */
				needed_len = 128 / BITS_PER_BYTE;
			}
			break;

		/* ESP_SEED is for IKEv1 only and not supported. Its number in IKEv2 has been re-used */

		default:
			/* bytes */
			needed_len = encrypt_max_key_bit_length(pi->attrs.transattrs.ta_encrypt) / BITS_PER_BYTE;
			if (needed_len > 0) {
				/* XXX: check key_len coupling with kernel.c's */
				if (pi->attrs.transattrs.enckeylen) {
					needed_len =
						pi->attrs.transattrs.enckeylen
						/ BITS_PER_BYTE;
					DBG(DBG_PARSING,
					    DBG_log("compute_proto_keymat: key_len=%d from peer",
						    (int)needed_len));
				}
				break;
			}
			bad_case(pi->attrs.transattrs.ta_ikev1_encrypt);
		}
		DBG(DBG_PARSING, DBG_log("compute_proto_keymat: needed_len (after ESP enc)=%d",
					 (int)needed_len));
		needed_len += pi->attrs.transattrs.ta_integ->integ_keymat_size;
		DBG(DBG_PARSING, DBG_log("compute_proto_keymat: needed_len (after ESP auth)=%d",
					 (int)needed_len));
		break;

	case PROTO_IPSEC_AH:
		needed_len += pi->attrs.transattrs.ta_integ->integ_keymat_size;
		break;

	default:
		bad_case(protoid);
	}

	pi->keymat_len = needed_len;

	/* Allocate space for the keying material.
	 * Although only needed_len bytes are desired, we
	 * must round up to a multiple of ctx.hmac_digest_len
	 * so that our buffer isn't overrun.
	 */
	{
		struct hmac_ctx ctx_me, ctx_peer;
		size_t needed_space; /* space needed for keying material (rounded up) */
		size_t i;

		hmac_init(&ctx_me, st->st_oakley.ta_prf, st->st_skeyid_d_nss);
		/* PK11Context * DigestContext makes hmac not allowable for copy */
		hmac_init(&ctx_peer, st->st_oakley.ta_prf, st->st_skeyid_d_nss);
		needed_space = needed_len + pad_up(needed_len,
						   ctx_me.hmac_digest_len);
		replace(pi->our_keymat,
			alloc_bytes(needed_space,
				    "keymat in compute_keymat()"));
		replace(pi->peer_keymat,
			alloc_bytes(needed_space,
				    "peer_keymat in quick_inI1_outR1()"));

		for (i = 0;; ) {
			if (st->st_shared_nss != NULL) {
				crypt_prf_update_symkey("g^xy", ctx_me.prf, st->st_shared_nss);
				crypt_prf_update_symkey("g^xy", ctx_peer.prf, st->st_shared_nss);
			}
			hmac_update(&ctx_me, &protoid, sizeof(protoid));
			hmac_update(&ctx_peer, &protoid, sizeof(protoid));

			hmac_update(&ctx_me, (u_char *)&pi->our_spi,
				    sizeof(pi->our_spi));
			hmac_update(&ctx_peer, (u_char *)&pi->attrs.spi,
				    sizeof(pi->attrs.spi));

			hmac_update_chunk(&ctx_me, st->st_ni);
			hmac_update_chunk(&ctx_peer, st->st_ni);

			hmac_update_chunk(&ctx_me, st->st_nr);
			hmac_update_chunk(&ctx_peer, st->st_nr);

			hmac_final(pi->our_keymat + i, &ctx_me);
			hmac_final(pi->peer_keymat + i, &ctx_peer);

			i += ctx_me.hmac_digest_len;
			if (i >= needed_space)
				break;

			/* more keying material needed: prepare to go around again */
			hmac_init(&ctx_me, st->st_oakley.ta_prf, st->st_skeyid_d_nss);
			hmac_init(&ctx_peer, st->st_oakley.ta_prf, st->st_skeyid_d_nss);

			hmac_update(&ctx_me,
				    pi->our_keymat + i - ctx_me.hmac_digest_len,
				    ctx_me.hmac_digest_len);
			hmac_update(&ctx_peer,
				    pi->peer_keymat + i - ctx_peer.hmac_digest_len,
				    ctx_peer.hmac_digest_len);
		}
	}

	DBG(DBG_PRIVATE, {
		    DBG_log("%s KEYMAT", satypename);
		    DBG_dump("  KEYMAT computed:", pi->our_keymat,
			     pi->keymat_len);
		    DBG_dump("  Peer KEYMAT computed:", pi->peer_keymat,
			     pi->keymat_len);
	    });
}

static void compute_keymats(struct state *st)
{
	if (st->st_ah.present)
		compute_proto_keymat(st, PROTO_IPSEC_AH, &st->st_ah, "AH");
	if (st->st_esp.present)
		compute_proto_keymat(st, PROTO_IPSEC_ESP, &st->st_esp, "ESP");
}

/* Decode the variable part of an ID packet (during Quick Mode).
 * This is designed for packets that identify clients, not peers.
 * Rejects 0.0.0.0/32 or IPv6 equivalent because
 * (1) it is wrong and (2) we use this value for inband signalling.
 */
static bool decode_net_id(struct isakmp_ipsec_id *id,
			  pb_stream *id_pbs,
			  ip_subnet *net,
			  const char *which)
{
	const struct af_info *afi = NULL;

	/* Note: the following may be a pointer into static memory
	 * that may be recycled, but only if the type is not known.
	 * That case is disposed of very early -- in the first switch.
	 */
	const char *idtypename = enum_show(&ike_idtype_names, id->isaiid_idtype);

	switch (id->isaiid_idtype) {
	case ID_IPV4_ADDR:
	case ID_IPV4_ADDR_SUBNET:
	case ID_IPV4_ADDR_RANGE:
		afi = &af_inet4_info;
		break;
	case ID_IPV6_ADDR:
	case ID_IPV6_ADDR_SUBNET:
	case ID_IPV6_ADDR_RANGE:
		afi = &af_inet6_info;
		break;
	case ID_FQDN:
		loglog(RC_COMMENT, "%s type is FQDN", which);
		return TRUE;

	default:
		/* XXX support more */
		loglog(RC_LOG_SERIOUS, "unsupported ID type %s",
		       idtypename);
		/* XXX Could send notification back */
		return FALSE;
	}

	switch (id->isaiid_idtype) {
	case ID_IPV4_ADDR:
	case ID_IPV6_ADDR:
	{
		ip_address temp_address;
		err_t ughmsg = initaddr(id_pbs->cur, pbs_left(id_pbs),
					afi->af, &temp_address);

		if (ughmsg != NULL) {
			loglog(RC_LOG_SERIOUS,
			       "%s ID payload %s has wrong length in Quick I1 (%s)",
			       which, idtypename, ughmsg);
			/* XXX Could send notification back */
			return FALSE;
		}
		if (isanyaddr(&temp_address)) {
			ipstr_buf b;

			loglog(RC_LOG_SERIOUS,
			       "%s ID payload %s is invalid (%s) in Quick I1",
			       which, idtypename, ipstr(&temp_address, &b));
			/* XXX Could send notification back */
			return FALSE;
		}
		happy(addrtosubnet(&temp_address, net));
		DBG(DBG_PARSING | DBG_CONTROL, {
			ipstr_buf b;
			DBG_log("%s is %s", which, ipstr(&temp_address, &b));
		});
		break;
	}

	case ID_IPV4_ADDR_SUBNET:
	case ID_IPV6_ADDR_SUBNET:
	{
		ip_address temp_address, temp_mask;
		err_t ughmsg;

		if (pbs_left(id_pbs) != 2 * afi->ia_sz) {
			loglog(RC_LOG_SERIOUS,
			       "%s ID payload %s wrong length in Quick I1",
			       which, idtypename);
			/* XXX Could send notification back */
			return FALSE;
		}
		ughmsg = initaddr(id_pbs->cur,
				  afi->ia_sz, afi->af, &temp_address);
		if (ughmsg == NULL)
			ughmsg = initaddr(id_pbs->cur + afi->ia_sz,
					  afi->ia_sz, afi->af, &temp_mask);
		if (ughmsg == NULL) {
			ughmsg = initsubnet(&temp_address,
					    masktocount(&temp_mask),
					   '0', net);
		}
		if (ughmsg == NULL && subnetisnone(net))
			ughmsg = "contains only anyaddr";
		if (ughmsg != NULL) {
			loglog(RC_LOG_SERIOUS,
			       "%s ID payload %s bad subnet in Quick I1 (%s)",
			       which, idtypename, ughmsg);
			/* XXX Could send notification back */
			return FALSE;
		}
		DBG(DBG_PARSING | DBG_CONTROL,
		    {
			    char temp_buff[SUBNETTOT_BUF];

			    subnettot(net, 0, temp_buff, sizeof(temp_buff));
			    DBG_log("%s is subnet %s", which, temp_buff);
		    });
		break;
	}

	case ID_IPV4_ADDR_RANGE:
	case ID_IPV6_ADDR_RANGE:
	{
		ip_address temp_address_from, temp_address_to;
		err_t ughmsg;

		if (pbs_left(id_pbs) != 2 * afi->ia_sz) {
			loglog(RC_LOG_SERIOUS,
			       "%s ID payload %s wrong length in Quick I1",
			       which, idtypename);
			/* XXX Could send notification back */
			return FALSE;
		}
		ughmsg = initaddr(id_pbs->cur, afi->ia_sz, afi->af,
				  &temp_address_from);
		if (ughmsg == NULL) {
			ughmsg = initaddr(id_pbs->cur + afi->ia_sz,
					  afi->ia_sz, afi->af,
					  &temp_address_to);
		}
		if (ughmsg != NULL) {
			loglog(RC_LOG_SERIOUS,
			       "%s ID payload %s malformed (%s) in Quick I1",
			       which, idtypename, ughmsg);
			/* XXX Could send notification back */
			return FALSE;
		}

		ughmsg = rangetosubnet(&temp_address_from, &temp_address_to,
				       net);
		if (ughmsg == NULL && subnetisnone(net))
			ughmsg = "contains only anyaddr";
		if (ughmsg != NULL) {
			ipstr_buf a, b;

			loglog(RC_LOG_SERIOUS, "%s ID payload in Quick I1, %s %s - %s unacceptable: %s",
			       which, idtypename,
			       ipstr(&temp_address_from, &a),
			       ipstr(&temp_address_to, &b),
			       ughmsg);
			return FALSE;
		}
		DBG(DBG_PARSING | DBG_CONTROL, {
			char temp_buff[SUBNETTOT_BUF];

			subnettot(net, 0, temp_buff, sizeof(temp_buff));
			DBG_log("%s is subnet %s (received as range)",
				which, temp_buff);
		});
		break;
	}
	}

	/* set the port selector */
	setportof(htons(id->isaiid_port), &net->addr);

	DBG(DBG_PARSING | DBG_CONTROL,
	    DBG_log("%s protocol/port is %d/%d", which, id->isaiid_protoid,
		    id->isaiid_port));

	return TRUE;
}

/* like decode, but checks that what is received matches what was sent */
static bool check_net_id(struct isakmp_ipsec_id *id,
			 pb_stream *id_pbs,
			 uint8_t *protoid,
			 uint16_t *port,
			 ip_subnet *net,
			 const char *which)
{
	ip_subnet net_temp;
	bool bad_proposal = FALSE;

	if (!decode_net_id(id, id_pbs, &net_temp, which))
		return FALSE;

	if (!samesubnet(net, &net_temp)) {
		char subrec[SUBNETTOT_BUF];
		char subxmt[SUBNETTOT_BUF];
		subnettot(net, 0, subxmt, sizeof(subxmt));
		subnettot(&net_temp, 0, subrec, sizeof(subrec));
		loglog(RC_LOG_SERIOUS,
		       "%s subnet returned doesn't match my proposal - us: %s vs them: %s",
		       which, subxmt, subrec);
#ifdef ALLOW_MICROSOFT_BAD_PROPOSAL
		loglog(RC_LOG_SERIOUS,
		       "Allowing questionable proposal anyway [ALLOW_MICROSOFT_BAD_PROPOSAL]");
		bad_proposal = FALSE;
#else
		bad_proposal = TRUE;
#endif
	}
	if (*protoid != id->isaiid_protoid) {
		loglog(RC_LOG_SERIOUS,
		       "%s peer returned protocol id does not match my proposal - us: %d vs them: %d",
		       which, *protoid, id->isaiid_protoid);
#ifdef ALLOW_MICROSOFT_BAD_PROPOSAL
		loglog(RC_LOG_SERIOUS,
		       "Allowing questionable proposal anyway [ALLOW_MICROSOFT_BAD_PROPOSAL]");
		bad_proposal = FALSE;
#else
		bad_proposal = TRUE;
#endif
	}
	/*
	 * workaround for #802- "our client ID returned doesn't match my proposal"
	 * until such time as bug #849 is properly fixed.
	 */
	if (*port != id->isaiid_port) {
		loglog(RC_LOG_SERIOUS,
		       "%s peer returned port doesn't match my proposal - us: %d vs them: %d",
		       which, *port, id->isaiid_port);
		if (*port != 0 && id->isaiid_port != 1701) {
			loglog(RC_LOG_SERIOUS,
			       "Allowing bad L2TP/IPsec proposal (see bug #849) anyway");
			bad_proposal = FALSE;
		} else {
			bad_proposal = TRUE;
		}
	}

	return !bad_proposal;
}

/* Compute HASH(1), HASH(2) of Quick Mode.
 * HASH(1) is part of Quick I1 message.
 * HASH(2) is part of Quick R1 message.
 * Used by: quick_outI1, quick_inI1_outR1 (twice), quick_inR1_outI2
 * (see RFC 2409 "IKE" 5.5, pg. 18 or draft-ietf-ipsec-ike-01.txt 6.2 pg 25)
 */
static size_t quick_mode_hash12(u_char *dest, const u_char *start,
				const u_char *roof,
				const struct state *st, const msgid_t *msgid,
				bool hash2)
{
	struct hmac_ctx ctx;

#if 0   /* if desperate to debug hashing */
#   define hmac_update(ctx, ptr, len) { \
		DBG_dump("hash input", (ptr), (len)); \
		(hmac_update)((ctx), (ptr), (len)); \
}
	DBG_dump("hash key", st->st_skeyid_a.ptr, st->st_skeyid_a.len);
#endif
	hmac_init(&ctx, st->st_oakley.ta_prf, st->st_skeyid_a_nss);
	passert(sizeof(msgid_t) == sizeof(uint32_t));
	msgid_t raw_msgid = htonl(*msgid);
	hmac_update(&ctx, (const void *)&raw_msgid, sizeof(raw_msgid));
	if (hash2)
		hmac_update_chunk(&ctx, st->st_ni); /* include Ni_b in the hash */
	hmac_update(&ctx, start, roof - start);
	hmac_final(dest, &ctx);

	DBG(DBG_CRYPT, {
			DBG_log("HASH(%d) computed:", hash2 + 1);
			DBG_dump("", dest, ctx.hmac_digest_len);
		});
	return ctx.hmac_digest_len;

#   undef hmac_update
}

/* Compute HASH(3) in Quick Mode (part of Quick I2 message).
 * Used by: quick_inR1_outI2, quick_inI2
 * See RFC2409 "The Internet Key Exchange (IKE)" 5.5.
 * NOTE: this hash (unlike HASH(1) and HASH(2)) ONLY covers the
 * Message ID and Nonces.  This is a mistake.
 */
static size_t quick_mode_hash3(u_char *dest, struct state *st)
{
	struct hmac_ctx ctx;

	hmac_init(&ctx, st->st_oakley.ta_prf, st->st_skeyid_a_nss);
	hmac_update(&ctx, (const u_char *)"\0", 1);
	passert(sizeof(msgid_t) == sizeof(uint32_t));
	msgid_t raw_msgid = htonl(st->st_msgid);
	hmac_update(&ctx, (const void*)&raw_msgid, sizeof(raw_msgid));
	hmac_update_chunk(&ctx, st->st_ni);
	hmac_update_chunk(&ctx, st->st_nr);
	hmac_final(dest, &ctx);
	DBG_cond_dump(DBG_CRYPT, "HASH(3) computed:", dest,
		      ctx.hmac_digest_len);
	return ctx.hmac_digest_len;
}

/* Compute Phase 2 IV.
 * Uses Phase 1 IV from st_iv; puts result in st_new_iv.
 */
void init_phase2_iv(struct state *st, const msgid_t *msgid)
{
	const struct hash_desc *h = st->st_oakley.ta_prf->hasher;
	passert(h);

	DBG_cond_dump(DBG_CRYPT, "last Phase 1 IV:",
		      st->st_ph1_iv, st->st_ph1_iv_len);

	st->st_new_iv_len = h->hash_digest_size;
	passert(st->st_new_iv_len <= sizeof(st->st_new_iv));

	DBG_cond_dump(DBG_CRYPT, "current Phase 1 IV:",
		      st->st_iv, st->st_iv_len);

	struct crypt_hash *ctx = crypt_hash_init(h, "IV", DBG_CRYPT);
	crypt_hash_digest_bytes(ctx, "PH1_IV", st->st_ph1_iv, st->st_ph1_iv_len);
	passert(*msgid != 0);
	passert(sizeof(msgid_t) == sizeof(uint32_t));
	msgid_t raw_msgid = htonl(*msgid);
	crypt_hash_digest_bytes(ctx, "MSGID", (void*) &raw_msgid, sizeof(raw_msgid));
	crypt_hash_final_bytes(&ctx, st->st_new_iv, st->st_new_iv_len);

	DBG_cond_dump(DBG_CRYPT, "computed Phase 2 IV:",
		      st->st_new_iv, st->st_new_iv_len);
}

static stf_status quick_outI1_tail(struct pluto_crypto_req *r,
				   struct state *st);

static crypto_req_cont_func quick_outI1_continue;	/* type assertion */

static void quick_outI1_continue(struct state *st, struct msg_digest **mdp UNUSED,
				 struct pluto_crypto_req *r)
{
	DBG(DBG_CONTROL,
		DBG_log("quick_outI1_continue for #%lu: calculated ke+nonce, sending I1",
			st->st_serialno));

	pexpect(*mdp == NULL); /* no packet */
	passert(st != NULL);
	stf_status e = quick_outI1_tail(r, st);
	if (e == STF_INTERNAL_ERROR) {
		loglog(RC_LOG_SERIOUS,
		       "%s: quick_outI1_tail() failed with STF_INTERNAL_ERROR",
		       __FUNCTION__);
	}
}

void quick_outI1(fd_t whack_sock,
		 struct state *isakmp_sa,
		 struct connection *c,
		 lset_t policy,
		 unsigned long try,
		 so_serial_t replacing
#ifdef HAVE_LABELED_IPSEC
		 , struct xfrm_user_sec_ctx_ike *uctx
#endif
		 )
{
	struct state *st = ikev1_duplicate_state(isakmp_sa);
	st->st_whack_sock = whack_sock;
	st->st_connection = c;	/* safe: from duplicate_state */
	passert(c != NULL);

	so_serial_t old_state = push_cur_state(st); /* we must reset before exit */
	st->st_policy = policy;
	st->st_try = try;

#ifdef HAVE_LABELED_IPSEC
	st->sec_ctx = NULL;
	if (uctx != NULL) {
		st->sec_ctx = clone_thing(*uctx, "sec ctx structure");
		DBG(DBG_CONTROL,
		    DBG_log("pending phase 2 with security context \"%s\"",
			    st->sec_ctx->sec_ctx_value));
	}
#endif

	st->st_myuserprotoid = c->spd.this.protocol;
	st->st_peeruserprotoid = c->spd.that.protocol;
	st->st_myuserport = c->spd.this.port;
	st->st_peeruserport = c->spd.that.port;

	st->st_msgid = generate_msgid(isakmp_sa);
	change_state(st, STATE_QUICK_I1); /* from STATE_UNDEFINED */

	insert_state(st); /* needs cookies, connection, and msgid */

	/* figure out PFS group, if any */

	if (policy & POLICY_PFS ) {
		/*
		 * Old code called ike_alg_pfsgroup() and that first
		 * checked st->st_policy for POLICY_PFS.  It's assumed
		 * the check was redundant.
		 */
		pexpect((st->st_policy & POLICY_PFS));
		/*
		 * See if pfs_group has been specified for this conn,
		 * use that group.
		 * if not, fallback to old use-same-as-P1 behaviour
		 */
		st->st_pfs_group = ikev1_quick_pfs(c->alg_info_esp);
		/* otherwise, use the same group as during Phase 1:
		 * since no negotiation is possible, we pick one that is
		 * very likely supported.
		 */
		if (st->st_pfs_group == NULL)
			st->st_pfs_group = isakmp_sa->st_oakley.ta_dh;
	}

	LSWLOG(buf) {
		lswlogf(buf, "initiating Quick Mode %s", prettypolicy(policy));
		if (replacing != SOS_NOBODY) {
			lswlogf(buf, " to replace #%lu", replacing);
		}
		lswlogf(buf, " {using isakmp#%lu msgid:%08" PRIx32 " proposal=",
			isakmp_sa->st_serialno, st->st_msgid);
		if (st->st_connection->alg_info_esp != NULL) {
			lswlog_alg_info(buf, &st->st_connection->alg_info_esp->ai);
		} else {
			lswlogf(buf, "defaults");
		}
		lswlogf(buf, " pfsgroup=");
		if ((policy & POLICY_PFS) != LEMPTY) {
			lswlogs(buf, st->st_pfs_group->common.fqn);
		} else {
			lswlogs(buf, "no-pfs");
		}
		lswlogf(buf, "}");
	}

	/* save for post crytpo logging */
	st->st_ipsec_pred = replacing;

	if (policy & POLICY_PFS) {
		request_ke_and_nonce("quick_outI1 KE", st,
				     st->st_pfs_group,
				     quick_outI1_continue);
	} else {
		request_nonce("quick_outI1 KE", st,
			      quick_outI1_continue);
	}
	pop_cur_state(old_state);
}

static stf_status quick_outI1_tail(struct pluto_crypto_req *r,
				   struct state *st)
{
	struct state *isakmp_sa = state_with_serialno(st->st_clonedfrom);
	struct connection *c = st->st_connection;
	pb_stream rbody;
	u_char          /* set by START_HASH_PAYLOAD: */
		*r_hashval,     /* where in reply to jam hash value */
		*r_hash_start;  /* start of what is to be hashed */
	bool has_client = c->spd.this.has_client || c->spd.that.has_client ||
			  c->spd.this.protocol != 0 || c->spd.that.protocol != 0 ||
			  c->spd.this.port != 0 || c->spd.that.port != 0;

	if (isakmp_sa == NULL) {
		/* phase1 state got deleted while cryptohelper was working */
		loglog(RC_LOG_SERIOUS,
		       "phase2 initiation failed because parent ISAKMP #%lu is gone",
		       st->st_clonedfrom);
		return STF_FATAL;
	}

	if (isakmp_sa->hidden_variables.st_nat_traversal & NAT_T_DETECTED) {
		/* Duplicate nat_traversal status in new state */
		st->hidden_variables.st_nat_traversal =
			isakmp_sa->hidden_variables.st_nat_traversal;
		if (LHAS(isakmp_sa->hidden_variables.st_nat_traversal,
			 NATED_HOST))
			has_client = TRUE;
		nat_traversal_change_port_lookup(NULL, st);
	} else {
		st->hidden_variables.st_nat_traversal = LEMPTY;
	}

	/* set up reply */
	init_out_pbs(&reply_stream, reply_buffer, sizeof(reply_buffer),
		 "reply packet");

	/* HDR* out */
	{
		struct isakmp_hdr hdr = {
			.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
					  ISAKMP_MINOR_VERSION,
			.isa_np = ISAKMP_NEXT_HASH,
			.isa_xchg = ISAKMP_XCHG_QUICK,
			.isa_msgid = st->st_msgid,
			.isa_flags = ISAKMP_FLAGS_v1_ENCRYPTION,
		};
		memcpy(hdr.isa_icookie, st->st_icookie, COOKIE_SIZE);
		memcpy(hdr.isa_rcookie, st->st_rcookie, COOKIE_SIZE);
		if (!out_struct(&hdr, &isakmp_hdr_desc, &reply_stream,
				&rbody)) {
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	/* HASH(1) -- create and note space to be filled later */
	START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_SA);

	/* SA out */

	/* Emit SA payload based on a subset of the policy bits.
	 * POLICY_COMPRESS is considered iff we can do IPcomp.
	 */
	{
		lset_t pm = st->st_policy & (POLICY_ENCRYPT |
					     POLICY_AUTHENTICATE |
					     can_do_IPcomp ? POLICY_COMPRESS : 0);
		DBGF(DBG_CONTROL, "emitting quick defaults using policy %s",
		     bitnamesof(sa_policy_bit_names, pm));

		if (!ikev1_out_sa(&rbody,
				  &ipsec_sadb[pm >> POLICY_IPSEC_SHIFT],
				  st, FALSE, FALSE, ISAKMP_NEXT_NONCE)) {
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	{
		/*
		 * ??? this np calculation says the test for KE is
		 *	(st->st_policy & POLICY_PFS)
		 * yet the KE code says the test is
		 *	st->st_pfs_group != NULL
		 */
		int np = (st->st_policy & POLICY_PFS) ?
				ISAKMP_NEXT_KE :
			has_client ?
				ISAKMP_NEXT_ID :
				ISAKMP_NEXT_NONE;

		/* Ni out */
		if (!ikev1_ship_nonce(&st->st_ni, r, &rbody, np, "Ni")) {
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	/* [ KE ] out (for PFS) */
	if (st->st_pfs_group != NULL) {
		if (!ikev1_ship_KE(st, r, &st->st_gi,
			     &rbody,
			     has_client ? ISAKMP_NEXT_ID : ISAKMP_NEXT_NONE)) {
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	/* [ IDci, IDcr ] out */
	if (has_client) {
		/* IDci (we are initiator), then IDcr (peer is responder) */
		if (!emit_subnet_id(&c->spd.this.client,
				    ISAKMP_NEXT_ID,
				    st->st_myuserprotoid,
				    st->st_myuserport, &rbody) ||
		    !emit_subnet_id(&c->spd.that.client,
				    ISAKMP_NEXT_NONE,
				    st->st_peeruserprotoid,
				    st->st_peeruserport, &rbody)) {
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	if ((st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATOA) &&
	    !(st->st_policy & POLICY_TUNNEL) &&
	    LHAS(st->hidden_variables.st_nat_traversal, NATED_HOST)) {
		/** Send NAT-OA if our address is NATed */
		if (!nat_traversal_add_natoa(ISAKMP_NEXT_NONE, &rbody, st,
					     TRUE /* initiator */)) {
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	/* finish computing  HASH(1), inserting it in output */
	(void) quick_mode_hash12(r_hashval, r_hash_start, rbody.cur,
				 st, &st->st_msgid, FALSE);

	/* encrypt message, except for fixed part of header */

	init_phase2_iv(isakmp_sa, &st->st_msgid);
	restore_new_iv(st, isakmp_sa->st_new_iv, isakmp_sa->st_new_iv_len);

	if (!ikev1_encrypt_message(&rbody, st)) {
		reset_cur_state();
		return STF_INTERNAL_ERROR;
	}

	record_and_send_v1_ike_msg(st, &reply_stream,
		"reply packet from quick_outI1");

	delete_event(st);
	start_retransmits(st, EVENT_v1_RETRANSMIT);

	if (st->st_ipsec_pred == SOS_NOBODY) {
		whack_log(RC_NEW_STATE + STATE_QUICK_I1,
			  "%s: initiate",
			  st->st_state_name);
	} else {
		whack_log(RC_NEW_STATE + STATE_QUICK_I1,
			  "%s: initiate to replace #%lu",
			  st->st_state_name,
			  st->st_ipsec_pred);
		st->st_ipsec_pred = SOS_NOBODY;
	}

	return STF_OK;
}

/* Handle first message of Phase 2 -- Quick Mode.
 * HDR*, HASH(1), SA, Ni [, KE ] [, IDci, IDcr ] -->
 * HDR*, HASH(2), SA, Nr [, KE ] [, IDci, IDcr ]
 * (see RFC 2409 "IKE" 5.5)
 * Installs inbound IPsec SAs.
 * Although this seems early, we know enough to do so, and
 * this way we know that it is soon enough to catch all
 * packets that other side could send using this IPsec SA.
 *
 * Broken into parts to allow asynchronous DNS for TXT records:
 *
 * - quick_inI1_outR1 starts the ball rolling.
 *   It checks and parses enough to learn the Phase 2 IDs
 *
 * - quick_inI1_outR1_tail does the rest of the job
 *   XXX: why the function split?
 *
 * At the end of quick_inI1_outR1_tail, we have all the info we need, but we
 * haven't done any nonce generation or DH that we might need
 * to do, so that are two crypto continuations that do this work,
 * they are:
 *    quick_inI1_outR1_continue1 -- called after NONCE/KE
 *    quick_inI1_outR1_continue2 -- called after DH (if PFS)
 *
 * we have to call nonce/ke and DH if we are doing PFS.
 */

/* hold anything we can handle of a Phase 2 ID */
struct p2id {
	ip_subnet net;
	uint8_t proto;
	uint16_t port;
};

struct verify_oppo_bundle {
	bool failure_ok;	/* if true, quick_inI1_outR1_tail will try
				 * other things on DNS failure
				 */
	struct msg_digest *md;
	struct p2id my, his;
	unsigned int new_iv_len; /* p1st's might change */
	u_char new_iv[MAX_DIGEST_LEN];
	/* int whackfd; */	/* not needed because we are Responder */
};

static stf_status quick_inI1_outR1_tail(struct verify_oppo_bundle *b);

stf_status quick_inI1_outR1(struct state *p1st, struct msg_digest *md)
{
	passert(p1st != NULL && p1st == md->st);
	struct connection *c = p1st->st_connection;
	struct payload_digest *const id_pd = md->chain[ISAKMP_NEXT_ID];
	struct verify_oppo_bundle b;

	/* HASH(1) in */
	CHECK_QUICK_HASH(md,
			 quick_mode_hash12(hash_val, hash_pbs->roof,
					   md->message_pbs.roof,
					   p1st, &md->hdr.isa_msgid, FALSE),
			 "HASH(1)", "Quick I1");

	/* [ IDci, IDcr ] in
	 * We do this now (probably out of physical order) because
	 * we wish to select the correct connection before we consult
	 * it for policy.
	 */

	if (id_pd != NULL) {
		struct payload_digest *IDci = id_pd->next;

		/* ??? we are assuming IPSEC_DOI */

		/* IDci (initiator is peer) */

		if (!decode_net_id(&id_pd->payload.ipsec_id, &id_pd->pbs,
				   &b.his.net, "peer client"))
			return STF_FAIL + INVALID_ID_INFORMATION;

		/* Hack for MS 818043 NAT-T Update.
		 *
		 * <http://support.microsoft.com/kb/818043>
		 * "L2TP/IPsec NAT-T update for Windows XP and Windows 2000"
		 * This update is has a bug.  We choose to work around that
		 * bug rather than failing to interoperate.
		 * As to what the bug is, Paul says:
		 * "I believe on rekey, it sent a bogus subnet or wrong type of ID."
		 * ??? needs more complete description.
		 */
		if (id_pd->payload.ipsec_id.isaiid_idtype == ID_FQDN) {
			loglog(RC_LOG_SERIOUS,
			       "Applying workaround for MS-818043 NAT-T bug");
			zero(&b.his.net);
			happy(addrtosubnet(&c->spd.that.host_addr,
					   &b.his.net));
		}
		/* End Hack for MS 818043 NAT-T Update */

		b.his.proto = id_pd->payload.ipsec_id.isaiid_protoid;
		b.his.port = id_pd->payload.ipsec_id.isaiid_port;
		b.his.net.addr.u.v4.sin_port = htons(b.his.port);

		/* IDcr (we are responder) */

		if (!decode_net_id(&IDci->payload.ipsec_id, &IDci->pbs,
				   &b.my.net, "our client"))
			return STF_FAIL + INVALID_ID_INFORMATION;

		b.my.proto = IDci->payload.ipsec_id.isaiid_protoid;
		b.my.port = IDci->payload.ipsec_id.isaiid_port;
		b.my.net.addr.u.v4.sin_port = htons(b.my.port);

		/*
		 * if there is a NATOA payload, then use it as
		 *    &st->st_connection->spd.that.client, if the type
		 * of the ID was FQDN
		 *
		 * we actually do NATOA calculation again later on,
		 * but we need the info here, and we don't have a state
		 * to store it in until after we've done the authorization steps.
		 */
		if ((p1st->hidden_variables.st_nat_traversal &
		     NAT_T_DETECTED) &&
		    (p1st->hidden_variables.st_nat_traversal &
		     NAT_T_WITH_NATOA) &&
		    (id_pd->payload.ipsec_id.isaiid_idtype == ID_FQDN)) {
			struct hidden_variables hv;
			char idfqdn[IDTOA_BUF];
			char subnet_buf[SUBNETTOT_BUF];
			size_t idlen = pbs_room(&IDci->pbs);

			if (idlen >= sizeof(idfqdn)) {
				/* ??? truncation seems rude and dangerous */
				idlen = sizeof(idfqdn) - 1;
			}
			/* ??? what should happen if fqdn contains '\0'? */
			memcpy(idfqdn, IDci->pbs.cur, idlen);
			idfqdn[idlen] = '\0';

			hv = p1st->hidden_variables;
			nat_traversal_natoa_lookup(md, &hv);

			if (!isanyaddr(&hv.st_nat_oa)) {
				addrtosubnet(&hv.st_nat_oa, &b.his.net);
				subnettot(&b.his.net, 0, subnet_buf,
					  sizeof(subnet_buf));
				loglog(RC_LOG_SERIOUS,
				       "IDci was FQDN: %s, using NAT_OA=%s %d as IDci",
				       idfqdn, subnet_buf,
				       isanyaddr(&hv.st_nat_oa));
			}
		}
	} else {
		/* implicit IDci and IDcr: peer and self */
		if (!sameaddrtype(&c->spd.this.host_addr,
				  &c->spd.that.host_addr))
			return STF_FAIL;

		happy(addrtosubnet(&c->spd.this.host_addr, &b.my.net));
		happy(addrtosubnet(&c->spd.that.host_addr, &b.his.net));
		b.his.proto = b.my.proto = 0;
		b.his.port = b.my.port = 0;
	}
	b.md = md;
	save_new_iv(p1st, b.new_iv, b.new_iv_len);

	/*
	 * FIXME - DAVIDM
	 * "b" is on the stack,  for OPPO  tunnels this will be bad, in
	 * quick_inI1_outR1_start_query it saves a pointer to it before
	 * a crypto (async op).
	 */
	return quick_inI1_outR1_tail(&b);
}


/* forward definitions */
static stf_status quick_inI1_outR1_continue12_tail(struct msg_digest *md,
						   struct pluto_crypto_req *r);

static crypto_req_cont_func quick_inI1_outR1_continue1;	/* forward decl and type assertion */

static crypto_req_cont_func quick_inI1_outR1_continue2;	/* forward decl and type assertion */

static stf_status quick_inI1_outR1_tail(struct verify_oppo_bundle *b)
{
	struct msg_digest *md = b->md;
	struct state *const p1st = md->st;
	struct connection *c = p1st->st_connection;
	ip_subnet *our_net = &b->my.net,
	*his_net = &b->his.net;
	struct hidden_variables hv;

	{
		char s1[SUBNETTOT_BUF], d1[SUBNETTOT_BUF];

		subnettot(our_net, 0, s1, sizeof(s1));
		subnettot(his_net, 0, d1, sizeof(d1));

		libreswan_log("the peer proposed: %s:%d/%d -> %s:%d/%d",
			      s1, c->spd.this.protocol, c->spd.this.port,
			      d1, c->spd.that.protocol, c->spd.that.port);
	}

	/* Now that we have identities of client subnets, we must look for
	 * a suitable connection (our current one only matches for hosts).
	 */
	{
		struct connection *p = find_client_connection(c,
							      our_net, his_net,
							      b->my.proto,
							      b->my.port,
							      b->his.proto,
							      b->his.port);

		if ((p1st->hidden_variables.st_nat_traversal &
		      NAT_T_DETECTED) &&
		     !(p1st->st_policy & POLICY_TUNNEL) &&
		     p == NULL) {
			p = c;
			DBG(DBG_CONTROL, {
				char cib[CONN_INST_BUF];
				DBG_log("using something (we hope the IP we or they are NAT'ed to) for transport mode connection \"%s\"%s",
				    p->name, fmt_conn_instance(p, cib));
			});
		}

		if (p == NULL) {
			/* This message occurs in very puzzling circumstances
			 * so we must add as much information and beauty as we can.
			 */
			struct end
				me = c->spd.this,
				he = c->spd.that;
			char buf[2 * SUBNETTOT_BUF + 2 * ADDRTOT_BUF + 2 *
				 IDTOA_BUF + 2 * ADDRTOT_BUF + 12];                       /* + 12 for separating */
			size_t l;

			me.client = *our_net;
			me.has_client = !subnetisaddr(our_net, &me.host_addr);
			me.protocol = b->my.proto;
			me.port = b->my.port;

			he.client = *his_net;
			he.has_client = !subnetisaddr(his_net, &he.host_addr);
			he.protocol = b->his.proto;
			he.port = b->his.port;

			l = format_end(buf, sizeof(buf), &me, NULL, TRUE,
				       LEMPTY, oriented(*c));
			snprintf(buf + l, sizeof(buf) - l, "...");
			l += strlen(buf + l);
			(void)format_end(buf + l, sizeof(buf) - l, &he, NULL,
					 FALSE, LEMPTY, oriented(*c));
			libreswan_log("cannot respond to IPsec SA request because no connection is known for %s",
				      buf);
			return STF_FAIL + INVALID_ID_INFORMATION;
		}

		/* did we find a better connection? */
		if (p != c) {
			/* We've got a better connection: it can support the
			 * specified clients.  But it may need instantiation.
			 */
			if (p->kind == CK_TEMPLATE) {
				/* Plain Road Warrior because no OPPO for IKEv1
				 * instantiate, carrying over authenticated peer ID
				 */
				p = rw_instantiate(p,
						   &c->spd.that.host_addr,
						   his_net,
						   &c->spd.that.id);
			}
			/* temporarily bump up cur_debugging to get "using..." message
			 * printed if we'd want it with new connection.
			 */
			{
				lset_t old_cur_debugging = cur_debugging;

				set_debugging(lmod(cur_debugging, p->extra_debugging));
				DBG(DBG_CONTROL, {
					char cib[CONN_INST_BUF];
					DBG_log("using connection \"%s\"%s",
						p->name, fmt_conn_instance(p, cib));
				});
				set_debugging(old_cur_debugging);
			}
			c = p;
		}

		/* fill in the client's true ip address/subnet */
		DBG(DBG_CONTROLMORE,
		    DBG_log("client wildcard: %s  port wildcard: %s  virtual: %s",
			    bool_str(c->spd.that.has_client_wildcard),
			    bool_str(c->spd.that.has_port_wildcard),
			    bool_str(is_virtual_connection(c))));

		if (c->spd.that.has_client_wildcard) {
			c->spd.that.client = *his_net;
			c->spd.that.has_client_wildcard = FALSE;
		}

		/* fill in the client's true port */
		if (c->spd.that.has_port_wildcard) {
			int port = htons(b->his.port);

			setportof(port, &c->spd.that.host_addr);
			setportof(port, &c->spd.that.client.addr);

			c->spd.that.port = b->his.port;
			c->spd.that.has_port_wildcard = FALSE;
		}

		if (is_virtual_connection(c)) {
			char cthat[END_BUF];

			c->spd.that.client = *his_net;
			c->spd.that.has_client = TRUE;
			c->spd.that.virt = NULL;	/* ??? leak? */

			if (subnetishost(his_net) &&
			    addrinsubnet(&c->spd.that.host_addr, his_net)) {
				c->spd.that.has_client = FALSE;
			}

			format_end(cthat, sizeof(cthat), &c->spd.that, NULL,
				   TRUE, LEMPTY, oriented(*c));
			DBG(DBG_CONTROLMORE,
			    DBG_log("setting phase 2 virtual values to %s",
				    cthat));
		}
	}

	passert((p1st->st_policy & POLICY_PFS) == 0 ||
		p1st->st_pfs_group != NULL);

	/* now that we are sure of our connection, create our new state, and
	 * do any asynchronous cryptographic operations that we may need to
	 * make it all work.
	 */

	hv = p1st->hidden_variables;
	if ((hv.st_nat_traversal & NAT_T_DETECTED) &&
	    (hv.st_nat_traversal & NAT_T_WITH_NATOA))
		nat_traversal_natoa_lookup(md, &hv);

	/* create our new state */
	{
		struct state *const st = ikev1_duplicate_state(p1st);

		/* first: fill in missing bits of our new state object
		 * note: we don't copy over st_peer_pubkey, the public key
		 * that authenticated the ISAKMP SA.  We only need it in this
		 * routine, so we can "reach back" to p1st to get it.
		 */
		if (st->st_connection != c) {
			st->st_connection = c;	/* safe: from duplicate_state */
			set_cur_connection(c);
		}

		st->st_try = 0; /* not our job to try again from start */

		st->st_msgid = md->hdr.isa_msgid;

		restore_new_iv(st, b->new_iv, b->new_iv_len);

		set_cur_state(st);      /* (caller will reset) */
		md->st = st;            /* feed back new state */

		st->st_peeruserprotoid = b->his.proto;
		st->st_peeruserport = b->his.port;
		st->st_myuserprotoid = b->my.proto;
		st->st_myuserport = b->my.port;

		change_state(st, STATE_QUICK_R0);

		insert_state(st); /* needs cookies, connection, and msgid */

		/* copy hidden variables (possibly with changes) */
		st->hidden_variables = hv;

		/* copy the connection's
		 * IPSEC policy into our state.  The ISAKMP policy is water under
		 * the bridge, I think.  It will reflect the ISAKMP SA that we
		 * are using.
		 */
		st->st_policy = (p1st->st_policy & POLICY_ID_AUTH_MASK) |
				(c->policy & ~POLICY_ID_AUTH_MASK);

		if (p1st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) {
			/* ??? this partially overwrites what was done via hv */
			st->hidden_variables.st_nat_traversal =
				p1st->hidden_variables.st_nat_traversal;
			nat_traversal_change_port_lookup(md, md->st);
		} else {
			/* ??? this partially overwrites what was done via hv */
			st->hidden_variables.st_nat_traversal = LEMPTY;
		}

		passert(st->st_connection != NULL);
		passert(st->st_connection == c);

		/* process SA in */
		{
			struct payload_digest *const sapd =
				md->chain[ISAKMP_NEXT_SA];
			pb_stream in_pbs = sapd->pbs;

			/* parse and accept body, setting variables, but not forming
			 * our reply. We'll make up the reply later on.
			 *
			 * note that we process the copy of the pbs,
			 * so that we can process it again in the
			 * tail(). XXX: Huh, this is the tail
			 * function!
			 *
			 */
			st->st_pfs_group = &unset_group;
			RETURN_STF_FAILURE(parse_ipsec_sa_body(&in_pbs,
							       &sapd->payload.
							       sa,
							       NULL,
							       FALSE, st));
		}

		/* Ni in */
		RETURN_STF_FAILURE(accept_v1_nonce(md, &st->st_ni, "Ni"));

		/* [ KE ] in (for PFS) */
		RETURN_STF_FAILURE(accept_PFS_KE(md, &st->st_gi,
						 "Gi", "Quick Mode I1"));

		passert(st->st_pfs_group != &unset_group);

		passert(st->st_connection != NULL);

		if (st->st_pfs_group != NULL) {
			request_ke_and_nonce("quick_outI1 KE", st,
					     st->st_pfs_group,
					     quick_inI1_outR1_continue1);
		} else {
			request_nonce("quick_outI1 KE", st,
				      quick_inI1_outR1_continue1);
		}

		passert(st->st_connection != NULL);
		return STF_SUSPEND;
	}
}

static void quick_inI1_outR1_continue1(struct state *st,
				       struct msg_digest **mdp,
				       struct pluto_crypto_req *r)
{
	DBG(DBG_CONTROL,
		DBG_log("quick_inI1_outR1_cryptocontinue1 for #%lu: calculated ke+nonce, calculating DH",
			st->st_serialno));

	passert(st->st_connection != NULL);

	/* we always calculate a nonce */
	unpack_nonce(&st->st_nr, r);

	if (st->st_pfs_group != NULL) {
		/* PFS is on: do a new DH */
		unpack_KE_from_helper(st, r, &st->st_gr);
		start_dh_v1_secret(quick_inI1_outR1_continue2, "quick outR1 DH",
				   st, ORIGINAL_RESPONDER, st->st_pfs_group);
		/*
		 * XXX: Since more crypto has been requsted, MD needs
		 * to be re suspended.  If the original crypto request
		 * did everything this wouldn't be needed.
		 */
		suspend_md(st, mdp);
	} else {
		/* but if PFS is off, we don't do a second DH, so just
		 * call the continuation with NULL struct pluto_crypto_req *
		 */
		stf_status e = quick_inI1_outR1_continue12_tail(*mdp, NULL);
		if (e == STF_OK) {
			passert(*mdp != NULL);	/* ??? when would this fail? */
			complete_v1_state_transition(mdp, e);
		}
	}
	/* ??? why does our caller not care about e? */
}

static void quick_inI1_outR1_continue2(struct state *st,
				       struct msg_digest **mdp,
				       struct pluto_crypto_req *r)
{
	DBG(DBG_CONTROL,
		DBG_log("quick_inI1_outR1_cryptocontinue2 for #%lu: calculated DH, sending R1",
			st->st_serialno));

	passert(st->st_connection != NULL);
	passert(*mdp != NULL);
	stf_status e = quick_inI1_outR1_continue12_tail(*mdp, r);
	complete_v1_state_transition(mdp, e);
}

/*
 * Spit out the IPsec ID payload we got.
 *
 * We go to some trouble to use out_struct so NP
 * for adjacent packets is handled correctly.
 */
static bool echo_id(pb_stream *outs,
	const struct payload_digest *const id_pd,
	enum next_payload_types_ikev1 np)
{
	struct isakmp_ipsec_id id = id_pd->payload.ipsec_id;
	id.isaiid_np = np;
	/* We leave .isaiid_length: It will be updated to the same value */

	uint8_t *hs = outs->cur;
	pb_stream id_body;
	if (!out_struct(&id, &isakmp_ipsec_identification_desc, outs, &id_body))
		return FALSE;
	ptrdiff_t hl = id_body.cur - hs;	/* length of header */

	if (!out_raw(id_pd->pbs.start + hl, pbs_room(&id_pd->pbs) - hl, &id_body, "ID body"))
		return FALSE;

	close_output_pbs(&id_body);
	return TRUE;
}

static stf_status quick_inI1_outR1_continue12_tail(struct msg_digest *md,
						   struct pluto_crypto_req *r)
{
	struct state *st = md->st;
	struct payload_digest *const id_pd = md->chain[ISAKMP_NEXT_ID];
	struct payload_digest *const sapd = md->chain[ISAKMP_NEXT_SA];
	u_char          /* set by START_HASH_PAYLOAD: */
		*r_hashval,     /* where in reply to jam hash value */
		*r_hash_start;  /* from where to start hashing */

	/* Start the output packet.
	 *
	 * proccess_packet() would automatically generate the HDR*
	 * payload if smc->first_out_payload is not ISAKMP_NEXT_NONE.
	 * We don't do this because we wish there to be no partially
	 * built output packet if we need to suspend for asynch DNS.
	 *
	 * We build the reply packet as we parse the message since
	 * the parse_ipsec_sa_body emits the reply SA
	 */

	/* HDR* out */
	pb_stream rbody;
	ikev1_init_out_pbs_echo_hdr(md, TRUE, ISAKMP_NEXT_HASH,
				    &reply_stream, reply_buffer, sizeof(reply_buffer),
				    &rbody);

	/* HASH(2) out -- first pass */
	START_HASH_PAYLOAD(rbody, ISAKMP_NEXT_SA);

	passert(st->st_connection != NULL);

	pb_stream r_sa_pbs;

	{
		struct isakmp_sa sa = {
			.isasa_doi = ISAKMP_DOI_IPSEC,
			.isasa_np = ISAKMP_NEXT_NONCE,
		};
		if (!out_struct(&sa, &isakmp_sa_desc, &rbody, &r_sa_pbs))
			return STF_INTERNAL_ERROR;
	}

	/* parse and accept body, this time recording our reply */
	RETURN_STF_FAILURE(parse_ipsec_sa_body(&sapd->pbs,
					       &sapd->payload.sa,
					       &r_sa_pbs,
					       FALSE, st));

	passert(st->st_pfs_group != &unset_group);

	if ((st->st_policy & POLICY_PFS) && st->st_pfs_group == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "we require PFS but Quick I1 SA specifies no GROUP_DESCRIPTION");
		return STF_FAIL + NO_PROPOSAL_CHOSEN; /* ??? */
	}

	libreswan_log("responding to Quick Mode proposal {msgid:%08" PRIx32 "}",
		      st->st_msgid);
	{
		char instbuf[END_BUF];
		const struct connection *c = st->st_connection;
		const struct spd_route *sr = &c->spd;

		format_end(instbuf, sizeof(instbuf), &sr->this, &sr->that,
			   TRUE, LEMPTY, oriented(*c));
		libreswan_log("    us: %s", instbuf);

		format_end(instbuf, sizeof(instbuf), &sr->that, &sr->this,
			   FALSE, LEMPTY, oriented(*c));
		libreswan_log("  them: %s", instbuf);
	}

	/**** finish reply packet: Nr [, KE ] [, IDci, IDcr ] ****/

	{
		int np;
#ifdef IMPAIR_UNALIGNED_R1_MSG
		const char *padstr = getenv("PLUTO_UNALIGNED_R1_MSG");

		if (padstr != NULL)
			np = ISAKMP_NEXT_VID;
		else
#endif
		if (st->st_pfs_group != NULL)
			np = ISAKMP_NEXT_KE;
		else if (id_pd != NULL)
			np = ISAKMP_NEXT_ID;
		else
			np = ISAKMP_NEXT_NONE;

		/* Nr out */
		if (!ikev1_justship_nonce(&st->st_nr, &rbody, np, "Nr"))
			return STF_INTERNAL_ERROR;

#ifdef IMPAIR_UNALIGNED_R1_MSG
		if (padstr != NULL) {
			unsigned long padsize;
			err_t ugh = ttoulb(padstr, 0, 10, 100, &padsize);
			pb_stream vid_pbs;

			if (ugh != NULL) {
				libreswan_log("$PLUTO_UNALIGNED_R1_MSG malformed: %s; pretending it is 3", ugh);
				padsize = 3;
			}

			libreswan_log("inserting fake VID payload of %lu size",
				      padsize);

			if (st->st_pfs_group != NULL)
				np = ISAKMP_NEXT_KE;
			else if (id_pd != NULL)
				np = ISAKMP_NEXT_ID;
			else
				np = ISAKMP_NEXT_NONE;

			if (!ikev1_out_generic(np,
					 &isakmp_vendor_id_desc, &rbody,
					 &vid_pbs))
				return STF_INTERNAL_ERROR;

			if (!out_zero(padsize, &vid_pbs, "Filler VID"))
				return STF_INTERNAL_ERROR;

			close_output_pbs(&vid_pbs);
		}
#endif
	}

	/* [ KE ] out (for PFS) */
	if (st->st_pfs_group != NULL && r != NULL) {
		if (!ikev1_justship_KE(&st->st_gr,
				 &rbody,
				 id_pd != NULL ?
					ISAKMP_NEXT_ID : ISAKMP_NEXT_NONE))
			return STF_INTERNAL_ERROR;

		finish_dh_secret(st, r);
	}

	/* [ IDci, IDcr ] out */
	if (id_pd != NULL) {
		passert(id_pd->next->next == NULL);	/* exactly two */
		if (!echo_id(&rbody, id_pd, ISAKMP_NEXT_ID) ||
		    !echo_id(&rbody, id_pd->next, ISAKMP_NEXT_NONE))
			return STF_INTERNAL_ERROR;
	}

	/* Compute reply HASH(2) and insert in output */
	(void)quick_mode_hash12(r_hashval, r_hash_start, rbody.cur,
				st, &st->st_msgid, TRUE);

	/* Derive new keying material */
	compute_keymats(st);

	/* Tell the kernel to establish the new inbound SA
	 * (unless the commit bit is set -- which we don't support).
	 * We do this before any state updating so that
	 * failure won't look like success.
	 */
	if (!install_inbound_ipsec_sa(st))
		return STF_INTERNAL_ERROR; /* ??? we may be partly committed */

	/* encrypt message, except for fixed part of header */

	if (!ikev1_encrypt_message(&rbody, st)) {
		delete_ipsec_sa(st);
		return STF_INTERNAL_ERROR; /* ??? we may be partly committed */
	}

	DBG(DBG_CONTROLMORE, DBG_log("finished processing quick inI1"));
	return STF_OK;
}

/* Handle (the single) message from Responder in Quick Mode.
 * HDR*, HASH(2), SA, Nr [, KE ] [, IDci, IDcr ] -->
 * HDR*, HASH(3)
 * (see RFC 2409 "IKE" 5.5)
 * Installs inbound and outbound IPsec SAs, routing, etc.
 */
static stf_status quick_inR1_outI2_tail(struct msg_digest *md,
					struct pluto_crypto_req *r);

static crypto_req_cont_func quick_inR1_outI2_continue;	/* forward decl and type assertion */

stf_status quick_inR1_outI2(struct state *st, struct msg_digest *md)
{
	/* HASH(2) in */
	CHECK_QUICK_HASH(md,
			 quick_mode_hash12(hash_val, hash_pbs->roof,
					   md->message_pbs.roof,
					   st, &st->st_msgid, TRUE),
			 "HASH(2)", "Quick R1");

	/* SA in */
	{
		struct payload_digest *const sa_pd = md->chain[ISAKMP_NEXT_SA];

		RETURN_STF_FAILURE(parse_ipsec_sa_body(&sa_pd->pbs,
						       &sa_pd->payload.sa,
						       NULL, TRUE, st));
	}

	/* Nr in */
	RETURN_STF_FAILURE(accept_v1_nonce(md, &st->st_nr, "Nr"));

	/* [ KE ] in (for PFS) */
	RETURN_STF_FAILURE(accept_PFS_KE(md, &st->st_gr, "Gr",
					 "Quick Mode R1"));

	if (st->st_pfs_group != NULL) {
		/* set up DH calculation */
		start_dh_v1_secret(quick_inR1_outI2_continue, "quick outI2 DH",
				   st, ORIGINAL_INITIATOR, st->st_pfs_group);
		return STF_SUSPEND;
	} else {
		/* just call the tail function */
		return quick_inR1_outI2_tail(md, NULL);
	}
}

static void quick_inR1_outI2_continue(struct state *st,
				      struct msg_digest **mdp,
				      struct pluto_crypto_req *r)
{	DBG(DBG_CONTROL,
		DBG_log("quick_inR1_outI2_continue for #%lu: calculated ke+nonce, calculating DH",
			st->st_serialno));

	passert(st->st_connection != NULL);
	passert(*mdp != NULL);
	stf_status e = quick_inR1_outI2_tail(*mdp, r);
	complete_v1_state_transition(mdp, e);
}

stf_status quick_inR1_outI2_tail(struct msg_digest *md,
				 struct pluto_crypto_req *r)
{
	struct state *st = md->st;
	struct connection *c = st->st_connection;

	pb_stream rbody;
	ikev1_init_out_pbs_echo_hdr(md, TRUE, ISAKMP_NEXT_HASH,
				    &reply_stream, reply_buffer, sizeof(reply_buffer),
				    &rbody);

	if (st->st_pfs_group != NULL && r != NULL)
		finish_dh_secret(st, r);

	if ((st->hidden_variables.st_nat_traversal & NAT_T_DETECTED) &&
	    (st->hidden_variables.st_nat_traversal & NAT_T_WITH_NATOA))
		nat_traversal_natoa_lookup(md, &st->hidden_variables);

	/* [ IDci, IDcr ] in; these must match what we sent */

	{
		struct payload_digest *const IDci = md->chain[ISAKMP_NEXT_ID];
		struct payload_digest *IDcr;

		if (IDci != NULL) {
			/* ??? we are assuming IPSEC_DOI */

			/* IDci (we are initiator) */
			if (!check_net_id(&IDci->payload.ipsec_id, &IDci->pbs,
					  &st->st_myuserprotoid,
					  &st->st_myuserport,
					  &st->st_connection->spd.this.client,
					  "our client"))
				return STF_FAIL + INVALID_ID_INFORMATION;

			/* we checked elsewhere that we got two of them */
			IDcr = IDci->next;
			passert(IDcr != NULL);

			/* IDcr (responder is peer) */

			if (!check_net_id(&IDcr->payload.ipsec_id, &IDcr->pbs,
					  &st->st_peeruserprotoid,
					  &st->st_peeruserport,
					  &st->st_connection->spd.that.client,
					  "peer client"))
				return STF_FAIL + INVALID_ID_INFORMATION;

			/*
			 * if there is a NATOA payload, then use it as
			 *    &st->st_connection->spd.that.client, if the type
			 * of the ID was FQDN
			 */
			if ((st->hidden_variables.st_nat_traversal &
			     NAT_T_DETECTED) &&
			    (st->hidden_variables.st_nat_traversal &
			     NAT_T_WITH_NATOA) &&
			    IDcr->payload.ipsec_id.isaiid_idtype == ID_FQDN) {
				char idfqdn[IDTOA_BUF];
				char subnet_buf[SUBNETTOT_BUF];
				size_t idlen = pbs_room(&IDcr->pbs);

				if (idlen >= sizeof(idfqdn)) {
					/* ??? truncation seems rude and dangerous */
					idlen = sizeof(idfqdn) - 1;
				}
				/* ??? what should happen if fqdn contains '\0'? */
				memcpy(idfqdn, IDcr->pbs.cur, idlen);
				idfqdn[idlen] = '\0';

				addrtosubnet(&st->hidden_variables.st_nat_oa,
					     &st->st_connection->spd.that.client);

				subnettot(&st->st_connection->spd.that.client,
					  0, subnet_buf, sizeof(subnet_buf));
				loglog(RC_LOG_SERIOUS,
				       "IDcr was FQDN: %s, using NAT_OA=%s as IDcr",
				       idfqdn, subnet_buf);
			}
		} else {
			/* no IDci, IDcr: we must check that the defaults match our proposal */
			if (!subnetisaddr(&c->spd.this.client,
					  &c->spd.this.host_addr) ||
			    !subnetisaddr(&c->spd.that.client,
					  &c->spd.that.host_addr)) {
				loglog(RC_LOG_SERIOUS,
					"IDci, IDcr payloads missing in message but default does not match proposal");
				return STF_FAIL + INVALID_ID_INFORMATION;
			}
		}
	}

	/* ??? We used to copy the accepted proposal into the state, but it was
	 * never used.  From sa_pd->pbs.start, length pbs_room(&sa_pd->pbs).
	 */

	/**************** build reply packet HDR*, HASH(3) ****************/

	/* HDR* out done */

	/* HASH(3) out -- sometimes, we add more content */
	{
		u_char *r_hashval;	/* set by START_HASH_PAYLOAD */

#ifdef IMPAIR_UNALIGNED_I2_MSG
		{
			const char *padstr = getenv("PLUTO_UNALIGNED_I2_MSG");

			if (padstr != NULL) {
				unsigned long padsize;
				err_t ugh = ttoulb(padstr, 0, 10, 100, &padsize)
				pb_stream vid_pbs;

				if (ugh != NULL) {
					libreswan_log("$PLUTO_UNALIGNED_I2_MSG malformed: %s; pretending it is 3",
						ugh);
					padsize = 3;
				}

				libreswan_log(
					"inserting fake VID payload of %u size",
					padsize);
				START_HASH_PAYLOAD_NO_R_HASH_START(rbody,
								   ISAKMP_NEXT_VID);

				if (!ikev1_out_generic(ISAKMP_NEXT_NONE,
						 &isakmp_vendor_id_desc,
						 &rbody, &vid_pbs))
					return STF_INTERNAL_ERROR;

				if (!out_zero(padsize, &vid_pbs, "Filler VID"))
					return STF_INTERNAL_ERROR;

				close_output_pbs(&vid_pbs);
			} else {
				START_HASH_PAYLOAD(rbody,
						   ISAKMP_NEXT_NONE);
			}
		}
#else
		START_HASH_PAYLOAD_NO_R_HASH_START(rbody,
						   ISAKMP_NEXT_NONE);
#endif


		(void)quick_mode_hash3(r_hashval, st);
	}

	/* Derive new keying material */
	compute_keymats(st);

	/* Tell the kernel to establish the inbound, outbound, and routing part
	 * of the new SA (unless the commit bit is set -- which we don't support).
	 * We do this before any state updating so that
	 * failure won't look like success.
	 */
	if (!install_ipsec_sa(st, TRUE))
		return STF_INTERNAL_ERROR;

	/* encrypt message, except for fixed part of header */

	if (!ikev1_encrypt_message(&rbody, st)) {
		delete_ipsec_sa(st);
		return STF_INTERNAL_ERROR; /* ??? we may be partly committed */
	}

	set_newest_ipsec_sa("inR1_outI2", st);

	/* If we have dpd delay and dpdtimeout set, then we are doing DPD
	    on this conn, so initialize it */
	if (deltasecs(st->st_connection->dpd_delay) != 0 &&
	    deltasecs(st->st_connection->dpd_timeout) != 0) {
		if (dpd_init(st) != STF_OK) {
			delete_ipsec_sa(st);
			return STF_FAIL;
		}
	}

	return STF_OK;
}

/* Handle last message of Quick Mode.
 * HDR*, HASH(3) -> done
 * (see RFC 2409 "IKE" 5.5)
 * Installs outbound IPsec SAs, routing, etc.
 */
stf_status quick_inI2(struct state *st, struct msg_digest *md)
{
	/* HASH(3) in */
	CHECK_QUICK_HASH(md, quick_mode_hash3(hash_val, st),
			 "HASH(3)", "Quick I2");

	/* Tell the kernel to establish the outbound and routing part of the new SA
	 * (the previous state established inbound)
	 * (unless the commit bit is set -- which we don't support).
	 * We do this before any state updating so that
	 * failure won't look like success.
	 */
	if (!install_ipsec_sa(st, FALSE))
		return STF_INTERNAL_ERROR;

	set_newest_ipsec_sa("inI2", st);

	update_iv(st);  /* not actually used, but tidy */

	/*
	 * If we have dpd delay and dpdtimeout set, then we are doing DPD
	 * on this conn, so initialize it
	 */
	if (deltasecs(st->st_connection->dpd_delay) != 0 &&
	    deltasecs(st->st_connection->dpd_timeout) != 0) {
		if (dpd_init(st) != STF_OK) {
			delete_ipsec_sa(st);
			return STF_FAIL;
		}
	}

	return STF_OK;
}
