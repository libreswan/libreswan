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
#include <sys/time.h>           /* for gettimeofday */
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
#include "dnskey.h"     /* needs keys.h and adns.h */
#include "kernel.h"     /* needs connections.h */
#include "log.h"
#include "cookie.h"
#include "server.h"
#include "spdb.h"
#include "timer.h"
#include "rnd.h"
#include "ipsec_doi.h"  /* needs demux.h and state.h */
#include "whack.h"
#include "fetch.h"
#include "asn1.h"

#include "sha1.h"
#include "md5.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "secrets.h"

#include "ike_alg.h"
#include "kernel_alg.h"
#include "plutoalg.h"

#include "pluto_crypt.h"
#include "crypt_prf.h"
#include "ikev1.h"
#include "ikev1_quick.h"
#include "ikev1_continuations.h"

#include "ikev1_xauth.h"

#include "vendor.h"
#include "nat_traversal.h"
#include "virtual.h"	/* needs connections.h */
#include "ikev1_dpd.h"
#include "pluto_x509.h"

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

static bool emit_subnet_id(ip_subnet *net,
			   u_int8_t np,
			   u_int8_t protoid,
			   u_int16_t port,
			   pb_stream *outs)
{
	struct isakmp_ipsec_id id;
	pb_stream id_pbs;
	ip_address ta;
	unsigned char *tbp;
	size_t tal;
	const struct af_info *ai;
	bool usehost = FALSE;
	int masklen;

	ai = aftoinfo(subnettypeof(net));

	passert(ai != NULL);

	maskof(net, &ta);
	masklen = masktocount(&ta);
#if 1
	if (masklen == ai->mask_cnt)
		usehost = TRUE;

#endif

	id.isaiid_np = np;
	id.isaiid_idtype = (usehost ? ai->id_addr : ai->id_subnet);
	id.isaiid_protoid = protoid;
	id.isaiid_port = port;

	if (!out_struct(&id, &isakmp_ipsec_identification_desc, outs, &id_pbs))
		return FALSE;

	networkof(net, &ta);
	tal = addrbytesptr(&ta, &tbp);
	if (!out_raw(tbp, tal, &id_pbs, "client network"))
		return FALSE;

	if (!usehost) {
		maskof(net, &ta);
		tal = addrbytesptr(&ta, &tbp);
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
				 u_int8_t protoid,
				 struct ipsec_proto_info *pi,
				 const char *satypename)
{
	size_t needed_len = 0; /* bytes of keying material needed */

	/* Add up the requirements for keying material
	 * (It probably doesn't matter if we produce too much!)
	 */
	switch (protoid) {
	case PROTO_IPSEC_ESP:
		switch (pi->attrs.transattrs.encrypt) {
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
		case ESP_CAMELLIAv1:
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

#if 0
		case ESP_SEED_CBC:
			if (st->st_esp.attrs.transattrs.enckeylen != 0) {
				/* SEED-CBC is always 128bit */
				passert(st->st_esp.attrs.transattrs.enckeylen == 128);
				needed_len = st->st_esp.attrs.transattrs.enckeylen / BITS_PER_BYTE;
			}
			break;
#endif

		default:
			needed_len = kernel_alg_esp_enc_max_keylen(
					pi->attrs.transattrs.encrypt);
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
			bad_case(pi->attrs.transattrs.encrypt);
		}
		DBG(DBG_PARSING, DBG_log("compute_proto_keymat: needed_len (after ESP enc)=%d",
					 (int)needed_len));

		switch (pi->attrs.transattrs.integ_hash) {
		case AUTH_ALGORITHM_NONE:
			break;
		case AUTH_ALGORITHM_HMAC_MD5:
			needed_len += HMAC_MD5_KEY_LEN;
			break;
		case AUTH_ALGORITHM_HMAC_SHA1:
			needed_len += HMAC_SHA1_KEY_LEN;
			break;
		/* kernel_alg_ah_auth_ok / kernel_alg_ah_auth_keylen are incomplete */
		case AUTH_ALGORITHM_HMAC_SHA2_256:
			needed_len += BYTES_FOR_BITS(256);
			break;
		case AUTH_ALGORITHM_HMAC_SHA2_384:
			needed_len += BYTES_FOR_BITS(384);
			break;
		case AUTH_ALGORITHM_HMAC_SHA2_512:
			needed_len += BYTES_FOR_BITS(512);
			break;
		case AUTH_ALGORITHM_HMAC_RIPEMD:
			needed_len += BYTES_FOR_BITS(160);
			break;
		case AUTH_ALGORITHM_AES_XCBC:
			needed_len += BYTES_FOR_BITS(128);
			break;
		case AUTH_ALGORITHM_SIG_RSA:
			/* ? */
			break;
		case AUTH_ALGORITHM_AES_128_GMAC:
			needed_len += BYTES_FOR_BITS(128);
			break;
		case AUTH_ALGORITHM_AES_192_GMAC:
			needed_len += BYTES_FOR_BITS(192);
			break;
		case AUTH_ALGORITHM_AES_256_GMAC:
			needed_len += BYTES_FOR_BITS(256);
			break;
		case AH_NULL:
			needed_len += 0; /* presumably? */
			break;
		default:
			if (kernel_alg_esp_auth_ok(pi->attrs.transattrs.
						   integ_hash, NULL)) {
				needed_len += kernel_alg_esp_auth_keylen(
					pi->attrs.transattrs.integ_hash);
				break;
			}
			bad_case(pi->attrs.transattrs.integ_hash);
		}

		DBG(DBG_PARSING, DBG_log("compute_proto_keymat: needed_len (after ESP auth)=%d",
					 (int)needed_len));
		break;

	case PROTO_IPSEC_AH:
		switch (pi->attrs.transattrs.encrypt) {
		case AH_MD5:
			needed_len = HMAC_MD5_KEY_LEN;
			break;
		case AH_SHA:
			needed_len = HMAC_SHA1_KEY_LEN;
			break;
		/* kernel_alg_ah_auth_ok / kernel_alg_ah_auth_keylen are incomplete */
		case AH_SHA2_256:
			needed_len = BYTES_FOR_BITS(256);
			break;
		case AH_SHA2_384:
			needed_len = BYTES_FOR_BITS(384);
			break;
		case AH_SHA2_512:
			needed_len = BYTES_FOR_BITS(512);
			break;
		case AH_RIPEMD:
			needed_len = BYTES_FOR_BITS(160);
			break;
		case AH_AES_XCBC_MAC:
			needed_len = BYTES_FOR_BITS(128);
			break;
		case AH_RSA:
			/* ? */
			break;
		case AH_AES_128_GMAC:
			needed_len = BYTES_FOR_BITS(128);
			break;
		case AH_AES_192_GMAC:
			needed_len = BYTES_FOR_BITS(192);
			break;
		case AH_AES_256_GMAC:
			needed_len = BYTES_FOR_BITS(256);
			break;
		case AH_NULL:
			needed_len = 0; /* presumably? */
			break;

		default:
			if (kernel_alg_ah_auth_ok(
			    pi->attrs.transattrs.integ_hash, NULL)) {
				needed_len += kernel_alg_ah_auth_keylen(
					pi->attrs.transattrs.integ_hash);
				break;
			}
			bad_case(pi->attrs.transattrs.encrypt);
		}
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

		hmac_init(&ctx_me, st->st_oakley.prf_hasher,
				st->st_skeyid_d_nss);
		/* PK11Context * DigestContext makes hmac not allowable for copy */
		hmac_init(&ctx_peer, st->st_oakley.prf_hasher,
				st->st_skeyid_d_nss);
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
			hmac_init(&ctx_me, st->st_oakley.prf_hasher,
					st->st_skeyid_d_nss);
			hmac_init(&ctx_peer, st->st_oakley.prf_hasher,
					st->st_skeyid_d_nss);

			hmac_update(&ctx_me,
				    pi->our_keymat + i - ctx_me.hmac_digest_len,
				    ctx_me.hmac_digest_len);
			hmac_update(&ctx_peer,
				    pi->peer_keymat + i - ctx_peer.hmac_digest_len,
				    ctx_peer.hmac_digest_len);
		}
	}

	DBG(DBG_CRYPT, {
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
		err_t ughmsg = initaddr(id_pbs->cur, pbs_left(
					  id_pbs), afi->af, &temp_address);

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
			 u_int8_t *protoid,
			 u_int16_t *port,
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
		       "%s subnet returned doesn't match my proposal - us:%s vs them:%s",
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
		       "%s peer returned protocol id does not match my proposal - us%d vs them: %d",
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
		       "%s peer returned port doesn't match my proposal - us:%d vs them:%d",
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
	hmac_init(&ctx, st->st_oakley.prf_hasher, st->st_skeyid_a_nss);
	hmac_update(&ctx, (const void *) msgid, sizeof(msgid_t));
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

	hmac_init(&ctx, st->st_oakley.prf_hasher, st->st_skeyid_a_nss);
	hmac_update(&ctx, (const u_char *)"\0", 1);
	hmac_update(&ctx, (u_char *) &st->st_msgid, sizeof(st->st_msgid));
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
	const struct hash_desc *h = st->st_oakley.prf_hasher;
	union hash_ctx ctx;

	DBG_cond_dump(DBG_CRYPT, "last Phase 1 IV:",
		      st->st_ph1_iv, st->st_ph1_iv_len);

	st->st_new_iv_len = h->hash_digest_len;
	passert(st->st_new_iv_len <= sizeof(st->st_new_iv));

	DBG_cond_dump(DBG_CRYPT, "current Phase 1 IV:",
		      st->st_iv, st->st_iv_len);

	h->hash_init(&ctx);
	h->hash_update(&ctx, st->st_ph1_iv, st->st_ph1_iv_len);
	passert(*msgid != 0);
	h->hash_update(&ctx, (const u_char *)msgid, sizeof(*msgid));
	h->hash_final(st->st_new_iv, &ctx);

	DBG_cond_dump(DBG_CRYPT, "computed Phase 2 IV:",
		      st->st_new_iv, st->st_new_iv_len);
}

static stf_status quick_outI1_tail(struct pluto_crypto_req_cont *qke,
				   struct pluto_crypto_req *r,
				   struct state *st);

static crypto_req_cont_func quick_outI1_continue;	/* type assertion */

static void quick_outI1_continue(struct pluto_crypto_req_cont *qke,
				 struct pluto_crypto_req *r)
{
	struct state *const st = state_with_serialno(
		qke->pcrc_serialno);
	stf_status e;

	DBG(DBG_CONTROL,
		DBG_log("quick_outI1_continue for #%lu: calculated ke+nonce, sending I1",
			qke->pcrc_serialno));

	if (qke->pcrc_serialno == SOS_NOBODY) {
		loglog(RC_LOG_SERIOUS,
		       "%s: Request was disconnected from state",
		       __FUNCTION__);
		release_any_md(&qke->pcrc_md);
		return;
	}

	passert(qke->pcrc_serialno == st->st_serialno);	/* transitional */

	DBG(DBG_CONTROLMORE, DBG_log("#%lu %s:%u st->st_calculating = FALSE;", st->st_serialno, __FUNCTION__, __LINE__));
	st->st_calculating = FALSE;

	passert(cur_state == NULL);
	passert(st != NULL);

	set_cur_state(st); /* we must reset before exit */
	unset_suspended(st);
	e = quick_outI1_tail(qke, r, st);

	/*
	 * ??? this boilerplate code looks different from others.
	 * Who frees md?
	 */
	if (e == STF_INTERNAL_ERROR) {
		loglog(RC_LOG_SERIOUS,
		       "%s: quick_outI1_tail() failed with STF_INTERNAL_ERROR",
		       __FUNCTION__);
	}

	reset_globals();
}

stf_status quick_outI1(int whack_sock,
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
	struct state *st = duplicate_state(isakmp_sa);
	char p2alg[256];	/* ??? who knows if this size is reasonable */

	st->st_whack_sock = whack_sock;
	st->st_connection = c;	/* safe: from duplicate_state */
	passert(c != NULL);

	DBG(DBG_CONTROLMORE, DBG_log("#%lu %s:%u st->st_calculating == %s;", st->st_serialno, __FUNCTION__, __LINE__, st->st_calculating ? "TRUE" : "FALSE"));
	if (st->st_calculating)
		return STF_IGNORE;

	set_cur_state(st); /* we must reset before exit */
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
	st->st_state = STATE_UNDEFINED; /* change_state ignores from == to */
	change_state(st, STATE_QUICK_I1);

	insert_state(st); /* needs cookies, connection, and msgid */

	strcpy(p2alg, "defaults");
	if (st->st_connection->alg_info_esp != NULL) {
		alg_info_snprint_phase2(p2alg, sizeof(p2alg),
					(struct alg_info_esp *)st->st_connection->alg_info_esp);
	}

	/* figure out PFS group, if any */

	if (policy & POLICY_PFS ) {
		/*
		 * See if pfs_group has been specified for this conn,
		 * use that group.
		 * if not, fallback to old use-same-as-P1 behaviour
		 */
		if (st->st_connection != NULL)
			st->st_pfs_group = ike_alg_pfsgroup(st->st_connection,
							    st->st_policy);

		/* otherwise, use the same group as during Phase 1:
		 * since no negotiation is possible, we pick one that is
		 * very likely supported.
		 */
		if (st->st_pfs_group == NULL)
			st->st_pfs_group = isakmp_sa->st_oakley.group;
	}

	{
		const char *pfsgroupname = "no-pfs";
		char replacestr[32];

		if ((policy & POLICY_PFS) != LEMPTY)
			pfsgroupname = enum_name(&oakley_group_names,
						 st->st_pfs_group->group);

		replacestr[0] = '\0';
		if (replacing != SOS_NOBODY)
			snprintf(replacestr, sizeof(replacestr), " to replace #%lu",
				 replacing);

		libreswan_log(
			"initiating Quick Mode %s%s {using isakmp#%lu msgid:%08" PRIx32 " proposal=%s pfsgroup=%s}",
			prettypolicy(policy),
			replacestr,
			isakmp_sa->st_serialno, st->st_msgid, p2alg,
			pfsgroupname);
	}


	{
		struct pluto_crypto_req_cont *qke = new_pcrc_repl(
			quick_outI1_continue, "quick_outI1 KE",
			st, NULL, replacing);
		stf_status e;

		if (policy & POLICY_PFS) {
			e = build_ke_and_nonce(qke, st->st_pfs_group,
				     st->st_import);
		} else {
			e = build_nonce(qke, st->st_import);
		}

		reset_globals();

		return e;
	}
}

static stf_status quick_outI1_tail(struct pluto_crypto_req_cont *qke,
				   struct pluto_crypto_req *r,
				   struct state *st)
{
	struct state *isakmp_sa = state_with_serialno(st->st_clonedfrom);
	struct connection *c = st->st_connection;
	pb_stream rbody;
	u_char          /* set by START_HASH_PAYLOAD: */
		*r_hashval,     /* where in reply to jam hash value */
		*r_hash_start;  /* start of what is to be hashed */
	bool has_client = c->spd.this.has_client || c->spd.that.has_client ||
			  c->spd.this.protocol || c->spd.that.protocol ||
			  c->spd.this.port || c->spd.that.port;

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
		struct isakmp_hdr hdr;

		hdr.isa_version = ISAKMP_MAJOR_VERSION << ISA_MAJ_SHIFT |
				  ISAKMP_MINOR_VERSION;
		hdr.isa_np = ISAKMP_NEXT_HASH;
		hdr.isa_xchg = ISAKMP_XCHG_QUICK;
		hdr.isa_msgid = st->st_msgid;
		hdr.isa_flags = ISAKMP_FLAGS_v1_ENCRYPTION;
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
		lset_t pm = POLICY_ENCRYPT | POLICY_AUTHENTICATE;

		if (can_do_IPcomp)
			pm |= POLICY_COMPRESS;

		if (!ikev1_out_sa(&rbody,
			    &ipsec_sadb[(st->st_policy &
					 pm) >> POLICY_IPSEC_SHIFT],
			    st, FALSE, FALSE, ISAKMP_NEXT_NONCE)) {
			reset_cur_state();
			return STF_INTERNAL_ERROR;
		}
	}

	{
		int np;

		if (st->st_policy & POLICY_PFS) {
			np = ISAKMP_NEXT_KE;
		} else {
			if (has_client)
				np = ISAKMP_NEXT_ID;
			else
				np = ISAKMP_NEXT_NONE;
		}

		/* Ni out */
		if (!ikev1_ship_nonce(&st->st_ni, r, &rbody,
				np,
				"Ni")) {
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

	if (!encrypt_message(&rbody, st)) {
		reset_cur_state();
		return STF_INTERNAL_ERROR;
	}

	record_and_send_ike_msg(st, &reply_stream,
		"reply packet from quick_outI1");

	delete_event(st);
	event_schedule_ms(EVENT_v1_RETRANSMIT, c->r_interval, st);

	if (qke->pcrc_replacing == SOS_NOBODY) {
		whack_log(RC_NEW_STATE + STATE_QUICK_I1,
			  "%s: initiate",
			  enum_name(&state_names, st->st_state));
	} else {
		whack_log(RC_NEW_STATE + STATE_QUICK_I1,
			  "%s: initiate to replace #%lu",
			  enum_name(&state_names, st->st_state),
			  qke->pcrc_replacing);
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
 * - quick_inI1_outR1_authtail does the rest of the job
 *   unless DNS must be consulted.  In that case,
 *   it starts a DNS query, salts away what is needed
 *   to continue, and suspends.  Calls
 *   + quick_inI1_outR1_start_query
 *   + quick_inI1_outR1_process_answer
 *
 * - quick_inI1_outR1_continue will restart quick_inI1_outR1_authtail
 *   when DNS comes back with an answer.
 *
 * A big chunk of quick_inI1_outR1_authtail is executed twice.
 * This is necessary because the set of connections
 * might change while we are awaiting DNS.
 * When first called, gateways_from_dns == NULL.  If DNS is
 * consulted asynchronously, gateways_from_dns != NULL the second time.
 * Remember that our state object might disappear too!
 *
 * At the end of authtail, we have all the info we need, but we
 * haven't done any nonce generation or DH that we might need
 * to do, so that are two crypto continuations that do this work,
 * they are:
 *    quick_inI1_outR1_cryptocontinue1 -- called after NONCE/KE
 *    quick_inI1_outR1_cryptocontinue2 -- called after DH (if PFS)
 *
 * we have to call nonce/ke and DH if we are doing PFS.
 *
 *
 * If the connection is opportunistic, we must verify delegation.
 *
 * 1. Check that we are authorized to be SG for
 *    our client.  We look for the TXT record that
 *    delegates us.  We also check that the public
 *    key (if present) matches the private key we used.
 *    Eventually, we should probably require DNSSEC
 *    authentication for our side.
 *
 * 2. If our client TXT record did not include a
 *    public key, check the KEY record indicated
 *    by the identity in the TXT record.
 *
 * 3. If the peer's client is the peer itself, we
 *    consider it authenticated.  Otherwise, we check
 *    the TXT record for the client to see that
 *    the identity of the SG matches the peer and
 *    that some public key (if present in the TXT)
 *    matches.  We need not check the public key if
 *    it isn't in the TXT record.
 *
 * Since p isn't yet instantiated, we need to look
 * in c for description of peer.
 *
 * We cannot afford to block waiting for a DNS query.
 * The code here is structured as two halves:
 * - process the result of just completed
 *   DNS query (if any)
 * - if another query is needed, initiate the next
 *   DNS query and suspend
 */

enum verify_oppo_step {
	vos_fail,
	vos_start,
	vos_our_client,
	vos_our_txt,
#ifdef USE_KEYRR
	vos_our_key,
#endif  /* USE_KEYRR */
	vos_his_client,
	vos_done
};

static const char *const verify_step_name[] = {
	"vos_fail",
	"vos_start",
	"vos_our_client",
	"vos_our_txt",
#ifdef USE_KEYRR
	"vos_our_key",
#endif  /* USE_KEYRR */
	"vos_his_client",
	"vos_done"
};

/* hold anything we can handle of a Phase 2 ID */
struct p2id {
	ip_subnet net;
	u_int8_t proto;
	u_int16_t port;
};

struct verify_oppo_bundle {
	enum verify_oppo_step step;
	bool failure_ok;	/* if true, quick_inI1_outR1_continue will try
				 * other things on DNS failure
				 */
	struct msg_digest *md;
	struct p2id my, his;
	unsigned int new_iv_len; /* p1st's might change */
	u_char new_iv[MAX_DIGEST_LEN];
	/* int whackfd; */	/* not needed because we are Responder */
};

struct verify_oppo_continuation {
	struct adns_continuation ac;    /* common prefix */
	struct verify_oppo_bundle b;
};

static stf_status quick_inI1_outR1_authtail(struct verify_oppo_bundle *b,
					    struct adns_continuation *ac);

stf_status quick_inI1_outR1(struct msg_digest *md)
{
	const struct state *const p1st = md->st;
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
	b.step = vos_start;
	b.md = md;
	save_new_iv(p1st, b.new_iv, b.new_iv_len);

	/*
	 * FIXME - DAVIDM
	 * "b" is on the stack,  for OPPO  tunnels this will be bad, in
	 * quick_inI1_outR1_start_query it saves a pointer to it before
	 * a crypto (async op).
	 */
	return quick_inI1_outR1_authtail(&b, NULL);
}

static void report_verify_failure(struct verify_oppo_bundle *b, err_t ugh)
{
	struct state *st = b->md->st;
	ipstr_buf ib1, ib2;
	ip_address client;
	err_t which;

	switch (b->step) {
	case vos_our_client:
	case vos_our_txt:
#ifdef USE_KEYRR
	case vos_our_key:
#endif          /* USE_KEYRR */
		which = "our";
		networkof(&b->my.net, &client);
		break;

	case vos_his_client:
		which = "his";
		networkof(&b->his.net, &client);
		break;

	case vos_start:
	case vos_done:
	case vos_fail:
	default:
		bad_case(b->step);
	}

	loglog(RC_OPPOFAILURE,
	       "gateway %s wants connection with %s as %s client, but DNS fails to confirm delegation: %s {msgid:%08" PRIx32 "}",
	       ipstr(&st->st_connection->spd.that.host_addr, &ib1),
	       ipstr(&client, &ib2),
	       which, ugh, st->st_msgid);
}

static stf_status quick_inI1_outR1_start_query(struct verify_oppo_bundle *b,
					       enum verify_oppo_step next_step)
{
	struct msg_digest *md = b->md;
	struct state *p1st = md->st;
	struct connection *c = p1st->st_connection;
	struct verify_oppo_continuation *vc =
		alloc_thing(struct verify_oppo_continuation,
			    "verify continuation");
	const struct id *our_id;
	struct id id,           /* subject of query */
		  our_id_space; /* ephemeral: no need for unshare_id_content */
	ip_address client;
	err_t ugh = NULL;

	/* Record that state is used by a suspended md */
	b->step = next_step; /* not just vc->b.step */
	vc->b = *b;
	passert(p1st->st_suspended_md == NULL);
	set_suspended(p1st, b->md);

	DBG(DBG_CONTROL,
	    {
		    char ours[SUBNETTOT_BUF];
		    char his[SUBNETTOT_BUF];

		    subnettot(&c->spd.this.client, 0, ours, sizeof(ours));
		    subnettot(&c->spd.that.client, 0, his, sizeof(his));

		    DBG_log("responding with DNS query - from %s to %s new state: %s",
			    ours, his, verify_step_name[b->step]);
	    });

	/* Resolve %myid in a cheesy way.
	 * We have to do the resolution because start_adns_query
	 * et al have insufficient information to do so.
	 * If %myid is already known, we'll use that value
	 * (XXX this may be a mistake: it could be stale).
	 * If %myid is unknown, we should check to see if
	 * there are credentials for the IP address or the FQDN.
	 * Instead, we'll just assume the IP address since we are
	 * acting as the responder and only the IP address would
	 * have gotten it to us.
	 * We don't even try to do this for the other side:
	 * %myid makes no sense for the other side (but it is syntactically
	 * legal).
	 */
	our_id = resolve_myid(&c->spd.this.id);
	if (our_id->kind == ID_NONE) {
		iptoid(&c->spd.this.host_addr, &our_id_space);
		our_id = &our_id_space;
	}
	/* ??? our_id not subsequently used */

	switch (next_step) {
	case vos_our_client:
		networkof(&b->my.net, &client);
		iptoid(&client, &id);
		vc->b.failure_ok = b->failure_ok = FALSE;
		break;

	case vos_our_txt:
		vc->b.failure_ok = b->failure_ok = TRUE;
		break;

#ifdef USE_KEYRR
	case vos_our_key:
		vc->b.failure_ok = b->failure_ok = FALSE;
		break;
#endif

	case vos_his_client:
		networkof(&b->his.net, &client);
		iptoid(&client, &id);
		vc->b.failure_ok = b->failure_ok = FALSE;
		break;

	default:
		bad_case(next_step);
	}

	if (ugh != NULL) {
		/* note: we'd like to use vc->b but vc has been freed
		 * (it got freed by start_adns_query->release_adns_continuation,
		 *  noting that &vc->ac == vc)
		 * so we have to use b.  This is why we plunked next_state
		 * into b, not just vc->b.
		 */
		report_verify_failure(b, ugh);
		unset_suspended(p1st);
		return STF_FAIL + INVALID_ID_INFORMATION;
	} else {
		return STF_SUSPEND;
	}
}

static enum verify_oppo_step quick_inI1_outR1_process_answer(
	struct verify_oppo_bundle *b,
	struct adns_continuation *ac,
	struct state *p1st)
{
	struct connection *c = p1st->st_connection;
	enum verify_oppo_step next_step;
	err_t ugh = NULL;

	DBG(DBG_CONTROL,
	    {
		    char ours[SUBNETTOT_BUF];
		    char his[SUBNETTOT_BUF];

		    subnettot(&c->spd.this.client, 0, ours, sizeof(ours));
		    subnettot(&c->spd.that.client, 0, his, sizeof(his));
		    DBG_log("responding on demand from %s to %s state: %s",
			    ours, his, verify_step_name[b->step]);
	    });

	/* process just completed DNS query (if any) */
	switch (b->step) {
	case vos_start:
		/* no query to digest */
		next_step = vos_our_client;
		break;

	case vos_our_client:
		next_step = vos_his_client;
		{
			const struct RSA_private_key *pri =
				get_RSA_private_key(c);
			struct gw_info *gwp;

			if (pri == NULL) {
				ugh = "we don't know our own key";
				break;
			}
			ugh = "our client does not delegate us as its Security Gateway";
			for (gwp = ac->gateways_from_dns; gwp != NULL;
			     gwp = gwp->next) {
				ugh = "our client delegates us as its Security Gateway but with the wrong public key";
				/* If there is no key in the TXT record,
				 * we count it as a win, but we will have
				 * to separately fetch and check the KEY record.
				 * If there is a key from the TXT record,
				 * we count it as a win if we match the key.
				 */
				if (!gwp->gw_key_present) {
					next_step = vos_our_txt;
					ugh = NULL; /* good! */
					break;
				} else if (same_RSA_public_key(&pri->pub,
							       &gwp->key->u.rsa))
				{
					ugh = NULL; /* good! */
					break;
				}
			}
		}
		break;

	case vos_our_txt:
		next_step = vos_his_client;
		{
			const struct RSA_private_key *pri =
				get_RSA_private_key(c);

			if (pri == NULL) {
				ugh = "we don't know our own key";
				break;
			}
			{
				struct gw_info *gwp;

				for (gwp = ac->gateways_from_dns; gwp != NULL;
				     gwp = gwp->next) {
#ifdef USE_KEYRR
					/* not an error yet, because we have to check KEY RR as well */
					ugh = NULL;
#else
					ugh = "our client delegation depends on our "
						RRNAME
						" record, but it has the wrong public key";
#endif
					if (gwp->gw_key_present &&
					    same_RSA_public_key(&pri->pub,
								&gwp->key->u.
								rsa)) {
						ugh = NULL; /* good! */
						break;
					}
#ifdef USE_KEYRR
					next_step = vos_our_key;
#endif
				}
			}
		}
		break;

#ifdef USE_KEYRR
	case vos_our_key:
		next_step = vos_his_client;
		{
			const struct RSA_private_key *pri =
				get_RSA_private_key(c);

			if (pri == NULL) {
				ugh = "we don't know our own key";
				break;
			}
			{
				struct pubkey_list *kp;

				ugh = "our client delegation depends on our missing "
					RRNAME " record";
				for (kp = ac->keys_from_dns; kp != NULL;
				     kp = kp->next) {
					ugh = "our client delegation depends on our "
						RRNAME
						" record, but it has the wrong public key";
					if (same_RSA_public_key(&pri->pub,
								&kp->key->u.rsa))
					{
						/* do this only once a day */
						if (!logged_txt_warning) {
							loglog(RC_LOG_SERIOUS,
							       "found KEY RR but not TXT RR.");
							logged_txt_warning =
								TRUE;
						}
						ugh = NULL; /* good! */
						break;
					}
				}
			}
		}
		break;
#endif          /* USE_KEYRR */

	case vos_his_client:
		next_step = vos_done;
		{
			struct gw_info *gwp;

			/* check that the public key that authenticated
			 * the ISAKMP SA (p1st) will do for this gateway.
			 */

			ugh = "peer's client does not delegate to peer";
			for (gwp = ac->gateways_from_dns; gwp != NULL;
			     gwp = gwp->next) {
				ugh = "peer and its client disagree about public key";
				/* If there is a key from the TXT record,
				 * we count it as a win if we match the key.
				 * If there was no key, we claim a match since
				 * it implies fetching a KEY from the same
				 * place we must have gotten it.
				 */
				if (!gwp->gw_key_present ||
				    same_RSA_public_key(&p1st->st_peer_pubkey->
							u.rsa,
							&gwp->key->u.rsa)) {
					ugh = NULL; /* good! */
					break;
				}
			}
		}
		break;

	default:
		bad_case(b->step);
	}

	if (ugh != NULL) {
		report_verify_failure(b, ugh);
		next_step = vos_fail;
	}
	return next_step;
}

/* forward definitions */
static stf_status quick_inI1_outR1_cryptotail(struct msg_digest *md,
					      struct pluto_crypto_req *r);


static crypto_req_cont_func quick_inI1_outR1_cryptocontinue1;	/* type assertion */

static crypto_req_cont_func quick_inI1_outR1_cryptocontinue2;	/* type assertion */

static stf_status quick_inI1_outR1_authtail(struct verify_oppo_bundle *b,
					    struct adns_continuation *ac)
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
				DBG_log("using (something - hopefully the IP we or they are NAT'ed to) for transport mode connection \"%s\"%s",
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
		/* should we use an else here, as we did in lsw 2.5.x? */
		if (p != c) {
			/* We've got a better connection: it can support the
			 * specified clients.  But it may need instantiation.
			 */
			if (p->kind == CK_TEMPLATE) {
				/* Yup, it needs instantiation.  How much?
				 * Is it a Road Warrior connection (simple)
				 * or is it an Opportunistic connection (needing gw validation)?
				 */
				if (p->policy & POLICY_OPPORTUNISTIC) {
					/* Opportunistic case: delegation must be verified.
					 * Here be dragons.
					 */
					enum verify_oppo_step next_step;
					ip_address our_client, his_client;

					passert(subnetishost(our_net) &&
						subnetishost(his_net));
					networkof(our_net, &our_client);
					networkof(his_net, &his_client);

					next_step =
						quick_inI1_outR1_process_answer(
							b, ac,
							p1st);
					if (next_step == vos_fail)
						return STF_FAIL +
						       INVALID_ID_INFORMATION;

					/* short circuit: if peer's client is self,
					 * accept that we've verified delegation in Phase 1
					 */
					if (next_step == vos_his_client &&
					    sameaddr(&c->spd.that.host_addr,
						     &his_client))
						next_step = vos_done;

					/* the second chunk: initiate the next DNS query (if any) */
					DBG(DBG_CONTROL,
					    {
						    char ours[SUBNETTOT_BUF];
						    char his[SUBNETTOT_BUF];

						    subnettot(&c->spd.this.
							      client, 0, ours,
							      sizeof(ours));
						    subnettot(&c->spd.that.
							      client, 0, his,
							      sizeof(his));

						    DBG_log("responding on demand from %s to %s new state: %s",
							    ours, his,
							    verify_step_name[
								    next_step]);
					    });

					/* start next DNS query and suspend (if necessary) */
					if (next_step != vos_done) {
						return quick_inI1_outR1_start_query(
							b,
							next_step);
					}

					/* Instantiate inbound Opportunistic connection,
					 * carrying over authenticated peer ID
					 * and filling in a few more details.
					 * We used to include gateways_from_dns, but that
					 * seems pointless at this stage of negotiation.
					 * We should record DNS sec use, if any -- belongs in
					 * state during perhaps.
					 */
					p = oppo_instantiate(p,
							     &c->spd.that.host_addr, &c->spd.that.id,
							     NULL, &our_client,
							     &his_client);
				} else {
					/* Plain Road Warrior:
					 * instantiate, carrying over authenticated peer ID
					 */
					p = rw_instantiate(p,
							   &c->spd.that.host_addr,
							   his_net,
							   &c->spd.that.id);
				}
			}
			/* temporarily bump up cur_debugging to get "using..." message
			 * printed if we'd want it with new connection.
			 */
			{
				lset_t old_cur_debugging = cur_debugging;

				set_debugging(
					cur_debugging | p->extra_debugging);
				DBG(DBG_CONTROL, {
					char cib[CONN_INST_BUF];
					DBG_log("using connection \"%s\"%s",
						p->name, fmt_conn_instance(p, cib));
				});
				set_debugging(old_cur_debugging);
			}
			c = p;
		}

		/* XXX Though c == p, they are used intermixed in the below section */
		/* fill in the client's true ip address/subnet */
		DBG(DBG_CONTROLMORE,
		    DBG_log("client wildcard: %s  port wildcard: %s  virtual: %s",
			    c->spd.that.has_client_wildcard ? "yes" : "no",
			    c->spd.that.has_port_wildcard  ? "yes" : "no",
			    is_virtual_connection(c) ? "yes" : "no"));

		if (c->spd.that.has_client_wildcard) {
			c->spd.that.client = *his_net;
			c->spd.that.has_client_wildcard = FALSE;
		}

		/* fill in the client's true port */
		if (p->spd.that.has_port_wildcard) {
			int port = htons(b->his.port);

			setportof(port, &p->spd.that.host_addr);
			setportof(port, &p->spd.that.client.addr);

			p->spd.that.port = b->his.port;
			p->spd.that.has_port_wildcard = FALSE;
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

	/* now that we are sure of our connection, create our new state */
	{
		struct state *const st = duplicate_state(p1st);

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
			 * note that we process the copy of the pbs, so that
			 * we can process it again in the cryptotail().
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

		{
			struct pluto_crypto_req_cont *qke = new_pcrc(
				quick_inI1_outR1_cryptocontinue1,
				"quick_outI1 KE",
				st, md);
			stf_status e;
			enum crypto_importance ci;

			/*
			 * ??? this code did NOT have a set_suspended(st, md).
			 * Now that is perfomed by new_pcrc.  Correct?
			 */
			/* ??? can ci calc be absorbed into build*nonce? */
			ci = pcim_ongoing_crypto;
			if (ci < st->st_import)
				ci = st->st_import;

			if (st->st_pfs_group != NULL) {
				e = build_ke_and_nonce(qke,
					st->st_pfs_group, ci);
			} else {
				e = build_nonce(qke, ci);
			}

			passert(st->st_connection != NULL);

			return e;
		}
	}
}

/* redundant type assertion: static crypto_req_cont_func quick_inI1_outR1_cryptocontinue1; */

static void quick_inI1_outR1_cryptocontinue1(
	struct pluto_crypto_req_cont *qke,
	struct pluto_crypto_req *r)
{
	struct msg_digest *md = qke->pcrc_md;
	struct state *const st = state_with_serialno(
		qke->pcrc_serialno);
	stf_status e;

	DBG(DBG_CONTROL,
		DBG_log("quick_inI1_outR1_cryptocontinue1 for #%lu: calculated ke+nonce, calculating DH",
			qke->pcrc_serialno));

	if (qke->pcrc_serialno == SOS_NOBODY) {
		loglog(RC_LOG_SERIOUS,
		       "%s: Request was disconnected from state",
		       __FUNCTION__);
		release_any_md(&qke->pcrc_md);
		return;
	}

	pexpect(st == md->st);	/* ??? why not? */

	passert(qke->pcrc_serialno == st->st_serialno);	/* transitional */

	passert(cur_state == NULL);
	passert(st != NULL);

	passert(st->st_connection != NULL);

	set_cur_state(st); /* we must reset before exit */
	DBG(DBG_CONTROLMORE, DBG_log("#%lu %s:%u st->st_calculating = FALSE;", st->st_serialno, __FUNCTION__, __LINE__));
	st->st_calculating = FALSE;
	unset_suspended(st);

	/* we always calculate a nonce */
	unpack_nonce(&st->st_nr, r);

	if (st->st_pfs_group != NULL) {
		/* PFS is on: do a new DH */
		struct pluto_crypto_req_cont *dh = new_pcrc(
			quick_inI1_outR1_cryptocontinue2,
			"quick outR1 DH",
			st, md);

		unpack_KE_from_helper(st, r, &st->st_gr);

		e = start_dh_secret(dh, st,
				    st->st_import,
				    ORIGINAL_RESPONDER,
				    st->st_pfs_group->group);

		/*
		 * In the STF_INLINE case, quick_inI1_outR1_cryptocontinue2 has
		 * already called complete_v1_state_transition and it has freed
		 * *dh.
		 * It called quick_inI1_outR1_cryptocontinue2 which did the
		 * release_any_md too.
		 *
		 * In the STF_SUSPEND case, we are done for now and must
		 * wait for the computation to finish.  *dh and md ownership
		 * has been transferred.
		 */
		if (e != STF_SUSPEND && e != STF_INLINE) {
			passert(md != NULL);	/* ??? when would this fail? */
			if (dh->pcrc_md != NULL) {
				complete_v1_state_transition(&dh->pcrc_md, e);
				release_any_md(&dh->pcrc_md);
			}
		}
	} else {
		/* but if PFS is off, we don't do a second DH, so just
		 * call the continuation with NULL struct pluto_crypto_req *
		 */
		e = quick_inI1_outR1_cryptotail(md, NULL);
		if (e == STF_OK) {
			passert(md != NULL);	/* ??? when would this fail? */
			if (md != NULL) {
				/* note: use qke-> pointer */
				complete_v1_state_transition(&qke->pcrc_md, e);
				release_any_md(&qke->pcrc_md);
			}
		}
	}
	reset_cur_state();
	/* ??? why does our caller not care about e? */
}

/* redundant type assertion: static crypto_req_cont_func quick_inI1_outR1_cryptocontinue2; */

static void quick_inI1_outR1_cryptocontinue2(
	struct pluto_crypto_req_cont *dh,
	struct pluto_crypto_req *r)
{
	struct msg_digest *md = dh->pcrc_md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROL,
		DBG_log("quick_inI1_outR1_cryptocontinue2 for #%lu: calculated DH, sending R1",
			dh->pcrc_serialno));

	if (dh->pcrc_serialno == SOS_NOBODY) {
		loglog(RC_LOG_SERIOUS,
		       "%s: Request was disconnected from state",
		       __FUNCTION__);
		release_any_md(&dh->pcrc_md);
		return;
	}

	passert(dh->pcrc_serialno == st->st_serialno);	/* transitional */

	passert(cur_state == NULL);
	passert(st != NULL);

	passert(st->st_connection != NULL);

	set_cur_state(st); /* we must reset before exit */
	DBG(DBG_CONTROLMORE, DBG_log("#%lu %s:%u st->st_calculating = FALSE;", st->st_serialno, __FUNCTION__, __LINE__));
	st->st_calculating = FALSE;
	unset_suspended(st);

	e = quick_inI1_outR1_cryptotail(dh->pcrc_md, r);
	passert(e != STF_INLINE);
	if (e == STF_OK) {
		passert(dh->pcrc_md != NULL);
		complete_v1_state_transition(&dh->pcrc_md, e);
		release_any_md(&dh->pcrc_md);
	}

	reset_cur_state();
}

static stf_status quick_inI1_outR1_cryptotail(struct msg_digest *md,
					      struct pluto_crypto_req *r)
{
	struct state *st = md->st;
	struct payload_digest *const id_pd = md->chain[ISAKMP_NEXT_ID];
	struct payload_digest *const sapd = md->chain[ISAKMP_NEXT_SA];
	struct isakmp_sa sa;
	pb_stream r_sa_pbs;
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
	ikev1_echo_hdr(md, TRUE, ISAKMP_NEXT_HASH);

	/* HASH(2) out -- first pass */
	START_HASH_PAYLOAD(md->rbody, ISAKMP_NEXT_SA);

	passert(st->st_connection != NULL);

	zero(&sa);	/* OK: no pointer fields */
	sa.isasa_doi = ISAKMP_DOI_IPSEC;
	sa.isasa_np = ISAKMP_NEXT_NONCE;
	if (!out_struct(&sa, &isakmp_sa_desc, &md->rbody, &r_sa_pbs))
		return STF_INTERNAL_ERROR;

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
		if (!ikev1_justship_nonce(&st->st_nr, &md->rbody, np, "Nr"))
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
					 &isakmp_vendor_id_desc, &md->rbody,
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
				 &md->rbody,
				 id_pd != NULL ?
					ISAKMP_NEXT_ID : ISAKMP_NEXT_NONE))
			return STF_INTERNAL_ERROR;

		finish_dh_secret(st, r);
	}

	/* [ IDci, IDcr ] out */
	if (id_pd != NULL) {
		struct isakmp_ipsec_id *p = (void *)md->rbody.cur; /* UGH! */

		if (!out_raw(id_pd->pbs.start, pbs_room(&id_pd->pbs),
			     &md->rbody, "IDci"))
			return STF_INTERNAL_ERROR;

		p->isaiid_np = ISAKMP_NEXT_ID;

		p = (void *)md->rbody.cur; /* UGH! */

		if (!out_raw(id_pd->next->pbs.start,
			     pbs_room(&id_pd->next->pbs), &md->rbody, "IDcr"))
			return STF_INTERNAL_ERROR;

		p->isaiid_np = ISAKMP_NEXT_NONE;
	}


	/* Compute reply HASH(2) and insert in output */
	(void)quick_mode_hash12(r_hashval, r_hash_start, md->rbody.cur,
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

	if (!encrypt_message(&md->rbody, st)) {
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
static stf_status quick_inR1_outI2_cryptotail(struct msg_digest *md,
					      struct pluto_crypto_req *r);

static crypto_req_cont_func quick_inR1_outI2_continue;	/* type assertion */

stf_status quick_inR1_outI2(struct msg_digest *md)
{
	struct state *const st = md->st;

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
		struct pluto_crypto_req_cont *dh = new_pcrc(
			quick_inR1_outI2_continue, "quick outI2 DH",
			st, md);

		return start_dh_secret(dh, st,
				       st->st_import,
				       ORIGINAL_INITIATOR,
				       st->st_pfs_group->group);
	} else {
		/* just call the tail function */
		return quick_inR1_outI2_cryptotail(md, NULL);
	}
}

/* redundant type assertion: static crypto_req_cont_func quick_inR1_outI2_continue; */

static void quick_inR1_outI2_continue(struct pluto_crypto_req_cont *dh,
				      struct pluto_crypto_req *r)
{
	struct msg_digest *md = dh->pcrc_md;
	struct state *const st = md->st;
	stf_status e;

	DBG(DBG_CONTROL,
		DBG_log("quick_inR1_outI2_continue for #%lu: calculated ke+nonce, calculating DH",
			dh->pcrc_serialno));

	if (dh->pcrc_serialno == SOS_NOBODY) {
		loglog(RC_LOG_SERIOUS,
		       "%s: Request was disconnected from state",
		       __FUNCTION__);
		release_any_md(&dh->pcrc_md);
		return;
	}

	passert(dh->pcrc_serialno == st->st_serialno);	/* transitional */

	passert(cur_state == NULL);
	passert(st != NULL);

	passert(st->st_connection != NULL);

	set_cur_state(st); /* we must reset before exit */
	DBG(DBG_CONTROLMORE, DBG_log("#%lu %s:%u st->st_calculating = FALSE;", st->st_serialno, __FUNCTION__, __LINE__));
	st->st_calculating = FALSE;
	unset_suspended(st);

	e = quick_inR1_outI2_cryptotail(dh->pcrc_md, r);

	passert(dh->pcrc_md != NULL);
	complete_v1_state_transition(&dh->pcrc_md, e);
	release_any_md(&dh->pcrc_md);
	reset_cur_state();
}

stf_status quick_inR1_outI2_cryptotail(struct msg_digest *md,
				       struct pluto_crypto_req *r)
{
	struct state *st = md->st;
	struct connection *c = st->st_connection;

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
				START_HASH_PAYLOAD_NO_R_HASH_START(md->rbody,
								   ISAKMP_NEXT_VID);

				if (!ikev1_out_generic(ISAKMP_NEXT_NONE,
						 &isakmp_vendor_id_desc,
						 &md->rbody, &vid_pbs))
					return STF_INTERNAL_ERROR;

				if (!out_zero(padsize, &vid_pbs, "Filler VID"))
					return STF_INTERNAL_ERROR;

				close_output_pbs(&vid_pbs);
			} else {
				START_HASH_PAYLOAD(md->rbody,
						   ISAKMP_NEXT_NONE);
			}
		}
#else
		START_HASH_PAYLOAD_NO_R_HASH_START(md->rbody,
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

	if (!encrypt_message(&md->rbody, st)) {
		delete_ipsec_sa(st);
		return STF_INTERNAL_ERROR; /* ??? we may be partly committed */
	}

	st->st_connection->newest_ipsec_sa = st->st_serialno;
	log_newest_sa_change("inR1_outI2", st);

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
stf_status quick_inI2(struct msg_digest *md)
{
	struct state *const st = md->st;

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

	st->st_connection->newest_ipsec_sa = st->st_serialno;
	log_newest_sa_change("inI2", st);

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
