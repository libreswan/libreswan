/*
 * Kernel runtime algorithm handling interface
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
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
 * Fixes by:
 *	ML: Mathieu Lafon <mlafon@arkoon.net>
 *
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/queue.h>

#include <libreswan.h>

#include <libreswan/pfkeyv2.h>
#include <libreswan/pfkey.h>

#include "constants.h"
#include "alg_info.h"
#include "kernel_alg.h"
#include "lswlog.h"
#include "lswalloc.h"
#include "ike_alg.h"
#include "ietf_constants.h"

/* ALG storage */
struct sadb_alg esp_aalg[K_SADB_AALG_MAX + 1];	/* ??? who fills this table in? */
struct sadb_alg esp_ealg[K_SADB_EALG_MAX + 1];
int esp_ealg_num = 0;
int esp_aalg_num = 0;

static struct sadb_alg *sadb_alg_ptr(unsigned satype, unsigned exttype,
				unsigned alg_id, bool rw)
{
	struct sadb_alg *alg_p = NULL;

	switch (exttype) {
	case SADB_EXT_SUPPORTED_AUTH:
		/* ??? should this be a passert? */
		if (alg_id > SADB_AALG_MAX)
			return NULL;	/* fail */

		switch (satype) {
		case SADB_SATYPE_AH:
		case SADB_SATYPE_ESP:
			/* ??? even though this might be AH, we only talk of ESP */
			alg_p = &esp_aalg[alg_id];

			/* get for write: increment elem count */
			if (rw)
				esp_aalg_num++;
			return alg_p;

		default:
			/* ??? should this be a passert? */
			return NULL;	/* fail */
		}

	case SADB_EXT_SUPPORTED_ENCRYPT:
		/* ??? should this be a passert? */
		if (alg_id > K_SADB_EALG_MAX)
			return NULL;	/* fail */

		switch (satype) {
		case SADB_SATYPE_ESP:
			alg_p = &esp_ealg[alg_id];

			/* get for write: increment elem count */
			if (rw)
				esp_ealg_num++;
			return alg_p;

		default:
			/* ??? should this be a passert? */
			return NULL;	/* fail */
		}
		break;

	default:
		/* ??? should this be a passert? */
		return NULL;	/* fail */
	}
}

const struct sadb_alg *kernel_alg_sadb_alg_get(unsigned satype,
					unsigned exttype, unsigned alg_id)
{
	return sadb_alg_ptr(satype, exttype, alg_id, FALSE);
}
/*
 *      Forget previous registration
 */
void kernel_alg_init(void)
{
	DBG(DBG_KERNEL, DBG_log("kernel_alg_init()"));
	/* ??? do these zero calls do anything useful? */
	zero(&esp_aalg);
	zero(&esp_ealg);
	esp_ealg_num = esp_aalg_num = 0;
}

/* used by kernel_netlink.c and kernel_bsdkame.c */
int kernel_alg_add(int satype, int exttype, const struct sadb_alg *sadb_alg)
{
	struct sadb_alg *alg_p, tmp_alg;
	uint8_t alg_id = sadb_alg->sadb_alg_id;

	if (DBGP(DBG_KERNEL|DBG_CRYPT)) {
		const char *exttype_name =
			exttype == SADB_EXT_SUPPORTED_AUTH ? "SADB_EXT_SUPPORTED_AUTH"
			: exttype == SADB_EXT_SUPPORTED_ENCRYPT ? "SADB_EXT_SUPPORTED_ENCRYPT"
			: "SADB_EXT_SUPPORTED_???";
		struct esb_buf alg_name_buf;
		/*
		 * XXX: The ALG_ID value found here comes from the
		 * Linux kernel (see libreswan/pfkeyv2.h) so using
		 * AH_TRANSFORMID_NAMES and ESP_TRANSFORMID_NAMES is
		 * only an approximation.
		 */
		const char *alg_name =
			exttype == SADB_EXT_SUPPORTED_AUTH ? enum_showb(&ah_transformid_names, alg_id, &alg_name_buf)
			: exttype == SADB_EXT_SUPPORTED_ENCRYPT ? enum_showb(&esp_transformid_names, alg_id, &alg_name_buf)
			: "???";
		const char *satype_name =
			satype == SADB_SATYPE_ESP ? "SADB_SATYPE_ESP"
			: satype == SADB_SATYPE_AH ? "SADB_SATYPE_AH"
			: "SADB_SATYPE_???";
		DBG_log("kernel_alg_add(): satype=%d(%s), exttype=%d(%s), alg_id=%d(%s), alg_ivlen=%d, alg_minbits=%d, alg_maxbits=%d",
			satype, satype_name,
			exttype, exttype_name,
			alg_id, alg_name,
			sadb_alg->sadb_alg_ivlen,
			sadb_alg->sadb_alg_minbits,
			sadb_alg->sadb_alg_maxbits);
	}
	alg_p = sadb_alg_ptr(satype, exttype, alg_id, TRUE);
	if (alg_p == NULL) {
		DBG(DBG_KERNEL,
			DBG_log("kernel_alg_add(%d,%d,%d) fails because alg combo is invalid",
			satype, exttype, alg_id));
		return -1;
	}

	/* This logic "mimics" KLIPS: first algo implementation will be used */
	if (alg_p->sadb_alg_id != 0) {
		DBG(DBG_KERNEL,
			DBG_log("kernel_alg_add(): discarding already setup satype=%d, exttype=%d, alg_id=%d",
				satype, exttype,
				alg_id);
			);
		return 0;
	}
	/*
	 * The kernel PFKEY interface gives us options we do not want to
	 * support. The kernel allows ESP_CAST with variable keysizes, and
	 * we only want to support 128bit. The kernel also allows ESP_BLOWFISH,
	 * but its inventor Bruce Schneier has said to stop using blowfish
	 * and use twofish instead. The kernel allows ESP_DES, which
	 * is simply too weak to be allowed. And for ESP_AES_CTR it returns
	 * the keysize including the 4 bytes of nonce.
	 */
	tmp_alg = *sadb_alg;
	switch (exttype) {
	case SADB_EXT_SUPPORTED_ENCRYPT:
		switch (satype) {
		case SADB_SATYPE_ESP:
			switch (alg_id) {
			case ESP_CAST:
				/* Overruling kernel - we only want to support 128 */
				tmp_alg.sadb_alg_minbits = 128;
				tmp_alg.sadb_alg_maxbits = 128;
				break;
			case ESP_AES_CTR:
				/* Overruling kernel - remove salt from calculation */
				tmp_alg.sadb_alg_minbits = 128;
				tmp_alg.sadb_alg_maxbits = 256;
				break;
			case ESP_BLOWFISH:
			case ESP_DES:
				DBG(DBG_KERNEL,
					DBG_log("kernel_alg_add(): Ignoring alg_id=%d(%s) - too weak",
						alg_id,
						enum_name(&esp_transformid_names,
							alg_id)));
				return 0;
			}
			break;
		}
		break;
	}

	*alg_p = tmp_alg;
	return 1;
}

static struct kernel_integ *kernel_integ;

void kernel_integ_add(enum sadb_aalg sadb_aalg,
		      const struct integ_desc *integ,
		      const char *netlink_name)
{
	struct sadb_alg alg = {
		.sadb_alg_minbits = integ->integ_keymat_size * BITS_PER_BYTE,
		.sadb_alg_maxbits = integ->integ_keymat_size * BITS_PER_BYTE,
		.sadb_alg_id = sadb_aalg,
	};
	if (kernel_alg_add(SADB_SATYPE_ESP,  SADB_EXT_SUPPORTED_AUTH, &alg) != 1) {
		loglog(RC_LOG_SERIOUS, "Warning: failed to register %s for ESP",
		       integ->common.name);
		return;
	}
	struct kernel_integ *new = alloc_thing(struct kernel_integ, "kernel integ");
	*new = (struct kernel_integ) {
		.sadb_aalg = sadb_aalg,
		.integ = integ,
		.netlink_name = netlink_name,
		.next = kernel_integ,
	};
	kernel_integ = new;
}

const struct kernel_integ *kernel_integ_by_sadb_aalg(enum sadb_aalg sadb_aalg)
{
	for (struct kernel_integ *k = kernel_integ; k != NULL; k = k->next) {
		if (k->sadb_aalg == sadb_aalg) {
			return k;
		}
	}
	return NULL;
}

const struct kernel_integ *kernel_integ_by_ikev1_auth_attribute(enum ikev1_auth_attribute id)
{
	for (struct kernel_integ *k = kernel_integ; k != NULL; k = k->next) {
		/*
		 * For integ, the ESP_ID contains enum
		 * ikev1_auth_attribute
		 */
		if ((enum ikev1_auth_attribute) k->integ->common.ikev1_esp_id == id) {
			return k;
		}
	}
	return NULL;
}

err_t check_kernel_encrypt_alg(int alg_id, unsigned int key_len)
{
	err_t ugh = NULL;

	/*
	 * test #1: encrypt algo must be present
	 */

	if (!ESP_EALG_PRESENT(alg_id)) {
		DBG(DBG_KERNEL,
			DBG_log("check_kernel_encrypt_alg(%d,%d): alg not present in system",
				alg_id, key_len);
			);
		ugh = "encryption alg not present in kernel";
	} else {
		struct sadb_alg *alg_p = &esp_ealg[alg_id];

		passert(alg_p != NULL);
		switch (alg_id) {
		case ESP_AES_GCM_8:
		case ESP_AES_GCM_12:
		case ESP_AES_GCM_16:
		case ESP_AES_CCM_8:
		case ESP_AES_CCM_12:
		case ESP_AES_CCM_16:
		case ESP_AES_CTR:
		case ESP_CAMELLIA:
			/* ??? does 0 make sense here? */
			if (key_len != 0 && key_len != 128 &&
			    key_len != 192 && key_len != 256) {
				/* ??? function name does not belong in log */
				ugh = builddiag("kernel_alg_db_add() key_len is incorrect: alg_id=%d, key_len=%d, alg_minbits=%d, alg_maxbits=%d",
						alg_id, key_len,
						alg_p->sadb_alg_minbits,
						alg_p->sadb_alg_maxbits);
			}
			break;
#if 0
		case ESP_SEED_CBC:
#endif
		case ESP_CAST:
			if (key_len != 128) {
				/* ??? function name does not belong in log */
				ugh = builddiag("kernel_alg_db_add() key_len is incorrect: alg_id=%d, key_len=%d, alg_minbits=%d, alg_maxbits=%d",
						alg_id, key_len,
						alg_p->sadb_alg_minbits,
						alg_p->sadb_alg_maxbits);
			}
			break;
		default:
			/* old behaviour - not necc. correct */
			if (key_len != 0 &&
			    (key_len < alg_p->sadb_alg_minbits ||
			     key_len > alg_p->sadb_alg_maxbits)) {
				/* ??? function name does not belong in log */
				ugh = builddiag("kernel_alg_db_add() key_len not in range: alg_id=%d, key_len=%d, alg_minbits=%d, alg_maxbits=%d",
					alg_id, key_len,
					alg_p->sadb_alg_minbits,
					alg_p->sadb_alg_maxbits);
			}
		}

		if (ugh != NULL) {
			DBG(DBG_KERNEL,
				DBG_log("check_kernel_encrypt_alg(%d,%d): %s alg_id=%d, alg_ivlen=%d, alg_minbits=%d, alg_maxbits=%d, res=%d",
					alg_id, key_len, ugh,
					alg_p->sadb_alg_id,
					alg_p->sadb_alg_ivlen,
					alg_p->sadb_alg_minbits,
					alg_p->sadb_alg_maxbits,
					alg_p->sadb_alg_reserved);
				);
		} else {
			DBG(DBG_KERNEL,
				DBG_log("check_kernel_encrypt_alg(%d,%d): OK",
					alg_id, key_len);
				);
		}
	}

	return ugh;
}

/*
 * Load kernel_alg arrays from /proc
 * Only used in manual mode from programs/spi/spi.c
 */
bool kernel_alg_proc_read(void)
{
	int satype;
	int supp_exttype;
	int alg_id, ivlen, minbits, maxbits;
	char name[20];
	struct sadb_alg sadb_alg;
	char buf[128];
	FILE *fp = fopen("/proc/net/pf_key_supported", "r");

	if (fp == NULL)
		return FALSE;

	kernel_alg_init();
	while (fgets(buf, sizeof(buf), fp)) {
		if (buf[0] != ' ')	/* skip titles */
			continue;
		sscanf(buf, "%d %d %d %d %d %d %s",
			&satype, &supp_exttype,
			&alg_id, &ivlen,
			&minbits, &maxbits, name);
		switch (satype) {
		case SADB_SATYPE_ESP:
			switch (supp_exttype) {
			case SADB_EXT_SUPPORTED_AUTH:
			case SADB_EXT_SUPPORTED_ENCRYPT:
				sadb_alg.sadb_alg_id = alg_id;
				sadb_alg.sadb_alg_ivlen = ivlen;
				sadb_alg.sadb_alg_minbits = minbits;
				sadb_alg.sadb_alg_maxbits = maxbits;
				sadb_alg.sadb_alg_reserved = 0;
				kernel_alg_add(satype, supp_exttype,
					       &sadb_alg);
				break;
			}
			break;
		default:
			break;
		}
	}
	fclose(fp);
	return TRUE;
}

/*
 * Load kernel_alg arrays pluto's SADB_REGISTER
 * Used by programs/pluto/kernel_pfkey.c and programs/pluto/kernel_netlink.c
 */
void kernel_alg_register_pfkey(const struct sadb_msg *msg)
{
	const void *p;	/* cursor through message */
	uint8_t satype;
	size_t msg_left;

	satype = msg->sadb_msg_satype;
	msg_left = msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN;
	passert(PFKEYv2_MAX_MSGSIZE >= msg_left);
	p = msg + 1;	/* after header */
	msg_left -= sizeof(struct sadb_msg);
	while (msg_left >= sizeof(struct sadb_supported)) {
		const struct sadb_supported *supp = p;
		uint16_t supp_exttype = supp->sadb_supported_exttype;
		size_t supp_len = supp->sadb_supported_len *
			IPSEC_PFKEYv2_ALIGN;

		DBG(DBG_KERNEL,
			DBG_log("kernel_alg_register_pfkey(): SADB_SATYPE_%s: sadb_msg_len=%u sadb_supported_len=%zd",
				satype == SADB_SATYPE_ESP ? "ESP" :
					satype == SADB_SATYPE_AH ? "AH" : "???",
				msg->sadb_msg_len,
				supp_len);
			);
		passert(supp_len >= sizeof(struct sadb_supported));
		passert(msg_left >= supp_len);
		p = supp + 1;	/* after header */
		msg_left -= supp_len;
		for (supp_len -= sizeof(struct sadb_supported);
		     supp_len >= sizeof(struct sadb_alg);
		     supp_len -= sizeof(struct sadb_alg)) {
			const struct sadb_alg *alg = p;
			kernel_alg_add(satype, supp_exttype, alg);
			p = alg + 1;	/* after alg */
		}
		passert(supp_len == 0);
	}
	passert(msg_left == 0);
}

int kernel_alg_esp_enc_max_keylen(int alg_id)
{
	int keylen = 0;

	if (!ESP_EALG_PRESENT(alg_id)) {
		DBG(DBG_KERNEL,
			DBG_log("kernel_alg_esp_enc_max_keylen(): alg_id=%d not found",
				alg_id);
			);
		return 0;
	}

	keylen = esp_ealg[alg_id].sadb_alg_maxbits / BITS_PER_BYTE;
	DBG(DBG_KERNEL,
		DBG_log("kernel_alg_esp_enc_max_keylen(): alg_id=%d, keylen=%d",
			alg_id, keylen);
		);
	return keylen;
}

struct sadb_alg *kernel_alg_esp_sadb_alg(int alg_id)
{
	struct sadb_alg *sadb_alg = NULL;

	if (ESP_EALG_PRESENT(alg_id))
		sadb_alg = &esp_ealg[alg_id];

	DBG(DBG_KERNEL,
		DBG_log("kernel_alg_esp_sadb_alg(): alg_id=%d, sadb_alg=%p",
			alg_id, sadb_alg);
		);
	return sadb_alg;
}

bool kernel_alg_is_ok(const struct ike_alg *alg)
{
	if (alg->algo_type == &ike_alg_dh) {
		/* require an in-process/ike implementation of DH */
		return ike_alg_is_ike(alg);
	} else {
		/* ask the kernel? */
		return TRUE;
	}
}

/* ??? identical to kernel_alg_ah_auth_ok */
bool kernel_alg_esp_auth_ok(int auth,
			struct alg_info_esp *alg_info __attribute__((unused)))
{
	return ESP_AALG_PRESENT(alg_info_esp_aa2sadb(auth));
}

/* ??? pretty similar to kernel_alg_ah_auth_keylen */
int kernel_alg_esp_auth_keylen(int auth)
{
	int sadb_aalg = alg_info_esp_aa2sadb(auth);
	int a_keylen = 0;

	if (sadb_aalg != 0)
		a_keylen = esp_aalg[sadb_aalg].sadb_alg_maxbits /
			BITS_PER_BYTE;

	DBG(DBG_CONTROL | DBG_CRYPT | DBG_PARSING,
		DBG_log("kernel_alg_esp_auth_keylen(auth=%d, sadb_aalg=%d): a_keylen=%d",
			auth, sadb_aalg, a_keylen);
		);
	return a_keylen;
}

/* ??? identical to kernel_alg_esp_auth_ok */
bool kernel_alg_ah_auth_ok(int auth,
			struct alg_info_esp *alg_info __attribute__((unused)))
{
	return ESP_AALG_PRESENT(alg_info_esp_aa2sadb(auth));
}

/* ??? pretty similar to kernel_alg_esp_auth_keylen */
int kernel_alg_ah_auth_keylen(int auth)
{
	int sadb_aalg = alg_info_esp_aa2sadb(auth);
	int a_keylen = 0;

	if (sadb_aalg != 0)
		a_keylen = esp_aalg[sadb_aalg].sadb_alg_maxbits /
			BITS_PER_BYTE;

	DBG(DBG_CONTROL | DBG_CRYPT | DBG_PARSING,
		DBG_log("kernel_alg_ah_auth_keylen(auth=%d, sadb_aalg=%d): a_keylen=%d",
			auth, sadb_aalg, a_keylen);
		);
	return a_keylen;
}

bool kernel_alg_info(u_int8_t transid, u_int16_t keylen, u_int16_t auth,
		     struct kernel_alg_info *ki)
{
	int sadb_aalg, sadb_ealg;
	zero(ki);

	DBG(DBG_PARSING,
		DBG_log("kernel_alg_esp_info(): transid=%d, keylen=%d,auth=%d, ",
			transid, keylen, auth));
	sadb_ealg = transid;
	sadb_aalg = alg_info_esp_aa2sadb(auth);

	if (!ESP_EALG_PRESENT(sadb_ealg) ||
		!ESP_AALG_PRESENT(sadb_aalg)) {
		DBG(DBG_PARSING,
			DBG_log("kernel_alg_esp_info(): transid or auth not registered with kernel"));
		return FALSE;
	}
	ki->transid = transid;
	ki->auth = auth;

	/*
	 * don't return "default" keylen because this value is used from
	 * setup_half_ipsec_sa() to "validate" keylen
	 * In effect,  enckeylen will be used as "max" value
	 */

	/* if no key length is given, return default */
	if (keylen == 0) {
		ki->enckeysize = esp_ealg[sadb_ealg].sadb_alg_minbits /
			BITS_PER_BYTE;
	} else if (esp_ealg[sadb_ealg].sadb_alg_minbits <= keylen &&
		keylen <= esp_ealg[sadb_ealg].sadb_alg_maxbits) {
		ki->enckeysize = keylen / BITS_PER_BYTE;
	} else {
		DBG(DBG_PARSING,
			DBG_log("kernel_alg_esp_info(): transid=%d, proposed keylen=%u is invalid, not %u<=X<=%u",
				transid, keylen,
				esp_ealg[sadb_ealg].sadb_alg_minbits,
				esp_ealg[sadb_ealg].sadb_alg_maxbits);
			);
		/* proposed key length is invalid! */
		return FALSE;
	}

	ki->encryptalg = sadb_ealg;
	ki->authalg = sadb_aalg;
	DBG(DBG_PARSING,
		DBG_log("kernel_alg_esp_info(): transid=%d, auth=%d, enckeysize=%d, encryptalg=%d, authalg=%d",
			transid, auth, (int)ki->enckeysize,
			ki->encryptalg,
			ki->authalg);
		);
	return TRUE;
}

/*
 * sadb/ESP aa attrib converters - conflicting for v1 and v2
 */
enum ipsec_authentication_algo alg_info_esp_aa2sadb(
	enum ikev1_auth_attribute auth)
{
	/* ??? this switch looks a lot like one in parse_ipsec_sa_body */
	switch (auth) {
	case AUTH_ALGORITHM_HMAC_MD5: /* 2 */
		return AH_MD5;

	case AUTH_ALGORITHM_HMAC_SHA1:
		return AH_SHA;

	case AUTH_ALGORITHM_HMAC_SHA2_256: /* 5 */
		return AH_SHA2_256;

	case AUTH_ALGORITHM_HMAC_SHA2_384:
		return AH_SHA2_384;

	case AUTH_ALGORITHM_HMAC_SHA2_512:
		return AH_SHA2_512;

	case AUTH_ALGORITHM_HMAC_RIPEMD:
		return AH_RIPEMD;

	case AUTH_ALGORITHM_AES_XCBC: /* 9 */
		return AH_AES_XCBC_MAC;

	/* AH_RSA not supported */
	case AUTH_ALGORITHM_SIG_RSA:
		return AH_RSA;

	case AUTH_ALGORITHM_AES_128_GMAC:
		return AH_AES_128_GMAC;

	case AUTH_ALGORITHM_AES_192_GMAC:
		return AH_AES_192_GMAC;

	case AUTH_ALGORITHM_AES_256_GMAC:
		return AH_AES_256_GMAC;

	case AUTH_ALGORITHM_AES_CMAC_96: /* private use 250 */
		return AH_AES_CMAC_96;

	case AUTH_ALGORITHM_NULL_KAME:
	case AUTH_ALGORITHM_NONE: /* private use 251 */
		return AH_NONE;

	default:
		bad_case(auth);
	}
}

/*
 * XXX This maps IPSEC AH Transform Identifiers to IKE Integrity Algorithm
 * Transform IDs. But IKEv1 and IKEv2 tables don't match fully! See:
 *
 * http://www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml#ikev2-parameters-7
 * http://www.iana.org/assignments/isakmp-registry/isakmp-registry.xhtml#isakmp-registry-7
 * http://www.iana.org/assignments/ipsec-registry/ipsec-registry.xhtml#ipsec-registry-6
 *
 * Callers of this function should get fixed
 */
int alg_info_esp_sadb2aa(int sadb_aalg)
{
	int auth = 0;

	/* md5 and sha1 entries are "off by one" */
	switch (sadb_aalg) {
	/* 0-1 RESERVED */
	case SADB_AALG_MD5HMAC: /* 2 */
		auth = AUTH_ALGORITHM_HMAC_MD5; /* 1 */
		break;
	case SADB_AALG_SHA1HMAC: /* 3 */
		auth = AUTH_ALGORITHM_HMAC_SHA1; /* 2 */
		break;
	/* 4 - SADB_AALG_DES */
	case SADB_X_AALG_SHA2_256HMAC:
		auth = AUTH_ALGORITHM_HMAC_SHA2_256;
		break;
	case SADB_X_AALG_SHA2_384HMAC:
		auth = AUTH_ALGORITHM_HMAC_SHA2_384;
		break;
	case SADB_X_AALG_SHA2_512HMAC:
		auth = AUTH_ALGORITHM_HMAC_SHA2_512;
		break;
	case SADB_X_AALG_RIPEMD160HMAC:
		auth = AUTH_ALGORITHM_HMAC_RIPEMD;
		break;
	case SADB_X_AALG_AES_XCBC_MAC:
		auth = AUTH_ALGORITHM_AES_XCBC;
		break;
	case SADB_X_AALG_RSA: /* unsupported by us */
		auth = AUTH_ALGORITHM_SIG_RSA;
		break;
	case SADB_X_AALG_AH_AES_128_GMAC:
		auth = AUTH_ALGORITHM_AES_128_GMAC;
		break;
	case SADB_X_AALG_AH_AES_192_GMAC:
		auth = AUTH_ALGORITHM_AES_192_GMAC;
		break;
	case SADB_X_AALG_AH_AES_256_GMAC:
		auth = AUTH_ALGORITHM_AES_256_GMAC;
		break;
	/* private use numbers */
	case SADB_X_AALG_AES_CMAC_96:
		auth = AUTH_ALGORITHM_AES_CMAC_96;
		break;
	case SADB_X_AALG_NULL:
		auth = AUTH_ALGORITHM_NULL_KAME;
		break;
	default:
		/* which would hopefully be true  */
		auth = sadb_aalg;
	}
	return auth;
}
