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
 * Fixes:
 *	ML: kernel_alg_esp_ok_final() function (make F_STRICT consider enc,auth)
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

#include <libreswan/ipsec_policy.h>

#include "constants.h"
#include "alg_info.h"
#include "kernel_alg.h"
#include "lswlog.h"
#include "lswalloc.h"

/* ALG storage */
struct sadb_alg esp_aalg[K_SADB_AALG_MAX + 1];
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
		break;
	case SADB_EXT_SUPPORTED_ENCRYPT:
		/* ??? should this be a passert? */
		if (alg_id > K_SADB_EALG_MAX)
			return NULL;	/* fail */
		break;
	default:
		/* ??? should this be a passert? */
		return NULL;	/* fail */
	}

	switch (satype) {
	case SADB_SATYPE_AH:
	case SADB_SATYPE_ESP:
		alg_p = (exttype == SADB_EXT_SUPPORTED_ENCRYPT) ?
			&esp_ealg[alg_id] : &esp_aalg[alg_id];

		/* get for write: increment elem count */
		if (rw) {
			if (exttype == SADB_EXT_SUPPORTED_ENCRYPT)
				esp_ealg_num++;
			else
				esp_aalg_num++;
		}
		return alg_p;

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
static void kernel_alg_init(void)
{
	DBG(DBG_KERNEL,
		DBG_log("alg_init(): memset(%p, 0, %d) memset(%p, 0, %d)",
			&esp_aalg,  (int)sizeof(esp_aalg),
			&esp_ealg,  (int)sizeof(esp_ealg));
		);
	zero(&esp_aalg);
	zero(&esp_ealg);
	esp_ealg_num = esp_aalg_num = 0;
}

/* used by kernel_netlink.c and kernel_bsdkame.c */
int kernel_alg_add(int satype, int exttype, const struct sadb_alg *sadb_alg)
{
	struct sadb_alg *alg_p;
	uint8_t alg_id = sadb_alg->sadb_alg_id;

	DBG(DBG_KERNEL,
		DBG_log("kernel_alg_add(): satype=%d, exttype=%d, alg_id=%d(%s)",
			satype, exttype, alg_id,
			enum_name(&esp_transformid_names, alg_id));
		);

	alg_p = sadb_alg_ptr(satype, exttype, alg_id, TRUE);
	if (alg_p == NULL) {
		DBG_log("kernel_alg_add(%d,%d,%d) fails because alg combo is invalid",
			satype, exttype, alg_id);
		return -1;
	}

	/*
	 * DBG(DBG_KERNEL,
	 *	DBG_log("kernel_alg_add(): assign *%p=*%p",
	 *		alg_p, sadb_alg);
	 *	);
	 */

	/* This logic "mimics" KLIPS: first algo implementation will be used */
	if (alg_p->sadb_alg_id != 0) {
		DBG(DBG_KERNEL,
			DBG_log("kernel_alg_add(): discarding already setup satype=%d, exttype=%d, alg_id=%d",
				satype, exttype,
				alg_id);
			);
		return 0;
	}
	*alg_p = *sadb_alg;
	return 1;
}

err_t kernel_alg_esp_enc_ok(int alg_id, unsigned int key_len,
			struct alg_info_esp *alg_info __attribute__((unused)))
{
	err_t ugh = NULL;

	/*
	 * test #1: encrypt algo must be present
	 */
	if (!ESP_EALG_PRESENT(alg_id)) {
		/*
		 * ??? why is this OK?
		 * Perhaps: ugh = "alg not present in system";
		 */
		DBG(DBG_KERNEL,
			DBG_log("kernel_alg_esp_enc_ok(%d,%d): alg not present in system",
				alg_id, key_len);
			);
	} else {
		struct sadb_alg *alg_p = &esp_ealg[alg_id];

		passert(alg_p != NULL);
		if (alg_id == ESP_AES_GCM_8 ||
			alg_id == ESP_AES_GCM_12 ||
			alg_id == ESP_AES_GCM_16) {
			if (key_len != 128 && key_len != 192 &&
				key_len != 256) {
				ugh = builddiag("kernel_alg_db_add() key_len is incorrect: alg_id=%d, key_len=%d, alg_minbits=%d, alg_maxbits=%d",
						alg_id, key_len,
						alg_p->sadb_alg_minbits,
						alg_p->sadb_alg_maxbits);
			}
		}

		/*
		 * test #2: if key_len specified, it must be in range
		 */
		if (ugh == NULL && key_len != 0 &&
			(key_len < alg_p->sadb_alg_minbits ||
				key_len > alg_p->sadb_alg_maxbits)) {

			ugh = builddiag("kernel_alg_db_add() key_len not in range: alg_id=%d, key_len=%d, alg_minbits=%d, alg_maxbits=%d",
					alg_id, key_len,
					alg_p->sadb_alg_minbits,
					alg_p->sadb_alg_maxbits);
		}
		if (ugh != NULL) {
			DBG(DBG_KERNEL,
				DBG_log("kernel_alg_esp_enc_ok(%d,%d): %s alg_id=%d, alg_ivlen=%d, alg_minbits=%d, alg_maxbits=%d, res=%d",
					alg_id, key_len, ugh,
					alg_p->sadb_alg_id,
					alg_p->sadb_alg_ivlen,
					alg_p->sadb_alg_minbits,
					alg_p->sadb_alg_maxbits,
					alg_p->sadb_alg_reserved);
				);
		} else {
			DBG(DBG_KERNEL,
				DBG_log("kernel_alg_esp_enc_ok(%d,%d): OK",
					alg_id, key_len);
				);
		}
	}

	return ugh;
}

/*
 * Load kernel_alg arrays from /proc
 * used in manual mode from klips/utils/spi.c
 */
int kernel_alg_proc_read(void)
{
	int satype;
	int supp_exttype;
	int alg_id, ivlen, minbits, maxbits;
	char name[20];
	struct sadb_alg sadb_alg;
	int ret;
	char buf[128];
	FILE *fp = fopen("/proc/net/pf_key_supported", "r");

	if (!fp)
		return -1;

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
				ret = kernel_alg_add(satype, supp_exttype,
						&sadb_alg);
				DBG(DBG_CRYPT,
					DBG_log("kernel_alg_proc_read() alg_id=%d, alg_ivlen=%d, alg_minbits=%d, alg_maxbits=%d, ret=%d",
						sadb_alg.sadb_alg_id,
						sadb_alg.sadb_alg_ivlen,
						sadb_alg.sadb_alg_minbits,
						sadb_alg.sadb_alg_maxbits,
						ret);
					);
			}
		default:
			continue;
		}
	}
	fclose(fp);
	return 0;
}

/*
 * Load kernel_alg arrays pluto's SADB_REGISTER
 * user by pluto/kernel.c
 */

void kernel_alg_register_pfkey(const struct sadb_msg *msg_buf, int buflen)
{
	/*
	 * Trick: one 'type-mangle-able' pointer to
	 * ease offset/assign
	 */
	union {
		const struct sadb_msg *msg;
		const struct sadb_supported *supported;
		const struct sadb_ext *ext;
		const struct sadb_alg *alg;
		const char *ch;
	} sadb;
	int satype;
	int msglen;
	int i = 0;
	/* Initialize alg arrays   */
	kernel_alg_init();
	satype = msg_buf->sadb_msg_satype;
	sadb.msg = msg_buf;
	msglen = sadb.msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN;
	msglen -= sizeof(struct sadb_msg);
	buflen -= sizeof(struct sadb_msg);
	passert(buflen > 0);
	sadb.msg++;
	while (msglen) {
		int supp_exttype = sadb.supported->sadb_supported_exttype;
		int supp_len;
		supp_len = sadb.supported->sadb_supported_len *
			IPSEC_PFKEYv2_ALIGN;
		DBG(DBG_KERNEL,
			DBG_log("kernel_alg_register_pfkey(): SADB_SATYPE_%s: sadb_msg_len=%d sadb_supported_len=%d",
				satype == SADB_SATYPE_ESP ? "ESP" : "AH",
				msg_buf->sadb_msg_len,
				supp_len);
			);
		sadb.supported++;
		msglen -= supp_len;
		buflen -= supp_len;
		passert(buflen >= 0);
		for (supp_len -= sizeof(struct sadb_supported);
			supp_len;
			supp_len -= sizeof(struct sadb_alg), sadb.alg++, i++) {
			int ret;
			ret = kernel_alg_add(satype, supp_exttype, sadb.alg);
			DBG(DBG_KERNEL,
				DBG_log("kernel_alg_register_pfkey(): SADB_SATYPE_%s: alg[%d], exttype=%d, satype=%d, alg_id=%d, alg_ivlen=%d, alg_minbits=%d, alg_maxbits=%d, res=%d, ret=%d",
					satype == SADB_SATYPE_ESP ? "ESP" :
					"AH", i, supp_exttype, satype,
					sadb.alg->sadb_alg_id,
					sadb.alg->sadb_alg_ivlen,
					sadb.alg->sadb_alg_minbits,
					sadb.alg->sadb_alg_maxbits,
					sadb.alg->sadb_alg_reserved,
					ret);
				);
		}
	}
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

err_t kernel_alg_esp_auth_ok(int auth,
			struct alg_info_esp *alg_info __attribute__((unused)))
{
	int ret = (ESP_AALG_PRESENT(alg_info_esp_aa2sadb(auth)));

	if (ret)
		return NULL;
	else
		return "bad auth alg";
}

int kernel_alg_esp_auth_keylen(int auth)
{
	int sadb_aalg = alg_info_esp_aa2sadb(auth);
	int a_keylen = 0;

	if (sadb_aalg)
		a_keylen = esp_aalg[sadb_aalg].sadb_alg_maxbits /
			BITS_PER_BYTE;

	DBG(DBG_CONTROL | DBG_CRYPT | DBG_PARSING,
		DBG_log("kernel_alg_esp_auth_keylen(auth=%d, sadb_aalg=%d): a_keylen=%d",
			auth, sadb_aalg, a_keylen);
		);
	return a_keylen;
}

err_t kernel_alg_ah_auth_ok(int auth,
			struct alg_info_esp *alg_info __attribute__((unused)))
{
	int ret = (ESP_AALG_PRESENT(alg_info_esp_aa2sadb(auth)));

	if (ret)
		return NULL;
	else
		return "bad auth alg";
}

int kernel_alg_ah_auth_keylen(int auth)
{
	int sadb_aalg = alg_info_esp_aa2sadb(auth);
	int a_keylen = 0;

	if (sadb_aalg)
		a_keylen = esp_aalg[sadb_aalg].sadb_alg_maxbits /
			BITS_PER_BYTE;

	DBG(DBG_CONTROL | DBG_CRYPT | DBG_PARSING,
		DBG_log("kernel_alg_ah_auth_keylen(auth=%d, sadb_aalg=%d): a_keylen=%d",
			auth, sadb_aalg, a_keylen);
		);
	return a_keylen;
}

struct esp_info *kernel_alg_esp_info(u_int8_t transid, u_int16_t keylen,
				u_int16_t auth)
{
	int sadb_aalg, sadb_ealg;
	static struct esp_info ei_buf;

	sadb_ealg = transid;
	sadb_aalg = alg_info_esp_aa2sadb(auth);

	if (!ESP_EALG_PRESENT(sadb_ealg) ||
		!ESP_AALG_PRESENT(sadb_aalg)) {
		DBG(DBG_PARSING,
			DBG_log("kernel_alg_esp_info(): transid=%d, auth=%d, ei=NULL",
				transid, auth);
			);
		return NULL;
	}
	zero(&ei_buf);
	ei_buf.transid = transid;
	ei_buf.auth = auth;

	/*
	 * don't return "default" keylen because this value is used from
	 * setup_half_ipsec_sa() to "validate" keylen
	 * In effect,  enckeylen will be used as "max" value
	 */

	/* if no key length is given, return default */
	if (keylen == 0) {
		ei_buf.enckeylen = esp_ealg[sadb_ealg].sadb_alg_minbits /
			BITS_PER_BYTE;
	} else if (keylen <= esp_ealg[sadb_ealg].sadb_alg_maxbits &&
		keylen >= esp_ealg[sadb_ealg].sadb_alg_minbits) {
		ei_buf.enckeylen = keylen / BITS_PER_BYTE;
	} else {
		DBG(DBG_PARSING,
			DBG_log("kernel_alg_esp_info(): transid=%d, proposed keylen=%u is invalid, not %u<X<%u",
				transid, keylen,
				esp_ealg[sadb_ealg].sadb_alg_maxbits,
				esp_ealg[sadb_ealg].sadb_alg_minbits);
			);
		/* proposed key length is invalid! */
		return NULL;
	}

	ei_buf.authkeylen = esp_aalg[sadb_aalg].sadb_alg_maxbits /
		BITS_PER_BYTE;
	ei_buf.encryptalg = sadb_ealg;
	ei_buf.authalg = sadb_aalg;
	DBG(DBG_PARSING,
		DBG_log("kernel_alg_esp_info(): transid=%d, auth=%d, ei=%p, enckeylen=%d, authkeylen=%d, encryptalg=%d, authalg=%d",
			transid, auth, &ei_buf, (int)ei_buf.enckeylen,
			(int)ei_buf.authkeylen, ei_buf.encryptalg,
			ei_buf.authalg);
		);
	return &ei_buf;
}
