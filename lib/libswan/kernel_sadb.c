/* SADB algorithm handling, for libreswan
 *
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
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
 * Fixes by:
 *	ML: Mathieu Lafon <mlafon@arkoon.net>
 *
 */

#include <stdlib.h>

#include "lswlog.h"
#include "kernel_sadb.h"
#include "kernel_alg.h"
#include "ike_alg.h"

/* used by kernel_netlink.c and kernel_bsdkame.c */
void kernel_add_sadb_alg(int satype, int exttype, const struct sadb_alg *sadb_alg)
{
	uint8_t alg_id = sadb_alg->sadb_alg_id;

	const struct encrypt_desc *encrypt = NULL;
	const struct integ_desc *integ = NULL;
	bool combo_ok = false;
	switch (exttype) {
	case SADB_EXT_SUPPORTED_ENCRYPT:
		switch (satype) {
		case SADB_SATYPE_ESP:
			encrypt = encrypt_desc_by_sadb_ealg_id(alg_id);
			combo_ok = true;
			break;
		}
		break;
	case SADB_EXT_SUPPORTED_AUTH:
		switch (satype) {
		case SADB_SATYPE_ESP:
		case SADB_SATYPE_AH:
			integ = integ_desc_by_sadb_aalg_id(alg_id);
			combo_ok = true;
			break;
		}
		break;
	}

	LSWDBGP(DBG_KERNEL|DBG_CRYPT, buf) {
		lswlogs(buf, __func__);
		lswlogs(buf, ":");
		lswlogf(buf, " satype=%d(%s)", satype,
			satype == SADB_SATYPE_ESP ? "SADB_SATYPE_ESP"
			: satype == SADB_SATYPE_AH ? "SADB_SATYPE_AH"
			: "SADB_SATYPE_???");
		lswlogf(buf, " exttype=%d(%s)", exttype,
			exttype == SADB_EXT_SUPPORTED_AUTH ? "SADB_EXT_SUPPORTED_AUTH"
			: exttype == SADB_EXT_SUPPORTED_ENCRYPT ? "SADB_EXT_SUPPORTED_ENCRYPT"
			: "SADB_EXT_SUPPORTED_???");
		DBG_log(" alg_id=%d(%s)", alg_id,
			integ != NULL ? integ->common.fqn
			: encrypt != NULL ? encrypt->common.fqn
			: "???");
		lswlogf(buf, " alg_ivlen=%d, alg_minbits=%d, alg_maxbits=%d",
			sadb_alg->sadb_alg_ivlen,
			sadb_alg->sadb_alg_minbits,
			sadb_alg->sadb_alg_maxbits);
		if (integ == NULL && encrypt == NULL) {
			lswlogs(buf, ", not supported");
		}
		if (!combo_ok) {
			lswlogs(buf, ", invalid combo");
		}
	}

	if (encrypt != NULL) {
		kernel_encrypt_add(encrypt);
	}
	if (integ != NULL) {
		kernel_integ_add(integ);
	}
}

/*
 * Load kernel_alg arrays pluto's SADB_REGISTER
 * Used by programs/pluto/kernel_pfkey.c and programs/pluto/kernel_netlink.c
 */

void kernel_add_sadb_algs(const struct sadb_msg *const msg, size_t sizeof_msg)
{
	uint8_t satype = msg->sadb_msg_satype;
	size_t msg_size = msg->sadb_msg_len * KERNEL_SADB_WORD_SIZE;
	passert(msg_size <= sizeof_msg);

	const void *p = msg + 1;	/* cursor through message: start after header */
	size_t msg_left = msg_size - sizeof(struct sadb_msg);
	while (msg_left >= sizeof(struct sadb_supported)) {
		const struct sadb_supported *supp = p;
		uint16_t supp_exttype = supp->sadb_supported_exttype;
		size_t supp_size = supp->sadb_supported_len * KERNEL_SADB_WORD_SIZE;

		DBGF(DBG_KERNEL, "kernel_alg_register_pfkey(): SADB_SATYPE_%s: sadb_msg_len=%u sadb_supported_len=%zd",
		     (satype == SADB_SATYPE_ESP ? "ESP" :
		      satype == SADB_SATYPE_AH ? "AH" : "???"),
		     msg->sadb_msg_len,
		     supp_size);
		passert(supp_size >= sizeof(struct sadb_supported));
		passert(msg_left >= supp_size);
		p = supp + 1;	/* after header */
		msg_left -= supp_size;
		for (supp_size -= sizeof(struct sadb_supported);
		     supp_size >= sizeof(struct sadb_alg);
		     supp_size -= sizeof(struct sadb_alg)) {
			const struct sadb_alg *alg = p;
			kernel_add_sadb_alg(satype, supp_exttype, alg);
			p = alg + 1;	/* after alg */
		}
		passert(supp_size == 0);
	}
	passert(msg_left == 0);
}
