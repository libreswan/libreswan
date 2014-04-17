/*
 * Cryptographic helper function - calculate KE and nonce
 * Copyright (C) 2004 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2009 - 2012 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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
 * This code was developed with the support of IXIA communications.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <signal.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "packet.h"
#include "demux.h"
#include "crypto.h"
#include "rnd.h"
#include "state.h"
#include "pluto_crypt.h"
#include "lswlog.h"
#include "log.h"

#include <nss.h>
#include <nspr.h>
#include <prerror.h>
#include <pk11pub.h>
#include <keyhi.h>
#include "lswconf.h"

/* MUST BE THREAD-SAFE */
void calc_ke(struct pluto_crypto_req *r)
{
	SECKEYDHParams dhp;
	PK11SlotInfo *slot = NULL;
	SECKEYPrivateKey *privk = NULL;
	SECKEYPublicKey   *pubk = NULL;
	struct pcr_kenonce *kn = &r->pcr_d.kn;
	const struct oakley_group_desc *group = lookup_group(kn->oakley_group);
	chunk_t base  = mpz_to_n_autosize(group->generator);
	chunk_t prime = mpz_to_n_autosize(group->modulus);

	DBG(DBG_CRYPT, DBG_dump_chunk("NSS: Value of Prime:\n", prime));
	DBG(DBG_CRYPT, DBG_dump_chunk("NSS: Value of base:\n", base));

	dhp.prime.data = prime.ptr;
	dhp.prime.len = prime.len;
	dhp.base.data = base.ptr;
	dhp.base.len = base.len;

	slot = PK11_GetBestSlot(CKM_DH_PKCS_KEY_PAIR_GEN,
				lsw_return_nss_password_file_info());
	if (slot == NULL)
		loglog(RC_LOG_SERIOUS, "NSS: slot for DH key gen is NULL");
	passert(slot != NULL);

	for (;;) {
		privk = PK11_GenerateKeyPair(slot, CKM_DH_PKCS_KEY_PAIR_GEN,
					     &dhp, &pubk, PR_FALSE, PR_TRUE,
					     lsw_return_nss_password_file_info());
		if (privk == NULL) {
			loglog(RC_LOG_SERIOUS,
			       "NSS: DH private key creation failed (err %d)",
			       PR_GetError());
		}
		passert(privk != NULL);

		if (group->bytes == pubk->u.dh.publicValue.len) {
			DBG(DBG_CRYPT,
			    DBG_log("NSS: generated dh priv and pub keys: %d\n",
				    pubk->u.dh.publicValue.len));
			break;
		} else {
			DBG(DBG_CRYPT,
			    DBG_log("NSS: generating dh priv and pub keys"));

			if (privk != NULL) {
				SECKEY_DestroyPrivateKey(privk);
				privk = NULL;
			}

			if (pubk != NULL) {
				SECKEY_DestroyPublicKey(pubk);
				pubk = NULL;
			}
		}
	}

	kn->secret = privk;
	kn->pubk = pubk;

	ALLOC_WIRE_CHUNK(*kn, gi, pubk->u.dh.publicValue.len);
	{
		unsigned char *gip = WIRE_CHUNK_PTR(*kn, gi);

		memcpy(gip, pubk->u.dh.publicValue.data,
		       pubk->u.dh.publicValue.len);
	}

	DBG(DBG_CRYPT, {
		    DBG_log("NSS: Local DH secret (pointer): %p\n",
			     kn->secret);
		    DBG_dump("NSS: Public DH value sent(computed in NSS):\n",
			     WIRE_CHUNK_PTR(*kn, gi),
			     pubk->u.dh.publicValue.len);
	    });

	DBG(DBG_CRYPT,
	    DBG_log("NSS: Local DH public value (pointer): %p\n",
		    kn->pubk));

	/* clean up after ourselves */

	if (slot != NULL)
		PK11_FreeSlot(slot);

	freeanychunk(prime);
	freeanychunk(base);
}

/* MUST BE THREAD-SAFE */
void calc_nonce(struct pluto_crypto_req *r)
{
	struct pcr_kenonce *kn = &r->pcr_d.kn;

	ALLOC_WIRE_CHUNK(*kn, n, DEFAULT_NONCE_SIZE);
	get_rnd_bytes(WIRE_CHUNK_PTR(*kn, n), DEFAULT_NONCE_SIZE);

	DBG(DBG_CRYPT,
	    DBG_dump("Generated nonce:\n",
		     WIRE_CHUNK_PTR(*kn, n),
		     DEFAULT_NONCE_SIZE));
}

stf_status build_ke(struct pluto_crypto_req_cont *cn,
		    struct state *st,
		    const struct oakley_group_desc *group,
		    enum crypto_importance importance)
{
	struct pluto_crypto_req rd;

	pcr_nonce_init(&rd, pcr_build_kenonce, importance);
	rd.pcr_d.kn.oakley_group = group->group;

	cn->pcrc_serialno = st->st_serialno;
	return send_crypto_helper_request(&rd, cn);
}

stf_status build_nonce(struct pluto_crypto_req_cont *cn,
		       struct state *st,
		       enum crypto_importance importance)
{
	struct pluto_crypto_req rd;

	pcr_nonce_init(&rd, pcr_build_nonce, importance);

	cn->pcrc_serialno = st->st_serialno;
	return send_crypto_helper_request(&rd, cn);
}
