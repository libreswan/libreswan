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
 * Modifications to use OCF interface written by
 * Daniel Djamaludin <danield@cyberguard.com>
 * Copyright (C) 2004-2005 Intel Corporation.
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
#include <libreswan/ipsec_policy.h>

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
#include "timer.h"

#include "lswcrypto.h"

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
	PR_ASSERT(slot != NULL);

	for (;;) {
		privk = PK11_GenerateKeyPair(slot, CKM_DH_PKCS_KEY_PAIR_GEN,
					     &dhp, &pubk, PR_FALSE, PR_TRUE,
					     lsw_return_nss_password_file_info());
		if (privk == NULL) {
			loglog(RC_LOG_SERIOUS,
			       "NSS: DH private key creation failed (err %d)",
			       PR_GetError());
		}
		PR_ASSERT(privk != NULL);

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

	ALLOC_WIRE_CHUNK(*kn, secret, sizeof(SECKEYPrivateKey *));
	{
		unsigned char *gip = wire_chunk_ptr(kn, &kn->secret);

		memcpy(gip, &privk, sizeof(SECKEYPrivateKey *));
	}

	ALLOC_WIRE_CHUNK(*kn, gi, pubk->u.dh.publicValue.len);
	{
		unsigned char *gip = wire_chunk_ptr(kn, &kn->gi);

		memcpy(gip, pubk->u.dh.publicValue.data,
		       pubk->u.dh.publicValue.len);
	}

	ALLOC_WIRE_CHUNK(*kn, pubk, sizeof(SECKEYPublicKey *));
	{
		unsigned char *gip = wire_chunk_ptr(kn, &kn->pubk);

		memcpy(gip, &pubk, sizeof(SECKEYPublicKey *));
	}

	DBG(DBG_CRYPT, {
		    DBG_dump("NSS: Local DH secret (pointer):\n",
			     wire_chunk_ptr(kn, &kn->secret),
			     sizeof(SECKEYPrivateKey*));
		    DBG_dump("NSS: Public DH value sent(computed in NSS):\n",
			     wire_chunk_ptr(kn, &kn->gi),
			     pubk->u.dh.publicValue.len);
	    });

	DBG(DBG_CRYPT,
	    DBG_dump("NSS: Local DH public value (pointer):\n",
		     wire_chunk_ptr(kn, &kn->pubk),
		     sizeof(SECKEYPublicKey*)));

	/* clean up after ourselves */

	if (slot != NULL)
		PK11_FreeSlot(slot);

#if 0	/* ??? currently broken.  Why?  A leak is better than a crash. */
	if (privk != NULL)
		SECKEY_DestroyPrivateKey(privk);

	if (pubk != NULL)
		SECKEY_DestroyPublicKey(pubk);
#endif

	freeanychunk(prime);
	freeanychunk(base);
}

/* MUST BE THREAD-SAFE */
void calc_nonce(struct pluto_crypto_req *r)
{
	struct pcr_kenonce *kn = &r->pcr_d.kn;

	ALLOC_WIRE_CHUNK(*kn, n, DEFAULT_NONCE_SIZE);
	get_rnd_bytes(wire_chunk_ptr(kn, &(kn->n)), DEFAULT_NONCE_SIZE);

	DBG(DBG_CRYPT,
	    DBG_dump("Generated nonce:\n",
		     wire_chunk_ptr(kn, &(kn->n)),
		     DEFAULT_NONCE_SIZE));
}

stf_status build_ke(struct pluto_crypto_req_cont *cn,
		    struct state *st,
		    const struct oakley_group_desc *group,
		    enum crypto_importance importance)
{
	struct pluto_crypto_req rd;
	err_t e;
	bool toomuch = FALSE;

	pcr_nonce_init(&rd, pcr_build_kenonce, importance);
	rd.pcr_d.kn.oakley_group = group->group;

	cn->pcrc_serialno = st->st_serialno;
	e = send_crypto_helper_request(&rd, cn, &toomuch);

	if (e != NULL) {
		loglog(RC_LOG_SERIOUS, "can not start crypto helper: %s", e);
		if (toomuch)
			return STF_TOOMUCHCRYPTO;
		else
			return STF_FAIL;
	} else if (!toomuch) {
		st->st_calculating = TRUE;
		delete_event(st);
		event_schedule(EVENT_CRYPTO_FAILED, EVENT_CRYPTO_FAILED_DELAY,
			       st);
		return STF_SUSPEND;
	} else {
		/* we must have run the continuation directly, so
		 * complete_v1_state_transition already got called.
		 */
		return STF_INLINE;
	}
}

stf_status build_nonce(struct pluto_crypto_req_cont *cn,
		       struct state *st,
		       enum crypto_importance importance)
{
	struct pluto_crypto_req rd;
	err_t e;
	bool toomuch = FALSE;

	pcr_nonce_init(&rd, pcr_build_nonce, importance);

	cn->pcrc_serialno = st->st_serialno;
	e = send_crypto_helper_request(&rd, cn, &toomuch);

	if (e != NULL) {
		loglog(RC_LOG_SERIOUS, "can not start crypto helper: %s", e);
		if (toomuch)
			return STF_TOOMUCHCRYPTO;
		else
			return STF_FAIL;
	} else if (!toomuch) {
		st->st_calculating = TRUE;
		delete_event(st);
		event_schedule(EVENT_CRYPTO_FAILED, EVENT_CRYPTO_FAILED_DELAY,
			       st);
		return STF_SUSPEND;
	} else {
		/* we must have run the continuation directly, so
		 * complete_v1_state_transition already got called.
		 */
		return STF_INLINE;
	}
}
