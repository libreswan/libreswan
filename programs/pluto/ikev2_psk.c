/* do PSK operations for IKEv2
 *
 * Copyright (C) 2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 Antony Antony <antony@xelerance.com>
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "lswlog.h"

#include "defs.h"
#include "cookie.h"
#include "id.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#ifdef XAUTH_HAVE_PAM
#include <security/pam_appl.h>
#endif
#include "connections.h"	/* needs id.h */
#include "state.h"
#include "packet.h"
#include "md5.h"
#include "sha1.h"
#include "crypto.h" /* requires sha1.h and md5.h */
#include "ike_alg.h"
#include "log.h"
#include "demux.h"	/* needs packet.h */
#include "ikev2.h"
#include "server.h"
#include "vendor.h"
#include "dpd.h"
#include "keys.h"

#include <nss.h>
#include <pk11pub.h>

static u_char psk_key_pad_str[] = "Key Pad for IKEv2"; /* 4306  2:15 */
static int psk_key_pad_str_len = 17; /* sizeof( psk_key_pad_str); -1 */

static bool ikev2_calculate_psk_sighash(struct state *st
					, enum phase1_role role
					, unsigned char *idhash
					, chunk_t firstpacket
					, unsigned char *signed_octets)
{
    const chunk_t *nonce;
    const char    *nonce_name;
    const struct connection *c = st->st_connection;
    const chunk_t *pss = get_preshared_secret(c);
    unsigned int  hash_len =  st->st_oakley.prf_hasher->hash_digest_len;
    unsigned char prf_psk[hash_len];
	
    if (pss == NULL){
	libreswan_log("No matching PSK found for connection:%s", 
		     st->st_connection->name);
	return FALSE;	/* failure: no PSK to use */
    }

        PK11SymKey *shared;
        CK_EXTRACT_PARAMS bs;
        SECItem param;

        memcpy(&shared, st->st_shared.ptr, st->st_shared.len);

    /*	RFC 4306  2:15
	AUTH = prf(prf(Shared Secret,"Key Pad for IKEv2"), <msg octets>)
    */

    /* calculate inner prf */
    {
	struct hmac_ctx id_ctx;
	chunk_t pss_chunk;

	PK11SymKey *tkey1 = pk11_derive_wrapper_lsw(shared, CKM_CONCATENATE_DATA_AND_BASE, *pss, CKM_EXTRACT_KEY_FROM_KEY, CKA_DERIVE, 0);	
	PR_ASSERT(tkey1!=NULL);

	bs=0;
	param.data = (unsigned char*)&bs;
	param.len = sizeof (bs);
	PK11SymKey *tkey2 = PK11_Derive(tkey1, CKM_EXTRACT_KEY_FROM_KEY, &param, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, pss->len);
	PR_ASSERT(tkey2!=NULL);

	pss_chunk.len = sizeof(PK11SymKey *);
	pss_chunk.ptr = alloc_bytes(pss_chunk.len, "ikev2_calculate_psk_sighash: calculated pss_chunk");
	memcpy(pss_chunk.ptr, &tkey2, pss_chunk.len);

	hmac_init_chunk(&id_ctx, st->st_oakley.prf_hasher, pss_chunk);
	
	PK11_FreeSymKey(tkey1);
	PK11_FreeSymKey(tkey2);
	pfree(pss_chunk.ptr);
	hmac_update(&id_ctx, psk_key_pad_str, psk_key_pad_str_len);
	hmac_final(prf_psk, &id_ctx);
    }

    DBG(DBG_CRYPT
	,DBG_log("negotiated prf: %s hash length: %lu", 
		 st->st_oakley.prf_hasher->common.name, 
		 (long unsigned) hash_len));
     DBG(DBG_PRIVATE
	 ,DBG_log("PSK , secret, used %s, length %lu"
	          ,pss->ptr,  (long unsigned) pss->len);
	 DBG_log("keypad used \"%s\", length %d", psk_key_pad_str
	 	  ,psk_key_pad_str_len));
     DBG(DBG_CRYPT
    	,DBG_dump("inner prf output", prf_psk, hash_len));
    
    /* decide nonce based on the role */
    if(role == INITIATOR) {
	/* on initiator, we need to hash responders nonce */
	nonce = &st->st_nr;
	nonce_name = "inputs to hash2 (responder nonce)";
    } else {
	nonce = &st->st_ni;
	nonce_name = "inputs to hash2 (initiator nonce)";
    }

    /* calculate outer prf */
    {
	struct hmac_ctx id_ctx;
        chunk_t pp_chunk, pps_chunk;
	
	pp_chunk.ptr = prf_psk;
	pp_chunk.len = hash_len;

        PK11SymKey *tkey1 = pk11_derive_wrapper_lsw(shared, CKM_CONCATENATE_DATA_AND_BASE, pp_chunk, CKM_EXTRACT_KEY_FROM_KEY, CKA_DERIVE, 0);      
        PR_ASSERT(tkey1!=NULL);

        bs=0;
        param.data = (unsigned char*)&bs;
        param.len = sizeof (bs);
        PK11SymKey *tkey2 = PK11_Derive(tkey1, CKM_EXTRACT_KEY_FROM_KEY, &param, CKM_CONCATENATE_BASE_AND_DATA, CKA_DERIVE, hash_len);
        PR_ASSERT(tkey2!=NULL);

        pps_chunk.len = sizeof(PK11SymKey *);
        pps_chunk.ptr = alloc_bytes(pps_chunk.len, "ikev2_calculate_psk_sighash: calculated pss_chunk");
        memcpy(pps_chunk.ptr, &tkey2, pps_chunk.len);

        hmac_init_chunk(&id_ctx, st->st_oakley.prf_hasher, pps_chunk);

        PK11_FreeSymKey(tkey1);
        PK11_FreeSymKey(tkey2);
        pfree(pps_chunk.ptr);
	
/*
 *  For the responder, the octets to
 *  be signed start with the first octet of the first SPI in the header
 *  of the second message and end with the last octet of the last payload
 *  in the second message.  Appended to this (for purposes of computing
 *  the signature) are the initiator's nonce Ni (just the value, not the
 *  payload containing it), and the value prf(SK_pr,IDr') where IDr' is
 *  the responder's ID payload excluding the fixed header.  Note that
 *  neither the nonce Ni nor the value prf(SK_pr,IDr') are transmitted.
 */

	hmac_update(&id_ctx, firstpacket.ptr, firstpacket.len);
	hmac_update(&id_ctx, nonce->ptr, nonce->len);
	hmac_update(&id_ctx, idhash, hash_len);
	hmac_final(signed_octets, &id_ctx);
	
    }
    
    DBG(DBG_CRYPT
	, DBG_dump_chunk("inputs to hash1 (first packet)", firstpacket);
	DBG_dump_chunk(nonce_name, *nonce);
	DBG_dump("idhash", idhash, hash_len));

    return TRUE;
}

bool ikev2_calculate_psk_auth(struct state *st
			      , enum phase1_role role
			      , unsigned char *idhash
			      , pb_stream *a_pbs)
{
    unsigned int  hash_len =  st->st_oakley.prf_hasher->hash_digest_len;
    unsigned char  signed_octets[hash_len];
    
    if(!ikev2_calculate_psk_sighash(st, role, idhash
				    , st->st_firstpacket_me
				    , signed_octets))
	return FALSE;
    DBG(DBG_CRYPT
	, DBG_dump("PSK auth octets", signed_octets, hash_len ));
    
    out_raw(signed_octets, hash_len, a_pbs, "PSK auth");
    
    return TRUE;
}

stf_status ikev2_verify_psk_auth(struct state *st
				 , enum phase1_role role
				 , unsigned char *idhash
				 , pb_stream *sig_pbs)
{
    unsigned int  hash_len =  st->st_oakley.prf_hasher->hash_digest_len;
    unsigned char calc_hash[hash_len];
    size_t sig_len = pbs_left(sig_pbs);
    
    enum phase1_role invertrole;
    
    invertrole = (role == INITIATOR ? RESPONDER : INITIATOR);
    
    if(sig_len != hash_len) {
	libreswan_log("negotiated prf: %s ", 
		     st->st_oakley.prf_hasher->common.name);
	libreswan_log("I2 hash length:%lu does not match with PRF hash len %lu",
		     (long unsigned) sig_len,  (long unsigned) hash_len);
	return STF_FAIL ;
    }
    
    if(!ikev2_calculate_psk_sighash(st, invertrole, idhash,
				    st->st_firstpacket_him, calc_hash))
	return STF_FAIL;
    
    DBG(DBG_CRYPT
	,DBG_dump("Received PSK auth octets",sig_pbs->cur, sig_len); 
	DBG_dump("Calculated PSK auth octets", calc_hash, hash_len));
    
    if(memcmp(sig_pbs->cur, calc_hash, hash_len) ) {
	libreswan_log("AUTH mismatch: Received AUTH != computed AUTH");
	return STF_FAIL ;
    }
    else {
	return STF_OK;
    }
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
