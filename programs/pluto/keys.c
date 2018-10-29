/*
 * interfaces to the secrets.c library functions in libswan.
 * for now, just stupid wrappers!
 *
 * Copyright (C) 1998-2001  D. Hugh Redelmeier.
 * Copyright (C) 2003-2008  Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2008 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2015 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2016, Andrew Cagney <cagney@gnu.org>
 * Copyright (C) 2017 Vukasin Karadzic <vukasin.karadzic@gmail.com>
 * Copyright (C) 2018 Sahana Prasad <sahana.prasad07@gmail.com>
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

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <resolv.h>

#include <libreswan.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "id.h"
#include "x509.h"
#include "certs.h"
#include "connections.h"        /* needs id.h */
#include "state.h"
#include "lex.h"
#include "keys.h"
#include "log.h"
#include "whack.h"      /* for RC_LOG_SERIOUS */
#include "timer.h"

#include "fetch.h"
#include "pluto_x509.h"
#include "nss_cert_load.h"

#include "nat_traversal.h"

#include <prerror.h>
#include <prinit.h>
#include <prmem.h>
#include <key.h>
#include <keyt.h>
#include <nss.h>
#include <pk11pub.h>
#include <seccomon.h>
#include <secerr.h>
#include <secport.h>
#include <time.h>
#include "lswconf.h"
#include "lswnss.h"
#include "secrets.h"
#include "ike_alg_hash.h"

static struct secret *pluto_secrets = NULL;

void load_preshared_secrets(void)
{
	const struct lsw_conf_options *oco = lsw_init_options();
	lsw_load_preshared_secrets(&pluto_secrets, oco->secretsfile);
}

void free_preshared_secrets(void)
{
	lsw_free_preshared_secrets(&pluto_secrets);
}

static int print_secrets(struct secret *secret,
			 struct private_key_stuff *pks UNUSED,
			 void *uservoid UNUSED)
{
	char idb1[IDTOA_BUF];
	char idb2[IDTOA_BUF];
	const char *kind = "?";
	const char *more = "";
	struct id_list *ids;

	switch (pks->kind) {
	case PKK_PSK:
		kind = "PSK";
		break;
	case PKK_RSA:
		kind = "RSA";
		break;
	case PKK_XAUTH:
		kind = "XAUTH";
		break;
	case PKK_ECDSA:
		kind = "ECDSA";
		break;
	default:
		return 1;
	}

	ids = lsw_get_idlist(secret);
	strcpy(idb1, "%any");
	strcpy(idb2, "");

	if (ids != NULL) {
		idtoa(&ids->id, idb1, sizeof(idb1));
		if (ids->next != NULL) {
			idtoa(&ids->next->id, idb2, sizeof(idb2));
			if (ids->next->next != NULL)
				more = "more";
		}
	}

	whack_log(RC_COMMENT, "    %d: %s %s %s%s",
		  pks->line, kind, idb1, idb2, more);

	/* continue loop until end */
	return 1;
}

void list_psks(void)
{
	const struct lsw_conf_options *oco = lsw_init_options();
	whack_log(RC_COMMENT, " ");
	whack_log(RC_COMMENT, "List of Pre-shared secrets (from %s)",
		  oco->secretsfile);
	whack_log(RC_COMMENT, " ");
	lsw_foreach_secret(pluto_secrets, print_secrets, NULL);
}

enum PrivateKeyKind nss_cert_key_kind(CERTCertificate *cert)
{
	if (!pexpect(cert != NULL)) {
		return PKK_INVALID;
	}

	SECKEYPublicKey *pk = SECKEY_ExtractPublicKey(&cert->subjectPublicKeyInfo);
	if (pk == NULL) {
		LSWLOG(buf) {
			lswlogs(buf, "NSS: could not determine certificate kind; SECKEY_ExtractPublicKey() returned");
			lswlog_nss_error(buf);
		}
		return PKK_INVALID;
	}

	KeyType type = SECKEY_GetPublicKeyType(pk);
	enum PrivateKeyKind kind;
	switch (type) {
	case rsaKey:
		kind = PKK_RSA;
		break;
	case ecKey:
		kind = PKK_ECDSA;
		break;
	default:
		kind = PKK_INVALID;
		break;
	}

	SECKEY_DestroyPublicKey(pk);
	return kind;
}

/* returns the length of the result on success; 0 on failure */
int sign_hash_RSA(const struct RSA_private_key *k,
		  const u_char *hash_val, size_t hash_len,
		  u_char *sig_val, size_t sig_len,
		  enum notify_payload_hash_algorithms hash_algo)
{
	SECKEYPrivateKey *privateKey = NULL;
	SECItem signature;
	SECItem data;
	PK11SlotInfo *slot = NULL;

	DBG(DBG_CRYPT, DBG_log("RSA_sign_hash: Started using NSS"));

	slot = PK11_GetInternalKeySlot();
	if (slot == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "RSA_sign_hash: Unable to find (slot security) device (err %d)",
		       PR_GetError());
		return 0;
	}

	/* XXX: is there no way to detect if we _need_ to authenticate ?? */
	if (PK11_Authenticate(slot, PR_FALSE,
			       lsw_return_nss_password_file_info()) == SECSuccess) {
		DBG(DBG_CRYPT,
		    DBG_log("NSS: Authentication to NSS successful"));
	} else {
		DBG(DBG_CRYPT,
		    DBG_log("NSS: Authentication to NSS either failed or not required,if NSS DB without password"));
	}

	privateKey = PK11_FindKeyByKeyID(slot, k->pub.ckaid.nss,
					 lsw_return_nss_password_file_info());
	if (privateKey == NULL) {
		DBG(DBG_CRYPT,
		    DBG_log("NSS: Can't find the private key from the NSS CKA_ID"));
		CERTCertificate *cert = get_cert_by_ckaid_t_from_nss(k->pub.ckaid);
		if (cert == NULL) {
			loglog(RC_LOG_SERIOUS, "Can't find the certificate or private key from the NSS CKA_ID");
			return 0;
		}
		privateKey = PK11_FindKeyByAnyCert(cert, lsw_return_nss_password_file_info());
		CERT_DestroyCertificate(cert);
		if (privateKey == NULL) {
			loglog(RC_LOG_SERIOUS, "Can't find the private key from the certificate (found using NSS CKA_ID");
			return 0;
		}
	}

	/*
	 * SIG_LEN contains "adjusted" length of modulus n in octets:
	 * [RSA_MIN_OCTETS, RSA_MAX_OCTETS].
	 *
	 * According to form_keyid() this is the modulus length less
	 * any leading byte added by DER encoding.
	 *
	 * The adjusted length is used in sign_hash() as the signature
	 * length - wouldn't PK11_SignatureLen be better?
	 *
	 * Let's find out.
	 */
	pexpect((int)sig_len == PK11_SignatureLen(privateKey));

	PK11_FreeSlot(slot);

	data.type = siBuffer;
	data.len = hash_len;
	data.data = DISCARD_CONST(u_char *, hash_val);

	signature.len = sig_len;
	signature.data = sig_val;

	if (hash_algo == 0 /* ikev1*/ ||
		hash_algo == IKEv2_AUTH_HASH_SHA1 /* old style rsa with SHA1*/) {
		{
			SECStatus s = PK11_Sign(privateKey, &signature, &data);

			if (s != SECSuccess) {
				loglog(RC_LOG_SERIOUS,
					"RSA_sign_hash: sign function failed (%d)",
					PR_GetError());
				return 0;
			}
		}
	} else { /* Digital signature scheme with rsa-pss*/
		CK_RSA_PKCS_PSS_PARAMS mech;

		switch (hash_algo) {
		case IKEv2_AUTH_HASH_SHA2_256:
			mech = rsa_pss_sha2_256;
			break;
		case IKEv2_AUTH_HASH_SHA2_384:
			mech = rsa_pss_sha2_384;
			break;
		case IKEv2_AUTH_HASH_SHA2_512:
			mech = rsa_pss_sha2_512;
			break;
		default:
			bad_case(hash_algo);
		}
		SECItem mechItem = { siBuffer, (unsigned char *)&mech, sizeof(mech) };

		{
			SECStatus s = PK11_SignWithMechanism(privateKey, CKM_RSA_PKCS_PSS,
					&mechItem, &signature, &data);

			if (s != SECSuccess) {
				loglog(RC_LOG_SERIOUS,
					"RSA_sign_hash: sign function failed (%d)",
					PR_GetError());
				return 0;
			}
		}
	}

	SECKEY_DestroyPrivateKey(privateKey);

	DBG(DBG_CRYPT, DBG_log("RSA_sign_hash: Ended using NSS"));
	return signature.len;
}

int sign_hash_ECDSA(const struct ECDSA_private_key *k,
		    const u_char *hash_val, size_t hash_len,
		    u_char *sig_val, size_t sig_len,
		    enum notify_payload_hash_algorithms hash_algo UNUSED)
{
	SECKEYPrivateKey *privateKey = NULL;
	PK11SlotInfo *slot = NULL;
	DBG(DBG_CRYPT, DBG_log("ECDSA_sign_hash: Started using NSS"));

	slot = PK11_GetInternalKeySlot();
	if (slot == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "ECDSA_sign_hash: Unable to find (slot security) device (err %d)",
		       PR_GetError());
		return 0;
	}

	/* XXX: is there no way to detect if we _need_ to authenticate ?? */
	if (PK11_Authenticate(slot, PR_FALSE,
			       lsw_return_nss_password_file_info()) == SECSuccess) {
		DBG(DBG_CRYPT,
		    DBG_log("NSS: Authentication to NSS successful"));
	} else {
		DBG(DBG_CRYPT,
		    DBG_log("NSS: Authentication to NSS either failed or not required,if NSS DB without password"));
	}

	DBG(DBG_CRYPT, DBG_dump("nss", k->pub.ckaid.nss->data, k->pub.ckaid.nss->len));

	CERTCertificate *cert = get_cert_by_ckaid_t_from_nss(k->pub.ckaid);

	LSWDBGP(DBG_MASK, buf) {
		lswlogf(buf, "got cert form ckaid");
		lswlog_nss_error(buf);
	}

	privateKey = PK11_FindKeyByAnyCert(cert, lsw_return_nss_password_file_info());
	DBGF(DBG_CRYPT, "keyType %d",privateKey->keyType);

	if (privateKey == NULL) {
		LSWDBGP(DBG_CRYPT, buf) {
		        lswlogf(buf, "NSS: Can't find the private key from the NSS CKA_ID");
			lswlog_nss_error(buf);
		}

		CERTCertificate *cert = get_cert_by_ckaid_t_from_nss(k->pub.ckaid);
		if (cert == NULL) {
			loglog(RC_LOG_SERIOUS, "Can't find the certificate or private key from the NSS CKA_ID");
			return 0;
		}
		privateKey = PK11_FindKeyByAnyCert(cert, lsw_return_nss_password_file_info());
		CERT_DestroyCertificate(cert);
		if (privateKey == NULL) {
			loglog(RC_LOG_SERIOUS, "Can't find the private key from the certificate (found using NSS CKA_ID");
			return 0;
		}
	}

	PK11_FreeSlot(slot);

	/* point hash at HASH_VAL */
	SECItem hash = {
		.type = siBuffer,
		.len = hash_len,
		.data = DISCARD_CONST(uint8_t *, hash_val),
	};

	/* point signature at the SIG_VAL buffer */
	SECItem signature = {
		.type = siBuffer,
		.len = PK11_SignatureLen(privateKey),
		.data = sig_val,
	};
	DBGF(DBG_CRYPT, "ECDSA signature.len %d", signature.len);
	passert(signature.len <= sig_len);

	SECStatus s = PK11_Sign(privateKey, &signature, &hash);
	DBG(DBG_CRYPT, DBG_dump("sig_from_nss", signature.data, signature.len));
	if (s != SECSuccess) {
		LSWDBGP(DBG_CRYPT, buf) {
			lswlogf(buf, "NSS: signing hash using PK11_Sign() failed:");
			lswlog_nss_error(buf);
		}
		return 0;
	}
	SECKEY_DestroyPrivateKey(privateKey);

	DBG(DBG_CRYPT, DBG_log("ECDSA_sign_hash: Ended using NSS"));
	return signature.len;
}

err_t RSA_signature_verify_nss(const struct RSA_public_key *k,
			       const u_char *hash_val, size_t hash_len,
			       const u_char *sig_val, size_t sig_len,
			       enum notify_payload_hash_algorithms hash_algo)
{
	SECKEYPublicKey *publicKey;
	PRArenaPool *arena;
	SECStatus retVal;
	SECItem nss_n, nss_e;
	SECItem signature, data;

	/* Converting n and e to form public key in SECKEYPublicKey data structure */

	arena = PORT_NewArena(DER_DEFAULT_CHUNKSIZE);
	if (arena == NULL) {
		PORT_SetError(SEC_ERROR_NO_MEMORY);
		return "10" "NSS error: Not enough memory to create arena";
	}

	publicKey = (SECKEYPublicKey *)
		PORT_ArenaZAlloc(arena, sizeof(SECKEYPublicKey));
	if (publicKey == NULL) {
		PORT_FreeArena(arena, PR_FALSE);
		PORT_SetError(SEC_ERROR_NO_MEMORY);
		return "11" "NSS error: Not enough memory to create publicKey";
	}

	publicKey->arena = arena;
	publicKey->keyType = rsaKey;
	publicKey->pkcs11Slot = NULL;
	publicKey->pkcs11ID = CK_INVALID_HANDLE;

	/* make a local copy.  */
	chunk_t n = clone_chunk(k->n, "n");
	chunk_t e = clone_chunk(k->e, "e");

	/* Converting n and e to nss_n and nss_e */
	nss_n.data = n.ptr;
	nss_n.len = (unsigned int)n.len;
	nss_n.type = siBuffer;

	nss_e.data = e.ptr;
	nss_e.len = (unsigned int)e.len;
	nss_e.type = siBuffer;

	retVal = SECITEM_CopyItem(arena, &publicKey->u.rsa.modulus, &nss_n);
	if (retVal == SECSuccess) {
		retVal = SECITEM_CopyItem(arena,
					  &publicKey->u.rsa.publicExponent,
					  &nss_e);
	}

	if (retVal != SECSuccess) {
		pfree(n.ptr);
		pfree(e.ptr);
		SECKEY_DestroyPublicKey(publicKey);
		return "12NSS error: Not able to copy modulus or exponent or both while forming SECKEYPublicKey structure";
	}
	signature.type = siBuffer;
	signature.data = DISCARD_CONST(unsigned char *, sig_val);
	signature.len  = (unsigned int)sig_len;

	data.type = siBuffer;

	if (hash_algo == 0 /* ikev1*/ ||
	    hash_algo == IKEv2_AUTH_HASH_SHA1 /* old style rsa with SHA1*/) {
		data.len = (unsigned int)sig_len;
		data.data = alloc_bytes(data.len, "NSS decrypted signature");

		if (PK11_VerifyRecover(publicKey, &signature, &data,
				       lsw_return_nss_password_file_info()) ==
		    SECSuccess ) {
			LSWDBGP(DBG_CRYPT, buf) {
				lswlogs(buf, "NSS RSA verify: decrypted sig: ");
				lswlog_nss_secitem(buf, &data);
			}
		} else {
			DBG(DBG_CRYPT,
			    DBG_log("NSS RSA verify: decrypting signature is failed"));
			return "13" "NSS error: Not able to decrypt";
		}
		if (!memeq(data.data + data.len - hash_len, hash_val, hash_len)) {
			pfree(data.data);
			loglog(RC_LOG_SERIOUS, "RSA Signature NOT verified");
			return "14" "NSS error: Not able to verify";
		}

		pfree(data.data);
	} else {
		/* Digital signature scheme with RSA-PSS */
		CK_RSA_PKCS_PSS_PARAMS mech;
		SECItem mechItem = { siBuffer, (unsigned char *)&mech, sizeof(mech) };

		switch (hash_algo) {
		case IKEv2_AUTH_HASH_SHA2_256:
			mech = rsa_pss_sha2_256;
			break;
		case IKEv2_AUTH_HASH_SHA2_384:
			mech = rsa_pss_sha2_384;
			break;
		case IKEv2_AUTH_HASH_SHA2_512:
			mech = rsa_pss_sha2_512;
			break;
		default:
			bad_case(hash_algo);
		}

		unsigned char *hash_data = alloc_bytes(hash_len + 1 , "hash length");

		data.len = hash_len + 1;
		memcpy(hash_data , DISCARD_CONST(u_char *, hash_val), hash_len);
		data.data = hash_data;

		LSWDBGP(DBG_CRYPT, buf) {
			lswlogs(buf, "data: ");
			lswlog_nss_secitem(buf, &data);
		}

		if (PK11_VerifyWithMechanism(publicKey, CKM_RSA_PKCS_PSS,  &mechItem, &signature, &data,
				       lsw_return_nss_password_file_info()) == SECSuccess) {
			LSWDBGP(DBG_CRYPT, buf) {
				lswlogs(buf, "NSS RSA verify: decrypted sig: ");
				lswlog_nss_secitem(buf, &data);
			}
		} else {
			DBG(DBG_CRYPT,
			    DBG_log("NSS RSA verify: decrypting signature is failed"));
			return "13" "NSS error: Not able to decrypt";
		}

		pfree(hash_data);
	}

	DBG(DBG_CRYPT,
	    DBG_dump("NSS RSA verify: hash value: ", hash_val, hash_len));

	pfree(n.ptr);
	pfree(e.ptr);
	SECKEY_DestroyPublicKey(publicKey);

	DBG(DBG_CRYPT, DBG_log("RSA Signature verified"));

	return NULL;
}

/*
 * Check signature against all RSA public keys we can find.
 * If we need keys from DNS KEY records, and they haven't been fetched,
 * return STF_SUSPEND to ask for asynch DNS lookup.
 *
 * Note: parameter keys_from_dns contains results of DNS lookup for key
 * or is NULL indicating lookup not yet tried.
 *
 * take_a_crack is a helper function.  Mostly forensic.
 * If only we had coroutines.
 */
struct tac_state_RSA {
	/* RSA_check_signature's args that take_a_crack needs */
	struct state *st;
	const u_char *hash_val;
	size_t hash_len;
	const pb_stream *sig_pbs;
	enum notify_payload_hash_algorithms hash_algo;

	err_t (*try_RSA_signature)(const u_char hash_val[MAX_DIGEST_LEN],
				   size_t hash_len,
				   const pb_stream *sig_pbs,
				   struct pubkey *kr,
				   struct state *st,
				   enum notify_payload_hash_algorithms hash_algo);

	/* state carried between calls */
	err_t best_ugh; /* most successful failure */
	int tried_cnt;  /* number of keys tried */
	char tried[50]; /* keyids of tried public keys */
	char *tn;       /* roof of tried[] */
};

struct tac_state_ECDSA {
	/* RSA_check_signature's args that take_a_crack needs */
	struct state *st;
	const u_char *hash_val;
	size_t hash_len;
	const pb_stream *sig_pbs;
	enum notify_payload_hash_algorithms hash_algo;

	err_t (*try_ECDSA_signature)(const u_char hash_val[MAX_DIGEST_LEN],
				   size_t hash_len,
				   const pb_stream *sig_pbs,
				   struct pubkey *kr,
				   struct state *st,
				   enum notify_payload_hash_algorithms hash_algo);

	/* state carried between calls */
	err_t best_ugh; /* most successful failure */
	int tried_cnt;  /* number of keys tried */
	char tried[50]; /* keyids of tried public keys */
	char *tn;       /* roof of tried[] */
};

static bool take_a_crack_RSA(struct tac_state_RSA *s,
			 struct pubkey *kr,
			 const char *story)
{
	err_t ugh =
		(s->try_RSA_signature)(s->hash_val, s->hash_len, s->sig_pbs,
				       kr, s->st, s->hash_algo);
	const struct RSA_public_key *k = &kr->u.rsa;

	s->tried_cnt++;
	if (ugh == NULL) {
		DBG(DBG_CRYPT | DBG_CONTROL,
		    DBG_log("an RSA Sig check passed with *%s [%s]",
			    k->keyid, story));
		return TRUE;
	} else {
		DBG(DBG_CRYPT,
		    DBG_log("an RSA Sig check failure %s with *%s [%s]",
			    ugh + 1, k->keyid, story));
		if (s->best_ugh == NULL || s->best_ugh[0] < ugh[0])
			s->best_ugh = ugh;
		if (ugh[0] > '0' &&
		    s->tn - s->tried + KEYID_BUF + 2 <
		    (ptrdiff_t)sizeof(s->tried)) {
			strcpy(s->tn, " *");
			strcpy(s->tn + 2, k->keyid);
			s->tn += strlen(s->tn);
		}
		return FALSE;
	}
}

static bool take_a_crack_ECDSA(struct tac_state_ECDSA *s,
			 struct pubkey *kr,
			 const char *story)
{
	err_t ugh =
		(s->try_ECDSA_signature)(s->hash_val, s->hash_len, s->sig_pbs,
				       kr, s->st, s->hash_algo);
	const struct ECDSA_public_key *k = &kr->u.ecdsa;

	s->tried_cnt++;
	if (ugh == NULL) {
		DBG(DBG_CRYPT | DBG_CONTROL,
		    DBG_log("an ECDSA Sig check passed with *%s [%s]",
			    k->keyid, story));
		return TRUE;
	} else {
		DBG(DBG_CRYPT,
		    DBG_log("an ECDSA Sig check failure %s with *%s [%s]",
			    ugh + 1, k->keyid, story));
		if (s->best_ugh == NULL || s->best_ugh[0] < ugh[0])
			s->best_ugh = ugh;
		if (ugh[0] > '0' &&
		    s->tn - s->tried + KEYID_BUF + 2 <
		    (ptrdiff_t)sizeof(s->tried)) {
			strcpy(s->tn, " *");
			strcpy(s->tn + 2, k->keyid);
			s->tn += strlen(s->tn);
		}
		return FALSE;
	}
}

stf_status RSA_check_signature_gen(struct state *st,
				   const u_char hash_val[MAX_DIGEST_LEN],
				   size_t hash_len,
				   const pb_stream *sig_pbs,
				   enum notify_payload_hash_algorithms hash_algo,
				   err_t (*try_RSA_signature)(
					   const u_char hash_val[MAX_DIGEST_LEN],
					   size_t hash_len,
					   const pb_stream *sig_pbs,
					   struct pubkey *kr,
					   struct state *st,
					   enum notify_payload_hash_algorithms hash_algo))
{
	const struct connection *c = st->st_connection;
	struct tac_state_RSA s;

	s.st = st;
	s.hash_val = hash_val;
	s.hash_len = hash_len;
	s.sig_pbs = sig_pbs;
	s.hash_algo = hash_algo;
	s.try_RSA_signature = try_RSA_signature;

	s.best_ugh = NULL;
	s.tried_cnt = 0;
	s.tn = s.tried;

	/* try all appropriate Public keys */
	{
		realtime_t nw = realnow();

		DBG(DBG_CONTROL, {
			char buf[IDTOA_BUF];
			dntoa_or_null(buf, IDTOA_BUF, c->spd.that.ca, "%any");
			DBG_log("required RSA CA is '%s'", buf);
		});

		struct pubkey_list **pp = &pluto_pubkeys;

		for (struct pubkey_list *p = pluto_pubkeys; p != NULL; p = *pp) {
			struct pubkey *key = p->key;

			DBG(DBG_CONTROL, {
				char printkid[IDTOA_BUF];
				idtoa(&key->id, printkid, IDTOA_BUF);
				char thatid[IDTOA_BUF];
				idtoa(&c->spd.that.id, thatid, IDTOA_BUF);
				DBG_log("checking RSA keyid '%s' for match with '%s'",
					printkid, thatid);
			});

			int pl;	/* value ignored */

			if (key->alg == PUBKEY_ALG_RSA &&
			    same_id(&c->spd.that.id, &key->id) &&
			    trusted_ca_nss(key->issuer, c->spd.that.ca, &pl))
			{
				DBG(DBG_CONTROL, {
					char buf[IDTOA_BUF];
					dntoa_or_null(buf, IDTOA_BUF,
						key->issuer, "%any");
					DBG_log("key issuer CA is '%s'", buf);
				});

				/* check if found public key has expired */
				if (!is_realtime_epoch(key->until_time) &&
				    realbefore(key->until_time, nw))
				{
					loglog(RC_LOG_SERIOUS,
					       "cached RSA public key has expired and has been deleted");
					*pp = free_public_keyentry(p);
					continue; /* continue with next public key */
				}

				if (take_a_crack_RSA(&s, key, "preloaded key")) {
					loglog(RC_LOG_SERIOUS, "Authenticated using RSA");
					return STF_OK;
				}
			}
			pp = &p->next;
		}
	}

	/* if no key was found (evidenced by best_ugh == NULL)
	 * and that side of connection is key_from_DNS_on_demand
	 * then go search DNS for keys for peer.
	 */
	/* To be re-implemented */

	/* no acceptable key was found: diagnose */
	{
		char id_buf[IDTOA_BUF]; /* arbitrary limit on length of ID reported */

		(void) idtoa(&st->st_connection->spd.that.id, id_buf,
			     sizeof(id_buf));

		if (s.best_ugh == NULL) {
				loglog(RC_LOG_SERIOUS,
				       "no RSA public key known for '%s'",
				       id_buf);

			/* ??? is this the best code there is? */
			return STF_FAIL + INVALID_KEY_INFORMATION;
		}

		if (s.best_ugh[0] == '9') {
			loglog(RC_LOG_SERIOUS, "%s", s.best_ugh + 1);
			/* XXX Could send notification back */
			return STF_FAIL + INVALID_HASH_INFORMATION;
		} else {
			if (s.tried_cnt == 1) {
				loglog(RC_LOG_SERIOUS,
				       "Signature check (on %s) failed (wrong key?); tried%s",
				       id_buf, s.tried);
				DBG(DBG_CONTROL,
				    DBG_log("public key for %s failed: decrypted SIG payload into a malformed ECB (%s)",
					    id_buf, s.best_ugh + 1));
			} else {
				loglog(RC_LOG_SERIOUS,
				       "Signature check (on %s) failed: tried%s keys but none worked.",
				       id_buf, s.tried);
				DBG(DBG_CONTROL,
				    DBG_log("all %d public keys for %s failed: best decrypted SIG payload into a malformed ECB (%s)",
					    s.tried_cnt, id_buf,
					    s.best_ugh + 1));
			}
			return STF_FAIL + INVALID_KEY_INFORMATION;
		}
	}
}

stf_status ECDSA_check_signature_gen(struct state *st,
				   const u_char hash_val[MAX_DIGEST_LEN],
				   size_t hash_len,
				   const pb_stream *sig_pbs,
				   enum notify_payload_hash_algorithms hash_algo,
				   err_t (*try_ECDSA_signature)(
					   const u_char hash_val[MAX_DIGEST_LEN],
					   size_t hash_len,
					   const pb_stream *sig_pbs,
					   struct pubkey *kr,
					   struct state *st,
					   enum notify_payload_hash_algorithms hash_algo))
{
	const struct connection *c = st->st_connection;
	struct tac_state_ECDSA s;

	s.st = st;
	s.hash_val = hash_val;
	s.hash_len = hash_len;
	s.sig_pbs = sig_pbs;
	s.hash_algo = hash_algo;
	s.try_ECDSA_signature = try_ECDSA_signature;

	s.best_ugh = NULL;
	s.tried_cnt = 0;
	s.tn = s.tried;

	/* try all appropriate Public keys */   /* ASKK */
	{
		realtime_t nw = realnow();

		DBG(DBG_CONTROL, {
			char buf[IDTOA_BUF];
			dntoa_or_null(buf, IDTOA_BUF, c->spd.that.ca, "%any");
			DBG_log("required ECDSA CA is '%s'", buf);
		});

		struct pubkey_list **pp = &pluto_pubkeys;

		for (struct pubkey_list *p = pluto_pubkeys; p != NULL; p = *pp) {
			struct pubkey *key = p->key;
			DBG(DBG_CONTROL, {
				char printkid[IDTOA_BUF];
				idtoa(&key->id, printkid, IDTOA_BUF);
				char thatid[IDTOA_BUF];
				idtoa(&c->spd.that.id, thatid, IDTOA_BUF);
				DBG_log("checking ECDSA keyid '%s' for match with '%s'",
					printkid, thatid);
			});

			int pl;	/* value ignored */

			if (key->alg == PUBKEY_ALG_ECDSA &&
		//	    same_id(&c->spd.that.id, &key->id) &&
			    trusted_ca_nss(key->issuer, c->spd.that.ca, &pl))
			{
				DBG(DBG_CONTROL, {
					char buf[IDTOA_BUF];
					dntoa_or_null(buf, IDTOA_BUF,
						key->issuer, "%any");
					DBG_log("key issuer CA is '%s'", buf);
				});

				/* check if found public key has expired */
				if (!is_realtime_epoch(key->until_time) &&
				    realbefore(key->until_time, nw))
				{
					loglog(RC_LOG_SERIOUS,
					       "cached ECDSA public key has expired and has been deleted");
					*pp = free_public_keyentry(p);
					continue; /* continue with next public key */
				}

				if (take_a_crack_ECDSA(&s, key, "preloaded key")) {
					loglog(RC_LOG_SERIOUS, "Authenticated using ECDSA");
					return STF_OK;
				}
			}
			pp = &p->next;
		}
	}

	/* if no key was found (evidenced by best_ugh == NULL)
	 * and that side of connection is key_from_DNS_on_demand
	 * then go search DNS for keys for peer.
	 */
	/* To be re-implemented */

	/* no acceptable key was found: diagnose */
	{
		char id_buf[IDTOA_BUF]; /* arbitrary limit on length of ID reported */

		(void) idtoa(&st->st_connection->spd.that.id, id_buf,
			     sizeof(id_buf));

		if (s.best_ugh == NULL) {
				loglog(RC_LOG_SERIOUS,
				       "no ECDSA public key known for '%s'",
				       id_buf);

			/* ??? is this the best code there is? */
			return STF_FAIL + INVALID_KEY_INFORMATION;
		}

		if (s.best_ugh[0] == '9') {
			loglog(RC_LOG_SERIOUS, "%s", s.best_ugh + 1);
			/* XXX Could send notification back */
			return STF_FAIL + INVALID_HASH_INFORMATION;
		} else {
			if (s.tried_cnt == 1) {
				loglog(RC_LOG_SERIOUS,
				       "ECDSA Signature check (on %s) failed (wrong key?); tried%s",
				       id_buf, s.tried);
				DBG(DBG_CONTROL,
				    DBG_log("public key for %s failed: decrypted SIG payload into a malformed ECB (%s)",
					    id_buf, s.best_ugh + 1));
			} else {
				loglog(RC_LOG_SERIOUS,
				       "ECDSA Signature check (on %s) failed: tried%s keys but none worked.",
				       id_buf, s.tried);
				DBG(DBG_CONTROL,
				    DBG_log("all %d public keys for %s failed: best decrypted SIG payload into a malformed ECB (%s)",
					    s.tried_cnt, id_buf,
					    s.best_ugh + 1));
			}
			return STF_FAIL + INVALID_KEY_INFORMATION;
		}
	}
}

/*
 * find the struct secret associated with the combination of
 * me and the peer.  We match the Id (if none, the IP address).
 * Failure is indicated by a NULL.
 */
static struct secret *lsw_get_secret(const struct connection *c,
				     enum PrivateKeyKind kind,
				     bool asym)
{
	const struct id *my_id = &c->spd.this.id;
	const struct id *his_id = &c->spd.that.id;

	char idme[IDTOA_BUF];
	char idhim[IDTOA_BUF];

	idtoa(my_id, idme,  IDTOA_BUF);
	idtoa(his_id, idhim, IDTOA_BUF);

	DBG(DBG_CONTROL,
	    DBG_log("started looking for secret for %s->%s of kind %s",
		    idme, idhim,
		    enum_name(&pkk_names, kind)));

	/* is there a certificate assigned to this connection? */
	if ((kind == PKK_ECDSA || kind == PKK_RSA) &&
	    c->spd.this.cert.ty == CERT_X509_SIGNATURE &&
	    c->spd.this.cert.u.nss_cert != NULL) {
		/* from here on: must free my_public_key */
		struct pubkey *my_public_key;
		switch (kind) {
		case PKK_RSA:
			my_public_key = allocate_RSA_public_key_nss(c->spd.this.cert.u.nss_cert);
			break;
		case PKK_ECDSA:
			my_public_key = allocate_ECDSA_public_key_nss(c->spd.this.cert.u.nss_cert);
			break;
		default:
			bad_case(kind);
		}

		if (my_public_key == NULL) {
			loglog(RC_LOG_SERIOUS, "Private key not found (missing or token locked?");
			/* XXX: ??? */
			free_public_key(my_public_key);
			return NULL;
		}

		struct secret *best = lsw_find_secret_by_public_key(pluto_secrets,
						     my_public_key, kind);
		if (best == NULL) {
			const char *nickname = cert_nickname(&c->spd.this.cert);
			DBG(DBG_CONTROL,
			    DBG_log("private key for cert %s not found in local cache; loading from NSS DB",
				    nickname));

			err_t err = load_nss_cert_secret(c->spd.this.cert.u.nss_cert);
			if (err != NULL) {
				/* ??? should this be logged? */
				DBG(DBG_CONTROL,
				    DBG_log("private key for cert %s not found in NSS DB (%s)",
					    nickname, err));
			} else {
				best = lsw_find_secret_by_public_key(pluto_secrets,
								     my_public_key, kind);
			}
		}
		/*
		 * If we don't find the right keytype (RSA, ECDSA, etc)
		 * then best will end up as NULL
		 */
		free_public_key(my_public_key);
		return best;
	}

	/* under certain conditions, override his_id to %ANYADDR */

	struct id rw_id;

	if (
	    /* case 1: */
	    ( remote_id_was_instantiated(c) &&
	      !(c->policy & POLICY_AGGRESSIVE) &&
	      isanyaddr(&c->spd.that.host_addr) ) ||

	    /* case 2 */
	    ( (c->policy & POLICY_PSK) &&
	      kind == PKK_PSK &&
	      ( ( c->kind == CK_TEMPLATE &&
		  c->spd.that.id.kind == ID_NONE ) ||
		( c->kind == CK_INSTANCE &&
		  id_is_ipaddr(&c->spd.that.id) &&
		  /* Check if we are a road warrior instantiation, not a vnet: instantiation */
		  isanyaddr(&c->spd.that.host_addr) ) ) )
	) {
		/* roadwarrior: replace him with %ANYADDR */
		DBG(DBG_CONTROL,
		    DBG_log("instantiating him to %%ANYADDR"));

		rw_id.kind = addrtypeof(&c->spd.that.host_addr) == AF_INET ?
			     ID_IPV4_ADDR : ID_IPV6_ADDR;
		happy(anyaddr(addrtypeof(&c->spd.that.host_addr),
			      &rw_id.ip_addr));
		his_id = &rw_id;
	}

	char idhim_revised[IDTOA_BUF];
	idtoa(his_id, idhim_revised, IDTOA_BUF);

	DBG(DBG_CONTROL,
	    DBG_log("actually looking for secret for %s->%s of kind %s",
		    idme, idhim_revised,
		    enum_name(&pkk_names, kind)));

	return lsw_find_secret_by_id(pluto_secrets,
				     kind,
				     my_id, his_id, asym);
}

/*
 * find the struct secret associated with an XAUTH username.
 */
struct secret *lsw_get_xauthsecret(const struct connection *c UNUSED,
				   char *xauthname)
{
	struct secret *best = NULL;

	DBG(DBG_CONTROL,
	    DBG_log("started looking for xauth secret for %s",
		    xauthname));

	struct id xa_id = {
		.kind = ID_FQDN,
		.name = {
			.ptr = (unsigned char *)xauthname,
			.len = strlen(xauthname)
		}
	};

	best = lsw_find_secret_by_id(pluto_secrets,
				     PKK_XAUTH,
				     &xa_id, NULL, TRUE);

	return best;
}

/* check the existence of an RSA private key matching an RSA public */
static bool has_private_rawkey(struct pubkey *pk)
{
	return lsw_has_private_rawkey(pluto_secrets, pk);
}

/*
 * find the appropriate preshared key (see get_secret).
 * Failure is indicated by a NULL pointer.
 * Note: the result is not to be freed by the caller.
 * Note2: this seems to be called for connections using RSA too?
 */
const chunk_t *get_psk(const struct connection *c)
{
	if (c->policy & POLICY_AUTH_NULL) {
		DBG(DBG_CRYPT, DBG_log("Mutual AUTH_NULL secret - returning empty_chunk"));
		return &empty_chunk;
	}

	struct secret *s = lsw_get_secret(c, PKK_PSK, FALSE);
	const chunk_t *psk =
		s == NULL ? NULL : &lsw_get_pks(s)->u.preshared_secret;

	if (psk != NULL) {
		DBG(DBG_PRIVATE, {
			DBG_dump_chunk("PreShared Key", *psk);
		});
	} else {
		DBG(DBG_CONTROL, DBG_log("no PreShared Key Found"));
	}
	return psk;
}


/* Return ppk and store ppk_id in *ppk_id */

chunk_t *get_ppk(const struct connection *c, chunk_t **ppk_id)
{
	struct secret *s = lsw_get_secret(c, PKK_PPK, FALSE);

	if (s == NULL) {
		*ppk_id = NULL;
		return NULL;
	}

	struct private_key_stuff *pks = lsw_get_pks(s);
	*ppk_id = &pks->ppk_id;
	DBG(DBG_PRIVATE, {
		DBG_log("Found PPK");
		DBG_dump_chunk("PPK_ID:", **ppk_id);
		DBG_dump_chunk("PPK:", pks->ppk);
		});
	return &pks->ppk;
}

/*
 * Find PPK, by its id (PPK_ID).
 * Used by responder.
 */
const chunk_t *get_ppk_by_id(const chunk_t *ppk_id)
{
	struct secret *s = lsw_get_ppk_by_id(pluto_secrets, *ppk_id);

	if (s != NULL) {
		const struct private_key_stuff *pks = lsw_get_pks(s);
		DBG(DBG_PRIVATE, {
			DBG_dump_chunk("Found PPK:", pks->ppk);
			DBG_dump_chunk("with PPK_ID:", *ppk_id);
		});
		return &pks->ppk;
	}
	DBG(DBG_CONTROL, {
		DBG_log("No PPK found with given PPK_ID");
	});
	return NULL;
}

/*
 * find the appropriate RSA private key (see get_secret).
 * Failure is indicated by a NULL pointer.
 */
const struct RSA_private_key *get_RSA_private_key(const struct connection *c)
{
	struct secret *s = lsw_get_secret(c, PKK_RSA, TRUE);
	const struct RSA_private_key *RSA_pk =
		s == NULL ? NULL : &lsw_get_pks(s)->u.RSA_private_key;

	DBG(DBG_CRYPT, {
		if (RSA_pk == NULL)
			DBG_log("no RSA key Found");
		else
			DBG_log("RSA key %s found",
				RSA_pk->pub.keyid);
	});
	return RSA_pk;
}

/*
 * find the appropriate ECDSA private key (see get_secret).
 * Failure is indicated by a NULL pointer.
 */
const struct ECDSA_private_key *get_ECDSA_private_key(const struct connection *c)
{
	struct secret *s = lsw_get_secret(c, PKK_ECDSA, TRUE);
	const struct ECDSA_private_key *ECDSA_pk =
		s == NULL ? NULL : &lsw_get_pks(s)->u.ECDSA_private_key;

	DBG(DBG_CRYPT, {
		if (ECDSA_pk == NULL)
			DBG_log("no ECDSA key Found");
		else
			DBG_log("ECDSA key %s found",
				ECDSA_pk->pub.keyid);
	});
	return ECDSA_pk;
}

/*
 * public key machinery
 */

/* root of chained public key list */

struct pubkey_list *pluto_pubkeys = NULL;       /* keys from ipsec.conf */

void free_remembered_public_keys(void)
{
	free_public_keys(&pluto_pubkeys);
}

err_t add_public_key(const struct id *id, /* ASKK */
		     enum dns_auth_level dns_auth_level,
		     enum pubkey_alg alg,
		     const chunk_t *key,
		     struct pubkey_list **head)
{
	struct pubkey *pk = alloc_thing(struct pubkey, "pubkey");

	/* first: algorithm-specific decoding of key chunk */
	switch (alg) {
	case PUBKEY_ALG_RSA:
	{
		err_t ugh = unpack_RSA_public_key(&pk->u.rsa, key);

		if (ugh != NULL) {
			pfree(pk);
			return ugh;
		}
	}
	break;
	case PUBKEY_ALG_ECDSA:
	{
		err_t ugh = unpack_ECDSA_public_key(&pk->u.ecdsa, key);

		if (ugh != NULL) {
			pfree(pk);
			return ugh;
		}
	}
	break;
	default:
		bad_case(alg);
	}

	pk->id = *id;
	pk->dns_auth_level = dns_auth_level;
	pk->alg = alg;
	pk->until_time = realtime_epoch;
	pk->issuer = empty_chunk;

	install_public_key(pk, head);
	return NULL;
}

err_t add_ipseckey(const struct id *id,
		     enum dns_auth_level dns_auth_level,
		     enum pubkey_alg alg,
		     uint32_t ttl, uint32_t ttl_used,
		     const chunk_t *key,
		     struct pubkey_list **head)
{
	struct pubkey *pk = alloc_thing(struct pubkey, "ipseckey publickey");

	/* first: algorithm-specific decoding of key chunk */
	switch (alg) {
	case PUBKEY_ALG_RSA:
	{
		err_t ugh = unpack_RSA_public_key(&pk->u.rsa, key);

		if (ugh != NULL) {
			pfree(pk);
			return ugh;
		}
	}
	break;
	case PUBKEY_ALG_ECDSA:
	{
		err_t ugh = unpack_ECDSA_public_key(&pk->u.ecdsa, key);

		if (ugh != NULL) {
			pfree(pk);
			return ugh;
		}
	}
	break;
	default:
		bad_case(alg);
	}

	pk->dns_ttl = ttl;
	pk->installed_time = realnow();
	pk->until_time = realtimesum(pk->installed_time, deltatime(ttl_used));
	pk->id = *id;
	pk->dns_auth_level = dns_auth_level;
	pk->alg = alg;
	pk->issuer = empty_chunk; /* ipseckey has no issuer */

	install_public_key(pk, head);
	return NULL;
}

/*
 *  list all public keys in the chained list
 */
void list_public_keys(bool utc, bool check_pub_keys)
{
	struct pubkey_list *p = pluto_pubkeys;

	if (!check_pub_keys) {
		whack_log(RC_COMMENT, " ");
		whack_log(RC_COMMENT, "List of Public Keys:");
		whack_log(RC_COMMENT, " ");
	}

	while (p != NULL) {
		struct pubkey *key = p->key;

		switch (key->alg) {
		case PUBKEY_ALG_RSA:
		case PUBKEY_ALG_ECDSA:
		{
			const char *check_expiry_msg = check_expiry(key->until_time,
							PUBKEY_WARNING_INTERVAL,
							TRUE);

			if (!check_pub_keys ||
			    !startswith(check_expiry_msg, "ok")) {
				char id_buf[IDTOA_BUF];

				idtoa(&key->id, id_buf, IDTOA_BUF);

				LSWLOG_WHACK(RC_COMMENT, buf) {
					lswlog_realtime(buf, key->installed_time, utc);
					lswlogs(buf, ", ");
					switch (key->alg) {
					case PUBKEY_ALG_RSA:
						lswlogf(buf, "%4d RSA Key %s",
							8 * key->u.rsa.k,
							key->u.rsa.keyid);
						break;
					case PUBKEY_ALG_ECDSA:
						lswlogf(buf, "%4d ECDSA Key %s",
							8 * key->u.ecdsa.k,
							key->u.ecdsa.keyid);
						break;
					default:
						bad_case(key->alg);
					}
					lswlogf(buf, " (%s private key), until ",
						(has_private_rawkey(key) ? "has" : "no"));
					lswlog_realtime(buf, key->until_time, utc);
					lswlogf(buf, " %s", check_expiry_msg);
				}

				/* XXX could be ikev2_idtype_names */
				whack_log(RC_COMMENT, "       %s '%s'",
					  enum_show(&ike_idtype_names,
						    key->id.kind), id_buf);

				if (key->issuer.len > 0) {
					dntoa(id_buf, IDTOA_BUF, key->issuer);
					whack_log(RC_COMMENT,
						  "       Issuer '%s'",
						  id_buf);
				}
			}
			break;
		}
		default:
			DBGF(DBG_CONTROL, "ignoring key with unsupported alg %d",
			     key->alg);
		}
		p = p->next;
	}
}

err_t load_nss_cert_secret(CERTCertificate *cert)
{
	if (cert == NULL) {
		return "NSS cert not found";
	}
	switch (nss_cert_key_kind(cert)) {
	case PKK_RSA:
		return lsw_add_rsa_secret(&pluto_secrets, cert);
	case PKK_ECDSA:
		return lsw_add_ecdsa_secret(&pluto_secrets, cert);
	default:
		return "NSS cert not supported";
	}
}

static bool rsa_pubkey_ckaid_matches(struct pubkey *pubkey, char *buf, size_t buflen)
{
	if (pubkey->u.rsa.n.ptr == NULL) {
		DBGF(DBG_CONTROL, "RSA pubkey with NULL modulus");
		return FALSE;
	}
	SECItem modulus = {
		.type = siBuffer,
		.len = pubkey->u.rsa.n.len,
		.data = pubkey->u.rsa.n.ptr,
	};
	SECItem *pubkey_ckaid = PK11_MakeIDFromPubKey(&modulus);
	if (pubkey_ckaid == NULL) {
		DBGF(DBG_CONTROL, "RSA pubkey incomputable CKAID");
		return FALSE;
	}
	LSWDBGP(DBG_CONTROL, buf) {
		lswlogs(buf, "comparing ckaid with: ");
		lswlog_nss_secitem(buf, pubkey_ckaid);
	}
	bool eq = pubkey_ckaid->len == buflen &&
		  memcmp(pubkey_ckaid->data, buf, buflen) == 0;
	SECITEM_FreeItem(pubkey_ckaid, PR_TRUE);
	return eq;
}

struct pubkey *get_pubkey_with_matching_ckaid(const char *ckaid)
{
	/* convert hex string ckaid to binary bin */
	size_t binlen = (strlen(ckaid) + 1) / 2;
	char *bin = alloc_bytes(binlen, "ckaid");
	const char *ugh = ttodata(ckaid, 0, 16, bin, binlen, &binlen);
	if (ugh != NULL) {
		pfree(bin);
		/* should have been rejected by whack? */
		libreswan_log("invalid hex CKAID '%s': %s", ckaid, ugh);
		return NULL;
	}
	DBG(DBG_CONTROL,
	    DBG_dump("looking for pubkey with CKAID that matches", bin, binlen));

	struct pubkey_list *p;
	for (p = pluto_pubkeys; p != NULL; p = p->next) {
		DBG_log("looking at a PUBKEY");
		struct pubkey *key = p->key;
		switch (key->alg) {
		case PUBKEY_ALG_RSA: {
			if (rsa_pubkey_ckaid_matches(key, bin, binlen)) {
				DBGF(DBG_CONTROL, "ckaid matching pubkey");
				pfree(bin);
				return key;
			}
		}
		default:
			break;
		}
	}
	pfree(bin);
	return NULL;
}
