/*
 * IKE modular algorithm handling interface
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * 
 * ike_alg.c,v 1.1.2.18 2002/05/29 04:13:04 jjo Exp
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
 * 	ML:	Mathieu Lafon <mlafon@arkoon.net>
 *
 * Fixes:
 * 	ML:	ike_alg_ok_final() funcion (make F_STRICT consider hash/auth and modp).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/queue.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "constants.h"
#include "defs.h"
#include "sha1.h"
#include "md5.h"
#include "crypto.h"

#include "state.h"
#include "packet.h"
#include "log.h"
#include "whack.h"
#include "spdb.h"
#include "alg_info.h"
#include "ike_alg.h"
#include "db_ops.h"
#include "id.h"
#include "connections.h"
#include "kernel.h"
#include "plutoalg.h"

#define AD(x) x, elemsof(x)	/* Array Description */
#define AD_NULL NULL, 0
/*
 * empty structure, for clone use.
 */
static struct db_attr otempty[] = {
	{ OAKLEY_ENCRYPTION_ALGORITHM, -1 },
	{ OAKLEY_HASH_ALGORITHM,       -1 },
	{ OAKLEY_AUTHENTICATION_METHOD, -1 },
	{ OAKLEY_GROUP_DESCRIPTION,    -1 },
	{ OAKLEY_KEY_LENGTH,    -1 },
	};

static struct db_trans oakley_trans_empty[] = {
	{ KEY_IKE, AD(otempty) },
    };

static struct db_prop oakley_pc_empty[] =
    { { PROTO_ISAKMP, AD(oakley_trans_empty) } };

static struct db_prop_conj oakley_props_empty[] = { { AD(oakley_pc_empty) } };

struct db_sa oakley_empty = { AD(oakley_props_empty) };

#define return_on(var, val) do { var=val;goto return_out; } while(0);

/*
 * 	Create an OAKLEY proposal based on alg_info and policy
 */
struct db_sa *
oakley_alg_makedb(struct alg_info_ike *ai
		  , struct db_sa *base
		  , int maxtrans)
{
    struct db_context inprog UNUSED;
    struct db_sa *gsp = NULL;
    struct db_sa *emp_sp = NULL;
    struct ike_info *ike_info;
    unsigned ealg, halg, modp, eklen=0;
    struct encrypt_desc *enc_desc;
    int transcnt = 0;
    int i;

    /*
     * start by copying the proposal that would have been picked by
     * standard defaults.
     */

    if (!ai) {
	DBG(DBG_CRYPT,DBG_log("no IKE algorithms for this connection "));
	
	goto fail;
    }

    gsp = NULL;

    /*
     * for each group, we will create a new proposal item, and then
     * append it to the list of transforms in the conjoint point.
     *
     * when creating each item, we will use the first transform
     * from the base item as the template.
     */
    ALG_INFO_IKE_FOREACH(ai, ike_info, i) {

	if(ike_info->ike_default == FALSE) {
	    struct db_attr  *enc, *hash, *auth, *grp, *enc_keylen, *new_auth;
	    struct db_trans *trans;
	    struct db_prop  *prop;
	    struct db_prop_conj *cprop;
	    
	    ealg = ike_info->ike_ealg;
	    halg = ike_info->ike_halg;
	    modp = ike_info->ike_modp;
	    eklen= ike_info->ike_eklen;
	    
	    if (!ike_alg_enc_present(ealg)) {
		DBG_log("ike_alg_db_new() "
			"ike enc ealg=%d not present",
			ealg);
		continue;
	    }
	    if (!ike_alg_hash_present(halg)) {
		DBG_log("ike_alg_db_new() "
			"ike hash halg=%d not present",
			halg);
		continue;
	    }
	    enc_desc = ike_alg_get_encrypter(ealg);
	    
	    passert(enc_desc != NULL);
	    if (eklen 
		&& (eklen < enc_desc->keyminlen
		    || eklen >  enc_desc->keymaxlen))
		
		{
		    DBG_log("ike_alg_db_new() "
			    "ealg=%d (specified) keylen:%d, "
			    "not valid "
			    "min=%d, max=%d"
			    , ealg
			    , eklen
			    , enc_desc->keyminlen
			    , enc_desc->keymaxlen
			    );
		    continue;
		}
	    
	    /* okay copy the basic item, and modify it. */
	    if(eklen > 0)
	    {
		emp_sp = sa_copy_sa(&oakley_empty, 0);
		cprop = &base->prop_conjs[0];
		prop = &cprop->props[0];
		trans = &prop->trans[0];
		new_auth = &trans->attrs[2];

		cprop = &emp_sp->prop_conjs[0];
		prop = &cprop->props[0];
		trans = &prop->trans[0];
		auth = &trans->attrs[2];
		*auth = *new_auth;
	    }
	    else
		emp_sp = sa_copy_sa_first(base);

	    passert(emp_sp->prop_conj_cnt == 1);
	    cprop = &emp_sp->prop_conjs[0];
	    
	    passert(cprop->prop_cnt == 1);
	    prop = &cprop->props[0];
	    
	    passert(prop->trans_cnt == 1);
	    trans = &prop->trans[0];
	    
	    passert(trans->attr_cnt == 4 || trans->attr_cnt == 5);
	    enc  = &trans->attrs[0];
	    hash = &trans->attrs[1];
	    auth = &trans->attrs[2];
	    grp  = &trans->attrs[3];

	    if(eklen > 0) {
		enc_keylen = &trans->attrs[4];
		enc_keylen->val = eklen;
	    }

	    passert(enc->type == OAKLEY_ENCRYPTION_ALGORITHM);
	    if(ealg > 0) {
		enc->val = ealg;
	    }
	    
	    modp = ike_info->ike_modp;
	    eklen= ike_info->ike_eklen;
	    
	    passert(hash->type == OAKLEY_HASH_ALGORITHM);
	    if(halg > 0) {
		hash->val = halg;
	    }
	    
	    passert(auth->type == OAKLEY_AUTHENTICATION_METHOD);
	    /* no setting for auth type for IKE */
	    
	    passert(grp->type == OAKLEY_GROUP_DESCRIPTION);
	    if(modp > 0) {
		grp->val = modp;
	    }
	} else {
	    emp_sp = sa_copy_sa(base, 0);
	}

	if(maxtrans == 1) {
	    if(transcnt == 0) {
		DBG(DBG_CONTROL, DBG_log("using transform (%d,%d,%d,%ld)"
					 , ike_info->ike_ealg
					 , ike_info->ike_halg
					 , ike_info->ike_modp
					 , (long)ike_info->ike_eklen));
		if(gsp) {
		    free_sa(gsp);
		}
		gsp = emp_sp;
	    } else {
		free_sa(emp_sp);
	    }

	    if(transcnt > 0) {
		if(transcnt == 1) {
		    loglog(RC_LOG_SERIOUS
			   
			   , "multiple transforms were set in aggressive mode. Only first one used.");
		}

		loglog(RC_LOG_SERIOUS
		       , "transform (%d,%d,%d,%ld) ignored."
		       , ike_info->ike_ealg
		       , ike_info->ike_halg
		       , ike_info->ike_modp
		       , (long)ike_info->ike_eklen);
	    } 

	} else {
	    struct db_sa *new;

	    /* now merge emp_sa and gsp */
	    if(gsp) {
		new = sa_merge_proposals(gsp, emp_sp);
		free_sa(gsp);
		free_sa(emp_sp);
		emp_sp = NULL;
		gsp = new;
	    } else {
		gsp = emp_sp;
	    }
	}
	transcnt++;
    }
fail:
    return gsp;
}

struct db_context *
ike_alg_db_new(struct alg_info_ike *ai , lset_t policy)
{
	struct db_context *db_ctx = NULL;
	struct ike_info *ike_info;
	unsigned ealg, halg, modp, eklen=0;
	struct encrypt_desc *enc_desc;
	int i;

	if (!ai) {
		DBG(DBG_CRYPT,DBG_log("no IKE algorithms for this connection "));

		goto fail;
	}
	policy &= POLICY_ID_AUTH_MASK;
	db_ctx = db_prop_new(PROTO_ISAKMP, 8, 8 * 5);

	/* for each group */
	ALG_INFO_IKE_FOREACH(ai, ike_info, i) {
	        char ikebuf[IKEALGBUF_LEN];

		DBG(DBG_CONTROLMORE
		    , DBG_log("examining ike policy of %s"
			      , alg_info_snprint_ike1(ike_info
						      , 0, 0
						      , ikebuf
						      , sizeof(ikebuf))));

		ealg = ike_info->ike_ealg;
		halg = ike_info->ike_halg;
		modp = ike_info->ike_modp;
		eklen= ike_info->ike_eklen;
		if (!ike_alg_enc_present(ealg)) {
			DBG_log("ike_alg_db_new() "
					"ike enc ealg=%d not present",
					ealg);
			continue;
		}
		if (!ike_alg_hash_present(halg)) {
			DBG_log("ike_alg_db_new() "
					"ike hash halg=%d not present",
					halg);
			continue;
		}
		enc_desc = ike_alg_get_encrypter(ealg);
		passert(enc_desc != NULL);
		if (eklen 
		/*
			&& eklen != enc_desc->keydeflen)
		*/
			&& (eklen < enc_desc->keyminlen
				|| eklen >  enc_desc->keymaxlen))
				
		{
			DBG_log("ike_alg_db_new() "
					"ealg=%d (specified) keylen:%d, "
					"not valid "
					/*
					 "keylen != %d"
					 */
					"min=%d, max=%d"
					, ealg
					, eklen
					/*
					, enc_desc->keydeflen
					*/
					, enc_desc->keyminlen
					, enc_desc->keymaxlen
					);
			continue;
		}
		if (policy & POLICY_RSASIG) {
			db_trans_add(db_ctx, KEY_IKE);
			db_attr_add_values(db_ctx, 
					OAKLEY_ENCRYPTION_ALGORITHM, ealg);
			db_attr_add_values(db_ctx, 
					OAKLEY_HASH_ALGORITHM, halg);
			if (eklen)
				db_attr_add_values(db_ctx, 
						OAKLEY_KEY_LENGTH, eklen);
			db_attr_add_values(db_ctx, 
					OAKLEY_AUTHENTICATION_METHOD, OAKLEY_RSA_SIG);
			db_attr_add_values(db_ctx, 
					OAKLEY_GROUP_DESCRIPTION, modp);
		}
		if (policy & POLICY_PSK) {
			db_trans_add(db_ctx, KEY_IKE);
			db_attr_add_values(db_ctx, 
					OAKLEY_ENCRYPTION_ALGORITHM, ealg);
			db_attr_add_values(db_ctx, 
					OAKLEY_HASH_ALGORITHM, halg);
			if (ike_info->ike_eklen) 
				db_attr_add_values(db_ctx, 
						OAKLEY_KEY_LENGTH, ike_info->ike_eklen);
			db_attr_add_values(db_ctx, 
					OAKLEY_AUTHENTICATION_METHOD, OAKLEY_PRESHARED_KEY);
			db_attr_add_values(db_ctx, 
					OAKLEY_GROUP_DESCRIPTION, modp);
		}
	}
fail:
	return db_ctx;
}
/*
 * 	Show registered IKE algorithms
 */
void
ike_alg_show_status(void)
{
	unsigned alg, i;
	struct ike_alg *algo;
	IKE_EALG_FOR_EACH(algo) {
		passert(algo != NULL);
		alg=algo->algo_id;
		whack_log(RC_COMMENT, "algorithm IKE encrypt: id=%d, name=%s, blocksize=%d, keydeflen=%d"
			, alg
			, enum_name(&oakley_enc_names, alg)
			, (int)((struct encrypt_desc *)algo)->enc_blocksize
			, ((struct encrypt_desc *)algo)->keydeflen
			);
		
	}
	IKE_HALG_FOR_EACH(algo) {
		whack_log(RC_COMMENT, "algorithm IKE hash: id=%d, name=%s, hashsize=%d"
			, algo->algo_id
			, enum_name(&oakley_hash_names, algo->algo_id)
			, (int)((struct hash_desc *)algo)->hash_digest_len
			);
	}
#define IKE_DH_ALG_FOR_EACH(idx) for(idx = 0; idx != oakley_group_size; idx++)
	IKE_DH_ALG_FOR_EACH(i) {
		const struct oakley_group_desc *gdesc=oakley_group+i;
		whack_log(RC_COMMENT, "algorithm IKE dh group: id=%d, name=%s, bits=%d"
			, gdesc->group
			, enum_name(&oakley_group_names, gdesc->group)
			, (int)gdesc->bytes*BITS_PER_BYTE
			);
	}
}
/*
 * 	Show IKE algorithms for 
 * 	- this connection (result from ike= string)
 * 	- newest SA
 */
void
ike_alg_show_connection(struct connection *c, const char *instance)
{
	char buf[256];
	struct state *st;
	if (c->alg_info_ike) {
		alg_info_snprint(buf, sizeof(buf)-1, 
				 (struct alg_info *)c->alg_info_ike, TRUE);
		whack_log(RC_COMMENT
		    , "\"%s\"%s:   IKE algorithms wanted: %s"
		    , c->name
		    , instance
		    , buf);
	}
	if (c->alg_info_ike) {
		alg_info_snprint_ike(buf, sizeof(buf)-1, c->alg_info_ike);
		whack_log(RC_COMMENT
		    , "\"%s\"%s:   IKE algorithms found:  %s"
		    , c->name
		    , instance
		    , buf);
	}
	st = state_with_serialno(c->newest_isakmp_sa);
	if (st)
		whack_log(RC_COMMENT
		, "\"%s\"%s:   IKE algorithm newest: %s_%d-%s-%s"
		, c->name
		, instance
		, enum_show(&oakley_enc_names, st->st_oakley.encrypt)
		+7 /* strlen("OAKLEY_") */
		/* , st->st_oakley.encrypter->keydeflen */
		, st->st_oakley.enckeylen
		, enum_show(&oakley_hash_names, st->st_oakley.hash)
		+7 /* strlen("OAKLEY_") */
		, enum_show(&oakley_group_names, st->st_oakley.group->group)
		+13 /* strlen("OAKLEY_GROUP_") */
	 );
}
/*==========================================================
 *
 * 	IKE algo list handling
 *
 * 	- registration
 * 	- lookup
 *=========================================================*/
struct ike_alg *ike_alg_base[IKE_ALG_MAX+1] = {NULL, NULL};
/*	check if IKE encrypt algo is present */
bool ike_alg_enc_present(int ealg)
{
	struct encrypt_desc *enc_desc = ike_alg_get_encrypter(ealg);
	return enc_desc ? enc_desc->enc_blocksize : 0;
}
/*	check if IKE hash algo is present */
bool ike_alg_hash_present(int halg)
{
	struct hash_desc *hash_desc = ike_alg_get_hasher(halg);
	return hash_desc ? hash_desc->hash_digest_len : 0;
}
bool ike_alg_enc_ok(int ealg, unsigned key_len, 
		struct alg_info_ike *alg_info_ike __attribute__((unused)), 
		const char **errp)
{
	int ret=TRUE;
	struct encrypt_desc *enc_desc;
	char errbuf[256]="encrypt algo not found";
	/* 
	 * test #1: encrypt algo must be present 
	 */
	enc_desc = ike_alg_get_encrypter(ealg);
	if (!enc_desc) return_on(ret, FALSE);
	/* 
	 * test #2: if key_len specified, it must be in range 
	 */
	if ((key_len) && ((key_len < enc_desc->keyminlen) ||
			 (key_len > enc_desc->keymaxlen))) {
		snprintf(errbuf, sizeof(errbuf)-1,
				"key_len not in range: encalg=%d, "
				"key_len=%d, keyminlen=%d, keymaxlen=%d",
				ealg, key_len,
				enc_desc->keyminlen,
				enc_desc->keymaxlen
		       );
		plog ("ike_alg_enc_ok(): %s", errbuf);
		return_on(ret, FALSE);
	} 
#if 0 /* ML: logic moved to ike_alg_ok_final() */
	/* 
	 * test #3: if alg_info specified AND strict flag, only
	 * only allow algo iff listed in st->alg_info_esp
	 */
	else if (alg_info_ike && (alg_info_ike->alg_info_flags & ALG_INFO_F_STRICT) ) {
		int i;
		struct ike_info *ike_info;
		ALG_INFO_IKE_FOREACH(alg_info_ike, ike_info, i) {
			if ((ike_info->ike_ealg == ealg) &&
				((ike_info->ike_eklen==0) || (key_len==0) ||
				 (ike_info->ike_eklen==key_len))) {
				return_on(ret, TRUE);
			}
		}
		snprintf(errbuf, sizeof(errbuf),
				"strict flag and encrypt algorithm "
				"not in transform string list: "
				"ealg=%d, "
				"key_len=%d, keyminbits=%d, keymaxbits=%d",
				ealg, key_len,
				enc_desc->keyminlen,
				enc_desc->keymaxlen
		   );
		log("ike_alg_enc_ok(): %s", errbuf);
		return_on(ret, FALSE);
	}
#endif
return_out:
	DBG(DBG_KLIPS, 
		if (ret) 
			DBG_log("ike_alg_enc_ok(ealg=%d,key_len=%d): "
				"blocksize=%d, keyminlen=%d, "
				"keydeflen=%d, keymaxlen=%d, "
				"ret=%d",
				ealg, key_len,
				(int)enc_desc->enc_blocksize,
				enc_desc->keyminlen,
				enc_desc->keydeflen,
				enc_desc->keymaxlen,
				ret);
		else 
			DBG_log("ike_alg_enc_ok(ealg=%d,key_len=%d): NO",
				ealg, key_len);
	);
	if (!ret && *errp)
		*errp=errbuf;
	return ret;
}
/* 
 * ML: make F_STRICT logic consider enc,hash/auth,modp algorithms 
 */
bool ike_alg_ok_final(int ealg, unsigned key_len, int aalg, int group, struct alg_info_ike *alg_info_ike)
{
	/* 
	 * simple test to toss low key_len, will accept it only
	 * if specified in "esp" string
	 */
	int ealg_insecure=(key_len < 128) ;

	if (ealg_insecure || 
		(alg_info_ike && alg_info_ike->alg_info_flags & ALG_INFO_F_STRICT))
	{
		int i;
		struct ike_info *ike_info;
		if (alg_info_ike) {
			ALG_INFO_IKE_FOREACH(alg_info_ike, ike_info, i) {
				if ((ike_info->ike_ealg == ealg) &&
						((ike_info->ike_eklen==0) || (key_len==0) ||
						 (ike_info->ike_eklen==key_len)) &&
						(ike_info->ike_halg == aalg) &&
						(ike_info->ike_modp == group)) {
					if (ealg_insecure) 
						loglog(RC_LOG_SERIOUS, "You should NOT use insecure IKE algorithms (%s)!"
								, enum_name(&oakley_enc_names, ealg));
					return TRUE;
				}
			}
		}
		openswan_log("Oakley Transform [%s (%d), %s, %s] refused due to %s",
			enum_name(&oakley_enc_names, ealg), key_len,
			enum_name(&oakley_hash_names, aalg),
			enum_name(&oakley_group_names, group),
			ealg_insecure ? "insecure key_len and enc. alg. not listed in \"ike\" string" : "strict flag"
			);
		return FALSE;
	}
	return TRUE;
}
/*
 * 	return ike_algo object by {type, id}
 */
/* XXX:jjo use keysize */
struct ike_alg *
ike_alg_find(unsigned algo_type, unsigned algo_id, unsigned keysize __attribute__((unused)))
{
	struct ike_alg *e=ike_alg_base[algo_type];
	for(;e!=NULL;e=e->algo_next) {
		if (e->algo_id==algo_id)
			break;
	}
	return e;
}

/*
 * 	Main "raw" ike_alg list adding function
 */
int
ike_alg_add(struct ike_alg* a)
{
	int ret=0;
	const char *ugh="No error";
	if (a->algo_type > IKE_ALG_MAX)
	{
		ugh="Invalid algo_type";
		return_on(ret,-EINVAL);
	}
	if (ike_alg_find(a->algo_type, a->algo_id, 0))
	{
		ugh="Algorithm already exists";
		return_on(ret,-EEXIST);
	}
	if (ret==0) {
		a->algo_next=ike_alg_base[a->algo_type];
		ike_alg_base[a->algo_type]=a;
	}
return_out:
	if (ret) 
		openswan_log("ike_alg_add(): ERROR: %s", ugh);
	return ret;
}

/*
 * 	Validate and register IKE hash algorithm object
 */
int
ike_alg_register_hash(struct hash_desc *hash_desc)
{
	const char *alg_name = "<none>";
	int ret=0;

	if (hash_desc->common.algo_id > OAKLEY_HASH_MAX) {
		plog ("ike_alg_register_hash(): hash alg=%d < max=%d",
				hash_desc->common.algo_id, OAKLEY_HASH_MAX);
		return_on(ret,-EINVAL);
	}
	if (hash_desc->hash_ctx_size > sizeof (union hash_ctx)) {
		plog ("ike_alg_register_hash(): hash alg=%d has "
				"ctx_size=%d > hash_ctx=%d",
				hash_desc->common.algo_id, 
				(int)hash_desc->hash_ctx_size,
				(int)sizeof (union hash_ctx));
		return_on(ret,-EOVERFLOW);
	}
	if (!(hash_desc->hash_init&&hash_desc->hash_update&&hash_desc->hash_final)) {
		plog ("ike_alg_register_hash(): hash alg=%d needs  "
				"hash_init(), hash_update() and hash_final()",
				hash_desc->common.algo_id);
		return_on(ret,-EINVAL);
	}

	alg_name=enum_name(&oakley_hash_names, hash_desc->common.algo_id);

	if (!alg_name) {
		plog ("ike_alg_register_hash(): WARNING: hash alg=%d not found in "
				"constants.c:oakley_hash_names  ",
				hash_desc->common.algo_id);
		alg_name="<NULL>";
	}
	
	if(hash_desc->common.name == NULL) {
	    hash_desc->common.name = clone_str(alg_name, "hasher name");
	}

return_out:
	if (ret==0)
		ret=ike_alg_add((struct ike_alg *)hash_desc);
	openswan_log("ike_alg_register_hash(): Activating %s: %s (ret=%d)", 
			alg_name, ret==0? "Ok" : "FAILED", ret);
	return ret;
}

/*
 * 	Validate and register IKE encryption algorithm object
 */
int
ike_alg_register_enc(struct encrypt_desc *enc_desc)
{
	const char *alg_name;
	int ret=0;

#if OAKLEY_ENCRYPT_MAX < 255
	if (enc_desc->common.algo_id > OAKLEY_ENCRYPT_MAX) {
		plog ("ike_alg_register_enc(): enc alg=%d < max=%d\n",
				enc_desc->common.algo_id, OAKLEY_ENCRYPT_MAX);
		return_on(ret, -EINVAL);
	}
#endif

	alg_name=enum_name(&oakley_enc_names, enc_desc->common.algo_id);
	if (!alg_name) {
		plog ("ike_alg_register_enc(): WARNING: enc alg=%d not found in "
				"constants.c:oakley_enc_names  ",
				enc_desc->common.algo_id);
		alg_name="<NULL>";
	}
#if OAKLEY_ENCRYPT_MAX < 255
return_out:
#endif

	if (ret==0)
		ret=ike_alg_add((struct ike_alg *)enc_desc);
	openswan_log("ike_alg_register_enc(): Activating %s: %s (ret=%d)", 
			alg_name, ret==0? "Ok" : "FAILED", ret);
	return 0;
}
/* Get pfsgroup for this connection */
const struct oakley_group_desc *
ike_alg_pfsgroup(struct connection *c, lset_t policy)
{
	const struct oakley_group_desc * ret = NULL;
	if ( (policy & POLICY_PFS) && 
			c->alg_info_esp && c->alg_info_esp->esp_pfsgroup)
		ret = lookup_group(c->alg_info_esp->esp_pfsgroup);
	return ret;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
