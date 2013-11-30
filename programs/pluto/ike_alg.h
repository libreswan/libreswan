#ifndef _IKE_ALG_H
#define _IKE_ALG_H

/* forward reference */
struct connection;

struct ike_alg {
	const char *name;
	const char *officname;
	u_int16_t algo_type;
	u_int16_t algo_id; /* either hash or enc algo id */
	u_int16_t algo_v2id; /* either hash or enc algo id */
	struct ike_alg *algo_next;
};

struct encrypt_desc {
	struct ike_alg common;
	size_t enc_ctxsize;
	size_t enc_blocksize;
/* Is this always true?  usually with CBC methods. Maybe not with others */
#define iv_size enc_blocksize
	unsigned keydeflen;
	unsigned keymaxlen;
	unsigned keyminlen;
	void (*do_crypt)(u_int8_t *dat,
			 size_t datasize,
			 u_int8_t *key,
			 size_t key_size,
			 u_int8_t *iv,
			 bool enc);
};

typedef void (*hash_update_t)(void *, const u_char *, size_t);

struct hash_desc {
	struct ike_alg common;
	size_t hash_key_size;      /* in bits */
	size_t hash_ctx_size;
	size_t hash_digest_len;
	size_t hash_integ_len;    /*truncated output len when used as an integrity algorithm in IKEV2*/
	size_t hash_block_size;
	void (*hash_init)(void *ctx);
	hash_update_t hash_update;
	void (*hash_final)(u_int8_t *out, void *ctx);
};

struct alg_info_ike; /* forward reference */
struct alg_info_esp;

extern struct db_context *ike_alg_db_new(struct alg_info_ike *ai, lset_t policy);

extern void ike_alg_show_status(void);
extern void ike_alg_show_connection(struct connection *c, const char *instance);

#define IKE_EALG_FOR_EACH(a) \
	for ((a) = ike_alg_base[IKE_ALG_ENCRYPT]; (a) != NULL; (a) = (a)->algo_next)

#define IKE_HALG_FOR_EACH(a) \
	for ((a) = ike_alg_base[IKE_ALG_HASH]; (a) != NULL; (a) = (a)->algo_next)

extern bool ike_alg_enc_present(int ealg);
extern bool ike_alg_hash_present(int halg);
extern bool ike_alg_enc_ok(int ealg, unsigned key_len,
		    struct alg_info_ike *alg_info_ike, const char **, char *,
		    size_t);
extern bool ike_alg_ok_final(int ealg, unsigned key_len, int aalg, unsigned int group,
		      struct alg_info_ike *alg_info_ike);

/*
 *	This could be just OAKLEY_XXXXXX_ALGORITHM, but it's
 *	here with other name as a way to assure that the
 *	algorithm hook type is supported (detected at compile time)
 */
#define IKE_ALG_ENCRYPT 0
#define IKE_ALG_HASH    1
#define IKE_ALG_INTEG   2
#define IKE_ALG_ROOF	3
extern struct ike_alg *ike_alg_base[IKE_ALG_ROOF];
extern void ike_alg_add(struct ike_alg *);
extern int ike_alg_register_enc(struct encrypt_desc *e);
extern int ike_alg_register_hash(struct hash_desc *a);
extern struct ike_alg *ikev1_alg_find(unsigned algo_type,
			     unsigned algo_id);

extern struct ike_alg *ikev2_alg_find(unsigned algo_type,
				   enum ikev2_trans_type_encr algo_v2id);

static __inline__ struct hash_desc *ike_alg_get_hasher(int alg)
{
	return (struct hash_desc *) ikev1_alg_find(IKE_ALG_HASH, alg);
}

static __inline__ struct encrypt_desc *ike_alg_get_encrypter(int alg)
{
	return (struct encrypt_desc *) ikev1_alg_find(IKE_ALG_ENCRYPT, alg);
}

extern const struct oakley_group_desc *ike_alg_pfsgroup(struct connection *c,
						  lset_t policy);

extern struct db_sa *oakley_alg_makedb(struct alg_info_ike *ai,
				       struct db_sa *basic,
				       int maxtrans);

extern struct db_sa *kernel_alg_makedb(lset_t policy,
				       struct alg_info_esp *ei,
				       bool logit);

/* exports from ike_alg_*.c */

#ifdef USE_TWOFISH
extern int ike_alg_twofish_init(void);
#endif

#ifdef USE_SERPENT
extern int ike_alg_serpent_init(void);
#endif

#ifdef USE_AES
extern int ike_alg_aes_init(void);
#endif

#ifdef USE_SHA2
extern int ike_alg_sha2_init(void);
#endif


#endif /* _IKE_ALG_H */
