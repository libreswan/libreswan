#ifndef _IKE_ALG_H
#define _IKE_ALG_H

#include <nss.h>
#include <pk11pub.h>

#include "camellia.h"

struct connection;	/* forward declaration */

/* common prefix for struct encrypt_desc and struct hash_desc
 * Read-only except for name and algo_next.
 */
struct ike_alg {
	const char *name;	/* note: overwritten sometimes */
	const char *const officname;
	const u_int16_t algo_type;
	const u_int16_t algo_id;	/* either hash or enc algo id */
	const u_int16_t algo_v2id;	/* either hash or enc algo id */
	const struct ike_alg *algo_next;
};

struct encrypt_desc {
	struct ike_alg common;	/* MUST BE FIRST and writable */
	const size_t enc_ctxsize;
	const size_t enc_blocksize;
	/*
	 * Does this algorithm require padding to the above
	 * ENC_BLOCKSIZE bytes?
	 *
	 * This shouldn't be confused with the need to pad things to
	 * 4-bytes (ESP) or not at all (IKE).
	 */
	const bool pad_to_blocksize;
	/*
	 * Number of additional bytes that should be extracted from
	 * the initial shared-secret.
	 *
	 * CTR calls this nonce; CCM calls it salt.
	 */
	const size_t salt_size;
	/*
	 * The IV sent across the wire; this is random material.
	 *
	 * The WIRE-IV which will be sent across the wire in public.
	 * The SALT, WIRE-IV, and who-knows what else are concatenated
	 * to form a ENC_BLOCKSIZE-byte starting-variable (aka IV).
	 */
	const size_t wire_iv_size;

	const unsigned keydeflen;
	const unsigned keymaxlen;
	const unsigned keyminlen;
	void (*const do_crypt)(u_int8_t *dat,
			 size_t datasize,
			 PK11SymKey *key,
			 u_int8_t *iv,
			 bool enc);

	/*
	 * For Authenticated Encryption with Associated Data (AEAD),
	 * the size (in 8-bit bytes) of the authentication tag
	 * appended to the end of the encrypted data.
	*/
	const size_t aead_tag_size;

	/*
	 * Perform Authenticated Encryption with Associated Data
	 * (AEAD).
	 *
	 * The salt and wire-IV are concatenated to form the NONCE
	 * (aka. counter variable; IV; ...).
	 *
	 * The Additional Authentication Data (AAD) and the
	 * cipher-text are concatenated when generating/validating the
	 * tag (which is appended to the text).
	 *
	 * All sizes are in 8-bit bytes.
	 */
	bool (*const do_aead_crypt_auth)(u_int8_t *salt, size_t salt_size,
				   u_int8_t *wire_iv, size_t wire_iv_size,
				   u_int8_t *aad, size_t aad_size,
				   u_int8_t *text_and_tag,
				   size_t text_size, size_t tag_size,
				   PK11SymKey *key, bool enc);
};

union hash_ctx;	/* forward declaration */

typedef void (*hash_update_t)(union hash_ctx *, const u_char *, size_t);

struct hash_desc {
	struct ike_alg common;	/* MUST BE FIRST */
	const size_t hash_key_size;	/* in bits */
	const size_t hash_ctx_size;
	const size_t hash_digest_len;
	const size_t hash_integ_len;	/* truncated output len when used as an integrity algorithm in IKEV2 */
	const size_t hash_block_size;
	void (*const hash_init)(union hash_ctx *ctx);
	const hash_update_t hash_update;
	void (*const hash_final)(u_int8_t *out, union hash_ctx *ctx);
};

struct alg_info_ike; /* forward reference */
struct alg_info_esp;

extern struct db_context *ike_alg_db_new(struct alg_info_ike *ai, lset_t policy);

extern void ike_alg_show_status(void);
extern void ike_alg_show_connection(const struct connection *c, const char *instance);

/* ??? a is type struct ike_alg * but should be struct encrypt_desc * */
#define IKE_EALG_FOR_EACH(a) \
	for ((a) = ike_alg_base[IKE_ALG_ENCRYPT]; (a) != NULL; (a) = (a)->algo_next)

/* ??? a is type struct ike_alg * but should be struct hash_desc * */
#define IKE_HALG_FOR_EACH(a) \
	for ((a) = ike_alg_base[IKE_ALG_HASH]; (a) != NULL; (a) = (a)->algo_next)

extern bool ike_alg_enc_present(int ealg);
extern bool ike_alg_hash_present(int halg);
extern bool ike_alg_enc_requires_integ(const struct encrypt_desc *enc_desc);
extern bool ike_alg_enc_ok(int ealg, unsigned key_len,
		    struct alg_info_ike *alg_info_ike,
		    const char **errp,
		    char *ugh_buf, size_t ugh_buf_len);
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
extern const struct ike_alg *ike_alg_base[IKE_ALG_ROOF];
extern void ike_alg_add(struct ike_alg *);
extern bool ike_alg_register_enc(struct encrypt_desc *e);
extern bool ike_alg_register_hash(struct hash_desc *a);
extern const struct ike_alg *ikev1_alg_find(unsigned algo_type,
			     unsigned algo_id);

extern const struct ike_alg *ikev2_alg_find(unsigned algo_type,
				   enum ikev2_trans_type_encr algo_v2id);

static __inline__ const struct hash_desc *ike_alg_get_hasher(int alg)
{
	return (const struct hash_desc *) ikev1_alg_find(IKE_ALG_HASH, alg);
}

static __inline__ const struct encrypt_desc *ike_alg_get_encrypter(int alg)
{
	return (const struct encrypt_desc *) ikev1_alg_find(IKE_ALG_ENCRYPT, alg);
}

extern const struct oakley_group_desc *ike_alg_pfsgroup(struct connection *c,
						  lset_t policy);

extern struct db_sa *oakley_alg_makedb(struct alg_info_ike *ai,
				       struct db_sa *basic,
				       bool single_dh);

extern struct db_sa *kernel_alg_makedb(lset_t policy,
				       struct alg_info_esp *ei,
				       bool logit);

/* exports from ike_alg_*.c */

#ifdef USE_TWOFISH
extern void ike_alg_twofish_init(void);
#endif

#ifdef USE_SERPENT
extern void ike_alg_serpent_init(void);
#endif

#ifdef USE_AES
extern void ike_alg_aes_init(void);
#endif

#ifdef USE_CAMELLIA
extern void ike_alg_camellia_init(void);
#endif

#ifdef USE_SHA2
extern void ike_alg_sha2_init(void);
#endif

CK_MECHANISM_TYPE nss_encryption_mech(const struct encrypt_desc *encrypter);

#endif /* _IKE_ALG_H */
