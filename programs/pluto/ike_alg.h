#ifndef _IKE_ALG_H
#define _IKE_ALG_H

#include <nss.h>
#include <pk11pub.h>

/*
 * Unification of cryptographic hashing mechanisms
 *
 * Better might be to define an anonymous struct, and then let each .c
 * file implement it.
 */

#ifdef USE_MD5
#include "md5.h"
#endif
#ifdef USE_SHA1
#include "sha1.h"
#endif
#ifdef USE_SHA2
#include "sha2.h"
#endif
#ifdef USE_AES
#include "aes_xcbc.h"
#endif

union hash_ctx {
#ifdef USE_MD5
	lsMD5_CTX ctx_md5;
#endif
#ifdef USE_SHA1
	SHA1_CTX ctx_sha1;
#endif
#ifdef USE_SHA2
	sha256_context ctx_sha256;
	sha384_context ctx_sha384;
	sha512_context ctx_sha512;
#endif
#ifdef USE_AES
	aes_xcbc_context ctx_aes_xcbc;
#endif
};

/*
 *	This could be just OAKLEY_XXXXXX_ALGORITHM, but it's
 *	here with other name as a way to assure that the
 *	algorithm hook type is supported (detected at compile time)
 */
enum ike_alg_type {
	IKE_ALG_ENCRYPT,
	IKE_ALG_HASH,
	IKE_ALG_INTEG,
};
#define	IKE_ALG_ROOF (IKE_ALG_INTEG+1)

/*
 * Common prefix for struct encrypt_desc and struct hash_desc.
 */
struct ike_alg {
	const char *name;	/* note: overwritten sometimes */
	const char *const officname;
	const enum ike_alg_type algo_type;
	/*
	 * These tables use the following numeric indexes:
	 *
	 *                  ENUM                ENUM->STRING                PREFIX
	 *
	 * ikev1_ike_id / struct ike_info:
	 *
	 * ENCRYPT:  ikev1_encr_attribute    oakley_enc_names              OAKLEY
	 * PRF:      ikev1_hash_attribute    oakley_hash_names             OAKLEY
	 * INTEG:    ikev1_hash_attribute    oakley_hash_names             OAKLEY
	 *
	 * ikev1_esp_id / struct esp_info:
	 *
	 * ENCRYPT:  ipsec_cipher_algo       esp_transformid_names         ESP
	 * INTEG:    ikev1_auth_attribute    auth_alg_names                AUTH_ALGORITHM
	 *
	 * ikev2_id:
	 *
	 * ENCRYPT:  ikev2_trans_type_encr   ikev2_trans_type_encr_names   IKEv2_ENCR
	 * PRF:      ikev2_trans_type_prf    ikev2_trans_type_prf_names    IKEv2_AUTH
	 * INTEG:    ikev2_trans_type_integ  ikev2_trans_type_integ_names  IKEv2_INTEG
	 *
	 * Notes:
	 *
	 * For ESP/AH, since PRF is not negotiated (the IKE SA's PRF
	 * is used) the field "PRF.ikev1_esp_id" should be left blank.
	 * Since, for IKEv2, "PRF.ikev2_id" is used by IKE, it should
	 * be defined.
	 *
	 * "struct ike_info" uses ikev1_ike_id values as defined
	 * above.  See plutoalg.c:ealg_getbyname_ike() and
	 * plutoalg.c:aalg_getbyname_ike().
	 *
	 * "struct esp_info" uses ikev1_esp_id values as defined
	 * above.  See alg_info.c:ealg_getbyname_esp() and
	 * alg_info.c:aalg_getbyname_esp().
	 *
	 * This doesn't deal with kernel codes (some kernel interfaces
	 * use numbers, some use strings), for moment keep them in a
	 * separate table.
	 *
	 * XXX: Still missing is a name/alias lookup letting some of
	 * alg_info be eliminated.
	 *
	 * XXX: As you can tell, there is a rename comming.
	 */
	const u_int16_t algo_id;	/* const int ikev1_ike_id */
	const int ikev1_esp_id;
	const u_int16_t algo_v2id;	/* const int ikev2_id */
	/*
	 * Is this algorithm FIPS approved (i.e., can be enabled in
	 * FIPS mode)?
	 */
	const bool fips;
	/*
	 * Test the algorithm's native (in process) implementation.
	 * Return TRUE if it works; FALSE otherwise.  Only algorithms
	 * with a working native implementation are suitable for IKE
	 * (phase 1 in IKEv1).
	 *
	 * ESP/AH only algorithms should default this field to NULL.
	 *
	 * XXX: While not exactly an ideal way to do this, it works.
	 */
	bool (*const do_ike_test)(const struct ike_alg*);
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

typedef void (*hash_update_t)(union hash_ctx *, const u_char *, size_t);

struct hash_desc {
	struct ike_alg common;	/* MUST BE FIRST */
	const size_t hash_key_size;	/* in bits */
	const size_t hash_ctx_size;
	const size_t hash_digest_len;
	const size_t hash_block_size;
	void (*const hash_init)(union hash_ctx *ctx);
	const hash_update_t hash_update;
	void (*const hash_final)(u_int8_t *out, union hash_ctx *ctx);
};

/*
 * PRF_DESC and INTEG_DESC extend HASH_DESC.
 *
 * XXX: In fact, for the moment, they are identical.  If nothing else,
 * HASH_INTEG_LEN should be moved out of HASH_DESC.
 *
 * XXX: Could also make hash_desc a separate structure.
 */

struct prf_desc {
	struct hash_desc hasher;
};

struct integ_desc {
	struct hash_desc hasher;
	const size_t integ_hash_len;	/* truncated output len */
};

/*
 * Find an IKEv2 IKE_ALG using wire-values:
 *
 * ike[12]_get_encrypt_desc(enum) and ikev2_get_integ_desc(enum):
 * return the specified algorithm; else return NULL.  In the case of
 * ESP/AH native support isn't required.  Further, because of races
 * such as a crypto module being loaded, it is only really possible to
 * detect support for ESP/AH at the time the XFRM entry is added.
 *
 * ikeN_get_ike_XXX_desc(enum): return the specified algorithm but
 * only if there is a native (in process) support; else return NULL.
 * The initial IKE negotiation (phase 1 in IKEv1?) is implemented
 * using native (in process) crypto.  Similarly, the CHILD_SA
 * negotiation, uses the native IKE PRF when computing its keying
 * material.
 *
 * The enum lookups are intended for wire data (in and out).
 * Unfortunately, they are also used to lookup "struct alg_info"
 * elements.
 */

const struct encrypt_desc *ikev1_get_encrypt_desc(enum ikev1_encr_attribute);
const struct prf_desc *ikev1_get_prf_desc(enum ikev1_auth_attribute);
const struct integ_desc *ikev1_get_integ_desc(enum ikev1_auth_attribute);

const struct encrypt_desc *ikev2_get_encrypt_desc(enum ikev2_trans_type_encr);
const struct prf_desc *ikev2_get_prf_desc(enum ikev2_trans_type_prf);
const struct integ_desc *ikev2_get_integ_desc(enum ikev2_trans_type_integ);

const struct encrypt_desc *ikev1_get_ike_encrypt_desc(enum ikev1_encr_attribute);
const struct prf_desc *ikev1_get_ike_prf_desc(enum ikev1_auth_attribute);
const struct integ_desc *ikev1_get_ike_integ_desc(enum ikev1_auth_attribute);

/*
 * Return the ENCRYPT/PRF/INTEG IKE_ALG as specified by IKE_INFO or
 * ESP_INFO.
 *
 * For IKE_INFO, the lookup is limited to native algorithms.  For
 * ESP_INFO there is no such limitation.
 *
 * Since IKE_INFO and ESP_INFO use IKEv1 numbers to identify the
 * relevant algorithm, these functions have an IKEv1 prefix.
 *
 * XXX: IKE_INFO/ESP_INFO should instead contain IKE_ALG pointers and
 * be done with all this.  Presumably that would mean adding a
 * lookup-by-string function to IKE_ALG.
 */

struct ike_info;

const struct encrypt_desc *ikev1_get_ike_info_encrypt_desc(const struct ike_info*);
const struct prf_desc *ikev1_get_ike_info_prf_desc(const struct ike_info*);
const struct integ_desc *ikev1_get_ike_info_integ_desc(const struct ike_info*);

struct esp_info;

const struct encrypt_desc *ikev1_get_esp_info_encrypt_desc(const struct esp_info*);
const struct integ_desc *ikev1_get_esp_info_integ_desc(const struct esp_info*);

/*
 * Older interfaces.
 */
extern bool ike_alg_enc_present(int ealg);
extern bool ike_alg_hash_present(int halg);
extern bool ike_alg_enc_requires_integ(const struct encrypt_desc *enc_desc);

void ike_alg_init(void);

const struct encrypt_desc *ikev1_alg_get_encrypter(int alg);
const struct hash_desc *ikev1_alg_get_hasher(int alg);

const struct encrypt_desc *ikev2_alg_get_encrypter(int alg);

/*
 * Return true always.
 *
 * Useful default for ike_alg.do_ike_test().
 */
extern bool ike_alg_true(const struct ike_alg*);

/*
 * Iterate over the IKE enabled algorithms.
 */
const struct encrypt_desc **next_ike_encrypt_desc(const struct encrypt_desc **last);
const struct hash_desc **next_ike_prf_desc(const struct hash_desc **last);

/* Oakley group descriptions */

struct oakley_group_desc {
	u_int16_t group;
	const char *gen;
	const char *modp;
	size_t bytes;
};

extern const struct oakley_group_desc unset_group;      /* magic signifier */
extern const struct oakley_group_desc *lookup_group(u_int16_t group);
const struct oakley_group_desc *next_oakley_group(const struct oakley_group_desc *);

#endif /* _IKE_ALG_H */
