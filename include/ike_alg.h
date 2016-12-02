#ifndef _IKE_ALG_H
#define _IKE_ALG_H

#include <nss.h>
#include <pk11pub.h>

/*
 * Different algorithms used by IKEv1/IKEv2.
 */
enum ike_alg_type {
	/* 0 is invalid */
	IKE_ALG_ENCRYPT = 1,
	IKE_ALG_HASH,
	IKE_ALG_PRF,
	IKE_ALG_INTEG,
	IKE_ALG_DH,
};
#define IKE_ALG_FLOOR IKE_ALG_ENCRYPT
#define	IKE_ALG_ROOF (IKE_ALG_DH+1)

/*
 * Common prefix for struct encrypt_desc and struct hash_desc (struct
 * prf_desc and struct integ_desc).
 *
 * These tables use the following numeric indexes:
 *
 * USE       ENUM                       ENUM->STRING                  PREFIX
 *
 * ikev2_id / IKEv2 IKE / IKEv2 ESP / IKEv2 AH / IKEv2 DH:
 *
 * Almost no confusion.  DH is using IKEv1.
 *
 * ENCRYPT:  ikev2_trans_type_encr      ikev2_trans_type_encr_names   IKEv2_ENCR
 * PRF:      ikev2_trans_type_prf       ikev2_trans_type_prf_names    IKEv2_AUTH
 * INTEG:    ikev2_trans_type_integ     ikev2_trans_type_integ_names  IKEv2_INTEG
 *
 * ikev1_oakley_id / struct ike_info.ike_ealg / struct ike_info.ike_halg:
 *
 * The only querk here is the use of the HASH (PRF) to select INTEG.
 * The suffix "oakley_id", rather than "ike_id" or "id", is used since
 * it is consistent with the enum values this field contains
 * (apparently IKEv1 IKE (phase 1) is based on the OAKLEY protocol).
 * See ealg_getbyname_ike() and aalg_getbyname_ike().
 *
 * ENCRYPT:  ikev1_encr_attribute       oakley_enc_names              OAKLEY
 * PRF:      ikev1_hash_attribute       oakley_hash_names             OAKLEY
 * INTEG:    ikev1_hash_attribute       oakley_hash_names             OAKLEY
 *
 * ikev1_esp_info_id (ikev1_esp_id) / struct esp_info.transid / struct esp_info.auth:
 *
 * Here be trouble.  While the obvious problem is that struct esp_info
 * is using both IKEv1 (INTEG) and IPSEC (ENCRYPT) enum types, that is
 * of no real importance.  The real issue here is with INTEG where
 * things have badly convoluted IKEv1 and IKEv2 ESP numbers and names.
 * For instance, while the enum ipsec_cipher_algo contains
 * ESP_CAMELLIA=23 (IKEv2), the name table esp_transformid_names
 * returns 22 (IKEv1) for the string "ESP_CAMELLIA".  See
 * ealg_getbyname_esp() and aalg_getbyname_esp().
 *
 * ENCRYPT:  ipsec_cipher_algo          esp_transformid_names         ESP
 * INTEG:    ikev1_auth_attribute       auth_alg_names                AUTH_ALGORITHM
 *
 * (not yet if ever) ikev[12]_ipsec_id:
 *
 * While these values started out being consistent with IKEv1 and (I
 * suspect) SADB/KLIPS, the've gone off the rails.  Over time they've
 * picked up IKEv2 values making for general confusion.  Worse, as noted above, For instance,
 * CAMELLIA has the IKEv2 value 23 (IKEv1 is 22) resulting in code
 * never being sure if which it is dealing with.
 *
 * These values are not included in this table.
 *
 * ENCRYPT:  ipsec_cipher_algo          esp_transformid_names         ESP
 * INTEG:    ipsec_authentication_algo  ah_transformid_names          AH
 *
 * (not yet if ever) SADB / KLIPS:
 *
 * These values, which I suspect are used to interface with KLIPS,
 * seem to follow the original IKEv1 ESP/AH numbering (which means
 * that they almost but not quite match the mashed up values above).
 *
 * These values are not included in this table
 *
 * ENCRYPT:  sadb_ealg                  ?                             K_SADB*EALG
 * INTEG:    sadb_aalg                  ?                             K_SADB*AALG
 *
 * (not yet if ever) XFRM names:
 *
 * The XFRM interface uses strings to identify algorithms.
 *
 * Notes:
 *
 * For ESP/AH, since the PRF is not negotiated (the IKE SA's PRF is
 * used) the field "PRF.ikev1_esp_id" should be left blank.  Since,
 * for IKEv2, "PRF.ikev2_id" is used by IKE, it should be defined.
 *
 * XXX: Still missing is a name/alias lookup letting some of alg_info
 * be eliminated.
 */
struct ike_alg {
	/*
	 * ??? why two names ???
	 *
	 * Seemingly (see ikev2.c:ikev2_log_parentSA()) OFFICNAME is
	 * expected to match tcpdump's -E option.  A check of the
	 * tcpdump man page would suggest otherwise.  For instance,
	 * "aes" vs "aes-cbc".
	 */
	const char *name;
	const char *const officname;
	/*
	 * See above.
	 */
	const enum ike_alg_type algo_type;
	const u_int16_t ikev1_oakley_id;
	const int ikev1_esp_id;
	const int ikev2_id;
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

	/*
	 * The NSS mechanism used to implement this algorithm
	 * (assuming NSS).
	 *
	 * Note that the SYMKEY object passed to NSS also need to have
	 * the mechanism (type) set to this value.  If it isn't, the
	 * the operation fails.
	 *
	 * For non-NSS algorithms, leave this blank (i.e., 0).  While,
	 * technically, 0 is CKM_RSA_PKCS_KEY_PAIR_GEN, that mechanism
	 * has no meaning in this context so it is safe.
	 */
	CK_MECHANISM_TYPE nss_mechanism;
};

struct encrypt_desc {
	struct ike_alg common;	/* MUST BE FIRST and writable */
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

	/*
	 * Should the key-length attribute be omitted when
	 * constructing the proposal's encrypt transform?
	 *
	 * Conversely, should a proposal be accepted when the encrypt
	 * transform contains no key-length?
	 */
	const bool keylen_omitted;

	/*
	 * Array of valid key lengths in bits.
	 *
	 * - must be zero terminated; makes iterating easier.
	 *
	 * - must contain at least one entry; else what is going on.
	 *
	 * - must be in descending order; so max value is first.
	 *
	 * If a key-length is required (!keylen_omitted) but omitted
	 * from the {ike,esp}= line, then both KEYDEFLEN and (if
	 * different) key_bit_lengths[0] are used in proposals.
	 */
	const unsigned key_bit_lengths[4];

	/*
	 * The default key length.
	 *
	 * XXX: this is not the _prefered_ key length.  IKEv2 IKE
	 * prefers key_bit_lengths[0], while IKEv2 ESP/AH prefer
	 * KEYDEFLEN.  Weird.
	 */
	const unsigned keydeflen;

	/*
	 * Perform simple encryption.
	 *
	 * Presumably something else is implementing the integrity.
	 */
	void (*const do_crypt)(const struct encrypt_desc *alg,
			       u_int8_t *dat,
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
	bool (*const do_aead_crypt_auth)(const struct encrypt_desc *alg,
					 u_int8_t *salt, size_t salt_size,
					 u_int8_t *wire_iv, size_t wire_iv_size,
					 u_int8_t *aad, size_t aad_size,
					 u_int8_t *text_and_tag,
					 size_t text_size, size_t tag_size,
					 PK11SymKey *key, bool enc);
};

/*
 * A "hash" algorithm is used to compute a simple message
 * authentication code.
 */

struct hash_desc {
	struct ike_alg common;	/* MUST BE FIRST */
	const size_t hash_digest_len;
	const size_t hash_block_size;
	const struct hash_ops *hash_ops;
};

/*
 * Generic implementation of HASH_DESC.
 */
struct hash_context;

struct hash_ops {
	struct hash_context *(*init)(const struct hash_desc *hash_desc,
				     const char *name, lset_t debug);
	void (*digest_symkey)(struct hash_context *hash,
			      const char *name, PK11SymKey *symkey);
	void (*digest_bytes)(struct hash_context *hash,
			     const char *name,
			     const u_int8_t *bytes, size_t sizeof_bytes);
	void (*final_bytes)(struct hash_context**,
			    u_int8_t *bytes, size_t sizeof_bytes);
	/* FIPS short cuts */
	PK11SymKey *(*symkey_to_symkey)(const struct hash_desc *hash_desc,
					const char *name, lset_t debug,
					const char *symkey_name, PK11SymKey *symkey);
};

/*
 * Pseudo Random Function:
 *
 *     PRF(<key>, <data>) -> digest
 *
 * While some PRFs are implemented using HMAC (for instance,
 * HMAC_SHA1), some are not (for instance, AES_CMAC).
 */
struct prf_desc {
	struct ike_alg common;	/* MUST BE FIRST */
	/*
	 * Prefered key size of the PRF.
	 *
	 * IKEv2 2.13: It is assumed that PRFs accept keys of any
	 * length, but have a preferred key size.  The preferred key
	 * size MUST be used as the length of SK_d, SK_pi, and SK_pr.
	 * For PRFs based on the HMAC construction, the preferred key
	 * size is equal to the length of the output of the underlying
	 * hash function.  Other types of PRFs MUST specify their
	 * preferred key size.
	*/
	size_t prf_key_size;
	/*
	 * Number of pseudo-random bytes returned by the PRF.
	 *
	 * IKEv2 2.13: Keying material will always be derived as the
	 * output of the negotiated PRF algorithm.  Since the amount
	 * of keying material needed may be greater than the size of
	 * the output of the PRF, the PRF is used iteratively.  The
	 * term "prf+" describes a function that outputs a
	 * pseudorandom stream based on the inputs to a pseudorandom
	 * function called "prf".
	 */
	size_t prf_output_size;
	/*
	 * For native-IKE.  The HASHER used by the HMAC construction.
	 *
	 * Non-NULL IFF there is a native implementation.
	 *
	 * If non-NULL its values must be consistent with the above.
	 */
	struct hash_desc *hasher;
	/*
	 * FIPS controlled native implementation.
	 */
	const struct prf_ops *prf_ops;
};

struct prf_ops {
	struct prf_context *(*init_symkey)(const struct prf_desc *prf_desc,
					   const char *name, lset_t debug,
					   const char *key_name, PK11SymKey *key);
	struct prf_context *(*init_bytes)(const struct prf_desc *prf_desc,
					  const char *name, lset_t debug,
					  const char *key_name,
					  const u_int8_t *bytes, size_t sizeof_bytes);
	void (*digest_symkey)(struct prf_context *prf,
			      const char *name, PK11SymKey *symkey);
	void (*digest_bytes)(struct prf_context *prf,
			     const char *name, const u_int8_t *bytes, size_t sizeof_bytes);
	PK11SymKey *(*final_symkey)(struct prf_context **prf);
	void (*final_bytes)(struct prf_context **prf, u_int8_t *bytes, size_t sizeof_bytes);
};

/*
 * Data Integrity.
 *
 * Currently all implementations use:
 *
 *    sizeof(<key>) == integ->integ_key_size
 *    TRUNC(integ->prf(<key>,<data>), integ->integ_output_size)
 *
 * However only IKE needs the PRF definition.  ESP/AH leave it to the
 * kernel.
 */
struct integ_desc {
	struct ike_alg common;	/* MUST BE FIRST */
	/*
	 * Number of secret bytes needed to prime the integ algorithm.
	 *
	 * If there's an IKE PRF implementation, then these values
	 * need to be consistent with the PRF.
	 */
	const size_t integ_key_size;
	/*
	 * The size of the output from the integrity algorithm.  This
	 * is put on the wire as "Integrity Checksum Data".
	 *
	 * If there's an IKE PRF implementation, then this must be <=
	 * the PRF's output size and if that is implemented using a
	 * HMAC construction, then it matches the HASH digest size.
	 *
	 * But none of that can be assumed.
	 */
	const size_t integ_output_size;
	/*
	 * For IKE.  The PRF implementing integrity.  The output is
	 * truncated down to INTEG_HASH_LEN.
	 *
	 * Non-NULL IFF there is a native implementation.
	 */
	struct prf_desc *prf;
};

/*
 * Find the IKEv2 ENCRYPT/PRF/INTEG algorithm using IKEv2 wire-values.
 *
 * The returned algorithm may not have native support.  Native
 * algorithms have do_ike_test non-NULL.
 */

const struct encrypt_desc *ikev2_get_encrypt_desc(enum ikev2_trans_type_encr);
const struct prf_desc *ikev2_get_prf_desc(enum ikev2_trans_type_prf);
const struct integ_desc *ikev2_get_integ_desc(enum ikev2_trans_type_integ);

/*
 * Find the IKEv1 ENCRYPT/PRF/INTEG algorithm using IKEv1 OAKLEY
 * values.
 *
 * Unlike IKEv2, IKEv1 uses different wire-values for IKE, ESP, and
 * AH.  This just deals with OAKLEY.
 */

const struct encrypt_desc *ikev1_get_ike_encrypt_desc(enum ikev1_encr_attribute);
const struct prf_desc *ikev1_get_ike_prf_desc(enum ikev1_auth_attribute);
const struct integ_desc *ikev1_get_ike_integ_desc(enum ikev1_auth_attribute);

/*
 * Does the encryption algorithm require separate integrity (FALSE
 * implies AEAD).
 */

extern bool ike_alg_enc_requires_integ(const struct encrypt_desc *enc_desc);

void ike_alg_init(void);

/*
 * Iterate over all enabled algorithms.
 */
const struct encrypt_desc **next_encrypt_desc(const struct encrypt_desc **last);
const struct prf_desc **next_prf_desc(const struct prf_desc **last);
const struct integ_desc **next_integ_desc(const struct integ_desc **last);

/*
 * Is the algorithm suitable for IKE (i.e., native)?
 *
 * Code should also filter on ikev1_oakley_id and/or ikev2_id.
 */
bool ike_alg_is_ike(const struct ike_alg *alg);

/*
 * Is the key valid for the encryption algorithm?
 */
bool encrypt_has_key_bit_length(const struct encrypt_desc *encrypt_desc, unsigned keylen);

/*
 * The largest key size allowed.
 */
unsigned encrypt_max_key_bit_length(const struct encrypt_desc *encrypt_desc);

/* Oakley group descriptions */

struct oakley_group_desc {
	struct ike_alg common;		/* must be first */
	u_int16_t group;
	const char *gen;
	const char *modp;
	size_t bytes;
};

extern const struct oakley_group_desc unset_group;      /* magic signifier */
extern const struct oakley_group_desc *lookup_group(u_int16_t group);
const struct oakley_group_desc **next_oakley_group(const struct oakley_group_desc **);

#endif /* _IKE_ALG_H */
