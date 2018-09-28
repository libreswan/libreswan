#ifndef _IKE_ALG_H
#define _IKE_ALG_H

#include <stdbool.h>	/* for bool */
#include <nss.h>
#include <pk11pub.h>
#include "shunk.h"
#include "ietf_constants.h"

struct ike_alg;
struct lswlog;
enum ike_alg_key;

/*
 * More meaningful passert.
 *
 * Do not wrap ASSERTION in parentheses as it will suppress the
 * warning for 'foo = bar'.
 */

#define lswlog_ike_alg(BUF, ALG)					\
	lswlogf(BUF, "IKE_ALG %s algorithm '%s'",			\
		ike_alg_type_name((ALG)->algo_type),			\
		(ALG)->fqn != NULL ? (ALG)->fqn				\
		: (ALG)->name != NULL ? (ALG)->name			\
		: "NULL")

#define pexpect_ike_alg(ALG, ASSERTION) {				\
		/* wrapping ASSERTION in parens suppresses -Wparen */	\
		bool assertion__ = ASSERTION; /* no paren */		\
		if (!assertion__) {					\
			LSWLOG_PEXPECT(buf) {				\
				lswlog_ike_alg(buf, ALG);	\
				lswlogs(buf, " fails: " #ASSERTION);	\
			}						\
		}							\
	}

#define pexpect_ike_alg_streq(ALG, LHS, RHS)				\
	{								\
		/* wrapping ASSERTION in parens suppresses -Wparen */	\
		const char *lhs = LHS;					\
		const char *rhs = RHS;					\
		if (lhs == NULL || rhs == NULL || !streq(LHS, RHS)) {	\
			LSWLOG_PEXPECT(buf) {				\
				lswlog_ike_alg(buf, ALG);	\
				lswlogf(buf, " fails: %s != %s (%s != %s)", \
					lhs, rhs, #LHS, #RHS);		\
			}						\
		}							\
	}

#define pexpect_ike_alg_strcaseeq(ALG, LHS, RHS)			\
	{								\
		/* wrapping ASSERTION in parens suppresses -Wparen */	\
		const char *lhs = LHS;					\
		const char *rhs = RHS;					\
		if (lhs == NULL || rhs == NULL || !strcaseeq(LHS, RHS)) { \
			LSWLOG_PEXPECT(buf) {				\
				lswlog_ike_alg(buf, ALG);	\
				lswlogf(buf, " fails: %s != %s (%s != %s)", \
					ike_alg_type_name((ALG)->algo_type), \
					(ALG)->fqn, lhs, rhs, #RHS, #LHS); \
			}						\
		}							\
	}

/*
 * Different algorithm classes used by IKEv1/IKEv2 protocols.
 */

struct ike_alg_type;

extern const struct ike_alg_type ike_alg_encrypt;
extern const struct ike_alg_type ike_alg_hash;
extern const struct ike_alg_type ike_alg_prf;
extern const struct ike_alg_type ike_alg_integ;
extern const struct ike_alg_type ike_alg_dh;

/* keep old code working */
#define IKE_ALG_ENCRYPT &ike_alg_encrypt
#define IKE_ALG_HASH &ike_alg_hash
#define IKE_ALG_PRF &ike_alg_prf
#define IKE_ALG_INTEG &ike_alg_integ
#define IKE_ALG_DH &ike_alg_dh

/*
 * User frendly string representing the algorithm type (family).
 * "...Name()" returns the capitalized name.
 */
const char *ike_alg_type_name(const struct ike_alg_type *type);
const char *ike_alg_type_Name(const struct ike_alg_type *type);

/*
 * Different lookup KEYs used by IKEv1/IKEv2
 */
enum ike_alg_key {
	IKEv1_OAKLEY_ID,
	IKEv1_ESP_ID,
	IKEv2_ALG_ID,

	IKE_ALG_KEY_ROOF,
	IKE_ALG_KEY_FLOOR = IKEv1_OAKLEY_ID
};

/*
 * User friendly string representing the key (protocol family).
 */
const char *ike_alg_key_name(enum ike_alg_key key);

/*
 * Look for NAME within TYPE algorithms.
 *
 * The first version uses the "ike_alg" tables only.
 *
 * The second variant uses the ietf_constant.h enum tables and is only
 * intended as a way to identify algorithms defined by IETF but not
 * supported here.
 */
const struct ike_alg *ike_alg_byname(const struct ike_alg_type *type,
				     shunk_t name);
int ike_alg_enum_match(const struct ike_alg_type *type, enum ike_alg_key key,
		       shunk_t name);

/*
 * Common prefix for struct encrypt_desc and struct hash_desc (struct
 * prf_desc and struct integ_desc).
 *
 * These tables use the following numeric indexes:
 *
 * TYPE      ENUM                       ENUM->STRING                  PREFIX
 *
 *
 * id[IKEv2_ALG_ID]:
 *
 * Used by: IKEv2 IKE, IKEv2 ESP, IKEv2 AH, IKEv2 DH
 *
 * Almost no confusion.  While IKEv2 DH uses the the IKEv1
 * OAKLEY_GROUP enum, there are no conflicts so things work.
 *
 * ENCRYPT:  ikev2_trans_type_encr      ikev2_trans_type_encr_names   IKEv2_ENCR
 * PRF:      ikev2_trans_type_prf       ikev2_trans_type_prf_names    IKEv2_AUTH
 * INTEG:    ikev2_trans_type_integ     ikev2_trans_type_integ_names  IKEv2_INTEG
 * DH:       ike_trans_type_dh          oakley_group_name             OAKLEY
 *
 *
 * id[IKEv1_OAKLEY_ID]:
 *
 * Used by: IKEv1 IKE a.k.a. phase 1
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
 * DH:       ike_trans_type_dh          oakley_group_name             OAKLEY
 *
 *
 * id[IKEv1_ESP_ID]:
 *
 * Used by: ESP and AH; struct esp_info.transid; struct esp_info.auth:
 *
 * Here be trouble.  While the obvious problem is that struct esp_info
 * is using both IKEv1 (INTEG) and IPSEC (ENCRYPT) enum types, that is
 * of no real importance.  The real issue here is with INTEG where
 * things have badly convoluted IKEv1 and IKEv2 ESP numbers and names.
 * For instance, while the enum ipsec_cipher_algo contained
 * ESP_CAMELLIA=23 (IKEv2), the name table esp_transformid_names
 * returns 22 (IKEv1) for the string "ESP_CAMELLIA" (the camellia case
 * is fixed, others remain).  See ealg_getbyname_esp() and
 * aalg_getbyname_esp().
 *
 * ENCRYPT:  ipsec_cipher_algo          esp_transformid_names         ESP
 * INTEG:    ikev1_auth_attribute       auth_alg_names                AUTH_ALGORITHM
 *
 *
 * (not yet if ever) ikev[12]_ipsec_id:
 *
 * While these values started out being consistent with IKEv1 and (I
 * suspect) SADB/KLIPS, the've gone off the rails.  Over time they've
 * picked up IKEv2 values making for general confusion.  Worse, as
 * noted above, CAMELLIA had the IKEv2 value 23 (IKEv1 is 22)
 * resulting in code never being sure of which it is dealing with.
 *
 * These values are not included in this table.
 *
 * ENCRYPT:  ipsec_cipher_algo          esp_transformid_names         ESP
 * INTEG:    ipsec_authentication_algo  ah_transformid_names          AH
 *
 *
 * id[IKE_ALG_SADB_ID] aka SADB/PFKEY (never?):
 *
 * See: https://tools.ietf.org/html/rfc2367#page-12
 *
 * These values are used when interacting with the SADB/PFKEY kernel
 * interface.  Any symbol named SADB_X_... indicates something local,
 * either to this OS or this system.
 *
 * ENCRYPT:  (1)                       (2)                           SADB[_X]_AALG_
 * INTEG:    (3)                       (4)                           SADB[_X]_EALG_
 *
 * (1) The linux centric header libreswan/pfkeyv2 tries to define the
 *     enum sadb_ealg with the names K_SADB[_X]_AALG_... but the code
 *     is broken - it doesn't accomodate missing algorithms (more
 *     generally, the header defines all sorts of stuff that conflicts
 *     with <net/pfkeyv2.h>)
 *
 * (2) Legacy broken code tries to use esp_transformid_names when
 *     printing the encryption algorithm's name
 *
 * (3) The linux centric header libreswan/pfkeyv2 tries to define the
 *     enum sadb_aalg with the names K_SADB[_X]_AALG_ but the code is
 *     broken - it doesn't handle missing algorithms and (more
 *     generally, the header defines all sorts of stuff that conflicts
 *     with <net/pfkeyv2.h>)
 *
 * (4) Legacy code tries to map the integrity value onto
 *     ikev1_auth_attribute and then use auth_alg_names to print the
 *     name
 *
 *
 * (not yet if ever) XFRM names:
 *
 * The XFRM interface uses strings to identify algorithms.
 *
 * It might be useful to add these names to the table.
 *
 * Notes:
 *
 * For ESP/AH, since the PRF is not negotiated (the IKE SA's PRF is
 * used) the field "PRF.id[IKEv1_ESP_ID]" should be left blank.
 * Since, for IKEv2, "PRF.id[IKEv2_ALG_ID]" is used by IKE, it should
 * be defined.
 *
 * XXX: Still missing is a name/alias lookup letting some of alg_info
 * be eliminated.
 */
struct ike_alg {
	/*
	 * Name to print when logging.  FQN = fully-qualified-name.
	 */
	const char *name;
	const char *fqn;
	/*
	 * List of all possible names that might be used to specify
	 * this algorithm.  Must include NAME and enum names.
	 *
	 * Easier to just require that this contain everything then
	 * poke around in multiple places.
	 */
	const char *names[5];
	/*
	 * See above.
	 *
	 * Macros provide short term aliases for the slightly longer
	 * index references (tacky, unixish, and delay churning the
	 * code).
	 *
	 * -1 indicates not valid (annoyingly 0 is used by IKEv2 for
	 * NULL integrity).
	 */
	const struct ike_alg_type *algo_type;
#define ikev1_oakley_id id[IKEv1_OAKLEY_ID]
#define ikev1_esp_id id[IKEv1_ESP_ID]
#define ikev2_alg_id id[IKEv2_ALG_ID]
	int id[IKE_ALG_KEY_ROOF];

	/*
	 * Is this algorithm FIPS approved (i.e., can be enabled in
	 * FIPS mode)?
	 */
	const bool fips;
};

struct encrypt_desc {
	struct ike_alg common;	/* MUST BE FIRST */
	/*
	 * The block size of the encryption algorithm in bytes.
	 */
	const size_t enc_blocksize;
	/*
	 * Does this algorithm require padding to the above
	 * ENC_BLOCKSIZE bytes?
	 *
	 * This shouldn't be confused with the need to pad payloads to
	 * 4-bytes (ESP) or not at all (IKE).
	 */
	const bool pad_to_blocksize;

	/*
	 * For stream and AEAD ciphers, bytes in addition to the KEY,
	 * that need to be extracted from initial shared-secret
	 * (PRF+).  It is concatenated to other material to form an
	 * ENC_BLOCKSIZE sized "starting variable".
	 *
	 * Note: the term "starting variable" comes from Wikipedia.
	 * The more common term Initialization Vector (IV) has
	 * conflicting definitions - the RFCs seem to use it to
	 * describe the chunk of starting variable sent over the wire.
	 * Another common term is "counter block".
	 *
	 * For CTR mode this is called the "nuance value in the
	 * counter block" (AES-CTR - RFC 3686).  It, the [wire] IV,
	 * and block counter are concatenated to form the "starting
	 * variable".
	 *
	 * For AEAD, this is called the "salt" (RFC 5282, RFC-4309 -
	 * AES-CCM-ESP, RFC-4106 - AES-GCM-ESP).  It, and the [wire]
	 * IV are concatenated to form the "nunce"; the block counter
	 * and the "nunce" are then concatenated to form the "starting
	 * variable".
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
	 *
	 * The selected keylen bits of keying material are extracted
	 * from the initial shared-secret (PRF+).
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
	 * For Authenticated Encryption with Associated Data (AEAD),
	 * the size (in 8-bit bytes) of the authentication tag
	 * appended to the end of the encrypted data.
	*/
	const size_t aead_tag_size;

	/*
	 * For NSS.
	 */
	struct {
		/*
		 * The NSS mechanism both used to implement this
		 * algorithm and the type of the key expected by the
		 * algorithm.
		 *
		 * Note that if the SYMKEY object passed to NSS does
		 * not have this type, the operation fails.
		 *
		 * For non-NSS algorithms, leave this blank (i.e., 0).  While,
		 * technically, 0 is CKM_RSA_PKCS_KEY_PAIR_GEN, that mechanism
		 * has no meaning in this context so it is safe.
		 */
		CK_MECHANISM_TYPE mechanism;
	} nss;

	/*
	 * This encryption algorithm's SADB (pfkeyv2) value (>0 when
	 * defined for this OS).
	 *
	 * XXX: The linux centric header libreswan/pfkeyv2 tries to
	 * define "enum sadb_ealg" with the names
	 * K_SADB[_X]_EALG_... but the code is broken - it doesn't
	 * accomodate missing algorithms.  Hence it is not used here.
	 */
	unsigned encrypt_sadb_ealg_id;

	/*
	 * This encryption algorithm's NETLINK_XFRM name, if known.
	 */
	const char *encrypt_netlink_xfrm_name;

	/*
	 * Name that should be parsable by tcpdump -E.  It isn't clear
	 * how true this is.  See ikev2.c:ikev2_log_parentSA().
	 */
	const char *encrypt_tcpdump_name;

	/*
	 * Name used when generating a linux audit record.  Allow an
	 * IKE SA and CHILD (IPSEC kernel) SA to use different names.
	 *
	 * XXX: At one point the CHILD SA's audit name was the IKEv1
	 * ESP enum_name table but that forced all kernel algorithms
	 * to have an IKEv1 name/number (even when it was bogus).
	 */
	const char *encrypt_ike_audit_name;
	const char *encrypt_kernel_audit_name;

	const struct encrypt_ops *encrypt_ops;
};

struct encrypt_ops {
	/*
	 * Delegate responsibility for checking OPS specific fields.
	 */
	void (*const check)(const struct encrypt_desc *alg);

	/*
	 * Perform simple encryption.
	 *
	 * Presumably something else is implementing the integrity.
	 */
	void (*const do_crypt)(const struct encrypt_desc *alg,
			       uint8_t *dat,
			       size_t datasize,
			       PK11SymKey *key,
			       uint8_t *iv,
			       bool enc);

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
	bool (*const do_aead)(const struct encrypt_desc *alg,
			      uint8_t *salt, size_t salt_size,
			      uint8_t *wire_iv, size_t wire_iv_size,
			      uint8_t *aad, size_t aad_size,
			      uint8_t *text_and_tag,
			      size_t text_size, size_t tag_size,
			      PK11SymKey *key, bool enc);
};

/*
 * A "hash" algorithm is used to compute a simple message
 * authentication code.
 */

struct hash_desc {
	struct ike_alg common;	/* MUST BE FIRST */
	/*
	 * Size of the output digest in bytes.
	 */
	const size_t hash_digest_size;
	/*
	 * Size of an input block, in bytes.
	 */
	const size_t hash_block_size;
	/*
	 * For NSS.
	 *
	 * This is all somewhat redundant.  Unfortunately there isn't
	 * a way to map between them.
	 */
	struct {
		/*
		 * The NSS_OID_TAG identifies the the PK11 digest
		 * (hash) context that should created when using
		 * PL11_Digest*().
		 */
		SECOidTag oid_tag;
		/*
		 * The DERIVE_MECHANISM specifies the derivation
		 * (algorithm) to use when using PK11_Derive().
		 */
		CK_MECHANISM_TYPE derivation_mechanism;
	} nss;

	const struct hash_ops *hash_ops;
};

/*
 * ASN.1 blobs specific to a particular hash algorithm are sent in the
 * Auth payload as part of Digital signature authentication as per RFC7427
 */
struct asn1_hash_blob {
	enum notify_payload_hash_algorithms hash_algo;
	const uint8_t size;
	const uint8_t *size_blob;
	const uint8_t asn1_blob_len;
	const uint8_t *asn1_blob;
};

/*
 * Generic implementation of HASH_DESC.
 */
struct hash_context;

struct hash_ops {
	/*
	 * Delegate responsibility for checking OPS specific fields.
	 */
	void (*const check)(const struct hash_desc *alg);

	struct hash_context *(*init)(const struct hash_desc *hash_desc,
				     const char *name);
	void (*digest_symkey)(struct hash_context *hash,
			      const char *name, PK11SymKey *symkey);
	void (*digest_bytes)(struct hash_context *hash,
			     const char *name,
			     const uint8_t *bytes, size_t sizeof_bytes);
	void (*final_bytes)(struct hash_context**,
			    uint8_t *bytes, size_t sizeof_bytes);
	/* FIPS short cuts */
	PK11SymKey *(*symkey_to_symkey)(const struct hash_desc *hash_desc,
					const char *name,
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
	 * Preferred key size of the PRF.
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
	 * For NSS.
	 */
	struct {
		/*
		 * The NSS mechanism both used to implement this
		 * algorithm and the type of the key expected by the
		 * algorithm.
		 *
		 * Note that if the SYMKEY object passed to NSS does
		 * not have this type, the operation fails.
		 *
		 * For non-NSS algorithms, leave this blank (i.e., 0).  While,
		 * technically, 0 is CKM_RSA_PKCS_KEY_PAIR_GEN, that mechanism
		 * has no meaning in this context so it is safe.
		 */
		CK_MECHANISM_TYPE mechanism;
	} nss;

	/*
	 * For native-IKE.  The HASHER used by the HMAC construction.
	 *
	 * Non-NULL IFF there is a native implementation.
	 *
	 * If non-NULL its values must be consistent with the above.
	 */
	const struct hash_desc *hasher;
	/*
	 * FIPS controlled native implementation.
	 */
	const struct prf_ops *prf_ops;
	/*
	 * Name used when generating a linux audit record for an IKE
	 * SA.
	 */
	const char *prf_ike_audit_name;
};

struct prf_ops {
	/*
	 * Delegate responsibility for checking OPS specific fields.
	 */
	void (*const check)(const struct prf_desc *alg);

	struct prf_context *(*init_symkey)(const struct prf_desc *prf_desc,
					   const char *name,
					   const char *key_name, PK11SymKey *key);
	struct prf_context *(*init_bytes)(const struct prf_desc *prf_desc,
					  const char *name,
					  const char *key_name,
					  const uint8_t *bytes, size_t sizeof_bytes);
	void (*digest_symkey)(struct prf_context *prf,
			      const char *name, PK11SymKey *symkey);
	void (*digest_bytes)(struct prf_context *prf,
			     const char *name, const uint8_t *bytes, size_t sizeof_bytes);
	PK11SymKey *(*final_symkey)(struct prf_context **prf);
	void (*final_bytes)(struct prf_context **prf, uint8_t *bytes, size_t sizeof_bytes);
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
	 * Size, in bytes (octets), of the keying material needed to
	 * prime the integrity algorithm.
	 *
	 * If there's an IKE PRF implementation, then these values
	 * need to be consistent with the PRF.
	 */
	const size_t integ_keymat_size;
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
	 * IKEv1 IPsec AH transform values
	 * https://www.iana.org/assignments/isakmp-registry/isakmp-registry.xhtml#isakmp-registry-7
	 *
	 * An IKEv1 AH proposal is structured as:
	 *
	 *     Transform: ikev1_ah_transform
	 *         Attribute: ikev1_auth_attribute
	 *
	 * Where the attrid and transid need to match.  Other than for
	 * an MD5 edge case, this is entirely redundant.
	 */
	enum ipsec_authentication_algo integ_ikev1_ah_transform;

	/*
	 * This integrity algorithm's SADB (pfkeyv2) value (>0 when
	 * defined for this OS).
	 *
	 * The linux centric header libreswan/pfkeyv2 tries to define
	 * "enum sadb_aalg" with the names K_SADB[_X]_AALG_... but the
	 * code is broken - it doesn't accomodate missing algorithms.
	 * Hence it is not used here.
	 */
	unsigned integ_sadb_aalg_id;

	/*
	 * This integrity algorithm's NETLINK_XFRM name if known.
	 */
	const char *integ_netlink_xfrm_name;

	/*
	 * Name that should be parsable by tcpdump -E.  It isn't clear
	 * how true this is.  See ikev2.c:ikev2_log_parentSA().
	 */
	const char *integ_tcpdump_name;

	/*
	 * Name used when generating a linux audit record.  Allow an
	 * IKE SA and CHILD (IPSEC kernel) SA to use different names.
	 *
	 * XXX: At one point the CHILD SA's audit name was the IKEv1
	 * ESP enum_name table but that forced all kernel algorithms
	 * to have an IKEv1 name/number (even when it was bogus).
	 */
	const char *integ_ike_audit_name;
	const char *integ_kernel_audit_name;

	/*
	 * For IKE.  The PRF implementing integrity.  The output is
	 * truncated down to INTEG_HASH_LEN.
	 *
	 * Non-NULL IFF there is a native implementation.
	 */
	const struct prf_desc *prf;
};

/*
 * Is the encryption algorithm AEAD (Authenticated Encryption with
 * Associated Data)?
 *
 * Since AEAD algorithms have integrity built in, separate integrity
 * is redundant.
 *
 * Note that the converse (non-AEAD algorithm always require
 * integrity) is not true.  For instance, with ESP, integrity is
 * optional.
 */

extern bool encrypt_desc_is_aead(const struct encrypt_desc *enc_desc);

void init_ike_alg(void);
void test_ike_alg(void);

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
 * Is the algorithm valid (or did FIPS, say, disable it)?
 */

bool ike_alg_is_valid(const struct ike_alg *alg);

/*
 * Is the key valid for the encryption algorithm?
 *
 * For the case of null encryption, 0 is considered valid.
 */
bool encrypt_has_key_bit_length(const struct encrypt_desc *encrypt_desc, unsigned keylen);

/*
 * The largest and smallest key bit length allowed.
 */
unsigned encrypt_min_key_bit_length(const struct encrypt_desc *encrypt_desc);
unsigned encrypt_max_key_bit_length(const struct encrypt_desc *encrypt_desc);

/*
 * DHMKE: Diffie–Hellman–Merkle key exchange.
 *
 * The naming follows Hellman's suggestion; besides "dh" is too short
 * and "oakley_group" is too long.
 */

struct oakley_group_desc {
	struct ike_alg common;		/* must be first */
	uint16_t group;
	size_t bytes;

	/*
	 * For MODP groups, the base and prime used when generating
	 * the KE.
	 */
	const char *gen;
	const char *modp;

	/*
	 * For ECP groups, the NSS ASN.1 OID that identifies the ECP.
	 */
	SECOidTag nss_oid;

	const struct dh_ops *dh_ops;
};

struct dh_ops {
	/*
	 * Delegate responsibility for checking OPS specific fields.
	 */
	void (*const check)(const struct oakley_group_desc *alg);

	/*
	 * Create the local secret and KE for remote.
	 *
	 * The LOCAL_PUBK parameter is arguably redundant - just the
	 * KE bytes and private key are needed - however MODP's
	 * CALC_G_IR() uses LOCAL_PUBK to fudge up the remote's public
	 * key.
	 *
	 * SIZEOF_KE == .BYTES from above, but pass it in so both ends
	 * can perform a sanity check.
	 */
	void (*calc_secret)(const struct oakley_group_desc *group,
			    SECKEYPrivateKey **local_privk,
			    SECKEYPublicKey **locak_pubk,
			    uint8_t *ke, size_t sizeof_ke);
	PK11SymKey *(*calc_shared)(const struct oakley_group_desc *group,
				   SECKEYPrivateKey *local_privk,
				   const SECKEYPublicKey *local_pubk,
				   uint8_t *remote_ke, size_t sizeof_remote_ke);
};

extern const struct oakley_group_desc unset_group;      /* magic signifier */
const struct oakley_group_desc **next_oakley_group(const struct oakley_group_desc **);

/*
 * Robustly cast struct ike_alg to underlying object.
 *
 * Could be reduced to a macro, but only if passert() returned
 * something.
 */
const struct hash_desc *hash_desc(const struct ike_alg *alg);
const struct prf_desc *prf_desc(const struct ike_alg *alg);
const struct integ_desc *integ_desc(const struct ike_alg *alg);
const struct encrypt_desc *encrypt_desc(const struct ike_alg *alg);
const struct oakley_group_desc *oakley_group_desc(const struct ike_alg *alg);
const struct oakley_group_desc *dh_desc(const struct ike_alg *alg);

/*
 * Find the ENCRYPT / PRF / INTEG / DH algorithm using the IKEv2 wire
 * value.
 *
 * Use ike_alg_is_ike() to confirm that the algorithm has a native
 * implementation (as needed by IKE and ESP/AH PFS).  Use a kernel
 * query to confirm that the algorithm has kernel support (XXX: what?
 * who knows).
 */

const struct encrypt_desc *ikev2_get_encrypt_desc(enum ikev2_trans_type_encr);
const struct prf_desc *ikev2_get_prf_desc(enum ikev2_trans_type_prf);
const struct integ_desc *ikev2_get_integ_desc(enum ikev2_trans_type_integ);
const struct oakley_group_desc *ikev2_get_dh_desc(enum ike_trans_type_dh);

/*
 * Find the ENCRYPT / PRF / DH algorithm using IKEv1 IKE (aka OAKLEY)
 * wire value.
 *
 * Unlike IKEv2, IKEv1 uses different wire-values for IKE, ESP, and
 * AH.  This just deals with IKE (well, ok, in the case of DH, it also
 * deals with ESP/AH as the value is the same).
 */

const struct encrypt_desc *ikev1_get_ike_encrypt_desc(enum ikev1_encr_attribute);
const struct prf_desc *ikev1_get_ike_prf_desc(enum ikev1_auth_attribute);
const struct oakley_group_desc *ikev1_get_ike_dh_desc(enum ike_trans_type_dh);

/*
 * Find the IKEv1 ENCRYPT / INTEG algorithm that will be fed into the
 * kernel to provide an IPSEC tunnel.
 */

const struct encrypt_desc *ikev1_get_kernel_encrypt_desc(enum ipsec_cipher_algo);
const struct integ_desc *ikev1_get_kernel_integ_desc(enum ikev1_auth_attribute);

/*
 * Find the ENCRYPT / INTEG algorithm using the SADB defined value.
 *
 * Note that these functions take an unsigned and _not_ an enum
 * parameter.  See above.
 */

const struct encrypt_desc *encrypt_desc_by_sadb_ealg_id(unsigned id);
const struct integ_desc *integ_desc_by_sadb_aalg_id(unsigned id);

/*
 * Pretty print the algorithm to the standard log.  The logged line is
 * very wide.
 */
void libreswan_log_ike_alg(const char *prefix, const struct ike_alg *alg);

#endif /* _IKE_ALG_H */
