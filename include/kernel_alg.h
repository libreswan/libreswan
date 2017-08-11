/*
 * Kernel runtime algorithm handling interface definitions
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 * Copyright (C) 2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2013 D. Hugh Redelmeier <hugh@mimosa.com>
 * Copyright (C) 2017 Andrew Cagney
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
 */

#ifndef _KERNEL_ALG_H
#define _KERNEL_ALG_H
#include "libreswan/pfkeyv2.h"

struct ike_alg; /* forward declaration */
struct sadb_msg; /* forward definition */

struct kernel_alg_info {
	/*
	 * The encryption algorithm and key length; if required by
	 * ESP.
	 *
	 * Because struct encrypt_desc still specifies multiple key
	 * lengths, ENCKEYSIZE is still required.
	 */
	u_int8_t transid;       /* enum ipsec_cipher_algo: ESP transform (AES, 3DES, etc.)*/
	size_t enckeysize;      /* keylength for ESP transform (bytes) */
	/*
	 * The authentication algorithm; if required by ESP/AH.
	 */
	u_int16_t auth;         /* enum ikev1_auth_attribute: AUTH */
	/*
	 * The above mapped onto SADB/KLIPS/PFKEYv2 equivalent and
	 * used by the kernel backends.
	 */
	u_int8_t encryptalg;    /* enum sadb_ealg: normally  encryptalg=transid */
	u_int16_t authalg;	/* enum sadb_aalg: normally  authalg=auth+1
				 * Paul: apparently related to magic at
				 * lib/libswan/alg_info.c alg_info_esp_aa2sadb()
				 */
};

/* Registration messages from pluto */
extern void kernel_alg_register_pfkey(const struct sadb_msg *msg);

struct alg_info;	/* forward declaration */
struct esp_info;	/* forward declaration */
struct alg_info_ike;	/* forward declaration */
struct alg_info_esp;	/* forward declaration */

extern bool kernel_alg_is_ok(const struct ike_alg *alg);

/* ESP interface */
extern struct sadb_alg *kernel_alg_esp_sadb_alg(int alg_id);
extern int kernel_alg_esp_ivlen(int alg_id);

/* returns success (NULL) if encrypt alg is present in kernel */
extern err_t check_kernel_encrypt_alg(int alg_id, unsigned int key_len);

/* returns encrypt keylen in BYTES for esp enc alg passed */
extern int kernel_alg_esp_enc_max_keylen(int alg_id);

/* returns bool success if esp auth alg is present  */
extern bool kernel_alg_esp_auth_ok(int auth, struct alg_info_esp *nfo);

extern int kernel_alg_ah_auth_keylen(int auth);

extern bool kernel_alg_ah_auth_ok(int auth, struct alg_info_esp *alg_info);

/* returns auth keylen in BYTES for esp auth alg passed */
extern int kernel_alg_esp_auth_keylen(int auth);

/* returns TRUE if read ok from /proc/net/pf_key_supported */
extern bool kernel_alg_proc_read(void);

/* get sadb_alg for passed args */
extern const struct sadb_alg *kernel_alg_sadb_alg_get(unsigned satype, unsigned exttype,
						       unsigned alg_id);

extern bool kernel_alg_info(u_int8_t transid,
			    u_int16_t keylen,
			    u_int16_t auth,
			    struct kernel_alg_info *ki);

extern struct sadb_alg esp_aalg[];
extern struct sadb_alg esp_ealg[];
extern int esp_ealg_num;
extern int esp_aalg_num;

#define ESP_EALG_PRESENT(algo) ((algo) <= K_SADB_EALG_MAX && \
				esp_ealg[algo].sadb_alg_id == (algo))

#define ESP_EALG_FOR_EACH(algo) \
	for ((algo) = 1; (algo) <= K_SADB_EALG_MAX; (algo)++) \
		if (ESP_EALG_PRESENT(algo))

#define ESP_EALG_FOR_EACH_DOWN(algo) \
	for ((algo) = K_SADB_EALG_MAX; (algo) > 0; (algo)--) \
		if (ESP_EALG_PRESENT(algo))

#define ESP_AALG_PRESENT(algo) ((algo) <= SADB_AALG_MAX && \
				esp_aalg[algo].sadb_alg_id == (algo))

#define ESP_AALG_FOR_EACH(algo) \
	for ((algo) = 1; (algo) <= SADB_AALG_MAX; (algo)++) \
		if (ESP_AALG_PRESENT(algo))

extern void kernel_alg_init(void);

extern int kernel_alg_add(int satype, int exttype,
			  const struct sadb_alg *sadb_alg);

struct integ_desc;

struct kernel_integ {
	enum sadb_aalg sadb_aalg;
	const struct integ_desc *integ;
	const char *netlink_name;
	struct kernel_integ *next;
};

void kernel_integ_add(enum sadb_aalg aalg, const struct integ_desc *integ,
		      const char *netkey);

const struct kernel_integ *kernel_integ_by_sadb_aalg(enum sadb_aalg aalg);
const struct kernel_integ *kernel_integ_by_ikev1_auth_attribute(enum ikev1_auth_attribute auth);

extern enum ipsec_authentication_algo alg_info_esp_aa2sadb(enum ikev1_auth_attribute auth);
extern int alg_info_esp_sadb2aa(int sadb_aalg);

#endif /* _KERNEL_ALG_H */
