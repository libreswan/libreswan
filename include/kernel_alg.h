/*
 * Kernel runtime algorithm handling interface definitions
 * Author: JuanJo Ciarlante <jjo-ipsec@mendoza.gov.ar>
 *
 * kernel_alg.h,v 1.1.2.1 2003/11/21 18:12:23 jjo Exp
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
#include "openswan/pfkeyv2.h"

struct sadb_msg; /* forward definition */

/* Registration messages from pluto */
extern void kernel_alg_register_pfkey(const struct sadb_msg *msg, int buflen);

struct alg_info;
struct esp_info;
struct alg_info_ike;
struct alg_info_esp;
/* ESP interface */
extern struct sadb_alg *kernel_alg_esp_sadb_alg(int alg_id);
extern int kernel_alg_esp_ivlen(int alg_id);
/* returns bool success if esp encrypt alg is present  */
extern err_t kernel_alg_esp_enc_ok(int alg_id, unsigned int key_len, struct alg_info_esp *nfo);
extern bool kernel_alg_esp_ok_final(int ealg, unsigned int key_len, int aalg, struct alg_info_esp *alg_info);
/* returns encrypt keylen in BYTES for esp enc alg passed */
extern int kernel_alg_esp_enc_keylen(int alg_id);
/* returns bool success if esp auth alg is present  */
extern err_t kernel_alg_esp_auth_ok(int auth, struct alg_info_esp *nfo);
/* returns auth keylen in BYTES for esp auth alg passed */
extern int kernel_alg_esp_auth_keylen(int auth);
/* returns 0 if read ok from /proc/net/pf_key_supported */
extern int kernel_alg_proc_read(void);

/* get sadb_alg for passed args */
extern const struct sadb_alg * kernel_alg_sadb_alg_get(int satype, int exttype, int alg_id);

struct db_prop;
extern struct db_context * kernel_alg_db_new(struct alg_info_esp *ai
					     , lset_t policy
					     , bool logit);

/* returns pointer to static buffer, no reentrant */
extern struct esp_info *kernel_alg_esp_info(u_int8_t transid
					    , u_int16_t keylen
					    , u_int16_t auth);

extern struct sadb_alg esp_aalg[];
extern struct sadb_alg esp_ealg[];
extern int esp_ealg_num;
extern int esp_aalg_num;

#define ESP_EALG_PRESENT(algo) (((algo)<=SADB_EALG_MAX)&&(esp_ealg[(algo)].sadb_alg_id==(algo)))
#define ESP_EALG_FOR_EACH(algo) \
	for (algo=1; algo <= SADB_EALG_MAX; algo++) \
		if (ESP_EALG_PRESENT(algo))
#define ESP_EALG_FOR_EACH_UPDOWN(algo) \
	for (algo=SADB_EALG_MAX; algo >0 ; algo--) \
		if (ESP_EALG_PRESENT(algo))
#define ESP_AALG_PRESENT(algo) ((algo<=SADB_AALG_MAX)&&(esp_aalg[(algo)].sadb_alg_id==(algo)))
#define ESP_AALG_FOR_EACH(algo) \
	for (algo=1; algo <= SADB_AALG_MAX; algo++) \
		if (ESP_AALG_PRESENT(algo))
#define ESP_AALG_FOR_EACH_UPDOWN(algo) \
	for (algo=SADB_AALG_MAX; algo >0 ; algo--) \
		if (ESP_AALG_PRESENT(algo))

#endif /* _KERNEL_ALG_H */
