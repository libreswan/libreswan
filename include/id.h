/* identity representation, as in IKE ID Payloads (RFC 2407 DOI 4.6.2.1)
 * Copyright (C) 1999-2001  D. Hugh Redelmeier
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
 */

#ifndef _ID_H
#define _ID_H

#include "ietf_constants.h"	/* for enum ike_id_type */
#include "chunk.h"
#include "err.h"
#include "ip_address.h"

struct id {
	enum ike_id_type kind;

	/* used for ID_IPV4_ADDR, ID_IPV6_ADDR */
	ip_address ip_addr;

	/* used for ID_FQDN, ID_USER_FQDN, ID_KEY_ID, ID_DER_ASN_DN */
	chunk_t name;
};

struct id_list {
	struct id id;
	struct id_list *next;
};

extern const struct id empty_id;	/* ID_NONE */

extern err_t atoid(char *src, struct id *id, bool oe_only);
extern unsigned char *temporary_cyclic_buffer(void);
extern int idtoa(const struct id *id, char *dst, size_t dstlen);
#define IDTOA_BUF	512
extern void escape_metachar(const char *src, char *dst, size_t dstlen);
extern void unshare_id_content(struct id *id);
extern void free_id_content(struct id *id);
extern bool any_id(const struct id *a);
extern bool same_id(const struct id *a, const struct id *b);
#define MAX_WILDCARDS	15
extern bool match_id(const struct id *a, const struct id *b, int *wildcards);
extern int id_count_wildcards(const struct id *id);
#define id_is_ipaddr(id) ((id)->kind == ID_IPV4_ADDR || (id)->kind == \
			  ID_IPV6_ADDR)

struct isakmp_ipsec_id;	/* forward declaration of tag (defined in packet.h) */
struct end;	/* forward declaration of tag (defined in connections.h) */
extern void build_id_payload(struct isakmp_ipsec_id *hd, chunk_t *tl,
			     const struct end *end);
struct ikev2_id;	/* forward declaration of tag (defined in packet.h) */
extern void v2_build_id_payload(struct ikev2_id *hd, chunk_t *tl,
			     const struct end *end);

extern void duplicate_id(struct id *dst, const struct id *src);
extern bool same_dn_any_order(chunk_t a, chunk_t b);

#endif /* _ID_H */

