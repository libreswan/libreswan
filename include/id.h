/* identity representation, as in IKE ID Payloads (RFC 2407 DOI 4.6.2.1)
 *
 * Copyright (C) 1999-2001  D. Hugh Redelmeier
 * Copyright (C) 2019-2020 Andrew Cagney <cagney@gnu.org>
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

#ifndef ID_H
#define ID_H

#include "ietf_constants.h"	/* for enum ike_id_type */
#include "chunk.h"
#include "err.h"
#include "ip_address.h"
#include "jambuf.h"

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

/*
 * parsing.
 */

err_t atoid(const char *src, struct id *id);

/*
 * Formattting.
 *
 * jam_id() only emits printable ASCII.  Non-printable characters, for
 * instance, are escaped using the RFC compliant sequence \<HEX><HEX>.
 *
 * While good for logging, it isn't good for shell commands.  Use
 * JAM_BYTES to apply additional escaping.
 */

void jam_id(struct lswlog *buf, const struct id *id, jam_bytes_fn *jam_bytes);

typedef struct {
	char buf[512];
} id_buf;
#define IDTOA_BUF	sizeof(id_buf)

const char *str_id(const struct id *id, id_buf *buf);

/*
 * Operations.
 */

struct id clone_id(const struct id *id, const char *why);
extern void free_id_content(struct id *id); /* also blats ID */

extern bool any_id(const struct id *a);
extern bool same_id(const struct id *a, const struct id *b);
#define MAX_WILDCARDS	15
extern bool match_dn_any_order_wild(chunk_t a, chunk_t b, int *wildcards);
extern bool match_id(const struct id *a, const struct id *b, int *wildcards);
extern int id_count_wildcards(const struct id *id);
#define id_is_ipaddr(id) ((id)->kind == ID_IPV4_ADDR || (id)->kind == \
			  ID_IPV6_ADDR)

/* returns ID Type; and points body at Identification Data */
enum ike_id_type id_to_payload(const struct id *id, const ip_address *host, shunk_t *body);

/*
 * Old stuff.
 */

void duplicate_id(struct id *dst, const struct id *src); /* use free_id_content; clone_id() */

#endif
