/* Find public key in DNS
 * Copyright (C) 2000-2002  D. Hugh Redelmeier.
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

#ifndef _DNSKEY_H_

struct adns_continuation;       /* forward declaration (not far!) */

typedef void (*cont_fn_t)(struct adns_continuation *cr, err_t ugh);

struct adns_continuation {
	unsigned long qtid;                     /* query transaction id number */
	int type;                               /* T_TXT or T_KEY, selecting rr type of interest */
	cont_fn_t cont_fn;                      /* function to carry on suspended work */
	struct id id;                           /* subject of query */
	bool sgw_specified;
	struct id sgw_id;                       /* peer, if constrained */
	lset_t debugging;
	struct gw_info *gateways_from_dns;      /* answer, if looking for our TXT rrs */
#ifdef USE_KEYRR
	struct pubkey_list *keys_from_dns;      /* answer, if looking for KEY rrs */
#endif
	struct adns_continuation *previous, *next;
	struct pubkey *last_info; /* the last structure we accumulated */
};

/* Gateway info gleaned from reverse DNS of client */
struct gw_info {
	unsigned refcnt;        /* reference counted! */
	unsigned pref;          /* preference: lower is better */
	struct id client_id;    /* id of client of peer */
	struct id gw_id;        /* id of peer (if id_is_ipaddr, .ip_addr is address) */
	bool gw_key_present;
	struct pubkey *key;
	struct gw_info *next;
};

#define _DNSKEY_H_
#endif /* _DNSKEY_H_ */
