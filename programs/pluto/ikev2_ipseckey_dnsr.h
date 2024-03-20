#include "defs.h"

#ifndef _IKEV2_IPSECKEY_DNSR_H
#define _IKEV2_IPSECKEY_DNSR_H

struct p_dns_req;

typedef void dnsr_cb_fn(struct p_dns_req *);

struct dns_pubkey {
	/* ID? */
	enum ipseckey_algorithm_type algorithm_type;
	struct dns_pubkey *next;
	uint32_t ttl;
	/* memory allocated with this struct */
	shunk_t pubkey;
};

typedef void dnsr_pubkeys_cb_fn(struct p_dns_req *dnsr,
				struct dns_pubkey *dns_pubkeys);

typedef void dnsr_validate_address_cb_fn(struct p_dns_req *dnsr,
					 unsigned char *addr);

struct p_dns_req {
	dns_status dns_status;

	bool cache_hit;		/* libunbound hit cache/local, calledback immediately */

	so_serial_t so_serial;	/* wake up the state when query returns */
	struct msg_digest *md;	/* wake up message to resume */
	stf_status (*callback)(struct ike_sa *ike, struct msg_digest *md, bool err);
	struct logger *logger;

	char *log_buf;

	realtime_t start_time;
	realtime_t done_time;

	char *qname;		/* DNS query to send, from ID */
	uint16_t qtype;
	uint16_t qclass;

	int ub_async_id;	/* used to track libunbound query, to cancel */

	int rcode;		/* libunbound dns query rcode */
	const char *rcode_name; /* rcode return txt defined by ldns */

	bool fwd_addr_valid;	/* additional check forward A/AAAA is valid */

	/*
	 * from unbound-event.h
	 * void *wire with packet: a buffer with DNS wireformat packet with the answer.
	 * do not inspect if rcode != 0.
	 * do not write or free the packet buffer, it is used
	 * internally in unbound (for other callbacks that want the same data).
	 */
	void *wire;	/* libunbound result wire buffer format */
	int wire_len;	/* length of the above buffer */

	int secure;	/* dnsec validiation returned by libunbound */
	char *why_bogus;	/* returned by libunbound if the security is bogus */

	dnsr_cb_fn *cb;	/* continue function for pluto, not the unbound cb */
	dnsr_pubkeys_cb_fn *pubkeys_cb;	/* called when public keys are retrieved from IPSECKEY RR */
	dnsr_validate_address_cb_fn *validate_address_cb; /* called when addresses are returned as A RR */

	struct p_dns_req *next;
};

extern void ikev2_ipseckey_log_missing_st(struct p_dns_req *dnsr);
extern void ipseckey_dbg_dns_resp(struct p_dns_req *dnsr);
extern err_t process_dns_resp(struct p_dns_req *dnsr);
extern dns_status dns_qry_start(struct p_dns_req *dnsr);
extern struct p_dns_req *pluto_dns_list;
extern void free_ipseckey_dns(struct p_dns_req *pp);

#endif
