#ifndef _IKEV2_IPSECKEY_H
#define _IKEV2_IPSECKEY_H

#ifdef USE_DNSSEC
# define LSW_LIBUNBOUND_ENABLED true
#else
# define LSW_LIBUNBOUND_ENABLED false
#endif

#define IS_LIBUNBOUND LSW_LIBUNBOUND_ENABLED

struct ike_sa;

typedef enum {
	DNS_OK = STF_OK,
	DNS_FATAL = STF_FATAL,
	DNS_SUSPEND = STF_SUSPEND,
} dns_status;

dns_status responder_fetch_idi_ipseckey(struct ike_sa *ike, struct msg_digest *md,
					stf_status (*callback)(struct ike_sa *ike,
							       struct msg_digest *md,
							       bool err));
bool initiator_fetch_idr_ipseckey(struct ike_sa *ike);

#endif
