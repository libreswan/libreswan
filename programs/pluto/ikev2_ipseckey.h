#include "state.h"

#ifndef _IKEV2_IPSECKEY_H
#define _IKEV2_IPSECKEY_H

#ifdef USE_DNSSEC
# define LSW_LIBUNBOUND_ENABLED TRUE
#else
# define LSW_LIBUNBOUND_ENABLED FALSE
#endif

#define IS_LIBUNBOUND LSW_LIBUNBOUND_ENABLED

typedef enum {
	DNS_OK = STF_OK,
	DNS_FATAL = STF_FATAL,
	DNS_SUSPEND = STF_SUSPEND,
} dns_status;

dns_status responder_fetch_idi_ipseckey(struct ike_sa *ike,
					stf_status (*callback)(struct ike_sa *ike,
							       struct msg_digest *md,
							       bool err));
bool initiator_fetch_idr_ipseckey(struct ike_sa *ike);

#endif
