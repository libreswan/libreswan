#include "state.h"
#include "ikev2_ipseckey_dnsr.h" /* for dns_status */

#ifndef _IKEV2_IPSECKEY_H
#define _IKEV2_IPSECKEY_H

#ifdef USE_DNSSEC
# define LSW_LIBUNBOUND_ENABLED true
#else
# define LSW_LIBUNBOUND_ENABLED false
#endif

#define IS_LIBUNBOUND LSW_LIBUNBOUND_ENABLED

dns_status responder_fetch_idi_ipseckey(struct ike_sa *ike,
					stf_status (*callback)(struct ike_sa *ike,
							       struct msg_digest *md,
							       bool err));
bool initiator_fetch_idr_ipseckey(struct ike_sa *ike);

#endif
