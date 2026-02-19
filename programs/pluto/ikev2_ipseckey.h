#ifndef IKEV2_IPSECKEY_H
#define IKEV2_IPSECKEY_H

struct dnssec_config;

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

void init_ikev2_ipseckey(struct event_base *event_base,
			 struct logger *logger);
void shutdown_ikev2_ipseckey(const struct logger *logger);

#endif
