#include "state.h"

#ifdef USE_DNSSEC
# define LSW_LIBUNBOUND_ENABLED TRUE
#else
# define LSW_LIBUNBOUND_ENABLED FALSE
#endif

#define IS_LIBUNBOUND LSW_LIBUNBOUND_ENABLED

struct p_dns_req;

extern stf_status idi_ipseckey_fetch(struct msg_digest *md);
extern void free_ipseckey_dns(struct p_dns_req *pp);
extern stf_status idr_ipseckey_fetch(struct state *st);
