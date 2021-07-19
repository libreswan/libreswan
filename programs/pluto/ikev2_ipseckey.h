#include "state.h"

#ifdef USE_DNSSEC
# define LSW_LIBUNBOUND_ENABLED TRUE
#else
# define LSW_LIBUNBOUND_ENABLED FALSE
#endif

#define IS_LIBUNBOUND LSW_LIBUNBOUND_ENABLED

extern stf_status idi_ipseckey_fetch(struct ike_sa *ike);
extern stf_status idr_ipseckey_fetch(struct ike_sa *ike);
