#ifndef _IKEv1_CONTINUATIONS_H
#define _IKEv1_CONTINUATIONS_H
/*
 * continuations used
 */
#include "ike_continuations.h"

struct qke_continuation {
	struct pluto_crypto_req_cont qke_pcrc;
	so_serial_t replacing;
	struct msg_digest           *md;        /* used in responder */
};

typedef stf_status initiator_function (int whack_sock,
				       struct connection *c,
				       struct state *predecessor,
				       lset_t policy,
				       unsigned long try,
				       enum crypto_importance importance
#ifdef HAVE_LABELED_IPSEC
				       , struct xfrm_user_sec_ctx_ike * uctx
#endif
				       );

/* MAGIC: perform f, a function that returns notification_t
 * and return from the ENCLOSING stf_status returning function if it fails.
 */
#define RETURN_STF_FAILURE2(f, xf)                                      \
	{ int r = (f); if (r != NOTHING_WRONG) { \
		  if ((xf) != NULL) \
			  pfree(xf);          \
		  return STF_FAIL + r; } }

#define RETURN_STF_FAILURE(f) RETURN_STF_FAILURE2(f, NULL)

#endif /* _IKEv1_CONTINUATIONS */
