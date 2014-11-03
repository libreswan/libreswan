#ifndef _IKEv1_CONTINUATIONS_H
#define _IKEv1_CONTINUATIONS_H
/*
 * continuations used
 */

typedef stf_status initiator_function (int whack_sock,
				       struct connection *c,
				       struct state *predecessor,
				       lset_t policy,
				       unsigned long try,
				       enum crypto_importance importance
#ifdef HAVE_LABELED_IPSEC
				       , struct xfrm_user_sec_ctx_ike *uctx
#endif
				       );

/* MAGIC: perform f, a function that returns notification_t
 * and return from the ENCLOSING stf_status returning function if it fails.
 */
/* ??? why are there so many copies of this routine (ikev2.h, ikev1_continuations.h, ipsec_doi.c).
 * Sometimes more than one copy is defined!
 */
#define RETURN_STF_FAILURE(f) { \
	notification_t res = (f); \
	if (res != NOTHING_WRONG) { \
		  return STF_FAIL + res; \
	} \
}

#endif /* _IKEv1_CONTINUATIONS */
