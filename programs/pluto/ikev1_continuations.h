#ifndef _IKEv1_CONTINUATIONS_H
#define _IKEv1_CONTINUATIONS_H
/*
 * continuations used
 */

/* MAGIC: perform f, a function that returns notification_t
 * and return from the ENCLOSING stf_status returning function if it fails.
 */
/* ??? why are there so many copies of this routine (ikev2.h, ikev1_continuations.h, ipsec_doi.c).
 * Sometimes more than one copy is defined!
 */
#define RETURN_STF_FAIL_v1NURE(f) { \
	v1_notification_t res = (f); \
	if (res != v1N_NOTHING_WRONG) { \
		  return STF_FAIL_v1N + res; \
	} \
}

#endif /* _IKEv1_CONTINUATIONS */
