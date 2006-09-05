/*
 * continuations used
 */
struct ke_continuation {
    struct pluto_crypto_req_cont ke_pcrc;
    struct msg_digest           *md;
};

struct qke_continuation {
    struct pluto_crypto_req_cont qke_pcrc;
    struct state                *st;            /* need to use abstract # */
    struct state                *isakmp_sa;     /* used in initiator */
    so_serial_t                  replacing;
    struct msg_digest           *md;            /* used in responder */
};

struct dh_continuation {
	struct pluto_crypto_req_cont dh_pcrc;
	struct msg_digest           *md;
	so_serial_t                  serialno;  /* used for inter state
						 * calculations on responder */
};


typedef stf_status initiator_function(int whack_sock
				      , struct connection *c
				      , struct state *predecessor
				      , lset_t policy
				      , unsigned long try
				      , enum crypto_importance importance);

/* MAGIC: perform f, a function that returns notification_t
 * and return from the ENCLOSING stf_status returning function if it fails.
 */
#define RETURN_STF_FAILURE2(f, xf)					\
    { int r = (f); if (r != NOTHING_WRONG) { \
	  if((xf)!=NULL) pfree(xf);	     \
	  return STF_FAIL + r; }}

#define RETURN_STF_FAILURE(f) RETURN_STF_FAILURE2(f, NULL)

