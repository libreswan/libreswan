void delete_cryptographic_continuation(struct state *st)
{
}

#include "pluto_crypt.h"
struct pluto_crypto_req_cont *continuation;

struct pluto_crypto_req rd;
struct pluto_crypto_req *r = &rd;

stf_status build_ke_and_nonce(struct pluto_crypto_req_cont *cn,
		    const struct oakley_group_desc *group,
		    enum crypto_importance importance)
{
	continuation = cn;
	zero(&rd);	/* ??? pointer fields might not be NULLed */

	r->pcr_len  = sizeof(struct pluto_crypto_req);
	r->pcr_type = pcr_build_ke_and_nonce;
	r->pcr_pcim = importance;

	pcr_nonce_init(r, pcr_build_ke_and_nonce, importance);
	r->pcr_d.kn.oakley_group = group->group;

	return STF_SUSPEND;
}

stf_status start_dh_v2(struct pluto_crypto_req_cont *cn,
		       struct state *st,
		       enum crypto_importance importance,
		       enum phase1_role init,        /* TRUE=g_init,FALSE=g_r */
		       u_int16_t oakley_group2)
{
	continuation = cn;
	zero(&rd);	/* ??? pointer fields might not be NULLed */

	r->pcr_len  = sizeof(struct pluto_crypto_req);
	r->pcr_type = pcr_compute_dh_v2;
	r->pcr_pcim = importance;

	pcr_dh_init(&r, st, pcr_compute_dh_v2, importance );
	r->pcr_d.kn.oakley_group   = oakley_group2;

	return STF_SUSPEND;
}

void run_continuation(struct pluto_crypto_req *r)
{
	while (continuation != NULL) {
		struct pluto_crypto_req_cont *cn = continuation;
		continuation = NULL;
		passert(cn->pcrc_func != NULL);
		(*cn->pcrc_func)(cn, r);
	}
}

bool ikev2_calculate_rsa_sha1(struct state *st,
			      enum phase1_role role,
			      unsigned char *idhash,
			      pb_stream *a_pbs)
{
	out_zero(192, a_pbs, "fake rsa sig");
	return TRUE;
}

bool ikev2_calculate_psk_auth(struct state *st,
			      enum phase1_role role,
			      unsigned char *idhash,
			      pb_stream *a_pbs)
{
	out_zero(20, a_pbs, "fake psk auth");
	return TRUE;
}

stf_status ikev2_verify_psk_auth(struct state *st,
				 enum phase1_role role,
				 unsigned char *idhash,
				 pb_stream *sig_pbs)
{
	return STF_OK;
}

stf_status ikev2_verify_rsa_sha1(struct state *st,
				 enum phase1_role role,
				 unsigned char *idhash,
#ifdef USE_KEYRR
				 const struct pubkey_list *keys_from_dns,
#endif
				 const struct gw_info *gateways_from_dns,
				 pb_stream *sig_pbs)
{
	return STF_OK;
}

