struct state *sendI1(struct connection *c1, int debugging)
{
	struct state *st;
	struct pcr_kenonce *kn = &r->pcr_d.kn;  /* r is a global */

	c1->extra_debugging = DBG_EMITTING | DBG_CONTROL | DBG_CONTROLMORE;
	ipsecdoi_initiate(/* whack-sock=stdout */ 1,
						  c1,
						  c1->policy,
						  0,
						  FALSE,
						  pcim_demand_crypto);

	/* find st involved */
	st = state_with_serialno(1);

	cur_debugging = debugging;
	c1->extra_debugging = debugging;

	/* now fill in the KE values from a constant.. not calculated */
	WIRE_CLONE_DATA(kn, secret, tc3_secret,
			 tc3_secret_len);
	WIRE_CLONE_DATA(kn, n,   tc3_ni,
			 tc3_ni_len);
	WIRE_CLONE_DATA(kn, gi,  tc3_gi,
			 tc3_gi_len);

	run_continuation(r);

	return st;
}
