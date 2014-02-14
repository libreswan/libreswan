void recv_pcap_packet1(u_char *user,
		       const struct pcap_pkthdr *h,
		       const u_char *bytes)
{
	struct state *st;
	struct pcr_kenonce *kn = &r->pcr_d.kn;

	recv_pcap_packet_gen(user, h, bytes);

	/* find st involved */
	st = state_with_serialno(1);
	st->st_connection->extra_debugging = add_debugging;

	/* now fill in the SKEYSEED values from constants.. not calculated */
	WIRE_CLONE_DATA(kn, secret, tc3_secret,
			 tc3_secret_len);
	WIRE_CLONE_DATA(kn, n,   tc3_ni,
			 tc3_ni_len);
	WIRE_CLONE_DATA(kn, gi,  tc3_gi,
			 tc3_gi_len);

	run_continuation(r);

}
