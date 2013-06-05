void recv_pcap_packet1(u_char *user,
		       const struct pcap_pkthdr *h,
		       const u_char *bytes)
{
	struct state *st;
	struct pcr_kenonce *kn = &r->pcr_d.kn;

	recv_pcap_packet_gen(user, h, bytes);

	/* find st involved */
	st = state_with_serialno(1);

	/* now fill in the SKEYSEED values from constants.. not calculated */
	clonetowirechunk(&kn->thespace, kn->space, &kn->secret, tc3_secret,
			 tc3_secret_len);
	clonetowirechunk(&kn->thespace, kn->space, &kn->n,   tc3_nr,
			 tc3_nr_len);
	clonetowirechunk(&kn->thespace, kn->space, &kn->gi,  tc3_gr,
			 tc3_gr_len);

	run_continuation(r);

}
