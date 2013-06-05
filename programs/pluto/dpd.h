extern stf_status dpd_init(struct state *st);
extern void dpd_event(struct state *st);
extern void p1_dpd_outI1(struct state *p1st);
extern void p2_dpd_outI1(struct state *p2st);
extern stf_status dpd_inI_outR(struct state *st,
			       struct isakmp_notification *const n,
			       pb_stream *pbs);
extern stf_status dpd_inR(struct state *st,
			  struct isakmp_notification *const n,
			  pb_stream *pbs);
extern void dpd_timeout(struct state *st);

