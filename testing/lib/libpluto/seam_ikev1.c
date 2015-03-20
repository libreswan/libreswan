stf_status aggr_outI1(int whack_sock,
		      struct connection *c,
		      struct state *predecessor,
		      lset_t policy,
		      unsigned long try,
		      enum crypto_importance importance)
{
	lsw_abort();
}

stf_status main_outI1(int whack_sock,
		      struct connection *c,
		      struct state *predecessor,
		      lset_t policy,
		      unsigned long try,
		      enum crypto_importance importance)
{
	DBG_log("MAIN OUTi1()\n");
}

stf_status quick_outI1(int whack_sock,
		       struct state *isakmp_sa,
		       struct connection *c,
		       lset_t policy,
		       unsigned long try,
		       so_serial_t replacing)
{
	lsw_abort();
}

void ikev1_delete_out(struct state *st)
{
	printf("deleted state #%lu\n", st->st_serialno);
}

void send_notification_from_state(struct state *st, enum state_kind state,
				  notification_t type)
{
}

void send_notification_from_md(struct msg_digest *md, notification_t type)
{
}

void process_v1_packet(struct msg_digest **mdp)
{
	lsw_abort();
}
