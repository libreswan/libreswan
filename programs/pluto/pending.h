struct pending; /* forward reference */
void flush_pending_by_connection(struct connection *c);
bool in_pending_use(struct connection *c);
void show_pending_phase2(const struct connection *c, const struct state *st);
bool pending_check_timeout(struct connection *c);

extern struct connection *first_pending(struct state *st,
					lset_t *policy,
					int *p_whack_sock);

