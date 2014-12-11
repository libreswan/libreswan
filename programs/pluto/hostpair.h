struct host_pair {
	struct {
		ip_address addr;
		u_int16_t host_port;            /* IKE port */
		bool host_port_specific;        /* if above is interesting */
	} me, him;
	struct connection *connections;         /* connections with this pair */
	struct pending *pending;                /* awaiting Keying Channel */
	struct host_pair *next;
};

extern struct host_pair *host_pairs;

extern void connect_to_host_pair(struct connection *c);
extern struct connection *find_host_pair_connections(const char *func,
						     const ip_address *myaddr,
						     u_int16_t myport,
						     const ip_address *hisaddr,
						     u_int16_t hisport);

extern struct host_pair *find_host_pair(const ip_address *myaddr,
					u_int16_t myport,
					const ip_address *hisaddr,
					u_int16_t hisport);

#define list_rm(etype, enext, e, ehead) { \
		etype **ep; \
		for (ep = &(ehead); *ep != (e); ep = &(*ep)->enext) \
			passert(*ep != NULL); /* we must not come up empty-handed */ \
		*ep = (e)->enext; \
	}

extern void remove_host_pair(struct host_pair *hp);

extern struct connection *connections;
