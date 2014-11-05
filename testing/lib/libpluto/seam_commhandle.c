u_int8_t reply_buffer[MAX_OUTPUT_UDP_SIZE];

void recv_pcap_packet_gen(u_char *user,
			  const struct pcap_pkthdr *h,
			  const u_char *bytes)
{
	struct msg_digest *md;
	u_int32_t *dlt;
	struct iphdr  *ip;
	struct udphdr *udp;
	u_char    *ike;
	const struct iface_port *ifp = &if1;
	int packet_len;
	err_t from_ugh;

	union {
		struct sockaddr sa;
		struct sockaddr_in sa_in4;
		struct sockaddr_in6 sa_in6;
	} from;

	md = alloc_md();
	dlt = (u_int32_t *)bytes;
	if (*dlt != PF_INET)
		return;

	ip  = (struct iphdr *)(dlt + 1);
	udp = (struct udphdr *)(dlt + ip->ihl + 1);
	ike = (u_char *)(udp + 1);

	from.sa_in4.sin_addr.s_addr = ip->saddr;
	from.sa_in4.sin_port        = udp->source;

	md->iface = ifp;
	packet_len = h->len - (ike - bytes);

	happy(anyaddr(addrtypeof(&ifp->ip_addr), &md->sender));

	from_ugh = initaddr((void *) &from.sa_in4.sin_addr,
			    sizeof(from.sa_in4.sin_addr),
			    AF_INET, &md->sender);
	setportof(from.sa_in4.sin_port, &md->sender);
	md->sender_port = ntohs(from.sa_in4.sin_port);

	cur_from      = &md->sender;
	cur_from_port = md->sender_port;

	/* Clone actual message contents
	 * and set up md->packet_pbs to describe it.
	 */
	init_pbs(&md->packet_pbs,
		 clone_bytes(ike, packet_len,
			     "message buffer in comm_handle()"),
		 packet_len, "packet");

	ipstr_buf b;

	DBG_log("*received %d bytes from %s:%u on %s (port=%d)",
		(int) pbs_room(&md->packet_pbs),
		ipstr(&md->sender, &b), (unsigned) md->sender_port,
		ifp->ip_dev->id_rname,
		ifp->port);

	DBG_dump("", md->packet_pbs.start, pbs_room(&md->packet_pbs));

	process_packet(&md);
	release_any_md(&md);

	cur_state = NULL;
	reset_cur_connection();
	cur_from = NULL;
}

