/*
 * The IKE Scanner (ike-scan) is Copyright (C) 2003-2005 Roy Hills,
 * NTA Monitor Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * If this license is unacceptable to you, I may be willing to negotiate
 * alternative licenses (contact ike-scan@nta-monitor.com).
 *
 * You are encouraged to send comments, improvements or suggestions to
 * me at ike-scan@nta-monitor.com.
 *
 * $Id: ike-scan.c,v 1.1.1.1 2005/01/13 18:45:15 mcr Exp $
 *
 * ike-scan -- The IKE Scanner
 *
 * Author:	Roy Hills
 * Date:	11 September 2002
 *
 * Usage:
 *    ike-scan [options] [host...]
 *
 * Description:
 *
 * ike-scan - The IKE Scanner
 *
 * ike-scan sends IKE main mode requests to the specified hosts and displays
 * any responses that are received.  It handles retry and retransmission with
 * backoff to cope with packet loss.
 *
 * Use ike-scan --help to display information on the usage and options.
 * See the README file for full details.
 *
 */
#include "socketwrapper.h"
#include "ike-scan.h"

static const char rcsid[] =
	"$Id: ike-scan.c,v 1.1.1.1 2005/01/13 18:45:15 mcr Exp $";                       /* RCS ID for ident(1) */

/* Global variables */
struct host_entry *helist = NULL;               /* Dynamic array of host entries */
struct host_entry **helistptr;                  /* Array of pointers to host entries */
struct host_entry **cursor;                     /* Pointer to current list entry */
struct pattern_list *patlist = NULL;            /* Backoff pattern list */
#ifdef HAVE_REGEX_H
struct vid_pattern_list *vidlist = NULL;        /* Vendor ID pattern list */
#endif
static int verbose = 0;                         /* Verbose level */
unsigned experimental_value = 0;                /* Experimental value */
int tcp_flag = 0;                               /* TCP flag */
int psk_crack_flag = 0;                         /* Pre-shared key cracking flag */
struct psk_crack psk_values = {                 /* Pre-shared key values */
	NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0, NULL, 0,
	NULL, 0
};
int no_dns_flag = 0;                      /* No DNS flag */

int main(int argc, char *argv[])
{
	const struct option long_options[] = {
		{ "file", required_argument, 0, 'f' },
		{ "help", no_argument, 0, 'h' },
		{ "sport", required_argument, 0, 's' },
		{ "dport", required_argument, 0, 'd' },
		{ "retry", required_argument, 0, 'r' },
		{ "timeout", required_argument, 0, 't' },
		{ "interval", required_argument, 0, 'i' },
		{ "backoff", required_argument, 0, 'b' },
		{ "selectwait", required_argument, 0, 'w' },
		{ "verbose", no_argument, 0, 'v' },
		{ "lifetime", required_argument, 0, 'l' },
		{ "lifesize", required_argument, 0, 'z' },
		{ "auth", required_argument, 0, 'm' },
		{ "version", no_argument, 0, 'V' },
		{ "vendor", required_argument, 0, 'e' },
		{ "trans", required_argument, 0, 'a' },
		{ "showbackoff", optional_argument, 0, 'o' },
		{ "fuzz", required_argument, 0, 'u' },
		{ "id", required_argument, 0, 'n' },
		{ "idtype", required_argument, 0, 'y' },
		{ "dhgroup", required_argument, 0, 'g' },
		{ "patterns", required_argument, 0, 'p' },
		{ "aggressive", no_argument, 0, 'A' },
		{ "gssid", required_argument, 0, 'G' },
		{ "vidpatterns", required_argument, 0, 'I' },
		{ "quiet", no_argument, 0, 'q' },
		{ "multiline", no_argument, 0, 'M' },
		{ "random", no_argument, 0, 'R' },
		{ "tcp", optional_argument, 0, 'T' },
		{ "pskcrack", optional_argument, 0, 'P' },
		{ "tcptimeout", required_argument, 0, 'O' },
		{ "nodns", no_argument, 0, 'N' },
		{ "experimental", required_argument, 0, 'X' },
		{ 0, 0, 0, 0 }
	};
	const char *short_options =
		"f:hs:d:r:t:i:b:w:vl:z:m:Ve:a:o::u:n:y:g:p:AG:I:qMRT::P::O:NX:";
	int arg;
	char arg_str[MAXLINE];  /* Args as string for syslog */
	int options_index = 0;
	char filename[MAXLINE];
	int filename_flag = 0;
	int random_flag = 0;                            /* Should we randomise the list? */
	int sockfd;                                     /* UDP socket file descriptor */
	unsigned source_port = DEFAULT_SOURCE_PORT;     /* UDP source port */
	unsigned dest_port = DEFAULT_DEST_PORT;         /* UDP destination port */
	unsigned retry = DEFAULT_RETRY;                 /* Number of retries */
	unsigned interval = 1000 * DEFAULT_INTERVAL;    /* Interval between packets */
	double backoff_factor = DEFAULT_BACKOFF_FACTOR; /* Backoff factor */
	unsigned end_wait = 1000 * DEFAULT_END_WAIT;    /* Time to wait after all done in ms */
	unsigned timeout = DEFAULT_TIMEOUT;             /* Per-host timeout in ms */
	unsigned lifetime = DEFAULT_LIFETIME;           /* Lifetime in seconds */
	unsigned lifesize = DEFAULT_LIFESIZE;           /* Lifesize in KB */
	unsigned auth_method = DEFAULT_AUTH_METHOD;     /* Authentication method */
	unsigned dhgroup = DEFAULT_DH_GROUP;            /* Diffie Hellman Group */
	unsigned idtype = DEFAULT_IDTYPE;               /* IKE Identification type */
	unsigned pattern_fuzz = DEFAULT_PATTERN_FUZZ;   /* Pattern matching fuzz in ms */
	unsigned exchange_type = DEFAULT_EXCHANGE_TYPE; /* Main or Aggressive mode */
	unsigned tcp_connect_timeout = DEFAULT_TCP_CONNECT_TIMEOUT;
	struct sockaddr_in sa_local;
	struct sockaddr_in sa_peer;
	struct timeval now;
	unsigned char packet_in[MAXUDP]; /* Received packet */
	struct hostent *hp;
	int n;
	struct host_entry *temp_cursor;
	struct timeval diff;                    /* Difference between two timevals */
	IKE_UINT64 loop_timediff;               /* Time since last packet sent in us */
	IKE_UINT64 host_timediff;               /* Time since last packet sent to this host */
	unsigned long end_timediff = 0;         /* Time since last packet received in ms */
	int req_interval;                       /* Requested per-packet interval */
	int select_timeout;                     /* Select timeout */
	int cum_err = 0;                        /* Cumulative timing error */
	static int reset_cum_err;
	struct timeval start_time;              /* Program start time */
	struct timeval end_time;                /* Program end time */
	struct timeval last_packet_time;        /* Time last packet was sent */
	struct timeval elapsed_time;            /* Elapsed time as timeval */
	double elapsed_seconds;                 /* Elapsed time in seconds */
	int arg_str_space;                      /* Used to avoid buffer overruns when copying */
	char patfile[MAXLINE];                  /* IKE Backoff pattern file name */
	char vidfile[MAXLINE];                  /* IKE Vendor ID pattern file name */
	char psk_crack_file[MAXLINE];           /* PSK crack data output file name */
	unsigned pass_no = 0;
	int first_timeout = 1;
	unsigned char *vid_data;        /* Binary Vendor ID data */
	size_t vid_data_len;            /* Vendor ID data length */
	unsigned char *gss_data = NULL; /* Binary GSSID data */
	size_t gss_data_len = 0;        /* GSSID data length */
	unsigned char *id_data = NULL;  /* Identity data */
	size_t id_data_len = 0;         /* Identity data length */
	int vendor_id_flag = 0;         /* Indicates if VID to be used */
	int gss_id_flag = 0;            /* Indicates if GSSID to be used */
	int trans_flag = 0;             /* Indicates custom transform */
	int showbackoff_flag = 0;       /* Display backoff table? */
	struct timeval last_recv_time;  /* Time last packet was received */
	unsigned char *packet_out;      /* IKE packet to send */
	size_t packet_out_len;          /* Length of IKE packet to send */
	unsigned sa_responders = 0;     /* Number of hosts giving handshake */
	unsigned notify_responders = 0; /* Number of hosts giving notify msg */
	unsigned num_hosts = 0;         /* Number of entries in the list */
	unsigned live_count;            /* Number of entries awaiting reply */
	int quiet = 0;                  /* Only print the basic info if nonzero */
	int multiline = 0;              /* Split decodes across lines if nonzero */
	int hostno;

/*
 *	Open syslog channel and log arguments if required.
 *	We must be careful here to avoid overflowing the arg_str buffer
 *	which could result in a buffer overflow vulnerability.
 */
#ifdef SYSLOG
	openlog("ike-scan", LOG_PID, SYSLOG_FACILITY);
	arg_str[0] = '\0';
	arg_str_space = MAXLINE; /* Amount of space left in the arg_str buffer */
	for (arg = 0; arg < argc; arg++) {
		arg_str_space -= strlen(argv[arg]);
		if (arg_str_space > 0) {
			strncat(arg_str, argv[arg], (size_t) arg_str_space);
			if (arg < (argc - 1)) {
				if (--arg_str_space > 0)
					strcat(arg_str, " ");
			}
		}
	}
	info_syslog("Starting: %s", arg_str);
#endif
/*
 *      Get program start time for statistics displayed on completion.
 */
	Gettimeofday(&start_time);
/*
 *	Initialise IKE pattern file names to the empty string.
 */
	patfile[0] = '\0';
	vidfile[0] = '\0';
/*
 *	Seed random number generator.
 */
	srand((unsigned) time(NULL));
/*
 *	Process options and arguments.
 */
	while ((arg =
			getopt_long_only(argc, argv, short_options,
					 long_options,
					 &options_index)) != -1) {
		switch (arg) {
			unsigned trans_enc;             /* Custom transform cipher */
			unsigned trans_keylen;          /* Custom transform cipher key length */
			unsigned trans_hash;            /* Custom transform hash */
			unsigned trans_auth;            /* Custom transform auth */
			unsigned trans_group;           /* Custom transform DH group */
			char trans_str[MAXLINE];        /* Custom transform string */
			char interval_str[MAXLINE];     /* --interval argument */
			size_t interval_len;            /* --interval argument length */
		case 'f':                               /* --file */
			strncpy(filename, optarg, MAXLINE);
			filename_flag = 1;
			break;
		case 'h': /* --help */
			usage(EXIT_SUCCESS);
			break;
		case 's': /* --sport */
			source_port = strtoul(optarg, (char **)NULL, 10);
			break;
		case 'd': /* --dport */
			dest_port = strtoul(optarg, (char **)NULL, 10);
			break;
		case 'r': /* --retry */
			retry = strtoul(optarg, (char **)NULL, 10);
			break;
		case 't': /* --timeout */
			timeout = strtoul(optarg, (char **)NULL, 10);
			break;
		case 'i': /* --interval */
			strncpy(interval_str, optarg, MAXLINE);
			interval_len = strlen(interval_str);
			if (interval_str[interval_len - 1] == 'u') {
				interval = strtoul(interval_str, (char **)NULL,
						   10);
			} else {
				interval = 1000 *
					   strtoul(interval_str, (char **)NULL,
						   10);
			}
			break;
		case 'b': /* --backoff */
			backoff_factor = atof(optarg);
			break;
		case 'w': /* --selectwait */
			fprintf(stderr,
				"--selectwait option ignored - no longer needed\n");
			break;
		case 'v': /* --verbose */
			verbose++;
			break;
		case 'l': /* --lifetime */
			lifetime = strtoul(optarg, (char **)NULL, 10);
			break;
		case 'z': /* --lifesize */
			lifesize = strtoul(optarg, (char **)NULL, 10);
			break;
		case 'm': /* --auth */
			auth_method = strtoul(optarg, (char **)NULL, 10);
			break;
		case 'V': /* --version */
			fprintf(stderr, "%s\n\n", PACKAGE_STRING);
			fprintf(stderr,
				"Copyright (C) 2003-2005 Roy Hills, NTA Monitor Ltd.\n");
			fprintf(stderr,
				"ike-scan comes with NO WARRANTY to the extent permitted by law.\n");
			fprintf(stderr,
				"You may redistribute copies of ike-scan under the terms of the GNU\n");
			fprintf(stderr, "General Public License.\n");
			fprintf(stderr,
				"For more information about these matters, see the file named COPYING.\n");
			fprintf(stderr, "\n");
/* We use rcsid here to prevent it being optimised away */
			fprintf(stderr, "%s\n", rcsid);
			isakmp_use_rcsid();
			error_use_rcsid();
			utils_use_rcsid();
			wrappers_use_rcsid();
			exit(EXIT_SUCCESS);
			break;
		case 'e':                       /* --vendor */
			if (strlen(optarg) % 2) /* Length is odd */
				err_msg(
					"ERROR: Length of --vendor argument must be even (multiple of 2).");


			vendor_id_flag = 1;
			vid_data = hex2data(optarg, &vid_data_len);
			add_vid(0, NULL, vid_data, vid_data_len);
			free(vid_data);
			break;
		case 'a': /* --trans */
			strncpy(trans_str, optarg, MAXLINE);
			trans_flag++;
			decode_trans(trans_str, &trans_enc, &trans_keylen,
				     &trans_hash,
				     &trans_auth, &trans_group);
			add_trans(0, NULL, trans_enc, trans_keylen, trans_hash,
				  trans_auth, trans_group, lifetime, lifesize,
				  gss_id_flag, gss_data, gss_data_len);
			break;
		case 'o': /* --showbackoff */
			showbackoff_flag = 1;
			if (optarg == NULL)
				end_wait = 1000 * DEFAULT_END_WAIT;
			else
				end_wait = 1000 * strtoul(optarg,
							  (char **)NULL, 10);
			break;
		case 'u': /* --fuzz */
			pattern_fuzz = strtoul(optarg, (char **)NULL, 10);
			break;
		case 'n': /* --id */
			if (id_data)
				err_msg(
					"ERROR: You may only specify one identity payload with --id");


			id_data = hex_or_str(optarg, &id_data_len);
			break;
		case 'y': /* --idtype */
			idtype = strtoul(optarg, (char **)NULL, 10);
			break;
		case 'g': /* --dhgroup */
			dhgroup = strtoul(optarg, (char **)NULL, 10);
			break;
		case 'p': /* --patterns */
			strncpy(patfile, optarg, MAXLINE);
			break;
		case 'A': /* --aggressive */
			exchange_type = ISAKMP_XCHG_AGGR;
			break;
		case 'G':                       /* --gssid */
			if (strlen(optarg) % 2) /* Length is odd */
				err_msg(
					"ERROR: Length of --gssid argument must be even (multiple of 2).");


			gss_id_flag = 1;
			gss_data = hex2data(optarg, &gss_data_len);
			break;
		case 'I': /* --vidpatterns */
			strncpy(vidfile, optarg, MAXLINE);
			break;
		case 'q': /* --quiet */
			quiet = 1;
			break;
		case 'M': /* --multiline */
			multiline = 1;
			break;
		case 'R': /* --random */
			random_flag = 1;
			break;
		case 'T': /* --tcp */
			if (optarg == NULL)
				tcp_flag = TCP_PROTO_RAW;
			else
				tcp_flag = strtoul(optarg, (char **)NULL, 10);
			break;
		case 'P': /* --pskcrack */
			psk_crack_flag = 1;
			if (optarg)
				strncpy(psk_crack_file, optarg, MAXLINE);
			else
				psk_crack_file[0] = '\0';       /* use stdout */
			break;
		case 'O':                                       /* --tcptimeout */
			tcp_connect_timeout =
				strtoul(optarg, (char **)NULL, 10);
			break;
		case 'N': /* --nodns */
			no_dns_flag = 1;
			break;
		case 'X': /* --experimental */
			experimental_value =
				strtoul(optarg, (char **)NULL, 10);
			break;
		default: /* Unknown option */
			usage(EXIT_FAILURE);
			break;
		}
	}
/*
 *	If we're not reading from a file, then we must have some hosts
 *	given as command line arguments.
 */
	if (!no_dns_flag)
		hp = gethostbyname("ike-scan-target.test.nta-monitor.com");
	if (!filename_flag)
		if ((argc - optind) < 1)
			usage(EXIT_FAILURE);
/*
 *	Populate the list from the specified file if --file was specified, or
 *	otherwise from the remaining command line arguments.
 */
	if (filename_flag) { /* Populate list from file */
		FILE *fp;
		char line[MAXLINE];
		char *cp;

		if ((strcmp(filename, "-")) == 0) { /* Filename "-" means stdin */
			fp = stdin;
		} else {
			if ((fp = fopen(filename, "r")) == NULL)
				err_sys("ERROR: fopen");
		}

		while (fgets(line, MAXLINE, fp)) {
			for (cp = line;
			     !isspace((unsigned char)*cp) && *cp != '\0'; cp++)
				;
			*cp = '\0';
			add_host_pattern(line, timeout, &num_hosts);
		}
		if (fp != stdin)
			fclose(fp);
	} else {        /* Populate list from command line arguments */
		argv = &argv[optind];
		while (*argv) {
			add_host_pattern(*argv, timeout, &num_hosts);
			argv++;
		}
	}
/*
 *	If we are displaying the backoff table, load known backoff
 *	patterns from the backoff patterns file.
 */
	if (showbackoff_flag)
		load_backoff_patterns(patfile, pattern_fuzz);
/*
 *	Load known Vendor ID patterns from the Vendor ID file.
 */
#ifdef HAVE_REGEX_H
	load_vid_patterns(vidfile);
#endif
/*
 *	Check that we have at least one entry in the list.
 */
	if (!num_hosts)
		err_msg("ERROR: No hosts to process.");
/*
 *	Check that the combination of specified options and arguments is
 *	valid.
 */
	if (tcp_flag && num_hosts > 1)
		err_msg(
			"ERROR: You can only specify one target host with the --tcp option.");


	if (*patfile != '\0' && !showbackoff_flag)
		warn_msg(
			"WARNING: Specifying a backoff pattern file with --patterns or -p does not\n         have any effect unless you also specify --showbackoff or -o\n");


	if (id_data && exchange_type != ISAKMP_XCHG_AGGR)
		warn_msg(
			"WARNING: Specifying an identification payload with --id or -n does not have\n         any effect unless you also specify aggressive mode with --aggressive\n         or -A\n");


	if (idtype != DEFAULT_IDTYPE && exchange_type != ISAKMP_XCHG_AGGR)
		warn_msg(
			"WARNING: Specifying an idtype payload with --idtype or -y does not have any\n         effect unless you also specify aggressive mode with --aggressive or -A\n");


	if (dhgroup != DEFAULT_DH_GROUP && exchange_type != ISAKMP_XCHG_AGGR)
		warn_msg(
			"WARNING: Specifying the DH Group with --dhgroup or -g does not have any effect\n         unless you also specify aggressive mode with --aggressive or -A\n");


	if (psk_crack_flag && exchange_type != ISAKMP_XCHG_AGGR) {
		warn_msg(
			"WARNING: The --pskcrack (-P) option is only relevant for aggressive mode.\n");
		psk_crack_flag = 0;
	}

	if (psk_crack_flag && num_hosts > 1)
		err_msg(
			"ERROR: You can only specify one target host with the --pskcrack (-P) option.");


/*
 *      Create and initialise array of pointers to host entries.
 */
	helistptr = Malloc(num_hosts * sizeof(struct host_entry *));
	for (hostno = 0; hostno < num_hosts; hostno++)
		helistptr[hostno] = &helist[hostno];
/*
 *      Randomise the list if required.
 *	Uses Knuth's shuffle algorithm.
 */
	if (random_flag) {
		struct timeval tv;
		int i;
		int r;
		struct host_entry *temp;

		Gettimeofday(&tv);
		srand((unsigned) tv.tv_usec ^ (unsigned) getpid());

		for (i = num_hosts - 1; i > 0; i--) {
			r = (int)((double)rand() / ((double)RAND_MAX + 1) * i); /* 0<=r<i */
			temp = helistptr[i];
			helistptr[i] = helistptr[r];
			helistptr[r] = temp;
		}
	}
/*
 *	Create network socket and bind to local source port.
 */
	if (tcp_flag) {
		const int on = 1; /* for setsockopt() */

		if ((sockfd = safe_socket(AF_INET, SOCK_STREAM, 0)) < 0)
			err_sys("ERROR: socket");
		if ((setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &on,
				sizeof(on))) < 0)
			err_sys("ERROR: setsockopt() failed");
	} else {
		if ((sockfd = safe_socket(AF_INET, SOCK_DGRAM, 0)) < 0)
			err_sys("ERROR: socket");
	}

	memset(&sa_local, '\0', sizeof(sa_local));
	sa_local.sin_family = AF_INET;
	sa_local.sin_addr.s_addr = htonl(INADDR_ANY);
	sa_local.sin_port = htons(source_port);

	if ((bind(sockfd, (struct sockaddr *)&sa_local,
		  sizeof(sa_local))) < 0) {
		warn_msg(
			"ERROR: Could not bind network socket to local port %u",
			source_port);
		if (errno == EACCES)
			warn_msg(
				"You need to be root, or ike-scan must be suid root to bind to ports below 1024.");


		if (errno == EADDRINUSE)
			warn_msg(
				"Only one process may bind to the source port at any one time.");


		err_sys("ERROR: bind");
	}
/*
 *	If we are using TCP transport, then connect the socket to the peer.
 *	We know that there is only one entry in the host list if we're using
 *	TCP.
 */
	if (tcp_flag) {
		struct sockaddr_in sa_tcp;
		NET_SIZE_T sa_tcp_len;
		struct sigaction act, oact; /* For sigaction */
/*
 *      Set signal handler for alarm.
 *      Must use sigaction() rather than signal() to prevent SA_RESTART
 */
		act.sa_handler = sig_alarm;
		sigemptyset(&act.sa_mask);
		act.sa_flags = 0;
		sigaction(SIGALRM, &act, &oact);
/*
 *	Set alarm
 */
		alarm(tcp_connect_timeout);
/*
 *	Connect to peer
 */
		memset(&sa_tcp, '\0', sizeof(sa_tcp));
		sa_tcp.sin_family = AF_INET;
		sa_tcp.sin_addr.s_addr = helist->addr.s_addr;
		sa_tcp.sin_port = htons(dest_port);
		sa_tcp_len = sizeof(sa_tcp);
		if ((connect(sockfd, (struct sockaddr *) &sa_tcp,
			     sa_tcp_len)) != 0) {
			if (errno == EINTR)
				errno = ETIMEDOUT;
			err_sys("ERROR: TCP connect");
		}
/*
 *	Cancel alarm
 */
		alarm(0);
	}
/*
 *	Set current host pointer (cursor) to start of list, zero
 *	last packet sent time, set last receive time to now and
 *	initialise static IKE header fields.
 */
	live_count = num_hosts;
	cursor = helistptr;
	last_packet_time.tv_sec = 0;
	last_packet_time.tv_usec = 0;
	Gettimeofday(&last_recv_time);
	packet_out = initialise_ike_packet(&packet_out_len, lifetime, lifesize,
					   auth_method, dhgroup, idtype,
					   id_data, id_data_len,
					   vendor_id_flag,
					   trans_flag, exchange_type,
					   gss_id_flag,
					   gss_data, gss_data_len);
/*
 *	Display initial message.
 */
	printf(
		"Starting %s with %u hosts (http://www.nta-monitor.com/ike-scan/)\n", PACKAGE_STRING,
		num_hosts);
/*
 *	Display the lists if verbose setting is 3 or more.
 */
	if (verbose > 2) {
		dump_list(num_hosts);
		if (showbackoff_flag)
			dump_backoff(pattern_fuzz);
#ifdef HAVE_REGEX_H
		dump_vid();
#else
		warn_msg(
			"This ike-scan binary was not compiled with Posix regular expression support.");
		warn_msg("Vendor ID Fingerprinting will not be possible.");
#endif
	}
/*
 *	Main loop: send packets to all hosts in order until a response
 *	has been received or the host has exhausted its retry limit.
 *
 *	The loop exits when all hosts have either responded or timed out
 *	and, if showbackoff_flag is set, at least end_wait ms have elapsed
 *	since the last packet was received and we have received at least one
 *	transform response.
 */
	reset_cum_err = 1;
	req_interval = interval;
	while (live_count ||
	       (showbackoff_flag && sa_responders &&
		(end_timediff < end_wait))) {
		int s_err = 0; /* smoothed timing error */
/*
 *	Obtain current time and calculate deltas since last packet and
 *	last packet to this host.
 */
		Gettimeofday(&now);
		timeval_diff(&now, &last_recv_time, &diff);
		end_timediff = 1000 * diff.tv_sec + diff.tv_usec / 1000;
/*
 *	If the last packet was sent more than interval us ago, then we can
 *	potentially send a packet to the current host.
 */
		timeval_diff(&now, &last_packet_time, &diff);
		loop_timediff = 1000000 * diff.tv_sec + diff.tv_usec;
		if (loop_timediff >= req_interval) {
/*
 *	If the last packet to this host was sent more than the current
 *	timeout for this host us ago, then we can potentially send a packet
 *	to it.
 */
			timeval_diff(&now, &((*cursor)->last_send_time),
				     &diff);
			host_timediff = 1000000 * diff.tv_sec + diff.tv_usec;
			if (host_timediff >= (*cursor)->timeout &&
			    (*cursor)->live) {
				if (reset_cum_err) {
					s_err = 0;
					cum_err = 0;
					req_interval = interval;
					reset_cum_err = 0;
				} else {
#ifdef ALPHA
					s_err = (ALPHA * s_err) +
						(1 -
						 ALPHA) *
						(long)(loop_timediff -
						       interval);
					cum_err += s_err;
#else
					cum_err += loop_timediff - interval;
#endif
					if (req_interval > cum_err)
						req_interval = req_interval -
							       cum_err;
					else
						req_interval = 0;
				}
				select_timeout = req_interval;
/*
 *	If we've exceeded our retry limit, then this host has timed out so
 *	remove it from the list.  Otherwise, increase the timeout by the
 *	backoff factor if this is not the first packet sent to this host
 *	and send a packet.
 */

/* This message only works if the list is not empty */
				if (verbose && (*cursor)->num_sent > pass_no) {
					warn_msg(
						"---\tPass %d of %u completed",
						++pass_no, retry);
				}
				if ((*cursor)->num_sent >= retry) {
					if (verbose > 1) {
						warn_msg(
							"---\tRemoving host entry %u (%s) - Timeout",
							(*cursor)->n,
							inet_ntoa((*cursor)->
								  addr));
					}
					remove_host(cursor, &live_count,
						    num_hosts); /* Automatically calls advance_cursor() */
					if (first_timeout) {
						timeval_diff(&now,
							     &((*cursor)->
							       last_send_time),
							     &diff);
						host_timediff = 1000000 *
								diff.tv_sec +
								diff.tv_usec;
						while (host_timediff >=
						       (*cursor)->timeout &&
						       live_count) {
							if ((*cursor)->live) {
								if (verbose >
								    1) {
									warn_msg(
										"---\tRemoving host %u (%s) - Timeout",
										(
											*
											cursor)->n,
										inet_ntoa((
												  *
												  cursor)
											  ->
											  addr));
								}

								remove_host(
									cursor,
									&live_count,
									num_hosts);
							} else {
								advance_cursor(
									live_count,
									num_hosts);
							}
							timeval_diff(&now,
								     &((*cursor)
								       ->
								       last_send_time),
								     &diff);
							host_timediff =
								1000000 *
								diff.tv_sec +
								diff.tv_usec;
						}
						first_timeout = 0;
					}
					Gettimeofday(&last_packet_time);
				} else { /* Retry limit not reached for this host */
					if ((*cursor)->num_sent)
						(*cursor)->timeout *=
							backoff_factor;
					send_packet(sockfd, packet_out,
						    packet_out_len, *cursor,
						    dest_port,
						    &last_packet_time);
					advance_cursor(live_count, num_hosts);
				}
			} else { /* We can't send a packet to this host yet */
/*
 *	Note that there is no point calling advance_cursor() here because if
 *	host n is not ready to send, then host n+1 will not be ready either.
 */
				if (live_count)
					select_timeout = (*cursor)->timeout -
							 host_timediff;
				else
					select_timeout = interval;
				reset_cum_err = 1;      /* Zero cumulative error */
			} /* End If */
		} else {                                /* We can't send a packet yet */
			select_timeout = req_interval - loop_timediff;
		} /* End If */
#ifdef DEBUG_TIMINGS
		printf(
			"int=%d, loop_t=%llu, req_int=%d, sel=%d, err=%d, cum_err=%d\n",
			interval, loop_timediff, req_interval, select_timeout, s_err,
			cum_err);
#endif
		n = recvfrom_wto(sockfd, packet_in, MAXUDP,
				 (struct sockaddr *)&sa_peer,
				 select_timeout);
		if (n != -1) {
/*
 *	We've received a response try to match up the packet by cookie
 *
 *	Note: We start at cursor->prev because we call advance_cursor() after
 *	      each send_packet().
 */
			temp_cursor = find_host_by_cookie(cursor, packet_in, n,
							  num_hosts);
			if (temp_cursor) {
/*
 *	We found a cookie match for the returned packet.
 */
				add_recv_time(temp_cursor, &last_recv_time);
				if (verbose > 1) {
					warn_msg(
						"---\tReceived packet #%u from %s", temp_cursor->num_recv,
						inet_ntoa(sa_peer.sin_addr));
				}
				if (temp_cursor->live) {
					display_packet(n, packet_in,
						       temp_cursor,
						       &(sa_peer.sin_addr),
						       &sa_responders,
						       &notify_responders,
						       quiet,
						       multiline);
					if (verbose > 1) {
						warn_msg(
							"---\tRemoving host entry %u (%s) - Received %d bytes", temp_cursor->n,
							inet_ntoa(sa_peer.
								  sin_addr),
							n);
					}
					remove_host(&temp_cursor, &live_count,
						    num_hosts);
				}
			} else {
				struct isakmp_hdr hdr_in;
/*
 *	The received cookie doesn't match any entry in the list.
 *	Issue a message to that effect if verbose is on and ignore the packet.
 */
				if (verbose && n >= sizeof(hdr_in)) {
					char *cp;
					memcpy(&hdr_in, packet_in,
					       sizeof(hdr_in));
					cp = hexstring(
						(unsigned char *)hdr_in.isa_icookie,
						sizeof(hdr_in.
						       isa_icookie));
					warn_msg(
						"---\tIgnoring %d bytes from %s with unknown cookie %s",
						n, inet_ntoa(
							sa_peer.sin_addr), cp);
					free(cp);
				}
			}
		}       /* End If */
	}               /* End While */
	close(sockfd);
/*
 *	Display the backoff times if --showbackoff option was specified
 *	and we have at least one system returning a handshake.
 */
	printf("\n");   /* Ensure we have a blank line */
	if (showbackoff_flag && sa_responders)
		dump_times(num_hosts);
/*
 *	Display PSK crack values if applicable
 */
	if (psk_crack_flag && psk_values.hash_r != NULL)
		print_psk_crack_values(psk_crack_file);
/*
 *	Get program end time and calculate elapsed time.
 */
	Gettimeofday(&end_time);
	timeval_diff(&end_time, &start_time, &elapsed_time);
	elapsed_seconds = (elapsed_time.tv_sec * 1000 +
			   elapsed_time.tv_usec / 1000.0) / 1000.0;

#ifdef SYSLOG
	info_syslog(
		"Ending: %u hosts scanned in %.3f seconds (%.2f hosts/sec). %u returned handshake; %u returned notify",
		num_hosts, elapsed_seconds, num_hosts / elapsed_seconds,
		sa_responders, notify_responders);
#endif
	printf(
		"Ending %s: %u hosts scanned in %.3f seconds (%.2f hosts/sec).  %u returned handshake; %u returned notify\n",
		PACKAGE_STRING, num_hosts, elapsed_seconds,
		num_hosts / elapsed_seconds, sa_responders, notify_responders);

	return 0;
}

/*
 *	add_host_pattern -- Add one or more new host to the list.
 *
 *	Inputs:
 *
 *	pattern	= The host pattern to add.
 *	timeout	= Per-host timeout in ms.
 *	num_hosts = The number of entries in the host list.
 *
 *	Returns: None
 *
 *	This adds one or more new hosts to the list.  The pattern argument
 *	can either be a single host or IP address, in which case one host
 *	will be added to the list, or it can specify a number of hosts with
 *	the IPnet/bits or IPstart-IPend formats.
 *
 *	The timeout and num_hosts arguments are passed unchanged to add_host().
 */
void add_host_pattern(const char *pattern, unsigned timeout,
		      unsigned *num_hosts)
{
	char *patcopy;
	struct in_addr in_val;
	unsigned numbits;
	char *cp;
	uint32_t ipnet_val;
	uint32_t network;
	uint32_t mask;
	unsigned long hoststart;
	unsigned long hostend;
	unsigned i;

/*
 *	Make a copy of pattern because we don't want to modify our argument.
 */
	patcopy = Malloc(strlen(pattern) + 1);
	strcpy(patcopy, pattern);

	if ((cp = strchr(patcopy, '/'))) {      /* IPnet/bits */
/*
 *	Get IPnet and bits as integers.  Perform basic error checking.
 */
		*(cp++) = '\0';                 /* patcopy points to IPnet, cp points to bits */
		if (!(inet_aton(patcopy, &in_val)))
			err_msg("ERROR: %s is not a valid IP address",
				patcopy);
		ipnet_val = ntohl(in_val.s_addr); /* We need host byte order */
		numbits = strtoul(cp, (char **) NULL, 10);
		if (numbits < 3 || numbits > 32) {
			err_msg(
				"ERROR: Number of bits in %s must be between 3 and 32",
				pattern);
		}
/*
 *	Construct 32-bit network bitmask from number of bits.
 */
		mask = 0;
		for (i = 0; i < numbits; i++)
			mask += 1 << i;
		mask = mask << (32 - i);
/*
 *	Mask off the network.  Warn if the host bits were non-zero.
 */
		network = ipnet_val & mask;
		if (network != ipnet_val)
			warn_msg("WARNING: host part of %s is non-zero",
				 pattern);
/*
 *	Determine maximum and minimum host values.  We include the host
 *	and broadcast.
 */
		hoststart = 0;
		hostend = (1 << (32 - numbits)) - 1;
/*
 *	Calculate all host addresses in the range and feed to add_host()
 *	in dotted-quad format.
 */
		for (i = hoststart; i <= hostend; i++) {
			uint32_t hostip;
			int b1, b2, b3, b4;
			char ipstr[16];

			hostip = network + i;
			b1 = (hostip & 0xff000000) >> 24;
			b2 = (hostip & 0x00ff0000) >> 16;
			b3 = (hostip & 0x0000ff00) >> 8;
			b4 = (hostip & 0x000000ff);
			sprintf(ipstr, "%d.%d.%d.%d", b1, b2, b3, b4);
			add_host(ipstr, timeout, num_hosts);
		}
	} else if ((cp = strchr(patcopy, '-'))) {       /* IPstart-IPend */
/*
 *	Get IPstart and IPend as integers.
 */
		*(cp++) = '\0';                         /* patcopy points to IPstart, cp points to IPend */
		if (!(inet_aton(patcopy, &in_val)))
			err_msg("ERROR: %s is not a valid IP address",
				patcopy);
		hoststart = ntohl(in_val.s_addr); /* We need host byte order */
		if (!(inet_aton(cp, &in_val)))
			err_msg("ERROR: %s is not a valid IP address", cp);
		hostend = ntohl(in_val.s_addr); /* We need host byte order */
/*
 *	Calculate all host addresses in the range and feed to add_host()
 *	in dotted-quad format.
 */
		for (i = hoststart; i <= hostend; i++) {
			int b1, b2, b3, b4;
			char ipstr[16];

			b1 = (i & 0xff000000) >> 24;
			b2 = (i & 0x00ff0000) >> 16;
			b3 = (i & 0x0000ff00) >> 8;
			b4 = (i & 0x000000ff);
			sprintf(ipstr, "%d.%d.%d.%d", b1, b2, b3, b4);
			add_host(ipstr, timeout, num_hosts);
		}
	} else {                        /* Single host */
		add_host(patcopy, timeout, num_hosts);
	}
	free(patcopy);
}

/*
 *	add_host -- Add a new host to the list.
 *
 *	Inputs:
 *
 *	name	= The Name or IP address of the host.
 *	timeout	= Per-host timeout in ms.
 *	num_hosts = The number of entries in the host list.
 *
 *	Returns: None
 */
void add_host(const char *name, unsigned timeout, unsigned *num_hosts)
{
	struct hostent *hp = NULL;
	struct host_entry *he;
	struct in_addr inp;
	char str[MAXLINE];
	struct timeval now;
	static int num_left = 0; /* Number of free entries left */

	if (no_dns_flag) {
		if (!(inet_aton(name, &inp)))
			err_msg("ERROR: inet_aton failed for \"%s\"", name);
	} else {
		if ((hp = gethostbyname(name)) == NULL)
			err_sys("ERROR: gethostbyname failed for \"%s\"",
				name);
	}

	if (!num_left) { /* No entries left, allocate some more */
		if (helist) {
			helist =
				Realloc(helist,
					((*num_hosts) *
					 sizeof(struct host_entry)) +
					REALLOC_COUNT *
					sizeof(struct host_entry));
		} else {
			helist =
				Malloc(
					REALLOC_COUNT *
					sizeof(struct host_entry));
		}
		num_left = REALLOC_COUNT;
	}

	he = helist + (*num_hosts); /* Would array notation be better? */

	(*num_hosts)++;
	num_left--;

	Gettimeofday(&now);

	he->n = *num_hosts;
	if (no_dns_flag)
		memcpy(&(he->addr), &inp, sizeof(struct in_addr));
	else
		memcpy(&(he->addr), hp->h_addr_list[0],
		       sizeof(struct in_addr));
	he->live = 1;
	he->timeout = timeout * 1000;   /* Convert from ms to us */
	he->num_sent = 0;
	he->num_recv = 0;
	he->last_send_time.tv_sec = 0;
	he->last_send_time.tv_usec = 0;
	he->recv_times = NULL;
/*
 * We cast the timeval elements to unsigned long because different vendors
 * use different types for them (int, long, unsigned int and unsigned long).
 * As long is the widest type, and the values should always be positive, it's
 * safe to cast to unsigned long.
 */
	sprintf(str, "%lu %lu %u %s", (unsigned long) now.tv_sec,
		(unsigned long) now.tv_usec, *num_hosts, inet_ntoa(he->addr));
	memcpy(he->icookie, MD5((unsigned char *)str, strlen(str), NULL),
	       sizeof(he->icookie));
}

/*
 *      remove_host -- Remove the specified host from the list
 *
 *	Inputs:
 *
 *	he		Pointer to host entry to remove.
 *	live_count	Number of hosts awaiting response.
 *	num_hosts	The number of hosts in the list.
 *
 *	Returns:
 *
 *	None.
 *
 *	If the host being removed is the one pointed to by the cursor, this
 *	function updates cursor so that it points to the next entry.
 */
void remove_host(struct host_entry **he, unsigned *live_count,
		 unsigned num_hosts)
{
	(*he)->live = 0;
	(*live_count)--;
	if (*he == *cursor)
		advance_cursor(*live_count, num_hosts);
}

/*
 *	advance_cursor -- Advance the cursor to point at next live entry
 *
 *	Inputs:
 *
 *	live_count	Number of hosts awaiting reply.
 *	num_hosts	The number of hosts in the list.
 *
 *	Returns:
 *
 *	None.
 *
 *	Does nothing if there are no live entries in the list.
 */
void advance_cursor(unsigned live_count, unsigned num_hosts)
{
	if (live_count) {
		do {
			if (cursor == (helistptr + (num_hosts - 1)))
				cursor = helistptr; /* Wrap round to beginning */
			else
				cursor++;
		} while (!(*cursor)->live);
	} /* End If */
}

/*
 *	find_host_by_cookie	-- Find a host in the list by cookie
 *
 *	Inputs:
 *
 *	he              Pointer to current position in list.  Search runs
 *			backwards starting from this point.
 *
 *	packet_in	points to the received packet containing the cookie.
 *
 *	n               Size of the received packet in bytes.
 *	num_hosts	The number of hosts in the list.
 *
 *	Returns a pointer to the host entry associated with the specified IP
 *	or NULL if no match found.
 */
struct host_entry *find_host_by_cookie(struct host_entry **he,
				       unsigned char *packet_in, int n,
				       unsigned num_hosts)
{
	struct host_entry **p;
	int found = 0;
	struct isakmp_hdr hdr_in;

/*
 *	Check that the current list position is not null.  Return NULL if it
 *	is.  It's possible for "he" to be NULL if a packet is received just
 *	after the last entry in the list is removed.
 */
	if (*he == NULL)
		return NULL;

/*
 *	Check that the received packet is at least as big as the ISAKMP
 *	header.  Return NULL if not.
 */
	if (n < sizeof(hdr_in))
		return NULL;

/*
 *	Copy packet into ISAKMP header structure.
 */
	memcpy(&hdr_in, packet_in, sizeof(hdr_in));

	p = he;

	do {
		if ((*p)->icookie[0] == hdr_in.isa_icookie[0] &&
		    (*p)->icookie[1] == hdr_in.isa_icookie[1]) {
			found = 1;
		} else {
			if (p == helistptr)
				p = helistptr + (num_hosts - 1); /* Wrap round to end */
			else
				p--;
		}
	} while (!found && p != he);

	if (found)
		return *p;
	else
		return NULL;
}

/*
 *	display_packet -- Display received IKE packet
 *
 *	Inputs:
 *
 *	n               The length of the received packet in bytes
 *	packet_in       The received packet
 *	he              The host entry corresponding to the received packet
 *	recv_addr       IP address that the packet was received from
 *	sa_responders	Number of hosts responding with SA
 *	notify_responders	Number of hosts responding with NOTIFY
 *	quiet		Only display basic info if nonzero
 *	multiline	Split decodes across lines if nonzero
 *
 *	Returns:
 *
 *	None.
 *
 *	This should check the received packet and display details of what
 *	was received in the format: <IP-Address><TAB><Details>.
 */
void display_packet(int n, unsigned char *packet_in, struct host_entry *he,
		    struct in_addr *recv_addr, unsigned *sa_responders,
		    unsigned *notify_responders, int quiet, int multiline)
{
	char *cp;               /* Temp pointer */
	size_t bytes_left;      /* Remaining buffer size */
	unsigned next;          /* Next Payload */
	unsigned type;          /* Exchange Type */
	char *msg;              /* Message to display */
	char *msg2;
	unsigned char *pkt_ptr;
	static const char *payload_name[] = {   /* Payload types from RFC 2408 3.1 */
		NULL,                           /* 0 */
		"SecurityAssociation",          /* 1 */
		"Proposal",                     /* 2 */
		"Transform",                    /* 3 */
		"KeyExchange",                  /* 4 */
		"Identification",               /* 5 */
		"Certificate",                  /* 6 */
		"CertificateRequest",           /* 7 */
		"Hash",                         /* 8 */
		"Signature",                    /* 9 */
		"Nonce",                        /* 10 */
		"Notification",                 /* 11 */
		"Delete",                       /* 12 */
		"VendorID"                      /* 13 */
	};

/*
 *	Set msg to the IP address of the host entry, plus the address of the
 *	responder if different, and a tab.
 */
	msg = make_message("%s\t", inet_ntoa(he->addr));
	if (((he->addr).s_addr != recv_addr->s_addr) && !tcp_flag) {
		cp = msg;
		msg = make_message("%s(%s) ", cp, inet_ntoa(*recv_addr));
		free(cp);
	}
/*
 *	Process ISAKMP header.
 *	If this returns zero length left, indicating some sort of problem, then
 *	we report a short or malformed packet and return.
 */
	bytes_left = n; /* Set remaining length to total packet len */
	if (psk_crack_flag)
		add_psk_crack_payload(packet_in, 0, 'X');
	pkt_ptr = process_isakmp_hdr(packet_in, &bytes_left, &next, &type);
	if (!bytes_left) {
		printf(
			"%sShort or malformed ISAKMP packet returned: %d bytes\n",
			msg, n);
		free(msg);
		return;
	}
/*
 *	Determine the overall type of the packet from the first payload type.
 */
	switch (next) {
	case ISAKMP_NEXT_SA:    /* SA */
		if (psk_crack_flag)
			add_psk_crack_payload(pkt_ptr, next, 'R');
		(*sa_responders)++;
		cp = process_sa(pkt_ptr, bytes_left, type, quiet, multiline);
		break;
	case ISAKMP_NEXT_N:     /* Notify */
		(*notify_responders)++;
		cp = process_notify(pkt_ptr, bytes_left);
		break;
	default:
		cp = make_message("Unknown IKE payload returned: %s",
				  STR_OR_ID(next, payload_name));
		break;
	}
	pkt_ptr = skip_payload(pkt_ptr, &bytes_left, &next);
	msg2 = msg;
	msg = make_message("%s%s", msg, cp);
	free(msg2);     /* Free old message (IP address) */
	free(cp);       /* Free 1st payload message */
/*
 *	Process any other interesting payloads if quiet is not in effect.
 */
	if (!quiet) {
		while (bytes_left) {
			if (next == ISAKMP_NEXT_VID) {
				msg2 = msg;
				cp = process_vid(pkt_ptr, bytes_left, vidlist);
				msg = make_message("%s%s%s", msg2,
						   multiline ? "\n\t" : " ",
						   cp);
				free(msg2);     /* Free old message */
				free(cp);       /* Free VID payload message */
			} else if (next == ISAKMP_NEXT_ID ) {
				if (psk_crack_flag)
					add_psk_crack_payload(pkt_ptr, next,
							      'R');
				msg2 = msg;
				cp = process_id(pkt_ptr, bytes_left);
				msg = make_message("%s%s%s", msg2,
						   multiline ? "\n\t" : " ",
						   cp);
				free(msg2);     /* Free old message */
				free(cp);       /* Free ID payload message */
			} else {
				if (psk_crack_flag)
					add_psk_crack_payload(pkt_ptr, next,
							      'R');
				msg2 = msg;
				if (bytes_left >=
				    sizeof(struct isakmp_generic)) {
					struct isakmp_generic *hdr =
						(struct isakmp_generic *)
						pkt_ptr;
					cp = make_message("%s(%u bytes)", STR_OR_ID(
								  next,
								  payload_name),
							  ntohs(hdr->
								isag_length) -
							  sizeof(struct
								 isakmp_generic));
				} else {
					cp =
						make_message("%s)",
							     STR_OR_ID(next,
								       payload_name));
				}
				msg = make_message("%s%s%s", msg2,
						   multiline ? "\n\t" : " ",
						   cp);
				free(msg2);     /* Free old message */
				free(cp);       /* Free generic payload message */
			}
			pkt_ptr = skip_payload(pkt_ptr, &bytes_left, &next);
		}
	}
/*
 *	Print the message.
 */
	printf("%s\n", msg);
	free(msg);
}

/*
 *	send_packet -- Construct and send a packet to the specified host
 *
 *	Inputs:
 *
 *	s               network socket file descriptor
 *	packet_out	IKE packet to send
 *	packet_out_len	Length of IKE packet to send
 *	he              Host entry to send to
 *	dest_port       Destination UDP port
 *	last_packet_time        Time when last packet was sent
 *
 *	Returns:
 *
 *	None.
 *
 *	This must construct an appropriate packet and send it to the host
 *	identified by "he" and UDP port "dest_port" using the socket "s".
 *	It must also update the "last_send_time" field for this host entry.
 */
void send_packet(int s, unsigned char *packet_out, size_t packet_out_len,
		 struct host_entry *he, unsigned dest_port,
		 struct timeval *last_packet_time)
{
	struct sockaddr_in sa_peer;
	NET_SIZE_T sa_peer_len;
	struct isakmp_hdr *hdr = (struct isakmp_hdr *) packet_out;

/*
 *	Set up the sockaddr_in structure for the host.
 */
	memset(&sa_peer, '\0', sizeof(sa_peer));
	sa_peer.sin_family = AF_INET;
	sa_peer.sin_addr.s_addr = he->addr.s_addr;
	sa_peer.sin_port = htons(dest_port);
	sa_peer_len = sizeof(sa_peer);
/*
 *	Copy the initiator cookie from the host entry into the ISAKMP header.
 */
	hdr->isa_icookie[0] = he->icookie[0];
	hdr->isa_icookie[1] = he->icookie[1];
/*
 *	Update the last send times for this host.
 */
	Gettimeofday(last_packet_time);
	he->last_send_time.tv_sec  = last_packet_time->tv_sec;
	he->last_send_time.tv_usec = last_packet_time->tv_usec;
	he->num_sent++;
/*
 *	Experimental Cisco TCP encapsulation.
 */
	if (tcp_flag == TCP_PROTO_ENCAP) {
		unsigned char *orig_packet_out = packet_out;
		unsigned char *udphdr;
		size_t udphdr_len;
		unsigned char *cp;

/* The two bits of extra data below were observed using Cisco VPN Client */
		unsigned char udpextra[16] = { /* extra data covered by UDP */
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		};
		unsigned char tcpextra[16] = { /* extra data covered by TCP */
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x21, 0x45, 0x6c, 0x69, 0x10, 0x11, 0x01, 0x00
		};

		packet_out = Malloc(packet_out_len + 40); /* 8 for udphdr + 32 extra */
		cp = packet_out;

		udphdr = make_udphdr(&udphdr_len, 500, 500,
				     packet_out_len + 8 + 16);
		memcpy(cp, udphdr, udphdr_len);
		cp += udphdr_len;

		memcpy(cp, orig_packet_out, packet_out_len);
		cp += packet_out_len;

		memcpy(cp, udpextra, 16);
		cp += 16;

		memcpy(cp, tcpextra, 16);
		cp += 16;

		packet_out_len += 40;
	}
/*
 *	Send the packet.
 */
	if (verbose > 1) {
		warn_msg(
			"---\tSending packet #%u to host entry %u (%s) tmo %d us",
			he->num_sent, he->n, inet_ntoa(he->addr),
			he->timeout);
	}
	if ((sendto(s, packet_out, packet_out_len, 0,
		    (struct sockaddr *) &sa_peer,
		    sa_peer_len)) < 0)
		err_sys("ERROR: sendto");
/*
 *	Experimental Cisco TCP encapsulation.
 */
	if (tcp_flag == TCP_PROTO_ENCAP)
		free(packet_out);
}

/*
 *	recvfrom_wto -- Receive packet with timeout
 *
 *      Inputs:
 *
 *      s       = Socket file descriptor.
 *      buf     = Buffer to receive data read from socket.
 *      len     = Size of buffer.
 *      saddr   = Socket structure.
 *      tmo     = Select timeout in us.
 *
 *	Returns number of characters received, or -1 for timeout.
 */
int recvfrom_wto(int s, unsigned char *buf, size_t len, struct sockaddr *saddr,
		 int tmo)
{
	fd_set readset;
	struct timeval to;
	int n;
	NET_SIZE_T saddr_len;

	if (tmo < 0)
		tmo = 0; /* Negative timeouts not allowed */
	FD_ZERO(&readset);
	FD_SET(s, &readset);
	to.tv_sec  = tmo / 1000000;
	to.tv_usec = (tmo - 1000000 * to.tv_sec);
	n = select(s + 1, &readset, NULL, NULL, &to);
	if (n < 0)
		err_sys("ERROR: select");
	else if (n == 0)
		return -1; /* Timeout */

	saddr_len = sizeof(struct sockaddr);
	if ((n = recvfrom(s, buf, len, 0, saddr, &saddr_len)) < 0) {
		if (errno == ECONNREFUSED || errno == ECONNRESET) {
/*
 *	Treat connection refused and connection reset as timeout.
 *	It would be nice to remove the associated host, but we can't because
 *	we cannot tell which host the connection refused relates to.
 */
			return -1;
		} else {
			err_sys("ERROR: recvfrom");
		}
	}
/*
 *	Experimental Cisco TCP encapsulation.
 *	Remove encapsulated UDP header from TCP segment.
 */
	if (tcp_flag == TCP_PROTO_ENCAP && n > 8) {
		struct ike_udphdr *udphdr;
		unsigned char *tmpbuf;
		size_t tmpbuf_len;

		udphdr = (struct ike_udphdr*) buf;
		if (ntohs(udphdr->source) == 500 &&
		    ntohs(udphdr->dest) == 500) {
			tmpbuf_len = n - 8;             /* we know that n > 8 at this point */
			tmpbuf = Malloc(tmpbuf_len);    /* could we use memmove() instead ? */
			memcpy(tmpbuf, buf + 8, tmpbuf_len);
			memcpy(buf, tmpbuf, tmpbuf_len);
			free(tmpbuf);
		}
	}

	return n;
}

/*
 *	initialise_ike_packet	-- Initialise IKE packet structures
 *
 *	Inputs:
 *
 *	packet_out_len	Size of output packet.
 *	lifetime	Lifetime in seconds.  Zero for no lifetime.
 *	lifesize	Lifesize in KB.  Zero for no lifesize.
 *	auth_method	Authentication method.
 *	dhgroup		Diffie Hellman Group.
 *	idtype		Identification Type (aggressive only).
 *	id_data		Identification Data (aggressive only).
 *	id_data_len	Identification Data Length (aggressive only).
 *	vendor_id_flag	Vendor ID Present.
 *	trans_flag	Custom Transforms Present.
 *	exchange_type	ISAKMP Exchange Type (Main or Aggressive mode)
 *	gss_id_flag	GSS Identification Present
 *	gss_data	GSS ID Data
 *	gss_data_len	GSS ID Length.
 *
 *	Returns:
 *
 *	Pointer to constructed packet.
 *
 *	We build the IKE packet backwards: from the last payload to the first.
 *	This ensures that we know the "next payload" value for the previous
 *	payload, and also that we know the total length for the ISAKMP header.
 */
unsigned char *initialise_ike_packet(size_t *packet_out_len, unsigned lifetime,
				     unsigned lifesize, unsigned auth_method,
				     unsigned dhgroup,
				     unsigned idtype, unsigned char *id_data,
				     size_t id_data_len,
				     int vendor_id_flag, int trans_flag,
				     unsigned exchange_type,
				     int gss_id_flag, unsigned char *gss_data,
				     size_t gss_data_len)
{
	struct isakmp_hdr *hdr;
	struct isakmp_sa *sa;
	struct isakmp_proposal *prop;
	unsigned char *transforms; /* All transforms */
	unsigned char *vid = NULL;
	unsigned char *id = NULL;
	unsigned char *nonce = NULL;
	unsigned char *ke = NULL;       /* Key Exchange */
	unsigned char *cp;
	unsigned char *packet_out;      /* Constructed IKE packet */
	unsigned char *sa_cp = NULL;    /* For experimental payload printing XXXXX */
	size_t vid_len;
	size_t trans_len;
	size_t id_len;
	size_t nonce_len;
	size_t nonce_data_len = 20;
	size_t ke_len;
	size_t kx_data_len = 0;
	unsigned no_trans = 0; /* Number of transforms */

	*packet_out_len = 0;
/*
 *	Vendor ID Payload (Optional)
 */
	if (vendor_id_flag) {
		vid = add_vid(1, &vid_len, NULL, 0);
		*packet_out_len += vid_len;
	}
/*
 *	Key Exchange, Nonce and ID for aggressive mode only.
 */
	if (exchange_type == ISAKMP_XCHG_AGGR) {
		if (vendor_id_flag)
			id = make_id(&id_len, ISAKMP_NEXT_VID, idtype, id_data,
				     id_data_len);
		else
			id = make_id(&id_len, ISAKMP_NEXT_NONE, idtype,
				     id_data, id_data_len);
		if (id_data)
			free(id_data);
		*packet_out_len += id_len;
		nonce = make_nonce(&nonce_len, ISAKMP_NEXT_ID, nonce_data_len);
		if (psk_crack_flag)
			add_psk_crack_payload(nonce, 10, 'I');
		*packet_out_len += nonce_len;
		switch (dhgroup) {
		case 1:
			kx_data_len = 96; /* Group 1 - 768 bits */
			break;
		case 2:
			kx_data_len = 128; /* Group 2 - 1024 bits */
			break;
		case 5:
			kx_data_len = 192; /* Group 5 - 1536 bits */
			break;
		case 14:
			kx_data_len = 256; /* Group 14 - 2048 bits */
			break;
		case 15:
			kx_data_len = 384; /* Group 15 - 3072 bits */
			break;
		case 16:
			kx_data_len = 512; /* Group 16 - 4096 bits */
			break;
		case 17:
			kx_data_len = 768; /* Group 17 - 6144 bits */
			break;
		case 18:
			kx_data_len = 1024; /* Group 18 - 8192 bits */
			break;
		default:
			err_msg(
				"ERROR: Bad Diffie Hellman group: %u, should be 1,2,5,14,15,16,17 or 18",
				dhgroup);
			break; /* NOTREACHED */
		}
		ke = make_ke(&ke_len, ISAKMP_NEXT_NONCE, kx_data_len);
		if (psk_crack_flag)
			add_psk_crack_payload(ke, 4, 'I');
		*packet_out_len += ke_len;
	}
/*
 *	Transform payloads
 */
	if (!trans_flag) {                                      /* Use standard transform set if none specified */
		if (exchange_type == ISAKMP_XCHG_IDPROT) {      /* Main Mode */
			add_trans(0, NULL, OAKLEY_3DES_CBC, 0, OAKLEY_SHA,
				  auth_method,
				  2, lifetime, lifesize, gss_id_flag, gss_data,
				  gss_data_len);
			add_trans(0, NULL, OAKLEY_3DES_CBC, 0, OAKLEY_MD5,
				  auth_method,
				  2, lifetime, lifesize, gss_id_flag, gss_data,
				  gss_data_len);
			add_trans(0, NULL, OAKLEY_DES_CBC,  0, OAKLEY_SHA,
				  auth_method,
				  2, lifetime, lifesize, gss_id_flag, gss_data,
				  gss_data_len);
			add_trans(0, NULL, OAKLEY_DES_CBC,  0, OAKLEY_MD5,
				  auth_method,
				  2, lifetime, lifesize, gss_id_flag, gss_data,
				  gss_data_len);
			add_trans(0, NULL, OAKLEY_3DES_CBC, 0, OAKLEY_SHA,
				  auth_method,
				  1, lifetime, lifesize, gss_id_flag, gss_data,
				  gss_data_len);
			add_trans(0, NULL, OAKLEY_3DES_CBC, 0, OAKLEY_MD5,
				  auth_method,
				  1, lifetime, lifesize, gss_id_flag, gss_data,
				  gss_data_len);
			add_trans(0, NULL, OAKLEY_DES_CBC,  0, OAKLEY_SHA,
				  auth_method,
				  1, lifetime, lifesize, gss_id_flag, gss_data,
				  gss_data_len);
			add_trans(0, NULL, OAKLEY_DES_CBC,  0, OAKLEY_MD5,
				  auth_method,
				  1, lifetime, lifesize, gss_id_flag, gss_data,
				  gss_data_len);
			no_trans = 8;
		} else { /* presumably aggressive mode */
			add_trans(0, NULL, OAKLEY_3DES_CBC, 0, OAKLEY_SHA,
				  auth_method,
				  dhgroup, lifetime, lifesize, gss_id_flag,
				  gss_data, gss_data_len);
			add_trans(0, NULL, OAKLEY_3DES_CBC, 0, OAKLEY_MD5,
				  auth_method,
				  dhgroup, lifetime, lifesize, gss_id_flag,
				  gss_data, gss_data_len);
			add_trans(0, NULL, OAKLEY_DES_CBC,  0, OAKLEY_SHA,
				  auth_method,
				  dhgroup, lifetime, lifesize, gss_id_flag,
				  gss_data, gss_data_len);
			add_trans(0, NULL, OAKLEY_DES_CBC,  0, OAKLEY_MD5,
				  auth_method,
				  dhgroup, lifetime, lifesize, gss_id_flag,
				  gss_data, gss_data_len);
			no_trans = 4;
		}
		if (gss_data)
			free(gss_data);
	} else { /* Custom transforms */
		no_trans = trans_flag;
	}
	transforms =
		add_trans(1, &trans_len, 0,  0, 0, 0, 0, 0, 0, 0, NULL, 0);
	*packet_out_len += trans_len;
/*
 *	Proposal payload
 */
	prop = make_prop(trans_len + sizeof(struct isakmp_proposal), no_trans);
	*packet_out_len += sizeof(struct isakmp_proposal);
/*
 *	SA Header
 */
	if (exchange_type == ISAKMP_XCHG_IDPROT) { /* Main Mode */
		if (vendor_id_flag) {
			sa = make_sa_hdr(ISAKMP_NEXT_VID, trans_len +
					 sizeof(struct isakmp_proposal) +
					 sizeof(struct isakmp_sa));
		} else {
			sa = make_sa_hdr(ISAKMP_NEXT_NONE, trans_len +
					 sizeof(struct isakmp_proposal) +
					 sizeof(struct isakmp_sa));
		}
	} else { /* Presumably aggressive mode */
		sa = make_sa_hdr(ISAKMP_NEXT_KE, trans_len +
				 sizeof(struct isakmp_proposal) +
				 sizeof(struct isakmp_sa));
	}
	*packet_out_len += sizeof(struct isakmp_sa);
/*
 *	ISAKMP Header
 */
	*packet_out_len += sizeof(struct isakmp_hdr);
	if (experimental_value)
		hdr = make_isakmp_hdr(exchange_type, ISAKMP_NEXT_SA,
				      experimental_value);
	else
		hdr = make_isakmp_hdr(exchange_type, ISAKMP_NEXT_SA,
				      *packet_out_len);
/*
 *	Allocate packet and copy payloads into packet.
 */
	packet_out = Malloc(*packet_out_len);
	cp = packet_out;
	memcpy(cp, hdr, sizeof(struct isakmp_hdr));
	free(hdr);
	cp += sizeof(struct isakmp_hdr);
	if (psk_crack_flag)
		sa_cp = cp; /* Remember position of SA payload */
	memcpy(cp, sa, sizeof(struct isakmp_sa));
	free(sa);
	cp += sizeof(struct isakmp_sa);
	memcpy(cp, prop, sizeof(struct isakmp_proposal));
	free(prop);
	cp += sizeof(struct isakmp_proposal);
	memcpy(cp, transforms, trans_len);
	free(transforms);
	cp += trans_len;
	if (exchange_type == ISAKMP_XCHG_AGGR) {
		memcpy(cp, ke, ke_len);
		free(ke);
		cp += ke_len;
		memcpy(cp, nonce, nonce_len);
		free(nonce);
		cp += nonce_len;
		memcpy(cp, id, id_len);
		free(id);
		cp += id_len;
	}
	if (vendor_id_flag) {
		memcpy(cp, vid, vid_len);
		free(vid);
		cp += vid_len;
	}
	if (psk_crack_flag)
		add_psk_crack_payload(sa_cp, 1, 'I');

	return packet_out;
}

/*
 *	dump_list -- Display contents of host list for debugging
 *
 *      Inputs:
 *
 *      num_hosts	The number of entries in the host list.
 *
 *	Returns:
 *
 *	None.
 */
void dump_list(unsigned num_hosts)
{
	char *cp;
	int i;

	printf("Host List:\n\n");
	printf("Entry\tIP Address\tCookie\n");
	for (i = 0; i < num_hosts; i++) {
		cp = hexstring((unsigned char *)helistptr[i]->icookie,
			       sizeof(helistptr[i]->icookie));
		printf("%u\t%s\t%s\n", helistptr[i]->n,
		       inet_ntoa(helistptr[i]->addr),
		       cp);
		free(cp);
	}
	printf("\nTotal of %u host entries.\n\n", num_hosts);
}

/*
 *	dump_backoff -- Display contents of backoff list for debugging
 *
 *	Inputs:
 *
 *	pattern_fuzz	Default pattern matching fuzz value in ms.
 *
 *	Returns:
 *
 *	None.
 *
 *	This displays the contents of the backoff pattern list.  It is useful
 *	when debugging to check that the patterns have been loaded correctly
 *	from the backoff patterns file.
 */
void dump_backoff(unsigned pattern_fuzz)
{
	struct pattern_list *pl;
	struct pattern_entry_list *pp;
	int i;

	printf("Backoff Pattern List:\n\n");
	printf("Entry\tName\tCount\tBackoff Pattern\n");
	pl = patlist;
	i = 1;
	while (pl != NULL) {
		printf("%d\t%s\t%u\t", i, pl->name, pl->num_times);
		pp = pl->recv_times;
		while (pp != NULL) {
/*
 *  Only print the fractional seconds part if required (generally it's not).
 *  We cast to unsigned long because some OSes define tv_sec/tv_usec as long and
 *  others define them as int.
 */
			if (pp->time.tv_usec) {
				printf("%lu.%.6lu",
				       (unsigned long)pp->time.tv_sec,
				       (unsigned long)pp->time.tv_usec);
			} else {
				printf("%lu", (unsigned long)pp->time.tv_sec);
			}
/*
 * Display the fuzz value for this pattern entry if it is not the default.
 */
			if (pp->fuzz != pattern_fuzz)
				printf("/%d", pp->fuzz);
/*
 * Print a newline if we're at the end of this pattern, otherwise print a
 * comma and space before the next time element.
 */
			pp = pp->next;
			if (pp == NULL)
				printf("\n");
			else
				printf(", ");
		}
		pl = pl->next;
		i++;
	} /* End While */
	printf("\nTotal of %d backoff pattern entries.\n\n", i - 1);
}

/*
 *	dump_vid -- Display contents of Vendor ID pattern list for debugging
 *
 *	Inputs:
 *
 *	None
 *
 *	Returns:
 *
 *	None.
 *
 *	This displays the contents of the Vendor ID pattern list.  It is useful
 *	when debugging to check that the patterns have been loaded correctly
 *	from the Vendor ID patterns file.
 */
#ifdef HAVE_REGEX_H
void dump_vid(void)
{
	struct vid_pattern_list *pl;
	int i;

	printf("Vendor ID Pattern List:\n\n");
	printf("Entry\tName\tVendor ID Pattern\n");
	pl = vidlist;
	i = 1;
	while (pl != NULL) {
		printf("%d\t%s\t%s\n", i++, pl->name, pl->pattern);
		pl = pl->next;
	} /* End While */
	printf("\nTotal of %d Vendor ID pattern entries.\n\n", i - 1);
}
#endif

/*
 *	dump_times -- Display packet times for backoff fingerprinting
 *
 *	Inputs:
 *
 *	num_hosts	The number of hosts in the list.
 *
 *	Returns:
 *
 *	None.
 */
void dump_times(unsigned num_hosts)
{
	struct time_list *te;
	int i;
	int time_no;
	struct timeval prev_time;
	struct timeval diff;
	char *patname;
	int unknown_patterns = 0;

	printf("IKE Backoff Patterns:\n");
	printf("\nIP Address\tNo.\tRecv time\t\tDelta Time\n");
	for (i = 0; i < num_hosts; i++) {
		if (helistptr[i]->recv_times != NULL &&
		    helistptr[i]->num_recv > 1) {
			te = helistptr[i]->recv_times;
			time_no = 1;
			diff.tv_sec = 0;
			diff.tv_usec = 0;
			while (te != NULL) {
				if (time_no > 1)
					timeval_diff(&(te->time), &prev_time,
						     &diff);
				printf("%s\t%d\t%lu.%.6lu\t%lu.%.6lu\n",
				       inet_ntoa(helistptr[i]->addr),
				       time_no, (unsigned long)te->time.tv_sec,
				       (unsigned long)te->time.tv_usec,
				       (unsigned long)diff.tv_sec,
				       (unsigned long)diff.tv_usec);
				prev_time = te->time;
				te = te->next;
				time_no++;
			} /* End While te != NULL */
			if ((patname = match_pattern(helistptr[i])) != NULL) {
				printf("%s\tImplementation guess: %s\n",
				       inet_ntoa(helistptr[i]->addr), patname);
			} else {
				if (patlist) {
					printf(
						"%s\tImplementation guess: %s\n",
						inet_ntoa(
							helistptr[i]->addr),
						"UNKNOWN");
				} else {
					printf(
						"%s\tImplementation guess: %s\n",
						inet_ntoa(
							helistptr[i]->addr),
						"UNKNOWN - No patterns available");
				}
				unknown_patterns++;
			}
			printf("\n");
		}       /* End If */
	}               /* End For */
	if (unknown_patterns && patlist) {
		printf(
			"Some IKE implementations found have unknown backoff fingerprints\n");
		printf(
			"If you know the implementation name, and the pattern is reproducible, you\n");
		printf(
			"are encouraged to submit the pattern and implementation details for\n");
		printf("inclusion in future versions of ike-scan.  See:\n");
		printf("http://www.nta-monitor.com/ike-scan/submit.htm\n");
	}
}

/*
 *	match_pattern -- Find backoff pattern match
 *
 *	Inputs:
 *
 *	he	Pointer to the host entry which we are trying to match.
 *
 *	Returns:
 *
 *	Pointer to the implementation name, or NULL if no match.
 *
 *	Finds the first match for the backoff pattern of the host entry *he.
 */
char *match_pattern(struct host_entry *he)
{
	struct pattern_list *pl;

/*
 *	Return NULL immediately if there is no chance of matching.
 */
	if (he == NULL || patlist == NULL)
		return NULL;

	if (he->recv_times == NULL || he->num_recv < 2)
		return NULL;

/*
 *	Try to find a match in the pattern list.
 */
	pl = patlist;
	while (pl != NULL) {
		if (he->num_recv == pl->num_times && pl->recv_times != NULL) {
			struct time_list *hp;
			struct pattern_entry_list *pp;
			struct timeval diff;
			struct timeval prev_time;
			int match;
			int i;

			hp = he->recv_times;
			pp = pl->recv_times;
			match = 1;
			i = 1;
			diff.tv_sec = 0;
			diff.tv_usec = 0;
			while (pp != NULL && hp != NULL) {
				if (i > 1)
					timeval_diff(&(hp->time), &prev_time,
						     &diff);
				if (!times_close_enough(&(pp->time), &diff,
							pp->fuzz)) {
					match = 0;
					break;
				}
				prev_time = hp->time;
				pp = pp->next;
				hp = hp->next;
				i++;
			} /* End While */
			if (match)
				return pl->name;
		}       /* End If */
		pl = pl->next;
	}               /* End While */
/*
 *	If we reach here, then we haven't matched the pattern so return NULL.
 */
	return NULL;
}

/*
 *	add_recv_time -- Add current time to the recv_times list
 *
 *	Inputs:
 *
 *	he	Pointer to host entry to add time to
 *	last_recv_time	Time packet was received
 *
 *	Returns:
 *
 *	None.
 */
void add_recv_time(struct host_entry *he, struct timeval *last_recv_time)
{
	struct time_list *p;    /* Temp pointer */
	struct time_list *te;   /* New timeentry pointer */

/*
 *	Allocate and initialise new time structure
 */
	te = Malloc(sizeof(struct time_list));
	Gettimeofday(&(te->time));
	last_recv_time->tv_sec = te->time.tv_sec;
	last_recv_time->tv_usec = te->time.tv_usec;
	te->next = NULL;
/*
 *	Insert new time structure on the tail of the recv_times list.
 */
	p = he->recv_times;
	if (p == NULL) {
		he->recv_times = te;
	} else {
		while (p->next != NULL)
			p = p->next;
		p->next = te;
	}
/*
 *	Increment num_received for this host
 */
	he->num_recv++;
}

/*
 *	load_backoff_patterns -- Load UDP backoff patterns from specified file
 *
 *	Inputs:
 *
 *	patfile		Name of the file to load the patterns from
 *	pattern_fuzz	Default fuzz value in ms
 *
 *	Returns:
 *
 *	None.
 */
void load_backoff_patterns(const char *patfile, unsigned pattern_fuzz)
{
	FILE *fp;
	char line[MAXLINE];
	int line_no;
	char *fn;

#ifdef __CYGWIN__
	char fnbuf[MAXLINE];
	int fnbuf_siz;
	int i;
#endif

	if (*patfile == '\0') { /* If patterns file not specified */
#ifdef __CYGWIN__
		if ((fnbuf_siz =
			     GetModuleFileName(GetModuleHandle(0), fnbuf,
					       MAXLINE)) == 0)
			err_msg("ERROR: Call to GetModuleFileName failed");
		for (i = fnbuf_siz - 1;
		     i >= 0 && fnbuf[i] != '/' && fnbuf[i] != '\\'; i--)
			;
		if (i >= 0)
			fnbuf[i] = '\0';
		fn = make_message("%s\\%s", fnbuf, PATTERNS_FILE);
#else
		fn = make_message("%s/%s", IKEDATADIR, PATTERNS_FILE);
#endif
	} else {
		fn = make_message("%s", patfile);
	}

	if ((fp = fopen(fn, "r")) == NULL) {
		warn_msg(
			"WARNING: Cannot open IKE backoff patterns file.  ike-scan will still display");
		warn_msg(
			"the backoff patterns, but it will not be able to identify the fingerprints.");
		warn_sys("fopen: %s", fn);
	} else {
		line_no = 0;
		while (fgets(line, MAXLINE, fp)) {
			line_no++;
			if (line[0] != '#' && line[0] != '\n') /* Not comment or empty */
				add_pattern(line, pattern_fuzz);
		}
		fclose(fp);
	}
	free(fn);
}

/*
 *	add_pattern -- add a backoff pattern to the list.
 *
 *	Inputs:
 *
 *	line		Backoff pattern entry from the patterns file
 *	pattern_fuzz	Default fuzz value in ms
 *
 *	Returns:
 *
 *	None.
 */
void add_pattern(char *line, unsigned pattern_fuzz)
{
	char *cp;
	char *np;
	char *pp;
	char name[MAXLINE];
	char pat[MAXLINE];
	int tabseen;
	struct pattern_list *pe;        /* Pattern entry */
	struct pattern_list *p;         /* Temp pointer */
	struct pattern_entry_list *te;
	struct pattern_entry_list *tp;
	char *endp;
	unsigned i;
	long back_sec;
	long back_usec;
	char back_usec_str[7];  /* Backoff microseconds as string */
	int len;
	unsigned fuzz;          /* Pattern matching fuzz in ms */

/*
 *	Allocate new pattern list entry and add to tail of patlist.
 */
	pe = Malloc(sizeof(struct pattern_list));
	pe->next = NULL;
	pe->recv_times = NULL;
	p = patlist;
	if (p == NULL) {
		patlist = pe;
	} else {
		while (p->next != NULL)
			p = p->next;
		p->next = pe;
	}
/*
 *	Separate line from patterns file into name and pattern.
 */
	tabseen = 0;
	cp = line;
	np = name;
	pp = pat;
	while (*cp != '\0' && *cp != '\n') {
		if (*cp == '\t') {
			tabseen++;
			cp++;
		}
		if (tabseen)
			*pp++ = *cp++;
		else
			*np++ = *cp++;
	}
	*np = '\0';
	*pp = '\0';
/*
 *	Copy name into malloc'ed storage and set pl->name to point to this.
 */
	cp = Malloc(strlen(name) + 1);
	strcpy(cp, name);
	pe->name = cp;
/*
 *	Process and store the backoff pattern.
 */
	i = 0;
	endp = pat;
	while (*endp != '\0') {
/*
 *      Convert the integer seconds part of the backoff pattern entry.
 */
		back_sec = strtol(endp, &endp, 10);
/*
 *      If there is a "." after the integer part, then there are fractional
 *      seconds to convert.  Convert the fractional seconds into a string
 *      representation of microseconds by zero-extending to 6 digits and
 *      then convert to long.
 */
		if (*endp == '.') {
			endp++;
			len = 0;
			for (len = 0; len < 6; len++) {
				if (isdigit((unsigned char) *endp)) {
					back_usec_str[len] = *endp;
					endp++;
				} else {
					back_usec_str[len] = '0';
				}
			}
			while (isdigit((unsigned char) *endp))
				endp++; /* Skip any fractional digits past 6th */
			back_usec_str[len] = '\0';
			back_usec = strtol(back_usec_str, NULL, 10);
		} else { /* No fractional seconds part */
			back_usec = 0;
		}
/*
 *      If there is a "/" after the number, this represents a fuzz value
 *      in milliseconds.
 */
		if (*endp == '/') {
			endp++;
			fuzz = strtol(endp, &endp, 10);
		} else {
			fuzz = pattern_fuzz;
		}
/*
 *      Allocate and fill in new pattern_entry_list structure for this backoff
 *      pattern entry and add it onto the tail of this pattern entry.
 */
		te = Malloc(sizeof(struct pattern_entry_list));
		te->next = NULL;
		te->time.tv_sec = back_sec;
		te->time.tv_usec = back_usec;
		te->fuzz = fuzz;
		tp = pe->recv_times;
		if (tp == NULL) {
			pe->recv_times = te;
		} else {
			while (tp->next != NULL)
				tp = tp->next;
			tp->next = te;
		}
/*
 *	Move on to next pattern entry.
 */
		if (*endp == ',')
			endp++;
		i++;
	} /* End While */
	pe->num_times = i;
}

/*
 *	load_vid_patterns -- Load Vendor ID Patterns from specified file
 *
 *	Inputs:
 *
 *	vidfile		The name of the file to load the patterns from
 *
 *	Returns:
 *
 *	None
 */
#ifdef HAVE_REGEX_H
void load_vid_patterns(const char *vidfile)
{
	FILE *fp;
	char line[MAXLINE];
	int line_no;
	char *fn;

#ifdef __CYGWIN__
	char fnbuf[MAXLINE];
	int fnbuf_siz;
	int i;
#endif

	if (*vidfile == '\0') { /* If patterns file not specified */
#ifdef __CYGWIN__
		if ((fnbuf_siz =
			     GetModuleFileName(GetModuleHandle(0), fnbuf,
					       MAXLINE)) == 0)
			err_msg("ERROR: Call to GetModuleFileName failed");
		for (i = fnbuf_siz - 1;
		     i >= 0 && fnbuf[i] != '/' && fnbuf[i] != '\\'; i--)
			;
		if (i >= 0)
			fnbuf[i] = '\0';
		fn = make_message("%s\\%s", fnbuf, VID_FILE);
#else
		fn = make_message("%s/%s", IKEDATADIR, VID_FILE);
#endif
	} else {
		fn = make_message("%s", vidfile);
	}

	if ((fp = fopen(fn, "r")) == NULL) {
		warn_msg(
			"WARNING: Cannot open Vendor ID patterns file.  ike-scan will still display");
		warn_msg(
			"the raw Vendor ID data in hex, but it will not be able to display the");
		warn_msg("associated Vendor ID names.");
		warn_sys("fopen: %s", fn);
	} else {
		line_no = 0;
		while (fgets(line, MAXLINE, fp)) {
			line_no++;
			if (line[0] != '#' && line[0] != '\n') /* Not comment or empty */
				add_vid_pattern(line);
		}
		fclose(fp);
	}
	free(fn);
}
#endif

/*
 *	add_vid_pattern -- add a Vendor ID pattern to the list.
 *
 *	Inputs:
 *
 *	line		Vendor ID pattern entry from the patterns file
 *
 *	Returns:
 *
 *	None.
 */
#ifdef HAVE_REGEX_H
void add_vid_pattern(char *line)
{
	char *cp;
	char *np;
	char *pp;
	regex_t *rep;   /* Compiled regex */
	char name[MAXLINE];
	char pat[MAXLINE];
	int tabseen;
	struct vid_pattern_list *pe;    /* Pattern entry */
	struct vid_pattern_list *p;     /* Temp pointer */
	int result;

/*
 *	Separate line from VID patterns file into name and pattern.
 */
	tabseen = 0;
	cp = line;
	np = name;
	pp = pat;
	while (*cp != '\0' && *cp != '\n') {
		if (*cp == '\t') {
			tabseen++;
			cp++;
		}
		if (tabseen)
			*pp++ = *cp++;
		else
			*np++ = *cp++;
	}
	*np = '\0';
	*pp = '\0';
/*
 *      Process and store the Vendor ID pattern.
 *	The pattern in the file is a Posix extended regular expression which is
 *	compiled with "regcomp".  A pointer to this compiled pattern is
 *	stored in pe->regex.  We also store the text pattern in pe->pattern
 *	for dump_vid().
 */
	rep = Malloc(sizeof(regex_t));
	if ((result =
		     regcomp(rep, pat, REG_EXTENDED | REG_ICASE |
			     REG_NOSUB))) {
		char errbuf[MAXLINE];
		size_t errlen;
		errlen = regerror(result, rep, errbuf, MAXLINE);
		warn_msg(
			"WARNING: Ignoring invalid Vendor ID pattern \"%s\": %s",
			pat, errbuf);
		free(rep);
		/* Should we call regfree(rep) here? */
	} else {
/*
 *      Allocate new pattern list entry and add to tail of vidlist.
 */
		pe = Malloc(sizeof(struct vid_pattern_list));
		pe->next = NULL;
		p = vidlist;
		if (p == NULL) {
			vidlist = pe;
		} else {
			while (p->next != NULL)
				p = p->next;
			p->next = pe;
		}
/*
 *	Store compiled regex.
 */
		pe->regex = rep;
/*
 *	Store text regex.
 */
		cp = Malloc(strlen(pat) + 1);
		strcpy(cp, pat);
		pe->pattern = cp;
/*
 *	Store pattern name.
 */
		cp = Malloc(strlen(name) + 1);
		strcpy(cp, name);
		pe->name = cp;
	}
}
#endif

/*
 *	decode_trans -- Decode a custom transform specification
 *
 *	Inputs:
 *
 *	str	Input transform specification
 *	enc	Output cipher algorithm
 *	keylen	Output cipher key length
 *	hash	Output hash algorithm
 *	auth	Output authentication method
 *	group	Output DG Group
 *
 *	Returns: None
 *
 */
void decode_trans(char *str, unsigned *enc, unsigned *keylen, unsigned *hash,
		  unsigned *auth, unsigned *group)
{
	char *cp;
	int pos; /* 1=enc, 2=hash, 3=auth, 4=group */
	unsigned val;
	unsigned len;

	cp = str;
	pos = 1;
	len = 0;
	while (*cp != '\0') {
		val = strtoul(cp, &cp, 10);
		if (*cp == '/' && pos == 1) { /* Keylength */
			cp++;
			len = strtoul(cp, &cp, 10);
		}
		switch (pos) {
		case 1:
			*enc = val;
			*keylen = len;
			break;
		case 2:
			*hash = val;
			break;
		case 3:
			*auth = val;
			break;
		case 4:
			*group = val;
			break;
		default:
			warn_msg(
				"WARNING: Ignoring extra transform specifications past 4th");
			break;
		}
		if (*cp == ',')
			cp++; /* Move on to next entry */
		pos++;
	}
}

/*
 *	usage -- display usage message and exit
 *
 *      Inputs:
 *
 *      status	Status value to pass to exit()
 *
 *	Returns:
 *
 *	None (this function never returns).
 */
void usage(int status)
{

	static const char *auth_methods[] = {   /* Auth methods from RFC 2409 App. A */
		NULL,                           /* 0 */
		"pre-shared key",               /* 1 */
		"DSS signatures",               /* 2 */
		"RSA signatures",               /* 3 */
		"Encryption with RSA",          /* 4 */
		"Revised encryption with RSA"   /* 5 */
	};
	static const char *id_type_name[] = {   /* ID Type names from RFC 2407 4.6.2.1 */
		NULL,                           /* 0 */
		"ID_IPV4_ADDR",                 /* 1 */
		"ID_FQDN",                      /* 2 */
		"ID_USER_FQDN",                 /* 3 */
		"ID_IPV4_ADDR_SUBNET",          /* 4 */
		"ID_IPV6_ADDR",                 /* 5 */
		"ID_IPV6_ADDR_SUBNET",          /* 6 */
		"ID_IPV4_ADDR_RANGE",           /* 7 */
		"ID_IPV6_ADDR_RANGE",           /* 8 */
		"ID_DER_ASN1_DN",               /* 9 */
		"ID_DER_ASN1_GN",               /* 10 */
		"ID_KEY_ID"                     /* 11 */
	};

	fprintf(stderr, "Usage: ike-scan [options] [hosts...]\n");
	fprintf(stderr, "\n");
	fprintf(stderr,
		"Target hosts must be specified on the command line unless the --file option is\n");
	fprintf(stderr,
		"given, in which case the targets are read from the specified file instead.\n");
	fprintf(stderr, "\n");
	fprintf(stderr,
		"The target hosts can be specified as IP addresses or hostnames.  You can also\n");
	fprintf(stderr,
		"specify IPnetwork/bits (e.g. 192.168.1.0/24) to specify all hosts in the given\n");
	fprintf(stderr,
		"network (network and broadcast addresses included), and IPstart-IPend\n");
	fprintf(stderr,
		"(e.g. 192.168.1.3-192.168.1.27) to specify all hosts in the inclusive range.\n");
	fprintf(stderr, "\n");
	fprintf(stderr,
		"These different options for specifying target hosts may be used both on the\n");
	fprintf(stderr,
		"command line, and also in the file specified with the --file option.\n");
	fprintf(stderr, "\n");
	fprintf(stderr,
		"In the options below a letter or word in angle brackets like <f> denotes a\n");
	fprintf(stderr,
		"value or string that should be supplied. The corresponding text should\n");
	fprintf(stderr,
		"indicate the meaning of this value or string. When supplying the value or\n");
	fprintf(stderr,
		"string, do not include the angle brackets. Text in square brackets like [<f>]\n");
	fprintf(stderr,
		"mean that the enclosed text is optional. This is used for options which take\n");
	fprintf(stderr, "an optional argument.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "\n");
	fprintf(stderr,
		"--help or -h\t\tDisplay this usage message and exit.\n");
	fprintf(stderr,
		"\n--file=<fn> or -f <fn>\tRead hostnames or addresses from the specified file\n");
	fprintf(stderr,
		"\t\t\tinstead of from the command line. One name or IP\n");
	fprintf(stderr,
		"\t\t\taddress per line.  Use \"-\" for standard input.\n");
	fprintf(stderr,
		"\n--sport=<p> or -s <p>\tSet UDP source port to <p>, default=%u, 0=random.\n",
		DEFAULT_SOURCE_PORT);
	fprintf(stderr,
		"\t\t\tSome IKE implementations require the client to use\n");
	fprintf(stderr,
		"\t\t\tUDP source port 500 and will not talk to other ports.\n");
	fprintf(stderr,
		"\t\t\tNote that superuser privileges are normally required\n");
	fprintf(stderr,
		"\t\t\tto use non-zero source ports below 1024.  Also only\n");
	fprintf(stderr,
		"\t\t\tone process on a system may bind to a given source port\n");
	fprintf(stderr, "\t\t\tat any one time.\n");
	fprintf(stderr,
		"\n--dport=<p> or -d <p>\tSet UDP destination port to <p>, default=%u.\n",
		DEFAULT_DEST_PORT);
	fprintf(stderr,
		"\t\t\tUDP port 500 is the assigned port number for ISAKMP\n");
	fprintf(stderr,
		"\t\t\tand this is the port used by most if not all IKE\n");
	fprintf(stderr, "\t\t\timplementations.\n");
	fprintf(stderr,
		"\n--retry=<n> or -r <n>\tSet total number of attempts per host to <n>,\n");
	fprintf(stderr, "\t\t\tdefault=%d.\n", DEFAULT_RETRY);
	fprintf(stderr,
		"\n--timeout=<n> or -t <n>\tSet initial per host timeout to <n> ms, default=%d.\n",
		DEFAULT_TIMEOUT);
	fprintf(stderr,
		"\t\t\tThis timeout is for the first packet sent to each host.\n");
	fprintf(stderr,
		"\t\t\tsubsequent timeouts are multiplied by the backoff\n");
	fprintf(stderr, "\t\t\tfactor which is set with --backoff.\n");
	fprintf(stderr,
		"\n--interval=<n> or -i <n> Set minimum packet interval to <n> ms, default=%d.\n",
		DEFAULT_INTERVAL);
	fprintf(stderr,
		"\t\t\tThis controls the outgoing bandwidth usage by limiting\n");
	fprintf(stderr,
		"\t\t\tthe rate at which packets can be sent.  The packet\n");
	fprintf(stderr,
		"\t\t\tinterval will be no smaller than this number.\n");
	fprintf(stderr,
		"\t\t\tThe outgoing packets have a total size of 364 bytes\n");
	fprintf(stderr,
		"\t\t\t(20 bytes IP hdr + 8 bytes UDP hdr + 336 bytes data)\n");
	fprintf(stderr,
		"\t\t\twhen the default transform set is used, or 112 bytes\n");
	fprintf(stderr,
		"\t\t\tif a single custom transform is specified.  Therefore\n");
	fprintf(stderr,
		"\t\t\tfor default transform set: 50=58240bps, 80=36400bps and\n");
	fprintf(stderr,
		"\t\t\tfor custom transform: 15=59733bps, 30=35840bps.\n");
	fprintf(stderr,
		"\t\t\tThe interval specified is in milliseconds by default,\n");
	fprintf(stderr,
		"\t\t\tor in microseconds if \"u\" is appended to the value.\n");
	fprintf(stderr,
		"\n--backoff=<b> or -b <b>\tSet timeout backoff factor to <b>, default=%.2f.\n",
		DEFAULT_BACKOFF_FACTOR);
	fprintf(stderr,
		"\t\t\tThe per-host timeout is multiplied by this factor\n");
	fprintf(stderr,
		"\t\t\tafter each timeout.  So, if the number of retrys\n");
	fprintf(stderr,
		"\t\t\tis 3, the initial per-host timeout is 500ms and the\n");
	fprintf(stderr,
		"\t\t\tbackoff factor is 1.5, then the first timeout will be\n");
	fprintf(stderr,
		"\t\t\t500ms, the second 750ms and the third 1125ms.\n");
	fprintf(stderr,
		"\n--verbose or -v\t\tDisplay verbose progress messages.\n");
	fprintf(stderr, "\t\t\tUse more than once for greater effect:\n");
	fprintf(stderr,
		"\t\t\t1 - Show when each pass is completed and when\n");
	fprintf(stderr,
		"\t\t\t    packets with invalid cookies are received.\n");
	fprintf(stderr,
		"\t\t\t2 - Show each packet sent and received and when\n");
	fprintf(stderr, "\t\t\t    hosts are removed from the list.\n");
	fprintf(stderr,
		"\t\t\t3 - Display the host, Vendor ID and backoff lists\n");
	fprintf(stderr, "\t\t\t    before scanning starts.\n");
	fprintf(stderr,
		"\n--quiet or -q\t\tDon't decode the returned packet.\n");
	fprintf(stderr,
		"\t\t\tThis prints less protocol information so the\n");
	fprintf(stderr, "\t\t\toutput lines are shorter.\n");
	fprintf(stderr,
		"\n--multiline or -M\tSplit the payload decode across multiple lines.\n");
	fprintf(stderr,
		"\t\t\tWith this option, the decode for each payload is\n");
	fprintf(stderr,
		"\t\t\tprinted on a seperate line starting with a TAB.\n");
	fprintf(stderr,
		"\t\t\tThis option makes the output easier to read, especially\n");
	fprintf(stderr, "\t\t\twhen there are many payloads.\n");
	fprintf(stderr,
		"\n--lifetime=<s> or -l <s> Set IKE lifetime to <s> seconds, default=%d.\n",
		DEFAULT_LIFETIME);
	fprintf(stderr,
		"\t\t\tRFC 2407 specifies 28800 as the default, but some\n");
	fprintf(stderr,
		"\t\t\timplementations may require different values.\n");
	fprintf(stderr,
		"\t\t\tIf you specify 0, then no lifetime will be specified.\n");
	fprintf(stderr,
		"\t\t\tYou can use this option more than once in conjunction\n");
	fprintf(stderr,
		"\t\t\twith the --trans options to produce multiple transform\n");
	fprintf(stderr,
		"\t\t\tpayloads with different lifetimes.  Each --trans option\n");
	fprintf(stderr,
		"\t\t\twill use the previously specified lifetime value.\n");
	fprintf(stderr,
		"\n--lifesize=<s> or -z <s> Set IKE lifesize to <s> Kilobytes, default=%d.\n",
		DEFAULT_LIFESIZE);
	fprintf(stderr,
		"\t\t\tIf you specify 0, then no lifesize will be specified.\n");
	fprintf(stderr,
		"\t\t\tYou can use this option more than once in conjunction\n");
	fprintf(stderr,
		"\t\t\twith the --trans options to produce multiple transform\n");
	fprintf(stderr,
		"\t\t\tpayloads with different lifesizes.  Each --trans option\n");
	fprintf(stderr,
		"\t\t\twill use the previously specified lifesize value.\n");
	fprintf(stderr,
		"\n--auth=<n> or -m <n>\tSet auth. method to <n>, default=%u (%s).\n", DEFAULT_AUTH_METHOD,
		STR_OR_ID(DEFAULT_AUTH_METHOD, auth_methods));
	fprintf(stderr,
		"\t\t\tRFC defined values are 1 to 5.  See RFC 2409 Appendix A.\n");
	fprintf(stderr, "\t\t\tCheckpoint hybrid mode is 64221.\n");
	fprintf(stderr, "\t\t\tGSS (Windows \"Kerberos\") is 65001.\n");
	fprintf(stderr, "\t\t\tXAUTH uses 65001 to 65010.\n");
	fprintf(stderr,
		"\n--version or -V\t\tDisplay program version and exit.\n");
	fprintf(stderr,
		"\n--vendor=<v> or -e <v>\tSet vendor id string to hex value <v>.\n");
	fprintf(stderr,
		"\t\t\tYou can use this option more than once to send\n");
	fprintf(stderr, "\t\t\tmultiple vendor ID payloads.\n");
	fprintf(stderr,
		"\n--trans=<t> or -a <t>\tUse custom transform <t> instead of default set.\n");
	fprintf(stderr,
		"\t\t\t<t> is specified as enc[/len],hash,auth,group.\n");
	fprintf(stderr, "\t\t\tWhere enc is the encryption algorithm,\n");
	fprintf(stderr,
		"\t\t\tlen is the key length for variable length ciphers,\n");
	fprintf(stderr,
		"\t\t\thash is the hash algorithm, and group is the DH Group.\n");
	fprintf(stderr,
		"\t\t\tSee RFC 2409 Appendix A for details of which values\n");
	fprintf(stderr,
		"\t\t\tto use.  For example, --trans=5,2,1,2 specifies\n");
	fprintf(stderr,
		"\t\t\tEnc=3DES-CBC, Hash=SHA1, Auth=shared key, DH Group=2\n");
	fprintf(stderr, "\t\t\tand --trans=7/256,1,1,5 specifies\n");
	fprintf(stderr,
		"\t\t\tEnc=AES-256, Hash=MD5, Auth=shared key, DH Group=5\n");
	fprintf(stderr,
		"\t\t\tYou can use this option more than once to send\n");
	fprintf(stderr, "\t\t\tan arbitary number of custom transforms.\n");
	fprintf(stderr,
		"\n--showbackoff[=<n>] or -o[<n>]\tDisplay the backoff fingerprint table.\n");
	fprintf(stderr,
		"\t\t\tDisplay the backoff table to fingerprint the IKE\n");
	fprintf(stderr, "\t\t\timplementation on the remote hosts.\n");
	fprintf(stderr,
		"\t\t\tThe optional argument specifies time to wait in seconds\n");
	fprintf(stderr, "\t\t\tafter receiving the last packet, default=%d.\n",
		DEFAULT_END_WAIT);
	fprintf(stderr,
		"\t\t\tIf you are using the short form of the option (-o)\n");
	fprintf(stderr,
		"\t\t\tthen the value must immediately follow the option\n");
	fprintf(stderr, "\t\t\tletter with no spaces, e.g. -o25 not -o 25.\n");
	fprintf(stderr,
		"\n--fuzz=<n> or -u <n>\tSet pattern matching fuzz to <n> ms, default=%d.\n",
		DEFAULT_PATTERN_FUZZ);
	fprintf(stderr,
		"\t\t\tThis sets the maximum acceptable difference between\n");
	fprintf(stderr,
		"\t\t\tthe observed backoff times and the reference times in\n");
	fprintf(stderr,
		"\t\t\tthe backoff patterns file.  Larger values allow for\n");
	fprintf(stderr,
		"\t\t\thigher variance but also increase the risk of\n");
	fprintf(stderr, "\t\t\tfalse positive identifications.\n");
	fprintf(stderr,
		"\t\t\tAny per-pattern-entry fuzz specifications in the\n");
	fprintf(stderr,
		"\t\t\tpatterns file will override the value set here.\n");
#ifdef __CYGWIN__
	fprintf(stderr,
		"\n--patterns=<f> or -p <f> Use IKE patterns file <f>,\n");
	fprintf(stderr, "\t\t\tdefault=%s in ike-scan.exe dir.\n",
		PATTERNS_FILE);
#else
	fprintf(stderr,
		"\n--patterns=<f> or -p <f> Use IKE patterns file <f>,\n");
	fprintf(stderr, "\t\t\tdefault=%s/%s.\n", IKEDATADIR, PATTERNS_FILE);
#endif
	fprintf(stderr,
		"\t\t\tThis specifies the name of the file containing\n");
	fprintf(stderr,
		"\t\t\tIKE backoff patterns.  This file is only used when\n");
	fprintf(stderr, "\t\t\t--showbackoff is specified.\n");
#ifdef __CYGWIN__
	fprintf(stderr,
		"\n--vidpatterns=<f> or -I <f> Use Vendor ID patterns file <f>,\n");
	fprintf(stderr, "\t\t\tdefault=%s in ike-scan.exe dir.\n", VID_FILE);
#else
	fprintf(stderr,
		"\n--vidpatterns=<f> or -I <f> Use Vendor ID patterns file <f>,\n");
	fprintf(stderr, "\t\t\tdefault=%s/%s.\n", IKEDATADIR, VID_FILE);
#endif
	fprintf(stderr,
		"\t\t\tThis specifies the name of the file containing\n");
	fprintf(stderr,
		"\t\t\tVendor ID patterns.  These patterns are used for\n");
	fprintf(stderr, "\t\t\tVendor ID fingerprinting.\n");
	fprintf(stderr,
		"\n--aggressive or -A\tUse IKE Aggressive Mode (The default is Main Mode)\n");
	fprintf(stderr,
		"\t\t\tIf you specify --aggressive, then you may also\n");
	fprintf(stderr,
		"\t\t\tspecify --dhgroup, --id and --idtype.  If you use\n");
	fprintf(stderr,
		"\t\t\tcustom transforms with aggressive mode with the --trans\n");
	fprintf(stderr,
		"\t\t\toption, note that all transforms should have the same\n");
	fprintf(stderr,
		"\t\t\tDH Group and this should match the group specified\n");
	fprintf(stderr,
		"\t\t\twith --dhgroup or the default if --dhgroup is not used.\n");
	fprintf(stderr,
		"\n--id=<id> or -n <id>\tUse <id> as the identification value.\n");
	fprintf(stderr,
		"\t\t\tThis option is only applicable to Aggressive Mode.\n");
	fprintf(stderr,
		"\t\t\t<id> can be specified as a string, e.g. --id=test or as\n");
	fprintf(stderr,
		"\t\t\ta hex value with a leading \"0x\", e.g. --id=0xdeadbeef.\n");
	fprintf(stderr,
		"\n--idtype=<n> or -y <n>\tUse identification type <n>.  Default %u (%s).\n", DEFAULT_IDTYPE,
		STR_OR_ID(DEFAULT_IDTYPE, id_type_name));
	fprintf(stderr,
		"\t\t\tThis option is only applicable to Aggressive Mode.\n");
	fprintf(stderr,
		"\t\t\tSee RFC 2407 4.6.2 for details of Identification types.\n");
	fprintf(stderr,
		"\n--dhgroup=<n> or -g <n>\tUse Diffie Hellman Group <n>.  Default %u.\n",
		DEFAULT_DH_GROUP);
	fprintf(stderr,
		"\t\t\tThis option is only applicable to Aggressive Mode where\n");
	fprintf(stderr,
		"\t\t\tit is used to determine the size of the key exchange\n");
	fprintf(stderr, "\t\t\tpayload.\n");
	fprintf(stderr,
		"\t\t\tAcceptable values are 1,2,5,14,15,16,17,18 (MODP only).\n");
	fprintf(stderr,
		"\n--gssid=<n> or -G <n>\tUse GSS ID <n> where <n> is a hex string.\n");
	fprintf(stderr,
		"\t\t\tThis uses transform attribute type 16384 as specified\n");
	fprintf(stderr,
		"\t\t\tin draft-ietf-ipsec-isakmp-gss-auth-07.txt, although\n");
	fprintf(stderr,
		"\t\t\tWindows-2000 has been observed to use 32001 as well.\n");
	fprintf(stderr,
		"\t\t\tFor Windows 2000, you'll need to use --auth=65001 to\n");
	fprintf(stderr, "\t\t\tspecify Kerberos (GSS) authentication.\n");
	fprintf(stderr, "\n--random or -R\t\tRandomise the host list.\n");
	fprintf(stderr,
		"\t\t\tThis option randomises the order of the hosts in the\n");
	fprintf(stderr,
		"\t\t\thost list, so the IKE probes are sent to the hosts in\n");
	fprintf(stderr,
		"\t\t\ta random order.  It uses the Knuth shuffle algorithm.\n");
	fprintf(stderr,
		"\n--tcp[=<n>] or -T[<n>]\tUse TCP transport instead of UDP.\n");
	fprintf(stderr,
		"\t\t\tThis allows you to test a host running IKE over TCP.\n");
	fprintf(stderr,
		"\t\t\tYou won't normally need this option because the vast\n");
	fprintf(stderr,
		"\t\t\tmajority of IPsec systems only support IKE over UDP.\n");
	fprintf(stderr,
		"\t\t\tThe optional value <n> specifies the type of IKE over\n");
	fprintf(stderr,
		"\t\t\tTCP.  There are currently two possible values:\n");
	fprintf(stderr,
		"\t\t\t1 = RAW IKE over TCP as used by Checkpoint (default);\n");
	fprintf(stderr,
		"\t\t\t2 = Encapsulated IKE over TCP as used by Cisco.\n");
	fprintf(stderr,
		"\t\t\tIf you are using the short form of the option (-T)\n");
	fprintf(stderr,
		"\t\t\tthen the value must immediately follow the option\n");
	fprintf(stderr, "\t\t\tletter with no spaces, e.g. -T2 not -T 2.\n");
	fprintf(stderr,
		"\t\t\tYou can only specify a single target host if you use\n");
	fprintf(stderr, "\t\t\tthis option.\n");
	fprintf(stderr,
		"\n--tcptimeout=<n> or -O <n> Set TCP connect timeout to <n> seconds (default=%u).\n",
		DEFAULT_TCP_CONNECT_TIMEOUT);
	fprintf(stderr,
		"\t\t\tThis is only applicable to TCP transport mode.\n");
	fprintf(stderr,
		"\n--pskcrack[=<f>] or -P[<f>] Crack aggressive mode pre-shared keys.\n");
	fprintf(stderr,
		"\t\t\tThis option outputs the aggressive mode pre-shared key\n");
	fprintf(stderr,
		"\t\t\t(PSK) parameters for offline cracking using the\n");
	fprintf(stderr,
		"\t\t\t\"psk-crack\" program that is supplied with ike-scan.\n");
	fprintf(stderr,
		"\t\t\tYou can optionally specify a filename, <f>, to write\n");
	fprintf(stderr,
		"\t\t\tthe PSK parameters to.  If you do not specify a filename\n");
	fprintf(stderr,
		"\t\t\tthen the PSK parameters are written to standard output.\n");
	fprintf(stderr,
		"\t\t\tIf you are using the short form of the option (-P)\n");
	fprintf(stderr,
		"\t\t\tthen the value must immediately follow the option\n");
	fprintf(stderr,
		"\t\t\tletter with no spaces, e.g. -Pfile not -P file.\n");
	fprintf(stderr,
		"\t\t\tYou can only specify a single target host if you use\n");
	fprintf(stderr, "\t\t\tthis option.\n");
	fprintf(stderr,
		"\t\t\tThis option is only applicable to IKE aggressive mode.\n");
	fprintf(stderr,
		"\n--nodns or -N\t\tDo not use DNS to resolve names.\n");
	fprintf(stderr,
		"\t\t\tIf you use this option, then all hosts must be\n");
	fprintf(stderr, "\t\t\tspecified as IP addresses.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Report bugs or send suggestions to %s\n",
		PACKAGE_BUGREPORT);
	fprintf(stderr,
		"See the ike-scan homepage at http://www.nta-monitor.com/ike-scan/\n");
	exit(status);
}
