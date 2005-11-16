/*
 * @(#) jig to exercise a UML/FreeSWAN kernel with two interfaces
 *
 * Copyright (C) 2001 Michael Richardson  <mcr@freeswan.org>
 * 
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * RCSID $Id: uml_netjig.c,v 1.27.26.1 2005/08/12 16:32:01 ken Exp $
 *
 * @(#) based upon uml_router from User-Mode-Linux tools package
 *
 */

/* 
 * This program has been seriously hacked since.
 * 
 *
 * This file contains a program to exercise a FreeSWAN kernel that is
 * built in a User-Mode-Linux form. It creates four sets of Unix
 * domain sockets: two control sockets and two data sockets. 
 *
 * These sockets make up the connection points for the "daemon" method
 * of networking provided by UML.
 *
 * The first connection is intended to connect to "eth0" (the inside
 * or "private" network) and the second one to "eth1" (the outside or
 * "public" network).
 *
 * Packets are fed into one network interface from a (pcap) capture file and
 * are captured from the other interface into a pcap capture file.
 *
 * The program can take an argument which is a script/program to run
 * with the appropriate UML arguments. This can be the UML kernel
 * itself, a script that invokes it or something that just records
 * things.
 *
 * The environment variables UML_{public,private}_{CTL,DATA} are set to
 * the names of the respective sockets. 
 *
 * If the --arp option is given, the program will respond to all ARP
 * requests that it sees, providing a suitable response.
 *
 * Note that the program continues to operate as a switch and will
 * accept multiple connections. All packets are logged and the
 * outgoing packets are sent to wherever the destination MAC address
 * specifies.
 *
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <poll.h>
#include <net/ethernet.h>
#include <net/if_arp.h>

#define _GNU_SOURCE 1
#include <getopt.h>

#include "pcap.h"
#include <sys/queue.h>

#ifdef NETDISSECT
#include "netdissect.h"
#endif

#include "nethub.h"
#include "hash.h"
#include "port.h"
#include "netjig.h"

char *progname;
jmp_buf getMeOut;

void *xmalloc1(size_t size, char *file, int linenum)
{
	void *space;

	space = malloc(size);
	if(space == NULL) {
		fprintf(stderr, "no memory allocating %d bytes at %s:%d\n",
			size, file, linenum);
		exit(1);
	}
	return space;
}

static void Usage(void)
{
  fprintf(stderr, "Usage : uml_netjig \n"
	  "Version $Revision: 1.27.26.1 $ \n\n"
      "\t--cmdproto (-C)             go into the command protocol prompt\n"
      "\t--exitonempty (-e)          exit when no more packets to read\n"
      "\t--playpublic (-p) <file>    pcap(3) file to feed into public side\n"
      "\t--recordpublic (-r) <file>  pcap(3) file to write from public side\n"
      "\t--playprivate (-P) <file>   pcap(3) file to feed into private side\n"
      "\t--recordprivate (-R) <file> pcap(3) file to write from private side\n"
      "\t--unix (-u) <dir>           directory to put sockets (default $TMPDIR)\n"
      "\t--startup (-s) <script>     script to run after sockets are setup.\n"
#ifdef NETDISSECT
	  "\t--tcpdump (-t)           dump packets with tcpdump-dissector\n"
#else
	  "\t--tcpdump (-t)           (not available - dissector not built in)\n"
#endif
#ifdef ARP_PROCESS
	  "\t--arpreply (-a)          respond to ARP requests\n"
#else
	  "\t--arpreply (-a)          (not available - arp replies disabled)\n"
#endif
	  "\t--help                   this message\n\n");
  exit(1);
}

void netjig1_init(struct netjig_state *ns) 
{
	struct nethub *nh_priv, *nh_pub;
	char errbuf[256];

	nh_pub = init_nethub(ns, "public", NULL, NULL, /* compat_v0 */ 1);
	if(nh_pub == NULL) {
		fprintf(stderr, "failed to allocate public hub\n");
		exit(3);
	}
	nh_priv= init_nethub(ns, "private", NULL, NULL, /* compat_v0 */ 1);
	if(nh_priv == NULL) {
		fprintf(stderr, "failed to allocate priv hub\n");
		exit(3);
	}

	nh_pub->nh_allarp = ns->arpreply;
	nh_priv->nh_allarp= ns->arpreply;

	fprintf(stderr, "%s: will exit on empty: %s\n", progname,
		ns->exitonempty ? "yes" : "no ");

	if(ns->playpublicfile) {
		fprintf(stderr, "%s: will play %s to public interface\n",
			progname, ns->playpublicfile);
		
		nh_pub->nh_inputFile = ns->playpublicfile;
		nh_pub->nh_input = pcap_open_offline(ns->playpublicfile,
						     errbuf);
		if(nh_pub->nh_input == NULL) {
			fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
			exit(1);
		}
		nh_pub->nh_rate = 1;
	}	  

	if(ns->playprivatefile) {
		fprintf(stderr, "%s: will play %s to private interface\n",
		       progname, ns->playprivatefile);
		
		nh_priv->nh_inputFile = ns->playprivatefile;
		nh_priv->nh_input = pcap_open_offline(ns->playprivatefile,
						      errbuf);
		if(nh_priv->nh_input == NULL) {
			fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
			exit(1);
		}
		nh_priv->nh_rate = 1;
	}

	if(ns->recordpublicfile) {
		pcap_t *pt;

		fprintf(stderr, "%s: will record to %s from public interface\n", 
			progname, ns->recordpublicfile);
		nh_pub->nh_outputFile = ns->recordpublicfile;

		pt = pcap_open_dead(DLT_EN10MB, 1536);
		nh_pub->nh_output = pcap_dump_open(pt, ns->recordpublicfile);
		if(nh_pub->nh_output == NULL) {
			fprintf(stderr, "pcap_dump_open failed to open %s\n",
				ns->recordpublicfile);
			exit(1);
		}
	}

	if(ns->recordprivatefile) {
		pcap_t *pt;
		
		fprintf(stderr, "%s: will record to %s from private interface\n",
			progname, ns->recordprivatefile);
		nh_priv->nh_outputFile = ns->recordprivatefile;

		pt = pcap_open_dead(DLT_EN10MB, 1536);
		nh_priv->nh_output = pcap_dump_open(pt, ns->recordprivatefile);
		if(nh_priv->nh_output == NULL) {
			fprintf(stderr, "pcap_dump_open failed to open %s\n",
				ns->recordprivatefile);
			exit(1);
		}
	}

	if(ns->startup) {
		system(ns->startup);
	}
}

void cleanup_njstate(struct netjig_state *ns)
{
  if(rmdir(ns->socketbasedir) < 0){
    fprintf(stderr, "Couldn't remove socket base dir '%s' : %s\n",
	    ns->socketbasedir, strerror(errno));
  }
}


void init_netdissect() 
{
#ifdef NETDISSECT	  
  memset(&gndo, 0, sizeof(gndo));
  gndo.ndo_default_print = default_print;

/*  gndo.ndo_default_output= stderr; */

  /* dump ethernet headers */
  gndo.ndo_eflag = 1;

  /* avoid DNS lookups */
  gndo.ndo_nflag = 0;
#endif
}

void sig_handler(int sig)
{
  fprintf(stderr, "Caught signal %d, cleaning up and exiting\n", sig);
  longjmp(getMeOut, 1);
}

int main(int argc, char **argv)
{
  int n;
  int publicturn;
  int opt;
  struct netjig_state ns;
  struct nethub *onh,*onh2;
  int    onh2toggle;
  int            *l_fd_array;
  int             l_fd_array_size;  /* so we can grow it in add_fd() */
  struct pollfd  *l_fds;        /* array of input sources */
  int             l_nfds;       /* number of relevant entries */

  static struct option long_options[] =
  {
    {"help",        no_argument, 0, 'h'},
    {"arpreply",    no_argument, 0, 'a'},
    {"debug",       no_argument, 0, 'd'},
    {"exitonempty", no_argument, 0, 'e'},
    {"tcpdump",     no_argument, 0, 't'},
    {"playpublic",  required_argument, 0, 'p'},
    {"playprivate", required_argument, 0, 'P'},
    {"recordpublic",  required_argument, 0, 'r'},
    {"recordprivate", required_argument, 0, 'R'},
    {"unix",        required_argument, 0, 'u'},
    {"cmdproto",    no_argument,       0, 'C'},
    {"startup",     required_argument, 0, 's'},
    {NULL, 0, 0, 0},
  };

  memset(&ns, 0, sizeof(ns));

  ns.packetrate = 500;    /* by default, send at a rate of packet/500ms */

  progname = argv[0];
  if(strrchr(progname, '/')) {
	  progname=strrchr(progname, '/')+1;
  }

  while((opt = getopt_long(argc, argv, "adehp:P:r:R:s:tu:v",
			   long_options, NULL)) !=  EOF) {
    switch(opt) {
    case 'a':
	    ns.arpreply++;
	    break;

    case 'C':
	    ns.cmdproto++;
	    break;

    case 'd':
	    ns.debug++;
	    break;

    case 'e':
	    ns.exitonempty++;
	    break;

    case 'u':
	    ns.socketbasedir = optarg;
	    break;

    case 's':
	    ns.startup = optarg;
	    break;
	    
    case 't':
#ifdef NETDISSECT
	    tcpdump_print = 1;
#else
	    if(ns.verbose) {
		    fprintf(stderr, "tcpdump dissector not available\n");
	    }
#endif
	    break;

    case 'p':
      ns.playpublicfile = optarg;
      break;

    case 'P':
      ns.playprivatefile = optarg;
      break;

    case 'r':
      ns.recordpublicfile= optarg;
      break;

    case 'R':
      ns.recordprivatefile= optarg;
      break;
      
    case 'v':
      ns.verbose++;
      break;

    case 'h':
    default:
      Usage();
    }
  }

  if(getenv("NETJIGVERBOSE")) {
	  ns.verbose++;
  }

  if(ns.debug) {
	  fprintf(stderr,"Debugging enabled, sleeping for 60 seconds. Pid=%d\n",
		  getpid());
	  sleep(60);
  }

  if(setjmp(getMeOut)!=0) {
	  struct nethub *nh;

	  signal(SIGINT,  SIG_DFL);
	  signal(SIGPIPE, SIG_IGN);

	  for(nh=ns.switches.tqh_first;
	      nh;
	      nh=onh2) {
		  onh2=nh->nh_link.tqe_next;
		  cleanup_nh(nh);
	  }
	  
	  cleanup_njstate(&ns);

	  exit(1);
  }

  if(signal(SIGINT, sig_handler) < 0)
    perror("Setting handler for SIGINT");

  if(signal(SIGPIPE, sig_handler) < 0)
    perror("Setting handler for SIGINT");


//  if(ns.startup) {
//	  system(ns.startup);
//  }

  /* init stuff */
  create_socket_dir(&ns);
  init_netdissect();

  TAILQ_INIT(&ns.switches);
  ns.cmdproto_out=stdout;

  if(isatty(0) || ns.cmdproto) {
	  add_fd(&ns, 0);
	  cmdprompt(&ns);
  }

  if(!ns.cmdproto) {
	  /* use standard script! */
	  netjig1_init(&ns);
  }

  publicturn = 1;
  ns.done = 0;
  l_fd_array = NULL;
  l_fd_array_size = 0;
  l_fds = NULL;
  l_nfds= 0;

//  printf("%s attached to unix sockets \n\t'%s,%s'\n and \n\t'%s,%s'\n",
//	 progname, ns.public.ctl_socket_name, ns.public.data_socket_name,
//	 ns.private.ctl_socket_name, ns.private.data_socket_name);


  onh2toggle=0;
  onh=NULL;

  while(!ns.done)
  {
    int    timeout;
    char   buf[128];
    struct nethub *nh;

    timeout=-1;

    if(ns.waitplay || !ns.cmdproto || ns.forcetick) {
	    for(nh=ns.switches.tqh_first;
		nh;
		nh=nh->nh_link.tqe_next) {
		    /* XXX
		     * actually, this is wrong. The NH's should be arranged
		     * in a priority queue based upon how long till their next
		     * packet should be sent, but for the moment, the rate is
		     * considered constant... tough.
		     */
		    if(nh->nh_input) {
			    timeout = ns.packetrate;
			    break; /* at least one is enough to invoke timer */
		    }
	    }
    }

    if(ns.debug > 1) {
	    fprintf(stderr, "invoking poll(,%d,) with %s", ns.nfds,
		   timeout ? "waittime" : "no wait");

    }

    /*
     * we need to allocate a local copy of the arrays to use!
     * since we are going to modify the arrays based upon I/O
     */
    if(l_nfds != ns.nfds) {
	    l_nfds = ns.nfds;
	    l_fds = realloc(l_fds, l_nfds * sizeof(struct pollfd));
    }
    memcpy(l_fds,      ns.fds,      l_nfds * sizeof(struct pollfd));
    if(l_fd_array_size != ns.fd_array_size) {
	    l_fd_array_size = ns.fd_array_size;
	    l_fd_array = realloc(l_fd_array, l_fd_array_size*sizeof(int));
    }
    memcpy(l_fd_array, ns.fd_array, l_fd_array_size * sizeof(int));
    
    n = poll(l_fds, l_nfds, timeout);
    
    if(ns.debug > 1) {
	    fprintf(stderr, " -> %d left %d\n", n, timeout);
    }

    if(n < 0 && errno!=EINTR) {
      perror("poll");
      ns.done = 1;
    }

    if((timeout!=-1 && n == 0) || ns.forcetick) {
	    int gotinput;
	    int looped;
	    /* timeout */

	    looped = 0;
	    gotinput=0;

	    while((onh==NULL ||
		   onh->nh_input == NULL) &&
		  looped < 2) {

		    if(onh==NULL || onh->nh_link.tqe_next==NULL) {
			    /* restart from the beginning, but only once */
			    onh=ns.switches.tqh_first;
			    onh2=NULL;
			    looped++;
		    } else {
			    /* this implements the tortose and hare loop
			     * detection algorithm, see Allen Van Gelder:
			     * _Efficient Loop Detection in Prolog using
			     * the Tortoise-and-Hare Technique.
			     * JLP 4(1): 23-31 (1987) 
			     */
			    if(onh2toggle) {
				    onh2=onh;
			    }
			    onh2toggle=!onh2toggle;
			    
			    /* advance the pointer once */
			    onh = onh->nh_link.tqe_next;
			    
			    assert(onh!=onh2);  /* is there a loop? */
		    }
	    }
	    /*
	     * now make sure that this source has data. If it doesn't,
	     * then it is because we have wrapped around and found nothing.
	     */
	    nh=onh;
	    
	    if(nh && nh->nh_input) {
		    struct pcap_pkthdr ph;
		    const u_char *packet;

		    memset(&ph, 0, sizeof(ph));
	
		    packet = pcap_next(nh->nh_input, &ph);
		    if(packet == NULL) {
			    nh->nh_input=NULL;
		    } else {
			    gotinput = 1;
			    if(ns.verbose) {
				    fprintf(stderr,
					    "%8s: inserting packet of len %d\n",
					    nh->nh_name, ph.len);
			    }
			    insert_data(&ns, nh,
					(struct packet *)packet, ph.len);
		    }
	    }

	    if(ns.forcetick == 0) {
		    if(!gotinput &&
		       ns.exitonempty) {
			    ns.done=1;
		    }
	    }
	    ns.forcetick = 0;

	    if(!gotinput && ns.waitplay) {
		    finish_waitplay(&ns);
	    }


	    /* timeout the switch tables */
	    for(nh=ns.switches.tqh_first;
		nh;
		nh=nh->nh_link.tqe_next) {
		    hash_periodic(nh);
	    }

    }

    if(n>0) {
	    /* first process commands on stdin */
	    if(l_fd_array_size > 0 &&
	       l_fd_array[0]!=-1) {
		    if(l_fds[l_fd_array[0]].revents & POLLIN) {
			    int readlen;
			    readlen = read(0, buf, sizeof(buf));
			    if(readlen < 0){
				    perror("Reading from stdin");
				    break;
			    }
			    else if(readlen == 0){
				    fprintf(stderr, "EOF on stdin, cleaning up and exiting\n");
				    break;
			    }
			    else if(ns.cmdproto) {
				    cmdread(&ns, buf, readlen);
			    }
			    
			    /* note that we have processed one descriptor */
			    l_fds[l_fd_array[0]].revents=0;
			    n--;
		    } else if(l_fds[l_fd_array[0]].revents & POLLHUP) {
			    /* exit! */
			    ns.done=1;
		    }
			    
	    }
	    
	    /* then process control socket connections */
	    for(nh=ns.switches.tqh_first;
		nh;
		nh=nh->nh_link.tqe_next) {

		    if(nh->ctl_listen_fd < l_fd_array_size &&
		       l_fd_array[nh->ctl_listen_fd]!=-1 &&
		       l_fds[l_fd_array[nh->ctl_listen_fd]].revents & (POLLIN|POLLHUP)) {
			    accept_connection(&ns, nh);
			    n--;
			    l_fds[l_fd_array[nh->ctl_listen_fd]].revents=0;
		    }
	    }

	    /* then look for packets to process */
	    for(nh=ns.switches.tqh_first;
		nh;
		nh=nh->nh_link.tqe_next) {

		    if(nh->data_fd < l_fd_array_size &&
		       l_fd_array[nh->data_fd]!=-1 && 
		       l_fds[l_fd_array[nh->data_fd]].revents & POLLIN) {
			    handle_sock_data(&ns, nh);
			    n--;
			    l_fds[l_fd_array[nh->data_fd]].revents=0;
#ifdef TUNTAP
		    } else if(nh->tap_fd < l_fd_array_size &&
		       l_fd_array[nh->tap_fd]!=-1 && 
		       l_fds[l_fd_array[nh->tap_fd]].revents & POLLIN) {
			    handle_tap_data(&ns, nh);
			    n--;
			    l_fds[l_fd_array[nh->data_fd]].revents=0;
#endif
		    }
	    }
	    
	    /* finally, check out the sockets that are just listen(2)
	     * for new connections.
	     */
	    for(nh=ns.switches.tqh_first;
		nh;
		nh=nh->nh_link.tqe_next) {
		    handle_port(&ns, nh,
				l_fds, l_nfds,
				l_fd_array, l_fd_array_size);
	    }
    }
  }

  signal(SIGINT,  SIG_DFL);
  signal(SIGPIPE, SIG_IGN);

  for(onh=ns.switches.tqh_first;
      onh;
      onh=onh2) {
	  onh2=onh->nh_link.tqe_next;
	  TAILQ_REMOVE(&ns.switches,onh,nh_link);
	  cleanup_nh(onh);
  }
  
  cleanup_njstate(&ns);
  
  return 0;
}

/*
 * $Log: uml_netjig.c,v $
 * Revision 1.27.26.1  2005/08/12 16:32:01  ken
 * Make tree PG13
 *
 * Revision 1.27  2003/04/02 20:25:53  mcr
 * 	quiet down uml_netjig unless -v or $NETJIGVERBOSE is set.
 *
 * Revision 1.26  2003/04/02 02:15:59  mcr
 * 	added option to set packet replay rate.
 *
 * Revision 1.25  2002/11/11 17:07:59  mcr
 * 	add new line for new libnetdissect - but this code
 * 	isn't ready yet.
 *
 * Revision 1.24  2002/09/05 17:01:42  mcr
 * 	make sure that the netdissect system is properly initialized.
 *
 * Revision 1.23  2002/09/02 19:33:47  mcr
 * 	the WAITPLAY command did work - it signaled end of
 * 	packet stream, but then forgot this fact, and didn't
 * 	actually exit.
 * 	The netjig.tcl will now log to stderr any problems talking
 * 	to uml_netjig, so this problem will be more obvious in
 * 	the future.
 *
 * Revision 1.22  2002/08/30 01:37:35  mcr
 * 	double buffered the poll(2) structures so that changes during
 * 	use would not affect the system.
 * 	changed fd_array to be indirect references so that the poll(2)
 * 	loop could more easily double buffer the structures.
 *
 * Revision 1.21  2002/08/13 00:50:19  mcr
 * 	when using poll(2), the invalid timeout value is -1,
 * 	not 0 as with select.
 *
 * Revision 1.20  2002/07/21 16:40:34  mcr
 * 	clean pid file upon exit, so that directories can be removed
 * 	properly. Free up memory that was allocated for the hub.
 * 	switch to using mkstemp instead of tmpname for directory
 * 	creation - append .d to the generated name. (still not race safe!)
 * 	when freeing the hubs, take care not to reference free'ed memory.
 *
 * Revision 1.19  2002/07/20 02:12:02  mcr
 * 	create a new function, insert_data() that calls send_dst
 * 	directly rather than using handle_data() which logs the data.
 * 	This avoids having input packets in the packet capture.
 *
 * Revision 1.18  2002/07/19 20:49:09  mcr
 * 	all incidental messages moved from stdout to stderr since
 * 	stdout is often attacked to a pipe in uml_netjig, and writing
 * 	to the pipe after it closes causes problems.
 * 	cleanup_nh() now properly closes the pcap file before exiting.
 * 	host-test.tcl now waits for eof from netjig - this may not work.
 * 	netjig does not output anything when told to "QUIT"
 *
 * Revision 1.17  2002/07/17 23:52:31  mcr
 * 	on some systems, the poll generates an POLLHUP for stdin
 * 	which must be dealt with in some way.
 *
 * Revision 1.16  2002/07/16 03:48:47  mcr
 * 	handle SIGPIPE cleanly.
 *
 * Revision 1.15  2002/07/15 09:58:38  mcr
 * 	debugging of uml_netjig with new network backend.
 *
 * Revision 1.14  2002/07/14 02:48:48  mcr
 * 	first version of merged uml_switch/uml_netjig that compiles.
 *
 * Revision 1.13  2002/06/17 05:17:01  mcr
 * 	when not in cmdproto mode, run the packets as possible.
 *
 * Revision 1.12  2002/06/16 23:51:16  mcr
 * 	revised uml_netjig - cmd mode has vastly improved, and it
 * 	now can run a single UML in cmd mode.
 * 	man page still missing.
 *
 * Revision 1.11  2002/06/03 01:24:11  mcr
 * 	uml_netjig now tries to cleanup (remove) the directories in
 * 	/tmp that it made.
 *
 * Revision 1.10  2002/05/30 07:06:55  dhr
 *
 * spelling
 *
 * Revision 1.9  2002/05/08 20:24:28  mcr
 * 	this is now uml_netjig version 2.
 * 	It has a command protocol (--cmdproto) which permits one to
 * 	invoke some functions as desired.
 * 	Without this option, it acts like version 1.
 *
 * Revision 1.8  2002/01/21 01:08:41  mcr
 * 	do not die if -t option is provided, but tcpdump compiled out.
 *
 * Revision 1.7  2002/01/12 04:01:36  mcr
 * 	another #ifdef NETDISSET for tcpdump_print access.
 *
 * Revision 1.6  2002/01/12 03:40:56  mcr
 * 	missing #ifdef for on NETDISSECT call.
 *
 * Revision 1.5  2002/01/12 02:52:46  mcr
 * 	added --debug option to replace #if 0.
 *
 * Revision 1.4  2001/10/23 16:34:12  mcr
 * 	use "progname" instead of "prog"
 * 	fixed public/private confused variables in printf().
 * 	fixed bug in termination logic.
 *
 * Revision 1.3  2001/10/14 00:27:10  mcr
 * 	added code to play pcap files to both public and private sides.
 * 	updated usage.
 *
 * Revision 1.2  2001/10/12 20:54:02  mcr
 * 	documented environment variables
 * 	added arp replies
 * 	added --help and fixed Usage().
 *
 * Revision 1.1  2001/10/08 22:54:05  mcr
 * 	uml_net program that handles two interfaces.
 * 	no support for pcap yet.
 *
 *
 *
 * Local variables:
 * c-file-style: "linux"
 * c-basic-offset: 2
 * End:
 *
 */
