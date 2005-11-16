/*
 * DNS KEY lookup helper
 * Copyright (C) 2002 Michael Richardson <mcr@freeswan.org>
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
 */

char tncfg_c_version[] = "RCSID $Id: lwdnsq.c,v 1.19 2004/12/02 06:16:19 mcr Exp $";


#include <stdio.h>
#include <string.h>
#include <stdlib.h> 
#include <unistd.h> 

#include <errno.h>
#include <getopt.h>
#include <setjmp.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>

#include <isc/lang.h>
#include <isc/magic.h>
#include <isc/types.h>
#include <isc/result.h>
#include <isc/mem.h>
#include <isc/buffer.h>
#include <isc/region.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdatastruct.h>
#include <lwres/netdb.h>
#include <lwres/async.h>

#include "lwdnsq.h"

FILE *cmdlog = NULL;

extern int EF_DISABLE_BANNER;
extern int EF_ALIGNMENT;
extern int EF_PROTECT_BELOW;
extern int EF_PROTECT_FREE;
extern int EF_ALLOW_MALLOC_0;
extern int EF_FREE_WIPES;


static void
usage(char *name)
{	
	fprintf(stdout,"%s\n", name);
	exit(1);
}

static struct option const longopts[] =
{
	{"prompt", 0, 0, 'i'},
	{"serial", 0, 0, 's'},
	{"debug",  0, 0, 'g'},
	{"log",    1, 0, 'l'},
	{"regress",0, 0, 'X'},
	{"ignoreeof",0, 0, 'Z'},
	{0, 0, 0, 0}
};

/* globals */
jmp_buf getMeOut;

static void sig_handler(int sig)
{
  fprintf(stderr, "Caught signal %d, cleaning up and exiting\n", sig);
  longjmp(getMeOut, 1);
}

static void cmdprompt(dnskey_glob *gs)
{
	if(gs->prompt) {
		printf("lwdnsq> ");
	}
	fflush(gs->cmdproto_out);
}

static void quitprog(dnskey_glob *gs,
		     int argc UNUSED,
		     char **argv UNUSED)
{
	argc = argc;
	argv = argv;
	gs->done=1;
}

static void setdebug(dnskey_glob *gs,
	      int argc,
	      char **argv)
{
	if(argc > 1) {
		gs->debug=strtoul(argv[1],NULL,0);
	}
	printf("0 DEBUG is %d\n",gs->debug);
}


static int cmdparse(dnskey_glob *gs,
	     char *cmdline)
{
	char *argv[256];
	int   argc;
	char *arg;
	static const struct cmd_entry {
		const char *cmdname;
		void (*cmdfunc)(dnskey_glob *, int, char **);
	} cmds[]={
		{"key",       lookup_key},
		{"key4",      lookup_key4},
		{"key6",      lookup_key6},
		{"txt",       lookup_txt},
		{"txt4",      lookup_txt4},
		{"txt6",      lookup_txt6},
		{"ipseckey",  lookup_ipseckey},
		{"ipseckey4", lookup_ipseckey4},
		{"ipseckey6", lookup_ipseckey6},
		{"oe4",       lookup_oe4},
		{"oe6",       lookup_oe6},
		{"vpn4",      lookup_key4},
		{"vpn6",      lookup_key6},
		{"quit",      quitprog},
		{"a",         lookup_a},
		{"aaaa",      lookup_aaaa},
		{"debug",     setdebug},
		{NULL,        NULL}};
	const struct cmd_entry *ce = cmds;

	if(cmdlog != NULL) {
		fprintf(cmdlog, "%lu|%s\n", time(NULL), cmdline);
		fflush(cmdlog);
	}

	argc=0;
	
	/* skip initial spaces */
	while(cmdline && isspace(*cmdline)) {
		cmdline++;
	}

	while(cmdline && *cmdline!='\0' &&
	      (arg=strsep(&cmdline, " \t\n"))!=NULL) {
	  if (argc < (signed)(sizeof(argv)/sizeof(*argv - 1))) {
	    /* ignore arguments that would overflow.
	     * XXX should generate a diagnostic.
	     */
	    argv[argc++]=arg;
	  }
	  while(cmdline && isspace(*cmdline)) {
	    cmdline++;
	  }
	}
	argv[argc]=NULL;

	if(argc==0 || argv[0][0]=='\0') {
	    /* ignore empty line */
	} else if(strcasecmp("help", argv[0]) == 0) {
	    fprintf(gs->cmdproto_out, "0 HELP\n");
	    for (; ce->cmdname != NULL; ce++)
		fprintf(gs->cmdproto_out, "0 HELP %s\n", ce->cmdname);
	} else {
	    for (;; ce++) {
		if (ce->cmdname == NULL) {
		    fprintf(gs->cmdproto_out, "0 FATAL unknown command \"%s\"\n", argv[0]);
		    break;
		}
		if(strcasecmp(ce->cmdname, argv[0])==0) {
		    (*ce->cmdfunc)(gs, argc, argv);
		    break;
		}
	    }
	}

	if (!gs->done) {
		gs->promptnow = 1;
	}
	return 0;
}

static int cmdread(dnskey_glob *gs,
		   char  *buf,
		   int    len)
{
	unsigned char *nl;
	int   cmdlen;

	cmdlen=0;

	/* 
	 * have to handle partial reads and multiple commands
	 * per read, since this may in fact be a file or a pipe.
	 */
	if((gs->cmdloc + len + 1) > sizeof(gs->cmdbuf)) {
		fprintf(stderr, "command '%.*s...' is too long, discarding!\n",
			40, buf);
		fflush(stdout);
		
		gs->cmdloc=0;
		return 0;
	}
	memcpy(gs->cmdbuf+gs->cmdloc, buf, len);
	gs->cmdloc+=len;
	gs->cmdbuf[gs->cmdloc]='\0';

	while((nl = strchr(gs->cmdbuf, '\n')) != NULL) {
		/* found a newline, so turn it into a \0, and process the
		 * command, and then we will pull the rest of the buffer
		 * up.
		 */
		*nl='\0';
		cmdlen= nl - gs->cmdbuf +1;

		cmdparse(gs, gs->cmdbuf);

		gs->cmdloc -= cmdlen;
		memmove(gs->cmdbuf, gs->cmdbuf+cmdlen, gs->cmdloc);
	}
	return 1;
}

int
main(int argc, char *argv[])
{
	char *program_name;
	dnskey_glob gs;
	int c;
	static int ignoreeof=0;  /* static to avoid longjmp clobber */
	int ineof;
	char *logfilename=NULL;

	memset(&gs, 0, sizeof(dnskey_glob));

#if 0
	printf("PID: %d\n", getpid());
	sleep(60);
#endif

#ifdef EFENCE
	EF_DISABLE_BANNER=1;
	/* EF_ALIGNMENT=4; */
	EF_PROTECT_BELOW=1;
	EF_PROTECT_FREE=1;
	/* EF_ALLOW_MALLOC_0; */
	EF_FREE_WIPES=1;
#endif

	{ 
			FILE *newerr;
			newerr = fopen("/var/tmp/lwdnsq.log", "a+");
			if(newerr) {
				close(2);
				dup2(fileno(newerr), 2);
				fclose(newerr);
			}
			fprintf(stderr, "stderr capture started\n");
			setbuf(stderr, NULL);
	}


	program_name = argv[0];
	gs.concurrent = 1;

	if(lwres_async_init(&gs.lwctx) != ERRSET_SUCCESS) {
		fprintf(stderr, "Can not initialize async context\n");
		exit(3);
	}

	if(isc_mem_create(0,0,&gs.iscmem) != ISC_R_SUCCESS) {
		fprintf(stderr, "Can not initialize isc memory allocator\n");
		exit(4);
	}

	if(isc_buffer_allocate(gs.iscmem, &gs.iscbuf, LWDNSQ_RESULT_LEN_MAX)) {
		fprintf(stderr, "Can not allocate a result buffer\n");
		exit(5);
	}

	while((c = getopt_long_only(argc, argv, "dgl:siXZ", longopts, 0)) != EOF) {
		switch(c) {
		case 'd':
			gs.debug+=2;
			logfilename="/var/tmp/lwdns.req.log";
			break;

		case 'g':
			gs.debug++;
			break;

		case 's':
			gs.concurrent=0;
			break;
		case 'i':
			gs.prompt=1;
			break;
		case 'X':
			gs.regress++;
			break;

		case 'l':
			logfilename=optarg;
			break;

		case 'Z':
			ignoreeof=1;
			break;

		default:
			usage(program_name);
			break;
		}
	}

	if(gs.debug && ignoreeof) {
		fprintf(stderr, "Ignoring end of file\n");
	}

	if(isatty(0)) {
		gs.prompt=1;
	}

	if(logfilename != NULL) {
	  cmdlog = fopen(logfilename, "w");
	  if(cmdlog == NULL) {
	    fprintf(stderr, "Can not open %s: %s\n", logfilename, strerror(errno));
	  }
	}

	/* do various bits of setup */
	if(setjmp(getMeOut)!=0) {
		signal(SIGINT,  SIG_DFL);
		signal(SIGPIPE, SIG_IGN);
		
		/* cleanup_crap(); */
		
		exit(1);
	}
	
	if(signal(SIGINT, sig_handler) == SIG_ERR)
		perror("Setting handler for SIGINT");
	
	if(signal(SIGPIPE, sig_handler) == SIG_ERR)
		perror("Setting handler for SIGINT");
	
	cmdprompt(&gs);

	ineof = 0;
	gs.done = 0;
	gs.cmdproto_out = stdout;

	while(!gs.done) 
	{
		int    timeout;
		char   buf[128];
		int    n;
		int    rlen, err2;

		timeout = LWDNSQ_RETRANSMIT_INTERVAL * 1000;

		/* 
		 * do not prompt for more items, or look for HUP if
		 * we are in serial mode.. We know we are working
		 * if there are questions in flight. 
		 */
		gs.l_fds[1].events = 0;

		if(gs.concurrent || gs.dns_inflight == 0) {
			if(gs.promptnow && gs.prompt) {
				cmdprompt(&gs);
				gs.promptnow = FALSE;
			}
			gs.l_fds[1].events = POLLIN;
			if(!ignoreeof) {
				gs.l_fds[1].events |= POLLHUP;
			}
			gs.l_nfds = 2;
		} else {
			gs.l_fds[1].events = 0;
			gs.l_nfds = 1;
		}
			
		gs.l_fds[1].revents = 0;

		gs.l_fds[0].events = POLLIN|POLLHUP;
		gs.l_fds[0].revents = 0;
		gs.l_fds[0].fd = lwres_async_fd(gs.lwctx);

		if(gs.debug > 1) {
			fprintf(stderr, "=== invoking poll(,%d,%d)\n",
				gs.l_nfds, timeout);
			for(n = 0; n < gs.l_nfds; n++) {
				fprintf(stderr, "=== waiting on fd#%d\n",
					gs.l_fds[n].fd);
			}
			fprintf(stderr, "=== inflight: %d\n", gs.dns_inflight);
		}

		errno = 0;
		n = poll(gs.l_fds, gs.l_nfds, timeout);
		err2 = errno;

		/* there was some activity, so look for pending retransmits
		 * first, even if it wasn't due to the timeout.
		 */
		{
			struct dnskey_lookup *dl, *dlthis;
			
			dl = gs.dns_outstanding;
			
			while(dl) {
				/* dl could go away */
				dlthis = dl;
				dl = dl->next;

				dns_rexmit(&gs, dlthis, 0);
			}
		}

		if(n < 0) {
			perror("poll");
		}

		if(gs.debug > 1) {
			fprintf(stderr, "=== poll returned with %d\n", n);
		}
				
		while(n>0) {
			if((gs.l_fds[0].revents & POLLERR) == POLLERR ||
			   (gs.l_fds[1].revents & POLLERR) == POLLERR)
			{
				struct dnskey_lookup *dl, *dlthis;
				if(gs.debug > 1) {
					fprintf(stderr, "=== poll returned error %s\n",
						strerror(err2));
				}

				/* on error, we force retransmit, because
				 * one reasonable source of errors it because
				 * the named isn't ready yet.
				 */
				sleep(1);
			
				dl = gs.dns_outstanding;
				while(dl) {
					/* dl could go away */
					dlthis = dl;
					dl = dl->next;
					
					dns_rexmit(&gs, dlthis, 1);
				}
				n = 0;
				break;
			}

			/* see if there are DNS events coming back */
			if((gs.l_fds[0].revents & POLLIN) == POLLIN) {
				if(gs.debug > 1) {
					fprintf(stderr,
						"=== new responses from lwdnsd\n");
				}

				process_dns_reply(&gs);
				fflush(stdout);
				n--;
			}

			if(!ignoreeof &&
			   (gs.l_fds[1].revents & POLLHUP) == POLLHUP)
			{
				break;
			}

			if((gs.l_fds[1].revents & POLLIN) == POLLIN) {
				
				rlen=read(0, buf, sizeof(buf));

				if(gs.debug > 1) {
					if(rlen > 0) {
						buf[rlen]='\0';
					}
					fprintf(stderr,
						"=== new commands on fd 0: %d: %s\n",
						rlen, buf);
				}

				if(rlen > 0) {
					cmdread(&gs, buf, rlen);
				} else if(rlen == 0) {
					ineof = 1;
					if(!ignoreeof) {
						/* EOF, die */
						gs.done=1;
					}
				}
				n--;
			} 

		}

		if((gs.l_fds[1].revents & POLLHUP) == POLLHUP)
		{
			ineof = 1;
			if(!ignoreeof)
			{
				gs.done=1;
			}
		}

		if(ignoreeof) {
			/* if we have exhausted the input,
			 * and there are none in flight,
			 * then exit, finally.
			 */
			if(ineof) { 
				if(gs.dns_inflight == 0) {
					gs.done=1;
				}
			}
		}

		if(gs.debug) {
			fprintf(stderr, "=== ineof: %d inflight: %d\n",
				ineof, gs.dns_inflight);
		}

	}

	signal(SIGINT,  SIG_DFL);
	signal(SIGPIPE, SIG_IGN);
  
	exit(0);
}
	
/*
 * $Log: lwdnsq.c,v $
 * Revision 1.19  2004/12/02 06:16:19  mcr
 * 	fixed long standing bug with async resolver when there was
 * 	more than one outstanding request.
 *
 * Revision 1.18  2004/11/25 18:16:47  mcr
 * 	make sure to actually open the log file.
 *
 * Revision 1.17  2004/11/24 01:36:10  mcr
 * 	if debugging is on, then log all requests that are sent,
 * 	so that we can later replay, looking for bugs.
 *
 * Revision 1.16  2003/12/02 04:34:09  mcr
 * 	if lwresd does not start early enough, then the request is
 * 	lost and never retransmitted. This version can now deal with
 * 	named being slow to start, or taking along time to verify
 * 	DNSSEC signatures.
 * 	This also fixes the non-concurrent stuff.
 *
 * Revision 1.15  2003/12/02 02:55:19  mcr
 * 	prompting in non-concurrent mode looks right now.
 * 	do not ask for EOF messages from stdin if we are in ignoreeof
 * 	mode.
 *
 * Revision 1.14  2003/12/01 21:45:17  mcr
 * 	the lwctx structure needs to be properly initialized.
 * 	the lwdnsq program needs to have the --serial option finished,
 * 	and a retransmitter installed.
 *
 * Revision 1.13  2003/09/19 02:56:11  mcr
 * 	fixes to make lwdnsq compile with strictest compile flags.
 *
 * Revision 1.12  2003/09/16 05:01:14  mcr
 * 	prefix all debugging with === so that it can be easily removed.
 *
 * Revision 1.11  2003/09/10 04:43:52  mcr
 * 	final fixes to lwdnsq to exit only when all requests are done,
 * 	and we have been told to wait, *OR* if there is an EOF in stdin.
 *
 * Revision 1.10  2003/09/03 01:13:24  mcr
 * 	first attempt at async capable lwdnsq.
 *
 * Revision 1.9  2003/04/02 07:37:57  dhr
 *
 * lwdnsq: fix non-deterministic bug in handling batched input
 *
 * Revision 1.8  2003/02/08 04:03:06  mcr
 * 	renamed --single to --serial.
 *
 * Revision 1.7  2003/01/14 03:01:14  dhr
 *
 * improve diagnostics; tidy
 *
 * Revision 1.6  2002/12/19 07:29:47  dhr
 *
 * - avoid (improbable) buffer overflow
 * - suppress prompt after "quit" command
 * - add space to prompt to match aesthetics and man page
 * - elminate a magic number
 *
 * Revision 1.5  2002/12/19 07:08:42  dhr
 *
 * continue renaming dnskey => lwdnsq
 *
 * Revision 1.4  2002/12/12 06:03:41  mcr
 * 	added --regress option to force times to be regular
 *
 * Revision 1.3  2002/11/25 18:37:48  mcr
 * 	make sure that we exit cleanly upon EOF.
 *
 * Revision 1.2  2002/11/16 02:53:53  mcr
 * 	lwdnsq - with new contract added.
 *
 * Revision 1.1  2002/10/30 02:25:31  mcr
 * 	renamed version of files from dnskey/
 *
 * Revision 1.3  2002/10/09 20:14:16  mcr
 * 	make sure to flush stdout at the right time - do it regardless
 * 	of whether or not we are printing prompts.
 *
 * Revision 1.2  2002/09/30 18:55:54  mcr
 * 	skeleton for dnskey helper program.
 *
 * Revision 1.1  2002/09/30 16:50:23  mcr
 * 	documentation for "dnskey" helper
 *
 * Local variables:
 * c-file-style: "linux"
 * c-basic-offset: 2
 * End:
 *
 */
