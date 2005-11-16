/* 
 * Cryptographic helper function.
 * Copyright (C) 2004 Michael C. Richardson <mcr@xelerance.com>
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
 * This code was developed with the support of IXIA communications.
 *
 * RCSID $Id: pluto_crypt.c,v 1.19 2005/07/13 02:14:08 mcr Exp $
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <signal.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "constants.h"
#include "defs.h"
#include "packet.h"
#include "demux.h"
#include "oswlog.h"
#include "log.h"
#include "state.h"
#include "demux.h"
#include "rnd.h"
#include "pluto_crypt.h"

struct pluto_crypto_worker {
    int   pcw_helpernum;
    pid_t pcw_pid;
    int   pcw_pipe;
    int   pcw_work;         /* how many items outstanding */
    int   pcw_maxbasicwork; /* how many basic things can be queued */
    int   pcw_maxcritwork;  /* how many critical things can be queued */
    bool  pcw_dead;         /* worker is dead, waiting for reap */
    bool  pcw_reaped;       /* worker has been reaped, waiting for dealloc */
    struct pluto_crypto_req_cont *pcw_cont;
};

static struct pluto_crypto_req_cont *backlogqueue;
static int                           backlogqueue_len;

static void init_crypto_helper(struct pluto_crypto_worker *w, int n);
static void cleanup_crypto_helper(struct pluto_crypto_worker *w, int status);
static void handle_helper_comm(struct pluto_crypto_worker *w);
extern void free_preshared_secrets(void);

/* may be NULL if we are to do all the work ourselves */
struct pluto_crypto_worker *pc_workers = NULL;
int pc_workers_cnt = 0;
int pc_worker_num;
pcr_req_id pcw_id;

/* local in child */
int pc_helper_num=-1;

void pluto_do_crypto_op(struct pluto_crypto_req *r)
{
    DBG(DBG_CONTROL
	, DBG_log("helper %d doing %s op id: %u"
		  , pc_helper_num
		  , enum_show(&pluto_cryptoop_names, r->pcr_type)
		  , r->pcr_id));


    /* now we have the entire request in the buffer, process it */
    switch(r->pcr_type) {
    case pcr_build_kenonce:
	calc_ke(r);
	calc_nonce(r);
	break;

    case pcr_build_nonce:
	calc_nonce(r);
	break;

    case pcr_compute_dh_iv:
	calc_dh_iv(r);
	break;

    case pcr_compute_dh:
	calc_dh(r);
	break;

    case pcr_rsa_sign:
    case pcr_rsa_check:
    case pcr_x509cert_fetch:
    case pcr_x509crl_fetch:
	break;
    }
}

static void catchhup(int signo UNUSED)
{
    /* socket closed die */
    exit(0);
}

static void catchusr1(int signo UNUSED)
{
    return;
}

static void
helper_passert_fail(const char *pred_str
		    , const char *file_str
		    , unsigned long line_no) NEVER_RETURNS;

static void
helper_passert_fail(const char *pred_str
		    , const char *file_str
		    , unsigned long line_no)
{
    static bool dying_breath = 0;

    /* we will get a possibly unplanned prefix.  Hope it works */
    loglog(RC_LOG_SERIOUS, "ASSERTION FAILED at %s:%lu: %s", file_str, line_no, pred_str);
    if (!dying_breath)
    {
	dying_breath = TRUE;
    }
    chdir("helper");
    abort();
}


void pluto_crypto_helper(int fd, int helpernum)
{
    char reqbuf[PCR_REQ_SIZE];
    struct pluto_crypto_req *r;

    signal(SIGHUP, catchhup);
    signal(SIGUSR1, catchusr1);

    pc_worker_num = helpernum;
    /* make us lower priority that average */
    setpriority(PRIO_PROCESS, 0, 10);

    DBG(DBG_CONTROL, DBG_log("helper %d waiting on fd: %d"
			      , helpernum, fd));

    memset(reqbuf, 0, sizeof(reqbuf));
    while(read(fd, reqbuf, sizeof(r->pcr_len)) == sizeof(r->pcr_len)) {
	int restlen;
	int actlen;

	r = (struct pluto_crypto_req *)reqbuf;
	restlen = r->pcr_len-sizeof(r->pcr_len);
	
	passert(restlen < (signed)PCR_REQ_SIZE);

	/* okay, got a basic size, read the rest of it */
	if((actlen= read(fd, reqbuf+sizeof(r->pcr_len), restlen)) != restlen) {
	    /* faulty read. die, parent will restart us */
	    
	    loglog(RC_LOG_SERIOUS, "cryptographic helper(%d) read(%d)=%d failed: %s\n",
		   getpid(), restlen, actlen, strerror(errno));
	    exit(1);
	}

	pluto_do_crypto_op(r);

	actlen = write(fd, (unsigned char *)r, r->pcr_len);

	if((unsigned)actlen != r->pcr_len) {
	    loglog(RC_LOG_SERIOUS, "failed to write answer: %d", actlen);
	    exit(2);
	}
	memset(reqbuf, 0, sizeof(reqbuf));
    }

    /* probably normal EOF */
    close(fd);
    exit(0);
}


/*
 * this function is called with a request to do some cryptographic operations
 * along with a continuation structure, which will be used to deal with
 * the response.
 *
 * This may fail if there are no helpers that can take any data, in which
 * case an error is returned. 
 *
 */
err_t send_crypto_helper_request(struct pluto_crypto_req *r
				 , struct pluto_crypto_req_cont *cn
				 , bool *toomuch)
{
    struct pluto_crypto_worker *w;
    int cnt;

    /* do it all ourselves? */
    if(pc_workers == NULL) {
	reset_cur_state();

	pluto_do_crypto_op(r);
	/* call the continuation */
	(*cn->pcrc_func)(cn, r, NULL);

	/* indicate that we did everything ourselves */
	*toomuch = TRUE;

	pfree(cn);
	pfree(r);
	return NULL;
    }

    /* set up the id */
    r->pcr_id = pcw_id++;
    cn->pcrc_id = r->pcr_id;
    cn->pcrc_pcr = r;

    pc_worker_num++;
    if(pc_worker_num >= pc_workers_cnt) {
	pc_worker_num = 0;
    }

    cnt = pc_workers_cnt;

    /* find an available worker, restarting one if it was found to be dead */
    w = &pc_workers[pc_worker_num];

    DBG(DBG_CONTROL
	, DBG_log("%d: w->pcw_dead: %d w->pcw_work: %d cnt: %d",
		  pc_worker_num, w->pcw_dead, w->pcw_work, cnt));
    
    while((w->pcw_dead || (w->pcw_work >= w->pcw_maxbasicwork))
	  && --cnt > 0) {
	
	pc_worker_num++;
	w = &pc_workers[pc_worker_num];

	/* see if there is something to clean up after */
	if(w->pcw_dead      == TRUE
	   && w->pcw_reaped == TRUE) {
	    cleanup_crypto_helper(w, 0);
	}
	DBG(DBG_CONTROL
	    , DBG_log("%d: w->pcw_dead: %d w->pcw_work: %d cnt: %d",
		      pc_worker_num, w->pcw_dead, w->pcw_work, cnt));
    }

    if(cnt == 0 && r->pcr_pcim > pcim_ongoing_crypto) {
	cnt = pc_workers_cnt;
	while((w->pcw_dead || (w->pcw_work >= w->pcw_maxcritwork))
	      && --cnt > 0) {
	
	    pc_worker_num++;
	    w = &pc_workers[pc_worker_num];

	    /* see if there is something to clean up after */
	    if(w->pcw_dead      == TRUE
	       && w->pcw_reaped == TRUE) {
		cleanup_crypto_helper(w, 0);
	    }
	    DBG(DBG_CONTROL
		, DBG_log("crit %d: w->pcw_dead: %d w->pcw_work: %d cnt: %d",
			  pc_worker_num, w->pcw_dead, w->pcw_work, cnt));
	}
    }

    if(cnt == 0 && r->pcr_pcim >= pcim_demand_crypto) {
	/* it is very important. Put it all on a queue for later */
	cn->pcrc_next = backlogqueue;
	backlogqueue  = cn;
	
	backlogqueue_len++;
	DBG(DBG_CONTROL
	    , DBG_log("critical demand crypto operation queued as item %d"
		      , backlogqueue_len));
	*toomuch = FALSE;
	return NULL;
    }

    if(cnt == 0) {
	/* didn't find any workers */
	DBG(DBG_CONTROL
	    , DBG_log("failed to find any available worker"));

	*toomuch = TRUE;
	return "failed to find any available worker";
    }

    /* w points to a work. Make sure it is live */
    if(w->pcw_pid == -1) {
	init_crypto_helper(w, pc_worker_num);
	if(w->pcw_pid == -1) {
	    DBG(DBG_CONTROL
		, DBG_log("found only a dead helper, and failed to restart it"));
	    *toomuch = TRUE;
	    return "failed to start a new helper";
	}
    }

    /* link it to the active worker list */
    cn->pcrc_next = w->pcw_cont;
    w->pcw_cont = cn;

    passert(w->pcw_pid != -1);
    passert(w->pcw_pipe != -1);
    passert(w->pcw_work < w->pcw_maxcritwork);
    
    DBG(DBG_CONTROL
	, DBG_log("asking helper %d to do %s op on seq: %u"
		  , w->pcw_helpernum
		  , enum_show(&pluto_cryptoop_names, r->pcr_type)
		  , r->pcr_id));

    /* send the request, and then mark the work as having more work */
    cnt = write(w->pcw_pipe, r, r->pcr_len);
    if(cnt == -1) {
	return "failed to write";
    } 

    w->pcw_work++;
    *toomuch = FALSE;
    return NULL;
}

/*
 * send 1 unit of backlog, if any, to indicated worker.
 */
static void crypto_send_backlog(struct pluto_crypto_worker *w)
{
    struct pluto_crypto_req *r;
    struct pluto_crypto_req_cont *cn;

    if(backlogqueue_len > 0) {
	int cnt;

	passert(backlogqueue != NULL);
	
	cn = backlogqueue;
	backlogqueue = cn->pcrc_next;
	backlogqueue_len--;
	
	r = cn->pcrc_pcr;
      
	DBG(DBG_CONTROL
	    , DBG_log("removing backlog item (%d) from queue: %d left"
		      , r->pcr_id, backlogqueue_len));

	/* w points to a work. Make sure it is live */
	if(w->pcw_pid == -1) {
	    init_crypto_helper(w, pc_worker_num);
	    if(w->pcw_pid == -1) {
		DBG(DBG_CONTROL
		    , DBG_log("found only a dead helper, and failed to restart it"));
		/* XXX invoke callback with failure */
		passert(0);
		return;
	    }
	}
	
	/* link it to the active worker list */
	cn->pcrc_next = w->pcw_cont;
	w->pcw_cont = cn;
	
	passert(w->pcw_pid != -1);
	passert(w->pcw_pipe != -1);
	passert(w->pcw_work > 0);
    
	DBG(DBG_CONTROL
	    , DBG_log("asking helper %d to do %s op on seq: %u"
		      , w->pcw_helpernum
		      , enum_show(&pluto_cryptoop_names, r->pcr_type)
		      , r->pcr_id));
	
	/* send the request, and then mark the work as having more work */
	cnt = write(w->pcw_pipe, r, r->pcr_len);
	if(cnt == -1) {
	    /* XXX invoke callback with failure */
	    passert(0);
	    return;
	} 
	
	w->pcw_work++;
    }
}

bool pluto_crypt_handle_dead_child(int pid, int status)
{
    int cnt;
    struct pluto_crypto_worker *w = pc_workers;

    for(cnt = 0; cnt < pc_workers_cnt; cnt++, w++) {
	if(w->pcw_pid == pid) {
	    w->pcw_reaped = TRUE;
	    
	    if(w->pcw_dead == TRUE) {
		cleanup_crypto_helper(w, status);
	    }
	    return TRUE;
	}
    }
    return FALSE;
}    

/*
 * look for any states attaches to continuations
 */
void delete_cryptographic_continuation(struct state *st)
{
    int i;

    for(i=0; i<pc_workers_cnt; i++) {
	struct pluto_crypto_worker *w = &pc_workers[i];
	struct pluto_crypto_req_cont *cn, **cnp;

	cn = w->pcw_cont;
	cnp = &w->pcw_cont;
	while(cn && st->st_serialno != cn->pcrc_serialno) {
	    cnp = &cn->pcrc_next;
	    cn = cn->pcrc_next;
	}
	
	if(cn == NULL) {
	    DBG(DBG_CRYPT, DBG_log("no suspended cryptographic state for %lu\n"
				   , st->st_serialno));
	    return;
	}

	/* unlink it, and free it */
	*cnp = cn->pcrc_next;
	cn->pcrc_next = NULL;
 
	if(cn->pcrc_free) {
	    /*
	     * use special free function which can deal with other
	     * saved structures.
	     */
	    (*cn->pcrc_free)(cn, cn->pcrc_pcr, "state removed");
	} else {
	    pfree(cn);
	}
    }
}
	
/*
 * this function is called when there is a helper pipe that is ready.
 * we read the request from the pipe, and find the associated continuation,
 * and dispatch to that continuation.
 *
 * this function should process only a single answer, and then go back
 * to the select call to get called again. This is not most efficient,
 * but is is most fair.
 *
 */
void handle_helper_comm(struct pluto_crypto_worker *w)
{
    char reqbuf[PCR_REQ_SIZE];
    struct pluto_crypto_req *r;
    int restlen;
    int actlen;
    struct pluto_crypto_req_cont *cn, **cnp;

    /* we can accept more work now that we are about to read from the pipe */
    w->pcw_work--;

    DBG(DBG_CRYPT, DBG_log("helper %u has work (cnt now %d)"
			   ,w->pcw_helpernum
			   ,w->pcw_work));

    /* read from the pipe */
    actlen = read(w->pcw_pipe, reqbuf, sizeof(r->pcr_len));

    if(actlen != sizeof(r->pcr_len)) {
	if(actlen != 0) {
	    loglog(RC_LOG_SERIOUS, "read failed with %d: %s"
		   , actlen, strerror(errno));
	}
	/*
	 * eof, mark worker as dead. If already reaped, then free.
	 */
	w->pcw_dead = TRUE;
	if(w->pcw_reaped) {
	    cleanup_crypto_helper(w, 0);
	}
	return;
    }

    r = (struct pluto_crypto_req *)reqbuf;

    if(r->pcr_len > sizeof(reqbuf)) {
	loglog(RC_LOG_SERIOUS, "helper(%d) pid=%d screwed up length: %lu > %lu, killing it"
	       , w->pcw_helpernum
	       , w->pcw_pid, (unsigned long)r->pcr_len
               , (unsigned long)sizeof(reqbuf));
	kill(w->pcw_pid, SIGTERM);
	w->pcw_dead = TRUE;
	return;
    }

    restlen = r->pcr_len-sizeof(r->pcr_len);
	
    /* okay, got a basic size, read the rest of it */
    if((actlen= read(w->pcw_pipe
		     , reqbuf+sizeof(r->pcr_len)
		     , restlen)) != restlen) {
	/* faulty read. die, parent will restart us */
	
	loglog(RC_LOG_SERIOUS
	       , "cryptographic handler(%d) read(%d)=%d failed: %s\n"
	       , w->pcw_pipe, restlen, actlen, strerror(errno));
	return;
    }

    DBG(DBG_CRYPT, DBG_log("helper %u replies to sequence %u"
			   ,w->pcw_helpernum
			   ,r->pcr_id));

    /*
     * if there is work queued, then send it off after reading, since this
     * avoids the most deadlocks
     */
    crypto_send_backlog(w);

    /* now match up request to continuation, and invoke it */
    cn = w->pcw_cont;
    cnp = &w->pcw_cont;
    while(cn && r->pcr_id != cn->pcrc_id) {
	cnp = &cn->pcrc_next;
	cn = cn->pcrc_next;
    }

    if(cn == NULL) {
	loglog(RC_LOG_SERIOUS
	       , "failed to find continuation associated with req %u\n",
	       (unsigned int)r->pcr_id);
	return;
    }

    /* unlink it */
    *cnp = cn->pcrc_next;
    cn->pcrc_next = NULL;
 
    passert(cn->pcrc_func != NULL);

    DBG(DBG_CRYPT, DBG_log("calling callback function %p"
			   ,cn->pcrc_func));

    /* call the continuation */
    (*cn->pcrc_func)(cn, r, NULL);

    /* now free up the continuation */
    pfree(cn);
}


/*
 * initialize a helper.
 */
static void init_crypto_helper(struct pluto_crypto_worker *w, int n)
{
    int fds[2];
    int errno2;

    /* reset this */
    w->pcw_pid = -1;

    if(socketpair(PF_UNIX, SOCK_STREAM, 0, fds) != 0) {
	loglog(RC_LOG_SERIOUS, "could not create socketpair for helpers: %s",
	       strerror(errno));
	return;
    }

    w->pcw_helpernum = n;
    w->pcw_pipe = fds[0];
    w->pcw_maxbasicwork  = 2;
    w->pcw_maxcritwork   = 4;
    w->pcw_work     = 0;
    w->pcw_reaped = FALSE;
    w->pcw_dead   = FALSE;

    /* set the send/received queue length to be at least maxcritwork
     * times sizeof(pluto_crypto_req) in size
     */
    {
	int qlen = w->pcw_maxcritwork * sizeof(struct pluto_crypto_req) + 10;
	
	if(setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF,&qlen, sizeof(qlen))==-1
	   || setsockopt(fds[0],SOL_SOCKET,SO_SNDBUF,&qlen,sizeof(qlen))==-1
	   || setsockopt(fds[1],SOL_SOCKET,SO_RCVBUF,&qlen,sizeof(qlen))==-1
	   || setsockopt(fds[1],SOL_SOCKET,SO_RCVBUF,&qlen,sizeof(qlen))==-1) {
	    loglog(RC_LOG_SERIOUS, "could not set socket queue to %d", qlen);
	    return;
	}
    }

    /* flush various descriptors so that they don't get written twice */
    fflush(stdout);
    fflush(stderr);
    close_log();
    close_peerlog();

    w->pcw_pid = fork();
    errno2 = errno;
    if(w->pcw_pid == 0) { 

	/* this is the CHILD */
	int fd;
	int maxfd;
	struct rlimit nf;
	int i;

	/* diddle with our proc title */
	memset(global_argv[0], '\0', strlen(global_argv[0])+1);
	sprintf(global_argv[0], "pluto helper %s #%3d   ", pluto_ifn_inst, n);
	for(i = 1; i < global_argc; i++) {
	    if(global_argv[i]) {
		int l = strlen(global_argv[i]);
		memset(global_argv[i], '\0', l);
	    }
	    global_argv[i]=NULL;
	}

	if(getenv("PLUTO_CRYPTO_HELPER_DEBUG")) {
	    sprintf(global_argv[0], "pluto helper %s #%3d (waiting for GDB) "
		    , pluto_ifn_inst, n);
	    sleep(60); /* for debugger to attach */
	    sprintf(global_argv[0], "pluto helper %s #%3d                   "
		    , pluto_ifn_inst, n);
	}

	if(getrlimit(RLIMIT_NOFILE, &nf) == -1) {
	    maxfd = 256;
	} else {
	    maxfd = nf.rlim_max;
	}

	/* in child process, close all non-essential fds */
	for(fd = 3; fd < maxfd; fd++) {
	    if(fd != fds[1]) close(fd);
	}
	
	pluto_init_log();
	init_rnd_pool();
	free_preshared_secrets();
	openswan_passert_fail = helper_passert_fail;
	debug_prefix='!';

	pluto_crypto_helper(fds[1], n);
	exit(0);
	/* NOTREACHED */
    }

    /* open the log files again */
    pluto_init_log();
	
    if(w->pcw_pid == -1) {
	loglog(RC_LOG_SERIOUS, "failed to start child, error = %s"
	       , strerror(errno2));
	close(fds[1]);
	close(fds[0]);
	w->pcw_dead   = TRUE;
	return;
    }

    /* PARENT */
    openswan_log("started helper pid=%d (fd:%d)", w->pcw_pid,  w->pcw_pipe);
    
    /* close client side of socket pair in parent */
    close(fds[1]);
}

/*
 * clean up after a crypto helper
 */
static void cleanup_crypto_helper(struct pluto_crypto_worker *w
				  , int status)
{
    if(w->pcw_pipe) {
	loglog(RC_LOG_SERIOUS, "closing helper(%u) pid=%d fd=%d exit=%d"
	       , w->pcw_helpernum, w->pcw_pid, w->pcw_pipe, status);
	close(w->pcw_pipe);
    }

    w->pcw_pid = -1;
    w->pcw_reaped = FALSE;
    w->pcw_dead   = FALSE;   /* marking is not dead lets it live again */
}


/*
 * initialize the helpers.
 *
 * Later we will have to make provisions for helpers that have hardware
 * underneath them, in which case, they may be able to accept many
 * more requests than average.
 *
 */
void init_crypto_helpers(int nhelpers)
{
    int i;

    pc_workers = NULL;
    pc_workers_cnt = 0;
    pcw_id = 1;

    /* find out how many CPUs there are, if nhelpers is -1 */
    /* if nhelpers == 0, then we do all the work ourselves */
    if(nhelpers == -1) {
	int ncpu_online = sysconf(_SC_NPROCESSORS_ONLN);

	if(ncpu_online > 2) {
	    nhelpers = ncpu_online - 1;
	} else {
	    /*
	     * if we have 2 CPUs or less, then create 1 helper, since
	     * we still want to deal with head-of-queue problem.
	     */
	    nhelpers = 1;
	}
    }

    if(nhelpers > 0) {
	openswan_log("starting up %d cryptographic helpers", nhelpers);
	pc_workers = alloc_bytes(sizeof(*pc_workers)*nhelpers
				 , "pluto helpers");
	pc_workers_cnt = nhelpers;
	
	for(i=0; i<nhelpers; i++) {
	    init_crypto_helper(&pc_workers[i], i);
	}
    } else {
	openswan_log("no helpers will be started, all cryptographic operations will be done inline");
    }
	
    pc_worker_num = 0;

}

void pluto_crypto_helper_sockets(fd_set *readfds)
{
    int cnt;
    struct pluto_crypto_worker *w = pc_workers;

    for(cnt = 0; cnt < pc_workers_cnt; cnt++, w++) {
	if(w->pcw_pid != -1 && !w->pcw_dead) {
	    passert(w->pcw_pipe > 0);

	    FD_SET(w->pcw_pipe, readfds);
	}
    }
}

int pluto_crypto_helper_ready(fd_set *readfds)
{
    int cnt;
    struct pluto_crypto_worker *w = pc_workers;
    int ndes;

    ndes = 0;

    for(cnt = 0; cnt < pc_workers_cnt; cnt++, w++) {
	if(w->pcw_pid != -1 && !w->pcw_dead) {
	    passert(w->pcw_pipe > 0);

	    if(FD_ISSET(w->pcw_pipe, readfds)) {
		handle_helper_comm(w);
		ndes++;
	    }
	}
    }
    
    return ndes;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
