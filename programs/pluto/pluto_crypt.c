/* 
 * Cryptographic helper function.
 * Copyright (C) 2004-2007 Michael C. Richardson <mcr@xelerance.com>
 * Copyright (C) 2004-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2006 Luis F. Ortiz <lfo@polyad.org>
 * Copyright (C) 2008-2009 David McCullough <david_mccullough@securecomputing.com>
 * Copyright (C) 2008 Anthony Tong <atong@TrustedCS.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009 Stefan Arentz <stefan@arentz.ca>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
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
 * Modifications to use OCF interface written by
 * Daniel Djamaludin <danield@cyberguard.com>
 * Copyright (C) 2004-2005 Intel Corporation.  
 *
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#if defined(macintosh) || (defined(__MACH__) && defined(__APPLE__))
#include <sys/sysctl.h>
#endif

#include <signal.h>

#include <libreswan.h>
#include <libreswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
#include "defs.h"
#include "packet.h"
#include "demux.h"
#include "lswlog.h"
#include "log.h"
#include "state.h"
#include "demux.h"
#include "rnd.h"
#include "pluto_crypt.h"

#include <nss.h>
#include "lswconf.h"
#include <pthread.h>

#include "lswcrypto.h"
#include "lsw_select.h"

TAILQ_HEAD(req_queue, pluto_crypto_req_cont);

struct pluto_crypto_worker {
    int   pcw_helpernum;
    /* pthread_t pcw_pid; */
   long int pcw_pid;
    int   pcw_pipe;
    int   pcw_helper_pipe;
    int   pcw_work;         /* how many items outstanding */
    int   pcw_maxbasicwork; /* how many basic things can be queued */
    int   pcw_maxcritwork;  /* how many critical things can be queued */
    bool  pcw_dead;         /* worker is dead, waiting for reap */
    bool  pcw_reaped;       /* worker has been reaped, waiting for dealloc */
    struct req_queue pcw_active;
};

static struct req_queue backlog;
static int       backlogqueue_len=0;

static void init_crypto_helper(struct pluto_crypto_worker *w, int n);
static void cleanup_crypto_helper(struct pluto_crypto_worker *w, int status);
static void handle_helper_comm(struct pluto_crypto_worker *w);
extern void free_preshared_secrets(void);

static void *pluto_helper_thread(void *w);

/* may be NULL if we are to do all the work ourselves */
struct pluto_crypto_worker *pc_workers = NULL;
int pc_workers_cnt = 0;
int pc_worker_num;
pcr_req_id pcw_id;

/* local in child */
int pc_helper_num=-1;

void pluto_do_crypto_op(struct pluto_crypto_req *r, int helpernum)
{
    DBG(DBG_CONTROL
	, DBG_log("helper %d doing %s op id: %u"
		  , helpernum
		  , enum_show(&pluto_cryptoop_names, r->pcr_type)
		  , r->pcr_id));
#ifdef DEBUG
    {
	char *d = getenv("PLUTO_CRYPTO_HELPER_DELAY");
	if(d != NULL) {
	    int delay=atoi(d);

	    DBG_log("helper is pausing for %d seconds", delay);
	    sleep(delay);
	}
    }
#endif

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

    case pcr_compute_dh_v2:
	calc_dh_v2(r);
	break;

    case pcr_rsa_sign:
    case pcr_rsa_check:
    case pcr_x509cert_fetch:
    case pcr_x509crl_fetch:
	break;
    }
}

void pluto_crypto_helper(int fd, int helpernum)
{
    FILE *in  = fdopen(fd, "rb");
    FILE *out = fdopen(fd, "wb");
    long reqbuf[PCR_REQ_SIZE/sizeof(long)];
    struct pluto_crypto_req *r;

    /* OS X does not have pthread_setschedprio */
#if !(defined(macintosh) || (defined(__MACH__) && defined(__APPLE__)))
    int status=pthread_setschedprio(pthread_self(), 10);
    DBG(DBG_CONTROL, DBG_log("status value returned by setting the priority of this thread (id=%d) %d",helpernum,status));
#endif

    DBG(DBG_CONTROL, DBG_log("helper %d waiting on fd: %d"
			     , helpernum, fileno(in)));

    memset(reqbuf, 0, sizeof(reqbuf));
    while(fread((char*)reqbuf, sizeof(r->pcr_len), 1, in) == 1) {
	int restlen;
	int actnum;
	unsigned char *reqrest = ((unsigned char *)reqbuf)+sizeof(r->pcr_len);

	r = (struct pluto_crypto_req *)reqbuf;
	restlen = r->pcr_len-sizeof(r->pcr_len);
	
	passert(restlen < (signed)PCR_REQ_SIZE);
	passert(restlen > 0);

	actnum = fread(reqrest, 1, restlen, in);
	/* okay, got a basic size, read the rest of it */

	DBG(DBG_CONTROL, DBG_log("helper %d read %d+4/%d bytes fd: %d"
				 , helpernum, actnum, (int)r->pcr_len, fileno(in)));

	if(actnum != restlen) {
	    /* faulty read. die, parent will restart us */

	    loglog(RC_LOG_SERIOUS, "cryptographic helper(%d) fread(%d)=%d failed: %s\n",
		   (int)pthread_self(), restlen, actnum, strerror(errno));

	   loglog(RC_LOG_SERIOUS, "pluto_crypto_helper: helper (%d) is error exiting\n",helpernum);
	    goto error; 
	}

	pluto_do_crypto_op(r,helpernum);

	actnum = fwrite((unsigned char *)r, r->pcr_len, 1, out);
	fflush(out);

	if(actnum != 1) {
	    loglog(RC_LOG_SERIOUS, "failed to write answer: %d", actnum);
	    goto error;
	}
	memset(reqbuf, 0, sizeof(reqbuf));
    }

    if(!feof(in)) {
	loglog(RC_LOG_SERIOUS, "helper %d got error: %s", helpernum, strerror(ferror(in)));
        goto error;
    }

    /* probably normal EOF */
    loglog(RC_LOG_SERIOUS, "pluto_crypto_helper: helper (%d) is  normal exiting\n",helpernum);

error:
    fclose(in);
    fclose(out);
    /*pthread_exit();*/
}


/* send the request, make sure it all goes down. */
static bool crypto_write_request(struct pluto_crypto_worker *w
				 ,struct pluto_crypto_req *r)
{
    unsigned char *wdat = (unsigned char *)r;
    int wlen = r->pcr_len;
    int cnt;
    
    DBG(DBG_CONTROL
	, DBG_log("asking helper %d to do %s op on seq: %u (len=%u, pcw_work=%d)"
		  , w->pcw_helpernum
		  , enum_show(&pluto_cryptoop_names, r->pcr_type)
		  , r->pcr_id, (unsigned int)r->pcr_len, w->pcw_work+1));

    do {
	errno=0;
	cnt = write(w->pcw_pipe, wdat, wlen);
	
	if(cnt <= 0) {
	    libreswan_log("write to helper failed: cnt=%d err=%s\n",
			 cnt, strerror(errno));
	    return FALSE;
	}
	if(DBGP(DBG_CONTROL) || cnt != wlen) {
	    DBG_log("crypto helper write of request: cnt=%d<wlen=%d. \n", cnt, wlen);
	}

	wlen -= cnt;
	wdat += cnt;

    } while(wlen > 0);

    return TRUE;
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

	pluto_do_crypto_op(r,pc_helper_num);
	/* call the continuation */
	(*cn->pcrc_func)(cn, r, NULL);

	/* indicate that we did everything ourselves */
	*toomuch = TRUE;

	pfree(cn);
	return NULL;
    }

    /* set up the id */
    r->pcr_id = pcw_id++;
    cn->pcrc_id = r->pcr_id;
    cn->pcrc_pcr = r;

    /* find an available worker */
    cnt = pc_workers_cnt;
    do {
	pc_worker_num++;
 	if(pc_worker_num >= pc_workers_cnt) {
 	    pc_worker_num = 0;
 	}
	w = &pc_workers[pc_worker_num];

 	DBG(DBG_CONTROL
 	    , DBG_log("%d: w->pcw_dead: %d w->pcw_work: %d cnt: %d",
 		      pc_worker_num, w->pcw_dead, w->pcw_work, cnt));

	/* see if there is something to clean up after */
	if(w->pcw_dead      == TRUE
	   && w->pcw_reaped == TRUE) {
	    cleanup_crypto_helper(w, 0);
 	    DBG(DBG_CONTROL
 		, DBG_log("clnup %d: w->pcw_dead: %d w->pcw_work: %d cnt: %d",
 			  pc_worker_num, w->pcw_dead, w->pcw_work, cnt));
	}
    } while(((w->pcw_work >= w->pcw_maxbasicwork))
 	    && --cnt > 0);

    if(cnt == 0 && r->pcr_pcim > pcim_ongoing_crypto) {
	cnt = pc_workers_cnt;
 	while((w->pcw_work >= w->pcw_maxcritwork)
	      && --cnt > 0) {
	
 	    /* find an available worker */
	    pc_worker_num++;
 	    if(pc_worker_num >= pc_workers_cnt) {
 		pc_worker_num = 0;
  	    }

	    w = &pc_workers[pc_worker_num];
	    /* see if there is something to clean up after */
	    if(w->pcw_dead      == TRUE
	       && w->pcw_reaped == TRUE) {
		cleanup_crypto_helper(w, 0);
	    }
	}
	DBG(DBG_CONTROL
	    , DBG_log("crit %d: w->pcw_dead: %d w->pcw_work: %d cnt: %d",
		      pc_worker_num, w->pcw_dead, w->pcw_work, cnt));
    }

    if(cnt == 0 && r->pcr_pcim >= pcim_demand_crypto) {
	/* it is very important. Put it all on a queue for later */
	
	TAILQ_INSERT_TAIL(&backlog, cn, pcrc_list);

	/* copy the request */
	r = clone_bytes(r, r->pcr_len, "saved cryptorequest");
	cn->pcrc_pcr = r;

	cn->pcrc_reply_stream = reply_stream;
	if (pbs_offset(&reply_stream)) {
	    cn->pcrc_reply_buffer = clone_bytes(reply_stream.start
		    , pbs_offset(&reply_stream), "saved reply buffer");
	}
	
	backlogqueue_len++;
	DBG(DBG_CONTROL
	    , DBG_log("critical demand crypto operation queued on backlog as %d'th item, id: q#%u"
		      , backlogqueue_len, r->pcr_id));
	*toomuch = FALSE;
	return NULL;
    }

    if(cnt == 0) {
	/* didn't find any workers */
	DBG(DBG_CONTROL
	    , DBG_log("failed to find any available worker (import=%s)"
		      , enum_name(&pluto_cryptoimportance_names,r->pcr_pcim)));

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
    TAILQ_INSERT_TAIL(&w->pcw_active, cn, pcrc_list);

    passert(w->pcw_pid != -1);
    passert(w->pcw_pipe != -1);
    passert(w->pcw_work < w->pcw_maxcritwork);

    cn->pcrc_reply_stream = reply_stream;
    if (pbs_offset(&reply_stream))
	cn->pcrc_reply_buffer = clone_bytes(reply_stream.start
		, pbs_offset(&reply_stream), "saved reply buffer");
    
    if(!crypto_write_request(w, r)) {
	libreswan_log("failed to write crypto request: %s\n",
		     strerror(errno));
	if (pbs_offset(&cn->pcrc_reply_stream))
	    pfree(cn->pcrc_reply_buffer);
	cn->pcrc_reply_buffer = NULL;
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

	passert(backlog.tqh_first != NULL);
	cn = backlog.tqh_first;
	TAILQ_REMOVE(&backlog, cn, pcrc_list);
	
	backlogqueue_len--;
	
	r = cn->pcrc_pcr;
      
	DBG(DBG_CONTROL
	    , DBG_log("removing backlog item id: q#%u from queue: %d left"
		      , r->pcr_id, backlogqueue_len));

	/* w points to a worker. Make sure it is live */
	if(w->pcw_pid == -1) {
	    init_crypto_helper(w, pc_worker_num);
	    if(w->pcw_pid == -1) {
		DBG(DBG_CONTROL
		    , DBG_log("found only a dead helper, and failed to restart it"));
		/* XXX invoke callback with failure */
		passert(0);
		if (pbs_offset(&cn->pcrc_reply_stream))
		    pfree(cn->pcrc_reply_buffer);
		cn->pcrc_reply_buffer = NULL;
		return;
	    }
	}
	
	/* link it to the active worker list */
	TAILQ_INSERT_TAIL(&w->pcw_active, cn, pcrc_list);
	
	passert(w->pcw_pid != -1);
	passert(w->pcw_pipe != -1);
	passert(w->pcw_work > 0);
    
	/* send the request, and then mark the worker as having more work */
	if(!crypto_write_request(w, r)) {
	    /* XXX invoke callback with failure */
	    passert(0);
	    if (pbs_offset(&cn->pcrc_reply_stream))
		pfree(cn->pcrc_reply_buffer);
	    cn->pcrc_reply_buffer = NULL;
	    return;
	} 

	/* if it was on the backlog, it was saved, free it */
	pfree(r);
	cn->pcrc_pcr = NULL;
	
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
 * also check the backlog
 */
void delete_cryptographic_continuation(struct state *st)
{
    int i;

    if(backlogqueue_len > 0) {
	struct pluto_crypto_req_cont *cn;
	struct pluto_crypto_req *r;

	passert(backlog.tqh_first != NULL);

	for(cn = backlog.tqh_first;
	    cn!=NULL && st->st_serialno != cn->pcrc_serialno;
	    cn = cn->pcrc_list.tqe_next);
		
	if(cn != NULL) {
	    TAILQ_REMOVE(&backlog, cn, pcrc_list);
	    backlogqueue_len--;
	    r = cn->pcrc_pcr;
	    DBG(DBG_CONTROL
		, DBG_log("removing deleted backlog item id: q#%u from queue: %d left"
			  , r->pcr_id, backlogqueue_len));
	    /* if it was on the backlog, it was saved, free it */
	    pfree(r);
	    cn->pcrc_pcr = NULL;
	    if (pbs_offset(&cn->pcrc_reply_stream))
		pfree(cn->pcrc_reply_buffer);
	    cn->pcrc_reply_buffer = NULL;
	}
    }

    for(i=0; i<pc_workers_cnt; i++) {
	struct pluto_crypto_worker *w = &pc_workers[i];
	struct pluto_crypto_req_cont *cn;

	for(cn = w->pcw_active.tqh_first;
	    cn!=NULL && st->st_serialno != cn->pcrc_serialno;
	    cn = cn->pcrc_list.tqe_next);
		
	if(cn == NULL) {
	    continue;
	}

	/* unlink it, and free it */
	TAILQ_REMOVE(&w->pcw_active, cn, pcrc_list);
	if (pbs_offset(&cn->pcrc_reply_stream))
	    pfree(cn->pcrc_reply_buffer);
	cn->pcrc_reply_buffer = NULL;
 
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
    DBG(DBG_CRYPT, DBG_log("no suspended cryptographic state for %lu\n"
				   , st->st_serialno));
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
    struct pluto_crypto_req reqbuf[2];
    unsigned char *inloc;
    struct pluto_crypto_req *r;
    int restlen;
    int actlen;
    struct pluto_crypto_req_cont *cn;

    DBG(DBG_CRYPT|DBG_CONTROL
	, DBG_log("helper %u has finished work (cnt now %d)"
		  ,w->pcw_helpernum
		  ,w->pcw_work));

    /* read from the pipe */
    memset(reqbuf, 0, sizeof(reqbuf));
    actlen = read(w->pcw_pipe, (char *)reqbuf, sizeof(r->pcr_len));

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

    /* we can accept more work now that we have read from the pipe */
    w->pcw_work--;

    r = &reqbuf[0];

    if(r->pcr_len > sizeof(reqbuf)) {
	loglog(RC_LOG_SERIOUS, "helper(%d) pid=%lu screwed up length: %lu > %lu, killing it"
	       , w->pcw_helpernum
	       , w->pcw_pid, (unsigned long)r->pcr_len
               , (unsigned long)sizeof(reqbuf));
    killit:
	pthread_cancel((pthread_t)w->pcw_pid);
	w->pcw_dead = TRUE;
	return;
    }

    restlen = r->pcr_len-sizeof(r->pcr_len);
    inloc = ((unsigned char*)reqbuf)+sizeof(r->pcr_len);

    while(restlen > 0) {
	/* okay, got a basic size, read the rest of it */
	actlen = read(w->pcw_pipe, inloc, restlen);

	if(actlen <= 0) {
	    /* faulty read. note this fact, and close pipe. */
	    /* we actually need to restart this query, but we'll do that
	     * another day.
	     */
	    loglog(RC_LOG_SERIOUS
		   , "cryptographic handler(%d) read(%d)=%d failed: %s\n"
		   , w->pcw_pipe, restlen, actlen, strerror(errno));
	    goto killit;
	}

	restlen -= actlen;
	inloc   += actlen;
    }

    DBG(DBG_CRYPT|DBG_CONTROL, DBG_log("helper %u replies to id: q#%u"
				       ,w->pcw_helpernum
				       ,r->pcr_id));

    /*
     * if there is work queued, then send it off after reading, since this
     * avoids the most deadlocks
     */
    crypto_send_backlog(w);

    /* now match up request to continuation, and invoke it */
    for(cn = w->pcw_active.tqh_first;
	cn!=NULL && r->pcr_id != cn->pcrc_id;
	cn = cn->pcrc_list.tqe_next);
		
    if(cn == NULL) {
	loglog(RC_LOG_SERIOUS
	       , "failed to find continuation associated with req %u\n",
	       (unsigned int)r->pcr_id);
	return;
    }

    /* unlink it */
    TAILQ_REMOVE(&w->pcw_active, cn, pcrc_list);
 
    passert(cn->pcrc_func != NULL);

    DBG(DBG_CRYPT, DBG_log("calling callback function %p"
			   ,cn->pcrc_func));

    reply_stream = cn->pcrc_reply_stream;
    if (pbs_offset(&reply_stream)) {
	memcpy(reply_stream.start, cn->pcrc_reply_buffer
		, pbs_offset(&reply_stream));
	pfree(cn->pcrc_reply_buffer);
    }
    cn->pcrc_reply_buffer = NULL;

    /* call the continuation */
    cn->pcrc_pcr = r;
    reset_cur_state();
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

    /* reset this */
    w->pcw_pid = -1;

    if(socketpair(PF_UNIX, SOCK_STREAM, 0, fds) != 0) {
	loglog(RC_LOG_SERIOUS, "could not create socketpair for helpers: %s",
	       strerror(errno));
	return;
    }

    w->pcw_helpernum = n;
    w->pcw_pipe = fds[0];
    w->pcw_helper_pipe = fds[1];
    w->pcw_maxbasicwork  = 2;
    w->pcw_maxcritwork   = 4;
    w->pcw_work     = 0;
    w->pcw_reaped = FALSE;
    w->pcw_dead   = FALSE;
    TAILQ_INIT(&w->pcw_active);

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

    /* set local so that child inheirits it */
    pc_helper_num = n;

    int thread_status;

    thread_status = pthread_create((pthread_t*)&w->pcw_pid, NULL, pluto_helper_thread, (void*)w);
    if(thread_status!=0) {
	loglog(RC_LOG_SERIOUS, "failed to start child, error = %d" , thread_status);
	w->pcw_pid= -1;
	close(fds[1]);
	close(fds[0]);
	w->pcw_dead   = TRUE;
	return;  
    }
    else{
	libreswan_log("started helper (thread) pid=%ld (fd:%d)", w->pcw_pid,  w->pcw_pipe);
    }
}

void *
pluto_helper_thread(void *w) {
    struct pluto_crypto_worker *helper;
    helper=(struct pluto_crypto_worker *)w;
    pluto_crypto_helper(helper->pcw_helper_pipe, helper->pcw_helpernum);
    return NULL;
}

/*
 * clean up after a crypto helper
 */
static void cleanup_crypto_helper(struct pluto_crypto_worker *w
				  , int status)
{
    if(w->pcw_pipe) {
	loglog(RC_LOG_SERIOUS, "closing helper(%u) pid=%lu fd=%d exit=%d"
	       , w->pcw_helpernum, w->pcw_pid, w->pcw_pipe, status);
	close(w->pcw_pipe);
    }

    w->pcw_pid = -1;
    w->pcw_work = 0; /* ?!? */
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

    TAILQ_INIT(&backlog);

    /* find out how many CPUs there are, if nhelpers is -1 */
    /* if nhelpers == 0, then we do all the work ourselves */
    if(nhelpers == -1) {
	int ncpu_online;
#if !(defined(macintosh) || (defined(__MACH__) && defined(__APPLE__)))
      ncpu_online = sysconf(_SC_NPROCESSORS_ONLN);
#else
      int mib[2], numcpu;
           size_t len;

           mib[0] = CTL_HW;
           mib[1] = HW_NCPU;
           len = sizeof(numcpu);
           ncpu_online = sysctl(mib, 2, &numcpu, &len, NULL, 0);
#endif

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
	libreswan_log("starting up %d cryptographic helpers", nhelpers);
	pc_workers = alloc_bytes(sizeof(*pc_workers)*nhelpers
				 , "pluto helpers");
	pc_workers_cnt = nhelpers;
	
	for(i=0; i<nhelpers; i++) {
	    init_crypto_helper(&pc_workers[i], i);
	}
    } else {
	libreswan_log("no helpers will be started, all cryptographic operations will be done inline");
    }
	
    pc_worker_num = 0;

}

void pluto_crypto_helper_sockets(lsw_fd_set *readfds)
{
    int cnt;
    struct pluto_crypto_worker *w = pc_workers;

    for(cnt = 0; cnt < pc_workers_cnt; cnt++, w++) {
	if(w->pcw_pid != -1 && !w->pcw_dead) {
	    passert(w->pcw_pipe > 0);

	    LSW_FD_SET(w->pcw_pipe, readfds);
	}
    }
}

int pluto_crypto_helper_ready(lsw_fd_set *readfds)
{
    int cnt;
    struct pluto_crypto_worker *w = pc_workers;
    int ndes;

    ndes = 0;

    for(cnt = 0; cnt < pc_workers_cnt; cnt++, w++) {
	if(w->pcw_pid != -1 && !w->pcw_dead) {
	    passert(w->pcw_pipe > 0);

	    if(LSW_FD_ISSET(w->pcw_pipe, readfds)) {
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
