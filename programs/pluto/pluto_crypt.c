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
 * Copyright (C) 2012-2013 Paul Wouters <paul@libreswan.org>
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

#include <pthread.h>    /* Must be the first include file */

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
#include "enum_names.h"
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

#include "lswcrypto.h"
#include "lsw_select.h"

TAILQ_HEAD(req_queue, pluto_crypto_req_cont);

/* Note: this per-helper struct is never modified in a helper thread */
struct pluto_crypto_worker {
	int pcw_helpernum;
	/* pthread_t pcw_pid; */
	/* ??? Note: the declaration and use of pcw_pid very much violates POSIX pthreads.
	 * pthread_t is an opaque type with few legitimate operations on it.
	 */
	long int pcw_pid;

	/* socket pair's file descriptors
	 * Each socket is bidirectional and they are cross-connected.
	 */
	int pcw_master_fd;	/* master's fd */
	int pcw_helper_fd;	/* helper's fd */

	int pcw_work;           /* how many items outstanding */
	int pcw_maxbasicwork;   /* how many basic things can be queued */
	int pcw_maxcritwork;    /* how many critical things can be queued */
	bool pcw_dead;          /* worker is dead, waiting for reap */
	bool pcw_reaped;        /* worker has been reaped, waiting for dealloc */
	struct req_queue pcw_active;
};

static struct req_queue backlog;
static int backlogqueue_len = 0;

static void init_crypto_helper(struct pluto_crypto_worker *w, int n);
static void cleanup_crypto_helper(struct pluto_crypto_worker *w, int status);

static void *pluto_helper_thread(void *w);	/* forward */

/* may be NULL if we are to do all the work ourselves */
static struct pluto_crypto_worker *pc_workers = NULL;

static int pc_workers_cnt = 0;	/* number of workers threads */
static int pc_worker_num;	/* index of last worker assigned work */
static pcr_req_id pcw_id;	/* counter for generating unique request IDs */

/* local in child
 * ??? in what way?  Looks global to all threads to me.
 */
static int pc_helper_num = -1;

/* pluto crypto operations */
static const char *const pluto_cryptoop_strings[] = {
	"build_kenonce",	/* calculate g^i and nonce */
	"build_nonce",	/* just fetch a new nonce */
	"compute dh+iv",	/* (g^x)(g^y) and skeyids for Phase 1 DH + prf */
	"compute dh(p2)",	/* perform (g^x)(g^y) for Phase 2 PFS */
	"compute dh(v2)",	/* perform IKEv2 PARENT SA calculation, create SKEYSEED */
};

static enum_names pluto_cryptoop_names =
	{ pcr_build_kenonce, pcr_compute_dh_v2, pluto_cryptoop_strings, NULL };

/* initializers for pluto_crypto_request continuations */

static void pcr_init(struct pluto_crypto_req *r,
			    enum pluto_crypto_requests pcr_type,
			    enum crypto_importance pcr_pcim)
{
	zero(r);
	r->pcr_len  = sizeof(struct pluto_crypto_req);
	r->pcr_type = pcr_type;
	r->pcr_pcim = pcr_pcim;
}


void pcr_nonce_init(struct pluto_crypto_req *r,
			    enum pluto_crypto_requests pcr_type,
			    enum crypto_importance pcr_pcim)
{
	pcr_init(r, pcr_type, pcr_pcim);

	INIT_WIRE_ARENA(r->pcr_d.kn);
}

void pcr_dh_init(struct pluto_crypto_req *r,
			enum pluto_crypto_requests pcr_type,
			enum crypto_importance pcr_pcim)
{
	pcr_init(r, pcr_type, pcr_pcim);

	INIT_WIRE_ARENA(r->pcr_d.dhq);
}

/* If there are any helper threads, this code is always executed IN A HELPER THREAD.
 * Otherwise it is executed in the main (only) thread.
 */
static void pluto_do_crypto_op(struct pluto_crypto_req *r, int helpernum)
{
	DBG(DBG_CONTROL,
	    DBG_log("helper %d doing %s op id: %u",
		    helpernum,
		    enum_show(&pluto_cryptoop_names, r->pcr_type),
		    r->pcr_id));
	{
		char *d = getenv("PLUTO_CRYPTO_HELPER_DELAY");
		if (d != NULL) {
			int delay = atoi(d);

			DBG_log("helper is pausing for %d seconds", delay);
			sleep(delay);
		}
	}

	/* now we have the entire request in the buffer, process it */
	switch (r->pcr_type) {
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
	}
}

/* IN A HELPER THREAD */
static void pluto_crypto_helper(int helper_fd, int helpernum)
{
	FILE *in = fdopen(helper_fd, "rb");
	FILE *out = fdopen(helper_fd, "wb");
	struct pluto_crypto_req req;

	/* OS X does not have pthread_setschedprio */
#if !(defined(macintosh) || (defined(__MACH__) && defined(__APPLE__)))
	int status = pthread_setschedprio(pthread_self(), 10);

	DBG(DBG_CONTROL,
	    DBG_log("status value returned by setting the priority of this thread (id=%d) %d",
		    helpernum, status));
#endif

	DBG(DBG_CONTROL, DBG_log("helper %d waiting on fd: %d",
				 helpernum, fileno(in)));

	passert(offsetof(struct pluto_crypto_req, pcr_len) == 0);

	for (;;) {
		size_t sz;

		zero(&req);

		errno = 0;
		sz = fread(&req, sizeof(char), sizeof(req), in);

		if (sz == 0 && feof(in)) {
			loglog(RC_LOG_SERIOUS,
			       "pluto_crypto_helper: helper %d normal exit (EOF)\n",
			       helpernum);
			break;
		} else if (sz != sizeof(req)) {
			if (ferror(in) != 0) {
				/* ??? is strerror(ferror(in)) correct? */
				char errbuf[100];	/* ??? how big is big enough? */

				strerror_r(errno, errbuf, sizeof(errbuf));
				loglog(RC_LOG_SERIOUS,
				       "pluto_crypto_helper: helper %d got read error: %s\n",
				       helpernum, errbuf);
			} else {
				/* short read -- fatal */
				loglog(RC_LOG_SERIOUS,
				       "pluto_crypto_helper: helper %d got a short read error: %zu instead of %zu\n",
				       helpernum, sz, sizeof(req));
			}
			break;
		}

		passert(req.pcr_len == sizeof(req));

		DBG(DBG_CONTROL, DBG_log("helper %d read fd: %d",
					 helpernum,
					 fileno(in)));

		pluto_do_crypto_op(&req, helpernum);

		passert(req.pcr_len == sizeof(req));

		errno = 0;
		sz = fwrite(&req, sizeof(char), sizeof(req), out);
		fflush(out);

		if (sz != sizeof(req)) {
			if (ferror(out) != 0) {
				/* ??? is strerror(ferror(out)) correct? */
				char errbuf[100];	/* ??? how big is big enough? */

				strerror_r(errno, errbuf, sizeof(errbuf));
				loglog(RC_LOG_SERIOUS,
				       "helper %d failed to write answer: %s",
				       helpernum, errbuf);
			} else {
				/* short write -- fatal */
				loglog(RC_LOG_SERIOUS,
				       "pluto_crypto_helper error: helper %d write truncated: %zu instead of %zu\n",
				       helpernum, sz, sizeof(req));
			}
			break;
		}
	}

	/* We have no way to report this thread's success or failure. */

	fclose(in);
	fclose(out);
	/*pthread_exit();*/
}

/* send the request, make sure it all goes down. */
static bool crypto_write_request(struct pluto_crypto_worker *w,
				 const struct pluto_crypto_req *r)
{
	const unsigned char *wdat = (unsigned char *)r;
	size_t wlen = r->pcr_len;

	passert(wlen == sizeof(*r));

	DBG(DBG_CONTROL,
	    DBG_log("asking helper %d to do %s op on seq: %u (len=%zu, pcw_work=%d)",
		    w->pcw_helpernum,
		    enum_show(&pluto_cryptoop_names, r->pcr_type),
		    r->pcr_id, r->pcr_len, w->pcw_work + 1));

	while (wlen > 0) {
		ssize_t cnt = write(w->pcw_master_fd, wdat, wlen);

		if (cnt < 0) {
			libreswan_log(
				"write to crypto helper %d failed: cnt=%d err=%s",
				w->pcw_helpernum, (int)cnt, strerror(errno));
			return FALSE;
		}

		if (cnt == 0) {
			/* Not clear why this would happen.  Socket full? */
			libreswan_log(
				"write to crypto helper %d failed to write any bytes",
				w->pcw_helpernum);
			return FALSE;
		}

		if ((size_t)cnt != wlen) {
			libreswan_log("short write to crypto helper %d (%zu of %zu bytes); will continue",
				w->pcw_helpernum, (size_t)cnt, wlen);
		}

		DBG(DBG_CONTROL,
			DBG_log("crypto helper write of request: cnt=%zu wlen=%zu",
				(size_t)cnt, wlen));

		wlen -= cnt;
		wdat += cnt;
	}

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
err_t send_crypto_helper_request(struct pluto_crypto_req *r,
				 struct pluto_crypto_req_cont *cn,
				 bool *toomuch)
{
	struct pluto_crypto_worker *w;
	int cnt;

	/* do it all ourselves? */
	if (pc_workers == NULL) {
		reset_cur_state();

		pluto_do_crypto_op(r, pc_helper_num);
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
		if (pc_worker_num >= pc_workers_cnt)
			pc_worker_num = 0;
		w = &pc_workers[pc_worker_num];

		DBG(DBG_CONTROL,
		    DBG_log("%d: w->pcw_dead: %d w->pcw_work: %d cnt: %d",
			    pc_worker_num, w->pcw_dead, w->pcw_work, cnt));

		/* see if there is something to clean up after */
		if (w->pcw_dead && w->pcw_reaped) {
			cleanup_crypto_helper(w, 0);
			DBG(DBG_CONTROL,
			    DBG_log("clnup %d: w->pcw_dead: %d w->pcw_work: %d cnt: %d",
				    pc_worker_num, w->pcw_dead, w->pcw_work,
				    cnt));
		}
	} while (((w->pcw_work >= w->pcw_maxbasicwork)) &&
		 --cnt > 0);

	if (cnt == 0 && r->pcr_pcim > pcim_ongoing_crypto) {
		cnt = pc_workers_cnt;
		while ((w->pcw_work >= w->pcw_maxcritwork) &&
		       --cnt > 0) {

			/* find an available worker */
			pc_worker_num++;
			if (pc_worker_num >= pc_workers_cnt)
				pc_worker_num = 0;

			w = &pc_workers[pc_worker_num];
			/* see if there is something to clean up after */
			if (w->pcw_dead && w->pcw_reaped)
				cleanup_crypto_helper(w, 0);
		}
		DBG(DBG_CONTROL,
		    DBG_log("crit %d: w->pcw_dead: %d w->pcw_work: %d cnt: %d",
			    pc_worker_num, w->pcw_dead, w->pcw_work, cnt));
	}

	if (cnt == 0 && r->pcr_pcim >= pcim_demand_crypto) {
		/* it is very important. Put it all on a queue for later */

		TAILQ_INSERT_TAIL(&backlog, cn, pcrc_list);

		/* copy the request */
		r = clone_bytes(r, r->pcr_len, "saved cryptorequest");
		cn->pcrc_pcr = r;

		cn->pcrc_reply_stream = reply_stream;
		if (pbs_offset(&reply_stream)) {
			cn->pcrc_reply_buffer = clone_bytes(reply_stream.start,
							    pbs_offset(&
								       reply_stream),
							    "saved reply buffer");
		}

		backlogqueue_len++;
		DBG(DBG_CONTROL,
		    DBG_log("critical demand crypto operation queued on backlog as %d'th item, id: q#%u",
			    backlogqueue_len, r->pcr_id));
		*toomuch = FALSE;
		return NULL;
	}

	if (cnt == 0) {
		/* didn't find any workers */
		DBG(DBG_CONTROL,
		    DBG_log("failed to find any available worker (import=%s)",
			    enum_name(&pluto_cryptoimportance_names,
				      r->pcr_pcim)));

		*toomuch = TRUE;
		return "failed to find any available worker";
	}

	/* w points to a worker. Make sure it is live */
	if (w->pcw_pid == -1) {
		init_crypto_helper(w, pc_worker_num);
		if (w->pcw_pid == -1) {
			DBG(DBG_CONTROL,
			    DBG_log("found only a dead helper, and failed to restart it"));
			*toomuch = TRUE;
			return "failed to start a new helper";
		}
	}

	/* link it to the active worker list */
	TAILQ_INSERT_TAIL(&w->pcw_active, cn, pcrc_list);

	passert(w->pcw_pid != -1);
	passert(w->pcw_master_fd != -1);
	passert(w->pcw_work < w->pcw_maxcritwork);

	cn->pcrc_reply_stream = reply_stream;
	if (pbs_offset(&reply_stream)) {
		cn->pcrc_reply_buffer = clone_bytes(reply_stream.start,
						    pbs_offset(
							    &reply_stream),
						    "saved reply buffer");
	}

	if (!crypto_write_request(w, r)) {
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

	if (backlogqueue_len > 0) {

		passert(backlog.tqh_first != NULL);
		cn = backlog.tqh_first;
		TAILQ_REMOVE(&backlog, cn, pcrc_list);

		backlogqueue_len--;

		r = cn->pcrc_pcr;

		DBG(DBG_CONTROL,
		    DBG_log("removing backlog item id: q#%u from queue: %d left",
			    r->pcr_id, backlogqueue_len));

		/* w points to a worker. Make sure it is live */
		if (w->pcw_pid == -1) {
			init_crypto_helper(w, pc_worker_num);
			if (w->pcw_pid == -1) {
				DBG(DBG_CONTROL,
				    DBG_log("found only a dead helper, and failed to restart it"));
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
		passert(w->pcw_master_fd != -1);
		passert(w->pcw_work > 0);

		/* send the request, and then mark the worker as having more work */
		if (!crypto_write_request(w, r)) {
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

/*
 * look for any states attaches to continuations
 * also check the backlog
 */
void delete_cryptographic_continuation(struct state *st)
{
	int i;

	if (backlogqueue_len > 0) {
		struct pluto_crypto_req_cont *cn;
		struct pluto_crypto_req *r;

		passert(backlog.tqh_first != NULL);

		for (cn = backlog.tqh_first;
		     cn != NULL && st->st_serialno != cn->pcrc_serialno;
		     cn = cn->pcrc_list.tqe_next) ;

		if (cn != NULL) {
			TAILQ_REMOVE(&backlog, cn, pcrc_list);
			backlogqueue_len--;
			r = cn->pcrc_pcr;
			DBG(DBG_CONTROL,
			    DBG_log("removing deleted backlog item id: q#%u from queue: %d left",
				    r->pcr_id, backlogqueue_len));
			/* if it was on the backlog, it was saved, free it */
			pfree(r);
			cn->pcrc_pcr = NULL;
			if (pbs_offset(&cn->pcrc_reply_stream))
				pfree(cn->pcrc_reply_buffer);
			cn->pcrc_reply_buffer = NULL;
		}
	}

	for (i = 0; i < pc_workers_cnt; i++) {
		struct pluto_crypto_worker *w = &pc_workers[i];
		struct pluto_crypto_req_cont *cn;

		for (cn = w->pcw_active.tqh_first;
		     cn != NULL && st->st_serialno != cn->pcrc_serialno;
		     cn = cn->pcrc_list.tqe_next) ;

		if (cn == NULL)
			continue;

		/* unlink it, and free it */
		TAILQ_REMOVE(&w->pcw_active, cn, pcrc_list);
		if (pbs_offset(&cn->pcrc_reply_stream))
			pfree(cn->pcrc_reply_buffer);
		cn->pcrc_reply_buffer = NULL;

		pfree(cn);
	}
	DBG(DBG_CRYPT, DBG_log("no suspended cryptographic state remains for #%lu\n",
			       st->st_serialno));
}

static void kill_helper(struct pluto_crypto_worker *w)
{
	pthread_cancel((pthread_t)w->pcw_pid);
	w->pcw_dead = TRUE;
}

/*
 * This function is called when there is socket input from a helper.
 * This is the answer from the helper.
 * We read the request from the socket, and find the associated continuation,
 * and dispatch to that continuation.
 *
 * This function should process only a single answer, and then go back
 * to the select call to get called again. This is not most efficient,
 * but is is most fair.
 *
 */
static void handle_helper_answer(struct pluto_crypto_worker *w)
{
	struct pluto_crypto_req reqbuf[2];
	unsigned char *inloc;
	struct pluto_crypto_req *r;
	int restlen;
	int actlen;
	struct pluto_crypto_req_cont *cn;

	DBG(DBG_CRYPT | DBG_CONTROL,
	    DBG_log("helper %u has finished work (cnt now %d)",
		    w->pcw_helpernum,
		    w->pcw_work));

	/* read from the pipe */
	zero(&reqbuf);
	actlen = read(w->pcw_master_fd, (char *)reqbuf, sizeof(r->pcr_len));

	if (actlen != sizeof(r->pcr_len)) {
		if (actlen != 0) {
			loglog(RC_LOG_SERIOUS, "read failed with %d: %s",
			       actlen, strerror(errno));
		}
		/*
		 * eof, mark worker as dead. If already reaped, then free.
		 */
		w->pcw_dead = TRUE;
		if (w->pcw_reaped)
			cleanup_crypto_helper(w, 0);
		return;
	}

	/* we can accept more work now that we have read from the pipe */
	w->pcw_work--;

	r = &reqbuf[0];

	if (r->pcr_len > sizeof(reqbuf)) {
		loglog(RC_LOG_SERIOUS,
		       "helper(%d) pid=%lu screwed up length: %lu > %lu, killing it",
		       w->pcw_helpernum,
		       w->pcw_pid, (unsigned long)r->pcr_len,
		       (unsigned long)sizeof(reqbuf));
		kill_helper(w);
		return;
	}

	restlen = r->pcr_len - sizeof(r->pcr_len);
	inloc = ((unsigned char*)reqbuf) + sizeof(r->pcr_len);

	while (restlen > 0) {
		/* okay, got a basic size, read the rest of it */
		actlen = read(w->pcw_master_fd, inloc, restlen);

		if (actlen <= 0) {
			/* faulty read. note this fact, and close pipe. */
			/* we actually need to restart this query, but we'll do that
			 * another day.
			 */
			loglog(RC_LOG_SERIOUS,
			       "cryptographic handler(%d) read(%d)=%d failed: %s\n",
			       w->pcw_master_fd, restlen, actlen, strerror(errno));
			kill_helper(w);
			return;
		}

		restlen -= actlen;
		inloc   += actlen;
	}

	DBG(DBG_CRYPT | DBG_CONTROL, DBG_log("helper %u replies to id: q#%u",
					     w->pcw_helpernum,
					     r->pcr_id));

	/*
	 * if there is work queued, then send it off after reading, since this
	 * avoids the most deadlocks
	 */
	crypto_send_backlog(w);

	/* now match up request to continuation, and invoke it */
	for (cn = w->pcw_active.tqh_first;
	     cn != NULL && r->pcr_id != cn->pcrc_id;
	     cn = cn->pcrc_list.tqe_next) ;

	if (cn == NULL) {
		loglog(RC_LOG_SERIOUS,
		       "failed to find continuation associated with req %u\n",
		       (unsigned int)r->pcr_id);
		return;
	}

	/* unlink it */
	TAILQ_REMOVE(&w->pcw_active, cn, pcrc_list);

	passert(cn->pcrc_func != NULL);

	DBG(DBG_CRYPT, DBG_log("calling callback function %p",
			       cn->pcrc_func));

	reply_stream = cn->pcrc_reply_stream;
	if (pbs_offset(&reply_stream)) {
		memcpy(reply_stream.start, cn->pcrc_reply_buffer,
		       pbs_offset(&reply_stream));
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
	int thread_status;

	/* reset this */
	w->pcw_pid = -1;

	if (socketpair(PF_UNIX, SOCK_STREAM, 0, fds) != 0) {
		loglog(RC_LOG_SERIOUS,
		       "could not create socketpair for helpers: %s",
		       strerror(errno));
		return;
	}

	w->pcw_helpernum = n;
	w->pcw_master_fd = fds[0];
	w->pcw_helper_fd = fds[1];
	w->pcw_maxbasicwork = 2;
	w->pcw_maxcritwork = 4;
	w->pcw_work = 0;
	w->pcw_reaped = FALSE;
	w->pcw_dead = FALSE;
	TAILQ_INIT(&w->pcw_active);

	/* set the send/received queue length to be at least maxcritwork
	 * times sizeof(pluto_crypto_req) in size
	 */
	{
		int qlen = w->pcw_maxcritwork *
			   sizeof(struct pluto_crypto_req);

		if (setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &qlen,
			       sizeof(qlen)) == -1 ||
		    setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, &qlen,
			       sizeof(qlen)) == -1 ||
		    setsockopt(fds[0], SOL_SOCKET, SO_RCVBUF, &qlen,
			       sizeof(qlen)) == -1 ||
		    setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &qlen,
			       sizeof(qlen)) == -1) {
			loglog(RC_LOG_SERIOUS,
			       "could not set socket queue to %d", qlen);
			return;
		}
	}

	/* set local so that child inheirits it */
	pc_helper_num = n;

	thread_status = pthread_create((pthread_t*)&w->pcw_pid, NULL,
				       pluto_helper_thread, (void*)w);
	if (thread_status != 0) {
		loglog(RC_LOG_SERIOUS, "failed to start child, error = %d",
		       thread_status);
		w->pcw_pid = -1;
		close(fds[1]);
		close(fds[0]);
		w->pcw_dead   = TRUE;
		return;
	} else {
		libreswan_log("started helper (thread) pid=%ld (fd:%d)",
			      w->pcw_pid,  w->pcw_master_fd);
	}
}

/* IN A HELPER THREAD */
static void *pluto_helper_thread(void *w)
{
	const struct pluto_crypto_worker *helper;

	helper = (struct pluto_crypto_worker *)w;
	pluto_crypto_helper(helper->pcw_helper_fd, helper->pcw_helpernum);
	return NULL;
}

/*
 * clean up after a crypto helper
 */
static void cleanup_crypto_helper(struct pluto_crypto_worker *w,
				  int status)
{
	if (w->pcw_master_fd != 0) {
		loglog(RC_LOG_SERIOUS,
		       "closing helper(%u) pid=%lu fd=%d exit=%d",
		       w->pcw_helpernum, w->pcw_pid, w->pcw_master_fd, status);
		close(w->pcw_master_fd);
		/* ??? should we set w->pcw_master_fd to 0? */
	}

	w->pcw_pid = -1;
	w->pcw_work = 0;        /* ?!? */
	w->pcw_reaped = FALSE;
	w->pcw_dead   = FALSE;  /* marking is not dead lets it live again */
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
	if (nhelpers == -1) {
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

		if (ncpu_online > 2) {
			nhelpers = ncpu_online - 1;
		} else {
			/*
			 * if we have 2 CPUs or less, then create 1 helper, since
			 * we still want to deal with head-of-queue problem.
			 */
			nhelpers = 1;
		}
	}

	if (nhelpers > 0) {
		libreswan_log("starting up %d cryptographic helpers",
			      nhelpers);
		pc_workers = alloc_bytes(sizeof(*pc_workers) * nhelpers,
					 "pluto helpers");
		pc_workers_cnt = nhelpers;

		for (i = 0; i < nhelpers; i++)
			init_crypto_helper(&pc_workers[i], i);
	} else {
		libreswan_log(
			"no helpers will be started, all cryptographic operations will be done inline");
	}

	pc_worker_num = 0;
}

void enumerate_crypto_helper_response_sockets(lsw_fd_set *readfds)
{
	int cnt;
	struct pluto_crypto_worker *w = pc_workers;

	for (cnt = 0; cnt < pc_workers_cnt; cnt++, w++) {
		if (w->pcw_pid != -1 && !w->pcw_dead) {
			passert(w->pcw_master_fd > 0);

			LSW_FD_SET(w->pcw_master_fd, readfds);
		}
	}
}

int pluto_crypto_helper_response_ready(lsw_fd_set *readfds)
{
	int cnt;
	struct pluto_crypto_worker *w = pc_workers;
	int ndes;

	ndes = 0;

	for (cnt = 0; cnt < pc_workers_cnt; cnt++, w++) {
		if (w->pcw_pid != -1 && !w->pcw_dead) {
			passert(w->pcw_master_fd > 0);

			if (LSW_FD_ISSET(w->pcw_master_fd, readfds)) {
				handle_helper_answer(w);
				ndes++;
			}
		}
	}

	return ndes;
}
