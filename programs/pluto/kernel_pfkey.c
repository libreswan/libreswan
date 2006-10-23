/* common routines for interfaces that use pfkey to talk to kernel
 *
 * Copyright (C) 1997 Angelos D. Keromytis.
 * Copyright (C) 1998-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003 Herbert Xu.
 * Copyright (C) 2003-2006  Michael Richardson <mcr@xelerance.com>
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
 * RCSID $Id: kernel_pfkey.c,v 1.25 2005/08/24 22:50:50 mcr Exp $
 */

#ifdef PFKEY

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <openswan.h>
#include <openswan/pfkeyv2.h>
#include <openswan/pfkey.h>

#include "sysdep.h"
#include "constants.h"
#include "oswlog.h"

#include "defs.h"
#include "id.h"
#include "connections.h"
#include "state.h"
#include "kernel.h"
#include "kernel_pfkey.h"
#include "timer.h"
#include "log.h"
#include "whack.h"	/* for RC_LOG_SERIOUS */
#ifdef NAT_TRAVERSAL
#include "packet.h"  /* for pb_stream in nat_traversal.h */
#include "nat_traversal.h"
#endif

#include "alg_info.h"
#include "kernel_alg.h"

#define KLIPS_OP_MASK	0xFF
#define KLIPS_OP_FLAG_SHIFT	8

int pfkeyfd = NULL_FD;

typedef u_int32_t pfkey_seq_t;
static pfkey_seq_t pfkey_seq = 0;	/* sequence number for our PF_KEY messages */

/* The orphaned_holds table records %holds for which we
 * scan_proc_shunts found no representation of in any connection.
 * The corresponding ACQUIRE message might have been lost.
 */
struct eroute_info *orphaned_holds = NULL;

const struct pfkey_proto_info null_proto_info[2];

static pid_t pid;

#define NE(x) { x, #x }	/* Name Entry -- shorthand for sparse_names */

static sparse_names pfkey_type_names = {
	NE(SADB_RESERVED),
	NE(SADB_GETSPI),
	NE(SADB_UPDATE),
	NE(SADB_ADD),
	NE(SADB_DELETE),
	NE(SADB_GET),
	NE(SADB_ACQUIRE),
	NE(SADB_REGISTER),
	NE(SADB_EXPIRE),
	NE(SADB_FLUSH),
	NE(SADB_DUMP),
	NE(K_SADB_X_PROMISC),
	NE(K_SADB_X_PCHANGE),
	NE(K_SADB_X_GRPSA),
	NE(K_SADB_X_ADDFLOW),
	NE(K_SADB_X_DELFLOW),
	NE(K_SADB_X_DEBUG),
	NE(K_SADB_X_NAT_T_NEW_MAPPING),
/*	NE(K_SADB_X_PLUMBIF),   */
/*	NE(K_SADB_X_UNPLUMBIF), */
	NE(SADB_MAX),	
	{ 0, sparse_end }
};

#ifdef NEVER /* not needed yet */
static sparse_names pfkey_ext_names = {
	NE(K_SADB_EXT_RESERVED),
	NE(K_SADB_EXT_SA),
	NE(K_SADB_EXT_LIFETIME_CURRENT),
	NE(K_SADB_EXT_LIFETIME_HARD),
	NE(K_SADB_EXT_LIFETIME_SOFT),
	NE(K_SADB_EXT_ADDRESS_SRC),
	NE(K_SADB_EXT_ADDRESS_DST),
	NE(K_SADB_EXT_ADDRESS_PROXY),
	NE(K_SADB_EXT_KEY_AUTH),
	NE(K_SADB_EXT_KEY_ENCRYPT),
	NE(K_SADB_EXT_IDENTITY_SRC),
	NE(K_SADB_EXT_IDENTITY_DST),
	NE(K_SADB_EXT_SENSITIVITY),
	NE(K_SADB_EXT_PROPOSAL),
	NE(K_SADB_EXT_SUPPORTED_AUTH),
	NE(K_SADB_EXT_SUPPORTED_ENCRYPT),
	NE(K_SADB_EXT_SPIRANGE),
	NE(K_SADB_X_EXT_KMPRIVATE),
	NE(K_SADB_X_EXT_SATYPE2),
	NE(K_SADB_X_EXT_POLICY),
	NE(K_SADB_X_EXT_SA2),
	NE(K_SADB_X_EXT_ADDRESS_DST2),
	NE(K_SADB_X_EXT_ADDRESS_SRC_FLOW),
	NE(K_SADB_X_EXT_ADDRESS_DST_FLOW),
	NE(K_SADB_X_EXT_ADDRESS_SRC_MASK),
	NE(K_SADB_X_EXT_ADDRESS_DST_MASK),
	NE(K_SADB_X_EXT_DEBUG),
	NE(K_SADB_X_EXT_PROTOCOL),
	NE(K_SADB_X_EXT_NAT_T_TYPE),
	NE(K_SADB_X_EXT_NAT_T_SPORT),
	NE(K_SADB_X_EXT_NAT_T_DPORT),
	NE(K_SADB_X_EXT_NAT_T_OA),
	NE(K_SADB_X_EXT_PLUMBIF),
	NE(K_SADB_X_EXT_SAREF),
	NE(K_SADB_EXT_MAX),
	{ 0, sparse_end }
};
#endif /* NEVER */

#undef NE

void
init_pfkey(void)
{
    pid = getpid();

    /* open PF_KEY socket */

    pfkeyfd = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);

    if (pfkeyfd == -1)
	exit_log_errno((e, "socket() in init_pfkeyfd()"));

#ifdef NEVER	/* apparently unsupported! */
    if (fcntl(pfkeyfd, F_SETFL, O_NONBLOCK) != 0)
	exit_log_errno((e, "fcntl(O_NONBLOCK) in init_pfkeyfd()"));
#endif
    if (fcntl(pfkeyfd, F_SETFD, FD_CLOEXEC) != 0)
	exit_log_errno((e, "fcntl(FD_CLOEXEC) in init_pfkeyfd()"));

    DBG(DBG_KLIPS,
	DBG_log("process %u listening for PF_KEY_V2 on file descriptor %d", (unsigned)pid, pfkeyfd));
}

/* Kinds of PF_KEY message from the kernel:
 * - response to a request from us
 *   + ACK/NAK
 *   + Register: indicates transforms supported by kernel
 *   + SPI requested by getspi
 * - Acquire, requesting us to deal with trapped clear packet
 * - expiration of of one of our SAs
 * - messages to other processes
 *
 * To minimize the effect on the event-driven structure of Pluto,
 * responses are dealt with synchronously.  We hope that the Kernel
 * produces them synchronously.  We must "read ahead" in the PF_KEY
 * stream, saving Acquire and Expiry messages that are encountered.
 * We ignore messages to other processes.
 */

typedef union {
	unsigned char bytes[PFKEYv2_MAX_MSGSIZE];
	struct sadb_msg msg;
    } pfkey_buf;

/* queue of unprocessed PF_KEY messages input from kernel
 * Note that the pfkey_buf may be partly allocated, reflecting
 * the variable length nature of the messages.  So the link field
 * must come first.
 */
typedef struct pfkey_item {
	struct pfkey_item *next;
	pfkey_buf buf;
    } pfkey_item;

static pfkey_item *pfkey_iq_head = NULL;	/* oldest */
static pfkey_item *pfkey_iq_tail;	/* youngest */

static bool
pfkey_input_ready(void)
{
    fd_set readfds;
    int ndes;
    struct timeval tm;

    tm.tv_sec = 0;	/* don't wait at all */
    tm.tv_usec = 0;

    FD_ZERO(&readfds);	/* we only care about pfkeyfd */
    FD_SET(pfkeyfd, &readfds);

    do {
	ndes = select(pfkeyfd + 1, &readfds, NULL, NULL, &tm);
    } while (ndes == -1 && errno == EINTR);

    if (ndes < 0)
    {
	log_errno((e, "select() failed in pfkey_get()"));
	return FALSE;
    }

    if (ndes == 0)
	return FALSE;	/* nothing to read */

    passert(ndes == 1 && FD_ISSET(pfkeyfd, &readfds));
    return TRUE;
}

/* get a PF_KEY message from kernel.
 * Returns TRUE is message found, FALSE if no message pending,
 * and aborts or keeps trying when an error is encountered.
 * The only validation of the message is that the message length
 * received matches that in the message header, and that the message
 * is for this process.
 */
static bool
pfkey_get(pfkey_buf *buf)
{
    for (;;)
    {
	/* len must be less than PFKEYv2_MAX_MSGSIZE,
	 * so it should fit in an int.  We use this fact when printing it.
	 */
	ssize_t len;

	if (!pfkey_input_ready())
	    return FALSE;

	len = read(pfkeyfd, buf->bytes, sizeof(buf->bytes));

	if (len < 0)
	{
	    if (errno == EAGAIN)
		return FALSE;

	    log_errno((e, "read() failed in pfkey_get()"));
	    return FALSE;
	}
	else if ((size_t) len < sizeof(buf->msg))
	{
	    plog("pfkey_get read truncated PF_KEY message: %d bytes; ignoring message"
		, (int) len);
	}
	else if ((size_t) len != buf->msg.sadb_msg_len * IPSEC_PFKEYv2_ALIGN)
	{
	    plog("pfkey_get read PF_KEY message with length %d that doesn't equal sadb_msg_len %u * %u; ignoring message"
		, (int) len
		, (unsigned) buf->msg.sadb_msg_len
		, (unsigned) IPSEC_PFKEYv2_ALIGN);
	}
	else if (!(buf->msg.sadb_msg_pid == (unsigned)pid
	/*	for now, unsolicited messages can be: 
	 *	K_SADB_ACQUIRE, K_SADB_REGISTER, K_SADB_X_NAT_T_NEW_MAPPING
	 */
	|| (buf->msg.sadb_msg_pid == 0 && buf->msg.sadb_msg_type == SADB_ACQUIRE)
#ifdef KERNEL_ALG
	|| (buf->msg.sadb_msg_type == SADB_REGISTER)
#endif
#ifdef NAT_TRAVERSAL
	|| (buf->msg.sadb_msg_pid == 0 && buf->msg.sadb_msg_type == K_SADB_X_NAT_T_NEW_MAPPING)
#endif
	))
	{
	    /* not for us: ignore */
	    DBG(DBG_KLIPS,
		DBG_log("pfkey_get: ignoring PF_KEY %s message %u for process %u"
		    , sparse_val_show(pfkey_type_names, buf->msg.sadb_msg_type)
		    , buf->msg.sadb_msg_seq
		    , buf->msg.sadb_msg_pid));
	}
	else
	{
	    DBG(DBG_KLIPS,
		DBG_log("pfkey_get: %s message %u"
		    , sparse_val_show(pfkey_type_names, buf->msg.sadb_msg_type)
		    , buf->msg.sadb_msg_seq));
	    return TRUE;
	}
    }
}

/* get a response to a specific message */
static bool
pfkey_get_response(pfkey_buf *buf, pfkey_seq_t seq)
{
    while (pfkey_get(buf))
    {
	if (buf->msg.sadb_msg_pid == (unsigned)pid
	&& buf->msg.sadb_msg_seq == seq)
	{
	    return TRUE;
	}
	else
	{
	    /* Not for us: queue it. */
	    size_t bl = buf->msg.sadb_msg_len * IPSEC_PFKEYv2_ALIGN;
	    pfkey_item *it = alloc_bytes(offsetof(pfkey_item, buf) + bl, "pfkey_item");

	    memcpy(&it->buf, buf, bl);

	    it->next = NULL;
	    if (pfkey_iq_head == NULL)
	    {
		pfkey_iq_head = it;
	    }
	    else
	    {
		pfkey_iq_tail->next = it;
	    }
	    pfkey_iq_tail = it;
	}
    }
    return FALSE;
}

/* Process a K_SADB_REGISTER message from the kernel.
 * This will be a response to one of ours, but it may be asynchronous
 * (if kernel modules are loaded and unloaded).
 * Some sanity checking has already been performed.
 */
void
klips_pfkey_register_response(const struct sadb_msg *msg)
{
    /* Find out what the kernel can support.
     * In fact, the only question at the moment
     * is whether it can support IPcomp.
     * So we ignore the rest.
     * ??? we really should pay attention to what transforms are supported.
     */
    switch (msg->sadb_msg_satype)
    {
    case SADB_SATYPE_AH:
	break;
    case SADB_SATYPE_ESP:
#ifdef KERNEL_ALG
	kernel_alg_register_pfkey(msg, sizeof (pfkey_buf));
#endif
	break;
    case SADB_X_SATYPE_COMP:
	/* ??? There ought to be an extension to list the
	 * supported algorithms, but RFC 2367 doesn't
	 * list one for IPcomp.  KLIPS uses K_SADB_X_CALG_DEFLATE.
	 * Since we only implement deflate, we'll assume this.
	 */
	can_do_IPcomp = TRUE;
	break;
    case SADB_X_SATYPE_IPIP:
	break;
    default:
	break;
    }
}

/* Processs a K_SADB_ACQUIRE message from KLIPS.
 * Try to build an opportunistic connection!
 * See RFC 2367 "PF_KEY Key Management API, Version 2" 3.1.6
 * <base, address(SD), (address(P)), (identity(SD),) (sensitivity,) proposal>
 * - extensions for source and data IP addresses
 * - optional extensions for identity [not useful for us?]
 * - optional extension for sensitivity [not useful for us?]
 * - expension for proposal [not useful for us?]
 *
 * ??? We must use the sequence number in creating an SA.
 * We actually need to create up to 4 SAs each way.  Which one?
 * I guess it depends on the protocol present in the sadb_msg_satype.
 * For now, we'll ignore this requirement.
 *
 * ??? We need some mechanism to make sure that multiple ACQUIRE messages
 * don't cause a whole bunch of redundant negotiations.
 */
static void
process_pfkey_acquire(pfkey_buf *buf, struct sadb_ext *extensions[K_SADB_EXT_MAX + 1])
{
    struct sadb_address *srcx = (void *) extensions[K_SADB_EXT_ADDRESS_SRC];
    struct sadb_address *dstx = (void *) extensions[K_SADB_EXT_ADDRESS_DST];
    int src_proto = srcx->sadb_address_proto;
    int dst_proto = dstx->sadb_address_proto;
    ip_address *src = (ip_address*)&srcx[1];
    ip_address *dst = (ip_address*)&dstx[1];
    ip_subnet ours, his;
    err_t ugh = NULL;

    /* assumption: we're only catching our own outgoing packets
     * so source is our end and destination is the other end.
     * Verifying this is not actually convenient.
     *
     * This stylized control structure yields a complaint or
     * desired results.  For compactness, a pointer value is
     * treated as a boolean.  Logically, the structure is:
     * keep going as long as things are OK.
     */

    if (buf->msg.sadb_msg_pid == 0	/* we only wish to hear from kernel */
	&& !(ugh = src_proto == dst_proto? NULL : "src and dst protocols differ")
	&& !(ugh = addrtypeof(src) == addrtypeof(dst)? NULL : "conflicting address types")
	&& !(ugh = addrtosubnet(src, &ours))
	&& !(ugh = addrtosubnet(dst, &his)))
      record_and_initiate_opportunistic(&ours, &his, 0, "%acquire-pfkey");

    if (ugh != NULL)
	plog("K_SADB_ACQUIRE message from KLIPS malformed: %s", ugh);

}

/* Handle PF_KEY messages from the kernel that are not dealt with
 * synchronously.  In other words, all but responses to PF_KEY messages
 * that we sent.
 */
static void
pfkey_async(pfkey_buf *buf)
{
    struct sadb_ext *extensions[K_SADB_EXT_MAX + 1];

    if (pfkey_msg_parse(&buf->msg, NULL, extensions, EXT_BITS_OUT))
    {
	plog("pfkey_async:"
	    " unparseable PF_KEY message:"
	    " %s len=%d, errno=%d, seq=%d, pid=%d; message ignored"
	    , sparse_val_show(pfkey_type_names, buf->msg.sadb_msg_type)
	    , buf->msg.sadb_msg_len
	    , buf->msg.sadb_msg_errno
	    , buf->msg.sadb_msg_seq
	    , buf->msg.sadb_msg_pid);
    }
    else
    {
	DBG(DBG_CONTROL | DBG_KLIPS, DBG_log("pfkey_async:"
	    " %s len=%u, errno=%u, satype=%u, seq=%u, pid=%u"
	    , sparse_val_show(pfkey_type_names, buf->msg.sadb_msg_type)
	    , buf->msg.sadb_msg_len
	    , buf->msg.sadb_msg_errno
	    , buf->msg.sadb_msg_satype
	    , buf->msg.sadb_msg_seq
	    , buf->msg.sadb_msg_pid));

	switch (buf->msg.sadb_msg_type)
	{
	case K_SADB_REGISTER:
	    kernel_ops->pfkey_register_response(&buf->msg);
	    break;
	case K_SADB_ACQUIRE:
	    /* to simulate loss of ACQUIRE, delete this call */
	    process_pfkey_acquire(buf, extensions);
	    break;
#ifdef NAT_TRAVERSAL
	case K_SADB_X_NAT_T_NEW_MAPPING:
	    process_pfkey_nat_t_new_mapping(&(buf->msg), extensions);
	    break;
#endif
	default:
	    /* ignored */
	    break;
	}
    }
}

/* asynchronous messages from our queue */
void pfkey_dequeue(void)
{
    while (pfkey_iq_head != NULL)
    {
	pfkey_item *it = pfkey_iq_head;

	pfkey_async(&it->buf);
	pfkey_iq_head = it->next;
	pfree(it);
    }

    /* Handle any orphaned holds, but only if no pfkey input is pending.
     * For each, we initiate Opportunistic.
     * note: we don't need to advance the pointer because
     * record_and_initiate_opportunistic will remove the current
     * record each time we call it.
     */
    while (orphaned_holds != NULL && !pfkey_input_ready())
      record_and_initiate_opportunistic(&orphaned_holds->ours
					, &orphaned_holds->his
					, orphaned_holds->transport_proto
					, "%hold found-pfkey");

}

/* asynchronous messages directly from PF_KEY socket */
void pfkey_event(void)
{
    pfkey_buf buf;

    if (pfkey_get(&buf))
	pfkey_async(&buf);
}

static bool
pfkey_build(int error
, const char *description
, const char *text_said
, struct sadb_ext *extensions[K_SADB_EXT_MAX + 1])
{
    if (error == 0)
    {
	return TRUE;
    }
    else
    {
	loglog(RC_LOG_SERIOUS, "building of %s %s failed, code %d"
	    , description, text_said, error);
	pfkey_extensions_free(extensions);
	return FALSE;
    }
}

/* pfkey_extensions_init + pfkey_build + pfkey_msg_hdr_build */
static bool
pfkey_msg_start(u_int8_t msg_type
, u_int8_t satype
, const char *description
, const char *text_said
, struct sadb_ext *extensions[K_SADB_EXT_MAX + 1])
{
    pfkey_extensions_init(extensions);
    return pfkey_build(pfkey_msg_hdr_build(&extensions[0], msg_type
	    , satype, 0, ++pfkey_seq, pid)
	, description, text_said, extensions);
}

/* pfkey_build + pfkey_address_build */
static bool
pfkeyext_address(u_int16_t exttype
, const ip_address *address
, const char *description
, const char *text_said
, struct sadb_ext *extensions[K_SADB_EXT_MAX + 1])
{
    /* the following variable is only needed to silence
     * a warning caused by the fact that the argument
     * to sockaddrof is NOT pointer to const!
     */
    ip_address t = *address;

    return pfkey_build(pfkey_address_build(extensions + exttype
	    , exttype, 0, 0, sockaddrof(&t))
	, description, text_said, extensions);
}

/* pfkey_build + pfkey_x_protocol_build */
static bool
pfkeyext_protocol(int transport_proto
, const char *description
, const char *text_said
, struct sadb_ext *extensions[K_SADB_EXT_MAX + 1])
{
    return (transport_proto == 0)
        ? TRUE
        : pfkey_build(pfkey_x_protocol_build(extensions + K_SADB_X_EXT_PROTOCOL,
                                             transport_proto),
                      description, text_said, extensions);
}


/* Finish (building, sending, accepting response for) PF_KEY message.
 * If response isn't NULL, the response from the kernel will be
 * placed there (and its errno field will not be examined).
 * Returns TRUE iff all appears well.
 */
static bool
finish_pfkey_msg(struct sadb_ext *extensions[K_SADB_EXT_MAX + 1]
		 , const char *description
		 , const char *text_said
		 , pfkey_buf *response)
{
    struct sadb_msg *pfkey_msg;
    bool success = TRUE;
    int error;

    error = pfkey_msg_build(&pfkey_msg, extensions, EXT_BITS_IN);

    if (error != 0)
    {
	loglog(RC_LOG_SERIOUS, "pfkey_msg_build of %s %s failed, code %d"
	    , description, text_said, error);
	success = FALSE;
    }
    else
    {
	size_t len = pfkey_msg->sadb_msg_len * IPSEC_PFKEYv2_ALIGN;

	DBG(DBG_KLIPS,
	    DBG_log("finish_pfkey_msg: %s message %u for %s %s"
		, sparse_val_show(pfkey_type_names, pfkey_msg->sadb_msg_type)
		, pfkey_msg->sadb_msg_seq
		, description, text_said);
	    DBG_dump(NULL, (void *) pfkey_msg, len));

	if (kern_interface != NO_KERNEL)
	{
	    ssize_t r = write(pfkeyfd, pfkey_msg, len);
	    int e1 = errno;

	    if (r != (ssize_t)len)
	    {
		if (r < 0)
		{
		  switch(e1) {
		  case ESRCH:
		    if(pfkey_msg->sadb_msg_type == K_SADB_DELETE) {
		      success=TRUE;
		    }
		    else {
		      goto logerr;
		    }
		    break;

		  case ENOENT:
		    loglog(RC_LOG_SERIOUS, "requested algorithm is not available in the kernel");
		    success=FALSE;
		    break;
		    
		  default:
		  logerr:
		    openswan_log_errno_routine(e1, "pfkey write() of %s message %u"
					       " for %s %s failed"
					       , sparse_val_show(pfkey_type_names
								 , pfkey_msg->sadb_msg_type)
					       , pfkey_msg->sadb_msg_seq
					       , description, text_said);
		    success = FALSE;
		  }
		}
		else
		{
		    loglog(RC_LOG_SERIOUS
			, "ERROR: pfkey write() of %s message %u"
			  " for %s %s truncated: %ld instead of %ld"
			, sparse_val_show(pfkey_type_names
			    , pfkey_msg->sadb_msg_type)
			, pfkey_msg->sadb_msg_seq
			, description, text_said
			, (long)r, (long)len);
		    success = FALSE;
		}

		/* if we were compiled with debugging, but we haven't already
		 * dumped the KLIPS command, do so.
		 */
#ifdef DEBUG
		if ((cur_debugging & DBG_KLIPS) == 0)
		    DBG_dump(NULL, (void *) pfkey_msg, len);
#endif
	    }
	    else
	    {
		/* Check response from KLIPS.
		 * It ought to be an echo, perhaps with additional info.
		 * If the caller wants it, response will point to space.
		 */
		pfkey_buf b;
		pfkey_buf *bp = response != NULL? response : &b;
		int seq = ((struct sadb_msg *) extensions[0])->sadb_msg_seq;

		if (!pfkey_get_response(bp, seq))
		{
		    loglog(RC_LOG_SERIOUS
			, "ERROR: no response to our PF_KEY %s message for %s %s (seq=%u)"
			, sparse_val_show(pfkey_type_names, pfkey_msg->sadb_msg_type)
			   , description, text_said, seq);
		    success = FALSE;
		}
		else if (pfkey_msg->sadb_msg_type != bp->msg.sadb_msg_type)
		{
		    loglog(RC_LOG_SERIOUS
			, "Openswan ERROR: response to our PF_KEY %s message for %s %s was of wrong type (%s)"
			, sparse_name(pfkey_type_names, pfkey_msg->sadb_msg_type)
			, description, text_said
			, sparse_val_show(pfkey_type_names, bp->msg.sadb_msg_type));
		    success = FALSE;
		}
		else if (response == NULL && bp->msg.sadb_msg_errno != 0)
		{
		    /* KLIPS is signalling a problem */
		    loglog(RC_LOG_SERIOUS
			, "ERROR: PF_KEY %s response for %s %s included errno %u: %s"
			, sparse_val_show(pfkey_type_names, pfkey_msg->sadb_msg_type)
			, description, text_said
			, (unsigned) bp->msg.sadb_msg_errno
			, strerror(bp->msg.sadb_msg_errno));
		    success = FALSE;
		}
	    }
	}
    }

    /* all paths must exit this way to free resources */
    pfkey_extensions_free(extensions);
    pfkey_msg_free(&pfkey_msg);
    return success;
}

/*  register SA types that can be negotiated */
void
pfkey_register_proto(unsigned satype, const char *satypename)
{
    struct sadb_ext *extensions[K_SADB_EXT_MAX + 1];
    pfkey_buf pfb;

    if (!(pfkey_msg_start(K_SADB_REGISTER
      , satype
      , satypename, NULL, extensions)
    && finish_pfkey_msg(extensions, satypename, "", &pfb)))
    {
	/* ??? should this be loglog */
	plog("no KLIPS support for %s", satypename);
    }
    else
    {
	kernel_ops->pfkey_register_response(&pfb.msg);
	DBG(DBG_KLIPS,
	    DBG_log("%s registered with kernel.", satypename));
    }
}

static int kernelop2klips(enum pluto_sadb_operations op)
{
    int klips_op=0;

    /* translate sadb_operations -> KLIPS speak */
    switch (op)
    {
    case ERO_REPLACE:
	klips_op = (K_SADB_X_ADDFLOW | (SADB_X_SAFLAGS_REPLACEFLOW << KLIPS_OP_FLAG_SHIFT));
	break;

    case ERO_ADD:
	klips_op = K_SADB_X_ADDFLOW;
	break;

    case ERO_DELETE:
	klips_op = K_SADB_X_DELFLOW;
	break;
	    
    case ERO_ADD_INBOUND:
	klips_op = (K_SADB_X_ADDFLOW | (SADB_X_SAFLAGS_INFLOW << KLIPS_OP_FLAG_SHIFT));
	break;

    case ERO_DEL_INBOUND:
	klips_op = (K_SADB_X_DELFLOW | (SADB_X_SAFLAGS_INFLOW << KLIPS_OP_FLAG_SHIFT));
	break;

    case ERO_REPLACE_INBOUND:
	klips_op = (K_SADB_X_ADDFLOW | (SADB_X_SAFLAGS_REPLACEFLOW|SADB_X_SAFLAGS_INFLOW << KLIPS_OP_FLAG_SHIFT));
	break;
    }

    return klips_op;
}

void klips_pfkey_register(void)
{
    pfkey_register_proto(SADB_SATYPE_AH, "AH");
    pfkey_register_proto(SADB_SATYPE_ESP, "ESP");
    can_do_IPcomp = FALSE;  /* until we get a response from KLIPS */
    pfkey_register_proto(SADB_X_SATYPE_COMP, "IPCOMP");
    pfkey_register_proto(SADB_X_SATYPE_IPIP, "IPIP");
}

bool
pfkey_raw_eroute(const ip_address *this_host
		 , const ip_subnet *this_client
		 , const ip_address *that_host
		 , const ip_subnet *that_client
		 , ipsec_spi_t spi
		 , unsigned int proto UNUSED
		 , unsigned int transport_proto
		 , enum eroute_type esatype
		 , const struct pfkey_proto_info *proto_info UNUSED
		 , time_t use_lifetime UNUSED
		 , enum pluto_sadb_operations op
		 , const char *text_said)
{
    struct sadb_ext *extensions[K_SADB_EXT_MAX + 1];
    ip_address
	sflow_ska,
	dflow_ska,
	smask_ska,
	dmask_ska;
    int  klips_op = kernelop2klips(op);

    int sport = ntohs(portof(&this_client->addr));
    int dport = ntohs(portof(&that_client->addr));
    int satype;

    networkof(this_client, &sflow_ska);
    maskof(this_client, &smask_ska);
    setportof(sport ? ~0:0, &smask_ska);

    networkof(that_client, &dflow_ska);
    maskof(that_client, &dmask_ska);
    setportof(dport ? ~0:0, &dmask_ska);

    switch(esatype) {
    case ET_UNSPEC:
	    satype = K_SADB_SATYPE_UNSPEC;
	    break;

    case ET_AH:
	    satype = K_SADB_SATYPE_AH;
	    break;

    case ET_ESP:
	    satype = K_SADB_SATYPE_ESP;
	    break;

    case ET_IPCOMP:
	    satype = K_SADB_X_SATYPE_COMP;
	    break;

    case ET_INT:
	    satype = K_SADB_X_SATYPE_INT;
	    break;

    case ET_IPIP:
	    satype = K_SADB_X_SATYPE_IPIP;
	    break;
    }

    if (!pfkey_msg_start(klips_op & KLIPS_OP_MASK, satype
		       , "pfkey_msg_hdr flow", text_said, extensions))
    {
	return FALSE;
    }

    if (op != ERO_DELETE)
    {
	if (!(pfkey_build(pfkey_sa_build(&extensions[K_SADB_EXT_SA]
					 , K_SADB_EXT_SA
					 , spi	/* in network order */
					 , 0, 0, 0, 0, klips_op >> KLIPS_OP_FLAG_SHIFT)
			  , "pfkey_sa add flow", text_said, extensions)

	    && pfkeyext_address(K_SADB_EXT_ADDRESS_SRC, this_host
		, "pfkey_addr_s add flow", text_said, extensions)

	    && pfkeyext_address(K_SADB_EXT_ADDRESS_DST, that_host
				, "pfkey_addr_d add flow", text_said
				, extensions)))
	{
	    return FALSE;
	}
    }

    if (!pfkeyext_address(K_SADB_X_EXT_ADDRESS_SRC_FLOW, &sflow_ska
			  , "pfkey_addr_sflow", text_said, extensions))
    {
	return FALSE;
    }

    if (!pfkeyext_address(K_SADB_X_EXT_ADDRESS_DST_FLOW, &dflow_ska
			, "pfkey_addr_dflow", text_said, extensions))
    {
	return FALSE;
    }

    if (!pfkeyext_address(K_SADB_X_EXT_ADDRESS_SRC_MASK, &smask_ska
			, "pfkey_addr_smask", text_said, extensions))
    {
	return FALSE;
    }

    if (!pfkeyext_address(K_SADB_X_EXT_ADDRESS_DST_MASK, &dmask_ska
			, "pfkey_addr_dmask", text_said, extensions))
    {
	return FALSE;
    }

    if (!pfkeyext_protocol(transport_proto
			, "pfkey_x_protocol", text_said, extensions))
    {
	return FALSE;
    }

    return finish_pfkey_msg(extensions, "flow", text_said, NULL);
}

bool pfkey_add_sa(const struct kernel_sa *sa, bool replace)
{
    struct sadb_ext *extensions[K_SADB_EXT_MAX + 1];
    pfkey_buf pfb;
    bool success = FALSE;

    int klips_satype = proto2satype(sa->esatype);

    success = pfkey_msg_start(replace ? K_SADB_UPDATE : K_SADB_ADD, klips_satype
			      , "pfkey_msg_hdr Add SA"
			      , sa->text_said, extensions);

    if(!success) return FALSE;

    success = pfkey_build(pfkey_sa_build(&extensions[K_SADB_EXT_SA]
					 , K_SADB_EXT_SA
					 , sa->spi	/* in network order */
					 , sa->replay_window, K_SADB_SASTATE_MATURE
					 , sa->authalg, sa->encalg, 0)
			  , "pfkey_sa Add SA", sa->text_said, extensions);
    if(!success) return FALSE;

    success = pfkeyext_address(K_SADB_EXT_ADDRESS_SRC, sa->src
			       , "pfkey_addr_s Add SA"
			       , sa->text_said, extensions);
    if(!success) return FALSE;

    success = pfkeyext_address(K_SADB_EXT_ADDRESS_DST, sa->dst
			       , "pfkey_addr_d Add SA", sa->text_said
			       , extensions);
    if(!success) return FALSE;

    if(sa->authkeylen != 0) {
	success = pfkey_build(pfkey_key_build(&extensions[K_SADB_EXT_KEY_AUTH]
					      , K_SADB_EXT_KEY_AUTH
					      , sa->authkeylen * BITS_PER_BYTE
					      , sa->authkey)
			      , "pfkey_key_a Add SA"
			      , sa->text_said, extensions);
	if(!success) return FALSE;
    }

#ifdef KLIPS_MAST
    if(sa->ref != IPSEC_SAREF_NULL || sa->refhim != IPSEC_SAREF_NULL) {
	    success = pfkey_build(pfkey_saref_build(&extensions[K_SADB_X_EXT_SAREF]
						    , sa->ref
						    , sa->refhim)
				  , "pfkey_key_sare Add SA"
				  , sa->text_said, extensions);
	    if(!success) return FALSE;
    }
#endif
	
    if(sa->enckeylen != 0) {
	success = pfkey_build(pfkey_key_build(&extensions[K_SADB_EXT_KEY_ENCRYPT]
					      , K_SADB_EXT_KEY_ENCRYPT
					      , sa->enckeylen * BITS_PER_BYTE
					      , sa->enckey)
			      , "pfkey_key_e Add SA"
			      , sa->text_said, extensions);
	if(!success) return FALSE;
    }
	

#ifdef NAT_TRAVERSAL
    if(sa->natt_type != 0) {
	success = pfkey_build(pfkey_x_nat_t_type_build(
				  &extensions[K_SADB_X_EXT_NAT_T_TYPE]
				  , sa->natt_type),
			      "pfkey_nat_t_type Add ESP SA"
			      ,  sa->text_said, extensions);
	DBG(DBG_KLIPS
	    , DBG_log("setting natt_type to %d\n", sa->natt_type));
	if(!success) return FALSE;

	if(sa->natt_sport != 0) {
	  success = pfkey_build(pfkey_x_nat_t_port_build(
				  &extensions[K_SADB_X_EXT_NAT_T_SPORT]
				  , K_SADB_X_EXT_NAT_T_SPORT,
				  sa->natt_sport)
			      , "pfkey_nat_t_sport Add ESP SA"
			      , sa->text_said, extensions);
	  DBG(DBG_KLIPS
	      , DBG_log("setting natt_sport to %d\n", sa->natt_sport));
	  if(!success) return FALSE;
	}
	
	if(sa->natt_dport != 0) {
	  success = pfkey_build(pfkey_x_nat_t_port_build(
				  &extensions[K_SADB_X_EXT_NAT_T_DPORT]
				  , K_SADB_X_EXT_NAT_T_DPORT
				  , sa->natt_dport)
			      , "pfkey_nat_t_dport Add ESP SA"
			      , sa->text_said, extensions);
	  DBG(DBG_KLIPS
	      , DBG_log("setting natt_dport to %d\n", sa->natt_dport));
	  if(!success) return FALSE;
	}
	

	if(sa->natt_type!=0 && !isanyaddr(sa->natt_oa)) {
	  success = pfkeyext_address(K_SADB_X_EXT_NAT_T_OA, sa->natt_oa
				     , "pfkey_nat_t_oa Add ESP SA"
				     , sa->text_said, extensions);
	  DBG(DBG_KLIPS
	      , DBG_log("setting nat_oa to %s\n", ip_str(sa->natt_oa)));
	  if(!success) return FALSE;
	}
    }
#endif

    success = finish_pfkey_msg(extensions, "Add SA", sa->text_said, &pfb);
    
    if(success) {
	    /* extract the saref extension */
	    struct sadb_ext *replies[K_SADB_EXT_MAX + 1];
	    int error;

	    error = pfkey_msg_parse(&pfb.msg, NULL, replies, EXT_BITS_IN);

#ifdef KLIPS_MAST	    
	    if(replies[K_SADB_X_EXT_SAREF]) {
		    struct sadb_x_saref *sar = (struct sadb_x_saref *)replies[K_SADB_X_EXT_SAREF];
		    
		    sa->ref = sar->sadb_x_saref_me;
		    sa->refhim = sar->sadb_x_saref_him;
	    }
#endif
    }
    return success;
}


bool pfkey_grp_sa(const struct kernel_sa *sa0, const struct kernel_sa *sa1)
{
    struct sadb_ext *extensions[K_SADB_EXT_MAX + 1];
    int klips_satype0 = proto2satype(sa0->esatype);
    int klips_satype1 = proto2satype(sa1->esatype);


    return pfkey_msg_start(K_SADB_X_GRPSA, klips_satype1
	, "pfkey_msg_hdr group", sa1->text_said, extensions)

    && pfkey_build(pfkey_sa_build(&extensions[K_SADB_EXT_SA]
	    , K_SADB_EXT_SA
	    , sa1->spi	/* in network order */
	    , 0, 0, 0, 0, 0)
	, "pfkey_sa group", sa1->text_said, extensions)

    && pfkeyext_address(K_SADB_EXT_ADDRESS_DST, sa1->dst
	, "pfkey_addr_d group", sa1->text_said, extensions)

    && pfkey_build(pfkey_x_satype_build(&extensions[K_SADB_X_EXT_SATYPE2]
	    , klips_satype0)
	, "pfkey_satype group", sa0->text_said, extensions)

    && pfkey_build(pfkey_sa_build(&extensions[K_SADB_X_EXT_SA2]
	    , K_SADB_X_EXT_SA2
	    , sa0->spi	/* in network order */
	    , 0, 0, 0, 0, 0)
	, "pfkey_sa2 group", sa0->text_said, extensions)

    && pfkeyext_address(K_SADB_X_EXT_ADDRESS_DST2, sa0->dst
	, "pfkey_addr_d2 group", sa0->text_said, extensions)

    && finish_pfkey_msg(extensions, "group", sa1->text_said, NULL);
}

bool pfkey_del_sa(const struct kernel_sa *sa)
{
    struct sadb_ext *extensions[K_SADB_EXT_MAX + 1];

    return pfkey_msg_start(K_SADB_DELETE, proto2satype(sa->proto)
	, "pfkey_msg_hdr delete SA", sa->text_said, extensions)

    && pfkey_build(pfkey_sa_build(&extensions[K_SADB_EXT_SA]
	    , K_SADB_EXT_SA
	    , sa->spi	/* in host order */
	    , 0, K_SADB_SASTATE_MATURE, 0, 0, 0)
	, "pfkey_sa delete SA", sa->text_said, extensions)

    && pfkeyext_address(K_SADB_EXT_ADDRESS_SRC, sa->src
	, "pfkey_addr_s delete SA", sa->text_said, extensions)

    && pfkeyext_address(K_SADB_EXT_ADDRESS_DST, sa->dst
	, "pfkey_addr_d delete SA", sa->text_said, extensions)

    && finish_pfkey_msg(extensions, "Delete SA", sa->text_said, NULL);
}

void
pfkey_close(void)
{
    while (pfkey_iq_head != NULL)
    {
	pfkey_item *it = pfkey_iq_head;

	pfkey_iq_head = it->next;
	pfree(it);
    }

    close(pfkeyfd);
    pfkeyfd = NULL_FD;
}

/* Add/replace/delete a shunt eroute.
 * Such an eroute determines the fate of packets without the use
 * of any SAs.  These are defaults, in effect.
 * If a negotiation has not been attempted, use %trap.
 * If negotiation has failed, the choice between %trap/%pass/%drop/%reject
 * is specified in the policy of connection c.
 */
bool
pfkey_shunt_eroute(struct connection *c
		   , struct spd_route *sr
		   , enum routing_t rt_kind
		   , enum pluto_sadb_operations op, const char *opname)
{
    /* We are constructing a special SAID for the eroute.
     * The destination doesn't seem to matter, but the family does.
     * The protocol is SA_INT -- mark this as shunt.
     * The satype has no meaning, but is required for PF_KEY header!
     * The SPI signifies the kind of shunt.
     */
    ipsec_spi_t spi = shunt_policy_spi(c, rt_kind == RT_ROUTED_PROSPECTIVE);

    if (spi == 0)
    {
        /* we're supposed to end up with no eroute: rejig op and opname */
        switch (op)
        {
        case ERO_REPLACE:
            /* replace with nothing == delete */
            op = ERO_DELETE;
            opname = "delete";
            break;
        case ERO_ADD:
            /* add nothing == do nothing */
            return TRUE;

        case ERO_DELETE:
            /* delete remains delete */
            break;
	    
	case ERO_ADD_INBOUND:
	    break;

	case ERO_DEL_INBOUND:
	    break;

        default:
            bad_case(op);
        }
    }

    if (sr->routing == RT_ROUTED_ECLIPSED && c->kind == CK_TEMPLATE)
    {
        /* We think that we have an eroute, but we don't.
         * Adjust the request and account for eclipses.
         */
        passert(eclipsable(sr));
        switch (op)
        {
        case ERO_REPLACE:
            /* really an add */
            op = ERO_ADD;
            opname = "replace eclipsed";
            eclipse_count--;
            break;
	    
        case ERO_DELETE:
            /* delete unnecessary: we don't actually have an eroute */
            eclipse_count--;
            return TRUE;

        case ERO_ADD:
        default:
            bad_case(op);
        }
    }
    else if (eclipse_count > 0 && op == ERO_DELETE && eclipsable(sr))
    {
        /* maybe we are uneclipsing something */
        struct spd_route *esr;
        struct connection *ue = eclipsed(c, &esr);

        if (ue != NULL)
        {
            esr->routing = RT_ROUTED_PROSPECTIVE;
            return pfkey_shunt_eroute(ue, esr
				      , RT_ROUTED_PROSPECTIVE
				      , ERO_REPLACE
				      , "restoring eclipsed");
        }
    }

#if 0
    {
	bool ok; 
	enum pluto_sadb_operations inop;
	
	inop = op + ERO_ADD_INBOUND-ERO_ADD;
	
	ok = pfkey_raw_eroute(&c->spd.that.host_addr, &c->spd.that.client
			      , &c->spd.this.host_addr, &c->spd.this.client
			      , htonl(spi)
			      , SA_INT
			      , 0 /* transport_proto is not relevant */
			      , SADB_X_SATYPE_INT, null_proto_info
			      , 0      /* use lifetime */
			      , inop
			      , opname);
	if(!ok) { return FALSE; }
    }
#endif

    {
      const ip_address *peer = &sr->that.host_addr;
      char buf2[256];
      
      snprintf(buf2, sizeof(buf2)
	       , "eroute_connection %s", opname);

      return pfkey_raw_eroute(&sr->this.host_addr, &sr->this.client
			      , aftoinfo(addrtypeof(peer))->any
			      , &sr->that.client
			      , htonl(spi)
			      , SA_INT
			      , sr->this.protocol
			      , SADB_X_SATYPE_INT
			      , null_proto_info, 0, op, buf2);
    }
}

/* install or remove eroute for SA Group */
bool
pfkey_sag_eroute(struct state *st, struct spd_route *sr
		 , unsigned op, const char *opname)
{
    unsigned int
        inner_proto,
        inner_satype;
    ipsec_spi_t inner_spi;
    struct pfkey_proto_info proto_info[4];
    int i;
    bool tunnel;

    /* figure out the SPI and protocol (in two forms)
     * for the innermost transformation.
     */

    i = sizeof(proto_info) / sizeof(proto_info[0]) - 1;
    proto_info[i].proto = 0;
    tunnel = FALSE;

    inner_proto = 0;
    inner_satype= 0;
    inner_spi = 0;

    if (st->st_ah.present)
    {
        inner_spi = st->st_ah.attrs.spi;
        inner_proto = SA_AH;
        inner_satype = SADB_SATYPE_AH;

        i--;
        proto_info[i].proto = IPPROTO_AH;
        proto_info[i].encapsulation = st->st_ah.attrs.encapsulation;
        tunnel |= proto_info[i].encapsulation == ENCAPSULATION_MODE_TUNNEL;
        proto_info[i].reqid = sr->reqid;
    }

    if (st->st_esp.present)
    {
        inner_spi = st->st_esp.attrs.spi;
        inner_proto = SA_ESP;
        inner_satype = SADB_SATYPE_ESP;

        i--;
        proto_info[i].proto = IPPROTO_ESP;
        proto_info[i].encapsulation = st->st_esp.attrs.encapsulation;
        tunnel |= proto_info[i].encapsulation == ENCAPSULATION_MODE_TUNNEL;
        proto_info[i].reqid = sr->reqid + 1;
    }

    if (st->st_ipcomp.present)
    {
        inner_spi = st->st_ipcomp.attrs.spi;
        inner_proto = SA_COMP;
        inner_satype = SADB_X_SATYPE_COMP;

        i--;
        proto_info[i].proto = IPPROTO_COMP;
        proto_info[i].encapsulation = st->st_ipcomp.attrs.encapsulation;
        tunnel |= proto_info[i].encapsulation == ENCAPSULATION_MODE_TUNNEL;
        proto_info[i].reqid = sr->reqid + 2;
    }

    if (i == sizeof(proto_info) / sizeof(proto_info[0]) - 1)
    {
        impossible();   /* no transform at all! */
    }

    if (tunnel)
    {
        int j;

        inner_spi = st->st_tunnel_out_spi;
        inner_proto = SA_IPIP;
        inner_satype = SADB_X_SATYPE_IPIP;

        proto_info[i].encapsulation = ENCAPSULATION_MODE_TUNNEL;
        for (j = i + 1; proto_info[j].proto; j++)
        {
            proto_info[j].encapsulation = ENCAPSULATION_MODE_TRANSPORT;
        }
    }

    return eroute_connection(sr
			     , inner_spi, inner_proto
			     , inner_satype, proto_info + i
			     , op, opname);
}

/*
 * This is only called when s is a likely SAID with  trailing protocol i.e.
 * it has the form :-
 *
 *   %<keyword>:p
 *   <ip-proto><spi>@a.b.c.d:p
 *
 * The task here is to remove the ":p" part so that the rest can be read
 * by another routine.
 */
static const char *
read_proto(const char * s, size_t * len, int * transport_proto)
{
    const char * p;
    const char * ugh;
    unsigned long proto;
    size_t l;

    l = *len;
    p = memchr(s, ':', l);
    if (p == 0) {
        *transport_proto = 0;
        return 0;
    }
    ugh = ttoul(p+1, l-((p-s)+1), 10, &proto);
    if (ugh != 0)
        return ugh;
    if (proto > 65535)
        return "protocol number is too large, legal range is 0-65535";
    *len = p-s;
    *transport_proto = proto;
    return 0;
}

/* scan /proc/net/ipsec_eroute every once in a while, looking for:
 *
 * - %hold shunts of which Pluto isn't aware.  This situation could
 *   be caused by lost ACQUIRE messages.  When found, they will
 *   added to orphan_holds.  This in turn will lead to Opportunistic
 *   initiation.
 *
 * - other kinds of shunts that haven't been used recently.  These will be
 *   deleted.  They represent OE failures.
 *
 * - recording recent uses of tunnel eroutes so that rekeying decisions
 *   can be made for OE connections.
 *
 * Here are some sample lines:
 * 10         10.3.2.1.0/24    -> 0.0.0.0/0          => %trap
 * 259        10.3.2.1.115/32  -> 10.19.75.161/32    => tun0x1002@10.19.75.145
 * 71         10.44.73.97/32   -> 0.0.0.0/0          => %trap
 * 4119       10.44.73.97/32   -> 10.114.121.41/32   => %pass
 * Newer versions of KLIPS start each line with a 32-bit packet count.
 * If available, the count is used to detect whether a %pass shunt is in use.
 *
 * NOTE: execution time is quadratic in the number of eroutes since the
 * searching for each is sequential.  If this becomes a problem, faster
 * searches could be implemented (hash or radix tree, for example).
 */
void
scan_proc_shunts(void)
{
    static const char procname[] = "/proc/net/ipsec_eroute";
    FILE *f;
    time_t nw = now();
    int lino;
    struct eroute_info *expired = NULL;

    event_schedule(EVENT_SHUNT_SCAN, SHUNT_SCAN_INTERVAL, NULL);

    DBG(DBG_CONTROL,
        DBG_log("scanning for shunt eroutes")
    )

    /* free any leftover entries: they will be refreshed if still current */
    while (orphaned_holds != NULL)
    {
        struct eroute_info *p = orphaned_holds;

        orphaned_holds = p->next;
        pfree(orphaned_holds);
    }

    /* decode the /proc file.  Don't do anything strenuous to it
     * (certainly no PF_KEY stuff) to minimize the chance that it
     * might change underfoot.
     */

    f = fopen(procname, "r");
    if (f == NULL)
        return;

    /* for each line... */
    for (lino = 1; ; lino++)
    {
        char buf[1024];        /* should be big enough */
        chunk_t field[10];      /* 10 is loose upper bound */
        chunk_t *ff;    /* fixed fields (excluding optional count) */
        int fi;
        struct eroute_info eri;
        char *cp;
        err_t context = ""
            , ugh = NULL;

	ff = NULL;

        cp = fgets(buf, sizeof(buf), f);
        if (cp == NULL)
            break;

        /* break out each field
         * Note: if there are too many fields, just stop;
         * it will be diagnosed a little later.
         */
        for (fi = 0; fi < (int)elemsof(field); fi++)
        {
            static const char sep[] = " \t\n";  /* field-separating whitespace */
            size_t w;

            cp += strspn(cp, sep);      /* find start of field */
            w = strcspn(cp, sep);       /* find width of field */
            setchunk(field[fi], (unsigned char *)cp, w);
            cp += w;
            if (w == 0)
                break;
        }

        /* This odd do-hickey is to share error reporting code.
         * A break will get to that common code.  The setting
         * of "ugh" and "context" parameterize it.
         */
        do {
            /* Old entries have no packet count; new ones do.
             * check if things are as they should be.
             */
            if (fi == 5)
                ff = &field[0]; /* old form, with no count */
            else if (fi == 6)
                ff = &field[1]; /* new form, with count */
            else
            {
                ugh = "has wrong number of fields";
                break;
            }

            if (ff[1].len != 2
		|| strncmp((char *)ff[1].ptr, "->", 2) != 0
		|| ff[3].len != 2
		|| strncmp((char *)ff[3].ptr, "=>", 2) != 0)
            {
                ugh = "is missing -> or =>";
                break;
            }

            /* actually digest fields of interest */

            /* packet count */

            eri.count = 0;
            if (ff != field)
            {
                context = "count field is malformed: ";
                ugh = ttoul((char *)field[0].ptr, field[0].len, 10, &eri.count);
                if (ugh != NULL)
                    break;
            }

            /* our client */

            context = "source subnet field malformed: ";
            ugh = ttosubnet((char *)ff[0].ptr, ff[0].len, AF_INET, &eri.ours);
            if (ugh != NULL)
                break;

            /* his client */

            context = "destination subnet field malformed: ";
            ugh = ttosubnet((char *)ff[2].ptr, ff[2].len, AF_INET, &eri.his);
            if (ugh != NULL)
                break;

            /* SAID */

            context = "SA ID field malformed: ";
            ugh = read_proto((char *)ff[4].ptr, &ff[4].len, &eri.transport_proto);
            if (ugh != NULL)
                break;
            ugh = ttosa((char *)ff[4].ptr, ff[4].len, &eri.said);
        } while (FALSE);

        if (ugh != NULL)
        {
            openswan_log("INTERNAL ERROR: %s line %d %s%s"
                , procname, lino, context, ugh);
            continue;   /* ignore rest of line */
        }

        /* Now we have decoded eroute, let's consider it.
         * For shunt eroutes:
         *
         * %hold: if not known, add to orphaned_holds list for initiation
         *    because ACQUIRE might have been lost.
         *
         * %pass, %drop, %reject: determine if idle; if so, blast it away.
         *    Can occur bare (if DNS provided insufficient information)
         *    or with a connection (failure context).
         *    Could even be installed by ipsec manual.
         *
         * %trap: always welcome.
         *
         * For other eroutes: find state and record count change
         */
        if (eri.said.proto == SA_INT)
        {
            /* shunt eroute */
            switch (ntohl(eri.said.spi))
            {
            case SPI_HOLD:
                if (bare_shunt_ptr(&eri.ours, &eri.his, eri.transport_proto) == NULL
                && shunt_owner(&eri.ours, &eri.his) == NULL)
                {
                    int ourport = ntohs(portof(&eri.ours.addr));
                    int hisport = ntohs(portof(&eri.his.addr));
                    char ourst[SUBNETTOT_BUF];
                    char hist[SUBNETTOT_BUF];
                    char sat[SATOT_BUF];

                    subnettot(&eri.ours, 0, ourst, sizeof(ourst));
                    subnettot(&eri.his, 0, hist, sizeof(hist));
                    satot(&eri.said, 0, sat, sizeof(sat));

                    DBG(DBG_CONTROL,
                        DBG_log("add orphaned shunt %s:%d -> %s:%d => %s:%d"
                            , ourst, ourport, hist, hisport, sat, eri.transport_proto)
                     )
                    eri.next = orphaned_holds;
                    orphaned_holds = clone_thing(eri, "orphaned %hold");
                }
                break;

            case SPI_PASS:
            case SPI_DROP:
            case SPI_REJECT:
                /* nothing sensible to do if we don't have counts */
                if (ff != field)
                {
                    struct bare_shunt **bs_pp
                        = bare_shunt_ptr(&eri.ours, &eri.his, eri.transport_proto);

                    if (bs_pp != NULL)
                    {
                        struct bare_shunt *bs = *bs_pp;

                        if (eri.count != bs->count)
                        {
                            bs->count = eri.count;
                            bs->last_activity = nw;
                        }
                        else if (nw - bs->last_activity > SHUNT_PATIENCE)
                        {
                            eri.next = expired;
                            expired = clone_thing(eri, "expired %pass");
                        }
                    }
                }
                break;

            case SPI_TRAP:
                break;

            default:
                bad_case(ntohl(eri.said.spi));
            }
        }
        else
        {
            /* regular (non-shunt) eroute */
            state_eroute_usage(&eri.ours, &eri.his, eri.count, nw);
        }
    }   /* for each line */
    fclose(f);

    /* Now that we've finished processing the /proc file,
     * it is safe to delete the expired %pass shunts.
     */
    while (expired != NULL)
    {
        struct eroute_info *p = expired;
        ip_address src, dst;

        networkof(&p->ours, &src);
        networkof(&p->his, &dst);
        (void) replace_bare_shunt(&src, &dst
            , BOTTOM_PRIO       /* not used because we are deleting.  This value is a filler */
            , SPI_PASS  /* not used because we are deleting.  This value is a filler */
            , FALSE, p->transport_proto, "delete expired bare shunts");
        expired = p->next;
        pfree(p);
    }
}

/* Check if there was traffic on given SA during the last idle_max
 * seconds. If TRUE, the SA was idle and DPD exchange should be performed.
 * If FALSE, DPD is not necessary. We also return TRUE for errors, as they
 * could mean that the SA is broken and needs to be replace anyway.
 */
bool pfkey_was_eroute_idle(struct state *st, time_t idle_max)
{
        static const char procname[] = "/proc/net/ipsec_spi";
        FILE *f;
        char buf[1024];
        int ret = TRUE;

        passert(st != NULL);
 
        f = fopen(procname, "r");
        if(f == NULL) { /** Can't open the file, perhaps were are on 26sec? */
                ret = TRUE;
        } else {
           while(f != NULL) {
                char *line;
                char text_said[SATOT_BUF];
                u_int8_t proto = 0;
                ip_address dst;
                ip_said said;
                ipsec_spi_t spi = 0;
                static const char idle[] = "idle=";
                time_t idle_time; /* idle time we read from /proc */
        
                dst = st->st_connection->spd.this.host_addr; /* inbound SA */
                if(st->st_ah.present) {
                        proto = SA_AH;
                        spi = st->st_ah.our_spi;
                }
                if(st->st_esp.present) {
                        proto = SA_ESP;
                        spi = st->st_esp.our_spi;  
                }
        
                if(proto == 0 && spi == 0) {
                        ret = TRUE;

                        break;
                }
                 
                initsaid(&dst, spi, proto, &said);
                satot(&said, 'x', text_said, SATOT_BUF);
                        
                line = fgets(buf, sizeof(buf), f);
                if(line == NULL) { /* Reached end of list */
                        ret = TRUE;
                        break;
                }
                 
                if(strncmp(line, text_said, strlen(text_said)) == 0) {
                        /* we found a match, now try to find idle= */
                        char *p = strstr(line, idle);   
                        if(p == NULL) { /* SAs which haven't been used yet
                                         don't have it */
                                ret = TRUE; /* it didn't have traffic */
                                break;
                        }
                        p += sizeof(idle)-1;
                        if(*p == '\0') {
                                ret = TRUE; /* be paranoid */
                                break;
                        }
			{
			    int idle_time_int;

			    if(sscanf(p, "%d", &idle_time_int) <= 0) {
                                ret = TRUE;
                                break;
			    }
			    idle_time = idle_time_int;
			}
                        if(idle_time > idle_max) {
                               DBG(DBG_KLIPS,
                                DBG_log("SA %s found idle for more than %ld sec",
                                        text_said, idle_max));
                                ret = TRUE;
                                break;
                        }
                        else {
                                ret = FALSE;
                                break;
                        }

                }
                                
           }
           fclose(f);
	}
        return ret;
}

void pfkey_set_debug(int cur_debug
		     , openswan_keying_debug_func_t debug_func
		     , openswan_keying_debug_func_t error_func)
{
    pfkey_lib_debug = (cur_debug&DBG_PFKEY ?
		       PF_KEY_DEBUG_PARSE_MAX : PF_KEY_DEBUG_PARSE_NONE);
    
    pfkey_debug_func = debug_func;
    pfkey_error_func = error_func;
}

void pfkey_remove_orphaned_holds(int transport_proto
				 , const ip_subnet *ours
				 , const ip_subnet *his)
{
    /*
     * if present, remove from orphaned_holds list.
     * NOTE: we do this last in case ours or his is a pointer into a member.
     */
    {
        struct eroute_info **pp, *p;

        for (pp = &orphaned_holds; (p = *pp) != NULL; pp = &p->next)
        {
            if (samesubnet(ours, &p->ours)
            && samesubnet(his, &p->his)
            && transport_proto == p->transport_proto
            && portof(&ours->addr) == portof(&p->ours.addr)
            && portof(&his->addr) == portof(&p->his.addr))
            {
                *pp = p->next;
                pfree(p);
                break;
            }
        }
    }
}

#ifdef KLIPS_MAST
bool
pfkey_plumb_mast_device(int mast_dev)
{
	struct sadb_ext *extensions[K_SADB_EXT_MAX + 1];
	int error;

	pfkey_extensions_init(extensions);

	if((error = pfkey_msg_hdr_build(&extensions[0],
					K_SADB_X_PLUMBIF,
					0, 0,
					++pfkey_seq, pid))) {
		return FALSE;
	}

	if((error = pfkey_outif_build(&extensions[K_SADB_X_EXT_PLUMBIF], mast_dev))) {
		return FALSE;
	}

	if(!finish_pfkey_msg(extensions, "configure_mast_device", "", NULL)) {
		return FALSE;
	}

	
	
	return TRUE;
}
#endif



#endif /* KLIPS */

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
