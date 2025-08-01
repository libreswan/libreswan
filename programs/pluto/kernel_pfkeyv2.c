/* Interface to the PF_KEY v2 IPsec mechanism, for Libreswan
 *
 * Copyright (C)  2022  Andrew Cagney
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <https://www.gnu.org/licenses/gpl2.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <errno.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/types.h>

#include "lsw_socket.h"

#include "ip_info.h"
#include "ip_encap.h"
#include "chunk.h"
#include "hunk.h"
#include "ike_alg_integ.h"	/* for ike_alg_integ_none; */

#include "kernel.h"
#include "kernel_alg.h"
#include "kernel_sadb.h"
#include "kernel_policy.h"
#include "log.h"
#include "rnd.h"
#include "initiate.h"
#include "acquire.h"
#include "server.h"		/* for add_fd_read_listener() */
#include "ipsec_interface.h"
#include "kernel_ipsec_interface.h"

static pid_t pfkeyv2_pid;
static uint32_t pfkeyv2_seq;
static int pfkeyv2_fd;

static void pfkeyv2_process_msg(int fd, void *arg, struct logger *logger);

#define SIZEOF_SADB_ADDRESS (sizeof(struct sadb_address) + sizeof(ip_sockaddr))
#define SIZEOF_SADB_BASE sizeof(struct sadb_msg)
#define SIZEOF_SADB_IDENT sizeof(struct sadb_ident)
#define SIZEOF_SADB_KEY (sizeof(struct sadb_key) +  1024 / 8 /*key*/)
#define SIZEOF_SADB_LIFETIME sizeof(struct sadb_lifetime)
#define SIZEOF_SADB_SA sizeof(struct sadb_sa)
#define SIZEOF_SADB_SENS sizeof(struct sadb_sens)
#define SIZEOF_SADB_SPIRANGE sizeof(struct sadb_spirange)
#define SIZEOF_SADB_X_POLICY (sizeof(struct sadb_x_policy) + SIZEOF_SADB_X_IPSECREQUEST * 2)
#define SIZEOF_SADB_X_SA2 sizeof(struct sadb_x_sa2)
#define SIZEOF_SADB_X_IPSECREQUEST (sizeof(struct sadb_x_ipsecrequest) + SIZEOF_SADB_ADDRESS * 2)
#define SIZEOF_SADB_X_SA_REPLAY sizeof(struct sadb_x_sa_replay) /* FreeBSD */
#define SIZEOF_SADB_PROTOCOL (sizeof(struct sadb_protocol)) /* OpenBSD */
#define SIZEOF_SADB_X_UDPENCAP (sizeof(struct sadb_x_udpencap)) /* OpenBSD */
#define SIZEOF_SADB_X_IFACE (sizeof(struct sadb_x_iface)) /* OpenBSD */

struct outbuf {
	const char *what;
	chunk_t buf;
	unsigned seq;
	const struct logger *logger;
	struct sadb_msg *base;
	/* cursor */
	void *ptr;
	size_t len;
};

static void ldbg_outbuf(struct verbose verbose, struct outbuf *msg)
{
	vdbg("msg: %p + %zu = %p + %zu = %p",
	     msg->buf.ptr, (msg->ptr - (void*)msg->buf.ptr),
	     msg->ptr, msg->len,
	     (msg->ptr + msg->len));
	vassert((msg->ptr + msg->len) == (msg->buf.ptr + msg->buf.len));
}

static size_t msg_len(const void *start, struct outbuf *msg)
{
	return (msg->ptr - start) / sizeof (uint64_t);
}

/*
 * Build and emit structures.
 *
 * - the *_INIT macros exist because remembering to correctly
 *   initializing .TYPE##_len is a pain
 *
 * - the *_INIT expand to the structures contents, and not the the
 *   brace wrapped structure because it ends up expanding MACRO({ a,
 *   b, c}) and that confuses the compiler, sigh.
 *
 * - it's assumed that, at all times, the chunk has correct memory
 *   alignment; that holds for pfkeyV2
 */

#define SADB_INIT(TYPE, ...)						\
	.TYPE##_len = sizeof(struct TYPE) / sizeof(uint64_t),		\
		##__VA_ARGS__						\

#define SADB_EXT_INIT(TYPE, EXTTYPE, ...)				\
	SADB_INIT(TYPE, .TYPE##_exttype = EXTTYPE, ##__VA_ARGS__)

#define put_sadb_struct(MSG, TYPE, ...)					\
	({								\
		struct TYPE ps_thing_ = { __VA_ARGS__ };		\
		struct outbuf *ps_req_ = MSG;				\
		struct TYPE *ps_ptr_ = hunk_put_thing(ps_req_, ps_thing_); \
		if (verbose.stream != NO_STREAM) {			\
			verbose("put %s ...", ps_req_->what);		\
			verbose.level++;				\
			llog_##TYPE(verbose, ps_req_->base, ps_ptr_);	\
			verbose.level--;				\
		}							\
		ps_ptr_;						\
	})

#define put_sadb(MSG, TYPE, ...)					\
	put_sadb_struct(MSG, TYPE, SADB_INIT(TYPE, __VA_ARGS__))

#define padup_sadb(MSG, NAME)						\
	({								\
		struct outbuf *req_ = MSG; /* eval once */		\
		/* ASSUME TYPE and VARIABLE have same name! */		\
		struct sadb_##NAME *ext_ = NAME; /* eval once */	\
		/* pad to 64-bit boundary */				\
		unsigned pad_ = req_->len % sizeof(uint64_t);		\
		req_->ptr += pad_;					\
		req_->len -= pad_;					\
		/* XXX: pexpect ..._len == sizeof(TYPE) */		\
		ext_->sadb_##NAME##_len = msg_len(ext_, req_);		\
		if (verbose.stream != NO_STREAM) {			\
			verbose("padup %s ...", req_->what);		\
			verbose.level++;				\
			llog_sadb_##NAME(verbose, req_->base, NAME);	\
			verbose.level--;				\
		}							\
	})

#define put_sadb_ext(REQ, TYPE, EXTTYPE, ...)				\
	put_sadb_struct(REQ, TYPE, SADB_EXT_INIT(TYPE, EXTTYPE, __VA_ARGS__))

struct pending {
	chunk_t msg;
	struct list_entry entry;
};

static size_t jam_pending(struct jambuf *buf, const struct pending *pending)
{
	return jam(buf, "%p", pending);
}

LIST_INFO(pending, entry, pending_info, jam_pending);

static struct list_head pending_queue = INIT_LIST_HEAD(&pending_queue, &pending_info);

struct inbuf {
	const char *what;
	shunk_t buf;
	shunk_t msg_cursor;
	shunk_t base_cursor;
	const struct sadb_msg *base;
	uint8_t buffer[65536];
};

static void queue_msg(const struct inbuf *msg)
{
	struct pending *pending = alloc_thing(struct pending, __func__);
	/* assume MSG still points at the entire buffer */
	pending->msg = clone_hunk(msg->buf, __func__);
	init_list_entry(&pending_info, pending, &pending->entry);
	insert_list_entry(&pending_queue, &pending->entry);
}

static bool recv_msg(struct inbuf *msg, const char *what, struct verbose verbose)
{
	*msg = (struct inbuf) { .what = what, };
	ssize_t s = recv(pfkeyv2_fd, msg->buffer, sizeof(msg->buffer), /*flags*/0);
	if (s < 0) {
		llog_errno(RC_LOG, verbose.logger, errno,
			   "receiving %s response: ", what);
		return false;
	}

	verbose("read %zd bytes for %s", s, msg->what);
	verbose.level++;

	msg->buf = shunk2(msg->buffer, s);
	llog_sadb(verbose, msg->buf);

	return true;
}

static bool msg_recv(struct inbuf *msg, const char *what, const struct sadb_msg *req,
		     struct verbose verbose)
{
	verbose("in %s() receiving message for %s", __func__, what);
	verbose.level++;

	while (true) {
		if (!recv_msg(msg, what, verbose)) {
			return false;
		}

		msg->msg_cursor = shunk2(msg->buf.ptr, msg->buf.len);
		msg->base = get_sadb_msg(&msg->msg_cursor, &msg->base_cursor, verbose);
		if (msg->base == NULL) {
			llog_pexpect(verbose.logger, HERE, "no base");
			return false;
		}

		if (msg->base->sadb_msg_seq == 0) {
			/* flip verbose to RC_LOG */
			struct verbose log = {
				.logger = verbose.logger,
				.stream = RC_LOG,
			};
			llog(RC_LOG, log.logger,
			     "ignoring message with sequence number 0:");
			log.level++;
			llog_sadb(log, msg->buf);
			/* XXX: need to trigger event */
			queue_msg(msg);
			continue;
		}

		if (msg->base->sadb_msg_seq != req->sadb_msg_seq) {
			/* flip verbose to rc_log */
			struct verbose log = {
				.logger = verbose.logger,
				.stream = RC_LOG,
			};
			llog(RC_LOG, log.logger,
			     "ignoring message with incorrect sequence number %u, expecting %u:",
			     msg->base->sadb_msg_seq, req->sadb_msg_seq);
			log.level++;
			llog_sadb(log, msg->buf);
			/* XXX: need to trigger event */
			queue_msg(msg);
			continue;
		}

		/*
		 * XXX: update when SA expired?
		 */
		if (msg->base->sadb_msg_errno == ENOENT) {
			llog_pexpect(verbose.logger, HERE, "ENOENT returned");
			return true;
		}

		if (msg->base->sadb_msg_errno != 0) {
			llog_errno(RC_LOG, verbose.logger, msg->base->sadb_msg_errno, "bad response: ");
			return false;
		}

		return true;
	}
}

static bool msg_sendrecv(struct outbuf *req, struct inbuf *recv,
			 struct verbose verbose)
{
	verbose("in %s()", __func__);
	verbose.level++;

	struct sadb_msg *msg = req->base;
	padup_sadb(req, msg);
	llog_sadb(verbose, HUNK_AS_SHUNK(req->buf));

	ssize_t s = send(pfkeyv2_fd, req->buf.ptr, req->ptr - (void*)req->buf.ptr, 0);
	if (s < 0) {
		vfatal(PLUTO_EXIT_KERNEL_FAIL, errno, "sending %s", req->what);
		return false;
	}

	return msg_recv(recv, req->what, msg, verbose);
}

static struct sadb_msg *put_sadb_base(struct outbuf *msg,
				      enum sadb_type type,
				      enum sadb_satype satype,
				      unsigned seq,
				      struct verbose verbose)
{
	verbose("%s", __func__);
	verbose.level++;

	struct sadb_msg *base = put_sadb(msg, sadb_msg,
					 .sadb_msg_version = PF_KEY_V2,
					 .sadb_msg_type = type,
					 .sadb_msg_errno = 0,
					 .sadb_msg_satype = satype,
					 .sadb_msg_seq = seq,
					 .sadb_msg_pid = pfkeyv2_pid);
	return base;
}

static struct sadb_sa *put_sadb_sa(struct outbuf *msg,
				   ipsec_spi_t spi,
				   enum sadb_satype satype,
				   enum sadb_sastate sastate,
				   unsigned replay_window,
				   unsigned saflags,
				   const struct integ_desc *integ,
				   const struct encrypt_desc *encrypt,
				   const struct ipcomp_desc *ipcomp,
				   struct verbose verbose)
{
	verbose("in %s() ...", __func__);
	verbose.level++;

	unsigned aalg = (integ == &ike_alg_integ_none && encrypt_desc_is_aead(encrypt) ? SADB_AALG_NONE :
			 integ != NULL ? integ->integ_sadb_aalg_id :
			 0);

	unsigned ealg = (encrypt != NULL ? encrypt->encrypt_sadb_ealg_id :
			 /* XXX: NetBSD treats IPCOMP like ENCRYPT */
			 ipcomp != NULL ? ipcomp->ipcomp_sadb_calg_id : 0);

	struct sadb_sa tmp = {
		SADB_EXT_INIT(sadb_sa, SADB_EXT_SA,
			      .sadb_sa_replay = replay_window,
			      .sadb_sa_state = sastate,
			      .sadb_sa_flags = saflags,
			      .sadb_sa_spi = spi,
			      .sadb_sa_auth = aalg,
			      .sadb_sa_encrypt = ealg),
	};
	struct sadb_sa *sa = hunk_put_thing(msg, tmp);
	llog_sadb_sa(verbose, msg->base, satype, sa);
	return sa;
}

static struct sockaddr *put_address_sockaddr(struct outbuf *msg,
					     const ip_address addr)
{
	ip_sockaddr sa = sockaddr_from_address(addr);
	return hunk_put(msg, &sa.sa.sa, sa.len);
}

/*
 * XXX: OpenBSD uses address+mask, instead of address/prefixlen;
 * protocol and prefix length were dropped from the structure.
 *
 * Ulgh!
 */
#ifdef sadb_address_prefixlen /* NetBSD FreeBSD */
static struct sadb_address *put_sadb_selector(struct outbuf *msg,
					      enum sadb_exttype srcdst_exttype,
					      const ip_selector selector,
					      struct verbose verbose)
{
	const struct ip_protocol *protocol = selector_protocol(selector);
	enum ipsec_proto proto = (protocol == &ip_protocol_all ? IPSEC_PROTO_ANY/*255*/ :
				  protocol != NULL ? protocol->ipproto :
				  pexpect(0));
	ip_address prefix = selector_prefix(selector);
	unsigned prefix_len = selector_prefix_len(selector);
	struct sadb_address *address =
		put_sadb_ext(msg, sadb_address, srcdst_exttype,
			     .sadb_address_proto = proto,
			     .sadb_address_prefixlen = prefix_len);
	put_address_sockaddr(msg, prefix);
	padup_sadb(msg, address);
	return address;
}
#endif

static struct sadb_address *put_sadb_address(struct outbuf *msg,
					     enum sadb_exttype srcdst_exttype,
					     const ip_address addr,
					     struct verbose verbose)
{
#ifdef sadb_address_prefixlen /* NetBSD FreeBSD */
	const struct ip_info *afi = address_info(addr);
	struct sadb_address *address =
		put_sadb_ext(msg, sadb_address, srcdst_exttype,
			     .sadb_address_proto = IPSEC_PROTO_ANY/*255*/,
			     .sadb_address_prefixlen = afi->mask_cnt);
#else /* OpenBSD */
	/*
	 * XXX: OpenBSD uses address+mask, instead of
	 * address/prefixlen; protocol and prefix length were dropped
	 * from the structure.
	 *
	 * Ulgh!
	 */
	struct sadb_address *address =
		put_sadb_ext(msg, sadb_address, srcdst_exttype);
#endif
	put_address_sockaddr(msg, addr);
	padup_sadb(msg, address);
	return address;
}

/*
 * XXX: the BSDs embed the host's port (when UDP) in the SA/SADB host
 * address.
 */

#if 0
static struct sockaddr *put_endpoint_sockaddr(struct outbuf *msg,
					      const ip_endpoint endpoint)
{
}

static struct sadb_address *put_sadb_endpoint(struct outbuf *msg,
					      enum sadb_exttype srcdst_exttype,
					      const ip_endpoint endpoint)
{
	pexpect(srcdst_exttype == SADB_EXT_ADDRESS_SRC ||
		srcdst_exttype == SADB_EXT_ADDRESS_DST);
	const struct ip_info *afi = endpoint_info(endpoint);
#ifdef sadb_address_prefixlen
	struct sadb_address *address =
		put_sadb_ext(msg, sadb_address, srcdst_exttype,
			     .sadb_address_proto = IPSEC_PROTO_ANY/*255*/,
			     .sadb_address_prefixlen = afi->mask_cnt);
#else
	/*
	 * XXX: OpenBSD uses address+mask, instead of
	 * address/prefixlen; protocol and prefix length were dropped
	 * from the structure.
	 *
	 * Ulgh!
	 */
	struct sadb_address *address =
		put_sadb_ext(msg, sadb_address, srcdst_exttype);
#endif
	put_endpoint_sockaddr(msg, endpoint);
	padup_sadb(msg, address);
	return address;
}
#endif

static struct sadb_key *put_sadb_key(struct outbuf *msg,
				     enum sadb_exttype key_alg,
				     shunk_t keyval,
				     struct verbose verbose)
{
	verbose("in %s() ...", __func__);
	verbose.level++;

	struct sadb_key *key =
		put_sadb_ext(msg, sadb_key, key_alg,
			     .sadb_key_bits = keyval.len * BITS_IN_BYTE);
	if (hunk_put_hunk(msg, keyval) == NULL) {
		llog_passert(verbose.logger, HERE, "bad key(E)");
	}
	padup_sadb(msg, key);
	return key;
}

static struct sadb_spirange *put_sadb_spirange(struct outbuf *msg, uintmax_t min, uintmax_t max,
					       struct verbose verbose)
{
	verbose("in %s() ...", __func__);
	verbose.level++;

	struct sadb_spirange *spirange =
		put_sadb_ext(msg, sadb_spirange, SADB_EXT_SPIRANGE,
			     .sadb_spirange_min = min,
			     .sadb_spirange_max = max);
	return spirange;
}

#ifdef SADB_X_EXT_SA2 /* FreeBSD NetBSD */
static struct sadb_x_sa2 *put_sadb_x_sa2(struct outbuf *msg,
					 enum ipsec_mode ipsec_mode,
					 reqid_t reqid,
					 struct verbose verbose)
{
	verbose("in %s() ...", __func__);
	verbose.level++;

	struct sadb_x_sa2 *x_sa2 =
		put_sadb_ext(msg, sadb_x_sa2, SADB_X_EXT_SA2,
			     .sadb_x_sa2_mode = ipsec_mode,
			     .sadb_x_sa2_sequence = 0,/*SPD sequence?*/
			     .sadb_x_sa2_reqid = reqid);
	return x_sa2;
}
#endif

static void msg_base(struct verbose verbose, struct outbuf *msg, const char *what,
		     chunk_t buf, enum sadb_type type,
		     enum sadb_satype satype)
{
	*msg = (struct outbuf) {
		.buf = buf,
		.ptr = buf.ptr,
		.len = buf.len,
		.what = what,
		.seq = ++pfkeyv2_seq,
		.logger = verbose.logger,
	};
	ldbg_outbuf(verbose, msg);
	msg->base = put_sadb_base(msg, type, satype, msg->seq, verbose);
}

static bool sadb_base_sendrecv(struct inbuf *resp,
			      enum sadb_type type,
			      enum sadb_satype satype,
			      struct verbose verbose)
{
	verbose("in %s() ...", __func__);
	verbose.level++;

	uint8_t reqbuf[SIZEOF_SADB_BASE];
	struct outbuf req;
	msg_base(verbose, &req, __func__,
		 chunk2(reqbuf, sizeof(reqbuf)),
		 type, satype);
	return msg_sendrecv(&req, resp, verbose);
}

static enum sadb_satype sadb_satype_from_protocol(const struct ip_protocol *proto)
{
	return (proto == &ip_protocol_esp ? SADB_SATYPE_ESP :
		proto == &ip_protocol_ah ? SADB_SATYPE_AH :
		proto == &ip_protocol_ipcomp ? SADB_X_SATYPE_IPCOMP :
		pexpect(0));
}

static bool register_alg(const struct sadb_msg *b,
			 shunk_t *msgext, const struct ike_alg_type *type,
			 struct verbose verbose)
{
	verbose("in %s() ...", __func__);
	verbose.level++;

	const struct sadb_supported *supported =
		hunk_get_thing(msgext, const struct sadb_supported);
	if (supported == NULL) {
		llog_pexpect(verbose.logger, HERE, "bad ext");
		return false;
	}

	llog_sadb_supported(verbose, b, supported);
	verbose.level++;

	unsigned nr_algs = ((supported->sadb_supported_len * sizeof(uint64_t) -
			     sizeof(struct sadb_supported)) / sizeof(struct sadb_alg));
	for (unsigned n = 0; n < nr_algs; n++) {

		const struct sadb_alg *alg =
			hunk_get_thing(msgext, const struct sadb_alg);
		if (alg == NULL) {
			llog_pexpect(verbose.logger, HERE, "bad ext");
			return false;
		}

		enum sadb_exttype exttype = supported->sadb_supported_exttype;
		llog_sadb_alg(verbose, b, exttype, alg);

		const struct ike_alg *ike_alg = ike_alg_by_sadb_alg_id(type, alg->sadb_alg_id);
		if (ike_alg != NULL) {
			kernel_alg_add(ike_alg);
		} else {
			vdbg("%s algorithm %d not recognized",
			     ike_alg_type_name(type),
			     alg->sadb_alg_id);
		}
	}
	return true;
}

static void register_satype(const struct ip_protocol *protocol, struct verbose verbose)
{
	verbose("in %s() sending %s request", __func__, protocol->name);
	verbose.level++;

	struct inbuf resp;
	if (!sadb_base_sendrecv(&resp, SADB_REGISTER,
				sadb_satype_from_protocol(protocol),
				verbose)) {
		return;
	}

	while (resp.base_cursor.len > 0) {

		shunk_t msgext;
		const struct sadb_ext *ext =
			get_sadb_ext(&resp.base_cursor, &msgext, verbose);
		if (ext == NULL) {
			llog_pexpect(verbose.logger, HERE, "bad ext");
			return;
		}

		enum sadb_exttype exttype = ext->sadb_ext_type;
		switch (exttype) {
		case SADB_EXT_SUPPORTED_AUTH:
			if (!register_alg(resp.base, &msgext, &ike_alg_integ, verbose)) {
				/* already logged */
				return;
			}
			break;
		case SADB_EXT_SUPPORTED_ENCRYPT:
			if (!register_alg(resp.base, &msgext, &ike_alg_encrypt, verbose)) {
				/* already logged */
				return;
			}
			break;
#ifdef SADB_X_EXT_SUPPORTED_COMP /* OpenBSD */
		case SADB_X_EXT_SUPPORTED_COMP:
			/*
			 * Handle COMP algorithms:
			 *
			 * + the original RFC 2367 makes no reference
			 * to compression, if it had been included it
			 * would have looked something like this.
			 *
			 * However, it's worth noting:
			 *
			 * + there's really only ever been one
			 * compression algorithm
			 *
			 * + using compression with IPsec has fallen
			 * out of favour (the benefit is marginal;
			 * it's not well tested on either Linux or
			 * [*]BSD)
			 */
			if (!register_alg(resp.base, &msgext, &ike_alg_ipcomp, verbose)) {
				/* already logged */
				return;
			}
			break;
#endif
		default:
			llog_pexpect(verbose.logger, HERE, "unknown ext");
			break;
		}
	}
}

static void kernel_pfkeyv2_init(struct logger *logger)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, logger, NULL);
	vdbg("initializing PFKEY V2");
	verbose.level++;

	pfkeyv2_pid = getpid();

	/* initialize everything */
	pfkeyv2_fd = cloexec_socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
	if (pfkeyv2_fd < 0) {
		fatal(PLUTO_EXIT_KERNEL_FAIL, logger, errno, "opening PF_KEY_V2 socket failed");
	}
	/* server.c will close this */
	add_fd_read_listener(pfkeyv2_fd, "pfkey v2 messages",
			     pfkeyv2_process_msg, NULL);
	vdbg("pfkey opened on %d with CLOEXEC", pfkeyv2_fd);

	/* register everything */

	register_satype(&ip_protocol_ah, verbose);
	register_satype(&ip_protocol_esp, verbose);
	register_satype(&ip_protocol_ipcomp, verbose);
}

static void kernel_pfkeyv2_flush(struct logger *logger)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, logger, NULL);
	vdbg("flushing");
	verbose.level++;

	struct inbuf resp;
	sadb_base_sendrecv(&resp, SADB_FLUSH, SADB_SATYPE_UNSPEC, verbose);
#ifdef SADB_X_SPDFLUSH /* FreeBSD NetBSD */
	sadb_base_sendrecv(&resp, SADB_X_SPDFLUSH, SADB_SATYPE_UNSPEC, verbose);
#else /* OpenBSD */
	vlog("OpenBSD SADB_FLUSH does everything; SADB_X_SPDFLUSH not needed");
#endif
}

static void kernel_pfkeyv2_poke_holes(struct logger *logger)
{
	ldbg(logger, "does PFKEY need to poke holes in its kernel policies?");
}

static void kernel_pfkeyv2_plug_holes(struct logger *logger)
{
	ldbg(logger, "does PFKEY need to poke holes in its kernel policies?");
}

static ipsec_spi_t pfkeyv2_get_ipsec_spi(ipsec_spi_t avoid UNUSED,
					 const ip_address *src,
					 const ip_address *dst,
					 const struct ip_protocol *protocol,
					 reqid_t reqid,
					 uintmax_t min, uintmax_t max,
					 const char *story UNUSED,	/* often SAID string */
					 struct logger *logger)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, logger, NULL);
	vdbg("%s() reqid=%d ...", __func__, reqid);
	verbose.level++;

	/* GETSPI */
	/* send: <base, address, SPI range> */
	/* recv: <base, SA(*), address(SD)> */

	uint8_t reqbuf[SIZEOF_SADB_BASE +
#ifdef SADB_X_EXT_SA2 /* FreeBSD NetBSD */
		       SIZEOF_SADB_X_SA2 +
#endif
		       SIZEOF_SADB_ADDRESS * 2 +
		       SIZEOF_SADB_SPIRANGE];
	struct outbuf req;
	msg_base(verbose, &req, __func__,
		 chunk2(reqbuf, sizeof(reqbuf)),
		 SADB_GETSPI,
		 sadb_satype_from_protocol(protocol));

	/*
	 * XXX: the original PF_KEY_V2 RFC didn't leave space to
	 * specify REQID and/or transport mode (tunnel was assumed).
	 *
	 * SADB_X_SA2 provides a way to specify that (it's optional,
	 * but since the REQID is always specified, it might as well
	 * be included).
	 */

#ifdef SADB_X_EXT_SA2 /* FreeBSD NetBSD */
	put_sadb_x_sa2(&req, IPSEC_MODE_ANY, reqid, verbose);
#endif

	/* (tunnel_mode ? ipsec_mode_tunnel : ipsec_mode_transport), */

	put_sadb_address(&req, SADB_EXT_ADDRESS_SRC, *src, verbose);
	put_sadb_address(&req, SADB_EXT_ADDRESS_DST, *dst, verbose);
	put_sadb_spirange(&req, min, max, verbose);

	struct inbuf resp;
	if (!msg_sendrecv(&req, &resp, verbose)) {
		return 0;
	}

	ipsec_spi_t spi = 0;
	while (resp.base_cursor.len > 0) {

		shunk_t msgext;
		const struct sadb_ext *ext =
			get_sadb_ext(&resp.base_cursor, &msgext, verbose);
		if (msgext.ptr == NULL) {
			llog_pexpect(verbose.logger, HERE, "bad ext");
			return 0;
		}

		enum sadb_exttype exttype = ext->sadb_ext_type;
		switch (exttype) {
		case SADB_EXT_SA:
		{
			const struct sadb_sa *sa =
				hunk_get_thing(&msgext, const struct sadb_sa);
			if (sa == NULL) {
				llog_pexpect(verbose.logger, HERE, "getting sa");
				return 0;
			}
			llog_sadb_sa(verbose, resp.base, req.base->sadb_msg_satype, sa);
			spi = sa->sadb_sa_spi;
			break;
		}
		case SADB_EXT_ADDRESS_SRC:
		case SADB_EXT_ADDRESS_DST:
			/* ignore these */
			break;
		default:
			llog_pexpect(logger, HERE, "bad ext");
			break;
		}
	}
	return spi;
}

static bool pfkeyv2_del_ipsec_spi(ipsec_spi_t spi,
				  const struct ip_protocol *protocol,
				  const ip_address *src_address,
				  const ip_address *dst_address,
				  const char *story UNUSED,
				  const struct logger *logger)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, logger, NULL);
	vdbg("%s() ...", __func__);
	verbose.level++;

	/* DEL */
	/* send: <base, SA(*), address(SD)> */
	/* recv: <base, SA(*), address(SD)> */

	/* base */

	uint8_t reqbuf[SIZEOF_SADB_BASE +
		       SIZEOF_SADB_SA +
		       SIZEOF_SADB_ADDRESS * 2];
	struct outbuf req;
	msg_base(verbose, &req, __func__,
		 chunk2(reqbuf, sizeof(reqbuf)),
		 SADB_DELETE,
		 sadb_satype_from_protocol(protocol));

	/* SA(*) */

	put_sadb_sa(&req, spi, /*satype*/0, /*sastate*/0, /*replay*/0, /*saflags*/0,
		    /*integ*/NULL, /*encrypt*/NULL, /*ipcomp*/NULL, verbose);

	/* address(SD) */

	put_sadb_address(&req, SADB_EXT_ADDRESS_SRC, *src_address, verbose);
	put_sadb_address(&req, SADB_EXT_ADDRESS_DST, *dst_address, verbose);

	struct inbuf recv;
	if (!msg_sendrecv(&req, &recv, verbose)) {
		llog_pexpect(logger, HERE, "bad");
		return false;
	}

	return true;
}

static bool pfkeyv2_add_sa(const struct kernel_state *k,
			   bool replace,
			   const struct logger *logger)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, logger, NULL);
	vdbg("%s() ...", __func__);
	verbose.level++;

	/* UPDATE <base, SA, (lifetime(HSC),) address(SD),
	   (address(P),) key(AE), (identity(SD),) (sensitivity)> */
	/* ADD <base, SA, (lifetime(HS),) address(SD), (address(P),)
	   key(AE), (identity(SD),) (sensitivity)> */

	enum sadb_type type = (replace ? SADB_UPDATE : SADB_ADD);

	uint8_t reqbuf[SIZEOF_SADB_BASE +
		       SIZEOF_SADB_SA +
		       SIZEOF_SADB_LIFETIME * 3 +
		       SIZEOF_SADB_ADDRESS * 3 +
		       SIZEOF_SADB_KEY * 2 +
		       SIZEOF_SADB_IDENT * 2 +
#ifdef SADB_X_EXT_SA_REPLAY /* FreeBSD */
		       SIZEOF_SADB_X_SA_REPLAY +
#endif
#ifdef SADB_X_EXT_UDPENCAP /* OpenBSD */
		       SIZEOF_SADB_X_UDPENCAP +
#endif
#ifdef SADB_X_EXT_IFACE
		       SIZEOF_SADB_X_IFACE +
#endif
		       SIZEOF_SADB_SENS +
		       0];
	struct outbuf req;
	msg_base(verbose, &req, __func__,
		 chunk2(reqbuf, sizeof(reqbuf)),
		 type,
		 sadb_satype_from_protocol(k->proto));

	/* SA */

	unsigned saflags = 0;
#ifdef SADB_X_SAFLAGS_ESN /* FreeBSD OpenBSD */
	/*
	 * Both FreeBSD and OpenBSD support the ESN flag.
	 */
	if (k->esn) {
		saflags |= SADB_X_SAFLAGS_ESN;
	}
#endif
#ifdef SADB_X_SAFLAGS_TUNNEL /* OpenBSD */
	/*
	 * FreeBSD and NetBSD use a field in SADB_SA2 to convey this
	 * information.
	 *
	 * OpenBSD instead uses this bit.
	 */
	if (k->mode == KERNEL_MODE_TUNNEL) {
		saflags |= SADB_X_SAFLAGS_TUNNEL;
	}
#endif
#ifdef SADB_X_EXT_UDPENCAP /* OpenBSD */
	/*
	 * NetBSD and FreeBSD, like Linux, call setsockopt
	 * UDP_ENCAP_ESPINUDP on the IKE UDP socket when it is first
	 * opened/accepted.
	 *
	 * -> this means that the socket is always in UDPENCAP mode;
	 *    presumably the non-ESP marker doesn't change (always
	 *    stripped)
	 *
	 * OpenBSD instead uses the UDPENCAP bit when adding the SA to
	 * the kernel.
	 *
	 * -> this means that the kernel only finds out that the
	 *    socket is UDPENCAP when the SA is added; does this mean
	 *    that non-ESP marker handling changes?
	 */
	if (k->encap_type == &ip_encap_esp_in_udp) {
		saflags |= SADB_X_SAFLAGS_UDPENCAP;
	}
#endif

	/*
	 * Determine the size of the replay window:
	 *
	 * -> the field kernel_state .replay_window is the size of the
	 *    replay window in packets
	 *
	 * -> PF KEY v2's .sadb_sa_replay is the number of bytes
	 *    needed to store the register window bit-mask (one bit
	 *    per-packet)
	 *
	 *    FreeBSD's setkey describes it as "one eighth of the
	 *    anti-replay window size in packets".
	 *
	 * Hence the strange conversion below.
	 *
	 * What about a replay window larger than UINT8_MAX*8 (~2k
	 * packets)?
	 *
	 * FreeBSD:
	 *
	 *   Supports both the original .sadb_sa_replay and the
	 *   SADB_X_EXT_SA_REPLAY extension.  When .replay_window
	 *   exceeds UINT8_MAX*8, .sadb_sa_replay is set to UINT8_MAX
	 *   and a SADB_X_EXT_SA_REPLAY payload is added containing
	 *   .replay_window (in packets not bytes).
	 *
	 * NetBSD:
	 *
	 *   Supports the original .sadb_sa_replay.
	 *
	 * OpenBSD:
	 *
	 *   Supports the original .sadb_sa_replay.  The kernel
	 *   enforces an additional hardwired limit of 64 (*8).  Also,
	 *   on the way in, IKED hardwires the value to 65(*8),
	 *   IPSECCTL can't set the value at all, but ISAKMPD does
	 *   have a parameter.
	 *
	 *   Note: OpenBSD defines SADB_X_EXT_REPLAY but it has
	 *   nothing to do with this code.  It seems to be used by the
	 *   kernel to return the number of replays that were
	 *   detected.
	 */
	unsigned bytes_for_replay_window = BYTES_FOR_BITS(k->replay_window);
	unsigned saturated_bytes_for_replay_window =
		(bytes_for_replay_window > UINT8_MAX ? UINT8_MAX : bytes_for_replay_window);

	put_sadb_sa(&req, k->spi,
		    req.base->sadb_msg_satype,
		    SADB_SASTATE_MATURE,
		    /*sadb_sa_replay*/saturated_bytes_for_replay_window,
		    saflags,
		    k->integ, k->encrypt, k->ipcomp,
		    verbose);

	/*
	 * X_SA2
	 *
	 * This is needed to specify the stuff that should have been
	 * included in SA, notably tunnel vs transport and reqid
	 *
	 * Tunnel only applies to the inner most encapsulation.
	 * Right?  Why?  Which means it applies to the packet
	 * interface.
	 *
	 * XXX: why not just set "tunnel" on the inner-most kernel_sa?
	 */

#ifdef SADB_X_EXT_SA2 /* FreeBSD NetBSD */
	put_sadb_x_sa2(&req, IPSEC_MODE_ANY, k->reqid, verbose);
#endif

	/*
	 * address(SD)
	 *
	 * -> OpenBSD passes the UDP encapsulated destination port
	 *    using SADB_X_EXT_UDPENCAP; there doesn't seem to be a
	 *    way to pass the source port.
	 *
	 * -> Linux passes the UDP encapsulated source and destination
	 *    ports using using XFRMA_ENCAP.
	 *
	 * -> NetBSD, FreeBSD, and OpenBSD(?) can handle the address
	 *    including the port.
	 */
	put_sadb_address(&req, SADB_EXT_ADDRESS_SRC, k->src.address, verbose);
	put_sadb_address(&req, SADB_EXT_ADDRESS_DST, k->dst.address, verbose);

	/* (address(P)) */

	/* key(AE[C]) (AUTH/INTEG/ENCRYPT/IPCOMP) */

	if (k->integ_key.len > 0) {
		put_sadb_key(&req, SADB_EXT_KEY_AUTH, k->integ_key, verbose);
	}
	if (k->encrypt_key.len > 0) {
		put_sadb_key(&req, SADB_EXT_KEY_ENCRYPT, k->encrypt_key, verbose);
	}

	/* (lifetime(HSC)) */

	put_sadb_ext(&req, sadb_lifetime, SADB_EXT_LIFETIME_HARD,
		     .sadb_lifetime_addtime = deltasecs(k->sa_lifetime));
	put_sadb_ext(&req, sadb_lifetime, SADB_EXT_LIFETIME_SOFT,
		     .sadb_lifetime_addtime =  deltasecs(k->sa_lifetime));

	/* (identity(SD)) */

	/* (sensitivity) */

	/* replay (extended mix) */

#ifdef SADB_X_EXT_SA_REPLAY /* FreeBSD */
	/*
	 * Per-above, only emit this when .sadb_sa_replay isn't big
	 * enough (it's pretty big at 2k, Linux caps things to 4k).
	 *
	 * Unlike .sadb_sa_replay which is in bytes (8 packets per
	 * byte), .sadb_x_ext_sa_replay_replay is in packets - no
	 * conversion is required (FreeBSD's kernel converts the packet
	 * value back to bytes internally).
	 */
	if (bytes_for_replay_window > UINT8_MAX) {
		/* The -32 comes from FreeBSD!?! */
		pexpect(k->replay_window <= (UINT32_MAX - 32));
		put_sadb_ext(&req, sadb_x_sa_replay, sadb_x_ext_sa_replay,
			     .sadb_x_sa_replay_replay = k->replay_window);
	}
#endif

	/* udpencap (continued) */

#ifdef SADB_X_EXT_UDPENCAP /* OpenBSD */
	/*
	 * OpenBSD: This mechanism only provides a way to specify the
	 * destination port.  The source port is fixed at 4500 (or
	 * what ever is configured in the kernel).
	 *
	 * Linux's XFRMA_ENCAP includes both the source and
	 * destination port.
	 *
	 * FreeBSD and NetBSD do what?  It looks like they provide
	 * SADB_X_EXT_NAT_T_[SD]PORT and expect the SA/SPD host
	 * addresses to also include the port and protocol?
	 */
	if (k->encap_type == &ip_encap_esp_in_udp) {
		if (k->src.encap_port != 4500) {
			llog(RC_LOG, logger,
			     "SADB_X_EXT_UDPENCAP assumes the source port is 4500, not %d",
			     k->src.encap_port);
		}
		put_sadb_ext(&req, sadb_x_udpencap, sadb_x_ext_udpencap,
			     .sadb_x_udpencap_port = htons(k->dst.encap_port));
	}
#endif

#ifdef SADB_X_EXT_IFACE
	if (k->ipsec_interface != NULL) {
		unsigned ipsec_if_index = if_nametoindex(k->ipsec_interface->name);
		if (ipsec_if_index == 0) {
			llog_errno(RC_LOG, logger, errno,
				   "invalid ipsec-interface %s: ",
				   k->ipsec_interface->name);
		} else {
			enum ipsp_direction direction;
			switch (k->direction) {
			case DIRECTION_INBOUND: direction = ipsp_direction_in; break;
			case DIRECTION_OUTBOUND: direction = ipsp_direction_out; break;
			default:
				bad_case(k->direction);
			}
			put_sadb_ext(&req, sadb_x_iface, sadb_x_ext_iface,

				     .sadb_x_iface_unit = k->ipsec_interface->if_id,
				     .sadb_x_iface_direction = direction);
		}
	}
#endif

	/* UPDATE */
        /* <base, SA, (lifetime(HSC),) address(SD), (address(P),)
	   (identity(SD),) (sensitivity)> */
	/* ADD */
	/* <base, SA, (lifetime(HS),) address(SD), (identity(SD),)
	   (sensitivity)> */

	struct inbuf recv;
	if (!msg_sendrecv(&req, &recv, verbose)) {
		llog_pexpect(logger, HERE, "bad");
		return false;
	}

	return true;
}

static bool pfkeyv2_get_kernel_state(const struct kernel_state *k,
				     uint64_t *bytes,
				     uint64_t *add_time,
				     uint64_t *lastused UNUSED,
				     struct logger *logger)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, logger, NULL);
	vdbg("%s() ...", __func__);
	verbose.level++;

	/* GET */
	/* <base, SA(*), address(SD)> */
	/* <base, SA, (lifetime(HSC),) address(SD), (address(P),) key(AE),
           (identity(SD),) (sensitivity)> */

	/* <base> */

	uint8_t reqbuf[SIZEOF_SADB_BASE +
		       SIZEOF_SADB_SA +
		       SIZEOF_SADB_ADDRESS * 2];
	struct outbuf req;
	msg_base(verbose, &req, __func__,
		 chunk2(reqbuf, sizeof(reqbuf)),
		 SADB_GET,
		 sadb_satype_from_protocol(k->proto));

	/* SA(*) */

	put_sadb_sa(&req, k->spi, /*satype*/0, /*sastate*/0, /*replay*/0, /*saflags*/0,
		    /*integ*/NULL, /*encrypt*/NULL, /*ipcomp*/NULL, verbose);

	/* address(SD) */

	put_sadb_address(&req, SADB_EXT_ADDRESS_SRC, k->src.address, verbose);
	put_sadb_address(&req, SADB_EXT_ADDRESS_DST, k->dst.address, verbose);

	struct inbuf resp;
	if (!msg_sendrecv(&req, &resp, verbose)) {
		llog_pexpect(logger, HERE, "bad");
		return false;
	}

	while (resp.base_cursor.len > 0) {

		shunk_t ext_cursor;
		const struct sadb_ext *ext =
			get_sadb_ext(&resp.base_cursor, &ext_cursor, verbose);
		if (ext_cursor.ptr == NULL) {
			llog_pexpect(verbose.logger, HERE, "bad ext");
			return false;
		}

		enum sadb_exttype exttype = ext->sadb_ext_type;
		switch (exttype) {
		case SADB_EXT_LIFETIME_CURRENT:
		{
			const struct sadb_lifetime *lifetime =
				hunk_get_thing(&ext_cursor, const struct sadb_lifetime);
			if (lifetime == NULL) {
				llog_pexpect(logger, HERE, "getting policy");
				return 0;
			}
			llog_sadb_lifetime(verbose, req.base, lifetime);
			*bytes = lifetime->sadb_lifetime_bytes;
			*add_time = lifetime->sadb_lifetime_addtime;
			break;
		}
		case SADB_EXT_ADDRESS_DST:
		case SADB_EXT_ADDRESS_SRC:
		case SADB_EXT_KEY_AUTH:
		case SADB_EXT_KEY_ENCRYPT:
		case SADB_EXT_SA:
#ifdef SADB_X_EXT_SA2 /* FreeBSD NetBSD */
		case SADB_X_EXT_SA2:
#endif
#ifdef SADB_X_EXT_NAT_T_TYPE /* FreeBSD NetBSD */
		case SADB_X_EXT_NAT_T_TYPE:
#endif
		case SADB_EXT_LIFETIME_HARD:
		case SADB_EXT_LIFETIME_SOFT:
#ifdef SADB_X_EXT_SA_REPLAY /* FreeBSD */
		case SADB_X_EXT_SA_REPLAY:
#endif
#ifdef SADB_X_EXT_LIFETIME_LASTUSE /* OpenBSD */
		case SADB_X_EXT_LIFETIME_LASTUSE:
#endif
#ifdef SADB_X_EXT_COUNTER /* OpenBSD */
		case  SADB_X_EXT_COUNTER:
#endif
#ifdef SADB_X_EXT_REPLAY /* OpenBSD */
		case SADB_X_EXT_REPLAY:
#endif
#ifdef SADB_X_EXT_IFACE /* OpenBSD */
		case SADB_X_EXT_IFACE:
#endif
			/* ignore these */
			break;
		default:
		{
			struct verbose verbose = VERBOSE(RC_LOG, logger, NULL);
			verbose("%s(), ignoring unexpected:", __func__);
			llog_sadb_ext(verbose, req.base, ext, ext_cursor);
			break;
		}
		}
	}

	return false;
}

#ifdef SADB_X_EXT_POLICY /* FreeBSD NetBSD */
static struct sadb_x_ipsecrequest *put_sadb_x_ipsecrequest(struct outbuf *msg,
							   const struct kernel_policy *kernel_policy,
							   enum ipsec_mode mode,
							   const struct kernel_policy_rule *rule)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, msg->logger, NULL);
	vdbg("%s() ...", __func__);
	verbose.level++;

	/*
	 * XXX: sadb_x_ipsecrequest screwed up the LEN parameter; it's
	 * in bytes.
	 */
	struct sadb_x_ipsecrequest *x_ipsecrequest =
		put_sadb(msg, sadb_x_ipsecrequest,
			 .sadb_x_ipsecrequest_proto = rule->proto,
			 .sadb_x_ipsecrequest_mode = mode,
			 .sadb_x_ipsecrequest_level = IPSEC_LEVEL_REQUIRE,
			 .sadb_x_ipsecrequest_reqid = /*rule->reqid*/0);
	/*
	 * setkey(8) man page says that transport mode doesn't require
	 * policy addresses (presumably the packet's address can be
	 * used).
	 *
	 * draft-schilcher-mobike-pfkey-extension-01 goes further and
	 * states: In the case that transport mode is used, no
	 * additional addresses are specified.
	 */
	if (mode == IPSEC_MODE_TUNNEL) {
		put_address_sockaddr(msg, kernel_policy->src.host);
		put_address_sockaddr(msg, kernel_policy->dst.host);
	}
	padup_sadb(msg, x_ipsecrequest);
	/* patch up mess? */
	x_ipsecrequest->sadb_x_ipsecrequest_len *= sizeof(uint64_t);
	return x_ipsecrequest;
}
#endif

#ifdef SADB_X_EXT_POLICY /* FreeBSD NetBSD */
static struct sadb_x_policy *put_sadb_x_policy(struct outbuf *req,
					       enum direction dir,
					       enum ipsec_policy policy_type,
					       enum kernel_policy_id policy_id,
					       const struct kernel_policy *kernel_policy)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, req->logger, NULL);
	vdbg("%s() ...", __func__);
	verbose.level++;

	enum ipsec_dir policy_dir = (dir == DIRECTION_INBOUND ? IPSEC_DIR_INBOUND :
				     dir == DIRECTION_OUTBOUND ? IPSEC_DIR_OUTBOUND :
				     pexpect(0));

	struct sadb_x_policy *x_policy =
		put_sadb_ext(req, sadb_x_policy, SADB_X_EXT_POLICY,
			     .sadb_x_policy_type = policy_type,
			     .sadb_x_policy_dir = policy_dir,
			     .sadb_x_policy_id = policy_id);

	if (kernel_policy != NULL) {
#ifdef sadb_x_policy_priority
		x_policy->sadb_x_policy_priority = kernel_policy->priority.value;
#endif
		if (kernel_policy->nr_rules > 0) {
			PEXPECT(req->logger, (policy_type == IPSEC_POLICY_IPSEC ||
					      policy_type == IPSEC_POLICY_DISCARD));
			/*
			 * XXX: Only the first rule gets the worm; er
			 * tunnel flag.
			 *
			 * Should the caller take care of this?
			 */
			enum ipsec_mode mode =
				(kernel_policy->mode == KERNEL_MODE_TUNNEL ? IPSEC_MODE_TUNNEL :
				 kernel_policy->mode == KERNEL_MODE_TRANSPORT ? IPSEC_MODE_TRANSPORT :
				 pexpect(0));
			for (unsigned i = 0; i < kernel_policy->nr_rules; i++) {
				const struct kernel_policy_rule *rule = &kernel_policy->rule[i];
				put_sadb_x_ipsecrequest(req, kernel_policy, mode, rule);
				mode = IPSEC_MODE_TRANSPORT;
			}
		}
	}

	padup_sadb(req, x_policy);
	return x_policy;
}
#endif

#ifdef SADB_X_EXT_POLICY
static bool parse_sadb_x_policy(struct verbose verbose, const struct sadb_msg *b,
				shunk_t *ext_cursor,
				enum kernel_policy_id *policy_id)
{
	verbose.level++;
	shunk_t policy_cursor;
	const struct sadb_x_policy *policy =
		get_sadb_x_policy(ext_cursor, &policy_cursor, verbose);
	if (policy == NULL) {
		return false;
	}
	llog_sadb_x_policy(verbose, b, policy);
	verbose.level++;
	*policy_id = policy->sadb_x_policy_id;
	return true;
}
#endif

static bool kernel_pfkeyv2_policy_add(enum kernel_policy_op op,
				      enum direction dir,
				      const ip_selector *src_client,
				      const ip_selector *dst_client,
				      const struct kernel_policy *policy,
				      deltatime_t use_lifetime UNUSED,
				      struct logger *logger, const char *func)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, logger, NULL);
	vdbg("%s() ...", func);
	verbose.level++;

	if (policy->ipsec_interface != NULL) {
		ipsec_interface_buf ifb;
		vlog("BSD doesn't add kernel-policy to an ipsec-interface (%s)",
		     str_ipsec_interface(policy->ipsec_interface, &ifb));
		return true;
	}
#ifdef __OpenBSD__

	if (policy->nr_rules > 1) {
		/*
		 * For IPcomp+ESP where two policies need to
		 * installed, OpenBSD instead: installs a flow with
		 * one policy (i guess the first); SA pairs for IPsec
		 * and ESP; bundle (SADB_X_EXT_GRPSPIs) to group the
		 * two SAs.
		 */
		llog_pexpect(verbose.logger, HERE,
			     "multiple policies using SADB_X_EXT_GRPSPIS (GRouP SPI S) not implemented");
		return false;
	}

	enum sadb_type type = (op == KERNEL_POLICY_OP_ADD ? SADB_X_ADDFLOW :
			       op == KERNEL_POLICY_OP_REPLACE ? SADB_X_ADDFLOW :
			       pexpect(0));

	enum sadb_satype satype =
		(policy->rule[0].proto == KERNEL_PROTO_ESP ? SADB_SATYPE_ESP :
		 policy->rule[0].proto == KERNEL_PROTO_AH ? SADB_SATYPE_AH :
		 policy->rule[0].proto == KERNEL_PROTO_IPCOMP ? SADB_X_SATYPE_IPCOMP :
		 pexpect(0));

	uint8_t reqbuf[SIZEOF_SADB_BASE +
		       SIZEOF_SADB_PROTOCOL + /*flow*/
		       SIZEOF_SADB_ADDRESS * 2 + /*src/dst addr*/
		       SIZEOF_SADB_ADDRESS * 4 + /*src/dst addr/mask*/
		       SIZEOF_SADB_PROTOCOL + /*flow*/
		       0];

	struct outbuf req;
	msg_base(verbose, &req, __func__,
		 chunk2(reqbuf, sizeof(reqbuf)),
		 type, satype);

	/* flow type */

	unsigned policy_direction =
		(dir == DIRECTION_INBOUND ? IPSP_DIRECTION_IN :
		 dir == DIRECTION_OUTBOUND ? IPSP_DIRECTION_OUT :
		 pexpect(0));

	enum sadb_x_flow_type policy_type = UINT_MAX;
	const char *policy_name = NULL;
	switch (policy->shunt) {
	case SHUNT_TRAP:
		policy_type = SADB_X_FLOW_TYPE_ACQUIRE;
		policy_name = "%trap(acquire)";
		break;
	case SHUNT_IPSEC:
		policy_type = SADB_X_FLOW_TYPE_REQUIRE;
		policy_name = (policy->mode == KERNEL_MODE_TUNNEL ? ip_protocol_ipip.name :
			       policy->mode == KERNEL_MODE_TRANSPORT ? protocol_from_ipproto(policy->rule[policy->nr_rules-1].proto)->name :
			       "UNKNOWN");
		break;
	case SHUNT_PASS:
		policy_type = SADB_X_FLOW_TYPE_BYPASS;
		policy_name = "%pass(bypass)";
		break;
	case SHUNT_DROP:
		policy_type = SADB_X_FLOW_TYPE_DENY;
		policy_name = "%drop(deny)";
		break;
	case SHUNT_NONE:
		/* FAILURE=NONE should have been turned into
		 * NEGOTIATION */
		bad_case(policy->shunt);
	case SHUNT_UNSET:
		bad_case(policy->shunt);
	}
	PASSERT(logger, policy_type != UINT_MAX);
	PASSERT(logger, policy_name != NULL);

	ldbg(logger, "%s()   policy=%s", func, policy_name);

	put_sadb_ext(&req, sadb_protocol, SADB_X_EXT_FLOW_TYPE,
		     .sadb_protocol_direction = policy_direction,
		     .sadb_protocol_proto = policy_type);

	/* host_addr */

	if (policy->nr_rules > 0) {
		/*
		 * XXX: needing to look at OP_DIRECTION to decide if a
		 * switch-a-roo is needed when setting the PFKEYv2
		 * field's SRC/DST from the actual SRC/DST sure feels
		 * like a bug.
		 */
		switch (dir) {
		case DIRECTION_INBOUND:
			/* XXX: notice how DST gets SRC's value et.al. */
			put_sadb_address(&req, SADB_EXT_ADDRESS_DST, policy->src.host, verbose);
			put_sadb_address(&req, SADB_EXT_ADDRESS_SRC, policy->dst.host, verbose);
			break;
		case DIRECTION_OUTBOUND:
			put_sadb_address(&req, SADB_EXT_ADDRESS_SRC, policy->src.host, verbose);
			put_sadb_address(&req, SADB_EXT_ADDRESS_DST, policy->dst.host, verbose);
			break;
		}
	}

	/* selectors */

	put_sadb_address(&req, SADB_X_EXT_SRC_FLOW, selector_prefix(*src_client), verbose);
	put_sadb_address(&req, SADB_X_EXT_SRC_MASK, selector_prefix_mask(*src_client), verbose);
	put_sadb_address(&req, SADB_X_EXT_DST_FLOW, selector_prefix(*dst_client), verbose);
	put_sadb_address(&req, SADB_X_EXT_DST_MASK, selector_prefix_mask(*dst_client), verbose);

	/* which protocol? */

	put_sadb_ext(&req, sadb_protocol, SADB_X_EXT_PROTOCOL,
		     .sadb_protocol_proto = selector_protocol(*src_client)->ipproto);

	/* sa_srcd, sa_dstid: identity (sec_label?) */

#else

	/* SPDADD: <base, policy, address(SD), [lifetime(HS)]> */

	enum sadb_type type = (op == KERNEL_POLICY_OP_ADD ? SADB_X_SPDADD :
			       op == KERNEL_POLICY_OP_REPLACE ? SADB_X_SPDUPDATE :
			       pexpect(0));
	/* what NetBSD expects */
	enum sadb_satype satype = SADB_SATYPE_UNSPEC;
	uint8_t reqbuf[SIZEOF_SADB_BASE +
		       SIZEOF_SADB_X_POLICY +
		       SIZEOF_SADB_ADDRESS * 2 +
		       SIZEOF_SADB_LIFETIME * 2];
	struct outbuf req;
	msg_base(verbose, &req, __func__,
		 chunk2(reqbuf, sizeof(reqbuf)),
		 type, satype);

	/* address(SD) */

	put_sadb_selector(&req, SADB_EXT_ADDRESS_SRC, *src_client, verbose);
	put_sadb_selector(&req, SADB_EXT_ADDRESS_DST, *dst_client, verbose);

	/* [lifetime(HSC)] */

	put_sadb_ext(&req, sadb_lifetime, SADB_EXT_LIFETIME_HARD);

	/* policy */

	enum ipsec_policy policy_type = UINT_MAX;
	const char *policy_name = NULL;
	switch (policy->shunt) {
	case SHUNT_TRAP:
		policy_type = IPSEC_POLICY_IPSEC;
		policy_name = "%trap(ipsec)";
		break;
	case SHUNT_IPSEC:
		policy_type = IPSEC_POLICY_IPSEC;
		policy_name = (policy->mode == KERNEL_MODE_TUNNEL ? ip_protocol_ipip.name :
			       policy->mode == KERNEL_MODE_TRANSPORT ? protocol_from_ipproto(policy->rule[policy->nr_rules-1].proto)->name :
			       "UNKNOWN");
		break;
	case SHUNT_PASS:
		policy_type = IPSEC_POLICY_NONE;
		policy_name = "%pass(none)";
		break;
	case SHUNT_DROP:
		policy_type = IPSEC_POLICY_DISCARD;
		policy_name = "%drop(discard)";
		break;
	case SHUNT_NONE:
	case SHUNT_UNSET:
		/* FAILURE=NONE should have been turned into
		 * NEGOTIATION */
		bad_case(policy->shunt);
	}
	PASSERT(logger, policy_type != UINT_MAX);
	PASSERT(logger, policy_name != NULL);

	ldbg(logger, "%s()   policy=%s", func, policy_name);

	put_sadb_x_policy(&req, dir, policy_type,
			  policy->id, policy);

#endif

	/* send/req */

	struct inbuf resp;
	return msg_sendrecv(&req, &resp, verbose);
}

static bool kernel_pfkeyv2_policy_del(enum direction direction,
				      enum expect_kernel_policy expect_kernel_policy,
				      const ip_selector *src_child,
				      const ip_selector *dst_child,
				      const struct sa_marks *sa_marks UNUSED,
				      const struct ipsec_interface *ipsec_interface,
				      enum kernel_policy_id policy_id,
				      const shunk_t sec_label UNUSED,
				      struct logger *logger, const char *func)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, logger, NULL);
	vdbg("%s() policy_id=%u ...", func, policy_id);
	verbose.level++;

	if (ipsec_interface != NULL) {
		ipsec_interface_buf ifb;
		vlog("BSD doesn't add kernel-policy to an ipsec-interface (%s)",
		     str_ipsec_interface(ipsec_interface, &ifb));
		return true;
	}
#ifdef __OpenBSD__

	uint8_t reqbuf[SIZEOF_SADB_BASE +
		       SIZEOF_SADB_PROTOCOL + /*flow*/
		       SIZEOF_SADB_ADDRESS * 2 + /*src/dst addr*/
		       SIZEOF_SADB_ADDRESS * 4 + /*src/dst addr/mask*/
		       SIZEOF_SADB_PROTOCOL + /*flow*/
		       0];

	struct outbuf req;
	msg_base(verbose, &req, __func__,
		 chunk2(reqbuf, sizeof(reqbuf)),
		 SADB_X_DELFLOW,
		 SADB_SATYPE_UNSPEC);

	/* flow type */

	unsigned policy_direction =
		(direction == DIRECTION_INBOUND ? IPSP_DIRECTION_IN :
		 direction == DIRECTION_OUTBOUND ? IPSP_DIRECTION_OUT :
		 pexpect(0));

	put_sadb_ext(&req, sadb_protocol, SADB_X_EXT_FLOW_TYPE,
		     .sadb_protocol_direction = policy_direction,
		     .sadb_protocol_proto = SADB_X_FLOW_TYPE_REQUIRE);

	/* selectors */

	put_sadb_address(&req, SADB_X_EXT_SRC_FLOW, selector_prefix(*src_child), verbose);
	put_sadb_address(&req, SADB_X_EXT_SRC_MASK, selector_prefix_mask(*src_child), verbose);
	put_sadb_address(&req, SADB_X_EXT_DST_FLOW, selector_prefix(*dst_child), verbose);
	put_sadb_address(&req, SADB_X_EXT_DST_MASK, selector_prefix_mask(*dst_child), verbose);

	/* which protocol? */

	put_sadb_ext(&req, sadb_protocol, SADB_X_EXT_PROTOCOL,
		     .sadb_protocol_proto = selector_protocol(*src_child)->ipproto);

	/* sa_srcd, sa_dstid: identity (sec_label?) */

#else

	/* SPDADD: <base, policy, address(SD), [lifetime(HS)]> */

	uint8_t reqbuf[SIZEOF_SADB_BASE +
		       SIZEOF_SADB_X_POLICY +
		       SIZEOF_SADB_ADDRESS * 2 +
		       SIZEOF_SADB_LIFETIME * 2];
	struct outbuf req;
	msg_base(verbose, &req, __func__,
		 chunk2(reqbuf, sizeof(reqbuf)),
		 SADB_X_SPDDELETE,
		 SADB_SATYPE_UNSPEC);

	/* address(SD) */

	put_sadb_selector(&req, SADB_EXT_ADDRESS_SRC, *src_child, verbose);
	put_sadb_selector(&req, SADB_EXT_ADDRESS_DST, *dst_child, verbose);

	/* policy */

	put_sadb_x_policy(&req, direction,
			  IPSEC_POLICY_IPSEC, policy_id, NULL);

#endif

	/* send/req */

	struct inbuf resp;
	if (!msg_sendrecv(&req, &resp, verbose)) {
		switch (expect_kernel_policy) {
		case KERNEL_POLICY_PRESENT_OR_MISSING:
		case KERNEL_POLICY_MISSING:
			ldbg(logger, "%s()   ignoring pfkey error", func);
			break;
		case KERNEL_POLICY_PRESENT:
			llog_pexpect(logger, HERE, "%s()   receiving", func);
			return false;
		}
	}

	return true;
}

static bool parse_sadb_address(struct verbose verbose, const struct sadb_msg *b,
			       shunk_t *ext_cursor, ip_address *addr, ip_port *port)
{
	shunk_t address_cursor;
	const struct sadb_address *address =
		get_sadb_address(ext_cursor, &address_cursor, verbose);
	if (address == NULL) {
		return false;
	}
	llog_sadb_address(verbose, b, address);
	verbose.level++;
	if (!get_sadb_sockaddr_address_port(&address_cursor, addr, port, verbose)) {
		return false;
	}
	address_buf ab;
	port_buf pb;
	verbose("%s:%s", str_address(addr, &ab), str_hport(*port, &pb));
	return true;
}

static void parse_sadb_acquire(const struct sadb_msg *msg,
			       shunk_t msg_cursor,
			       struct verbose verbose)
{
	vdbg("%s() ...", __func__);
	verbose.level++;

	ip_address src_address = unset_address;
	ip_address dst_address = unset_address;
	ip_port src_port, dst_port;
	enum kernel_policy_id policy_id = 0;

	while (msg_cursor.len > 0) {

		shunk_t ext_cursor;
		const struct sadb_ext *ext =
			get_sadb_ext(&msg_cursor, &ext_cursor, verbose);
		if (ext == NULL) {
			llog_pexpect(verbose.logger, HERE, "bad ext");
			return;
		}

		enum sadb_exttype exttype = ext->sadb_ext_type;
		switch (exttype) {

		case SADB_EXT_ADDRESS_SRC:
			if (!parse_sadb_address(verbose, msg, &ext_cursor, &src_address, &src_port)) {
				return;
			}
			break;
		case SADB_EXT_ADDRESS_DST:
			if (!parse_sadb_address(verbose, msg, &ext_cursor, &dst_address, &dst_port)) {
				return;
			}
			break;
#ifdef SADB_X_EXT_POLICY /* FreeBSD NetBSD */
		case SADB_X_EXT_POLICY:
			policy_id = 0;
			if (!parse_sadb_x_policy(verbose, msg, &ext_cursor, &policy_id)) {
				return;
			}
			break;
#endif

		case SADB_EXT_PROPOSAL:
			if (VDBGP()) {
				verbose("ignore: ");
				verbose.level++;
				llog_sadb_ext(verbose, msg, ext, ext_cursor);
				verbose.level--;
			}
			break;

		default:
			if (VDBGP()) {
				verbose.level++;
				llog_sadb_ext(verbose, msg, ext, ext_cursor);
				verbose.level--;
			}
			break;
		}
	}

	if (address_is_unset(&src_address) || address_is_unset(&dst_address)) {
		vdbg("something isn't set");
		return;
	}

	ip_packet packet = packet_from_raw(HERE,
					   address_info(src_address),
					   &src_address.bytes,
					   &dst_address.bytes,
					   &ip_protocol_all,
					   src_port,
					   dst_port);
	struct kernel_acquire b = {
		.packet = packet,
		.by_acquire = true,
		.logger = verbose.logger, /*on-stack*/
		.background = true, /* no whack so doesn't matter */
		.sec_label = null_shunk,
		.policy_id = policy_id,
	};
	initiate_ondemand(&b);
}

static void process_pending(shunk_t payload, struct verbose verbose)
{
	verbose("in %s() processing ...", __func__);
	verbose.level++;

	llog_sadb(verbose, payload);

	shunk_t cursor = payload;
	shunk_t msg_cursor;
	const struct sadb_msg *msg = get_sadb_msg(&cursor, &msg_cursor, verbose);
	if (msg == NULL) {
		llog_pexpect(verbose.logger, HERE, "no msg");
	}

	switch (msg->sadb_msg_type) {
	case SADB_ACQUIRE:
		parse_sadb_acquire(msg, msg_cursor, verbose);
		break;
	}
}

static void process_pending_queue(struct verbose verbose)
{
	struct pending *pending;
	FOR_EACH_LIST_ENTRY_OLD2NEW(pending, &pending_queue) {
		remove_list_entry(&pending->entry);
		process_pending(HUNK_AS_SHUNK(pending->msg), verbose);
		free_chunk_content(&pending->msg);
		pfree(pending);
	}
}

static void pfkeyv2_process_msg(int fd UNUSED, void *arg UNUSED, struct logger *logger)
{
	struct verbose verbose = VERBOSE(DEBUG_STREAM, logger, NULL);
	vdbg("processing message");
	verbose.level++;

	struct inbuf msg;
	if (!recv_msg(&msg, "process", verbose)) {
		return;
	}
	queue_msg(&msg);
	process_pending_queue(verbose);
}

static void kernel_pfkeyv2_shutdown(struct logger *logger)
{
	ldbg(logger, "%s() called; nothing to do", __func__);
}

static err_t kernel_directional_ipsec_is_enabled(struct logger *logger)
{
	ldbg(logger, "%s() called; nothing to do", __func__);
	return "not supported";
}

static err_t kernel_iptfs_ipsec_sa_is_enabled(const struct logger *logger)
{
	ldbg(logger, "%s() called; nothing to do", __func__);
	return "not supported";
}

static err_t kernel_migrate_ipsec_sa_is_enabled(const struct logger *logger)
{
	ldbg(logger, "%s() called; nothing to do", __func__);
	return "not supported";
}

static const char *pfkeyv2_protostack_names[] = {
	"pfkeyv2",
	"pfkey",
	"bsdkame", /* provide compatible name */
	NULL,
};

const struct kernel_ops pfkeyv2_kernel_ops = {
	.protostack_names = pfkeyv2_protostack_names,
	.updown_name = "bsd",
	.interface_name = "PF_KEY v2",
	.sha2_truncbug_support = false,
#ifdef SADB_X_SAFLAGS_ESN /* FreeBSD OpenBSD */
	.esn_supported = true,		/* FreeBSD and OpenBSD? */
#endif
#ifdef SADB_X_EXT_SA_REPLAY /* FreeBSD */
	/* .sadb_x_sa_replay_replay is in packets */
	.max_replay_window = (UINT32_MAX - 32), /* packets */
#elif defined(__OpenBSD__)
	/* kernel limits value to 64 * 8 packet bits per-byte */
	.max_replay_window = 64 * 8, /* packets */
#else
	/* .sadb_sa_replay is in bytes with 1 bit per packet */
	.max_replay_window = UINT8_MAX * 8, /* packets */
#endif

	.init = kernel_pfkeyv2_init,
	.flush = kernel_pfkeyv2_flush,
	.poke_holes = kernel_pfkeyv2_poke_holes,
	.plug_holes = kernel_pfkeyv2_plug_holes,
	.shutdown = kernel_pfkeyv2_shutdown,

	.get_ipsec_spi = pfkeyv2_get_ipsec_spi,
	.del_ipsec_spi = pfkeyv2_del_ipsec_spi,
	.add_sa = pfkeyv2_add_sa,
	.get_kernel_state = pfkeyv2_get_kernel_state,
	.policy_del = kernel_pfkeyv2_policy_del,
	.policy_add = kernel_pfkeyv2_policy_add,
	.ipsec_interface = &kernel_ipsec_interface_ifconfig,
	.directional_ipsec_sa_is_enabled = kernel_directional_ipsec_is_enabled,
	.iptfs_ipsec_sa_is_enabled = kernel_iptfs_ipsec_sa_is_enabled,
	.migrate_ipsec_sa_is_enabled = kernel_migrate_ipsec_sa_is_enabled,
};
