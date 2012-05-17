/* Find public key in DNS
 * Copyright (C) 2000-2002  D. Hugh Redelmeier.
 * Copyright (C) 2003-2007 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 2007-2008 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2012 Paul Wouters <pwouters@redhat.com>
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

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>	/* ??? for h_errno */
#include <resolv.h>

#include <libreswan.h>
#include <libreswan/ipsec_policy.h>

#include "sysdep.h"
#include "constants.h"
#include "adns.h"	/* needs <resolv.h> */
#include "defs.h"
#include "id.h"
#include "log.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "connections.h"	/* needs id.h */
#include "keys.h"	    /* needs connections.h */
#include "dnskey.h"
#include "packet.h"
#include "timer.h"
#include "server.h"

/* somebody has to decide */
#define MAX_IPSECKEY_RDATA	((MAX_KEY_BYTES * 8 / 6) + 40)	/* somewhat arbitrary overkill */

/* ADNS stuff */

int adns_qfd = NULL_FD,	/* file descriptor for sending queries to adns (O_NONBLOCK) */
    adns_afd = NULL_FD;	/* file descriptor for receiving answers from adns */
static pid_t adns_pid = 0;
const char *pluto_adns_option = NULL;	/* path from --pluto_adns */

static int adns_in_flight = 0;	/* queries outstanding */
int adns_restart_count;
#define ADNS_RESTART_MAX 20

static void release_all_continuations(void);

bool adns_reapchild(pid_t pid, int status UNUSED)
{
  if(pid == adns_pid) {
    close_any(adns_qfd);
    adns_qfd = NULL_FD;
    close_any(adns_afd);
    adns_afd = NULL_FD;

    adns_pid = 0;

    if(adns_in_flight > 0) {
	release_all_continuations();
    }
    pexpect(adns_in_flight == 0);

    return TRUE;
  }
  return FALSE;
}


void
init_adns(void)
{
    const char *adns_path = pluto_adns_option;
    const char *helper_bin_dir = getenv("IPSEC_EXECDIR");
    static const char adns_name[] = "_pluto_adns";
    char adns_path_space[4096];	/* plenty long? */
    int qfds[2];
    int afds[2];

    /* find a pathname to the ADNS program */
    if (adns_path == NULL)
    {
	/* pathname was not specified as an option: build it.
	 * First, figure out the directory to be used.
	 */
	ssize_t n=0;

	if (helper_bin_dir != NULL)
	{
	    n = strlen(helper_bin_dir);
	    if ((size_t)n <= sizeof(adns_path_space) - sizeof(adns_name))
	    {
		strcpy(adns_path_space, helper_bin_dir);
		if (n > 0 && adns_path_space[n -1] != '/')
		    adns_path_space[n++] = '/';
	    }
	}
	else
#if !(defined(macintosh) || (defined(__MACH__) && defined(__APPLE__)))
	{
	    /* The program will be in the same directory as Pluto,
	     * so we use the sympolic link /proc/self/exe to
	     * tell us of the path prefix.
	     */
	    n = readlink("/proc/self/exe", adns_path_space, sizeof(adns_path_space));

	    if (n < 0)
# ifdef __uClibc__
		/* on some nommu we have no proc/self/exe, try without path */
		*adns_path_space = '\0', n = 0;
# else
		exit_log_errno((e
		    , "readlink(\"/proc/self/exe\") failed in init_adns()"));
# endif

	}
#else
	/* This is wrong. Should end up in a resource_dir on MacOSX -- Paul */
	adns_path="/usr/local/libexec/ipsec/lwdnsq";
#endif


	if ((size_t)n > sizeof(adns_path_space) - sizeof(adns_name))
	    exit_log("path to %s is too long", adns_name);

	while (n > 0 && adns_path_space[n - 1] != '/')
	    n--;

	strcpy(adns_path_space + n, adns_name);
	adns_path = adns_path_space;
    }
    if (access(adns_path, X_OK) < 0)
	exit_log_errno((e, "%s missing or not executable", adns_path));

    if (pipe(qfds) != 0 || pipe(afds) != 0)
	exit_log_errno((e, "pipe(2) failed in init_adns()"));

#ifdef HAVE_NO_FORK
    adns_pid = vfork(); /* for better, for worse, in sickness and health..... */
#else
    adns_pid = fork();
#endif
    switch (adns_pid)
    {
    case -1:
	exit_log_errno((e, "fork() failed in init_adns()"));

    case 0:
	/* child */
	{
	    /* Make stdin and stdout our pipes.
	     * Take care to handle case where pipes already use these fds.
	     */
	    if (afds[1] == 0)
		afds[1] = dup(afds[1]);	/* avoid being overwritten */
	    if (qfds[0] != 0)
	    {
		dup2(qfds[0], 0);
		close(qfds[0]);
	    }
	    if (afds[1] != 1)
	    {
		dup2(afds[1], 1);
		close(qfds[1]);
	    }
	    if (afds[0] > 1)
		close(afds[0]);
	    if (afds[1] > 1)
		close(afds[1]);

	    DBG(DBG_DNS, execlp(adns_path, adns_name, "-d", NULL));

	    execlp(adns_path, adns_name, NULL);
	    exit_log_errno((e, "execlp of %s failed", adns_path));
	}

    default:
	/* parent */
	close(qfds[0]);
	adns_qfd = qfds[1];
	adns_afd = afds[0];
	close(afds[1]);
	fcntl(adns_qfd, F_SETFD, FD_CLOEXEC);
	fcntl(adns_afd, F_SETFD, FD_CLOEXEC);
	fcntl(adns_qfd, F_SETFL, O_NONBLOCK);
	break;
    }
}

void
stop_adns(void)
{
    close_any(adns_qfd);
    adns_qfd = NULL_FD;
    close_any(adns_afd);
    adns_afd = NULL_FD;

    if (adns_pid != 0)
    {
	int status;
	pid_t p;

	sleep(1);
	p = waitpid(adns_pid, &status, WNOHANG);

	if (p == -1)
	{
	    log_errno((e, "waitpid for ADNS process failed"));

	    /* get rid of, it might be stuck */
	    kill(adns_pid, 15);
	}
	else if (WIFEXITED(status))
	{
	    if (WEXITSTATUS(status) != 0)
		libreswan_log("ADNS process exited with status %d"
		    , (int) WEXITSTATUS(status));
	    adns_pid = 0;
	}
	else if (WIFSIGNALED(status))
	{
	    libreswan_log("ADNS process terminated by signal %d", (int)WTERMSIG(status));
	    adns_pid = 0;
	}
	else
	{
	    libreswan_log("wait for end of ADNS process returned odd status 0x%x\n"
		, status);
	    adns_pid = 0;
	}
    }
}



/* tricky macro to pass any hot potato */
#define TRY(x)	{ err_t ugh = x; if (ugh != NULL) return ugh; }


/* Process IPSECKEY X-IPsec-Server record, accumulating relevant ones
 * in cr->gateways_from_dns, a list sorted by "preference".
 *
 * Format of IPSECKEY record body: X-IPsec-Server ( nnn ) = iii kkk
 *  nnn is a 16-bit unsigned integer preference
 *  iii is @FQDN or dotted-decimal IPv4 address or colon-hex IPv6 address
 *  kkk is an optional RSA public signing key in base 64.
 *
 * NOTE: we've got to be very wary of anything we find -- bad guys
 * might have prepared it.
 */

#define our_IPSECKEY_attr_string "X-IPsec-Server"
static const char our_IPSECKEY_attr[] = our_IPSECKEY_attr_string;

static err_t
decode_iii(char **pp, struct id *gw_id)
{
    char *p = *pp + strspn(*pp, " \t");
    char *e = p + strcspn(p, " \t");
    char under = *e;

    if (p == e)
	return "IPSECKEY " our_IPSECKEY_attr_string " badly formed (no gateway specified)";

    *e = '\0';
    if (*p == '@')
    {
	/* gateway specification in this record is @FQDN */
	err_t ugh = atoid(p, gw_id, FALSE);

	if (ugh != NULL)
	    return builddiag("malformed FQDN in IPSECKEY " our_IPSECKEY_attr_string ": %s"
			     , ugh);
    }
    else
    {
	/* gateway specification is numeric */
	ip_address ip;
	err_t ugh = tnatoaddr(p, e-p
	    , strchr(p, ':') == NULL? AF_INET : AF_INET6
	    , &ip);

	if (ugh != NULL)
	    return builddiag("malformed IP address in IPSECKEY " our_IPSECKEY_attr_string ": %s"
		, ugh);

	if (isanyaddr(&ip))
	    return "gateway address must not be 0.0.0.0 or 0::0";

	iptoid(&ip, gw_id);
    }

    *e = under;
    *pp = e + strspn(e, " \t");

    return NULL;
}

static err_t
process_ipseckey(char *str
		    , bool doit	/* should we capture information? */
		    , enum dns_auth_level dns_auth_level
		    , struct adns_continuation *const cr)
{
    const struct id *client_id = &cr->id;	/* subject of query */
    char *p = str;
    unsigned long pref = 0;
    struct gw_info gi;

    p += strspn(p, " \t");	/* ignore leading whitespace */

    /* is this for us? */
    if (strncasecmp(p, our_IPSECKEY_attr, sizeof(our_IPSECKEY_attr)-1) != 0)
	return NULL;	/* neither interesting nor bad */

    p += sizeof(our_IPSECKEY_attr) - 1;	/* ignore our attribute name */
    p += strspn(p, " \t");	/* ignore leading whitespace */

    /* decode '(' nnn ')' */
    if (*p != '(')
	return "X-IPsec-Server missing '('";

    {
	char *e;

	p++;
	pref = strtoul(p, &e, 0);
	if (e == p)
	    return "malformed X-IPsec-Server priority";

	p = e + strspn(e, " \t");

	if (*p != ')')
	    return "X-IPsec-Server priority missing ')'";

	p++;
	p += strspn(p, " \t");

	if (pref > 0xFFFF)
	    return "X-IPsec-Server priority larger than 0xFFFF";
    }

    /* time for '=' */

    if (*p != '=')
	return "X-IPsec-Server priority missing '='";

    p++;
    p += strspn(p, " \t");

    /* Decode iii (Security Gateway ID). */

    zero(&gi);	/* before first use */

    TRY(decode_iii(&p, &gi.gw_id));	/* will need to unshare_id_content */

    if (!cr->sgw_specified)
    {
	/* we don't know the peer's ID (because we are initiating
	 * and we don't know who to initiate with.
	 * So we're looking for gateway specs with an IP address
	 */
	if (!id_is_ipaddr(&gi.gw_id))
	{
	    DBG(DBG_DNS,
		{
		    char cidb[IDTOA_BUF];
		    char gwidb[IDTOA_BUF];

		    idtoa(client_id, cidb, sizeof(cidb));
		    idtoa(&gi.gw_id, gwidb, sizeof(gwidb));
		    DBG_log("IPSECKEY %s record for %s: security gateway %s;"
			" ignored because gateway's IP is unspecified"
			, our_IPSECKEY_attr, cidb, gwidb);
		});
	    return NULL;	/* we cannot use this record, but it isn't wrong */
	}
    }
    else
    {
	/* We do know the peer's ID (because we are responding)
	 * So we're looking for gateway specs specifying this known ID.
	 */
	const struct id *peer_id = &cr->sgw_id;

	if (!same_id(peer_id, &gi.gw_id))
	{
	    DBG(DBG_DNS,
		{
		    char cidb[IDTOA_BUF];
		    char gwidb[IDTOA_BUF];
		    char pidb[IDTOA_BUF];

		    idtoa(client_id, cidb, sizeof(cidb));
		    idtoa(&gi.gw_id, gwidb, sizeof(gwidb));
		    idtoa(peer_id, pidb, sizeof(pidb));
		    DBG_log("IPSECKEY %s record for %s: security gateway %s;"
			" ignored -- looking to confirm %s as gateway"
			, our_IPSECKEY_attr, cidb, gwidb, pidb);
		});
	    return NULL;	/* we cannot use this record, but it isn't wrong */
	}
    }

    if (doit)
    {
	/* really accept gateway */
	struct gw_info **gwip;	/* gateway insertion point */

	gi.client_id = *client_id;	/* will need to unshare_id_content */

	/* decode optional kkk: base 64 encoding of key */

	gi.gw_key_present = *p != '\0';
	if (gi.gw_key_present)
	{
	    /* Decode base 64 encoding of key.
	     * Similar code is in process_lwdnsq_key.
	     */
	    u_char kb[RSA_MAX_ENCODING_BYTES];	/* plenty of space for binary form of public key */
	    chunk_t kbc;
	    struct RSA_public_key r;

	    err_t ugh = ttodatav(p, 0, 64, (char *)kb, sizeof(kb), &kbc.len
		, diag_space, sizeof(diag_space), TTODATAV_SPACECOUNTS);

	    if (ugh != NULL)
		return builddiag("malformed key data: %s", ugh);

	    if (kbc.len > sizeof(kb))
		return builddiag("key data larger than %lu bytes"
		    , (unsigned long) sizeof(kb));

	    kbc.ptr = kb;
	    ugh = unpack_RSA_public_key(&r, &kbc);
	    if (ugh != NULL)
		return builddiag("invalid key data: %s", ugh);

	    /* now find a key entry to put it in */
	    gi.key = public_key_from_rsa(&r);

	    free_RSA_public_content(&r);

	    unreference_key(&cr->last_info);
	    cr->last_info = reference_key(gi.key);
	}

	/* we're home free!  Allocate everything and add to gateways list. */
	gi.refcnt = 1;
	gi.pref = pref;
	gi.key->dns_auth_level = dns_auth_level;
	gi.key->last_tried_time = gi.key->last_worked_time = NO_TIME;

	/* find insertion point */
	for (gwip = &cr->gateways_from_dns; *gwip != NULL && (*gwip)->pref < pref; gwip = &(*gwip)->next)
	    ;

	DBG(DBG_DNS,
	    {
		char cidb[IDTOA_BUF];
		char gwidb[IDTOA_BUF];

		idtoa(client_id, cidb, sizeof(cidb));
		idtoa(&gi.gw_id, gwidb, sizeof(gwidb));
		if (gi.gw_key_present)
		{
		    DBG_log("gateway for %s is %s with key %s"
			, cidb, gwidb, gi.key->u.rsa.keyid);
		}
		else
		{
		    DBG_log("gateway for %s is %s; no key specified"
			, cidb, gwidb);
		}
	    });

	gi.next = *gwip;
	*gwip = clone_thing(gi, "gateway info");
	unshare_id_content(&(*gwip)->gw_id);
	unshare_id_content(&(*gwip)->client_id);
    }

    return NULL;
}

static const char *
rr_typename(int type)
{
    switch (type)
    {
    case ns_t_ipseckey:
	return "IPSECKEY";
    default:
	return "???";
    }
}


/* RFC 4025 2,1: IPSECKEY RRs 
 * unpack_ipseckey_rdata() deals with this peculiar representation.

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  precedence   | gateway type  |  algorithm  |     gateway     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-------------+                 +
~                            gateway                            ~
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               /
/                          public key                           /
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|

* precedence 0-255  (similar to preference in MX records)
* gateway type: 
*    0 no gateway
*    1 IPv4
*    2 IPv6
*    3 wire-encoded uncompressed domain name (so length is implicit)
* algo:
*    1 DSA
*    2 RSA
* gateway (depends on gateway-type)
*    32 bit IPV4
*    128 bit IPv6
*    section 3.3 of RFC 1035 domain name, uncompressed
* public key
*     the public key field contains the algorithm-specific portion of the KEY (or DNSKEY) RR RDATA
*/

struct ipseckey_rdata {
    u_int8_t precedence;
    u_int8_t gateway_type;
    u_int8_t algorithm;
    /* gateway */
    /* pubkey */
};

static field_desc ipseckey_rdata_fields[] = {
    { ft_nat, BYTES_FOR_BITS(8), "precedence", NULL },
    { ft_nat, BYTES_FOR_BITS(8), "gatewaytype", NULL },
    { ft_nat, BYTES_FOR_BITS(8), "algorithm", NULL },
    { ft_end, 0, NULL, NULL }
};

static struct_desc ipseckey_rdata_desc = {
    "IPSECKEY RR RData fixed part",
    ipseckey_rdata_fields,
    sizeof(struct ipseckey_rdata)
};

/* handle an IPSECKEY Resource Record. */
/* Likely will be completely redone using libunbound */
static err_t
process_ipseckey_rr(u_char *ptr, size_t len
, bool doit	/* should we capture information? */
, enum dns_auth_level dns_auth_level
, struct adns_continuation *const cr)
{
    pb_stream pbs;
    struct ipseckey_rdata kr;

    if (len < sizeof(struct ipseckey_rdata))
	return "KEY Resource Record's RD Length is too small";

    init_pbs(&pbs, ptr, len, "IPSECKEY RR");

    if (!in_struct(&kr, &ipseckey_rdata_desc, &pbs, NULL))
	return "failed to get fixed part of KEY Resource Record RDATA";

    if (kr.protocol == 4	/* IPSEC (RFC 2535 3.1.3) */
    && kr.algorithm == 1	/* RSA/MD5 (RFC 2535 3.2) */
    && (kr.flags & 0x8000) == 0	/* use for authentication (3.1.2) */
    && (kr.flags & 0x2CF0) == 0)	/* must be zero */
    {
	/* we have what seems to be a tasty key */

	if (doit)
	{
	    chunk_t k;

	    setchunk(k, pbs.cur, pbs_left(&pbs));
	    TRY(add_public_key(&cr->id, dns_auth_level, PUBKEY_ALG_RSA, &k
		, &cr->keys_from_dns));
	}
    }
    return NULL;
}




/* process DNS answer -- IPSECKEY query */

static err_t
process_dns_answer(struct adns_continuation *const cr
, u_char ans[], int anslen)
{
    const int type = cr->query.type;	/* type of record being sought */
    int r;	/* all-purpose return value holder */
    u_int16_t c;	/* number of current RR in current answer section */
    pb_stream pbs;
    u_int8_t *ans_start;	/* saved position of answer section */
    struct qr_header qr_header;
    enum dns_auth_level dns_auth_level;

    init_pbs(&pbs, ans, anslen, "Query Response Message");

    /* decode and check header */

    if (!in_struct(&qr_header, &qr_header_desc, &pbs, NULL))
	return "malformed header";

    /* ID: nothing to do with us */

    /* stuff -- lots of things */
    if ((qr_header.stuff & QRS_QR) == 0)
	return "not a response?!?";

    if (((qr_header.stuff >> QRS_OPCODE_SHIFT) & QRS_OPCODE_MASK) != QRSO_QUERY)
	return "unexpected opcode";

    /* I don't think we care about AA */

    if (qr_header.stuff & QRS_TC)
	return "response truncated";

    /* I don't think we care about RD, RA, or CD */

    /* AD means "authentic data" */
    dns_auth_level = qr_header.stuff & QRS_AD? DAL_UNSIGNED : DAL_NOTSEC;

    if (qr_header.stuff & QRS_Z)
	return "Z bit is not zero";

    r = (qr_header.stuff >> QRS_RCODE_SHIFT) & QRS_RCODE_MASK;
    if (r != 0)
	return r < (int)elemsof(rcode_text)? rcode_text[r] : "unknown rcode";

    if (qr_header.ancount == 0)
	return builddiag("no %s RR found by DNS", rr_typename(type));

    /* end of header checking */

    /* Question Section processing */

    /* 4.1.2. Question section format:
     *                                 1  1  1  1  1  1
     *   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     * |                                               |
     * /                     QNAME                     /
     * /                                               /
     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     * |                     QTYPE                     |
     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     * |                     QCLASS                    |
     * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
     */

    DBG(DBG_DNS, DBG_log("*Question Section:"));

    for (c = 0; c != qr_header.qdcount; c++)
    {
	struct qs_fixed qsf;

	TRY(eat_name_helpfully(&pbs, "Question Section"));

	if (!in_struct(&qsf, &qs_fixed_desc, &pbs, NULL))
	    return "failed to get fixed part of Question Section";

	if (qsf.qtype != type)
	    return "unexpected QTYPE in Question Section";

	if (qsf.qclass != ns_c_in)
	    return "unexpected QCLASS in Question Section";
    }

    /* rest of sections are made up of Resource Records */

    /* Answer Section processing -- error checking, noting T_SIG */

    ans_start = pbs.cur;	/* remember start of answer section */

    TRY(process_answer_section(&pbs, FALSE, &dns_auth_level
	, qr_header.ancount, cr));

    /* Authority Section processing (just sanity checking) */

    DBG(DBG_DNS, DBG_log("*Authority Section:"));

    for (c = 0; c != qr_header.nscount; c++)
    {
	struct rr_fixed rrf;
	size_t tail;

	TRY(eat_name_helpfully(&pbs, "Authority Section"));

	if (!in_struct(&rrf, &rr_fixed_desc, &pbs, NULL))
	    return "failed to get fixed part of Authority Section Resource Record";

	if (rrf.rdlength > pbs_left(&pbs))
	    return "RD Length extends beyond end of message";

	/* ??? should we care about ttl? */

	tail = rrf.rdlength;

	in_raw(NULL, tail, &pbs, "RR RDATA");
    }

    /* Additional Section processing (just sanity checking) */

    DBG(DBG_DNS, DBG_log("*Additional Section:"));

    for (c = 0; c != qr_header.arcount; c++)
    {
	struct rr_fixed rrf;
	size_t tail;

	TRY(eat_name_helpfully(&pbs, "Additional Section"));

	if (!in_struct(&rrf, &rr_fixed_desc, &pbs, NULL))
	    return "failed to get fixed part of Additional Section Resource Record";

	if (rrf.rdlength > pbs_left(&pbs))
	    return "RD Length extends beyond end of message";

	/* ??? should we care about ttl? */

	tail = rrf.rdlength;

	in_raw(NULL, tail, &pbs, "RR RDATA");
    }

    /* done all sections */

    /* ??? is padding legal, or can we complain if more left in record? */

    /* process Answer Section again -- accept contents */

    pbs.cur = ans_start;	/* go back to start of answer section */

    return process_answer_section(&pbs, TRUE, &dns_auth_level
	, qr_header.ancount, cr);
}


/****************************************************************/

static err_t
build_dns_name(char name_buf[NS_MAXDNAME + 2]
	       , unsigned long serial USED_BY_DEBUG
	       , const struct id *id
	       , const char *typename USED_BY_DEBUG
	       , const char *gwname   USED_BY_DEBUG)
{
    /* note: all end in "." to suppress relative searches */
    id = resolve_myid(id);
    switch (id->kind)
    {
    case ID_IPV4_ADDR:
    {
	/* XXX: this is really ugly and only temporary until addrtot can
	 *      generate the correct format
	 */
	const unsigned char *b;
	size_t bl USED_BY_DEBUG = addrbytesptr(&id->ip_addr, &b);

	passert(bl == 4);
	snprintf(name_buf, NS_MAXDNAME + 2, "%d.%d.%d.%d.in-addr.arpa."
		 , b[3], b[2], b[1], b[0]);
	break;
    }

    case ID_IPV6_ADDR:
    {
	/* ??? is this correct? */
	const unsigned char *b;
	size_t bl;
	char *op = name_buf;
	static const char suffix[] = "IP6.INT.";

	for (bl = addrbytesptr(&id->ip_addr, &b); bl-- != 0; )
	{
	    if (op + 4 + sizeof(suffix) >= name_buf + NS_MAXDNAME + 1)
		return "IPv6 reverse name too long";
	    op += sprintf(op, "%x.%x.", b[bl] & 0xF, b[bl] >> 4);
	}
	strcpy(op, suffix);
	break;
    }

    case ID_FQDN:
	/* strip trailing "." characters, then add one */
	{
	    size_t il = id->name.len;

	    while (il > 0 && id->name.ptr[il - 1] == '.')
		il--;
	    if (il > NS_MAXDNAME)
		return "FQDN too long for domain name";

	    memcpy(name_buf, id->name.ptr, il);
	    strcpy(name_buf + il, ".");
	}
	break;

    default:
	return "can only query DNS for key for ID that is a FQDN, IPV4_ADDR, or IPV6_ADDR";
    }

    DBG(DBG_CONTROL | DBG_DNS, DBG_log("DNS query %lu for %s for %s (gw: %s)"
	, serial, typename, name_buf, gwname));
    return NULL;
}

void
gw_addref(struct gw_info *gw)
{
    if (gw != NULL)
    {
	DBG(DBG_DNS, DBG_log("gw_addref: %p refcnt: %d++", gw, gw->refcnt))
	gw->refcnt++;
    }
}

void
gw_delref(struct gw_info **gwp)
{
    struct gw_info *gw = *gwp;

    if (gw != NULL)
    {
	DBG(DBG_DNS, DBG_log("gw_delref: %p refcnt: %d--", gw, gw->refcnt));

	passert(gw->refcnt != 0);
	gw->refcnt--;
	if (gw->refcnt == 0)
	{
	    free_id_content(&gw->client_id);
	    free_id_content(&gw->gw_id);
	    if (gw->gw_key_present)
		unreference_key(&gw->key);
	    gw_delref(&gw->next);
	    pfree(gw);	/* trickery could make this a tail-call */
	}
	*gwp = NULL;
    }
}

/* Start an asynchronous DNS query.
 *
 * For KEY record, the result will be a list in cr->keys_from_dns.
 * For IPSECKEY records, the result will be a list in cr->gateways_from_dns.
 *
 * If sgw_id is null, only consider IPSECKEY records that specify an
 * IP address for the gatway: we need this in the initiation case.
 *
 * If sgw_id is non-null, only consider IPSECKEY records that specify
 * this id as the security gatway; this is useful to the Responder
 * for confirming claims of gateways.
 *
 * Continuation cr gives information for continuing when the result shows up.
 *
 * Two kinds of errors must be handled: synchronous (immediate)
 * and asynchronous.  Synchronous errors are indicated by the returned
 * value of start_adns_query; in this case, the continuation will
 * have been freed and the continuation routine will not be called.
 * Asynchronous errors are indicated by the ugh parameter passed to the
 * continuation routine.
 *
 * After the continuation routine has completed, handle_adns_answer
 * will free the continuation.  The continuation routine should have
 * freed any axiliary resources.
 *
 * Note: in the synchronous error case, start_adns_query will have
 * freed the continuation; this means that the caller will have to
 * be very careful to release any auxiliary resources that were in
 * the continuation record without using the continuation record.
 *
 * Either there will be an error result passed to the continuation routine,
 * or the results will be in cr->keys_from_dns or cr->gateways_from_dns.
 * The result variables must by left NULL by the continutation routine.
 * The continuation routine is responsible for establishing and
 * disestablishing any logging context (whack_log_fd, cur_*).
 */

static struct adns_continuation *continuations = NULL;	/* newest of queue */
static struct adns_continuation *next_query = NULL;	/* oldest not sent */

static struct adns_continuation *
continuation_for_qtid(unsigned long qtid)
{
    struct adns_continuation *cr = NULL;

    if (qtid != 0)
	for (cr = continuations; cr != NULL && cr->qtid != qtid; cr = cr->previous)
	    ;
    return cr;
}

static void
release_adns_continuation(struct adns_continuation *cr)
{
    gw_delref(&cr->gateways_from_dns);
#ifdef USE_KEYRR
    free_public_keys(&cr->keys_from_dns);
#endif /* USE_KEYRR */
    unreference_key(&cr->last_info);
    unshare_id_content(&cr->id);
    unshare_id_content(&cr->sgw_id);

    /* unlink from doubly-linked list */
    if (cr->next == NULL)
    {
	passert(continuations == cr);
	continuations = cr->previous;
    }
    else
    {
	passert(cr->next->previous == cr);
	cr->next->previous = cr->previous;
    }

    if (cr->previous != NULL)
    {
	passert(cr->previous->next == cr);
	cr->previous->next = cr->next;
    }

    pfree(cr);
}

static void
release_all_continuations()
{
    struct adns_continuation *cr = NULL;
    struct adns_continuation *crnext;
    int num_released = 0;

    for(cr = continuations; cr != NULL; cr = crnext) {
	crnext = cr->previous;

	cr->cont_fn(cr, "no results returned by lwdnsq");
	release_adns_continuation(cr);
	num_released++;
    }

    DBG_log("release_all_cnt: released %d, %d in flight => %d\n",
	    num_released, adns_in_flight,  adns_in_flight-num_released);

    adns_in_flight-=num_released;
}

err_t
start_adns_query(const struct id *id	/* domain to query */
, const struct id *sgw_id	/* if non-null, any accepted gw_info must match */
, int type	/* T_IPSECKEY or T_KEY, selecting rr type of interest */
, cont_fn_t cont_fn
, struct adns_continuation *cr)
{
    static unsigned long qtid = 1;	/* query transaction id; NOTE: static */
    const char *typename = rr_typename(type);
    char gwidb[IDTOA_BUF];

    if(adns_pid == 0
    && adns_restart_count < ADNS_RESTART_MAX)
    {
	libreswan_log("ADNS helper was not running. Restarting attempt %d",adns_restart_count);
	init_adns();
    }


    /* Splice this in at head of doubly-linked list of continuations.
     * Note: this must be done before any release_adns_continuation().
     */
    cr->next = NULL;
    cr->previous = continuations;
    if (continuations != NULL)
    {
	passert(continuations->next == NULL);
	continuations->next = cr;
    }
    continuations = cr;

    cr->qtid = qtid++;
    cr->type = type;
    cr->cont_fn = cont_fn;
    cr->id = *id;
    unshare_id_content(&cr->id);
    cr->sgw_specified = sgw_id != NULL;
    cr->sgw_id = cr->sgw_specified? *sgw_id : empty_id;
    unshare_id_content(&cr->sgw_id);
    cr->gateways_from_dns = NULL;
#ifdef USE_KEYRR
    cr->keys_from_dns = NULL;
#endif /* USE_KEYRR */

#ifdef DEBUG
    cr->debugging = cur_debugging;
#else
    cr->debugging = LEMPTY;
#endif

    idtoa(&cr->sgw_id, gwidb, sizeof(gwidb));

    zero(&cr->query);

    {
	err_t ugh = build_dns_name(cr->query.name_buf, cr->qtid
				   , id, typename, gwidb);

	if (ugh != NULL)
	{
	    release_adns_continuation(cr);
	    return ugh;
	}
    }

    if (next_query == NULL)
	next_query = cr;

    unsent_ADNS_queries = TRUE;

    return NULL;
}

/* send remaining ADNS queries (until pipe full or none left)
 *
 * This is a co-routine, so it uses static variables to
 * preserve state across calls.
 */
bool unsent_ADNS_queries = FALSE;

void
send_unsent_ADNS_queries(void)
{
    static const char *buf_end = NULL;	/* NOTE STATIC */
    static const char *buf_cur = NULL;	/* NOTE STATIC */

    if (adns_qfd == NULL_FD)
	return;	/* nothing useful to do */

    for (;;)
    {
	if (buf_cur != buf_end)
	{
	    static int try = 0;	/* NOTE STATIC */
	    size_t n = buf_end - buf_cur;
	    ssize_t r = write(adns_qfd, buf_cur, n);

	    if (r == -1)
	    {
		switch (errno)
		{
		case EINTR:
		    continue;	/* try again now */
		case EAGAIN:
		    DBG(DBG_DNS, DBG_log("EAGAIN writing to ADNS"));
		    break;	/* try again later */
		default:
		    try++;
		    log_errno((e, "error %d writing DNS query", try));
		    break;	/* try again later */
		}
		unsent_ADNS_queries = TRUE;
		break;	/* done! */
	    }
	    else
	    {
		passert(r >= 0);
		try = 0;
		buf_cur += r;
	    }
	}
	else
	{
	    if (next_query == NULL)
	    {
		unsent_ADNS_queries = FALSE;
		break;	/* done! */
	    }

	    next_query->query.debugging = next_query->debugging;
	    next_query->query.serial = next_query->qtid;
	    next_query->query.len = sizeof(next_query->query);
	    next_query->query.qmagic = ADNS_Q_MAGIC;
	    next_query->query.type = next_query->type;
	    buf_cur = (const void *)&next_query->query;
	    buf_end = buf_cur + sizeof(next_query->query);
	    next_query = next_query->next;
	    adns_in_flight++;
	}
    }
}

static void
recover_adns_die(void)
{
    struct adns_continuation *cr = NULL;

    adns_pid = 0;
    if(adns_restart_count < ADNS_RESTART_MAX) {
	adns_restart_count++;

	/* next DNS query will restart it */

	/* we have to walk the list of the outstanding requests,
	 * and redo them!
	 */

	cr = continuations;

	/* find the head of the list */
	if(continuations != NULL) {
	    for (; cr->previous != NULL; cr = cr->previous);
	}

	next_query = cr;

	if(next_query != NULL) {
	    unsent_ADNS_queries = TRUE;
	}
    }
}

void reset_adns_restart_count(void)
{
    adns_restart_count=0;
}

void
handle_adns_answer(void)
{
  /* These are retained across calls to handle_adns_answer. */
    static size_t buflen = 0;	/* bytes in answer buffer */
    static struct adns_answer buf;
    ssize_t n;

    passert(buflen < sizeof(buf));
    n = read(adns_afd, (unsigned char *)&buf + buflen, sizeof(buf) - buflen);

    if (n < 0)
    {
	if (errno != EINTR)
	{
	    log_errno((e, "error reading answer from adns"));
	    /* ??? how can we recover? */
	}
	n = 0;	/* now n reflects amount read */
    }
    else if (n == 0)
    {
	/* EOF */
	if (adns_in_flight != 0)
	{
	    libreswan_log("EOF from ADNS with %d queries outstanding (restarts %d)"
		 , adns_in_flight, adns_restart_count);
	    recover_adns_die();
	}
	if (buflen != 0)
	{
	    libreswan_log("EOF from ADNS with %lu bytes of a partial answer outstanding"
		 "(restarts %d)"
		 , (unsigned long)buflen
		 ,  adns_restart_count);
	    recover_adns_die();
	}
	stop_adns();
	return;
    }
    else
    {
	passert(adns_in_flight > 0);
    }

    buflen += n;
    while (buflen >= offsetof(struct adns_answer, ans) && buflen >= buf.len)
    {
	/* we've got a tasty answer -- process it */
	err_t ugh;
	struct adns_continuation *cr = continuation_for_qtid(buf.serial);	/* assume it works */
	const char *typename = rr_typename(cr->query.type);
	const char *name_buf = cr->query.name_buf;

#ifdef USE_KEYRR
	passert(cr->keys_from_dns == NULL);
#endif /* USE_KEYRR */
	passert(cr->gateways_from_dns == NULL);
	adns_in_flight--;
	if (buf.result == -1)
	{
	    /* newer resolvers support statp->res_h_errno as well as h_errno.
	     * That might be better, but older resolvers don't.
	     * See resolver(3), if you have it.
	     * The undocumented(!) h_errno values are defined in
	     * /usr/include/netdb.h.
	     */
	    switch (buf.h_errno_val)
	    {
	    case NO_DATA:
		ugh = builddiag("no %s record for %s", typename, name_buf);
		break;
	    case HOST_NOT_FOUND:
		ugh = builddiag("no host %s for %s record", name_buf, typename);
		break;
	    default:
		ugh = builddiag("failure querying DNS for %s of %s: %s"
		    , typename, name_buf, hstrerror(buf.h_errno_val));
		break;
	    }
	}
	else if (buf.result > (int) sizeof(buf.ans))
	{
	    ugh = builddiag("(INTERNAL ERROR) answer too long (%ld) for buffer"
		, (long)buf.result);
	}
	else
	{
	    ugh = process_dns_answer(cr, buf.ans, buf.result);
	    if (ugh != NULL)
		ugh = builddiag("failure processing %s record of DNS answer for %s: %s"
		    , typename, name_buf, ugh);
	}
	DBG(DBG_RAW | DBG_CRYPT | DBG_PARSING | DBG_CONTROL | DBG_DNS,
	    if (ugh == NULL)
		DBG_log("asynch DNS answer %lu for %s of %s"
		    , cr->query.serial, typename, name_buf);
	    else
		DBG_log("asynch DNS answer %lu %s", cr->query.serial, ugh);
	    );

	passert(GLOBALS_ARE_RESET());
	cr->cont_fn(cr, ugh);
	reset_globals();
	release_adns_continuation(cr);

	/* shift out answer that we've consumed */
	buflen -= buf.len;
	memmove((unsigned char *)&buf, (unsigned char *)&buf + buf.len, buflen);
    }
}
