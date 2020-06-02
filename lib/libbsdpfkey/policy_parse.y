/*	$NetBSD: policy_parse.y,v 1.14 2018/05/28 20:45:38 maxv Exp $	*/

/*	$KAME: policy_parse.y,v 1.21 2003/12/12 08:01:26 itojun Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, 1998, and 1999 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * IN/OUT bound policy configuration take place such below:
 *	in <priority> <policy>
 *	out <priority> <policy>
 *
 * <priority> is one of the following:
 * priority <signed int> where the integer is an offset from the default
 *                       priority, where negative numbers indicate lower
 *                       priority (towards end of list) and positive numbers 
 *                       indicate higher priority (towards beginning of list)
 *
 * priority {low,def,high} {+,-} <unsigned int>  where low and high are
 *                                               constants which are closer
 *                                               to the end of the list and
 *                                               beginning of the list,
 *                                               respectively
 *
 * <policy> is one of following:
 *	"discard", "none", "ipsec <requests>", "entrust", "bypass",
 *
 * The following requests are accepted as <requests>:
 *
 *	protocol/mode/src-dst/level
 *	protocol/mode/src-dst		parsed as protocol/mode/src-dst/default
 *	protocol/mode/src-dst/		parsed as protocol/mode/src-dst/default
 *	protocol/transport		parsed as protocol/mode/any-any/default
 *	protocol/transport//level	parsed as protocol/mode/any-any/level
 *
 * You can concatenate these requests with either ' '(single space) or '\n'.
 */

%{
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include PATH_IPSEC_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>

#include <errno.h>

#include "config.h"

#include "ipsec_strerror.h"
#include "libpfkey.h"

#ifndef INT32_MAX
#define INT32_MAX	(0xffffffff)
#endif

#ifndef INT32_MIN
#define INT32_MIN	(-INT32_MAX-1)
#endif

#define ATOX(c) \
  (isdigit(c) ? (c - '0') : (isupper(c) ? (c - 'A' + 10) : (c - 'a' + 10) ))

static u_int8_t *pbuf = NULL;		/* sadb_x_policy buffer */
static int tlen = 0;			/* total length of pbuf */
static int offset = 0;			/* offset of pbuf */
static int p_dir, p_type, p_protocol, p_mode, p_level, p_reqid;
static u_int32_t p_priority = 0;
static long p_priority_offset = 0;
static struct sockaddr *p_src = NULL;
static struct sockaddr *p_dst = NULL;

struct _val;
extern void yyerror(const char *msg);
static struct sockaddr *parse_sockaddr(struct _val *addrbuf,
    struct _val *portbuf);
static int rule_check(void);
static int init_x_policy(void);
static int set_x_request(struct sockaddr *, struct sockaddr *);
static int set_sockaddr(struct sockaddr *);
static void policy_parse_request_init(void);
static void *policy_parse(const char *, int);

extern void __policy__strbuffer__init__(const char *);
extern void __policy__strbuffer__free__(void);
extern int yyparse(void);
extern int yylex(void);

extern char *__libipsectext;	/*XXX*/

%}

%union {
	u_int num;
	u_int32_t num32;
	struct _val {
		int len;
		char *buf;
	} val;
}

%token DIR 
%token PRIORITY PLUS
%token <num32> PRIO_BASE 
%token <val> PRIO_OFFSET 
%token ACTION PROTOCOL MODE LEVEL LEVEL_SPECIFY IPADDRESS PORT
%token ME ANY
%token SLASH HYPHEN
%type <num> DIR PRIORITY ACTION PROTOCOL MODE LEVEL
%type <val> IPADDRESS LEVEL_SPECIFY PORT

%%
policy_spec
	:	DIR ACTION
		{
			p_dir = $1;
			p_type = $2;

#ifdef HAVE_PFKEY_POLICY_PRIORITY
			p_priority = PRIORITY_DEFAULT;
#else
			p_priority = 0;
#endif

			if (init_x_policy())
				return -1;
		}
		rules
	|	DIR PRIORITY PRIO_OFFSET ACTION
		{
			p_dir = $1;
			p_type = $4;
			p_priority_offset = -atol($3.buf);

			errno = 0;
			if (errno != 0 || p_priority_offset < INT32_MIN)
			{
				__ipsec_errcode = EIPSEC_INVAL_PRIORITY_OFFSET;
				return -1;
			}

			p_priority = PRIORITY_DEFAULT + (u_int32_t) p_priority_offset;

			if (init_x_policy())
				return -1;
		}
		rules
	|	DIR PRIORITY HYPHEN PRIO_OFFSET ACTION
		{
			p_dir = $1;
			p_type = $5;

			errno = 0;
			p_priority_offset = atol($4.buf);

			if (errno != 0 || p_priority_offset > INT32_MAX)
			{
				__ipsec_errcode = EIPSEC_INVAL_PRIORITY_OFFSET;
				return -1;
			}

			/* negative input value means lower priority, therefore higher
			   actual value so that is closer to the end of the list */
			p_priority = PRIORITY_DEFAULT + (u_int32_t) p_priority_offset;

			if (init_x_policy())
				return -1;
		}
		rules
	|	DIR PRIORITY PRIO_BASE ACTION
		{
			p_dir = $1;
			p_type = $4;

			p_priority = $3;

			if (init_x_policy())
				return -1;
		}
		rules
	|	DIR PRIORITY PRIO_BASE PLUS PRIO_OFFSET ACTION
		{
			p_dir = $1;
			p_type = $6;

			errno = 0;
			p_priority_offset = atol($5.buf);

			if (errno != 0 || p_priority_offset > PRIORITY_OFFSET_NEGATIVE_MAX)
			{
				__ipsec_errcode = EIPSEC_INVAL_PRIORITY_BASE_OFFSET;
				return -1;
			}

			/* adding value means higher priority, therefore lower
			   actual value so that is closer to the beginning of the list */
			p_priority = $3 - (u_int32_t) p_priority_offset;

			if (init_x_policy())
				return -1;
		}
		rules
	|	DIR PRIORITY PRIO_BASE HYPHEN PRIO_OFFSET ACTION
		{
			p_dir = $1;
			p_type = $6;

			errno = 0;
			p_priority_offset = atol($5.buf);

			if (errno != 0 || p_priority_offset > PRIORITY_OFFSET_POSITIVE_MAX)
			{
				__ipsec_errcode = EIPSEC_INVAL_PRIORITY_BASE_OFFSET;
				return -1;
			}

			/* subtracting value means lower priority, therefore higher
			   actual value so that is closer to the end of the list */
			p_priority = $3 + (u_int32_t) p_priority_offset;

			if (init_x_policy())
				return -1;
		}
		rules
	|	DIR
		{
			p_dir = $1;
			p_type = 0;	/* ignored it by kernel */

			p_priority = 0;

			if (init_x_policy())
				return -1;
		}
	;

rules
	:	/*NOTHING*/
	|	rules rule {
			if (rule_check() < 0)
				return -1;

			if (set_x_request(p_src, p_dst) < 0)
				return -1;

			policy_parse_request_init();
		}
	;

rule
	:	protocol SLASH mode SLASH addresses SLASH level
	|	protocol SLASH mode SLASH addresses SLASH
	|	protocol SLASH mode SLASH addresses
	|	protocol SLASH mode SLASH
	|	protocol SLASH mode SLASH SLASH level
	|	protocol SLASH mode
	|	protocol SLASH {
			__ipsec_errcode = EIPSEC_FEW_ARGUMENTS;
			return -1;
		}
	|	protocol {
			__ipsec_errcode = EIPSEC_FEW_ARGUMENTS;
			return -1;
		}
	;

protocol
	:	PROTOCOL { p_protocol = $1; }
	;

mode
	:	MODE { p_mode = $1; }
	;

level
	:	LEVEL {
			p_level = $1;
			p_reqid = 0;
		}
	|	LEVEL_SPECIFY {
			p_level = IPSEC_LEVEL_UNIQUE;
			p_reqid = atol($1.buf);	/* atol() is good. */
		}
	;

addresses
	:	IPADDRESS {
			p_src = parse_sockaddr(&$1, NULL);
			if (p_src == NULL)
				return -1;
		}
		HYPHEN
		IPADDRESS {
			p_dst = parse_sockaddr(&$4, NULL);
			if (p_dst == NULL)
				return -1;
		}
	|	IPADDRESS PORT {
			p_src = parse_sockaddr(&$1, &$2);
			if (p_src == NULL)
				return -1;
		}
		HYPHEN
		IPADDRESS PORT {
			p_dst = parse_sockaddr(&$5, &$6);
			if (p_dst == NULL)
				return -1;
		}
	|	ME HYPHEN ANY {
			if (p_dir != IPSEC_DIR_OUTBOUND) {
				__ipsec_errcode = EIPSEC_INVAL_DIR;
				return -1;
			}
		}
	|	ANY HYPHEN ME {
			if (p_dir != IPSEC_DIR_INBOUND) {
				__ipsec_errcode = EIPSEC_INVAL_DIR;
				return -1;
			}
		}
		/*
	|	ME HYPHEN ME
		*/
	;

%%

void
yyerror(const char *msg)
{
	fprintf(stderr, "libipsec: %s while parsing \"%s\"\n",
		msg, __libipsectext);

	return;
}

static struct sockaddr *
parse_sockaddr(struct _val *addrbuf, struct _val *portbuf)
{
	struct addrinfo hints, *res;
	char *addr;
	char *serv = NULL;
	int error;
	struct sockaddr *newaddr = NULL;

	if ((addr = malloc(addrbuf->len + 1)) == NULL) {
		yyerror("malloc failed");
		__ipsec_set_strerror(strerror(errno));
		return NULL;
	}

	if (portbuf && ((serv = malloc(portbuf->len + 1)) == NULL)) {
		free(addr);
		yyerror("malloc failed");
		__ipsec_set_strerror(strerror(errno));
		return NULL;
	}

	strncpy(addr, addrbuf->buf, addrbuf->len);
	addr[addrbuf->len] = '\0';

	if (portbuf) {
		strncpy(serv, portbuf->buf, portbuf->len);
		serv[portbuf->len] = '\0';
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_flags = AI_NUMERICHOST;
	hints.ai_socktype = SOCK_DGRAM;
	error = getaddrinfo(addr, serv, &hints, &res);
	free(addr);
	if (serv != NULL)
		free(serv);
	if (error != 0) {
		yyerror("invalid IP address");
		__ipsec_set_strerror(gai_strerror(error));
		return NULL;
	}

	if (res->ai_addr == NULL) {
		yyerror("invalid IP address");
		__ipsec_set_strerror(gai_strerror(error));
		return NULL;
	}

	newaddr = malloc(res->ai_addrlen);
	if (newaddr == NULL) {
		__ipsec_errcode = EIPSEC_NO_BUFS;
		freeaddrinfo(res);
		return NULL;
	}
	memcpy(newaddr, res->ai_addr, res->ai_addrlen);

	freeaddrinfo(res);

	__ipsec_errcode = EIPSEC_NO_ERROR;
	return newaddr;
}

static int
rule_check(void)
{
	if (p_type == IPSEC_POLICY_IPSEC) {
		if (p_protocol == IPPROTO_IP) {
			__ipsec_errcode = EIPSEC_NO_PROTO;
			return -1;
		}

		if (p_mode != IPSEC_MODE_TRANSPORT
		 && p_mode != IPSEC_MODE_TUNNEL) {
			__ipsec_errcode = EIPSEC_INVAL_MODE;
			return -1;
		}

		if (p_src == NULL && p_dst == NULL) {
			 if (p_mode != IPSEC_MODE_TRANSPORT) {
				__ipsec_errcode = EIPSEC_INVAL_ADDRESS;
				return -1;
			}
		}
		else if (p_src->sa_family != p_dst->sa_family) {
			__ipsec_errcode = EIPSEC_FAMILY_MISMATCH;
			return -1;
		}
	}

	__ipsec_errcode = EIPSEC_NO_ERROR;
	return 0;
}

static int
init_x_policy(void)
{
	struct sadb_x_policy *p;

	if (pbuf) {
		free(pbuf);
		tlen = 0;
	}
	pbuf = malloc(sizeof(struct sadb_x_policy));
	if (pbuf == NULL) {
		__ipsec_errcode = EIPSEC_NO_BUFS;
		return -1;
	}
	tlen = sizeof(struct sadb_x_policy);

	memset(pbuf, 0, tlen);
	p = (struct sadb_x_policy *)pbuf;
	p->sadb_x_policy_len = 0;	/* must update later */
	p->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	p->sadb_x_policy_type = p_type;
	p->sadb_x_policy_dir = p_dir;
	p->sadb_x_policy_id = 0;
#ifdef HAVE_PFKEY_POLICY_PRIORITY
	p->sadb_x_policy_priority = p_priority;
#else
    /* fail if given a priority and libipsec was not compiled with 
	   priority support */
	if (p_priority != 0)
	{
		__ipsec_errcode = EIPSEC_PRIORITY_NOT_COMPILED;
		return -1;
	}
#endif

	offset = tlen;

	__ipsec_errcode = EIPSEC_NO_ERROR;
	return 0;
}

static int
set_x_request(struct sockaddr *src, struct sockaddr *dst)
{
	struct sadb_x_ipsecrequest *p;
	int reqlen;
	u_int8_t *n;

	reqlen = sizeof(*p)
		+ (src ? sysdep_sa_len(src) : 0)
		+ (dst ? sysdep_sa_len(dst) : 0);
	tlen += reqlen;		/* increment to total length */

	n = realloc(pbuf, tlen);
	if (n == NULL) {
		__ipsec_errcode = EIPSEC_NO_BUFS;
		return -1;
	}
	pbuf = n;

	p = (struct sadb_x_ipsecrequest *)&pbuf[offset];
	p->sadb_x_ipsecrequest_len = reqlen;
	p->sadb_x_ipsecrequest_proto = p_protocol;
	p->sadb_x_ipsecrequest_mode = p_mode;
	p->sadb_x_ipsecrequest_level = p_level;
	p->sadb_x_ipsecrequest_reqid = p_reqid;
	offset += sizeof(*p);

	if (set_sockaddr(src) || set_sockaddr(dst))
		return -1;

	__ipsec_errcode = EIPSEC_NO_ERROR;
	return 0;
}

static int
set_sockaddr(struct sockaddr *addr)
{
	if (addr == NULL) {
		__ipsec_errcode = EIPSEC_NO_ERROR;
		return 0;
	}

	/* tlen has already incremented */

	memcpy(&pbuf[offset], addr, sysdep_sa_len(addr));

	offset += sysdep_sa_len(addr);

	__ipsec_errcode = EIPSEC_NO_ERROR;
	return 0;
}

static void
policy_parse_request_init(void)
{
	p_protocol = IPPROTO_IP;
	p_mode = IPSEC_MODE_ANY;
	p_level = IPSEC_LEVEL_DEFAULT;
	p_reqid = 0;
	if (p_src != NULL) {
		free(p_src);
		p_src = NULL;
	}
	if (p_dst != NULL) {
		free(p_dst);
		p_dst = NULL;
	}

	return;
}

static void *
policy_parse(const char *msg, int msglen)
{
	int error;

	pbuf = NULL;
	tlen = 0;

	/* initialize */
	p_dir = IPSEC_DIR_INVALID;
	p_type = IPSEC_POLICY_DISCARD;
	policy_parse_request_init();
	__policy__strbuffer__init__(msg);

	error = yyparse();	/* it must be set errcode. */
	__policy__strbuffer__free__();

	if (error) {
		if (pbuf != NULL)
			free(pbuf);
		return NULL;
	}

	/* update total length */
	((struct sadb_x_policy *)pbuf)->sadb_x_policy_len = PFKEY_UNIT64(tlen);

	__ipsec_errcode = EIPSEC_NO_ERROR;

	return pbuf;
}

ipsec_policy_t
ipsec_set_policy(__ipsec_const char *msg, int msglen)
{
	caddr_t policy;

	policy = policy_parse(msg, msglen);
	if (policy == NULL) {
		if (__ipsec_errcode == EIPSEC_NO_ERROR)
			__ipsec_errcode = EIPSEC_INVAL_ARGUMENT;
		return NULL;
	}

	__ipsec_errcode = EIPSEC_NO_ERROR;
	return policy;
}
