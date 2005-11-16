/* identity representation, as in IKE ID Payloads (RFC 2407 DOI 4.6.2.1)
 * Copyright (C) 1999-2001  D. Hugh Redelmeier
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
 * RCSID $Id: id.c,v 1.46 2005/02/14 05:56:02 ken Exp $
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#ifndef HOST_NAME_MAX	/* POSIX 1003.1-2001 says <unistd.h> defines this */
# define HOST_NAME_MAX	255 /* upper bound, according to SUSv2 */
#endif
#include <sys/queue.h>

#include <openswan.h>
#include <openswan/ipsec_policy.h>

#include "constants.h"
#include "defs.h"
#include "id.h"
#include "log.h"
#include "x509.h"
#include "pgp.h"
#include "certs.h"
#include "smartcard.h"
#ifdef XAUTH_USEPAM
#include <security/pam_appl.h>
#endif
#include "connections.h"	/* needs id.h */
#include "packet.h"
#include "whack.h"

const struct id empty_id;	/* ID_NONE */

enum myid_state myid_state = MYID_UNKNOWN;
struct id myids[MYID_SPECIFIED+1];	/* %myid */
char *myid_str[MYID_SPECIFIED+1];     /* string form of IDs */

/* initialize id module
 * Fills in myid from environment variable IPSECmyid or defaultrouteaddr
 */
void
init_id(void)
{
    passert(empty_id.kind == ID_NONE);
    myid_state = MYID_UNKNOWN;
    {
	enum myid_state s;

	for (s = MYID_UNKNOWN; s <= MYID_SPECIFIED; s++)
	{
	    myids[s] = empty_id;
	    myid_str[s] = NULL;
	}
    }
    set_myid(MYID_SPECIFIED, getenv("IPSECmyid"));
    set_myid(MYID_IP, getenv("defaultrouteaddr"));
    set_myFQDN();
}

static void
calc_myid_str(enum myid_state s)
{
    /* preformat the ID name */
    char buf[IDTOA_BUF];

    idtoa(&myids[s], buf, IDTOA_BUF);
    replace(myid_str[s], clone_str(buf, "myid string"));
}


void
set_myid(enum myid_state s, char *idstr)
{
    if (idstr != NULL)
    {
	struct id id;
	err_t ugh = atoid(idstr, &id, FALSE);

	if (ugh != NULL)
	{
	    loglog(RC_BADID, "myid malformed: %s \"%s\"", ugh, idstr);
	}
	else
	{
	    free_id_content(&myids[s]);
	    unshare_id_content(&id);
	    myids[s] = id;
	    if (s == MYID_SPECIFIED)
		myid_state = MYID_SPECIFIED;

	    calc_myid_str(s);
	}
    }
}

void
set_myFQDN(void)
{
    char FQDN[HOST_NAME_MAX + 1];
    int r = gethostname(FQDN, sizeof(FQDN));

    free_id_content(&myids[MYID_HOSTNAME]);
    myids[MYID_HOSTNAME] = empty_id;
    if (r != 0)
    {
	log_errno((e, "gethostname() failed in set_myFQDN"));
    }
    else
    {
	FQDN[sizeof(FQDN) - 1] = '\0';	/* insurance */

	{
	    size_t len = strlen(FQDN);

	    if (len > 0 && FQDN[len-1] == '.')
	    {
		/* nuke trailing . */
		FQDN[len-1]='\0';
	    }
	}

	if (!strcaseeq(FQDN, "localhost.localdomain"))
	{
	    clonetochunk(myids[MYID_HOSTNAME].name, FQDN, strlen(FQDN), "my FQDN");
	    myids[MYID_HOSTNAME].kind = ID_FQDN;
	    calc_myid_str(MYID_HOSTNAME);
	}
    }
}

void
show_myid_status(void)
{
    char idstr[IDTOA_BUF];

    (void)idtoa(&myids[myid_state], idstr, sizeof(idstr));
    whack_log(RC_COMMENT, "%%myid = %s", idstr);
}

/*  Note that there may be as many as six IDs that are temporary at
 *  one time before unsharing the two ends of a connection. So we need
 *  at least six temporary buffers for DER_ASN1_DN IDs.
 *  We rotate them. Be careful!
 */
#define	MAX_BUF		6

char*
temporary_cyclic_buffer(void)
{
    static char buf[MAX_BUF][IDTOA_BUF];	/* MAX_BUF internal buffers */
    static int counter = 0;			/* cyclic counter */

    if (++counter == MAX_BUF) counter = 0;	/* next internal buffer */
    return buf[counter];			/* assign temporary buffer */
}

/* Convert textual form of id into a (temporary) struct id.
 * Note that if the id is to be kept, unshare_id_content will be necessary.
 */
err_t
atoid(char *src, struct id *id, bool myid_ok)
{
    err_t ugh = NULL;

    *id = empty_id;

    if (myid_ok && streq("%myid", src))
    {
	id->kind = ID_MYID;
    }
    else if (strchr(src, '=') != NULL)
    {
	/* we interpret this as an ASCII X.501 ID_DER_ASN1_DN */
	id->kind = ID_DER_ASN1_DN;
	id->name.ptr = temporary_cyclic_buffer(); /* assign temporary buffer */
	id->name.len = 0;
	/* convert from LDAP style or openssl x509 -subject style to ASN.1 DN
	 * discard optional @ character in front of DN
	 */
	ugh = atodn((*src == '@')?src+1:src, &id->name);
    }
    else if (strchr(src, '@') == NULL)
    {
	if (streq(src, "%any") || streq(src, "0.0.0.0"))
	{
	    /* any ID will be accepted */
	    id->kind = ID_NONE;
	}
	else
	{
	   /* !!! this test is not sufficient for distinguishing address families.
	    * We need a notation to specify that a FQDN is to be resolved to IPv6.
	    */
	   const struct af_info *afi = strchr(src, ':') == NULL
	? &af_inet4_info: &af_inet6_info;

	   id->kind = afi->id_addr;
	   ugh = ttoaddr(src, 0, afi->af, &id->ip_addr);
	}
    }
    else
    {
	if (*src == '@')
	{
	    if (*(src+1) == '#')
	    {
		/* if there is a second specifier (#) on the line
		 * we interprete this as ID_KEY_ID
		 */
		id->kind = ID_KEY_ID;
		id->name.ptr = src;
		/* discard @~, convert from hex to bin */
		ugh = ttodata(src+2, 0, 16, id->name.ptr, strlen(src), &id->name.len);
	    }
	    else if (*(src+1) == '~')
	    {
		/* if there is a second specifier (~) on the line
		* we interprete this as a binary ID_DER_ASN1_DN
		*/
		id->kind = ID_DER_ASN1_DN;
		id->name.ptr = src;
		/* discard @~, convert from hex to bin */
		ugh = ttodata(src+2, 0, 16, id->name.ptr, strlen(src), &id->name.len);
	    }
	    else if (*(src+1) == '[')
	    {
		/* if there is a second specifier ([) on the line
		 * we interprete this as a text ID_KEY_ID, and we remove
		 * a trailing ", if there is one.
		 */
		int len = strlen(src+2);

		id->kind = ID_KEY_ID;
		id->name.ptr = src+2;

		if(src[len+2]==']')
		{
		    src[len+2-1]='\0';
		    len--;
		}
		id->name.len = len;
	    }
	    else
	    {
		id->kind = ID_FQDN;
		id->name.ptr = src+1;	/* discard @ */
		id->name.len = strlen(src)-1;
	    }
	}
	else
	{
	    /* We leave in @, as per DOI 4.6.2.4
	     * (but DNS wants . instead).
	     */
	    id->kind = ID_USER_FQDN;
	    id->name.ptr = src;
	    id->name.len = strlen(src);
	}
    }
    return ugh;
}


/*
 *  Converts a binary key ID into hexadecimal format
 */
static int
keyidtoa(char *dst, size_t dstlen, chunk_t keyid)
{
    int n = datatot(keyid.ptr, keyid.len, 'x', dst, dstlen);
    return ((n < (int)dstlen)? n : (int)dstlen) - 1;
}

void
iptoid(const ip_address *ip, struct id *id)
{
    *id = empty_id;

    switch (addrtypeof(ip))
    {
    case AF_INET:
	id->kind = ID_IPV4_ADDR;
	break;
    case AF_INET6:
	id->kind = ID_IPV6_ADDR;
	break;
    default:
	bad_case(addrtypeof(ip));
    }
    id->ip_addr = *ip;
}

int
idtoa(const struct id *id, char *dst, size_t dstlen)
{
    int n;

    id = resolve_myid(id);
    switch (id->kind)
    {
    case ID_NONE:
	n = snprintf(dst, dstlen, "(none)");
	break;
    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
	n = (int)addrtot(&id->ip_addr, 0, dst, dstlen) - 1;
	break;
    case ID_FQDN:
	n = snprintf(dst, dstlen, "@%.*s", (int)id->name.len, id->name.ptr);
	break;
    case ID_USER_FQDN:
	n = snprintf(dst, dstlen, "%.*s", (int)id->name.len, id->name.ptr);
	break;
    case ID_DER_ASN1_DN:
	n = dntoa(dst, dstlen, id->name);
	break;
    case ID_KEY_ID:
	passert(dstlen > 4);
	dst[0]='@';
	dst[1]='#';
	dstlen-=2; dst+=2;
	n = keyidtoa(dst, dstlen, id->name);
	n+= 2;
	break;
    default:
	n = snprintf(dst, dstlen, "unknown id kind %d", id->kind);
	break;
    }

    /* "Sanitize" string so that log isn't endangered:
     * replace unprintable characters with '?'.
     */
    if (n > 0)
    {
	for ( ; *dst != '\0'; dst++)
	    if (!isprint(*dst))
		*dst = '?';
    }

    return n;
}

/* Replace the shell metacharacters ', \, ", `, and $ in a character string
 * by escape sequences consisting of their octal values
 */
void
escape_metachar(const char *src, char *dst, size_t dstlen)
{
    while (*src != '\0' && dstlen > 4)
    {
	switch (*src)
	{
	case '\'':
	case '\\':
	case '"':
	case '`':
	case '$':
	    sprintf(dst,"\\%s%o", (*src < 64)?"0":"", *src);
	    dst += 4;
	    dstlen -= 4;
	    break;
	default:
	    *dst++ = *src;
	    dstlen--;
	}
	src++;
    }
    *dst = '\0';
}

/*
 * Remove all shell metacharacters ', \, ", `, and $ in a character string
 */
void
remove_metachar(const char *src, char *dst, size_t dstlen)
{
    while (*src != '\0' && dstlen > 1)
    {
	if((*src >= '0' && *src <= '9')
	   || (*src >= 'a' && *src <= 'z')
	   || (*src >= 'A' && *src <= 'Z')
	   || *src == '_') {
	    *dst++ = *src;
	    dstlen--;
	} 
	src++;
    }
    *dst = '\0';
}


/* Make private copy of string in struct id.
 * This is needed if the result of atoid is to be kept.
 */
void
unshare_id_content(struct id *id)
{
    switch (id->kind)
    {
    case ID_FQDN:
    case ID_USER_FQDN:
    case ID_DER_ASN1_DN:
    case ID_KEY_ID:
	id->name.ptr = clone_bytes(id->name.ptr, id->name.len, "keep id name");
	break;
    case ID_MYID:
    case ID_NONE:
    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
	break;
    default:
	bad_case(id->kind);
    }
}

void
free_id_content(struct id *id)
{
    switch (id->kind)
    {
    case ID_FQDN:
    case ID_USER_FQDN:
    case ID_DER_ASN1_DN:
    case ID_KEY_ID:
	freeanychunk(id->name);
	break;
    case ID_MYID:
    case ID_NONE:
    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
	break;
    default:
	bad_case(id->kind);
    }
}

/* compare two struct id values */
bool
same_id(const struct id *a, const struct id *b)
{
    a = resolve_myid(a);
    b = resolve_myid(b);
    if (a->kind != b->kind)
	return FALSE;
    switch (a->kind)
    {
    case ID_NONE:
	return TRUE;	/* kind of vacuous */

    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
	return sameaddr(&a->ip_addr, &b->ip_addr);

    case ID_FQDN:
    case ID_USER_FQDN:
	/* assumptions:
	 * - case should be ignored
	 * - trailing "." should be ignored (even if the only character?)
	 */
	{
	    size_t al = a->name.len
		, bl = b->name.len;

	    while (al > 0 && a->name.ptr[al - 1] == '.')
		al--;
	    while (bl > 0 && b->name.ptr[bl - 1] == '.')
		bl--;
	    return al == bl
		&& strncasecmp(a->name.ptr, b->name.ptr, al) == 0;
	}

    case ID_DER_ASN1_DN:
	return same_dn(a->name, b->name);

    case ID_KEY_ID:
	return a->name.len == b->name.len
	    && memcmp(a->name.ptr, b->name.ptr, a->name.len) == 0;

    default:
	bad_case(a->kind);
    }
}

/* compare two struct id values, DNs can contain wildcards */
bool
match_id(const struct id *a, const struct id *b, int *wildcards)
{
    
    char abuf[IDTOA_BUF];
    char bbuf[IDTOA_BUF];
    bool match;

    if (b->kind == ID_NONE)
    {
	*wildcards = MAX_WILDCARDS;
	match = TRUE;
	goto done;
    }

    if (a->kind != b->kind) {
	match = FALSE;
	goto done;
    }

    if (a->kind == ID_DER_ASN1_DN) {
	match = match_dn(a->name, b->name, wildcards);
    }
    else
    {
	*wildcards = 0;
	match = same_id(a, b);
    }

 done:
    DBG(DBG_CONTROLMORE,
	idtoa(a, abuf, IDTOA_BUF);
	idtoa(b, bbuf, IDTOA_BUF);
	DBG_log("   match_id a=%s", abuf);
	DBG_log("            b=%s", bbuf);
	DBG_log("   results  %s", match ? "matched" : "fail");
	);
    
    return match;
}

/* count the numer of wildcards in an id */
int
id_count_wildcards(const struct id *id)
{
    int count;
    char idbuf[IDTOA_BUF];

    count = 0;

    switch (id->kind)
    {
    case ID_NONE:
	count = MAX_WILDCARDS;
	break;
    case ID_DER_ASN1_DN:
	count = dn_count_wildcards(id->name);
	break;
    default:
	count = 0;
	break;
    }
	
    idtoa(id, idbuf, IDTOA_BUF);
    DBG(DBG_CONTROL,
	DBG_log("counting wild cards for %s is %d"
		, idbuf
		, count));
    
    return count;
}

/* build an ID payload
 * Note: no memory is allocated for the body of the payload (tl->ptr).
 * We assume it will end up being a pointer into a sufficiently
 * stable datastructure.  It only needs to last a short time.
 */
void
build_id_payload(struct isakmp_ipsec_id *hd, chunk_t *tl, struct end *end)
{
    const struct id *id = resolve_myid(&end->id);

    zero(hd);
    hd->isaiid_idtype = id->kind;
    switch (id->kind)
    {
    case ID_NONE:
	hd->isaiid_idtype = aftoinfo(addrtypeof(&end->host_addr))->id_addr;
	tl->len = addrbytesptr(&end->host_addr
	    , (const unsigned char **)&tl->ptr);	/* sets tl->ptr too */
	break;
    case ID_FQDN:
    case ID_USER_FQDN:
    case ID_DER_ASN1_DN:
    case ID_KEY_ID:
	*tl = id->name;
	break;
    case ID_IPV4_ADDR:
    case ID_IPV6_ADDR:
	tl->len = addrbytesptr(&id->ip_addr
	    , (const unsigned char **)&tl->ptr);	/* sets tl->ptr too */
	break;
    default:
	bad_case(id->kind);
    }
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
