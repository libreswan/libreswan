/*	$NetBSD: policy_token.l,v 1.10 2018/05/28 20:45:38 maxv Exp $	*/

/* Id: policy_token.l,v 1.12 2005/05/05 12:32:18 manubsd Exp */

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

%{
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <net/pfkeyv2.h>
#include <netinet/in.h>
#include PATH_IPSEC_H

#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "libpfkey.h"

#if !defined(__NetBSD__) && !defined(__FreeBSD__) && !defined(__linux__)  && \
!defined(__APPLE__) && !defined(__MACH__)
#include "y.tab.h"
#else
#include "policy_parse.h"
#endif
#define yylval __libipseclval	/* XXX */

int yylex(void);
%}

%option noyywrap
%option nounput
%option noinput

/* common section */
nl		\n
ws		[ \t]+
digit		[0-9]
hexdigit	[0-9A-Fa-f]
special		[()+\|\?\*,]
dot		\.
comma		\,
hyphen		\-
colon		\:
slash		\/
bcl		\{
ecl		\}
blcl		\[
elcl		\]
percent		\%
semi		\;
plus	\+
usec		{dot}{digit}{1,6}
comment		\#.*
ccomment	"/*"
bracketstring	\<[^>]*\>
quotedstring	\"[^"]*\"
decstring	{digit}+
hexpair		{hexdigit}{hexdigit}
hexstring	0[xX]{hexdigit}+
octetstring	{octet}({dot}{octet})+
ipaddress	[a-zA-Z0-9:\._][a-zA-Z0-9:\._]*(%[a-zA-Z0-9]+)?

%%

in		{ yylval.num = IPSEC_DIR_INBOUND; return(DIR); }
out		{ yylval.num = IPSEC_DIR_OUTBOUND; return(DIR); }
fwd		{ 
#ifdef HAVE_POLICY_FWD
		  yylval.num = IPSEC_DIR_FWD; return(DIR); 
#else
		  yylval.num = IPSEC_DIR_INBOUND; return(DIR); 
#endif
		}

priority	{ return(PRIORITY); }
prio	{ return(PRIORITY); }
low	{ yylval.num32 = PRIORITY_LOW; return(PRIO_BASE); }
def { yylval.num32 = PRIORITY_DEFAULT; return(PRIO_BASE); }
high	{ yylval.num32 = PRIORITY_HIGH; return(PRIO_BASE); }
{plus}	{ return(PLUS); }
{decstring}	{
			yylval.val.len = strlen(yytext);
			yylval.val.buf = yytext;
			return(PRIO_OFFSET);
}

discard		{ yylval.num = IPSEC_POLICY_DISCARD; return(ACTION); }
none		{ yylval.num = IPSEC_POLICY_NONE; return(ACTION); }
ipsec		{ yylval.num = IPSEC_POLICY_IPSEC; return(ACTION); }
bypass		{ yylval.num = IPSEC_POLICY_BYPASS; return(ACTION); }
entrust		{ yylval.num = IPSEC_POLICY_ENTRUST; return(ACTION); }

esp		{ yylval.num = IPPROTO_ESP; return(PROTOCOL); }
ah		{ yylval.num = IPPROTO_AH; return(PROTOCOL); }
ipcomp		{ yylval.num = IPPROTO_IPCOMP; return(PROTOCOL); }

transport	{ yylval.num = IPSEC_MODE_TRANSPORT; return(MODE); }
tunnel		{ yylval.num = IPSEC_MODE_TUNNEL; return(MODE); }

me		{ return(ME); }
any		{ return(ANY); }

default		{ yylval.num = IPSEC_LEVEL_DEFAULT; return(LEVEL); }
use		{ yylval.num = IPSEC_LEVEL_USE; return(LEVEL); }
require		{ yylval.num = IPSEC_LEVEL_REQUIRE; return(LEVEL); }
unique{colon}{decstring} {
			yylval.val.len = strlen(yytext + 7);
			yylval.val.buf = yytext + 7;
			return(LEVEL_SPECIFY);
		}
unique		{ yylval.num = IPSEC_LEVEL_UNIQUE; return(LEVEL); }
{slash}		{ return(SLASH); }

{ipaddress}	{
			yylval.val.len = strlen(yytext);
			yylval.val.buf = yytext;
			return(IPADDRESS);
		}

{hyphen}	{ return(HYPHEN); }

{blcl}{decstring}{elcl} {
			/* Remove leading '[' and trailing ']' */
			yylval.val.buf = yytext + 1;
			yylval.val.len = strlen(yytext) - 2;

			return(PORT);
		}

{ws}		{ ; }
{nl}		{ ; }

%%

void __policy__strbuffer__init__(char *);
void __policy__strbuffer__free__(void);

static YY_BUFFER_STATE strbuffer;

void
__policy__strbuffer__init__(char *msg)
{
	if (YY_CURRENT_BUFFER)
		yy_delete_buffer(YY_CURRENT_BUFFER);
	strbuffer = (YY_BUFFER_STATE)yy_scan_string(msg);
	yy_switch_to_buffer(strbuffer);

	return;
}

void
__policy__strbuffer__free__(void)
{
	yy_delete_buffer(strbuffer);

	return;
}
