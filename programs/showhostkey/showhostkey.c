/*
 * show the host keys in various formats
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 1999, 2000, 2001  Henry Spencer.
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009 Stefan Arentz <stefan@arentz.ca>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
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
 * replaces a shell script.
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <libreswan.h>
#include <sys/utsname.h>

#include <arpa/nameser.h>
/* older versions lack ipseckey support */
#ifndef ns_t_ipseckey
# define ns_t_ipseckey 45
#endif

#include "constants.h"
#include "lswlog.h"
#include "lswalloc.h"
#include "lswconf.h"
#include "secrets.h"
#include "mpzfuncs.h"

#include <nss.h>
#include <prerror.h>
#include <prinit.h>

char usage[] =
	"Usage: ipsec showhostkey [--ipseckey] | [--left ] | [--right ]\n"
	"                         [--precedence <precedence> ] [--gateway <gateway>]\n"
	"                         [--dump ] [--list ]\n"
	"                         [--dhclient ] [--file secretfile ]\n"
	"                         [--keynum count ] [--id identity ]\n"
	"                         [--rsaid keyid ] [--verbose] [--version]\n";

struct option opts[] = {
	{ "help",      no_argument,    NULL,   '?', },
	{ "left",      no_argument,    NULL,   'l', },
	{ "right",     no_argument,    NULL,   'r', },
	{ "dump",      no_argument,    NULL,   'D', },
	{ "list",      no_argument,    NULL,   'L', },
	{ "ipseckey",  no_argument,    NULL,   'K', },
	{ "gateway",   required_argument, NULL, 'g', },
	{ "precedence", required_argument, NULL, 'p', },
	{ "dhclient",  no_argument,    NULL,   'd', },
	{ "file",      required_argument, NULL, 'f', },
	{ "keynum",    required_argument, NULL, 'n', },
	{ "id",        required_argument, NULL, 'i', },
	{ "rsaid",     required_argument, NULL, 'I', },
	{ "version",   no_argument,     NULL,  'V', },
	{ "verbose",   no_argument,     NULL,  'v', },
	{ 0,           0,      NULL,   0, }
};

char *progname = "ipsec showhostkey";   /* for messages */

/* exit_tool() is needed if the library was compiled with DEBUG, even if we are not.
 * The odd-looking parens are to prevent macro expansion:
 * lswlog.h without DEBUG define a macro exit_tool().
 */
void (exit_tool)(int x)
{
	exit(x);
}

static void print_key(struct secret *secret,
		      struct private_key_stuff *pks,
		      bool disclose)
{
	int lineno = lsw_get_secretlineno(secret);
	struct id_list *l = lsw_get_idlist(secret);
	char idb[IDTOA_BUF];
	int count = 1;

	char pskbuf[128];

	if (pks->kind == PPK_PSK || pks->kind == PPK_XAUTH) {
		datatot(pks->u.preshared_secret.ptr,
			pks->u.preshared_secret.len,
			'x', pskbuf, sizeof(pskbuf));
	}

	while (l != NULL) {
		idtoa(&l->id, idb, IDTOA_BUF);

		switch (pks->kind) {
		case PPK_PSK:
			printf("%d(%d): PSK keyid: %s\n", lineno, count, idb);
			if (disclose)
				printf("    psk: \"%s\"\n", pskbuf);
			break;

		case PPK_RSA:
			printf("%d(%d): RSA keyid: %s with id: %s\n", lineno,
			       count, pks->u.RSA_private_key.pub.keyid, idb);
			break;

		case PPK_XAUTH:
			printf("%d(%d): XAUTH keyid: %s\n", lineno, count,
			       idb);
			if (disclose)
				printf("    xauth: \"%s\"\n", pskbuf);
			break;
		case PPK_NULL:
			/* can't happen but the compiler does not know that */
			printf("%d(%d): NULL authentication -- cannot happen: %s\n", lineno, count, idb);
			abort();
		}

		l = l->next;
		count++;
	}
}

static int list_key(struct secret *secret,
		    struct private_key_stuff *pks,
		    void *uservoid UNUSED)
{
	print_key(secret, pks, FALSE);
	return 1;
}

static int dump_key(struct secret *secret,
		    struct private_key_stuff *pks,
		    void *uservoid UNUSED)
{
	print_key(secret, pks, TRUE);
	return 1;
}

static int pickbyid(struct secret *secret UNUSED,
		    struct private_key_stuff *pks,
		    void *uservoid)
{
	char *rsakeyid = (char *)uservoid;

	if (streq(pks->u.RSA_private_key.pub.keyid, rsakeyid))
		return 0;

	return 1;
}

static struct secret *get_key_byid(struct secret *host_secrets, char *rsakeyid)
{
	return lsw_foreach_secret(host_secrets, pickbyid, rsakeyid);
}

static void list_keys(struct secret *host_secrets)
{
	(void)lsw_foreach_secret(host_secrets, list_key, NULL);
}

static void dump_keys(struct secret *host_secrets)
{
	(void)lsw_foreach_secret(host_secrets, dump_key, NULL);
}

static struct secret *pick_key(struct secret *host_secrets,
			char *idname)
{
	struct id id;
	struct secret *s;
	err_t e = atoid(idname, &id, FALSE, FALSE);

	if (e != NULL) {
		printf("%s: key '%s' is invalid\n", progname, idname);
		exit(4);
	}

	s = lsw_find_secret_by_id(host_secrets, PPK_RSA,
				  &id, NULL, TRUE /* asymmetric */);

	if (s == NULL) {
		char abuf[IDTOA_BUF];
		idtoa(&id, abuf, IDTOA_BUF);
		printf("%s: cannot find key: %s (%s)\n", progname, idname,
		       abuf);
		exit(5);
	}

	return s;
}

static unsigned char *pubkey_to_rfc3110(const struct RSA_public_key *pub,
				 unsigned int *keybuflen)
{
	unsigned char *buf;
	unsigned char *p;
	unsigned int elen;

	chunk_t e, n;

	e = mpz_to_n_autosize(&pub->e);
	n = mpz_to_n_autosize(&pub->n);
	elen = e.len;

	buf = alloc_bytes(e.len + n.len + 3, "buffer for rfc3110");
	p = buf;

	if (elen <= 255) {
		*p++ = elen;
	} else if ((elen & ~0xffff) == 0) {
		*p++ = 0;
		*p++ = (elen >> 8) & 0xff;
		*p++ = elen & 0xff;
	} else {
		pfree(buf);
		return 0; /* unrepresentable exponent length */
	}

	memcpy(p, e.ptr, e.len);
	p += e.len;
	memcpy(p, n.ptr, n.len);
	p += n.len;

	*keybuflen = (p - buf);

	return buf;
}

static void show_dnskey(struct secret *s,
			int precedence,
			char *gateway)
{
	char qname[256];
	char base64[8192];
	int gateway_type = 0;
	const struct private_key_stuff *pks = lsw_get_pks(s);
	unsigned char *keyblob;
	unsigned int keybloblen = 0;

	gethostname(qname, sizeof(qname));

	if (pks->kind != PPK_RSA) {
		printf("%s: wrong kind of key %s in show_dnskey. Expected PPK_RSA.\n",
			progname, enum_name(&ppk_names, pks->kind));
		exit(5);
	}

	keyblob = pubkey_to_rfc3110(&pks->u.RSA_private_key.pub, &keybloblen);

	datatot(keyblob, keybloblen, 's', base64, sizeof(base64));

	if (gateway != NULL) {
		ip_address test;
		if (ttoaddr(gateway, strlen(gateway), AF_INET,
			    &test) == NULL) {
			gateway_type = 1;
		} else if (ttoaddr(gateway, strlen(gateway), AF_INET6,
			    &test) == NULL) {
			gateway_type = 2;
		} else {
			printf("%s: unknown address family for gateway %s",
			       progname, gateway);
			exit(5);
		}
	}

	printf("%s.    IN    IPSECKEY  %d %d 2 %s %s\n",
	       qname, precedence, gateway_type,
	       (gateway == NULL) ? "." : gateway, base64 + sizeof("0s") - 1);
}

static void show_confkey(struct secret *s,
			 char *side)
{
	char base64[8192];
	const struct private_key_stuff *pks = lsw_get_pks(s);
	unsigned char *keyblob;
	unsigned int keybloblen = 0;

	if (pks->kind != PPK_RSA) {
		char *enumstr = "gcc is crazy";
		switch (pks->kind) {
		case PPK_PSK:
			enumstr = "PPK_PSK";
			break;
		case PPK_XAUTH:
			enumstr = "PPK_XAUTH";
			break;
		default:
			sscanf(enumstr, "UNKNOWN (%d)", (int *)pks->kind);
		}
		printf("%s: wrong kind of key %s in show_confkey. Expected PPK_RSA.\n", progname,
			enumstr);
		exit(5);
	}

	keyblob = pubkey_to_rfc3110(&pks->u.RSA_private_key.pub, &keybloblen);

	datatot(keyblob, keybloblen, 's', base64, sizeof(base64));

	printf("\t# rsakey %s\n",
	       pks->u.RSA_private_key.pub.keyid);
	printf("\t%srsasigkey=%s\n", side,
	       base64);
}

int main(int argc, char *argv[])
{
	char secrets_file[PATH_MAX];
	int opt;
	int errflg = 0;
	bool left_flg = FALSE;
	bool right_flg = FALSE;
	bool dump_flg = FALSE;
	bool list_flg = FALSE;
	bool ipseckey_flg = FALSE;
	bool dhclient_flg = FALSE;
	char *gateway = NULL;
	int precedence = 10;
	int verbose = 0;
	const struct lsw_conf_options *oco = lsw_init_options();
	char *rsakeyid, *keyid;
	struct secret *host_secrets = NULL;
	struct secret *s;

	rsakeyid = NULL;
	keyid = NULL;

	snprintf(secrets_file, PATH_MAX, "%s/ipsec.secrets", oco->confdir);

	while ((opt = getopt_long(argc, argv, "", opts, NULL)) != EOF) {
		switch (opt) {
		case '?':
			goto usage;
			break;

		case 'l':
			left_flg = TRUE;
			break;
		case 'r':
			right_flg = TRUE;
			break;

		case 'D': /* --dump */
			dump_flg = TRUE;
			break;

		case 'K':
			ipseckey_flg = TRUE;
			gateway = clone_str(optarg, "gateway");
			break;

		case 'p':
			{
				unsigned long u;
				err_t ugh = ttoulb(optarg, 0, 10, 255, &u);

				if (ugh != NULL) {
					fprintf(stderr,
						"precedence malformed: %s\n", ugh);
					exit(5);
				}
				precedence = u;
			}
			break;
		case 'L':
			list_flg = TRUE;
			break;

		case 's':
		case 'R':
		case 'c':
			break;

		case 'g':
			ipseckey_flg = TRUE;
			gateway = clone_str(optarg, "gateway");
			break;

		case 'd':
			break;

		case 'f': /* --file arg */
			jam_str(secrets_file, sizeof(secrets_file), optarg);
			break;

		case 'i':
			keyid = clone_str(optarg, "keyname");
			break;

		case 'I':
			rsakeyid = clone_str(optarg, "rsakeyid");
			break;

		case 'n':
		case 'h':
			break;

		case 'v':
			verbose++;
			break;

		case 'V':
			fprintf(stdout, "%s\n", ipsec_version_string());
			exit(0);

		default:
			goto usage;
		}
	}

	if (errflg) {
usage:
		fputs(usage, stderr);
		exit(1);
	}

	if (!left_flg && !right_flg && !dump_flg && !list_flg &&
	    !ipseckey_flg && !dhclient_flg) {
		fprintf(stderr, "You must specify some operation\n");
		goto usage;
	}

	if ((left_flg + right_flg + dump_flg + list_flg +
	     ipseckey_flg + dhclient_flg) > 1) {
		fprintf(stderr, "You must specify only one operation\n");
		goto usage;
	}

	if (verbose)
		fprintf(stderr, "ipsec showhostkey using nss directory: %s\n",
			oco->confddir);
	PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 1);

	{
		SECStatus rv = NSS_InitReadWrite(oco->confddir);

		if (rv != SECSuccess) {
			fprintf(stderr, "%s: NSS_InitReadWrite returned %d\n",
				progname, PR_GetError());
			exit(1);
		}
	}

	PK11_SetPasswordFunc(getNSSPassword);

	lsw_load_preshared_secrets(&host_secrets, secrets_file);

	NSS_Shutdown();
	PR_Cleanup();

	/* options that apply to entire files */
	if (dump_flg) {
		/* dumps private key info too */
		dump_keys(host_secrets);
		exit(0);
	}

	if (list_flg) {
		list_keys(host_secrets);
		exit(0);
	}

	if (rsakeyid != NULL) {
		if (verbose)
			printf("; picking by rsakeyid=%s\n", rsakeyid);
		s = get_key_byid(host_secrets, rsakeyid);
	} else if (keyid != NULL) {
		if (verbose)
			printf("; picking by keyid=%s\n", keyid);
		s = pick_key(host_secrets, keyid);
	} else {
		/* Paul: This assumption is WRONG. Mostly I have PSK's above my
		 * multiline default : RSA entry, and then this assumption breaks
		 * The proper test would be for ": RSA" vs "@something :RSA"
		 */
		/* default key is the *LAST* key, because it is first in the file.*/
		s = lsw_get_defaultsecret(host_secrets);
	}

	if (s == NULL) {
		printf("No keys found\n");
		exit(20);
	}

	if (left_flg) {
		show_confkey(s, "left");
		exit(0);
	}

	if (right_flg) {
		show_confkey(s, "right");
		exit(0);
	}

	if (ipseckey_flg)
		show_dnskey(s, precedence, gateway);

	exit(0);
}
