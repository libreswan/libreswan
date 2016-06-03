/*
 * show the host keys in various formats, for libreswan
 *
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 1999, 2000, 2001  Henry Spencer.
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009 Stefan Arentz <stefan@arentz.ca>
 * Copyright (C) 2010 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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
#include "lswnss.h"

#include <nss.h>
#include <keyhi.h>
#include <prerror.h>
#include <prinit.h>

char usage[] =
	"Usage: ipsec showhostkey --ipseckey | --left | --right\n"
	"                         [--configdir <configdir> ]"
#if 0
	"                         [--password <password> ]\n"
#endif
	"                         [--precedence <precedence> ] [--gateway <gateway>]\n"
	"                         [--dump ] [--list ]\n"
	"                         [--dhclient ] [--file secretfile ]\n"
	"                         [--keynum count ] [--id identity ] [--ckaid <ckaid>]\n"
	"                         [--rsaid keyid ] [--verbose] [--version]\n";

/*
 * For new options, avoid magic numbers.
 *
 * XXX: Can fix old options later.
 */
enum opt {
	OPT_CONFIGDIR,
	OPT_PASSWORD,
	OPT_CKAID,
};

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
	{ "ckaid",     required_argument, NULL, OPT_CKAID, },
	{ "rsaid",     required_argument, NULL, 'I', },
	{ "version",   no_argument,     NULL,  'V', },
	{ "verbose",   no_argument,     NULL,  'v', },
	{ "configdir", required_argument,     NULL,  OPT_CONFIGDIR, },
#if 0
	{ "password",  required_argument,     NULL,  OPT_PASSWORD, },
#endif
	{ 0,           0,      NULL,   0, }
};

char *progname = "ipsec showhostkey";   /* for messages */

static void print(struct private_key_stuff *pks,
		  int lineno, int count, struct id *id,
		  bool disclose)
{
	char idb[IDTOA_BUF] = "n/a";
	if (id) {
		idtoa(id, idb, IDTOA_BUF);
	}

	char pskbuf[128] = "";
	if (pks->kind == PPK_PSK || pks->kind == PPK_XAUTH) {
		datatot(pks->u.preshared_secret.ptr,
			pks->u.preshared_secret.len,
			'x', pskbuf, sizeof(pskbuf));
	}

	switch (pks->kind) {
	case PPK_PSK:
		printf("%d(%d): PSK keyid: %s\n", lineno, count, idb);
		if (disclose)
			printf("    psk: \"%s\"\n", pskbuf);
		break;

	case PPK_RSA: {
		char *ckaid = ckaid_as_string(pks->u.RSA_private_key.pub.ckaid);
		char *keyid = pks->u.RSA_private_key.pub.keyid;
		printf("%d(%d): RSA ", lineno, count);
		if (keyid[0]) {
			printf("keyid: %s", keyid);
		} else {
			printf("keyid: <missing-pubkey>");
		}
		printf(" id: %s CKAID: %s\n", idb, ckaid);
		pfree(ckaid);
		break;
	}

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
}

static void print_key(struct secret *secret,
		      struct private_key_stuff *pks,
		      bool disclose)
{
	if (secret) {
		int count = 1;
		int lineno = lsw_get_secretlineno(secret);
		struct id_list *l = lsw_get_idlist(secret);
		while (l != NULL) {
			print(pks, lineno, count, &l->id, disclose);
			l = l->next;
			count++;
		}
	} else {
		print(pks, 0, 0, NULL, disclose);
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

static int pick_by_rsakeyid(struct secret *secret UNUSED,
			    struct private_key_stuff *pks,
			    void *uservoid)
{
	char *rsakeyid = (char *)uservoid;

	if (streq(pks->u.RSA_private_key.pub.keyid, rsakeyid))
		return 0;

	return 1;
}

static int pick_by_ckaid(struct secret *secret UNUSED,
			 struct private_key_stuff *pks,
			 void *uservoid)
{
	char *start = (char *)uservoid;
	if (ckaid_starts_with(pks->u.RSA_private_key.pub.ckaid, start)) {
		/* try again */
		return 1;
	}
	return 0;
}

static struct secret *pick_key(struct secret *host_secrets,
			       char *idname)
{
	struct id id;
	struct secret *s;
	err_t e = atoid(idname, &id, FALSE, FALSE);

	if (e != NULL) {
		printf("%s: key '%s' is invalid\n", progname, idname);
		return NULL;
	}

	s = lsw_find_secret_by_id(host_secrets, PPK_RSA,
				  &id, NULL, TRUE /* asymmetric */);

	if (s == NULL) {
		char abuf[IDTOA_BUF];
		idtoa(&id, abuf, IDTOA_BUF);
		printf("%s: cannot find key: %s (%s)\n", progname, idname,
		       abuf);
		return NULL;
	}

	return s;
}

static char *pubkey_to_rfc3110_base64(const struct RSA_public_key *pub)
{
	char* base64;
	err_t err = rsa_pubkey_to_base64(pub->e, pub->n, &base64);
	if (err) {
		fprintf(stderr, "%s: unexpected error encoing RSA public key '%s'\n",
			progname, err);
		return NULL;
	}
	return base64;
}

static int show_dnskey(struct private_key_stuff *pks,
		       int precedence,
		       char *gateway)
{
	char qname[256];
	int gateway_type = 0;

	gethostname(qname, sizeof(qname));

	if (pks->kind != PPK_RSA) {
		printf("%s: wrong kind of key %s in show_dnskey. Expected PPK_RSA.\n",
			progname, enum_name(&ppk_names, pks->kind));
		return 5;
	}

	char *base64 = pubkey_to_rfc3110_base64(&pks->u.RSA_private_key.pub);
	if (base64 == NULL) {
		return 5;
	}

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
			return 5;
		}
	}

	printf("%s.    IN    IPSECKEY  %d %d 2 %s %s\n",
	       qname, precedence, gateway_type,
	       (gateway == NULL) ? "." : gateway, base64 + sizeof("0s") - 1);
	pfree(base64);
	return 0;
}

static int show_confkey(struct private_key_stuff *pks,
			char *side)
{
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
		return 5;
	}

	char *base64 = pubkey_to_rfc3110_base64(&pks->u.RSA_private_key.pub);
	if (base64 == NULL) {
		return 5;
	}

	printf("\t# rsakey %s\n",
	       pks->u.RSA_private_key.pub.keyid);
	printf("\t%srsasigkey=%s\n", side,
	       base64);
	pfree(base64);
	return 0;
}

static struct private_key_stuff *foreach_secret(char *secrets_file, secret_eval func, void *uservoid)
{
	/*
	 * XXX: Potential Memory leak.
	 *
	 * lsw_foreach_secret() + lsw_get_pks() returns an object that
	 * must not be freed BUT lsw_nss_foreach_private_key_stuff()
	 * returns an object that must be freed.
	 *
	 * For moment ignore this - as only caller is showhostkey.c
	 * which quickly exits.
	 */
	if (secrets_file && secrets_file[0]) {
		struct secret *host_secrets = NULL;
		lsw_load_preshared_secrets(&host_secrets, secrets_file);
		struct secret *s = lsw_foreach_secret(host_secrets, func, uservoid);
		return s ? lsw_get_pks(s) : NULL;
	} else {
		lsw_nss_buf_t err;
		struct private_key_stuff *pks = lsw_nss_foreach_private_key_stuff(func, uservoid, err);
		if (err[0]) {
			fprintf(stderr, "%s: %s\n", progname, err);
			return NULL;
		}
		return pks;
	}
}

int main(int argc, char *argv[])
{
	char secrets_file[PATH_MAX] = "";
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
	char *configdir = oco->confddir;
	char *rsakeyid, *keyid;
	struct private_key_stuff *pks;
	char *ckaid = NULL;
#if 0
	char *password = NULL;
#endif

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

		case OPT_CKAID:
			ckaid = clone_str(optarg, "ckaid");
			break;

		case 'I':
			rsakeyid = clone_str(optarg, "rsakeyid");
			break;

		case OPT_CONFIGDIR:
			configdir = clone_str(optarg, "configdir");
			break;

#if 0
		case OPT_PASSWORD:
			password = clone_str(optarg, "password");
			break;
#endif

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
		fprintf(stderr, "%s using config directory \"%s\"\n",
			progname, configdir);

	int status = 0;
	lsw_nss_buf_t err;
	if (!lsw_nss_setup(configdir, LSW_NSS_READONLY, getNSSPassword, err)) {
		fprintf(stderr, "%s: %s\n", progname, err);
		exit(1);
	}

	/* options that apply to entire files */
	if (dump_flg) {
		/* dumps private key info too */
		foreach_secret(secrets_file, dump_key, NULL);
		goto out;
	}

	if (list_flg) {
		foreach_secret(secrets_file, list_key, NULL);
		goto out;
	}

	if (rsakeyid != NULL) {
		if (verbose)
			printf("; picking by rsakeyid=%s\n", rsakeyid);
		pks = foreach_secret(secrets_file, pick_by_rsakeyid, rsakeyid);
	} else if (ckaid != NULL) {
		if (verbose) {
			printf("; picking by ckaid=%s\n", ckaid);
		}
		pks = foreach_secret(secrets_file, pick_by_ckaid, ckaid);
	} else {
		if (secrets_file == NULL || secrets_file[0] == '\0') {
			fprintf(stderr, "no secrets file not specified\n");
			status = 1;
			goto out;
		}
		struct secret *host_secrets = NULL;
		lsw_load_preshared_secrets(&host_secrets, secrets_file);
		struct secret *s;
		if (keyid != NULL) {
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
		pks = s ? lsw_get_pks(s) : NULL;
	}

	if (pks == NULL) {
		printf("No keys found\n");
		status = 20;
		goto out;
	}

	if (left_flg) {
		status = show_confkey(pks, "left");
		goto out;
	}

	if (right_flg) {
		status = show_confkey(pks, "right");
		goto out;
	}

	if (ipseckey_flg) {
		status = show_dnskey(pks, precedence, gateway);
		goto out;
	}

out:
	/*
	 * XXX: pks is being leaked.
	 *
	 * Problem is that for a secret the PKS can't be freed but for
	 * NSS it can.  Not really a problem since the entire secret
	 * table gets leaked anyway.
	 */
	lsw_nss_shutdown(LSW_NSS_CLEANUP);
	exit(status);
}
