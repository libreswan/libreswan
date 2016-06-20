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
  "Usage: ipsec showhostkey [ --verbose ]\n"
  "                    { --version | --dump | --list | --left | --right |\n"
  "                      --ipseckey [ --precedence <precedence> ] [ --gateway <gateway> ] }\n"
  "                    [ --rsaid <rsaid> | --ckaid <ckaid> ]\n"
  "                    [ --configdir <configdir> ] [ --password <password> ]\n";

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
	{ "ckaid",     required_argument, NULL, OPT_CKAID, },
	{ "rsaid",     required_argument, NULL, 'I', },
	{ "version",   no_argument,     NULL,  'V', },
	{ "verbose",   no_argument,     NULL,  'v', },
	{ "configdir", required_argument,     NULL,  OPT_CONFIGDIR, },
	{ "password",  required_argument,     NULL,  OPT_PASSWORD, },
	{ 0,           0,      NULL,   0, }
};

char *progname = "ipsec showhostkey";   /* for messages */

static void print(struct private_key_stuff *pks,
		  int count, struct id *id, bool disclose)
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

	if (count) {
		/* ipsec.secrets format */
		printf("%d(%d): ", pks->line, count);
	} else {
		/* NSS format */
		printf("<%2d> ", pks->line);
	}

	switch (pks->kind) {
	case PPK_PSK:
		printf("PSK keyid: %s\n", idb);
		if (disclose)
			printf("    psk: \"%s\"\n", pskbuf);
		break;

	case PPK_RSA: {
		printf("RSA");
		char *keyid = pks->u.RSA_private_key.pub.keyid;
		printf(" keyid: %s", keyid[0] ? keyid : "<missing-pubkey>");
		if (id) {
			printf(" id: %s", idb);
		}
		char *ckaid = ckaid_as_string(pks->u.RSA_private_key.pub.ckaid);
		printf(" ckaid: %s\n", ckaid);
		pfree(ckaid);
		break;
	}

	case PPK_XAUTH:
		printf("XAUTH keyid: %s\n", idb);
		if (disclose)
			printf("    xauth: \"%s\"\n", pskbuf);
		break;
	case PPK_NULL:
		/* can't happen but the compiler does not know that */
		printf("NULL authentication -- cannot happen: %s\n", idb);
		abort();
	}
}

static void print_key(struct secret *secret,
		      struct private_key_stuff *pks,
		      bool disclose)
{
	if (secret) {
		int count = 1;
		struct id_list *l = lsw_get_idlist(secret);
		while (l != NULL) {
			print(pks, count, &l->id, disclose);
			l = l->next;
			count++;
		}
	} else {
		print(pks, 0, NULL, disclose);
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

static int pick_by_rsaid(struct secret *secret UNUSED,
			 struct private_key_stuff *pks,
			 void *uservoid)
{
	char *rsaid = (char *)uservoid;

	if (pks->kind == PPK_RSA && streq(pks->u.RSA_private_key.pub.keyid, rsaid)) {
		/* stop */
		return 0;
	} else {
		/* try again */
		return 1;
	}
}

static int pick_by_ckaid(struct secret *secret UNUSED,
			 struct private_key_stuff *pks,
			 void *uservoid)
{
	char *start = (char *)uservoid;
	if (pks->kind == PPK_RSA && ckaid_starts_with(pks->u.RSA_private_key.pub.ckaid, start)) {
		/* stop */
		return 0;
	} else {
		/* try again */
		return 1;
	}
}

static char *pubkey_to_rfc3110_base64(const struct RSA_public_key *pub)
{
	if (pub->e.len == 0 || pub->n.len == 0) {
		fprintf(stderr, "%s: public key not found\n",
			progname);
		return NULL;
	}
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
		fprintf(stderr, "%s: wrong kind of key %s in show_dnskey. Expected PPK_RSA.\n",
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
			fprintf(stderr, "%s: unknown address family for gateway %s",
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
		fprintf(stderr, "%s: wrong kind of key %s in show_confkey. Expected PPK_RSA.\n",
			progname, enumstr);
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

static struct private_key_stuff *foreach_secret(secret_eval func, void *uservoid)
{
	lsw_nss_buf_t err = {0};
	struct private_key_stuff *pks = lsw_nss_foreach_private_key_stuff(func, uservoid, err);
	if (err[0]) {
		fprintf(stderr, "%s: %s\n", progname, err);
		return NULL;
	}
	return pks;
}

int main(int argc, char *argv[])
{
	int opt;
	bool left_flg = FALSE;
	bool right_flg = FALSE;
	bool dump_flg = FALSE;
	bool list_flg = FALSE;
	bool ipseckey_flg = FALSE;
	char *gateway = NULL;
	int precedence = 10;
	char *ckaid = NULL;
	char *rsaid = NULL;

	log_to_stderr = FALSE;
	tool_init_log();

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
						"%s: precedence malformed: %s\n", progname, ugh);
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

		case OPT_CKAID:
			ckaid = clone_str(optarg, "ckaid");
			break;

		case 'I':
			rsaid = clone_str(optarg, "rsaid");
			break;

		case OPT_CONFIGDIR:
#if 0
			/*
			 * Will mean adding extra --nssdb option.
			 */
			lsw_conf_configddir(optarg);
#else
			lsw_init_ipsecdir(optarg);
#endif
			break;

		case OPT_PASSWORD:
			lsw_conf_nsspassword(optarg);
			break;

		case 'n':
		case 'h':
			break;

		case 'v':
			log_to_stderr = TRUE;
			break;

		case 'V':
			fprintf(stdout, "%s\n", ipsec_version_string());
			exit(0);

		default:
			goto usage;
		}
	}

	if (!(left_flg + right_flg + ipseckey_flg + dump_flg + list_flg)) {
		fprintf(stderr, "%s: You must specify an operation\n", progname);
		goto usage;
	}

	if ((left_flg + right_flg + ipseckey_flg + dump_flg + list_flg) > 1) {
		fprintf(stderr, "%s: You must specify only one operation\n",
			progname);
		goto usage;
	}

	if ((left_flg + right_flg + ipseckey_flg) && !ckaid && !rsaid) {
		fprintf(stderr, "%s: You must select a key using --ckaid or --rsaid\n",
			progname);
		goto usage;
	}

	if ((dump_flg + list_flg) && (ckaid || rsaid)) {
		fprintf(stderr, "%s: You must not select a key\n",
			progname);
		goto usage;
	}

	/*
	 * Don't fetch the config options until after they have been
	 * processed, and really are "constant".
	 */
	const struct lsw_conf_options *oco = lsw_init_options();
	libreswan_log("using config directory \"%s\"\n", oco->confddir);

	/*
	 * Set up for NSS - contains key pairs.
	 */
	int status = 0;
	lsw_nss_buf_t err;
	if (!lsw_nss_setup(oco->nssdb, LSW_NSS_READONLY,
			   lsw_nss_get_password, err)) {
		fprintf(stderr, "%s: %s\n", progname, err);
		exit(1);
	}

	/* options that apply to entire files */
	if (dump_flg) {
		/* dumps private key info too */
		foreach_secret(dump_key, NULL);
		goto out;
	}

	if (list_flg) {
		foreach_secret(list_key, NULL);
		goto out;
	}

	struct private_key_stuff *pks;
	if (rsaid != NULL) {
		if (log_to_stderr)
			printf("%s picking by rsaid=%s\n",
			       ipseckey_flg ? ";" : "\t#", rsaid);
		pks = foreach_secret(pick_by_rsaid, rsaid);
	} else if (ckaid != NULL) {
		if (log_to_stderr) {
			printf("%s picking by ckaid=%s\n",
			       ipseckey_flg ? ";" : "\t#", ckaid);
		}
		pks = foreach_secret(pick_by_ckaid, ckaid);
	} else {
		fprintf(stderr, "%s: nothing to do\n", progname);
		status = 1;
		goto out;
	}

	if (pks == NULL) {
		fprintf(stderr, "%s: No keys found\n", progname);
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
	lsw_nss_shutdown();
	exit(status);

usage:
	fputs(usage, stderr);
	exit(1);
}
