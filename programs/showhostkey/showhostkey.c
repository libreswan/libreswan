/*
 * show the host keys in various formats, for libreswan
 *
 * Copyright (C) 2005 Michael Richardson <mcr@xelerance.com>
 * Copyright (C) 1999, 2000, 2001  Henry Spencer.
 * Copyright (C) 2003-2008 Michael C Richardson <mcr@xelerance.com>
 * Copyright (C) 2003-2010 Paul Wouters <paul@xelerance.com>
 * Copyright (C) 2009 Avesh Agarwal <avagarwa@redhat.com>
 * Copyright (C) 2009 Stefan Arentz <stefan@arentz.ca>
 * Copyright (C) 2010, 2016 Tuomo Soini <tis@foobar.fi>
 * Copyright (C) 2012-2013 Paul Wouters <pwouters@redhat.com>
 * Copyright (C) 2012 Paul Wouters <paul@libreswan.org>
 * Copyright (C) 2016 Andrew Cagney <cagney@gnu.org>
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
#include "lswtool.h"
#include "ip_info.h"

#include <keyhi.h>
#include <prerror.h>
#include <prinit.h>

char usage[] =
	"Usage: showhostkey [ --verbose ] [ --debug ]\n"
	"        { --version | --dump | --list | --left | --right |\n"
	"                --ipseckey [ --precedence <precedence> ] \n"
	"                [ --gateway <gateway> ] }\n"
	"        [ --rsaid <rsaid> | --ckaid <ckaid> ]\n"
	"        [ --nssdir <nssdir> ] [ --password <password> ]\n";

/*
 * For new options, avoid magic numbers.
 *
 * XXX: Can fix old options later.
 */
enum opt {
	OPT_CONFIGDIR = 256,
	OPT_DUMP,
	OPT_PASSWORD,
	OPT_CKAID,
	OPT_DEBUG,
};

struct option opts[] = {
	{ "help",       no_argument,            NULL,   '?', },
	{ "left",       no_argument,            NULL,   'l', },
	{ "right",      no_argument,            NULL,   'r', },
	{ "dump",       no_argument,            NULL,   OPT_DUMP, },
	{ "debug",      no_argument,            NULL,   OPT_DEBUG, },
	{ "list",       no_argument,            NULL,   'L', },
	{ "ipseckey",   no_argument,            NULL,   'K', },
	{ "gateway",    required_argument,      NULL,   'g', },
	{ "precedence", required_argument,      NULL,   'p', },
	{ "ckaid",      required_argument,      NULL,   OPT_CKAID, },
	{ "rsaid",      required_argument,      NULL,   'I', },
	{ "version",    no_argument,            NULL,   'V', },
	{ "verbose",    no_argument,            NULL,   'v', },
	{ "configdir",  required_argument,      NULL,   OPT_CONFIGDIR, }, /* obsoleted */
	{ "nssdir",     required_argument,      NULL,   'd', }, /* nss-tools use -d */
	{ "password",   required_argument,      NULL,   OPT_PASSWORD, },
	{ 0,            0,                      NULL,   0, }
};

static void print(struct private_key_stuff *pks,
		  int count, struct id *id, bool disclose)
{
	id_buf idbuf = { "n/a", };
	if (id != NULL) {
		str_id(id, &idbuf);
	}
	const char *idb = idbuf.buf;

	char pskbuf[128] = "";
	if (pks->kind == PKK_PSK || pks->kind == PKK_XAUTH) {
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
	case PKK_PSK:
		printf("PSK keyid: %s\n", idb);
		if (disclose)
			printf("    psk: \"%s\"\n", pskbuf);
		break;

	// only old/obsolete secrets entries use this
	case PKK_RSA: {
		printf("RSA");
		keyid_t keyid = pks->keyid;
		printf(" keyid: %s", str_keyid(keyid)[0] ? str_keyid(keyid) : "<missing-pubkey>");
		if (id) {
			printf(" id: %s", idb);
		}
		ckaid_buf cb;
		ckaid_t *ckaid = &pks->ckaid;
		printf(" ckaid: %s\n", str_ckaid(ckaid, &cb));
		break;
	}

	// this never has a secret entry so shouldn't ne needed
	case PKK_ECDSA: {
		break;
	}

	case PKK_XAUTH:
		printf("XAUTH keyid: %s\n", idb);
		if (disclose)
			printf("    xauth: \"%s\"\n", pskbuf);
		break;

	case PKK_PPK:
		break;

	case PKK_NULL:
		/* can't happen but the compiler does not know that */
		printf("NULL authentication -- cannot happen: %s\n", idb);
		abort();

	case PKK_INVALID:
		printf("Invalid or unknown key: %s\n", idb);
		exit(1);
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

	if (pks->kind == PKK_RSA && streq(pks->keyid.keyid, rsaid)) {
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
	if ((pks->kind == PKK_RSA || pks->kind == PKK_ECDSA) &&
	    ckaid_starts_with(&pks->ckaid, start)) {
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
		fprintf(stderr, "%s: unexpected error encoding RSA public key '%s'\n",
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

	if (pks->kind != PKK_RSA) {
		fprintf(stderr, "%s: wrong kind of key %s in show_dnskey. Expected PKK_RSA.\n",
			progname, enum_name(&pkk_names, pks->kind));
		return 5;
	}

	char *base64 = pubkey_to_rfc3110_base64(&pks->u.RSA_private_key.pub);
	if (base64 == NULL) {
		return 5;
	}

	if (gateway != NULL) {
		/* XXX: ttoaddress_dns() - knows how to figure out IPvX? */
		ip_address test;
		if (ttoaddress_dns(shunk1(gateway), &ipv4_info, &test) == NULL) {
			gateway_type = 1;
		} else if (ttoaddress_dns(shunk1(gateway), &ipv6_info, &test) == NULL) {
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
	if (pks->kind != PKK_RSA && pks->kind != PKK_ECDSA) {
		char *enumstr = "gcc is crazy";
		switch (pks->kind) {
		case PKK_PSK:
			enumstr = "PKK_PSK";
			break;
		case PKK_XAUTH:
			enumstr = "PKK_XAUTH";
			break;
		default:
			sscanf(enumstr, "UNKNOWN (%d)", (int *)pks->kind);
		}
		fprintf(stderr, "%s: wrong kind of key %s in show_confkey. Expected PKK_RSA.\n",
			progname, enumstr);
		return 5;
	}

	char *base64 = pubkey_to_rfc3110_base64(&pks->u.RSA_private_key.pub);
	if (base64 == NULL) {
		return 5;
	}

	switch (pks->kind) {
	case PKK_RSA:
		printf("\t# rsakey %s\n",
		       pks->keyid.keyid);
		printf("\t%srsasigkey=%s\n", side,
		       base64);
		pfree(base64);
		break;
	case PKK_ECDSA:
		printf("\t# ecdsakey %s\n",
		       pks->keyid.keyid);
		printf("\t%secdsasigkey=%s\n", side,
		       base64);
		pfree(base64);
		break;
	default:
		passert(FALSE);
	}

	return 0;
}

static struct private_key_stuff *lsw_nss_foreach_private_key_stuff(secret_eval func,
								   void *uservoid,
								   struct logger *logger)
{
	PK11SlotInfo *slot = lsw_nss_get_authenticated_slot(logger);
	if (slot == NULL) {
		/* already logged */
		return NULL;
	}

	SECKEYPrivateKeyList *list = PK11_ListPrivateKeysInSlot(slot);
	if (list == NULL) {
		llog(RC_LOG_SERIOUS|ERROR_STREAM, logger, "no list");
		PK11_FreeSlot(slot);
		return NULL;
	}

	int line = 1;

	struct private_key_stuff *result = NULL;

	SECKEYPrivateKeyListNode *node;
	for (node = PRIVKEY_LIST_HEAD(list);
	     !PRIVKEY_LIST_END(node, list);
	     node = PRIVKEY_LIST_NEXT(node)) {

		SECKEYPrivateKey *private_key = node->key;

		/*
		 * XXX: this code has a lot in common with secrets.c
		 * which also creates private-key-stuff.
		 */

		/* XXX: see also private_key_type_nss(pubk); */
		const struct pubkey_type *type;
		switch (SECKEY_GetPrivateKeyType(private_key)) {
		case rsaKey:
			type = &pubkey_type_rsa;
			break;
		case ecKey:
			type = &pubkey_type_ecdsa;
			break;
		default:
			continue;
		}

		SECItem *ckaid_nss = PK11_GetLowLevelKeyIDForPrivateKey(node->key); /* must free */
		if (ckaid_nss == NULL) {
			continue;
		}

		SECKEYPublicKey *pubk = SECKEY_ConvertToPublicKey(node->key);
		if (pubk == NULL) {
			continue;
		}

		struct private_key_stuff pks = {
			.pubkey_type = type,
			.kind = type->private_key_kind,
			.line = 0,
			.private_key = SECKEY_CopyPrivateKey(private_key), /* add reference */
		};

		type->extract_private_key_pubkey_content(&pks, &pks.keyid, &pks.ckaid, &pks.size,
							 pubk, ckaid_nss);

		/*
		 * Only count private keys that get processed.
		 */
		pks.line = line++;

		int ret = func(NULL, &pks, uservoid);
		if (ret == 0) {
			/*
			 * save/return the result.
			 *
			 * XXX: Potential Memory leak.
			 *
			 * lsw_foreach_secret() + lsw_get_pks()
			 * returns an object that must not be freed
			 * BUT lsw_nss_foreach_private_key_stuff()
			 * returns an object that must be freed.
			 *
			 * For moment ignore this - as only caller is
			 * showhostkey.c which quickly exits.
			 */
			result = clone_thing(pks, "pks");
			break;
		}

		type->free_secret_content(&pks);

		if (ret < 0) {
			break;
		}
	}

	SECKEY_DestroyPrivateKeyList(list);
	PK11_FreeSlot(slot);

	return result; /* could be NULL */
}

static struct private_key_stuff *foreach_secret(secret_eval func, void *uservoid, struct logger *logger)
{
	struct private_key_stuff *pks = lsw_nss_foreach_private_key_stuff(func, uservoid, logger);
	if (pks == NULL) {
		/* already logged any error */
		return NULL;
	}
	return pks;
}

int main(int argc, char *argv[])
{
	log_to_stderr = FALSE;
	struct logger *logger = tool_init_log("ipsec showhostkey");

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

		case OPT_DUMP:
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

		case OPT_CKAID:
			ckaid = clone_str(optarg, "ckaid");
			break;

		case 'I':
			rsaid = clone_str(optarg, "rsaid");
			break;

		case OPT_CONFIGDIR:	/* Obsoletd by --nssdir|-d */
		case 'd':
			lsw_conf_nssdir(optarg, logger);
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

		case OPT_DEBUG:
			cur_debugging = -1;
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
	llog(RC_LOG, logger, "using nss directory \"%s\"", oco->nssdir);

	/*
	 * Set up for NSS - contains key pairs.
	 */
	diag_t d = lsw_nss_setup(oco->nssdir, LSW_NSS_READONLY, logger);
	if (d != NULL) {
		fatal_diag(1, logger, &d, "%s", "");
	}

	int status = 0;

	/* options that apply to entire files */
	if (dump_flg) {
		/* dumps private key info too */
		foreach_secret(dump_key, NULL, logger);
		goto out;
	}

	if (list_flg) {
		foreach_secret(list_key, NULL, logger);
		goto out;
	}

	struct private_key_stuff *pks;
	if (rsaid != NULL) {
		if (log_to_stderr)
			printf("%s picking by rsaid=%s\n",
			       ipseckey_flg ? ";" : "\t#", rsaid);
		pks = foreach_secret(pick_by_rsaid, rsaid, logger);
	} else if (ckaid != NULL) {
		if (log_to_stderr) {
			printf("%s picking by ckaid=%s\n",
			       ipseckey_flg ? ";" : "\t#", ckaid);
		}
		pks = foreach_secret(pick_by_ckaid, ckaid, logger);
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
