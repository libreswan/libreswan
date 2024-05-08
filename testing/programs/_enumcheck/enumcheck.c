#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "constants.h"
#include "lswalloc.h"
#include "lswtool.h"
#include "jambuf.h"
#include "passert.h"
#include "enum_names.h"

#define PREFIX "         "

unsigned errors;

enum enum_name_expectation {
	OPTIONAL,
	PRESENT,
	ABSENT,
};

static void test_enum(enum_names *enum_test, int i,
		      enum enum_name_expectation expect)
{
	char scratch[100];

	/* find a name, if any, for this value */
	enum_buf name;
	bool found = enum_long(enum_test, i, &name);
	switch (expect) {
	case OPTIONAL:
		if (!found) {
			return;
		}
		break;
	case PRESENT:
		if (!found) {
			printf("name for %d missing (should be present)\n", i);
			return;
		}
		break;
	case ABSENT:
		if (found) {
			printf("name for %d present (should be absent)\n", i);
		}
		return;
	}
	printf("  %3d -> %s\n", i, name.buf);

	/*
	 * So that it is easy to see what was tested, print something
	 * for every comparison.
	 */

	if (i < 0) {
		/* we are cheating: don't do the other checks */
		return;
	}

	{
		printf(PREFIX "jam_enum %d: ", i);
		struct jambuf buf = ARRAY_AS_JAMBUF(scratch);
		jam_enum(&buf, enum_test, i);
		shunk_t s = jambuf_as_shunk(&buf);
		printf(""PRI_SHUNK" ", pri_shunk(s));
		if (hunk_streq(s, name.buf)) {
			printf("OK\n");
		} else {
			printf("ERROR\n");
			errors++;
		}
	}

	{
		printf(PREFIX "search %s: ", name.buf);
		int e = enum_search(enum_test, name.buf);
		if (e != i) {
			printf("%d ERROR\n", e);
			errors++;
		} else {
			printf("OK\n");
		}
	}

	{
		printf(PREFIX "match %s: ", name.buf);
		int e = enum_match(enum_test, shunk1(name.buf));
		if (e != i) {
			printf("%d ERROR\n", e);
			errors++;
		} else {
			printf("OK\n");
		}
	}

	if (strchr(name.buf, '(') != NULL) {
		char *clone = clone_str(name.buf, "trunc_name");
		shunk_t trunc_name = shunk2(clone, strcspn(clone, "("));
		passert(clone[trunc_name.len] == '(');
		clone[trunc_name.len] = '*';
		printf(PREFIX "match "PRI_SHUNK" [trunc]: ",
		       pri_shunk(trunc_name));
		int e = enum_match(enum_test, trunc_name);
		pfree(clone);
		if (e != i) {
			printf("%d ERROR\n", e);
			errors++;
		} else {
			printf("OK\n");
		}
	}

	printf(PREFIX "short_name %d: ", i);
	enum_buf short_name;
	if (!enum_name_short(enum_test, i, &short_name)) {
		printf("ERROR\n");
		errors++;
		return;
	}
	printf("%s ", short_name.buf);
	printf("OK\n");

	{
		printf(PREFIX "jam_enum_short %d: ", i);
		struct jambuf buf = ARRAY_AS_JAMBUF(scratch);
		jam_enum_short(&buf, enum_test, i);
		shunk_t s = jambuf_as_shunk(&buf);
		printf(""PRI_SHUNK" ", pri_shunk(s));
		if (hunk_streq(s, short_name.buf)) {
			printf("OK\n");
		} else {
			printf("ERROR\n");
			errors++;
		}
	}

	{
		printf(PREFIX "jam_enum_human %d: ", i);
		struct jambuf buf = ARRAY_AS_JAMBUF(scratch);
		jam_enum_human(&buf, enum_test, i);
		shunk_t s = jambuf_as_shunk(&buf);
		printf(""PRI_SHUNK" ", pri_shunk(s));
		if (strchr(short_name.buf, '_') == NULL) {
			if (hunk_strcaseeq(s, short_name.buf)) {
				printf("OK\n");
			} else {
				printf("ERROR\n");
				errors++;
			}
		} else {
			printf("OK\n"); /* what can be checked? */
		}
	}


	if (streq(short_name.buf, name.buf)) {
		/* remaining tests redundant */
		return;
	}

	{
		printf(PREFIX "match %s [short]: ", short_name.buf);
		int e = enum_match(enum_test, shunk1(short_name.buf));
		if (e != i) {
			printf("%d ERROR\n", e);
			errors++;
		} else {
			printf("OK\n");
		}
	}

	const char *bra = strchr(short_name.buf, '(');
	if (bra != NULL) {
		int tsl = bra - short_name.buf;
		printf(PREFIX "match %.*s [short+trunc]: ", tsl, short_name.buf);
		int e = enum_match(enum_test, shunk2(short_name.buf, tsl));
		if (e != i) {
			printf("%d ERROR\n", e);
			errors++;
		} else {
			printf("OK\n");
		}
	}
}

static void test_enum_range(char *enumname, enum_names *enum_test, int floor, int long roof)
{
	printf("  %s:\n", enumname);
	for (int i = floor; i < roof; i++) {
		test_enum(enum_test, i, OPTIONAL);
	}
	printf("\n");
}

static void test_enums(const char *enumname, enum_names *enum_test)
{
	printf("  %s:\n", enumname);
	int first = -1;
	int last = -1;
	for (int i = next_enum(enum_test, -1);
	     i >= 0; i = next_enum(enum_test, i)) {
		if (first < 0) {
			first = i;
		} else if (i <= first) {
			printf("enum %d <= first %d\n", i, first);
		}
		if (i <= last) {
			printf("enum %d <= last %d\n", i, last);
		}
		last = i;
		test_enum(enum_test, i, PRESENT);
	}
	test_enum(enum_test, last + 1, ABSENT);
	printf("\n");
}

static void test_enum_enum(const char *title, enum_enum_names *een,
			   unsigned long table, enum_names *en,
			   unsigned long val, bool val_ok)
{
	char scratch[100];

	printf("%s:\n", title);

	{
		printf(PREFIX "enum_enum_table %lu: ", table);
		if (en == enum_enum_table(een, table)) {
			printf("OK\n");
		} else {
			printf("ERROR\n");
			errors++;
		}
	}

	printf(PREFIX "enum_enum_name %lu %lu: ", table, val);
	const char *name = enum_enum_name(een, table, val);
	printf("%s ", name == NULL ? "NULL" : name);
	if ((val_ok) == (name != NULL)) {
		printf("OK\n");
	} else {
		printf("ERROR\n");
		errors++;
	}

	printf(PREFIX "enum_name table %lu: ", val);
	if (en == NULL) {
		printf("N/A\n");
	} else {
		enum_buf n;
		if (enum_name(en, val, &n)) {
			/*n.buf is never NULL */
			if (name == n.buf) {
				printf("OK\n");
			} else {
				printf("ERROR (pointer)\n");
				errors++;
			}
		} else if (name == NULL) {
			printf("OK\n");
		} else {
			printf("ERROR (lookup)\n");
			errors++;
		}
	}

	{
		printf(PREFIX "jam_enum_enum %lu %lu: ", table, val);
		struct jambuf buf = ARRAY_AS_JAMBUF(scratch);
		jam_enum_enum(&buf, een, table, val);
		shunk_t s = jambuf_as_shunk(&buf);
		printf(""PRI_SHUNK" ", pri_shunk(s));
		/* ??? clang says that name might be NULL */
		if (val_ok && name == NULL) {
			printf("name == NULL\n");
		} else if (val_ok && hunk_streq(s, name)) {
			printf("OK\n");
		} else if (s.len > 0) {
			printf("OK\n");
		} else {
			printf("ERROR [empty]\n");
			errors++;
		}
	}

	{
		printf(PREFIX "jam_enum_enum_short %lu %lu: ", table, val);
		struct jambuf buf = ARRAY_AS_JAMBUF(scratch);
		jam_enum_enum_short(&buf, een, table, val);
		shunk_t s = jambuf_as_shunk(&buf);
		printf(""PRI_SHUNK" ", pri_shunk(s));
		enum_buf enb;
		if (val_ok && hunk_streq(s, str_enum_short(en, val, &enb))) {
			printf("OK\n");
		} else if (s.len > 0) {
			printf("OK\n");
		} else {
			printf("ERROR [empty]\n");
			errors++;
		}
	}
}

static void test_enum_lset(const char *name, const enum_names *en, lset_t val)
{
	printf("  %s "PRI_LSET":\n", name, val);
	printf("\t<<");
	{
		char scratch[100];
		struct jambuf buf = ARRAY_AS_JAMBUF(scratch);
		jam_lset_short(&buf, en, "+", val);
		printf(PRI_SHUNK, pri_shunk(jambuf_as_shunk(&buf)));
	}
	printf(">>");
}

int main(int argc UNUSED, char *argv[])
{
	leak_detective = true;
	struct logger *logger = tool_logger(argc, argv);

	/* don't hold back */
	setbuf(stdout, NULL);

	for (const struct enum_names_check *c = enum_names_checklist;
	     c->name != NULL && c->enum_names != NULL; c++) {
		if (c->enum_names == &encapsulation_mode_names) {
			test_enum_range("encapsulation_mode_names", &encapsulation_mode_names, 0, 256);
		} else if (c->enum_names == &ike_id_type_names) {
			test_enum_range("ike_id_type_names", &ike_id_type_names, -10, 256);
		} else if (c->enum_names == &ikev2_trans_attr_descs) {
			test_enum_range("ikev2_trans_attr_descs", &ikev2_trans_attr_descs, 0, 256);
		} else if (c->enum_names == &ikev2_trans_type_encr_names) {
			test_enum_range("ikev2_trans_type_encr_names", &ikev2_trans_type_encr_names, 0, 256);
		} else if (c->enum_names == &ipsec_attr_names) {
			test_enum_range("ipsec_attr_names", &ipsec_attr_names, 0, 256);
		} else if (c->enum_names == &modecfg_attr_names) {
			test_enum_range("modecfg_attr_names", &modecfg_attr_names, 0, 256);
		} else if (c->enum_names == &oakley_attr_names) {
			test_enum_range("oakley_attr_names", &oakley_attr_names, 0, 256);
		} else if (c->enum_names == &oakley_auth_names) {
			test_enum_range("oakley_auth_names", &oakley_auth_names, 0, 256);
		} else if (c->enum_names == &oakley_enc_names) {
			test_enum_range("oakley_enc_names", &oakley_enc_names, 0, 256);
		} else if (c->enum_names == &v1_notification_names) {
			test_enum_range("v1_notification_names", &v1_notification_names, 0, 16384);
		} else if (c->enum_names == &v2_notification_names) {
			test_enum_range("v2_notification_names", &v2_notification_names, 0, 16384);
		} else if (c->enum_names == &version_names) {
			test_enum_range("version_names", &version_names, 0, 256);
		} else if (c->enum_names == &xauth_attr_names) {
			test_enum_range("xauth_attr_names", &xauth_attr_names, 0, 256);
		} else {
			test_enums(c->name, c->enum_names);
		}
	}

	/*
	 * Some hard-wired checks of enum_enum_name.  If a lookup
	 * should fail, pass NULL for the enum table.
	 */
	test_enum_enum("IKEv2 transforms", &v2_transform_ID_enums,
		       IKEv2_TRANS_TYPE_ENCR, &ikev2_trans_type_encr_names,
		       IKEv2_ENCR_3DES, true);
	test_enum_enum("IKEv2 transforms", &v2_transform_ID_enums,
		       IKEv2_TRANS_TYPE_ROOF, NULL,
		       1, false);
	test_enum_enum("IKEv2 transforms", &v2_transform_ID_enums,
		       IKEv2_TRANS_TYPE_PRF, &ikev2_trans_type_prf_names,
		       IKEv2_PRF_INVALID, false);
	printf("\n");

	printf("jam_enum_lset_short:\n\n");
	test_enum_lset("debug", &debug_names, DBG_CRYPT|DBG_CPU_USAGE);
	printf("\n");

	if (report_leaks(logger)) {
		errors++;
	}

	if (errors > 0) {
		fprintf(stderr, "TOTAL FAILURES: %d\n", errors);
		return 1;
	}

	return 0;
}
