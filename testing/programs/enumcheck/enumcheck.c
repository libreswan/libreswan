#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "constants.h"
#include "lswalloc.h"
#include "lswtool.h"
#include "jambuf.h"
#include "passert.h"
#include "pexpect.h"
#include "enum_names.h"

#define PREFIX "         "

unsigned errors;

enum enum_name_expectation {
	OPTIONAL,
	PRESENT,
	ABSENT,
};

struct clash {
	int e;
	int short_match; /* returned by match(short_name) */
};

static void test_enum(enum_names *enum_test, int i,
		      enum enum_name_expectation expect,
		      const struct clash *clash)
{
	char scratch[100];

	/* find a name, if any, for this value */
	name_buf name;
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
		jam_enum_long(&buf, enum_test, i);
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
	name_buf short_name;
	if (!enum_short(enum_test, i, &short_name)) {
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
		int short_match = (clash == NULL ? -1 : clash->short_match);
		if (short_match >= 0 && e == short_match) {
			printf("OK (clashed with %d)\n", short_match);
		} else if (short_match >= 0) {
			printf("%d ERROR (should clash with %d)\n", e, short_match);
			errors++;
		} else if (e == i) {
			printf("OK\n");
		} else {
			printf("%d ERROR\n", e);
			errors++;
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

struct bounds {
	long int floor;
	long int roof;
};

static struct bounds enum_bounds(const struct enum_names *en)
{
	/* find lower and upper bounds; might contain gaps */
	long int first = next_enum(en, -1);
	struct bounds b = {
		.floor = first,
		.roof = first+1,
	};
	for (int e = next_enum(en, first);
	     e >= 0; e = next_enum(en, e)) {
		b.roof = e+1;
	}
	return b;
}

static void test_enum_range(char *enumname, enum_names *enum_test, long int floor, long int roof)
{
	struct bounds b = enum_bounds(enum_test);
	printf("  %s: ", enumname);
	printf("[%ld", b.floor);
	if (b.floor != floor) {
		printf("(%ld)", floor);
	}
	printf("..");
	printf("%ld", b.roof);
	if (b.roof != roof) {
		printf("(%ld)", roof);
	}
	printf(")\n");
	for (int i = floor; i < roof; i++) {
		test_enum(enum_test, i, OPTIONAL, NULL);
	}
	printf("\n");
}

static void test_enums(const char *enumname, enum_names *enum_test,
		       const struct clash *clashes, struct logger *logger)
{
	struct bounds b = enum_bounds(enum_test);
	printf("  %s: [%ld..%ld)\n", enumname, b.floor, b.roof);

	/* test those next_enum() returns */
	int clashed = 0;
	for (int i = next_enum(enum_test, -1);
	     i >= 0; i = next_enum(enum_test, i)) {
		const struct clash *clash = NULL;
		for (const struct clash *c = clashes; c != NULL && c->e >= 0; c++) {
 			if (c->e == i) {
				clashed++;
				clash = c;
 				break;
 			}
 		}
		test_enum(enum_test, i, PRESENT, clash);
	}

	test_enum(enum_test, b.floor-1, ABSENT, NULL);
	test_enum(enum_test, b.roof, ABSENT, NULL);

	for (const struct clash *c = clashes; c != NULL && c->e >= 0; c++) {
		clashed--;
	}
	if (clashed != 0) {
		printf("    ERROR missing clashes %d\n", clashed);
		errors++;
	}

	/* check tables are not empty */
	unsigned level = 0;
	for (const struct enum_names *en = enum_test; en != NULL; en = en->en_next_range) {
		unsigned count = 0;
		for (unsigned i = 0; i < en->en_checklen; i++) {
			if (en->en_names[i] != NULL) {
				count++;
			}
		}
		/*
		 * The goal is to catch an array with an entry at 0
		 * and another at 64000 say.  10% is pretty arbitrary.
		 */
		if (count * 10 < en->en_checklen) {
			llog_pexpect(logger, HERE,
				     "enum table %s at level %u of size %zu only contains %u names",
				     enumname, level, en->en_checklen, count);
		}
		level++;
	}

	printf("\n");
}

static void test_enum_enum(const char *title, enum_enum_names *een,
			   unsigned long table, enum_names *en,
			   unsigned long val, bool val_ok)
{
	char scratch[100];

	printf("%s:\n", title);

	printf(PREFIX "enum_enum_name %lu %lu: ", table, val);
	name_buf name;
	bool name_ok = enum_enum_name(een, table, val, &name);
	printf("%s ", (name_ok ? name.buf : "NULL"));
	if (name_ok == val_ok) {
		printf("OK\n");
	} else {
		printf("ERROR\n");
		errors++;
	}

	printf(PREFIX "enum_name table %lu: ", val);
	if (en == NULL) {
		printf("N/A\n");
	} else {
		name_buf n;
		if (enum_long(en, val, &n)) {
			/*
			 * Should point to the same static string.
			 * name.buf and n.buf are never NULL.
			 */
			if (name.buf == n.buf) {
				printf("OK\n");
			} else {
				printf("ERROR (pointer)\n");
				errors++;
			}
		} else if (!name_ok) {
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
		if (val_ok && hunk_streq(s, name.buf)) {
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
		name_buf enb;
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

	init_enum_names();

	for (const struct enum_names_check *c = enum_names_checklist;
	     c->name != NULL && c->enum_names != NULL; c++) {
		if (c->enum_names == &encapsulation_mode_names) {
			test_enum_range("encapsulation_mode_names", &encapsulation_mode_names, 0, 256);
		} else if (c->enum_names == &event_type_names) {
			static const struct clash clash[] = {
				{ EVENT_v1_EXPIRE, EVENT_v2_EXPIRE, },
				{ EVENT_v1_DISCARD, EVENT_v2_DISCARD, },
				{ EVENT_v1_REPLACE, EVENT_v2_REPLACE, },
				{ EVENT_v1_RETRANSMIT, EVENT_v2_RETRANSMIT, },
				{ EVENT_v1_NAT_KEEPALIVE, EVENT_v2_NAT_KEEPALIVE, },
				{ -1, -1, },
			};
			test_enums("event_type_names", c->enum_names, clash, logger);
		} else {
			test_enums(c->name, c->enum_names, NULL, logger);
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
