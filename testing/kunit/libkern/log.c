/*

   Copyright (c) 2003,2004 Jeremy Kerr & Rusty Russell

   This file is part of nfsim.

   nfsim is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   nfsim is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with nfsim; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define _GNU_SOURCE
#include "core.h"
#include "tui.h"
#include "expect.h"
#include "utils.h"

#include <list.h>

static struct {
	enum log_type type;
	char *          name;
} log_names[] = {
	{ LOG_KERNEL,   "kernel" },
	{ LOG_UI,       "ui" },
	{ LOG_ROUTE,    "route" },
	{ LOG_PROTOCOL, "protocol" },
	{ LOG_USERSPACE, "userspace" },
	{ LOG_PACKET,   "packet" },
	{ LOG_HOOK,     "hook" },
	{ 0, NULL }
};

static FILE *logstream;
static int typemask = 0;
static int describe_packets;

#define PRINTK_BUFSIZ 4096
/* Rusty says: only hippies need two pointers. */
static char printk_buf[PRINTK_BUFSIZ];

int log_describe_packets(void)
{
	return describe_packets;
}

bool nfsim_log(enum log_type type, const char *format, ...)
{
	va_list ap;
	char *line;
	bool ret;

	va_start(ap, format);
	line = talloc_vasprintf(NULL, format, ap);
	va_end(ap);

	if (!type || (type & typemask))
		fprintf(logstream ? : stderr, "%s\n", line);

	ret = expect_log_hook(line);
	talloc_free(line);
	return ret;
}

static void nfsim_log_partial_v(enum log_type type,
				char *buf,
				unsigned bufsize,
				const char *format,
				va_list ap)
{
	char *ptr;
	int len = strlen(buf);

	/* write to the end of buffer */
	if (vsnprintf(buf + len, bufsize - len - 1, format, ap) >
	    bufsize - len - 1)
		nfsim_log(LOG_ALWAYS, "nfsim_log_partial buffer is full!");

	ptr = buf;

	/* print each bit that ends in a newline */
	for (len = strcspn(ptr, "\n"); *(ptr + len);
	     ptr += len, len = strcspn(ptr, "\n"))
		nfsim_log(type, "%.*s", len++, ptr);

	/* if we've printed, copy any remaining (non-newlined)
	   parts (including the \0) to the front of buf */
	memmove(buf, ptr, strlen(ptr) + 1);
}

void nfsim_log_partial(enum log_type type, char *buf, unsigned bufsize,
		       const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	nfsim_log_partial_v(type, buf, bufsize, format, ap);
	va_end(ap);
}

void printk(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	nfsim_log_partial_v(LOG_KERNEL, printk_buf, PRINTK_BUFSIZ, format, ap);
	va_end(ap);
}

static inline int parsetype(const char *type)
{
	int i;

	for (i = 0; log_names[i].type; i++)
		if (streq(log_names[i].name, type))
			return log_names[i].type;

	return 0;
}

static bool log_admin(int argc, char **argv)
{
	char *logname;
	int i;

	if (argc == 1) {

		nfsim_log(LOG_ALWAYS, "current log types:", typemask);

		i = 0;
		while ((logname = log_names[i].name)) {
			if (typemask & log_names[i].type)
				nfsim_log(LOG_ALWAYS, "\t%s",
					  log_names[i].name);
			i++;
		}
		return true;
	}

	if ((argc == 2 || argc == 3) &&
	    strcaseeq(argv[1], "describe_packets")) {

		if (argc == 3) {
			describe_packets = strcaseeq(argv[2], "on") ||
					   strcaseeq(argv[2], "true");
		}

		nfsim_log(argc == 2 ? LOG_ALWAYS : LOG_UI,
			  "packet descriptions are %s",
			  describe_packets ? "on" : "off");

		return false;
	}

	if (argc > 1 && streq(*argv[1] == 't' ? argv[1] : argv[1] + 1,
				"types") ) {

		int newtypemask = 0;
		for (i = 2; i < argc; i++) {
			int type;

			if (!(type = parsetype(argv[i]))) {
				nfsim_log(LOG_ALWAYS, "no such type %s",
					  argv[i]);
				return false;
			}
			newtypemask |= type;
		}

		switch (*argv[1]) {
		case 't':
		case '=':
			typemask = newtypemask;
			break;
		case '-':
			typemask &= ~newtypemask;
			break;
		case '+':
			typemask |= newtypemask;
			break;
		default:
			nfsim_log(LOG_ALWAYS, "unknown modifer: %c", *argv[1]);
			return false;
		}

		return true;
	}

	nfsim_log(LOG_ALWAYS, "meep");

	return 1;

}

static void log_admin_help(int agc, char **argv)
{
#include "log-help:log"
/*** XML Help:
    <section id="c:log">
     <title><command>log</command></title>
     <para>Manage logging settings</para>
     <cmdsynopsis>
      <command>log</command>
      <group choice="opt">
       <arg choice="plain">=</arg>
       <arg choice="plain">+</arg>
       <arg choice="plain">-</arg>
      </group>
      <arg choice="req"><replaceable>type, ...</replaceable></arg>
     </cmdsynopsis>
     <para>Each log message is classified into one of the following
     types:</para>
     <variablelist>
      <varlistentry>
       <term>KERNEL</term>
       <listitem>
        <para>Kernel messages (including <function>printk()</function> calls)
        </para>
       </listitem>
      </varlistentry>
      <varlistentry>
       <term>UI</term>
       <listitem>
        <para>Messages from the user interface (deprecated?)</para>
       </listitem>
      </varlistentry>
      <varlistentry>
       <term>ROUTE</term>
       <listitem>
        <para>Routing information</para>
       </listitem>
      </varlistentry>
      <varlistentry>
       <term>PROTOCOL</term>
       <listitem>
        <para>Information from the protocol (IPv4) layer</para>
       </listitem>
      </varlistentry>
      <varlistentry>
       <term>PACKET</term>
       <listitem>
        <para>Information about packet movements (including netfilter hook
        results)</para>
       </listitem>
      </varlistentry>
     </variablelist>
     <para>The <command>log</command> command allows you to select which
      messages are displayed. By default, all messages will be shown.</para>
     <para>If the <replaceable>types</replaceable> argument is prefixed with a
   +, - or = character, those types will be added, removed or set as the
      current types of messages to be logged (repectively). If none of these
      characters is specified, = is assumed (the types are set to only those
      specified)</para>
     <para>Messages generated as a result of user input are always logged.
     </para>
    </section>
 */
}

static void log_init(void)
{
	logstream = stdout;
	if (!tui_quiet)
		typemask = -1;
	describe_packets = 1;
	memset(printk_buf, 0, PRINTK_BUFSIZ);

	tui_register_command("log", log_admin, log_admin_help);
}

init_call(log_init);
