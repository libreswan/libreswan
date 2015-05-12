Overview
--------

mk/manpages.mk
--------------

The make variable MANPAGES contains the list of man pages to be built
and installed.  For instance, assuming there is foo.3.xml source, then:

  MANPAGES += foo.3

will build/install foo.3 into $(MANDIR.3) (man3).  If the .xml source
is being generated (into $(builddir)/foo.3.xml) then $(builddir)
should be specified vis:

  MANPAGES += $(builddir)/foo.3

If the .xml file specifies multiple <refname></refname> entries then
they will all be installed (see packaging/utils/refname.sh).

mk/find.sh
----------

This script outputs a list of everything that might be make file
related.  For instance:

  ./mk/find.sh | xargs grep PROGRAMS

mk/tests.sh
-----------

This script goes through a whole heap of make commands, such as
sub-directory clean/build, that should work.

Where is this code going?
-------------------------

The basic idea is to reduce things to the point that a Makefile looks
something like:

    PROGRAMS=foo
    include ../../mk/program.mk
    ifdef EXTRA_STUFF
    LIBS+=-lextra
    endif

This means:

- the srcdir/objdir shuffle has to go
- all the flags get set up
- all the auto-dependency stuff is delt with
- makefiles use a small well-defined set of flags

And a small set of well defined targets work:

- make (default to programs or all?)
- make install
- make clean
- make distclean?

TODO: a.k.a. what needs fixing in the existing build system
-----------------------------------------------------------

switch lib/libswan to using library.mk; having more recursive targets
descend $(srcdir) is predicated on this.

switch programs/pluto to using program.mk; having more recursive
targets descend $(srcdir) is predicated on this.

switch initsystems to using subdirs.mk; this means also cleaning up
sub-directories; for now might be safer to keep adding hacks.

switch packaging to using subdirs.mkl this means also cleaning up
sub-directories; for now might be safer to keep adding hacks.

have "make install-programs" descend $(srcdir)

have "make install" descend $(srcdir); "make install-manpages" already
works so just need to fix above.

have "make programs" descend $(srcdir)

have "make all" descend $(srcdir); "make manpages" already works so
just need to fix above.

Expand $(OBJDIR) to include more build specific information such as
.kvm, the actual kernel, and any thing else.

When on fedora/rhel, enable audit logs.  One way to implement this is
to add packaging/defaults/fedora and pull that in.  Presumably OBJDIR
would be updated to reflect this.  Mumble something about how it would
be nice if audit tests were not run on systems that did not have
audit.

merge sanitize.sh and re-sanitize.sh

when a test fails early, should sanitize.sh still be run?

Have *init.sh et.al. scripts always succeed.  This means that commands
like ping that are expected to fail (demonstrating no conectivity)
will need a "!" prefix so the failure is success.

As a separate line in the log file print the basename, line, and
function of DBG calls.

Run swan-init et.al. from ../../../testing/guestbin/ (a relative
path), and not /testing/guestbin/

Remove the redundant prefix in -I${SRCDIR}${LIBRESWANSRCDIR}

move modobj to under $(builddir)

stuff built under testing/ could do with its own unit-test.mk file -
which is just a tweak of program.mk; grep for UNITTEST

add depend.mk to program.mk

enable -std=gnu99: hopefully just slog

Free up CFLAGS, like autoconf/automake?

= vs :=

eliminate :: rules

Make --warn-undefined-variables

Do not generate OBJDIR make files.

eliminate Makefile.ver: this is really messy as scripts do all sorts
of wierd and wonderful stuff with it.

kvm-build-east use "make" and not "swan-build"

"make" run "make all".
