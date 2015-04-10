mk/tests.mk
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

Split CONFDFILES into CONFDFILES and CONFDSUBDIRFILES.  Former goes to
CONFDDIR and latter goes to CONFDSUBDIR.  Currently it isn't possible
to install stuff into /etc/ipsec.d/

Instead of building man pages as part of make programs have "make doc"
and "make install-doc" (check automake for target names) build and
install documentation including man pages.  "make all" would depend on
both programs and doc.  Also consider "make dist" which would
pre-generate the documentation.

When on fedora/rhel, enable audit logs.  One way to implement this is
to add packaging/defaults/fedora and pull that in.  Presumably OBJDIR
would be updated to reflect this.

Delete programs/pluto/Makefile.options; ti just adds to general
confusion when looking for what/why things are happening.

delete LIBRESWANSRCDIRREL

Remove the redundant prefix in -I${SRCDIR}${LIBRESWANSRCDIR}

move modobj to under $(OBJDIR)

For install targets add the $(DESTDIR) prefix to everything; that is
$(DESTDIR)$(BINDIR) for instance.  This convention, at least for RPMs,
lets installs be directed to a staging area.

stuff under testing could do with its own unit-test.mk file - which is
just a tweak of program.mk; grep for UNITTEST

switch lib/libswan/Makefile to library.mk; it contains conditional
definitions; these can be moved to after the include of library.mk.

add depend.mk to program.mk

switch programs/pluto to program.mk

enable -std=gnu99: hopefully just slog

eliminate Makefile.manpage

OBJ.* include kernel and KVM

clean up the pluto directory some more

Free up CFLAGS, like autoconf/automake?

subdir.mk to a hard case

testing/pluto/Makefile update target

= vs := and overrides

Make --warn-undefined-variables

descend srcdir not objdir

do not generate OBJDIR make files!

eliminate Makefile.ver: this is really messy as scripts do all sorts
of wierd and wonderful stuff with it.

kvm-build-east use "make" and not "swan-build"

have swantest check exit status and bail when tests start to fail.

more stuff that shouldn't be in the repo such as generated manual pages.
