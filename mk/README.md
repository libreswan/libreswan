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

Instead of including generated man pages in the source, and maybe
building them with make-programs, have make-doc and make-install-doc
targets (check automake for target names) that build and install all
documentation including man pages.  The existing make-all /
make-install targets would also build/install manages.  Finally,
consider make-dist which would pre-generate the documentation.

When on fedora/rhel, enable audit logs.  One way to implement this is
to add packaging/defaults/fedora and pull that in.  Presumably OBJDIR
would be updated to reflect this.  Mumble something about how it would
be nice if audit tests were not run on systems that did not have
audit.

When a test fails early, should sanitize.sh still be run?

Delete programs/pluto/Makefile.options; it just adds to general
confusion when looking for what/why things are happening.

Have *init.sh et.al. scripts always succeed.  This means that commands
like ping that are expected to fail (demonstrating no conectivity)
will need a "!" prefix so the failure is success.

As a separate line in the log file print the basename, line, and
function of DBG calls.

Run swan-init et.al. from ../../../testing/guestbin/ (a relative
path), and not /testing/guestbin/

delete LIBRESWANSRCDIRREL

Remove the redundant prefix in -I${SRCDIR}${LIBRESWANSRCDIR}

move modobj to under $(OBJDIR)

For install targets add the $(DESTDIR) prefix to everything; for
instance $(DESTDIR)$(BINDIR).  This convention, at least for RPMs,
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

Always decend the source directory (instead of OBJDIR) so that
subdir.mk can be used everywhere.

testing/pluto/Makefile update target

= vs := and overrides

Make --warn-undefined-variables

Do not generate OBJDIR make files.

eliminate Makefile.ver: this is really messy as scripts do all sorts
of wierd and wonderful stuff with it.

kvm-build-east use "make" and not "swan-build"

"make" run "make all".
