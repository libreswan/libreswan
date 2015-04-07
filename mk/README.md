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

TODO list
---------

delete LIBRESWANSRCDIRREL

fix code like -I${SRCDIR}${LIBRESWANSRCDIR}

stuff under testing could do with its own unit-test.mk file - which is
just a tweak of program.mk; grep for UNITTEST

switch lib/libswan/Makefile to library.mk; it contains conditional
definitions

add depend.mk to program.mk

switch programs/pluto to program.mk

enable -std=gnu99: hopefully just slog

eliminate Makefile.program

eliminate Makefile.manpage

OBJ.* include kernel and KVM

clean up the pluto directory some more

Free up CFLAGS, like autoconf/automake?

subdir.mk to a hard case

testing/pluto/Makefile update target

= vs := and overrides

Make --warn-undefined-variables

descend srcdir not objdir

eliminate Makefile.ver: this is really messy as scripts do all sorts
of wierd and wonderful stuff with it.

kvm-build-east use "make" and not "swan-build"

have swantest check exit status and bail when tests start to fail.

more stuff that shouldn't be in the repo such as generated manual pages.
