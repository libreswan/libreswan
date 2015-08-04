Overview
--------

Where is this code going?
-------------------------

The basic idea is to reduce things to the point that a Makefile looks
something like:

    PROGRAMS=foo
    include ../../mk/program.mk
    ifdef EXTRA_STUFF
    LIBS+=-lextra
    endif

Either subdirs.mk, program.mk, or library.mk gets included.

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

TODO: a.k.a. what needs fixing
------------------------------

The following are querks in the build system:

- stop library.mk switching to $(builddir)

- stop program.mk switching to $(builddir)

- recursive make targets should stick to $(srcdir); currently some
  switch back to $(builddir) at the last moment (see above)

- lib/libswan should use library.mk

- programs/pluto should to use program.mk

- remove the redundant prefix in -I${SRCDIR}${LIBRESWANSRCDIR}

- move modobj to under $(builddir)

- unit tests under testing/ could do with their own unit-test.mk file;
  grep for UNITTEST in testing's Makefile-s

- free up CFLAGS; see autoconf/automake for possible guidelines?

- be more consistent with "=", ":=" and "?="; there's a meta issue
  here - configuration files are included early leading to "?=" rather
  than late

- eliminate :: rules

- run "make --warn-undefined-variables"

- do not generate the makefiles under $(OBJDIR); need to stop things
  switching to that directory first

- eliminate Makefile.ver: this is really messy as scripts do all sorts
  of wierd and wonderful stuff with it.

The following are querks inside of pluto:

- log, as a separate line, the file's basename, line and function

- enable -std=gnu99; hopefully just slog

The following are querks in the test infrastructure:

- have *init.sh et.al. scripts always succeed.  This means that
  commands like ping that are expected to fail (demonstrating no
  conectivity) will need a "!" prefix so the failure is success.

- run ../../../testing/guestbin/swan-init (a relative path within the
  current test tree), and not /testing/guestbin/swan-init

- support multiple run files (for instance run1east.sh, run2west.sh,
  ...); this will allow more complicated tests such as where west
  establishes a connection but east triggers the re-establish

- speed up ping aka liveness tests

- simplify fips check

- eliminate test results "incomplete" and "bad"
