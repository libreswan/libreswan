
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

TODO: a.k.a. what needs fixing
------------------------------

The following are quirks in the build system:

- drop the ipsec_ prefix to man page names in the source tree makes
  finding them a pain

- merge config.mk and userlandcflags.mk; two types of flags are needed:
  USERLAND_CFLAGS += -D ... - defined for all builds
  <FEATURE>_LDFLAGS = ... - added as needed to an application's LDFLAGS

- build/install test applications at build/install time
  stops tests needing to get to /source (the build tree) during
  testing

- when fips, generate fipshmac checksums during install

- stop program.mk switching to $(builddir)

- recursive make targets should stick to $(srcdir); currently some
  switch back to $(builddir) at the last moment (see above)

- lib/libswan should use library.mk

- programs/pluto should to use program.mk

- remove the redundant prefix in -I${SRCDIR}${LIBRESWANSRCDIR}

- rename modobj to something more specific - like builddir

- unit tests under testing/ could do with their own unit-test.mk file;
  grep for UNITTEST in testing's Makefile-s

- free up CFLAGS; see autoconf/automake for possible guidelines?

- be more consistent with "=", ":=" and "?="; there's a meta issue
  here - configuration files are included early leading to "?=" rather
  than late

- run "make --warn-undefined-variables"

- do not generate the makefiles under $(OBJDIR); need to stop things
  switching to that directory first

- eliminate Makefile.ver: this is really messy as scripts do all sorts
  of wierd and wonderful stuff with it.

- make building individual programs configurable

- add a minimal config for small systems

The following are quirks inside of pluto:

- log, as a separate line, the file's basename, line and function

- enable -std=gnu99; hopefully just slog

The following are quirks with /testing:

- don't have /etc/ipsec.conf refer to /testing

- don't have tests run scripts in /testing

- run ../../../testing/guestbin/swan-init (a relative path within the
  current test tree), and not /testing/guestbin/swan-init

The following are quirks in the test infrastructure:

- have *init.sh et.al. scripts always succeed.  This means that
  commands like ping that are expected to fail (demonstrating no
  conectivity) will need a "!" prefix so the failure is success.

- support multiple run files (for instance run1east.sh, run2west.sh,
  ...); this will allow more complicated tests such as where west
  establishes a connection but east triggers the re-establish

- simplify fips check

- eliminate test results "incomplete" and "bad"

- swan-transmogrify runs chcon -R testing/pluto, it should only run
  that over the current test directory

- simplify and speed up ping deadness check
