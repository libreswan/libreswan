Overview
========

This directory contains the new build and test framework that is
gradually being merged into the existing build environment.

The first section of this README describes how to use this framework.
Following sections get into more technical detail.

Just keep in mind that some is experimental.


Building and testing - mk/kvm-targets.mk
----------------------------------------

mk/kvm-targets.mk implements an alternative to "make check" for using
KVM to build and test libreswan.


Setting up virtual machines
~~~~~~~~~~~~~~~~~~~~~~~~~~~

This requires two steps:

    make kvm-networks
    make kvm-domains

To build an individual domain use the target "kvm-domain-east" for
instance.  To delete the domains or networks use the targets
"clean-kvm-domains" and "clean-kvm-networks".

(This replaces the script ./testing/libvirt/install.sh)


Logging into a domain
~~~~~~~~~~~~~~~~~~~~~

To get a shell prompt on a domain, such as east, use:

    ./testing/utils/kvmsh.py east


Installing libreswan
~~~~~~~~~~~~~~~~~~~~

Use:

    make kvm-install

To install/update a single domain use a target like
"kvm-install-east".  To clean the build directory use "clean-kvm".

(This replaces something like "make check UPDATEONLY=1")


Creating test keys
~~~~~~~~~~~~~~~~~~

The tests requires custom keys.  They can be generated, using a test
domain, with:

    make kvm-keys

Please note that they are not currently automatically re-generated
(this is because of concern that critical keys may accidently be
deleted).  To manually re-build the keys use "make clean-kvm-keys
kvm-keys".

(This replaces directly running scripts in testing/x509 directory)


Running the tests
~~~~~~~~~~~~~~~~~

There are two targets available for running the testsuite.  The
difference is in how previously run tests are handled.

- run tests unconditionally:

      make kvm-test

  This target is best suited for the iterative build test cycle where
  a limited set of tests need to be run.  For instance, to update the
  domain east with the latest changes and then run a subset of tests,
  use:

      make kvm-install-east kvm-test KVM_TESTS=testing/pluto/ikev2-algo-*

- to run tests that haven't passed (i.e, un-tested and failed tests):

      make kvm-check

  This target is best suited for running or updating the entire
  testsuite.  For instance, because some tests fail intermittently, a
  second kvm-check will likely improve the test results.

(This replaces and better focuses the functionality found in "make
check" and the script testing/utils/swantest.)

(If you forget to run kvm-keys it doesn't matter, both kvm-test and
kvm-check depend on the kvm-keys target.)


Examining test results
~~~~~~~~~~~~~~~~~~~~~~

The script kvmresults can be used to examine the results from the
current test run:

    ./testing/utils/kvmresults.py testing/pluto

(even while the testsuite is still running) and compare the results
with an earlier baseline vis:

    ./testing/utils/kvmresults.py testing/pluto ../saved-testing-pluto-directory


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

TODO: Invert this rule, instead of specifying the output, specify the source files: MANPAGES += foo.3.xml

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

The following are quirks in the build system:

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

- make building individual programs configurable

- add a minimal config for small systems

The following are quirks inside of pluto:

- log, as a separate line, the file's basename, line and function

- enable -std=gnu99; hopefully just slog

- switch to vfork

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

- speed up ping aka liveness tests

- simplify fips check

- eliminate test results "incomplete" and "bad"
