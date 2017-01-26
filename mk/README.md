
Overview
========

The kvm-* make targets provide an alternative build and test
framework.

Just keep in mind that some is experimental.


Installing KVM test domains
---------------------------


Preparation (FC23)
------------------

sudo dnf install virt-manager virt-install python3-pexpect
sudo usermod -a -G qemu cagney
sudo chmod g+w /var/lib/libvirt/qemu/


Makefile.inc.local configuration
................................

(from "make kvm-config-variables")

Before creating the test domains, the following make variables need to
be defined (these make variables are only used when creating the
domains):

    KVM_POOL: directory containg the test domain disks

    KVM_SOURCEDIR: directory to mount on /source within the domains

    KVM_TESTINGDIR: directory to mount on /testing within the domains

For a traditional test domain configuration, with a single libreswan
source directory mounted under /source, add the following to
Makefile.inc.local:

    KVM_POOL = /home/build/pool
    KVM_SOURCEDIR = $(abs_top_srcdir)
    KVM_TESTINGDIR = $(abs_top_srcdir)/testing

Alternatively, if you have multiple libreswan source directories and
would like their common parent directory to be mounted under /source
then add the following to Makefile.inc.local:

    KVM_POOL = $(abspath $(abs_top_srcdir)/../pool)
    KVM_SOURCEDIR = $(abspath $(abs_top_srcdir)/..)
    KVM_TESTINGDIR = $(abs_top_srcdir)/testing


Installing and uninstalling test networks and test domains
..........................................................

Once the make variables are set, the test networks and test domains
can be installed with:

    make install-kvm-networks
    make install-kvm-domains

If not already present, a base domain, from which the test domains are
be cloned, is also be created.

Conversely the test domains and networks can be completely uninstalled
using:

    make uninstall-kvm-networks
    make uninstall-kvm-domains

The base domain, from which the test domains are cloned, is not
uninstalled.  To also remove the base domain use:

    make uninstall-kvm-domains uninstall-kvm-base-domain

This is both to prevent accidental domain updates; and avoid the
unreliable and slow process of creating the base .qcow2 file.


Logging into a test domain
--------------------------

To get a shell prompt on a domain, such as east, use either:

    ./testing/utils/kvmsh.py east

or:

    make kvmsh-east

to exit enter the escape character '^]'.


Installing libreswan
--------------------

To install libreswan on all test domains (except nic), use:

    make kvm-install

and to install libreswan on just one domain, for instance "east", use:

    make kvm-install-east

To clean the kvm build directory use:

    make kvm-clean

(This replaces something like "make check UPDATEONLY=1")


Creating test keys
------------------

The tests requires custom keys.  They are generated using a test
domain, with:

    make kvm-keys

Please note that they are not currently automatically re-generated
(this is because of concern that critical keys may be accidentally
deleted).  To manually re-build the keys use:

    make clean-kvm-keys kvm-keys

(This replaces directly running scripts in testing/x509 directory)


Running the tests
-----------------

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
----------------------

The script kvmresults can be used to examine the results from the
current test run:

    ./testing/utils/kvmresults.py testing/pluto

(even while the testsuite is still running) and compare the results
with an earlier baseline vis:

    ./testing/utils/kvmresults.py testing/pluto ../saved-testing-pluto-directory

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
