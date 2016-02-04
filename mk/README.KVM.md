
Overview
========

The kvm-* make targets provide an alternative build and test
framework.

Just keep in mind that some is experimental.


Creating KVM test domains
-------------------------

This requires two steps:

    make install-kvm-networks
    make install-kvm-domains

By default, the KVM domain's mount points are set up as:

    /testing   -> current source tree's testing/ directory
    /source    -> directory above current source tree

(The latter is different to the old install.sh script).  The following
make variables (default values shown) alter this behaviour:

    KVM_OS ?= fedora
    KVM_POOL ?= /home/build/pool
    KVM_SOURCEDIR ?= $(abspath $(abs_top_srcdir)/..)
    KVM_TESTINGDIR ?= $(abs_top_srcdir)/testing

and can be overridden in Makefile.inc.local, for instance, to point
/source at just this source tree, set:

    KVM_SOURCEDIR = $(abs_top_srcdir)

To uninstall the KVM domains or networks use the targets
"uninstall-kvm-domains" and "uninstall-kvm-networks".  Individual
domains and networks can also be installed an uninstalled with make
targets like install-kvm-domain-east and uninstall-kvm-domain-east.

Note: qemu-img seems to occasionally trigger a kernel bug leading to a
corrupt .qcow2 file.  The symptom is "rpm -Va" failing really badly in
the test domains.  The make file kvm-targets.mk includes a hack -
dmesg | grep qemu-img - that tries to detect this.  The workaround is
to reboot your machine.

(This replaces the ./testing/libvirt/install.sh and
./testing/libvirt/uninstall.sh)


Rebuilding and updating the test domains
----------------------------------------

The test domains can be rebuilt with:

    make uninstall-kvm-test-domains
    make install-kvm-test-domains

They will use the base .qcow2 image created earlier.  That base .qcow2
image will not be updated.

To also force an update of the base .qcow2 image, that file will need
to be explicitly deleted.  This is both to prevent accidental domain
updates; and avoid the unreliable and slow operation of creating the
base .qcow2 file.


Logging into a test domain
--------------------------

To get a shell prompt on a domain, such as east, use:

    ./testing/utils/kvmsh.py east


Installing libreswan
--------------------

Use:

    make kvm-install

To install/update a single domain use a target like
"kvm-install-east".  To clean the build directory use:

    make kvm-clean

(This replaces something like "make check UPDATEONLY=1")


Creating test keys
------------------

The tests requires custom keys.  They are generated using a test
domain, with:

    make kvm-keys

Please note that they are not currently automatically re-generated
(this is because of concern that critical keys may be accidently
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
