Running the pluto tests using namespaces
========================================

This describes how to run a subset of the `testing/pluto/` tests on a
single Linux host using namespaces (`testing/utils/nsrun`) instead of
KVM.  The GitHub Action `.github/workflows/namespace-tests.yml` runs
the same steps.

The steps were validated on Ubuntu 26.04, the same release as the
`ubuntu-26.04` GitHub runner.  The reference output in
`testing/pluto/` is generated on Fedora, so a few extra steps make an
Ubuntu host behave the same way.

All commands are run from the top of the libreswan source tree.


Host requirements
-----------------

- password-less `sudo` (nsrun creates namespaces, veth pairs and
  bridges, bind mounts directories and sets sysctls)

- a kernel with namespaces, `CONFIG_VETH`, `CONFIG_BRIDGE` and the
  XFRM (IPsec) stack, plus the algorithms used by the tests: ESP, AH,
  IPCOMP, SHA1, SHA2, MD5, NULL, DES/3DES, AES-CBC/CTR/GCM/CCM, XCBC,
  ChaCha20-Poly1305.  Ubuntu's kernels (including the runner's
  `linux-azure`) have these, mostly as modules.

- the tests run on the host itself: libreswan is installed into
  `/usr/local`, strongSwan into `/usr` and `/etc/strongswan`, and
  nsrun writes to `/run/{netns,mountns,utsns}` and `/testing`.  Use a
  VM or a throwaway machine.


Kernel configuration differences
--------------------------------

The reference output is generated with Fedora's kernel.  The test
tools accept these kernel configuration differences, so that the tests
also pass on kernels built without these options:

- without `CONFIG_XFRM_SUB_POLICY` (for instance the runner's
  `linux-azure`), the kernel doesn't report a policy's type, so
  `ip xfrm policy` prints `dir in priority 1757393` instead of
  `dir in priority 1757393 ptype main`.  The sanitizer
  `testing/sanitizers/ipsec-kernel-policy.sed` rewrites such lines to
  `dir in priority PRIORITY ptype main`, as in the reference output.
  This hides nothing: libreswan only installs main policies, and
  without `CONFIG_XFRM_SUB_POLICY` the kernel has no other type.  On a
  kernel that prints `ptype`, the rule doesn't apply.

- without `CONFIG_XFRM_STATISTICS`, `/proc/net/xfrm_stat` doesn't
  exist.  nsrun then detects the IPsec stack using
  `/proc/sys/net/core/xfrm_acq_expires` (only needs `CONFIG_XFRM`)
  instead of aborting with `no Linux IPsec stack found`.


1. Install dependencies
-----------------------

    sudo apt-get update
    sudo apt-get install -y --no-install-recommends \
        build-essential pkg-config bison flex \
        libnss3-dev libnss3-tools libevent-dev libunbound-dev \
        libpam0g-dev libcap-ng-dev libldns-dev xmlto \
        libcurl4-openssl-dev libseccomp-dev \
        libaudit-dev systemd-dev \
        git patch python3-pexpect curl tar diffutils \
        gawk diffstat iptables iproute2 iputils-ping kmod openssl \
        util-linux \
        libssl-dev libgmp-dev libcap-dev

Beyond the basic build and test lists:

- `--no-install-recommends`: otherwise `xmlto` pulls in hundreds of
  extra packages

- `systemd-dev`: provides `systemd.pc`; without it `make install`
  fails with `install: missing destination file operand after
  ...ipsec.service`

- `libaudit-dev`: see step 4

- `gawk`, `diffstat`: used by the output sanitizers; without `gawk`
  the sanitized output is silently empty and tests such as
  `ikev2-04-basic-x509-ckaid` fail

- `iptables`, `iproute2`, `iputils-ping`, `kmod`, `openssl`,
  `util-linux`: used by nsrun and the test scripts

- `libssl-dev`, `libgmp-dev`, `libcap-dev`: to build strongSwan, see
  step 3

Do not install the distribution's `strongswan` package, see step 3.


2. Prepare the host
-------------------

    sudo ./testing/ns/prepare-host.sh

This loads the kernel modules used by the tests.  It is needed once
after each boot.


3. Build and install strongSwan
-------------------------------

The `interop-*-strongswan-*` tests expect Fedora's strongSwan 6.0.7
(as used by the KVM tests): the `strongswan` command (Debian/Ubuntu
call it `ipsec`), `/usr/libexec/strongswan/charon`, configuration in
`/etc/strongswan/`, the version `U6.0.7` (checked by
`testing/guestbin/swan-prep`) and the `bypass-lan` and `stroke`
plugins.  Ubuntu's package (6.0.4, Debian layout) doesn't work, so
build it from source using Fedora's configure options:

    ./testing/ns/install-strongswan.sh

This downloads, verifies, builds (about 30 seconds) and installs
strongSwan.  `strongswan version` should print `Linux strongSwan
U6.0.7/...`.


4. Build and install libreswan
------------------------------

    make -j$(nproc) USE_LINUX_AUDIT=true
    sudo make USE_LINUX_AUDIT=true install

`USE_LINUX_AUDIT=true` matches the Fedora build used to generate the
reference output.  On Debian/Ubuntu it defaults to false and tests
such as `ikev2-03-basic-rawrsa` fail because pluto logs
`audit-log=no` instead of `audit-log=yes`.

Changing a make variable doesn't trigger a rebuild; if the tree was
already built without it, run `make clean` first.


5. Generate the test certificates
---------------------------------

    make -C testing/x509

This creates `testing/x509/pki/` and `testing/x509/selfsigned/` (about
a minute).  The certificates are dated relative to when they are
generated (valid from 11 months ago for 24 months; the up-to-date CRL
for 360 days), so regenerate them now and then.


6. Run the tests
----------------

    ./testing/utils/namespace-runner.py ikev2-0* interop-ikev2-strongswan-0*

Test names are directories in `testing/pluto/`.  Globs that don't
match in the current directory are expanded in `testing/pluto/`; a
glob or name that matches no test is an error.

Useful options:

- `-j N`: number of tests to run in parallel (default 5); most of a
  test's time is spent waiting, so twice the number of CPUs works

- `--diff`: print the output differences of failed tests at the end

- `-v`: print nsrun's output (interleaved)

The runner prints a summary and exits non-zero when a test failed.
The results of each test are in `testing/pluto/<test>/OUTPUT/`:

- `RESULT`: JSON, includes `"result": "passed"` or `"failed"`
- `<host>.console.diff`: differences against the reference
  `<host>.console.txt`
- `<host>.console.verbose.txt`: raw console output
- `<host>.pluto.log`, `<host>.charon.log`, `debug.log`

The runner hides why a test could not be started; to see that, run a
single test with nsrun:

    ./testing/utils/nsrun --ns --shutdown --exitcode --testname ikev2-05-basic-psk

`OUTPUT/` and `NS/` are ignored by git; some files in them are owned
by root, remove them with:

    sudo rm -rf testing/pluto/*/OUTPUT testing/pluto/*/NS


Troubleshooting
---------------

`ABORT no Linux IPsec stack found`
:   The kernel lacks XFRM (`CONFIG_XFRM`, `CONFIG_XFRM_USER`).

`received netlink error: Requested AUTH/CRYPT algorithm not found`, `Requested type not found`, Child SA `NO_PROPOSAL_CHOSEN`
:   The kernel lacks an algorithm or protocol (for instance
    `CONFIG_INET_AH`, `CONFIG_INET_IPCOMP`, `CONFIG_CRYPTO_CCM`,
    `CONFIG_CRYPTO_DES`, `CONFIG_CRYPTO_XCBC`); see
    `OUTPUT/*.charon.log`.  Load the module or use a kernel that has
    it.  On a kernel without AH, IPCOMP, CCM, DES and XCBC,
    `interop-ikev2-strongswan-01-ah-algo-responder`, `-01-esp-algo-responder`,
    `-05-psk-aes`, `-06-aes192`, `-07-strongswan` and
    `-09-psk-aes-ccm` fail.

`strongswan U6.0.7 must be installed` in the console output
:   The wrong strongSwan is installed, see step 3.


GitHub Actions
--------------

`.github/workflows/namespace-tests.yml` runs the steps above on
`ubuntu-26.04` for every push and pull request, using `-j` twice the
number of CPUs.  It can also be started manually (`workflow_dispatch`)
with a different list of tests.  The summary of the run is shown on
the job's page; when tests fail, their `OUTPUT/` directories are
uploaded as the `nsrun-output` artifact.

To save time it caches:

- the strongSwan install (built with `DESTDIR` set into a staging
  directory, keyed on `install-strongswan.sh`)

- the libreswan object files, using `ccache` (a new entry per commit,
  restoring the most recent one)

- the test certificates (keyed on `testing/x509/` and the make
  configuration, and regenerated weekly)

The caches are saved as soon as they are built, so they are kept even
when tests fail.  A run with all caches hit spends its time on
installing packages and running the tests.
