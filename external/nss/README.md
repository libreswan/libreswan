This directory is used to build a local version of NSS.

## LOCAL NATIVE BUILD

```
$ sudo dnf install gyp ninja c++ mercurial
$ make -C external/nss
```

then add:

```
ifneq ($(shell uname -no),linux GNU/Linux)
include $(top_srcdir)/external/nss/Makefile.nss
endif
```

to `Makefile.inc.local` (the `ifneq` is so that the include doesn't
happen on VMs).

And finally do a clean build:

```
gmake clean
gmake -j
```

To confirm it is being linked, look carefully for
`-I../../external/nss/dist/public/nss` in the output.

## KVM build

First check that the build depencencies are installed (linux does this
by default during upgrade):

```
$ ./kvm sh linux
linux#  dnf install gyp ninja c++ mercurial ...?
```

Build from within the KVM

```
$ ./kvm sh linux
linux# make -C /source/external/nss
```

- there are likely missing packages, above is a guess
- it may take several attempts; mecurial download can fail

Add dependencies:

```
ifeq ($(shell hostname),linux)
include $(top_srcdir)/external/nss/Makefile.nss
endif
```

To Makefile.inc.local (I'm assuming your machine isn't called linux).

## Debugging

When debugging the local NSS libraries need to be added to LD's
library path vis:

```
LD_LIBRARY_PATH=$PWD/external/nss/dest/Debug/lib \
gdb --args /usr/local/libexec/ipsec/pluto \
    --config /etc/ipsec.conf \
    --stderrlog \
    --nhelpers=0 \
    --nofork
```

## TODO

- support separate build tree so that multiple NSS builds can co-exist

## To update the REPO

```
make -C external/nss update
```
