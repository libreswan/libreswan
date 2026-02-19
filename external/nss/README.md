This directory is used to build a local version of NSS.

## LOCAL NATIVE BUILD

```
$ make -C external/nss
```

then add:

```
include $(top_srcdir)/external/nss/Makefile.nss
```

to Makefile.inc.local

## KVM build

First check that the build depencencies are installed (linux does this
by default during upgrade):

```
$ ./kvm sh linux
linux#  dnf install gyp ninja c++ ...?
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

## TODO

- support separate build tree so that multiple NSS builds can co-exist

## To update the REPO

```
make -C external/nss update
```
