This directory is used to build a local version of NSS.

- for a local native build:

    $ make -C external/nss

  then add:

    include $(top_srcdir)/external/nss/Makefile.nss

  to Makefile.inc.local

- for a kvm build:

    $ ./kvm sh linux

    linux#  dnf install gyp ninja c++ ...?

    linux#  make -C /source/external/nss

  -> there are likely missing packages, above is a guess
  -> it may take several attempts; mecurial download can fail

  and then add:

    ifeq ($(shell hostname),linux)
    include $(top_srcdir)/external/nss/Makefile.nss
    endif

  to Makefile.inc.local (I'm assuming your machine isn't called
  linux).
