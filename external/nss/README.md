This directory is used to build a local version of NSS.

- for a local native build:

    $ make -C external/nss

  then add:

    include $(top_srcdir)/external/nss/Makefile.kvm.linux

  to Makefile.inc.local

- for a kvm build:

    $ ./kvm sh linux
    linux#  make -C /source/external/nss

  IT MIGHT TAKE SEVERAL ATTEMPTS AS THE MECURIAL DOWNLOAD CAN FAIL!

  and then add:

    ifeq ($(shell hostname),linux)
    include $(top_srcdir)/external/nss/Makefile.kvm.linux
    endif

  to Makefile.inc.local (I'm assuming your machine isn't called
  linux).
