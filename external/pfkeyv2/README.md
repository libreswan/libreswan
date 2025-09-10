This directory contains versions of <net/pfkeyv2.h> taken from the
various BSD derived distributions that provide PFKEY V2.  They are
included for reference:

- BSD builds include the system header <net/pfkeyv2.h>

- Linux builds shouldn't include pfkeyv2.h at all

The files are:

- a copy of <net/pfkeyv2.h> embedded in RFC 2367 (named rfc2367.h)

  this file, from NRL, is in the public domain

- copy of <net/pfkeyv2.h> taken from mainline FreeBSD and NetBSD,
  (named freebsd.h, netbsd.h)

  the files are BSD-3-Clause (C) WIDE Project

- copy of <net/pfkeyv2.h> taken from mainline OpenBSD
  (named openbsd.h)

  the file is BSD-4-Clause (C) NRL

  This (C) is strange: NRL releaed the same text as public domain;
  Berkley revoked the 4th clause; and constant's can't be (C).

(with some Make foo, it is possible to build the BSD kernel code on a
linux host using one of these files; just don't try to run it)
