This directory contains a patch to the OpenBSD 7.8 kernel so that it
announces all the supported algorithms.  It's in mainline upstream.

Without this libreswan doesn't know that OpenBSD supports some newer
algorithms.

To rebuild see "Building a Custom Kernel" in:

   https://www.openbsd.org/faq/faq5.html#Custom

something like:

  ./kvm sh openbsd
  # cd /usr/src/sys/arch/$(uname -m)/conf
  # cp GENERIC LIBRESWAN
  # config LIBRESWAN
  # cd ../compile/LIBRESWAN
  # make
  ...
  VM bugs mean that on fast AMD h/w you might need to run make several
  times.  On slow intel h/w seems more reliable.
  ...
  # cp obj/bsd     /pool/kernel.openbsd
  # cp obj/bsd.gdb /pool/kernel.openbsd.gdb

If it is a custom custom kernel then /pool/${KVM_PREFIX}openbsd-kernel
will only upgrade the one build.  See upgrade/openbsd.sh.

(yea, the VMs don't have user accounts)
