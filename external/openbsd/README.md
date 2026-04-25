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
  on fast amd h/w you might need to run make several times
  ...
  # cp obj/bsd     /pool/${KVM_PREFIX}${KVM_PLATFORM}-kernel
  # cp obj/bsd.gdb /pool/${KVM_PREFIX}${KVM_PLATFORM}-kernel.gdb

(yea, the VMs don't have user accounts)
