KVM_ISO_URL_BSD = https://cloudflare.cdn.openbsd.org/pub/OpenBSD/6.7/amd64/install67.iso
KVM_ISO_URL_BSD = https://cdn.openbsd.org/pub/OpenBSD/6.7/amd64/install67.iso
KVM_BSD_RC = $(KVM_TESTINGDIR)/libvirt/rc.firsttime
KVM_BSD_CONF = $(KVM_TESTINGDIR)/libvirt/install.conf
KVM_BSD_ISO = install67.iso
KVM_BSD_BASE_NAME := openbsd-base
#We install OpenBSD 6.7 but use os-varient as openbsd6.6 as virt install dosen't support 6.7 yet
VIRT_BSD_VARIANT = openbsd6.6