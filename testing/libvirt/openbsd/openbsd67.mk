KVM_OPENBSD_ISO_URL = https://cdn.openbsd.org/pub/OpenBSD/6.7/amd64/install67.iso
KVM_OPENBSD_BASE_HOST = openbsd-base
KVM_OPENBSD_BASE_DOMAIN = $(addprefix $(KVM_FIRST_PREFIX), $(KVM_OPENBSD_BASE_HOST))

# We install OpenBSD 6.7 but use os-varient as openbsd6.5 as virt
# install dosen't support 6.7 yet
VIRT_OPENBSD_VARIANT = openbsd6.5
