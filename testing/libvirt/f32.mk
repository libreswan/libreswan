#KVM_LINUX_ISO_URL = https://muug.ca/mirror/fedora/linux/releases/32/Server/x86_64/iso/Fedora-Server-dvd-x86_64-32-1.6.iso
KVM_LINUX_ISO_URL = https://ftp.nluug.nl/pub/os/Linux/distr/fedora/linux/releases/32/Server/x86_64/iso/Fedora-Server-dvd-x86_64-32-1.6.iso
KVM_KICKSTART_FILE = testing/libvirt/$(KVM_GUEST_OS).ks
# LIE! bit older version to be more complaint with older hosts
KVM_LINUX_VIRT_INSTALL_VARIANT ?= fedora30
KVM_PACKAGE_INSTALL = dnf install -y
KVM_PACKAGE_UPGRADE = dnf upgrade -y
KVM_DEBUGINFO_INSTALL = dnf install --enablerepo=*-debuginfo -y
KVM_INSTALL_RPM_LIST = 'rpm -aq > /var/tmp/rpm-qa-fedora-updates.log'

#
# NSS+NSPR
#
# If necessary, force the NSS version and/or the RPM directory.
#
# There's history here: version 3.40 dumped core while loading the NSS
# DB; version 3.59 and 3.60 both dumped core while computing
# appendix-b keymat.
#
# KVM_NSS_RPMDIR = /pool/nss/x866_64/
# KVM_NSS_VERSION = -3.36.0-1.0.fc28.x86_64

KVM_NSS_RPMDIR ?=
KVM_NSS_VERSION ?=

KVM_NSS_DEBUGINFO_NAMES ?= \
	nss-debugsource \
	nss-debuginfo \
	nss-softokn-debuginfo \
	nss-softokn-freebl-debuginfo \
	nss-util-debuginfo \
	$(NULL)
KVM_NSS_DEBUGINFO ?= \
	$(addprefix $(KVM_NSS_RPMDIR), $(addsuffix $(KVM_NSS_VERSION), $(KVM_NSS_DEBUGINFO_NAMES)))

KVM_NSS_PACKAGE_NAMES ?= \
	nss \
	nss-devel \
	nss-softokn \
	nss-softokn-devel \
	nss-softokn-freebl \
	nss-softokn-freebl-devel \
	nss-sysinit \
	nss-tools \
	nss-util \
	nss-util-devel \
	$(NULL)
KVM_NSS_PACKAGES ?= \
	$(addprefix $(KVM_NSS_RPMDIR), $(addsuffix $(KVM_NSS_VERSION), $(KVM_NSS_PACKAGE_NAMES)))

KVM_NSPR_RPMDIR ?=
KVM_NSPR_VERSION ?=

KVM_NSPR_DEBUGINFO_NAMES ?= nspr-debuginfo
KVM_NSPR_DEBUGINFO ?= $(addprefix $(KVM_NSPR_RPMDIR), $(addsuffix $(KVM_NSPR_VERSION), $(KVM_NSPR_DEBUGINFO_NAMES)))
KVM_NSPR_PACKAGE_NAMES ?= nspr nspr-devel
KVM_NSPR_PACKAGES ?= \
	$(addprefix $(KVM_NSPR_RPMDIR), $(addsuffix $(KVM_NSPR_VERSION), $(KVM_NSPR_PACKAGE_NAMES)))

.PHONY: nss-rpms
nss-rpms:
	@for rpm in $(KVM_NSS_DEBUGINFO) ; do echo $$rpm ; done
	@for rpm in $(KVM_NSS_PACKAGES) ; do echo $$rpm ; done
.PHONY: nspr-rpms
nspr-rpms:
	@for rpm in $(KVM_NSPR_DEBUGINFO) ; do echo $$rpm ; done
	@for rpm in $(KVM_NSPR_PACKAGES) ; do echo $$rpm ; done

#
# KERNEL:
#
# The kernel packages can only be installed.
#
# To stop a new version of the kernel being installed set this to
# empty.  XL2TPD sucks in the latest kernel so is included in the
# list.
#
# KVM_KERNEL_RPMDIR ?= /source/kernel
# KVM_KERNEL_ARCH ? = x86_64
# KVM_KERNEL_VERSION ?= 5.8.0-0.rc1.1.fc33.$(KERNEL_ARCH).rpm

KVM_KERNEL_RPMDIR ?=
KVM_KERNEL_VERSION ?=

KVM_KERNEL_PACKAGE_NAMES ?= \
	kernel \
	kernel-core \
	kernel-devel \
	kernel-headers \
	kernel-modules \
	kernel-modules-extra \
	$(NULL)

KVM_KERNEL_PACKAGES ?= \
	$(addprefix $(KVM_KERNEL_RPMDIR), $(addsuffix $(KVM_KERNEL_VERSION), $(KVM_KERNEL_PACKAGE_NAMES))) \
	xl2tpd

.PHONY: kernel-rpms
kernel-prms:
	@for rpm in $(KVM_KERNEL_PACKAGES) ; do echo $$rpm ; done


#    kernel-debuginfo-$(RPM_KERNEL_VERSION)
#    kernel-debuginfo-common-$(KERNEL_ARCH)-$(RPM_KERNEL_VERSION)


#
# STRONGSWAN
#
# Strongswan is brokenly dependent on libgcrypt.
#
# Because it calls gcry_check_version(GCRYPT_VERSION) (where
# GCRYPT_VERSION is defined in gcrypt.h) it must be installed with a
# version of libgcrypt >= the version it was built against.  Good luck
# trying to describe that using RPM's .spec file (%buildrequires
# libgcrypt-devel isn't sufficient).

# KVM_STRONGSWAN_PACKAGES = \
#   https://nohats.ca/ftp/strongswan/strongswan-5.8.4-2.fc30.x86_64.rpm \
#   libgcrypt

KVM_STRONGSWAN_PACKAGES = strongswan libgcrypt


KVM_INSTALL_PACKAGES += \
    $(KVM_KERNEL_PACKAGES) \
    $(KVM_UPGRADE_PACKAGES)

KVM_UPGRADE_PACKAGES += \
    ElectricFence \
    audit-libs-devel \
    bind-utils \
    bind-dnssec-utils \
    bison \
    conntrack-tools \
    crypto-policies-scripts \
    curl-devel \
    elfutils-libelf-devel \
    flex \
    fping \
    gcc \
    gdb \
    git \
    glibc-devel \
    gnutls-utils \
    hping3 \
    htop \
    iftop \
    ike-scan \
    iproute \
    iptables \
    iputils \
    ldns \
    ldns-devel \
    libcap-ng-devel \
    libfaketime \
    libevent-devel \
    libseccomp-devel \
    libselinux-devel \
    linux-firmware \
    linux-system-roles \
    lsof \
    make \
    mtr \
    nc \
    net-tools \
    nmap \
    nsd \
    $(KVM_NSPR_PACKAGES) \
    $(KVM_NSS_PACKAGES) \
    ocspd \
    openldap-devel \
    p11-kit-trust \
    pam-devel \
    patch \
    perf \
    policycoreutils-python-utils \
    psmisc \
    python3-pyOpenSSL \
    python3-pexpect \
    python3-netaddr \
    rpm-build \
    rsync \
    selinux-policy-devel \
    screen \
    socat \
    softhsm \
    strace \
    systemd-devel \
    tar \
    tcpdump \
    telnet \
    unbound \
    unbound-devel \
    unbound-libs \
    valgrind \
    vim-enhanced \
    wget \
    wireshark-cli \
    xmlto \
    $(KVM_STRONGSWAN_PACKAGES) \


KVM_DEBUGINFO += \
	ElectricFence-debuginfo \
	audit-libs-debuginfo \
	conntrack-tools-debuginfo \
	cyrus-sasl-lib-debuginfo \
	glibc-debuginfo \
	keyutils-libs-debuginfo \
	krb5-libs-debuginfo \
	ldns-debuginfo \
	libbrotli-debuginfo \
	libcap-ng-debuginfo \
	libcom_err-debuginfo \
	libcurl-debuginfo \
	libevent-debuginfo \
	libffi-debuginfo \
	libgcc-debuginfo \
	libgcrypt-debuginfo \
	libgpg-error-debuginfo \
	libidn-debuginfo \
	libidn2-debuginfo \
	libpsl-debuginfo \
	libseccomp-debuginfo \
	libselinux-debuginfo \
	libssh-debuginfo \
	libssh2-debuginfo \
	libtasn1-debuginfo \
	libunistring-debuginfo \
	libxcrypt-debuginfo \
	lz4-libs-debuginfo \
	$(KVM_NSPR_DEBUGINFO) \
	$(KVM_NSS_DEBUGINFO) \
	ocspd-debuginfo \
	openldap-debuginfo \
	openssl-libs-debuginfo \
	p11-kit-debuginfo \
	p11-kit-trust-debuginfo \
	pam-debuginfo \
	pcre-debuginfo \
	pcre2-debuginfo \
	sqlite-libs-debuginfo \
	systemd-libs-debuginfo \
	unbound-libs-debuginfo \
	xz-libs-debuginfo \
	zlib-debuginfo \
	$(NULL)
