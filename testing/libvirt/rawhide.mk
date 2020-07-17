DATE:=$(shell date '%y.%m.%d')
# take the netinst it is going to change every day
ISO_FILE_NAME = Fedora-Server-netinst-x86_64-Rawhide-$(DATE).n.0.iso

KVM_ISO_URL  = https://muug.ca/mirror/fedora/linux/development/rawhide/Server/x86_64/iso/$(ISO_FILE_NAME)
KVM_ISO_URL= https://ftp.nluug.nl/pub/os/Linux/distr/fedora/linux/development/rawhide/Server/x86_64/iso/$(ISO_FILE_NAME)


KVM_KICKSTART_FILE = testing/libvirt/$(KVM_GUEST_OS).ks
# LIE!
KVM_OS_VARIANT ?= fedora28
KVM_PACKAGE_INSTALL = dnf install -y
KVM_PACKAGE_UPGRADE = dnf upgrade -y
KVM_DEBUGINFO_INSTALL = dnf debuginfo-install -y
KVM_INSTALL_RPM_LIST = 'rpm -aq > /var/tmp/rpm-qa-fedora-updates.log'

# Force the NSS version - version 3.40 caused pluto to dump core while
# loading the NSS DB.  Versions 3.36 and 3.41 (current at time of
# writing) seem to work.

# NSS_VERSION = -3.36.0-1.0.fc28.x86_64
NSS_VERSION =

# The kernel packages can only be installed.  To stop a new version
# being installed set this to empty.

KVM_KERNEL_VERSION ?=
KVM_KERNEL_PACKAGES ?= \
    kernel$(KVM_KERNEL_VERSION) \
    kernel-core$(KVM_KERNEL_VERSION) \
    kernel-modules$(KVM_KERNEL_VERSION) \
    kernel-devel$(KVM_KERNEL_VERSION) \
    kernel-headers$(KVM_KERNEL_VERSION) \
    kernel-modules-extra$(KVM_KERNEL_VERSION)

KVM_INSTALL_PACKAGES ?= \
    $(KVM_KERNEL_PACKAGES) \
    $(KVM_UPGRADE_PACKAGES)

KVM_UPGRADE_PACKAGES ?= \
    ElectricFence \
    audit-libs-devel \
    bind-utils	\
    bison \
    conntrack-tools \
    curl-devel \
    elfutils-libelf-devel \
    fipscheck-devel \
    flex \
    fping \
    gcc \
    gdb \
    git \
    glibc-devel \
    hping3 \
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
    lsof \
    mtr \
    nc \
    net-tools \
    nsd \
    nspr \
    nspr-devel \
    nss$(NSS_VERSION) \
    nss-devel$(NSS_VERSION) \
    nss-tools$(NSS_VERSION) \
    nss-softokn$(NSS_VERSION) \
    nss-softokn-freebl$(NSS_VERSION) \
    ocspd \
    openldap-devel \
    pam-devel \
    patch \
    perf \
    policycoreutils-python-utils \
    psmisc \
    python3-pyOpenSSL \
    python3-pexpect \
    rpm-build \
    screen \
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
    xl2tpd \
    xmlto \
    strongswan \
    libfaketime \


KVM_DEBUGINFO = \
    ElectricFence \
    audit-libs \
    conntrack-tools \
    cyrus-sasl \
    glibc \
    keyutils \
    krb5-libs \
    ldns \
    libcap-ng \
    libcom_err \
    libcurl \
    libevent \
    libevent-devel \
    libgcc \
    libidn \
    libseccomp \
    libselinux \
    libssh2 \
    nspr \
    nss$(NSS_VERSION) \
    nss-softokn$(NSS_VERSION) \
    nss-softokn-freebl$(NSS_VERSION) \
    nss-util$(NSS_VERSION) \
    ocspd \
    openldap \
    openssl-libs \
    pam \
    pcre \
    python3-libs \
    sqlite \
    unbound-libs \
    xz-libs \
    zlib \
