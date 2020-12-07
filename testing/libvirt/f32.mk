KVM_ISO_URL = https://muug.ca/mirror/fedora/linux/releases/32/Server/x86_64/iso/Fedora-Server-dvd-x86_64-32-1.6.iso
KVM_ISO_URL = https://ftp.nluug.nl/pub/os/Linux/distr/fedora/linux/releases/32/Server/x86_64/iso/Fedora-Server-dvd-x86_64-32-1.6.iso
KVM_KICKSTART_FILE = testing/libvirt/$(KVM_GUEST_OS).ks
# LIE! bit older version to be more complaint with older hosts
KVM_OS_VARIANT ?= fedora30
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
# being installed set this to empty.  XL2TPD sucks in the latest
# kernel so is included in the list.

# KVM_KERNEL_ARCH ? = x86_64
# KVM_KERNEL_VERSION ?= 5.8.0-0.rc1.1.fc33.$(KERNEL_ARCH).rpm

KVM_KERNEL_VERSION ?=
KVM_KERNEL_PACKAGES ?= \
    kernel$(KVM_KERNEL_VERSION) \
    kernel-core$(KVM_KERNEL_VERSION) \
    kernel-modules$(KVM_KERNEL_VERSION) \
    kernel-devel$(KVM_KERNEL_VERSION) \
    kernel-headers$(KVM_KERNEL_VERSION) \
    kernel-modules-extra$(KVM_KERNEL_VERSION) \
    xl2tpd

#    kernel-debuginfo-$(RPM_KERNEL_VERSION)
#    kernel-debuginfo-common-$(KERNEL_ARCH)-$(RPM_KERNEL_VERSION)


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

KVM_INSTALL_PACKAGES ?= \
    $(KVM_KERNEL_PACKAGES) \
    $(KVM_UPGRADE_PACKAGES)

KVM_UPGRADE_PACKAGES ?= \
    ElectricFence \
    audit-libs-devel \
    bind-utils \
    bind-dnssec-utils \
    bison \
    conntrack-tools \
    crypto-policies-scripts \
    curl-devel \
    elfutils-libelf-devel \
    fipscheck-devel \
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
    lsof \
    make \
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
    p11-kit-trust \
    pam-devel \
    patch \
    perf \
    policycoreutils-python-utils \
    psmisc \
    python3-pyOpenSSL \
    python3-pexpect \
    rpm-build \
    rsync \
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
    wireshark-cli \
    xmlto \
    $(KVM_STRONGSWAN_PACKAGES) \


KVM_DEBUGINFO = \
    ElectricFence \
    audit-libs \
    conntrack-tools \
    cyrus-sasl-lib \
    glibc \
    keyutils-libs \
    krb5-libs \
    ldns \
    libbrotli \
    libcap-ng \
    libcom_err \
    libcurl \
    libevent \
    libevent-devel \
    libffi \
    libgcc \
    libgcrypt \
    libgpg-error \
    libidn \
    libidn2 \
    libnghttp2 \
    libpsl \
    libseccomp \
    libselinux \
    libssh \
    libssh2 \
    libtasn1 \
    libunistring \
    libxcrypt \
    lz4-libs \
    nspr \
    nss$(NSS_VERSION) \
    nss-softokn$(NSS_VERSION) \
    nss-softokn-freebl$(NSS_VERSION) \
    nss-util$(NSS_VERSION) \
    ocspd \
    openldap \
    openssl-libs \
    p11-kit \
    p11-kit-trust \
    pam \
    pcre \
    pcre2 \
    python3-libs \
    sqlite-libs \
    systemd-libs \
    unbound-libs \
    xz-libs \
    zlib \
