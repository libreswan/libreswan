KVM_ISO_URL = https://muug.ca/mirror/fedora/linux/releases/28/Server/x86_64/iso/Fedora-Server-dvd-x86_64-28-1.1.iso
KVM_ISO_URL = https://ftp.nluug.nl/pub/os/Linux/distr/fedora/linux/releases/28/Server/x86_64/iso/Fedora-Server-dvd-x86_64-28-1.1.iso
KVM_KICKSTART_FILE = testing/libvirt/fedora28.ks
# LIE!
KVM_OS_VARIANT ?= fedora26
KVM_PACKAGE_INSTALL = dnf install -y
KVM_DEBUGINFO_INSTALL = dnf  debuginfo-install -y
KVM_INSTALL_RPM_LIST = 'rpm -aq > /var/tmp/rpm-qa-fedora-updates.log'

KVM_PACKAGES = \
    ElectricFence \
    audit-libs-devel \
    bind-utils	\
    bison \
    conntrack-tools \
    curl-devel \
    elfutils-libelf-devel \
    fipscheck-devel \
    flex \
    gcc \
    gdb \
    git \
    glibc-devel \
    hping3 \
    ike-scan \
    ipsec-tools \
    ldns \
    ldns-devel \
    libcap-ng-devel \
    libfaketime \
    libevent-devel \
    libseccomp-devel \
    libselinux-devel \
    lsof \
    mtr \
    nc \
    net-tools \
    nsd \
    nspr-devel \
    nss-devel \
    nss-tools \
    ocspd\
    openldap-devel \
    pam-devel \
    patch \
    pexpect \
    policycoreutils-python-utils \
    psmisc \
    python2-pyOpenSSL \
    python3-pexpect \
    python-setproctitle \
    racoon2 \
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
    nss \
    nss-softokn \
    nss-softokn-freebl \
    nss-util \
    ocspd \
    openldap \
    openssl-libs \
    pam \
    pcre \
    python-libs \
    sqlite \
    unbound-libs \
    xz-libs \
    zlib \
