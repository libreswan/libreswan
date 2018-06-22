# The domain download.fedoraproject.org can redirect to a mirror, such
# as fedora.bhs.mirrors.ovh.net as of 2017-08-09, that doesn't carry
# F22.
KVM_ISO_URL = http://archives.fedoraproject.org/pub/archive/fedora/linux/releases/22/Server/x86_64/iso/Fedora-Server-DVD-x86_64-22.iso
KVM_OS_VARIANT = fedora22

KVM_KICKSTART_FILE = testing/libvirt/fedora22.ks

KVM_PACKAGE_INSTALL = dnf install -y
KVM_DEBUGINFO_INSTALL = dnf  debuginfo-install -y
KVM_INSTALL_RPM_LIST = 'rpm -aq > /var/tmp/rpm-qa-fedora-updates.log'

KVM_PACKAGES = \
    ElectricFence \
    audit-libs-devel \
    bison \
    bind-utils \
    conntrack-tools \
    curl-devel \
    fipscheck-devel \
    flex \
    gcc \
    gdb \
    git \
    glibc-devel \
    hping3 \
    hping3 \
    ike-scan \
    ipsec-tools \
    ldns \
    ldns-devel \
    libcap-ng-devel \
    libevent-devel \
    libseccomp-devel \
    libselinux-devel \
    lsof \
    mtr \
    nc \
    nc6 \
    nsd \
    net-tools \
    nss-devel \
    nss-tools \
    nspr-devel \
    ocspd \
    openldap-devel \
    pam-devel \
    patch \
    pexpect \
    psmisc \
    python3-pexpect \
    python3-setproctitle \
    pyOpenSSL \
    rpm-build \
    screen \
    racoon2 \
    strace \
    systemd-devel \
    tar \
    tcpdump \
    telnet  \
    unbound \
    unbound-devel \
    unbound-libs \
    valgrind \
    vim-enhanced \
    xl2tpd \
    xmlto \
    https://download.nohats.ca/strongswan/strongswan-5.6.0-1.fc22.x86_64.rpm \
    https://download.nohats.ca/libfaketime/libfaketime-0.9.6-4.fc22.x86_64.rpm

KVM_DEBUGINFO = \
    ElectricFence \
    audit-libs \
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
    wget \
    xz-libs \
    zlib
