FROM fedora:24

RUN dnf -y update && \
    dnf -y install epel-release && \
    dnf -y install nss-devel nspr-devel pkgconfig pam-devel libcap-ng-devel \
                   libselinux-devel libseccomp-devel curl-devel flex bison gcc \
                   make fipscheck-devel unbound-devel libevent-devel xmlto \
                   audit-libs-devel systemd-devel git clang && \
    dnf clean all

