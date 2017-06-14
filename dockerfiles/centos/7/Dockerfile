FROM centos:7

RUN yum -y update && \
    yum -y install epel-release && \
    yum -y install nss-devel nspr-devel pkgconfig pam-devel libcap-ng-devel \
                   libselinux-devel libseccomp-devel curl-devel flex bison gcc \
                   make fipscheck-devel unbound-devel libevent-devel xmlto \
                   audit-libs-devel systemd-devel git clang && \
    yum clean all

