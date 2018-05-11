FROM docker.io/centos
MAINTAINER "Antony Antony" <antony@phenome.org>
ENV container docker
RUN yum -y update;
RUN yum -y install systemd; \
(cd /lib/systemd/system/sysinit.target.wants/; for i in *; do [ $i == systemd-tmpfiles-setup.service ] || rm -f $i; done); \
rm -f /lib/systemd/system/multi-user.target.wants/*;\
rm -f /etc/systemd/system/*.wants/*;\
rm -f /lib/systemd/system/local-fs.target.wants/*; \
rm -f /lib/systemd/system/sockets.target.wants/*udev*; \
rm -f /lib/systemd/system/sockets.target.wants/*initctl*; \
rm -f /lib/systemd/system/basic.target.wants/*;\
rm -f /lib/systemd/system/anaconda.target.wants/*;
#put these first that way if install break you start it up.
VOLUME [ "/sys/fs/cgroup" ]
CMD ["/usr/sbin/init"]
RUN yum install -y ElectricFence audit-libs-devel bind-utils bison \
 conntrack-tools curl-devel fipscheck-devel flex gcc git \
 hping3 iproute iptables ipsec-tools ldns-devel libcap-ng-devel \
 libevent-devel libfaketime libseccomp libseccomp-devel libselinux-devel \
 lsof make mtr nc net-tools nmap nsd ocspd \
 openldap-devel openssh-server openssh-clients pexpect \
 pexpect psmisc pyOpenSSL python3-cryptography \
 python3-pexpect python3-setproctitle racoon2 \
 redhat-rpm-config rpm-build screen strace strongswan tcpdump \
 telnet traceroute trousers unbound unbound-devel unbound-libs valgrind \
 vim-enhanced wget xl2tpd xmlto;
# RUN yum-builddep -y libreswan
RUN mkdir -p /home/build/libreswan
RUN wget -O libreswan.spec https://raw.githubusercontent.com/libreswan/libreswan/master/packaging/rhel/7/libreswan.spec
RUN yum-builddep -y ./libreswan.spec
VOLUME ["/home/build/libreswan:/home/build/libreswan"]
RUN echo " DAEMON_COREFILE_LIMIT='unlimited'" >> /etc/sysconfig/pluto
#
RUN yum -y update; yum clean all
