# FROM fedora:27
# MAINTAINER "Antony Antony" <antony@phenome.org>
# ENV container docker
RUN dnf -y update
RUN mkdir -p /home/build/
COPY . /home/build/libreswan
RUN dnf -y install systemd; \
(cd /lib/systemd/system/sysinit.target.wants/; for i in *; do [ $i == systemd-tmpfiles-setup.service ] || rm -f $i; done); \
rm -f /lib/systemd/system/multi-user.target.wants/*;\
rm -f /etc/systemd/system/*.wants/*;\
rm -f /lib/systemd/system/local-fs.target.wants/*; \
rm -f /lib/systemd/system/sockets.target.wants/*udev*; \
rm -f /lib/systemd/system/sockets.target.wants/*initctl*; \
rm -f /lib/systemd/system/basic.target.wants/*;\
rm -f /lib/systemd/system/anaconda.target.wants/*;
# these first. If install breaks docker image will start, can debug.
VOLUME [ "/sys/fs/cgroup" ]
CMD ["/sbin/init"]
RUN dnf install -y dnf-plugins-core git iproute openssh-server openssh-clients \
	pexpect vim-enhanced wget
RUN dnf install -y @development-tools
RUN dnf builddep -y libreswan
# F28 and later to support X509 Certificates, signed with SHA1
RUN ls -l /usr/bin/update-crypto-policies && /usr/bin/update-crypto-policies --set LEGACY || true
RUN cd /home/build/libreswan; make install-rpm-dep && cd /
# RUN systemctl enable network
# RUN rm -fr /etc/sysconfig/network-scripts/ifcfg-ens3
