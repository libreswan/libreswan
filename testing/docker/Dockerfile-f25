FROM fedora:23
MAINTAINER "Antony Antony" <antony@phenome.org>
ENV container docker
RUN dnf -y update;
RUN dnf -y install systemd; \
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
RUN dnf install -y ElectricFence audit-libs-devel bind-utils bison \
 conntrack-tools curl-devel dnf-plugins-core fipscheck-devel flex gcc git \
 hping3 ike-scan iproute iptables ipsec-tools ldns-devel libcap-ng-devel \
 libevent-devel libfaketime libseccomp libseccomp-devel libselinux-devel \
 lsof make mtr nc net-tools nmap nsd nspr-devel nss-devel nss-tools ocspd \
 openldap-devel openssh-server openssh-clients pam-devel pam-devel pexpect \
 pexpect psmisc pyOpenSSL python3-cryptography \
 python3-pexpect python3-setproctitle racoon2 \
 redhat-rpm-config rpm-build screen strace strongswan systemd-devel tcpdump \
 telnet traceroute trousers unbound unbound-devel unbound-libs valgrind \
 vim-enhanced wget xl2tpd xmlto;
RUN dnf -y install 'dnf-command(debuginfo-install)'
RUN dnf -y  debuginfo-install ElectricFence audit-libs cyrus-sasl glibc keyutils \
 krb5-libs ldns ldns-devel libcap-ng libcom_err libcurl libevent libgcc libidn \
 libselinux libssh2 nspr nss nss-softokn nss-softokn-freebl nss-util openldap \
 openssl-libs pam pcre python-libs sqlite unbound-libs xz-libs zlib nspr \
 nss libevent-devel;
RUN mkdir -p /home/build/libreswan
VOLUME ["/home/build/libreswan:/home/build/libreswan"]
RUN ln -s /home/build/libreswan/testing /testing
RUN echo " * soft core unlimited" >> /etc/security/limits.conf
RUN echo " DAEMON_COREFILE_LIMIT='unlimited'" >> /etc/sysconfig/pluto
#
#setup ssh
RUN mkdir /root/.ssh
RUN mkdir /var/run/sshd
# create ssh host keys
RUN ssh-keygen -b 1024 -t rsa -f /etc/ssh/ssh_host_key
RUN ssh-keygen -b 1024 -t rsa -f /etc/ssh/ssh_host_rsa_key
RUN ssh-keygen -b 1024 -t dsa -f /etc/ssh/ssh_host_dsa_key
# move public key to enable ssh keys login
# copy the file /root/.ssh/authorized_keys to cwd
ADD authorized_keys /root/.ssh/authorized_keys
RUN chmod 400 /root/.ssh/authorized_keys
RUN chown -R root:root /root/.ssh
RUN  systemctl enable sshd.service
# tell ssh to not use ugly PAM
RUN sed -i 's/UsePAM\syes/UsePAM no/' /etc/ssh/sshd_config
RUN echo "UseDNS no" >> /etc/ssh/sshd_config
# make the terminal prettier
RUN echo 'export GIT_PS1_SHOWDIRTYSTATE=true' >> /root/.bash_profile
RUN echo 'export PS1="[\u@i\h] \w # "' >> /root/.bash_profile
RUN echo 'export EDITOR=vim' >> /root/.bash_profile
RUN printf '#!/bin/bash\n/home/build/libreswan/testing/guestbin/swan-transmogrify\n'  >> /etc/rc.d/rc.local
RUN chmod a+x /etc/rc.d/rc.local;
RUN systemctl enable rc-local.service
RUN printf 'export TERM=xterm\nexport EDITOR=vim\n' > /etc/profile.d/docker_exec_hack.sh
RUN printf "alias rebuild='D=`pwd`; cd /home/build/libreswan; ipsec stop; make install-base; cd $D'\n" >> /root/.bash_profile
RUN printf "alias gdbp='gdp -p `pidof pluto`'\n" >>  /root/.bash_profile
RUN dnf -y update; dnf clean all
