# Minimal Kickstart file - updated for fedora 21
install
text
reboot
lang en_US.UTF-8
keyboard us
network --bootproto=dhcp --hostname swanbase
# static network does not work with recent dracut, use kernel args instead
#network --bootproto=static --ip=76.10.157.78 --netmask=255.255.255.240 --gateway=76.10.157.65 --hostname swanbase
rootpw swan
firewall --disable
selinux --enforcing
timezone --utc America/New_York
#firstboot --disable
bootloader --location=mbr --append="console=tty0 console=ttyS0,115200 rd_NO_PLYMOUTH"
zerombr
clearpart --all --initlabel
part / --asprimary --grow
part swap --size 1024
services --disabled=sm-client,sendmail,network,smartd,crond,atd

%packages --ignoremissing

# Full list of RPMs to install (see also %post)

# Since it is fast and local, try to install everything here using the
# install DVD image.  Anything missing will be fixed up later in
# %post.  The option --ignoremissing is specified so we don't have to
# juggle what is enabled / disabled here.

# Note: The problem is that the DVD doesn't contain "Everything" -
# that repo only becomes available during %post when it is enabled.
# To get around this, %post installing a few things that were missed.
# The easiest way to figure out if something ALSO needs to be listed
# in %post is to look in "Packaging/" on the DVD.  I just wish this
# could go in a separate file so post could do the fix up
# automatically.

# Note: %post also installs debug-rpms.  Downloading and installing
# them is what takes all the time and bandwith.

# Note: To avoid an accidental kernel upgrade (KLIPS doesn't build
# with some 4.x kernels), install everything kernel dependent here.
# If you find the kernel still being upgraded look at the log files in
# /var/tmp created during the %post state.

@core

ElectricFence
audit-libs-devel
bind-utils
bison
curl-devel
fipscheck-devel
flex
gcc
gdb
git
glibc-devel
hping3
ipsec-tools
kernel-core
kernel-devel
kernel-headers
kernel-modules
kernel-modules-extra
libcap-ng-devel
libevent-devel
libselinux-devel
lsof
make
mtr
nc
nc6
net-tools
nmap
nspr-devel
nss-devel
nss-tools
openldap-devel
pam-devel
pexpect
psmisc
pyOpenSSL
python3-pexpect
python3-setproctitle
racoon2
redhat-rpm-config
rpm-build
screen
strace
strongswan
systemd-devel
tcpdump
telnet
unbound
unbound-devel
unbound-libs
valgrind
vim-enhanced
wget
xl2tpd
xmlto
yum-utils

# for now, let's not try and mix openswan rpm and /usr/local install of openswan
# later on, we will add an option to switch between "stock" and /usr/local openswan
-openswan
-sendmail
-libreswan

# nm causes problems and steals our interfaces desipte NM_CONTROLLED="no"
-NetworkManager

%end

#%pre
#!/bin/bash
# Paul needs this due to bad ISP
#ip link set eth0 mtu 1400
#%end


%post
echo "nameserver 193.110.157.123" >> /etc/resolv.conf
/sbin/restorecon /etc/resolv.conf
# Paul needs this due to broken isp
#ifconfig eth0 mtu 1400
# Tuomo switched to this alternative work-around for pmtu issues
sysctl -w net.ipv4.tcp_mtu_probing=1

# Install anything missing from the CD, but found in the "Everything"
# repo here.

# There is also extra stuff, not in a repo, being installed at the
# very end of this file.

# Capture a before "yum install" log.  If something (such as a 4.x
# kernel) is inadvertently installed, check this and yum-install.log
# for what triggered it.

rpm -qa > /var/tmp/rpm-qa.log

# TODO: if rhel/centos, we should install epel-release too

yum install -y 2>&1 \
    ElectricFence \
    audit-libs-devel \
    curl-devel \
    fipscheck-devel \
    hping3 \
    ipsec-tools \
    libcap-ng-devel \
    libevent-devel \
    nc \
    nc6 \
    nspr-devel \
    nss-devel \
    pexpect \
    python3-pexpect \
    python3-setproctitle \
    racoon2 \
    strongswan \
    systemd-devel \
    unbound \
    unbound-devel \
    vim-enhanced \
    xmlto \
    | tee /var/tmp/yum-install.log

debuginfo-install -y \
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
    libselinux \
    libssh2 \
    nspr \
    nss \
    nss-softokn \
    nss-softokn-freebl \
    nss-util \
    openldap \
    openssl-libs \
    ocspd \
    pam \
    pcre \
    python-libs \
    sqlite \
    unbound-libs \
    xz-libs \
    zlib \
    | tee /var/tmp/yum-debug-info-install.log

mkdir /testing /source

cat << EOD >> /etc/issue

The root password is "swan"
EOD

# noauto for now, as we seem to need more system parts started before we can mount 9p
cat << EOD >> /etc/fstab
testing /testing 9p defaults,noauto,trans=virtio,version=9p2000.L,context=system_u:object_r:var_log_t:s0 0 0
swansource /source 9p defaults,noauto,trans=virtio,version=9p2000.L,context=system_u:object_r:usr_t:s0 0 0
tmpfs                   /dev/shm                tmpfs   defaults        0 0
tmpfs                   /tmp                    tmpfs   defaults        0 0
devpts                  /dev/pts                devpts  gid=5,mode=620  0 0
sysfs                   /sys                    sysfs   defaults        0 0
proc                    /proc                   proc    defaults        0 0
EOD

cat << EOD >> /etc/rc.d/rc.local
#!/bin/sh
mount /testing
mount /source
/testing/guestbin/swan-transmogrify
EOD
chmod 755 /etc/rc.d/rc.local

cat << EOD > /etc/profile.d/swanpath.sh
# add swan test binaries to path

case ":${PATH:-}:" in
    *:/testing/guestbin:*) ;;
    *) PATH="/testing/guestbin${PATH:+:$PATH}" ;;
esac
# too often various login/sudo/ssh methods don't have /usr/local/sbin
case ":${PATH:-}:" in
    *:/usr/local/sbin:*) ;;
    *) PATH="/usr/local/sbin${PATH:+:$PATH}" ;;
esac
EOD

cat << EOD > /etc/modules-load.d/9pnet_virtio.conf
# load 9p modules in time for auto mounts
9pnet_virtio
EOD
cat << EOD > /etc/modules-load.d/virtio-rng.conf
# load virtio RNG device to get entropy from the host
# Note it should also be loaded on the host
virtio-rng
EOD

cat << EOD >> /root/.bash_profile
export GIT_PS1_SHOWDIRTYSTATE=true
source /usr/share/git-core/contrib/completion/git-prompt.sh
source /usr/share/doc/git/contrib/completion/git-prompt.sh
#export PS1='\[\033[32m\]\u@\h\[\033[00m\]:\[\033[34m\]\w\[\033[31m\]$(declare -F __git_ps1 &>/dev/null && __git_ps1 " (%s)")\[\033[00m\]\\$ '
alias git-log-p='git log --pretty=format:"%h %ad%x09%an%x09%s" --date=short'
export EDITOR=vim
EOD

systemctl disable firewalld.service
systemctl enable network.service
systemctl enable iptables.service
systemctl enable ip6tables.service

cat << EOD > /etc/systemd/system/sshd-shutdown.service
# work around for broken systemd/sshd interaction in fedora 20 causes VM hangs
[Unit]
Description=kill all sshd sessions
Requires=mutil-user.target

[Service]
ExecStart=/usr/bin/killall sshd
Type=oneshot

[Install]
WantedBy=shutdown.target reboot.target poweroff.target
EOD
systemctl enable sshd-shutdown.service

# ensure pluto does not get restarted by systemd on crash
sed -i "s/Restart=always/Restart=no" /lib/systemd/system/ipsec.service

#ensure we can get coredumps
echo " * soft core unlimited" >> /etc/security/limits.conf
echo " DAEMON_COREFILE_LIMIT='unlimited'" >> /etc/sysconfig/pluto
ln -s /testing/guestbin/swan-prep /usr/bin/swan-prep
ln -s /testing/guestbin/swan-build /usr/bin/swan-build
ln -s /testing/guestbin/swan-install /usr/bin/swan-install
ln -s /testing/guestbin/swan-update /usr/bin/swan-update
ln -s /testing/guestbin/swan-run /usr/bin/swan-run

# add easy names so we can jump from vm to vm

cat << EOD >> /etc/hosts

192.0.1.254 west
192.0.2.254 east
192.0.3.254 north
192.1.3.209 road
192.1.2.254 nic
EOD

# Extra yum stuff

# Do this last so that should something barf or hang the install is
# still essentially OK.

# Need pyOpenSSL with ability to dump all certificates
yum upgrade -y 2>&1 \
    https://nohats.ca/ftp/pyOpenSSL/pyOpenSSL-0.14-4.fc21.noarch.rpm \
    | tee /var/tmp/pyOpenSSL.log

# Need strongswan with CTR, GCM, and other fixes
yum upgrade -y 2>&1 \
    https://nohats.ca/ftp/ssw/strongswan-5.3.2-1.0.lsw.fc22.x86_64.rpm \
    https://nohats.ca/ftp/ssw/strongswan-debuginfo-5.3.2-1.0.lsw.fc22.x86_64.rpm \
    | tee /var/tmp/strongswan.log

%end
