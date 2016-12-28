# Minimal Kickstart file - updated for fedora 23
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

# To help avoid duplicates THIS LIST IS SORTED.

ElectricFence
audit-libs-devel
bind-utils
bison
conntrack-tools
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
libfaketime
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
ocspd
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


%post

%end
