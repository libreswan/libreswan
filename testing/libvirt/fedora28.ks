# Minimal Kickstart file - updated for fedora 28
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
bootloader --timeout=0 --location=mbr --append="console=tty0 console=ttyS0,115200 rd_NO_PLYMOUTH net.ifnames=0 biosdevname=0"
zerombr
clearpart --all --initlabel
part / --asprimary --grow
# part swap --size 1024
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
# them is what takes all the time and bandwidth.

# Note: To avoid an accidental kernel upgrade (KLIPS doesn't build
# with some 4.x kernels), install everything kernel dependent here.
# If you find the kernel still being upgraded look at the log files in
# /var/tmp created during the %post state.

@core

# Install the kernel stuff from the CD so it is somewhat stable.

kernel-core
kernel-devel
kernel-headers
kernel-modules
kernel-modules-extra

-sendmail
-libreswan

# nm causes problems and steals our interfaces desipte NM_CONTROLLED="no"
-NetworkManager

%end

%post
# Paul needs this due to broken isp
#ifconfig eth0 mtu 1400
# Tuomo switched to this alternative work-around for pmtu issues
sysctl -w net.ipv4.tcp_mtu_probing=1

ip addr show scope global >> /var/tmp/network.log
HWA=`cat /sys/class/net/e[n-t][h-s]?/address`
#clean up HWADDR line F22 has it F26 not:)
mv /etc/sysconfig/network-scripts/ifcfg-ens? /etc/sysconfig/network-scripts/ifcfg-eth0
sed -i '/HWADDR=/d' /etc/sysconfig/network-scripts/ifcfg-eth0
echo "HWADDR=\"$HWA\"" >> /etc/sysconfig/network-scripts/ifcfg-eth0
sed  -i 's/ens.*/eth0/' /etc/sysconfig/network-scripts/ifcfg-eth0
# sometimes it need another ifup
ifup ens2 >> /var/tmp/network.log

rpm -qa > /var/tmp/rpm-qa-fedora.log

dnf -y --disablerepo=updates update | tee /var/tmp/dnf-update-fedora.log
dnf -y --disablerepo=updates install kernel-devel
sed -i '/exclude=kernel/d' /etc/dnf/dnf.conf
echo "exclude=kernel*" >> /etc/dnf/dnf.conf

mkdir /testing /source

cat << EOD >> /etc/issue

The root password is "swan"
EOD

# Once the machine has rebooted testing and swansource will be
# available and mounted automatically.

cat << EOD >> /etc/fstab
testing /testing 9p defaults,trans=virtio,version=9p2000.L,context=system_u:object_r:var_log_t:s0 0 0
swansource /source 9p defaults,trans=virtio,version=9p2000.L,context=system_u:object_r:usr_t:s0 0 0
tmpfs                   /dev/shm                tmpfs   defaults        0 0
tmpfs                   /tmp                    tmpfs   defaults        0 0
devpts                  /dev/pts                devpts  gid=5,mode=620  0 0
sysfs                   /sys                    sysfs   defaults        0 0
proc                    /proc                   proc    defaults        0 0
EOD

cat << EOD >> /etc/rc.d/rc.local
#!/bin/sh
SELINUX=\$(getenforce)
echo "getenforce \$SELINUX" > /tmp/rc.local.txt
setenforce Permissive
/testing/guestbin/swan-transmogrify 2>&1 >> /tmp/rc.local.txt || echo "ERROR swan-transmogrify" >> /tmp/rc.local.txt
echo "restore SELINUX to \$SELINUX"
setenforce \$SELINUX
hostname |grep -q swanbase || rm /etc/rc.d/rc.local
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

#ensure we can get coredumps
echo " * soft core unlimited" >> /etc/security/limits.conf
echo " DAEMON_COREFILE_LIMIT='unlimited'" >> /etc/sysconfig/pluto
ln -s /testing/guestbin/swan-prep /usr/bin/swan-prep
ln -s /testing/guestbin/swan-build /usr/bin/swan-build
ln -s /testing/guestbin/swan-install /usr/bin/swan-install
ln -s /testing/guestbin/swan-update /usr/bin/swan-update
ln -s /testing/guestbin/swan-run /usr/bin/swan-run

# F28 and later to support X509 Certificates, signed with SHA1
/usr/bin/update-crypto-policies --set LEGACY

# > F24  keep eth0 naming : "Disabling Consistent Network Device Naming"
ln -s /dev/null /etc/udev/rules.d/80-net-name-slot.rules

# add easy names so we can jump from vm to vm
cat << EOD >> /etc/hosts

192.0.1.254 west
192.0.2.254 east
192.0.3.254 north
192.1.3.209 road
192.1.2.254 nic
EOD

%end
