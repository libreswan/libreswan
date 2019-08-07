# Minimal Kickstart file for fedora
install
text
reboot
lang en_US.UTF-8
keyboard us
# F30 will install network using systemd-networkd
network --bootproto=dhcp --hostname swanbase
#
# static network does not work with recent dracut, use kernel args instead
# network --bootproto=static --ip=76.10.157.78 --netmask=255.255.255.240 --gateway=76.10.157.65 --hostname swanbase
rootpw swan
firewall --disable

timezone --utc America/New_York
# firstboot --disable
bootloader --timeout=0 --location=mbr --append="console=tty0 console=ttyS0,115200 rd_NO_PLYMOUTH net.ifnames=0 biosdevname=0"
zerombr
clearpart --all --initlabel
part / --asprimary --grow
# part swap --size 1024

services --disabled=sm-client,sendmail,network,smartd,crond,atd,systemd-resolved

%packages --ignoremissing

# Full list of RPMs to install (see also fedoraXX.mk)

# Since it is fast and local, try to install everything here using the
# install DVD image.  Anything missing will be fixed up later in
# %post. The option --ignoremissing is specified so we don't have to
# juggle what is enabled / disabled here.

# Note: The problem is that the DVD doesn't contain "Everything" -
# that repo only becomes available during %post when it is enabled.
# To get around this, %post installing a few things that were missed.
# The easiest way to figure out if something ALSO needs to be listed
# in %post is to look in "Packaging/" on the DVD.  I just wish this
# could go in a separate file so post could do the fix up
# automatically.

@core
dracut-network
-sendmail
-libreswan

# NetworkManager causes problems and steals our interfaces despite
# NM_CONTROLLED="no".
-NetworkManager

%end

%post

# Paul needs this due to broken isp
#ifconfig eth0 mtu 1400
# Tuomo switched to this alternative work-around for pmtu issues
sysctl -w net.ipv4.tcp_mtu_probing=1

ip addr show scope global >> /var/tmp/network.log
networkctl >> /var/tmp/network.log

# > F28 selinux set to permissive while debugging systemd-networkd
# systemd-networkd.service: Failed to set up mount namespacing: Permission denied
# systemd-networkd.service: Failed at step NAMESPACE spawning /usr/lib/systemd/systemd-networkd: Permission denied
# systemd[1]: systemd-networkd.service: Main process exited, code=exited, status=226/NAMESPACE
selinux --permissive
/usr/bin/sed -i -e 's/SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config

# dracut does not create systemd-networkd config, so create one
# https://bugzilla.redhat.com/show_bug.cgi?id=1582941
cat > /etc/systemd/network/eth0.network << EOF
[Match]
Name=eth0

[Network]
DHCP=yes

EOF

# F28 dracut leaves network config files there. remove it to be safe
rm -fr /etc/sysconfig/network-scripts/i*

cat > /etc/sysconfig/network-scripts/README.libreswan << EOF
Do not add files here.  networkig is handled by systemd-networkd
/etc/systemd/nework
networkctl
EOF

rpm -qa > /var/tmp/rpm-qa-darcut-fedora.log

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
export GIT_PS1_SHOWDIRTYSTATE=true
alias git-log-p='git log --pretty=format:"%h %ad%x09%an%x09%s" --date=short'
export EDITOR=vim
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

systemctl disable firewalld.service
systemctl enable systemd-networkd
systemctl enable systemd-networkd-wait-online
systemctl enable iptables.service
systemctl enable ip6tables.service
systemctl enable sshd-shutdown.service

#ensure we can get coredumps
echo " * soft core unlimited" >> /etc/security/limits.conf
echo " DAEMON_COREFILE_LIMIT='unlimited'" >> /etc/sysconfig/pluto
ln -s /testing/guestbin/swan-prep /usr/bin/swan-prep
ln -s /testing/guestbin/swan-build /usr/bin/swan-build
ln -s /testing/guestbin/swan-install /usr/bin/swan-install
ln -s /testing/guestbin/swan-update /usr/bin/swan-update
ln -s /testing/guestbin/swan-run /usr/bin/swan-run

# > F27 and later to support X509 Certificates, signed with SHA1
/usr/bin/update-crypto-policies --set LEGACY

# add easy names so we can jump from vm to vm
cat << EOD >> /etc/hosts

192.0.1.254 west
192.0.2.254 east
192.0.3.254 north
192.1.3.209 road
192.1.2.254 nic
EOD

%end
