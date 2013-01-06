# Minimal Kickstart file
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

#Just core packages
#ensure we never accidentally get the openswan package
%packages
@core
# for now, let's not try and mix openswan rpm and /usr/local install of openswan
# later on, we will add an option to switch between "stock" and /usr/local openswan
-openswan
-sendmail
gdb
tcpdump
# nm causes problems and steals our interfaces desipte NM_CONTROLLED="no"
-NetworkManager
# to compile openswan
gcc
make
flex
bison
gmp-devel
nss-devel
nspr-devel
openldap-devel
curl-devel 
pam-devel
redhat-rpm-config
# not available at install time in this repo??
#racoon2
#nc6
#unbound-devel
#fipscheck-devel
#libcap-ng-devel
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
ifconfig eth0 mtu 1400

# TODO: if rhel/centos, we should install epel-release too
yum install -y wget vim-enhanced bison flex gmp-devel nss-devel nss-tools  gcc make kernel-devel unbound-libs ipsec-tools
yum install -y racoon2 nc6 unbound-devel fipscheck-devel libcap-ng-devel git pam-devel audit-libs-devel

mkdir /testing /source

cat << EOD >> /etc/issue

The root password is "swan"
EOD

# noauto for now, as we seem to need more system parts started before we can mount 9p
cat << EOD >> /etc/fstab
testing /testing 9p defaults,noauto,trans=virtio,version=9p2000.L 0 0
swansource /source 9p defaults,noauto,trans=virtio,version=9p2000.L 0 0
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

systemctl enable network.service
systemctl enable iptables.service
systemctl enable ip6tables.service

# Takes a long time, disable for now
# yum update -y 

# Instal openswan
mount /source
cd /source
make programs module install module_install

# ensure pluto does not get restarted by systemd on crash
sed -i "s/Restart=always/Restart=no" /lib/systemd/system/ipsec.service

%end
