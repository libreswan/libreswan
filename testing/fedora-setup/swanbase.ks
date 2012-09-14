# Minimal Kickstart file
install
text
reboot
lang en_US.UTF-8
keyboard us
#network --bootproto=static --ip=76.10.157.78 --netmask=255.255.255.240 --gateway=76.10.157.65 --hostname swanbase
network --bootproto=dhcp --hostname swanbase 
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
racoon2
nc6
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
unbound-devel
fipscheck-devel
libcap-ng-devel
openldap-devel
curl-devel 
redhat-rpm-config
%end

%post 
echo "nameserver 193.110.157.123" >> /etc/resolv.conf
/sbin/restorecon /etc/resolv.conf
# TODO: if rhel/centos, we should install epel-release too
yum install -y nc6 racoon2 wget vim-enhanced bison flex gmp-devel nss-devel nss-tools  gcc make kernel-devel unbound-libs

mkdir /testing /source

# noauto for now, as we seem to need more system parts started before we can mount 9p
echo "testing /testing 9p defaults,noauto,trans=virtio 0 0" >> /etc/fstab
echo "swansource /source 9p defaults,noauto,trans=virtio 0 0" >> /etc/fstab
# mounting tmp as /tmp causes weird IO issues 
#echo "tmp /tmp 9p defaults,noauto,trans=virtio 0 0" >> /etc/fstab

cat << EOD > /etc/rc.d/rc.local 
mount /testing
mount /source
/testing/fedora-setup/swan-transmogrify
EOD
chmod 755 /etc/rc.d/rc.local

cat << EOD > /etc/modules-load.d/9pnet_virtio.conf
# load 9p modules in time for auto mounts
9pnet_virtio
EOD
cat << EOD > /etc/modules-load.d/virtio-rng.conf
# load virtio RNG device to get entropy from the host
# Note it should also be loaded on the host
virtio-rng
EOD

cat << EOD >> /etc/sysconfig/iptables
*filter
:INPUT ACCEPT [111:7052]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [75:6652]
:LOGDROP - [0:0]
COMMIT
EOD

cat << EOD >> /etc/sysconfig/ip6tables
*filter
:INPUT ACCEPT [111:7052]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [75:6652]
:LOGDROP - [0:0]
COMMIT
EOD

systemctl enable network.service
systemctl enable iptables.service
systemctl enable ip6tables.service

yum update -y 
%end
