# Minimal Kickstart file
install
text
reboot
lang en_US
langsupport en_US
keyboard us
#url --url http://76.10.157.69/ubuntu/
url --url http://ftp.ubuntu.com/ubuntu/
user --disabled
timezone --utc America/New_York
rootpw swan1234
bootloader --location=mbr
zerombr
clearpart --all --initlabel
part / --fstype ext4 --size 7000 --asprimary
part swap --size 1024
#network --bootproto=static --ip=76.10.157.78 --netmask=255.255.255.240 --gateway=76.10.157.65 --hostname swanbase
network --bootproto=dhcp --hostname swanbase
auth  --useshadow  --enablemd5
firewall --disabled --ssh
skipx
#xconfig --depth=32 --resolution=1280x1024 --defaultdesktop=GNOME --startxonboot

# ugh, packagges selection not supported in ubuntu installer
#%packages


%pre
ip link set eth0 mtu 1400
%end

%post
echo "nameserver 193.110.157.123" >> /etc/resolv.conf
#/sbin/restorecon /etc/resolv.conf
# Paul needs this due to broken isp
ip link set eth0 mtu 1400

# TODO: Do we need to configure universe/multiverse/everythingverse?
apt-get install -y wget vim bison flex gcc make netcat-openbsd strace python-pexpect
# racoon2 not available on ubuntu?
apt-get install -y libnss3-tools libnss3-dev libunbound-dev libldap-dev libcurl4-nss-dev libcap-ng-dev libpam-dev ipsec-tools
# no package for fipscheck-devel?

mkdir /testing /source

cat << EOD >> /etc/issue

The root password is "swan1234"
EOD

# noauto for now, as we seem to need more system parts started before we can mount 9p
cat << EOD >> /etc/fstab
testing /testing 9p defaults,noauto,trans=virtio,version=9p2000.L 0 0
swansource /source 9p defaults,noauto,trans=virtio,version=9p2000.L 0 0
EOD


cat << EOD > /etc/rc.local
#!/bin/sh
mount /testing
mount /source
/testing/guestbin/swan-transmogrify
EOD
chmod 755 /etc/rc.local

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

cat << EOD >> /etc/modules
# load 9p modules in time for auto mounts
9p
9pnet
9pnet_virtio
# load virtio RNG device to get entropy from the host
# Note it should also be loaded on the host
virtio-rng
EOD

# Takes a long time, disable for now
# apt-get update -y

# Instal openswan
mount /source
cd /source
make programs module install module_install

# ensure pluto does not get restarted by systemd on crash
sed -i "s/Restart=always/Restart=no" /lib/systemd/system/ipsec.service

ln -s /testing/guestbin/swan-prep /usr/bin/swan-prep
ln -s /testing/guestbin/swan-build /usr/bin/swan-build
ln -s /testing/guestbin/swan-install /usr/bin/swan-install
ln -s /testing/guestbin/swan-update /usr/bin/swan-update
ln -s /testing/guestbin/swan-run /usr/bin/swan-run

%end
