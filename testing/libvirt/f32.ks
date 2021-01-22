# Minimal Kickstart file for fedora

# Limit things to: basic network configuration; 9pfs mounts; setting
# the password; et.al.

# Everything interesting, such as installing packages, configuring and
# transmogrifying, happens after the domain is rebooted.

install
text
reboot
lang en_US.UTF-8
keyboard us
rootpw swan
# UTC???
timezone --utc America/New_York
# firstboot --disable

# Need to set hostname, scripts use hostname==swanbase as a marker
# indicating that the domain hasn't been transmogrified (provided we
# ignore base's transmogrification).

# Don't enable the network.  That's handled in %post when
# systemd-networkd is configured (the machine only needs to come
# online after a reboot).

network --hostname swanbase

# See kernel and dracut documentation:
#   net.ifnames=0 biosdevname=0: call network interfaces eth0...
#   plymouth.enable=0: disable the plymouth bootsplash completely

bootloader --timeout=0 --location=mbr --append="console=tty0 console=ttyS0,115200 plymouth.enable=0 net.ifnames=0 biosdevname=0"

# start with a blank disk

zerombr
clearpart --all --initlabel
part / --asprimary --grow
# part swap --size 1024

%packages

# Minimal list of RPMs to install; see fNN.mk for the full list which
# are installed after a reboot and when the netork is up.

@core

# don't confuse things
-libreswan
# only one network config
-NetworkManager
-network-scripts
# misc
-firewalld
-at
-sendmail
# cron
-cronie
# eye candy
-plymouth

%end

%post

# This first appeared in f28; but with f32 still seems to be needed:
#
# The original f28 comment was: Without this systemd-networkd fails to
# start with:
#
#   systemd-networkd.service: Failed to set up mount namespacing: Permission denied
#   systemd-networkd.service: Failed at step NAMESPACE spawning /usr/lib/systemd/systemd-networkd: Permission denied
#   systemd[1]: systemd-networkd.service: Main process exited, code=exited, status=226/NAMESPACE
#
# On f32, it isn't possible to log into the base domain (use <<make
# kvm-demolish kvmsh-base>>) - after the password prompt things hang
# for a bit then re-prompt the username.

selinux --permissive
/usr/bin/sed -i -e 's/SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config

# Add a default network configuration for swanbase.

# Since systemd-networkd matches .network files in lexographical
# order, this zzz.*.network file is only matched when all else fails.

# During transmogrification, more specific .network files are
# installed.  The kernel boot parameters net.ifnames=0 and
# biosdevname=0 (set way above) force the eth0 names (keeping test
# output happy).

cat > /etc/systemd/network/zzz.eth0.network << EOF
[Match]
Name=eth0
Host=swanbase
[Network]
Description=fallback for when no other interface matches
DHCP=yes
EOF

systemctl enable systemd-networkd.servide
systemctl enable systemd-networkd-wait-online.service
systemctl disable systemd-resolved

# F28-F31 dracut leaves network config files there. remove it to be safe
# Drcut cannot use systemd-networkd or create an initial configuration yet.
# https://github.com/dracutdevs/dracut/issues/670
rm -fr /etc/sysconfig/network-scripts/i*

# Danger: the transmogrify scripts use the presence of this file as an
# indicator that systemd-networkd is being used.

cat > /etc/sysconfig/network-scripts/README.libreswan << EOF
Do not add files here.  networkig is handled by systemd-networkd
/etc/systemd/network
networkctl
EOF

cat << EOD >> /etc/issue

The root password is "swan"
EOD


# Mount /testing, /source, and /pool (swanbase only) using 9p (will
# be available after a reboot).

# load 9p modules in time for auto mounts
cat << EOD > /etc/modules-load.d/9pnet_virtio.conf
9pnet_virtio
EOD

for mount in testing source pool ; do

    case ${mount} in
    pool) condition_host= ;;
    *)    condition_host="# " ;;
    esac

    cat <<EOF >/etc/systemd/system/${mount}.mount
[Unit]
  Description=libreswan ${mount}
  ${condition_host}ConditionHost=swanbase
[Mount]
  What=${mount}
  Where=/${mount}
  Type=9p
  Options=defaults,trans=virtio,version=9p2000.L,context=system_u:object_r:usr_t:s0
[Install]
  WantedBy=multi-user.target
EOF

    mkdir /${mount}
    systemctl enable ${mount}.mount
done

systemctl enable systemd-networkd
systemctl enable systemd-networkd-wait-online
systemctl enable iptables.service
systemctl enable ip6tables.service

# > F27 and later to support X509 Certificates, signed with SHA1
/usr/bin/update-crypto-policies --set LEGACY

# blacklist NetworkManager since it conflits with systemd-networkd
sed -i $'s/enabled=1/enabled=1\\\nexclude=NetworkManager*/g' /etc/yum.repos.d/fedora.repo
sed -i $'s/enabled=1/enabled=1\\\nexclude=NetworkManager*/g' /etc/yum.repos.d/fedora-updates.repo

%end
