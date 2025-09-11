# Minimal Kickstart file for fedora

# Limit things to: basic network configuration; 9pfs mounts; setting
# the password; et.al.

# Everything interesting, such as installing packages, configuring and
# transmogrifying, happens after the domain is rebooted.

cmdline
reboot
lang en_US.UTF-8
keyboard us
rootpw swan
# UTC???
timezone --utc America/New_York
# firstboot --disable

# Don't configure the network (allow NetworkManager)
#
# That is handled by transmogrify after systemd-networkd has been
# installed.

network --hostname linux

# See kernel and dracut documentation:
#   net.ifnames=0 biosdevname=0: call network interfaces eth0...
#   plymouth.enable=0: disable the plymouth bootsplash completely

bootloader --timeout=0 --location=mbr --append="console=tty0 console=ttyS0,115200 plymouth.enable=0 net.ifnames=0 biosdevname=0 mitigations=off"

# Start with a blank disk (ignoring that it is already).  Force
# standard label (was --disklabel gpt) (F37 likely doesn't support
# MBR?); required machine dependent partitions; add /; don't add swap!

clearpart --all --initlabel
reqpart --add-boot
part / --asprimary --grow
# part swap --size 1024

%packages

# Minimal list of RPMs to install; see fNN.mk for the full list which
# are installed after a reboot and when the netork is up.

@core

# don't confuse things
-libreswan
# Temporary; will install systemd-networkd during upgrade.sh
NetworkManager
-network-scripts
# misc
-firewalld
-at
-sendmail
# cron
-cronie
# eye candy
-plymouth
# tests use custom resolved; not needed for build
-systemd-resolved

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


# Keep the root password secret

cat << EOD >> /etc/issue
The root password is "swan"
EOD


# load 9p modules in time for auto mounts

cat << EOD > /etc/modules-load.d/9pnet_virtio.conf
9pnet_virtio
EOD


# Mount /pool and /bench
#
# Full KVM snapshots (saves) don't work with NFS/9p mounts.  Hence use
# automount so that things are only mounted after the VM has booted
# and a snapshot has been taken.
#
# Why use /etc/fstab?
#
# To quote the systemd.mount documentation: In general, configuring
# mount points through /etc/fstab is the preferred approach.
#
# Why not create and mount /source and /testing?
#
# These may not point at the current directory (they can change, and
# are setup during transmogrify).  Not setting them now makes it
# harder to accidentally use a file from a wrong directory.

mkdir /pool /bench
cat <<EOF >>/etc/fstab
pool  /pool  9p defaults,trans=virtio,version=9p2000.L,context=system_u:object_r:usr_t:s0,x-systemd.automount 0 0
bench /bench 9p defaults,trans=virtio,version=9p2000.L,context=system_u:object_r:usr_t:s0,x-systemd.automount 0 0
EOF


systemctl enable iptables.service
systemctl enable ip6tables.service

# > F27 and later to support X509 Certificates, signed with SHA1
/usr/bin/update-crypto-policies --set LEGACY

# blacklist NetworkManager since it conflicts with systemd-networkd
sed -i $'s/enabled=1/enabled=1\\\nexclude=NetworkManager*/g' /etc/yum.repos.d/fedora.repo
sed -i $'s/enabled=1/enabled=1\\\nexclude=NetworkManager*/g' /etc/yum.repos.d/fedora-updates.repo

# minimal prompt

# Simple .bashrc; see also testing/libvirt/bashrc

cat <<EOF > /root/.bashrc
# don't flood output with bracket characters
bind 'set enable-bracketed-paste off'
# simple path
PATH=/bin:/sbin:/usr/local/bin:/usr/local/sbin:/testing/guestbin
# editor
export EDITOR=vim
# git stuff
export GIT_PS1_SHOWDIRTYSTATE=true
alias git-log-p='git log --pretty=format:"%h %ad%x09%an%x09%s" --date=short'
# stop systemd adding control characters
export LC_CTYPE=C
export SYSTEMD_COLOURS=false
# don't wander into the weeds looking for debug info
unset DEBUGINFOD_URLS
# include status in the prompt
PS1='[\u@\h \W \$?]\\$ '
EOF

%end
