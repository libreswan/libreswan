# Minimal Kickstart file for fedora

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
# ntp
-crony
# cron
-cronie
# System Security Services Daemon (i.e., real PAM)
-sssd

%end

%post

# Everything interesting happens after the domain is rebooted.  Namely
# upgrade / install missing packages; and transmogrify the
# configuration.

#
# Configure eth0 so that it comes up after a reboot
#
# How come this machine still uses legacy names?

# Without this systemd-networkd fails to start with:
#
#   systemd-networkd.service: Failed to set up mount namespacing: Permission denied
#   systemd-networkd.service: Failed at step NAMESPACE spawning /usr/lib/systemd/systemd-networkd: Permission denied
#   systemd[1]: systemd-networkd.service: Main process exited, code=exited, status=226/NAMESPACE

selinux --permissive
/usr/bin/sed -i -e 's/SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config

# Configure swanbase's network.  Once the domain is transmogrified
# (and hostname changes) eth0.network will be overwritten. The kernel
# parameters net.ifnames=0 biosdevname=0 forces eth0 et.al. to be
# used.
# once dracut can create the filre remove this this hack
# https://github.com/dracutdevs/dracut/issues/670

cat > /etc/systemd/network/eth0.network << EOF
[Match]
Name=eth0
Host=swanbase
[Network]
DHCP=yes
EOF

systemctl enable systemd-networkd.servide
systemctl enable systemd-networkd-wait-online.service
systemctl disable systemd-resolved

# F28-F31 dracut leaves network config files there. remove it to be safe
# Drcut can not use systemd-networkd or create an initial configuration yet.
# https://github.com/dracutdevs/dracut/issues/670
rm -fr /etc/sysconfig/network-scripts/i*

# Danger: the transmogrify scripts use the presence of this file as an
# indicator that systemd-networkd is being used.

cat > /etc/sysconfig/network-scripts/README.libreswan << EOF
Do not add files here.  networkig is handled by systemd-networkd
/etc/systemd/network
networkctl
EOF

rpm -qa > /var/tmp/rpm-qa-darcut-fedora.log

cat << EOD >> /etc/issue

The root password is "swan"
EOD

#
# Mount /testing, /source, and /pool (swanbase only) using 9p (will
# be available after a reboot).
#

# load 9p modules in time for auto mounts
cat << EOD > /etc/modules-load.d/9pnet_virtio.conf
9pnet_virtio
EOD

for mount in testing source pool ; do

    what=${mount}
    condition_host="# "
    case ${mount} in
    source) what=swansource;;
    pool) condition_host=;;
    esac

    cat <<EOF >/etc/systemd/system/${mount}.mount
[Unit]
  Description=libreswan ${mount}
  ${condition_host}ConditionHost=swanbase
[Mount]
  What=${what}
  Where=/${mount}
  Type=9p
  Options=defaults,trans=virtio,version=9p2000.L,context=system_u:object_r:usr_t:s0
[Install]
  WantedBy=multi-user.target
EOF

    mkdir /${mount}
    systemctl enable ${mount}.mount
done


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

# enable password root logins (f32 disables these per default)
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config

# blacklist NetworkManager since it conflits with systemd-networkd
sed -i $'s/enabled=1/enabled=1\\\nexclude=NetworkManager*/g' /etc/yum.repos.d/fedora.repo
sed -i $'s/enabled=1/enabled=1\\\nexclude=NetworkManager*/g' /etc/yum.repos.d/fedora-updates.repo


%end
