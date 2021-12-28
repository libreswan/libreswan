#!/bin/sh

title()
{
    printf "\n\n$*\n\n"
}

run()
{
    title "$@"
    "$@"
}


title limit kernel to two installs

# https://ask.fedoraproject.org/t/old-kernels-removal/7026/2
sudo sed -i 's/installonly_limit=3/installonly_limit=2/' /etc/dnf/dnf.conf


title systemd-networkd

# Provide a default network configuration for "fedora".

# Since systemd-networkd matches .network files in lexographical
# order, this zzz.*.network file is only matched when all else fails.

cat > /etc/systemd/network/zzz.eth0.network << EOF
[Match]
Name=eth0
Host=fedora
[Network]
Description=fallback for when no other interface matches
DHCP=yes
EOF

systemctl enable systemd-networkd.service
systemctl enable systemd-networkd-wait-online.service
systemctl disable systemd-resolved
systemctl disable NetworkManager

cp -v /testing/baseconfigs/all/etc/systemd/network/* /etc/systemd/network
restorecon -R /etc/systemd/network


title /etc/hosts

# add easy names so we can jump from vm to vm and map from IP address
# to hostname
cat <<EOF >> /etc/hosts
192.0.1.254 west
192.0.2.254 east
192.0.3.254 north
192.1.3.209 road
192.1.2.254 nic
EOF


title hostnamer

rm -f /etc/hostname # hostnamectl set-hostname ""
cat <<EOF > /etc/systemd/system/hostnamer.service
[Unit]
  Description=hostnamer: who-am-i
  #not-file-not-empty == file empty
  ConditionFileNotEmpty=|!/etc/hostname
  # need interfaces configured
  After=systemd-networkd-wait-online.service
  Before=network.target
[Service]
  Type=oneshot
  ExecStart=/usr/local/sbin/hostnamer.sh
[Install]
  WantedBy=multi-user.target
EOF
cat <<EOF > /usr/local/sbin/hostnamer.sh
#!/bin/sh
# per hostnamer.service, only run when /etc/hostname is empty
echo hostnamer: determining hostname | tee /dev/console
host()
{
	echo hostnamer hostname: \$1 | tee /dev/console
	hostnamectl set-hostname \$1
	exit 0
}
for mac in \$(ip address show | awk '\$1 == "link/ether" { print \$2 }') ; do
    echo hostnamer mac: \${mac} | tee /dev/console
    case \${mac} in
    	 #   eth0                 eth1               eth2
	                     12:00:00:de:ad:ba | 12:00:00:32:64:ba ) host nic ;;
	 12:00:00:dc:bc:ff | 12:00:00:64:64:23                     ) host east ;;
	 12:00:00:ab:cd:ff | 12:00:00:64:64:45                     ) host west ;;
	 12:00:00:ab:cd:02                                         ) host road ;;
	 12:00:00:de:cd:49 | 12:00:00:96:96:49                     ) host north ;;
     esac
done
EOF
chmod a+x /usr/local/sbin/hostnamer.sh
restorecon -R /etc/systemd/system
systemctl enable hostnamer.service


title add swan to paths

cat <<EOF > /etc/profile.d/swanpath.sh
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
EOF
restorecon -R /etc/profile.d/swanpath.sh


title /usr/bin/swan-...

ln -vs /testing/guestbin/swan-prep /usr/bin/swan-prep
ln -vs /testing/guestbin/swan-build /usr/bin/swan-build
ln -vs /testing/guestbin/swan-install /usr/bin/swan-install
ln -vs /testing/guestbin/swan-update /usr/bin/swan-update
ln -vs /testing/guestbin/swan-run /usr/bin/swan-run
restorecon -R /usr/bin/swan-*


title enable entropy

cat <<EOF > /etc/modules-load.d/virtio-rng.conf
# load virtio RNG device to get entropy from the host
# Note it should also be loaded on the host
virtio-rng
EOF
restorecon -R /etc/modules-load.d/virtio-rng.conf


title ensure we can get coredumps

echo " * soft core unlimited" >> /etc/security/limits.conf
echo " DAEMON_COREFILE_LIMIT='unlimited'" >> /etc/sysconfig/pluto
restorecon -R /etc/security/limits.conf /etc/sysconfig/pluto


title bind

# and bind config - can be run on all hosts (to prevent network DNS
# packets) as well as on nic
mkdir -p /etc/bind
cp -av /testing/baseconfigs/all/etc/bind/* /etc/bind/
restorecon -R /etc/bind


title ssh

mkdir -p /etc/ssh
chown -v 755 /etc/ssh
mkdir -p /root/.ssh
chown -v 700 /root/.ssh
cp -av /testing/baseconfigs/all/etc/ssh/*key* /etc/ssh/
cp -av /testing/baseconfigs/all/root/.ssh/* /root/.ssh/
chmod -v 600 /etc/ssh/*key* /root/.ssh/*
# enable password root logins (f32 disables these per default)
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
echo "MaxAuthTries 32" >> /etc/ssh/sshd_config
restorecon -R /root/.ssh /etc/ssh


title replace root/.bashrc

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
EOF

title files mysteriously needed for systemd-networkd too

for fname in /testing/baseconfigs/all/etc/sysconfig/* ; do
    if test -f "${fname}"; then
	cp -av "${fname}" /etc/sysconfig/
    fi
done
restorecon -R /etc/sysconfig/


title fixup /etc/sysctl.conf

cp -av /testing/baseconfigs/all/etc/sysctl.conf /etc/
sysctl -q -p
restorecon -R /etc/sysctl.conf


title run unbound-keygen once

systemctl start unbound-keygen.service


title Clobber some annoying services

# System Security Services Daemon (i.e., real PAM)
run systemctl disable sssd.service
run systemctl disable chronyd.service #NTP
# run systemctl mask systemd-user-sessions.service # doesn't work
run systemctl mask modprobe@drm.service
run systemctl mask dev-mqueue.mount
run systemctl mask dev-hugepages.mount
run systemctl mask systemd-vconsole-setup.service
run systemctl mask sys-kernel-tracing.mount
run systemctl mask sys-kernel-debug.mount
run systemctl mask systemd-repart.service
run systemctl mask systemd-homed.service
run systemctl mask user@0.service
run systemctl mask user-runtime-dir@0.service


title finally ... SElinux fixup with errors in /tmp/chcon.log

chcon -R --reference /var/log /testing/pluto > /tmp/chcon.log 2>&1 || true
