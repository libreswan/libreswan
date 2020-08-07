#!/bin/sh

set -x

cp -v /testing/baseconfigs/all/etc/systemd/network/* /etc/systemd/network


# /etc/rc.d/rc.local
cat <<EOF > /etc/rc.d/rc.local
#!/bin/sh
exec > /tmp/rc.local.txt 2>&1
ls /sys
ls /proc
SELINUX=\$(getenforce)
echo "getenforce \$SELINUX" > /tmp/rc.local.txt
setenforce Permissive
/testing/guestbin/swan-transmogrify
echo "restore SELINUX to \$SELINUX"
setenforce \$SELINUX
hostname |grep -q swanbase || rm /etc/rc.d/rc.local
EOF
chmod 755 /etc/rc.d/rc.local


# /etc/hosts
#
# add easy names so we can jump from vm to vm and map from IP address
# to hostname

cat <<EOF >> /etc/hosts
192.0.1.254 west
192.0.2.254 east
192.0.3.254 north
192.1.3.209 road
192.1.2.254 nic
EOF


# default paths

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

ln -s /testing/guestbin/swan-prep /usr/bin/swan-prep
ln -s /testing/guestbin/swan-build /usr/bin/swan-build
ln -s /testing/guestbin/swan-install /usr/bin/swan-install
ln -s /testing/guestbin/swan-update /usr/bin/swan-update
ln -s /testing/guestbin/swan-run /usr/bin/swan-run


# enable password root logins (f32 disables these per default)

echo "PermitRootLogin yes" >> /etc/ssh/sshd_config


# enable entropy

cat <<EOF > /etc/modules-load.d/virtio-rng.conf
# load virtio RNG device to get entropy from the host
# Note it should also be loaded on the host
virtio-rng
EOF


# work around for broken systemd/sshd interaction in fedora 20 causes VM hangs

cat <<EOF > /etc/systemd/system/sshd-shutdown.service
# work around for broken systemd/sshd interaction in fedora 20 causes VM hangs
[Unit]
  Description=kill all sshd sessions
  Requires=mutil-user.target
[Service]
  ExecStart=/usr/bin/killall sshd
  Type=oneshot
[Install]
  WantedBy=shutdown.target reboot.target poweroff.target
EOF
systemctl enable sshd-shutdown.service


#ensure we can get coredumps

echo " * soft core unlimited" >> /etc/security/limits.conf
echo " DAEMON_COREFILE_LIMIT='unlimited'" >> /etc/sysconfig/pluto
