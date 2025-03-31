#!/bin/sh

set -xe ; exec < /dev/null

GATEWAY=@@GATEWAY@@
PREFIX=@@PREFIX@@
BENCHDIR=@@BENCHDIR@@
POOLDIR=@@POOLDIR@@
SOURCEDIR=@@SOURCEDIR@@
TESTINGDIR=@@TESTINGDIR@@
PLATFORM=@@PLATFORM@@

title()
{
    :
    : $*
    :
}

run()
{
    title "$@"
    "$@"
}

title mount /source and /testing

# /source and /testing are only pinned down during transmogrify.

for mount in source testing ; do
    cat <<EOF >>/etc/fstab
${mount} /${mount} 9p defaults,trans=virtio,version=9p2000.L,context=system_u:object_r:usr_t:s0,x-systemd.automount 0 0
EOF
    mkdir /${mount}
done


:
: systemd-networkd
:

. /bench/testing/kvm/systemd/transmogrify-networkd.sh
. /bench/testing/kvm/systemd/transmogrify-hostnamer.sh

systemctl disable NetworkManager

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
#
# XXX: are these config files are tied to the test run and hence
# should be copied over during the install or swan-pref step?

mkdir -p /etc/bind
cp -av /bench/testing/baseconfigs/all/etc/bind/* /etc/bind/
restorecon -R /etc/bind


title ssh

mkdir -p /etc/ssh
chown -v 755 /etc/ssh
mkdir -p /root/.ssh
chown -v 700 /root/.ssh
cp -av /bench/testing/baseconfigs/all/etc/ssh/*key* /etc/ssh/
cp -av /bench/testing/baseconfigs/all/root/.ssh/* /root/.ssh/
chmod -v 600 /etc/ssh/*key* /root/.ssh/*
# enable password root logins (f32 disables these per default)
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
echo "MaxAuthTries 32" >> /etc/ssh/sshd_config
restorecon -R /root/.ssh /etc/ssh


title replace root/.bash_profile

for f in /bench/testing/kvm/root/[a-z]* ; do
    cp -v ${f} /root/.$(basename $f)
done


title files mysteriously needed for systemd-networkd too

# XXX: are these config files are tied to the test run and hence
# should be copied over during the install or swan-pref step?
for fname in /bench/testing/baseconfigs/all/etc/sysconfig/* ; do
    cp -av "${fname}" /etc/sysconfig/
done
restorecon -R /etc/sysconfig/


title fixup /etc/sysctl.conf

# XXX: are these config files are tied to the test run and hence
# should be copied over during the install or swan-pref step?
cp -av /bench/testing/baseconfigs/all/etc/sysctl.conf /etc/
sysctl -q -p || true # expected to fail
restorecon -R /etc/sysctl.conf
sysctl -q -p || true # still expected to fail!


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

mount /testing
chcon -R --reference /var/log /testing/pluto > /tmp/chcon.log 2>&1 || true
