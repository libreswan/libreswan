#!/bin/sh

set -xe ; exec < /dev/null

GATEWAY=@@GATEWAY@@
PREFIX=@@PREFIX@@
BENCHDIR=@@BENCHDIR@@
POOLDIR=@@POOLDIR@@
SOURCEDIR=@@SOURCEDIR@@
TESTINGDIR=@@TESTINGDIR@@
PLATFORM=@@PLATFORM@@

TITLE()
{
    :
    : $*
    :
}

RUN()
{
    TITLE "$@"
    "$@"
}


:
: mount /source and /testing and /pool
:

# /source and /testing are only pinned down during transmogrify; /pool
# is where the packages live.

sed -e '/9p/d' /etc/fstab > /etc/fstab.tmp

for mount in source testing pool ; do
    mkdir -p /${mount}
    cat <<EOF >> /etc/fstab.tmp
${mount} /${mount} 9p defaults,trans=virtio,version=9p2000.L,context=system_u:object_r:usr_t:s0,x-systemd.automount 0 0
EOF
done

mv /etc/fstab.tmp /etc/fstab


:
: systemd-networkd
:

. /bench/testing/kvm/systemd/transmogrify-networkd.sh

systemctl disable NetworkManager

TITLE /etc/hosts

# add easy names so we can jump from vm to vm and map from IP address
# to hostname
cat <<EOF >> /etc/hosts
192.0.1.254 west
192.0.2.254 east
192.0.3.254 north
192.1.3.209 road
192.1.2.254 nic
EOF


TITLE add swan to paths

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


TITLE /usr/bin/swan-...

ln -vs /testing/guestbin/swan-prep /usr/bin/swan-prep
ln -vs /testing/guestbin/swan-build /usr/bin/swan-build
ln -vs /testing/guestbin/swan-install /usr/bin/swan-install
ln -vs /testing/guestbin/swan-update /usr/bin/swan-update
ln -vs /testing/guestbin/swan-run /usr/bin/swan-run
restorecon -R /usr/bin/swan-*


TITLE enable entropy

cat <<EOF > /etc/modules-load.d/virtio-rng.conf
# load virtio RNG device to get entropy from the host
# Note it should also be loaded on the host
virtio-rng
EOF
restorecon -R /etc/modules-load.d/virtio-rng.conf


TITLE ensure we can get coredumps

echo " * soft core unlimited" >> /etc/security/limits.conf
echo " DAEMON_COREFILE_LIMIT='unlimited'" >> /etc/sysconfig/pluto
restorecon -R /etc/security/limits.conf /etc/sysconfig/pluto


TITLE bind

# and bind config - can be run on all hosts (to prevent network DNS
# packets) as well as on nic
#
# XXX: are these config files are tied to the test run and hence
# should be copied over during the install or swan-pref step?

mkdir -p /etc/bind
cp -av /bench/testing/baseconfigs/all/etc/bind/* /etc/bind/
restorecon -R /etc/bind


TITLE ssh

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


TITLE replace root/.bash_profile

for f in /bench/testing/kvm/root/[a-z]* ; do
    cp -v ${f} /root/.$(basename $f)
done


TITLE files mysteriously needed for systemd-networkd too

# XXX: are these config files are tied to the test run and hence
# should be copied over during the install or swan-pref step?
for fname in /bench/testing/baseconfigs/all/etc/sysconfig/* ; do
    cp -av "${fname}" /etc/sysconfig/
done
restorecon -R /etc/sysconfig/


TITLE fixup /etc/sysctl.conf

# XXX: are these config files are tied to the test run and hence
# should be copied over during the install or swan-pref step?
cp -av /bench/testing/baseconfigs/all/etc/sysctl.conf /etc/
sysctl -q -p || true # expected to fail
restorecon -R /etc/sysctl.conf
sysctl -q -p || true # still expected to fail!


TITLE run unbound-keygen once

systemctl start unbound-keygen.service
systemctl disable unbound-anchor.timer


TITLE Clobber some annoying services

# System Security Services Daemon (i.e., real PAM)
RUN systemctl disable sssd.service
RUN systemctl disable chronyd.service #NTP
# RUN systemctl mask systemd-user-sessions.service # doesn't work
RUN systemctl mask modprobe@drm.service
RUN systemctl mask dev-mqueue.mount
RUN systemctl mask dev-hugepages.mount
RUN systemctl mask systemd-vconsole-setup.service
RUN systemctl mask sys-kernel-tracing.mount
RUN systemctl mask sys-kernel-debug.mount
RUN systemctl mask systemd-repart.service
RUN systemctl mask systemd-homed.service
RUN systemctl mask user@0.service
RUN systemctl mask user-runtime-dir@0.service


TITLE install any custom RPMs

for rpmdir in /bench/linux-rpms /pool/${PREFIX}linux-rpms ; do
    # directory is not called linux-transmogrify.* as a cleanup would
    # delete it; oops!
    if test -d ${rpmdir} ; then
	RUN rpm -vi --force ${rpmdir}/*.rpm
	break
    fi
done


TITLE save the latest kernels

# The Saved kernel is called linux.* so that cleaning up transmogrify,
# using `make uninstall`, cleans up the files.
kernel=$(ls /boot/vmlinuz-* | sort -V | tail -1)
cp -vf ${kernel} /pool/${PREFIX}linux.vmlinuz
ramfs=$(ls /boot/initramfs-*.img | sort -V | tail -1)
cp -vf ${ramfs} /pool/${PREFIX}linux.initramfs

# Ensure that the files are globally readable.  Work-around for
# libvirt/761 where the file ownership is flip-flops between ROOT and
# WHOAMI - a u=r,go= file when owned by ROOT isn't accessible by QEMU
# when running as WHOAMI.
chmod go+r  /pool/${PREFIX}linux.vmlinuz
chmod go+r /pool/${PREFIX}linux.initramfs

TITLE finally ... SElinux fixup with errors in /tmp/chcon.log

mount /testing
chcon -R --reference /var/log /testing/pluto > /tmp/chcon.log 2>&1 || true
