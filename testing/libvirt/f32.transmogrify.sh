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
  Description=Figure out who we are
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
ip=\$(ip address show dev eth0 | awk '\$1 == "inet" { print gensub("/[0-9]*", "", 1, \$2)}')
echo ip: \${ip} | tee /dev/console
hostname=\$(awk '\$1 == IP { host=\$2; } END { print host; }' IP=\${ip} /etc/hosts)
echo hostname: \${hostname} | tee /dev/console
test -n "\${hostname}" && hostnamectl set-hostname \${hostname}
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


title get rid of rm, cp, mv shell aliases

sed -i 's/^alias rm/# alias rm/g' /root/.bashrc
sed -i 's/^alias cp/# alias cp/g' /root/.bashrc
sed -i 's/^alias mv/# alias mv/g' /root/.bashrc


title files mysteriously needed for systemd-networkd too

for fname in /testing/baseconfigs/all/etc/sysconfig/* ; do
    if test -f "${fname}"; then
	cp -av "${fname}" /etc/sysconfig/
    fi
done
restorecon -R /etc/sysconfig/


title unbound -- for nic

cp -av /testing/baseconfigs/all/etc/unbound /etc/
cp -av /testing/baseconfigs/all/etc/systemd/system/unbound.service /etc/systemd/system/
restorecon -R /etc/unbound


title nsd -- for nic

cp -av /testing/baseconfigs/all/etc/nsd /etc/
restorecon -R /etc/nsd


title fixup /etc/sysctl.conf

cp -av /testing/baseconfigs/all/etc/sysctl.conf /etc/
sysctl -q -p
restorecon -R /etc/sysctl.conf


# clobber some anoying services

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
