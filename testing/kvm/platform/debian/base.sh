#!/bin/sh

echo
echo
echo

# this is run from within /target

echo
echo profile
echo

cat <<EOF | tee /root/.profile
PS1='[\u@\h \w \$(echo \$?)]\\$ '
EOF

echo
echo grub
echo

sed -i -e '/^GRUB_TIMEOUT=/ s/=.*/=0/' /etc/default/grub
update-grub


echo
echo fstab
echo

mkdir -p /pool /bench
cat <<EOF >>/etc/fstab
# can only mount after boot, see
# https://superuser.com/questions/1721448/systemd-twice-mounts-entry-in-fstab-during-boot-first-attempt-fails-with-bad-op#1721512
pool  /pool  9p defaults,trans=virtio,version=9p2000.L,context=system_u:object_r:usr_t:s0,x-systemd.automount 0 0
bench /bench 9p defaults,trans=virtio,version=9p2000.L,context=system_u:object_r:usr_t:s0,x-systemd.automount 0 0
EOF


echo
echo network
echo

cp /usr/lib/systemd/system/systemd-networkd-wait-online.service /etc/systemd/system
sed -i -e '/ExecStart/ s/$/ --interface eth0:routable/' /etc/systemd/system/systemd-networkd-wait-online.service
systemctl enable systemd-networkd-wait-online.service

echo
echo
echo
