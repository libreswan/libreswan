:
: hostnamer
:

# hostnamer runs whenever /etc/hostname is empty; it detects east,
# west, et.al., but for build domains lets the above kick in
# rm -f /etc/hostname # hostnamectl set-hostname ""

cp -v /bench/testing/kvm/systemd/hostnamer.service /etc/systemd/system
cp -v /bench/testing/kvm/systemd/hostnamer.sh /usr/local/sbin/hostnamer.sh
chmod a+x /usr/local/sbin/hostnamer.sh
test -x /usr/sbin/restorecon && restorecon -R /etc/systemd/system
systemctl enable hostnamer.service
