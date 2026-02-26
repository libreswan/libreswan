/testing/guestbin/swan-prep --userland strongswan

# DANGER: when resolvconf, from systemd-resolved, is present,
# strongSwan unconditionally uses it over /etc/resolv.conf; this hack
# is to stop it.
#
# See https://github.com/strongswan/strongswan/issues/3013
# See https://github.com/libreswan/libreswan/issues/2635

test -r /usr/sbin/resolvconf && mv -v /usr/sbin/resolvconf{,.tmp}

../../guestbin/strongswan-start.sh

test -r /usr/sbin/resolvconf.tmp && mv -v /usr/sbin/resolvconf{.tmp,}

echo "initdone"
