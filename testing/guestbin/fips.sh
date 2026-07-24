#!/bin/sh

ipsecdir=$(ipsec addconn --configsetup=ipsecdir --config /dev/null)

fips_on()
{
    # XXX: what's this?
    cp /testing/baseconfigs/all/etc/sysconfig/pluto.fips \
       /etc/sysconfig/pluto

    # fips password
    nsspassword=$(cat /testing/x509/nsspassword)
    echo "NSS FIPS 140-2 Certificate DB:${nsspassword}" \
	 > ${ipsecdir}/nsspassword
    nsspw=/run/pluto/nsspw
    echo "" > ${nsspw}
    ipsec certutil -W -f ${nsspw} -@ /testing/x509/nsspassword
    echo "${nsspassword}" > ${nsspw}

    # unmount if we find it mounted
    fips_enabled=/proc/sys/crypto/fips_enabled
    if grep ${fips_enabled} /proc/mounts > /dev/null; then
	umount ${fips_enabled}
    fi
    echo "1" > /run/pluto/fips_enabled
    mount --bind /run/pluto/fips_enabled ${fips_enabled}
    chcon system_u:object_r:proc_t:s0 ${fips_enabled}

    echo FIPS mode enabled.
}

case $1 in

    on )
	fips_on
	;;

    * )
	echo $1 unknown
	exit 1
	;;
esac
