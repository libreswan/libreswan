#!/bin/sh

if test $# -ne 1 ; then
    echo "Missing hostname" 1>&2
    exit 1
fi

if test ! -d testing ; then
    echo "Missing testing directory" 1>&2
    exit 1
fi

# Hobble swan-transmogrify so it doesn't undo this script's good work
sed -i '/swan-transmogrify.sh/ s;^;#;' /etc/rc.d/rc.local

fqdn=$1
hostname=$(expr ${fqdn} : '\([^.]*\).*')
domainname=$(expr ${fqdn} : ${hostname}.'\(.*\)')

copy()
{
    for d in testing/baseconfigs/all testing/baseconfigs/$hostname ; do
	if test -f $d/$1 ; then
	    cp -v $d/$1 $1
	fi
	if test -d $d/$1 -a -d $1 ; then
	    for f in $d/$1/* ; do
		test -f $f && cp -v $f $1/$(basename $f)
	    done
	fi
    done
}

# Kerberos needs a FQDN.  Hopefully hostname contains what is needed.
# echo $1.testing.libreswan.org > /etc/hostname
echo ${fqdn} > /etc/hostname

copy /etc/resolv.conf

# Kerberos needs a host file with FQDNs; either that or run bind.
cat <<EOF > /etc/hosts
127.0.0.1	localhost
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
192.1.2.45 west.testing.libreswan.org west
192.0.1.254 west-in  west-eth0
192.1.2.23  east.testing.libreswan.org east
192.0.2.254 east-in  east-eth0
192.0.2.1   sunrise
192.1.2.254 nic.testing.libreswan.org nic
EOF

rm -rf /etc/bind
mkdir /etc/bind
copy /etc/bind/

rm -rf /etc/ssh
mkdir --mode=0755 /etc/ssh
copy /etc/ssh/
chmod -v 600 /etc/ssh/*key*

rm -rf /root/.ssh
mkdir --mode=0700 /root/.ssh
copy /root/.ssh/
chmod -v 600 /root/.ssh/*


if test -r /etc/redhat-release ; then

    copy /etc/sysconfig/
    copy /etc/sysconfig/network-scripts/

    # get rid of damn cp/mv/rm aliases for root
    sed -i 's/alias/# alias/g' /root/.bashrc

elif test -r /etc/debian_version ; then

    copy /etc/network/interfaces

else
    echo "Unknown OS" 1>&2
    exit 1
fi

if test -r /etc/redhat-release ; then
    restorecon -R /etc/ /root/.ssh
fi
