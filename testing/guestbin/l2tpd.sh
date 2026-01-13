#!/bin/sh

copy()
{
    local src=$1
    local dst=$2
    rm -f ${dst}
    for f in $(hostname).${src}  ${src} ; do
	test ! -r ${f} && continue
	if test -r ${dst} ; then
	    echo "duplicate ${dst}: $@" 1>&2
	    exit 1
	fi
	mkdir -p $(dirname ${dst})
	cp -v ${f} ${dst}
	chmod u=r,go= ${dst}
    done
}

mkdir -p /var/run/xl2tpd

copy xl2tpd.conf /etc/xl2tpd/xl2tpd.conf
copy chap-secrets /etc/ppp/chap-secrets
copy ppp-options.xl2tpd /etc/ppp/options.xl2tpd

mknod /dev/ppp c 108 0

cd /tmp
xl2tpd -D 2>/tmp/xl2tpd.log &

# give it a chance to start
sleep 1
