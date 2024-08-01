#!/bin/bash

if test $# -lt 3 -o $# -gt 4 ; then
    cat <<EOF 1>&2
Usage:

  $0 <from-src> <to-src> <to-port> [ <nr-ports> ]

Configure teh NAT to map outbound TCP and UDP connections from
<from-src> and ports 500 and 4500 to be from <to-src> and starting
ports <to-port>+500 and <to-port>+4500.  For instance:

   1.2.3.4 5.6.7.8 4000 1

NATs

   1.2.3.4:4500 -> 5.6.7.8:44500...

EOF
    exit 1
fi

old_src=$1 ; shift
new_src=$1 ; shift
new_port=$1 ; shift
count=100

if test $# -gt 0 ; then
    count=$4 ; shift
fi

# NAT to NIC's address

if ! output=$(iptables -t nat --flush 2>&1) ; then
    echo "iptables: ${output}"
fi

if ! output=$(conntrack --flush 2>&1) ; then
    echo "conntrack: ${output}"
fi

# NAT UDP 500, 4500 to NICs address with sport to high EPEM port

for old_port in 500 4500 ; do
    lo_port=$((new_port + old_port))
    hi_port=$((new_port + old_port + count))
    for proto in udp tcp ; do
	iptables -t nat -A POSTROUTING -s ${old_src} -p ${proto} --sport ${old_port} -j SNAT --to-source ${new_src}:${lo_port}-${hi_port}
	echo "${old_src}:${old_port} -${proto}-> ${new_src}:${lo_port}-${hi_port}"
    done
done

iptables -t nat -A POSTROUTING -s ${old_src} -j SNAT --to-source ${new_src}
echo "${old_src} -> ${new_src}"
