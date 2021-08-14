if test $# -ne 3 ; then
    echo "usage: <src> <dst> <start-port>" 1>&2
    exit 1
fi

src=$1
dst=$2
start=$3

# NAT to NIC's address
# NAT UDP 500,4500 to NICs address with sport to high EPEM port
for sport in 500 4500 ; do
    lo=$(expr $sport + $start)
    hi=$(expr $sport + $start + 100)
    for proto in udp tcp ; do
	iptables -t nat -A POSTROUTING -s ${src} -p ${proto} --sport ${sport} -j SNAT --to-source 192.1.2.254:${lo}-${hi}
	echo "${src}:${sport} -${proto}-> ${dst}:${lo}-${hi}"
    done
done
iptables -t nat -A POSTROUTING -s ${src} -j SNAT --to-source ${dst}
echo "${src} -> ${dst}"
