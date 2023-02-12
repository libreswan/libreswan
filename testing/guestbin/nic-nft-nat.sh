
set -eu
src="192.1.3.0/24"
dst="192.1.2.254"
pstart=35000 # 35K because Linux treat 32768-61000 as ephemeral
step=100


usage() {
    echo "usage: $0 [--src <src>  --dst <dst> --pstart <start-port> --step <step>]" 1>&2
    echo    "Defaults: src=${src} dst=${dst} start-port=$pstart step=$step" 1>&2
    exit 1
}

err() {
	err=${1:=""}
	echo  "ERROR ${err}"
	exit 1
}

OPTIONS=$(getopt -o h --long help,src:,dst:,pstart:,step: -- "$@")
if (( $? != 0 )); then
    e=$?
    err "from getopt $e"
fi

eval set -- "$OPTIONS"

while true; do
        case "$1" in
                -h | --help )
                        usage
                        exit 1
                        shift
			break
                        ;;

                --src )
                        src=$2
                        shift 2
			break
                        ;;
                --dst )
                        dst=$2
                        shift 2
			break
                        ;;
                --pstart )
                        pstart=$2
                        shift 2
			break
                        ;;

                --step )
                        step=$2
                        shift 2
			break
                        ;;

		-- ) shift;
			break
			;;
	* )
            shift
            break
            ;;
        esac
done

nft flush ruleset
nft add table ipsec-nat
nft 'add chain ipsec-nat ipsec-postrouting { type nat hook postrouting priority srcnat; }'

# NAT to NIC's address
# NAT TCP and UDP 500,4500 to NICs address with sport to high EPEM port
for sport in 500 4500 ; do
    lo=$(expr $sport + $pstart)
    hi=$(expr $sport + $pstart + $step)
    for proto in udp tcp ; do
	nft add rule ipsec-nat ipsec-postrouting ip saddr ${src} ${proto} sport ${sport} snat to ${dst}:${lo}-${hi}
	echo "${src}:${sport} -${proto}-> ${dst}:${lo}-${hi}"
    done
done
# snat the rest without port specified.
nft add rule ipsec-nat ipsec-postrouting ip saddr ${src} snat to ${dst}
echo "${src} -> ${dst}"
