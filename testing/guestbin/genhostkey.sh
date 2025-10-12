#!/bin/sh

set -e

if test $# -eq 0 ; then
    cat <<EOF 1>&2
Usage:
    $(basename $0) <directory>
Generates a host key and then creates:
     OUTPUT/<us>.pub      i.e., {left,right}pubkey=...
     OUTPUT/<us>.raw      i.e., {left,right}{rsasig,ecdsa,eddsa}key=
     OUTPUT/<us>.pem      mime file
     OUTPUT/<us>.ckaid    i.e., {left,right}ciakd=...
     OUTPUT/<us>.hostkey  copy of .raw or .pub
Uses directory to determine raw|pem and rsa|ecdsa|eddsa.
EOF
    exit 1
fi

keytype=
case $1 in
	*rsa* )   keytype=rsa ;;
	*ecdsa* ) keytype=ecdsa ;;
	*eddsa* ) keytype=eddsa ;;
	* ) echo "Unknown keytype" 1>&2 ; exit 1 ;;
esac

format=
case $1 in
	*raw* ) format=raw ;;
	*pem* ) format=pub ;;
	*pub* ) format=pub ;;
	* ) echo "Unknown format" 1>&2 ; exit 1 ;;
esac

echo ${format} ${keytype}

# US vs THEM

us=$(hostname | cut -d. -f1)
them=$(case $us in east ) echo west ;; west ) echo east ;; esac)
leftright=$(case $us in east ) echo right ;; west ) echo left ;; esac)

echo us=${us} them=${them} leftright=${leftright}

# generate the host key and save it

ckaid=$(ipsec newhostkey --keytype ${keytype} 2>&1 | grep "showhostkey" | sed "s/^.*ckaid //")

# sanitizing brought to you by id-sanitize.sed

printf "\t${leftright}ckaid=${ckaid}\n" > OUTPUT/$us.ckaid
# BEGIN...END
ipsec showhostkey --pem                   --ckaid "${ckaid}" > OUTPUT/$us.pem
# {left,right}{rsasig,ecdsa,eddsa}key=...
ipsec showhostkey --${leftright}          --ckaid "${ckaid}" > OUTPUT/$us.raw
# {left,right}pubkey=...
ipsec showhostkey --${leftright} --pubkey --ckaid "${ckaid}" > OUTPUT/$us.pub

cp OUTPUT/${us}.${format} OUTPUT/${us}.hostkey
