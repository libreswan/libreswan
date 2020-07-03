#!/bin/sh

set -eu

. ../bin/algo-common.sh

echo check the stack is ${initiator_stack}
grep protostack=${initiator_stack} /etc/ipsec.conf

echo confirm that the network is alive
../bin/wait-until-alive -I 192.0.1.254 192.0.2.254

echo ensure that clear text does not get through
iptables -A INPUT -i eth1 -s 192.0.2.0/24 -j DROP
iptables -I INPUT -m policy --dir in --pol ipsec -j ACCEPT
../../pluto/bin/ping-once.sh --down -I 192.0.1.254 192.0.2.254

# specify the kernel module from the command line?
ipsec start
/testing/pluto/bin/wait-until-pluto-started
ipsec whack --impair suppress-retransmits

# The 'echo +' is to stop the sanitizer eating blank lines.  Works,
# but '+' given diff, isn't the best character choice.

echo testing ${algs}
for alg in ${algs} ; do
    name=${proto}-${version}-${alg}
    echo +
    echo + ${name}
    echo +

    ( set -x ; ipsec whack --name ${name} \
		     --${version}-allow \
		     --psk \
		     --esp ${alg} \
		     --${proto} \
		     --pfs \
		     --no-esn \
		     \
		     --id @west \
		     --host 192.1.2.45 \
		     --nexthop 192.1.2.23 \
		     --client 192.0.1.0/24 \
		     \
		     --to \
		     \
		     --id @east \
		     --host 192.1.2.23 \
		     --nexthop=192.1.2.45 \
		     --client 192.0.2.0/24 \
	)
    echo +

    ipsec auto --up ${name}
    echo +

    # IKEv1 KLIPS ESP/AH responder needs to be given some extra time
    # before the SA really is established - clearly a BUG given
    # neither IKEv2 (with KLIPS) nor NETKEY (IKEv1 responder) suffer
    # the same problem.
    case ${version}-${responder_stack} in
	ikev1-klips )
	    echo "sleep 2 # hack around bug in IKEv1 KLIPS AH"
	    sleep 2
	    echo +
	    ;;
    esac

    ../bin/ping-once.sh --up -I 192.0.1.254 192.0.2.254
    echo +

    ipsec auto --delete ${name}
    echo +

done
