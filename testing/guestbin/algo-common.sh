# algo-{esp,ah}-{netkey|xfrm}-to-{netkey|xfrm}-ikev{1,2}

d=$(basename $(pwd))

case $d in
    *-esp-* ) protocol=esp ;;
    *-ah-*) protocol=ah ;;
esac
echo "protocol=${protocol}"

case $d in
    *-netkey-to-* ) initiator_stack=xfrm ;;
    *-xfrm-to-* ) initiator_stack=xfrm ;;
esac
echo "initiator_stack=${initiator_stack}"

case $d in
    *-to-netkey-* ) responder_stack=xfrm ;;
    *-to-xfrm-* ) responder_stack=xfrm ;;
esac
echo "responder_stack=${responder_stack}"

case $d in
    *-ikev1) version=ikev1 ;;
    *-ikev2) version=ikev2 ;;
esac
echo "version=${version}"

# order by lowest common denominator
case -${initiator_stack}-${responder_stack}- in
    *-netkey-* ) encrypt="aes" ; integ="sha1" ;;
    *-xfrm-* ) encrypt="aes" ; integ="sha1" ;;
esac
echo "encrypt=${encrypt} integ=${integ}"

algs=
case ${protocol} in
    esp )
	proto=encrypt
	for e in ${encrypt} ; do
	    for i in ${integ} ; do
		algs="${algs} ${e}-${i}"
	    done
	done
	;;
    ah )
	proto=authenticate
	for i in ${integ} ; do
	    algs="${algs} ${i}"
	done
	;;
esac
echo "proto=${proto} algs=${algs}"
