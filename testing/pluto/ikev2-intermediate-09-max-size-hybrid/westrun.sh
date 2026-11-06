ipsec up west # sanitize-retransmits
# verify fragmentation occurred with large keys
../../guestbin/wait-for-pluto.sh 'reassembled from'
echo done
