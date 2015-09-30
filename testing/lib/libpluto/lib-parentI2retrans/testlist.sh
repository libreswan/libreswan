export TZ=UTC

(../parentI2retrans ../lib-parentI1/ikev2.record westnet--eastnet-ikev2 ../lib-parentI2/parentR1.pcap 2>&1 | tee secrets.raw

    grep '^| ikev2 [IR]' secrets.raw | cut -c3- >ike-secrets.txt
    echo TCPDUMP output
    tcpdump -t -v -v -s 1600 -n -E 'file ike-secrets.txt' -r parentI2.pcap

) 2>&1 | sed -f ../lib-parentI1/sanity.sed








