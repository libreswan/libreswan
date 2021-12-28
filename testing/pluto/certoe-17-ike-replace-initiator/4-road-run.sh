# trigger OE
../../guestbin/ping-once.sh --forget -I 192.1.3.209 192.1.2.23
../../guestbin/wait-for.sh --match private -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
# wait on OE retransmits and rekeying
../../guestbin/wait-for.sh --match '#8:.*established' -- ipsec status
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
# expect new #13 and old #10 in traffic status
../../guestbin/wait-for.sh --match '#13:' -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
 ipsec whack --trafficstatus
# expect new #15 and old #13 in traffic status
../../guestbin/wait-for.sh --match '#15:' -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
# expect new #18 and old #15 in traffic status
../../guestbin/wait-for.sh --match '#18:' -- ipsec whack --trafficstatus
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
# go for broke, let IKE sa establish
../../guestbin/wait-for.sh --match '#26:.*established IKE SA' -- ipsec status
../../guestbin/ping-once.sh --up -I 192.1.3.209 192.1.2.23
ipsec whack --trafficstatus
ipsec whack --shuntstatus
echo done
