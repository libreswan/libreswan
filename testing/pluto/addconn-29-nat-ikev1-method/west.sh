/testing/guestbin/swan-prep
ipsec start
../../guestbin/wait-until-pluto-started

ipsec add addconn--default
ipsec add addconn--both
ipsec add addconn--rfc
ipsec add addconn--drafts
ipsec add addconn--none

ipsec whack --name whack--default                      --encrypt --ikev1 --ipv4 --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--both    --ikev1-natt both    --encrypt --ikev1 --ipv4 --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--rfc     --ikev1-natt rfc     --encrypt --ikev1 --ipv4 --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--drafts  --ikev1-natt drafts  --encrypt --ikev1 --ipv4 --host 1.2.3.4 --to --host 5.6.7.8
ipsec whack --name whack--none    --ikev1-natt none    --encrypt --ikev1 --ipv4 --host 1.2.3.4 --to --host 5.6.7.8

ipsec connectionstatus | sed -n -e 's/^\([^:]*:\) .* \(ikev1-method:\)[ ]*\([^ ;]*\).*/\1 \2 \3/p' | sort
