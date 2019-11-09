# temp
ipsec auto --add westnet-eastnet-ikev2-modp1536
ipsec auto --add westnet-eastnet-ikev2-modp2048
ipsec auto --add westnet-eastnet-ikev2-modp3072
ipsec auto --add westnet-eastnet-ikev2-modp4096
ipsec auto --add westnet-eastnet-ikev2-modp8192
ipsec auto --add westnet-eastnet-ikev2-dh19
ipsec auto --add westnet-eastnet-ikev2-dh20
ipsec auto --add westnet-eastnet-ikev2-dh21
ipsec auto --add westnet-eastnet-ikev2-dh31
ipsec auto --add westnet-eastnet-ikev2-dh20-fallback
ipsec auto --up westnet-eastnet-ikev2-modp2048
ipsec auto --delete westnet-eastnet-ikev2-modp2048
ipsec auto --up westnet-eastnet-ikev2-modp3072
ipsec auto --delete westnet-eastnet-ikev2-modp3072
ipsec auto --up westnet-eastnet-ikev2-modp4096
ipsec auto --delete westnet-eastnet-ikev2-modp4096
ipsec auto --up westnet-eastnet-ikev2-modp8192
ipsec auto --delete westnet-eastnet-ikev2-modp8192
ipsec auto --up westnet-eastnet-ikev2-dh19
ipsec auto --delete westnet-eastnet-ikev2-dh19
ipsec auto --up westnet-eastnet-ikev2-dh20
ipsec auto --delete westnet-eastnet-ikev2-dh20
ipsec auto --up westnet-eastnet-ikev2-dh21
ipsec auto --delete westnet-eastnet-ikev2-dh21
ipsec auto --up westnet-eastnet-ikev2-dh31
ipsec auto --delete westnet-eastnet-ikev2-dh31
# NOTE: we cannot do this test anymore as we support everything now in the default proposal list
# Next one should work after INVALID_KE suggestion by east to change dh20 to modp2048
# ipsec auto --up westnet-eastnet-ikev2-dh20-fallback
# ipsec auto --delete westnet-eastnet-ikev2-dh20-fallback
#
# MODP1536 is no longer in the default list and should fail
ipsec whack --impair delete-on-retransmit
ipsec auto --up westnet-eastnet-ikev2-modp1536
echo done
