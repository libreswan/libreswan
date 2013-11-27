#westnet-eastnet-ikev2[1]: ESTABLISHED 18 seconds ago, 192.1.2.23[east]...192.1.2.45[west]
#westnet-eastnet-ikev2[1]: IKEv2 SPIs: 00745962c0df8d66_i 2742f60ea5679118_r*, pre-shared key reauthentication in 2 hours
#westnet-eastnet-ikev2[1]: IKE proposal: 3DES_CBC/HMAC_MD5_96/PRF_HMAC_MD5/MODP_1024
#westnet-eastnet-ikev2{1}:  INSTALLED, TUNNEL, ESP SPIs: c2954ab2_i e20b55a0_o
#westnet-eastnet-ikev2{1}:  AES_CBC_128/HMAC_SHA1_96, 336 bytes_i (14s ago), 336 bytes_o (14s ago), rekeying in 42 minutes
#westnet-eastnet-ikev2{1}:   192.0.2.0/24 === 192.0.1.0/24 
# some other sanitzer seems to kill line 2,3 and 5 ?
s/^\(Starting strongSwan \)\(.*\)\( IPsec.*\)$/\1X.X.X\3/g
s/\(Status of IKE charon daemon \)(.*)$/\1 (VERSION)/g
s/\(  uptime: \)\([0-9]*\)\( seconds, since \)\(.*\)$/\1XXX\3YYY/g
s/^\(.* ESTABLISHED \)\([0-9]*\)\( seconds ago.*\)$/\1XXX\3/g
s/^\(.* IKEv2 SPIs: \)\(.*\) \(.*\)\(, .*\)$/\1SPISPI_i SPISPI_r\3/g
s/^\(.*  INSTALLED, TUNNEL, ESP SPIs: \)\(.*_i \)\(.*_o\)$/\1SPISPI_i SPISPI_o/g
s/^\(scheduling reauthentication in \)\([0-9]*s\)/\1XXXs/g
s/^\(maximum IKE_SA lifetime \)\([0-9]*s\)/\1XXXs/g
#s/([0-9]*s ago)/(XXs ago)/g
